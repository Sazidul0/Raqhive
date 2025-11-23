#!/usr/bin/python3
import argparse
import json
import logging
import re
import socket
import sys
import threading
import yaml
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
import os
import signal

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

from bcc import BPF
from ctypes import (
    Structure, Union, POINTER,
    c_uint, c_uint64, c_uint32, c_ushort,
    c_char, c_uint8, cast
)

# ==================== GLOBALS ====================
RULES = {}
RULES_LOCK = threading.Lock()
IPS_MODE = False
IDS_LOGGER = None
IPS_LOGGER = None
b = None  

# ==================== STRUCTS ====================
class Daddr(Union):
    _fields_ = [("v4_addr", c_uint32), ("v6_addr", c_uint8 * 16)]

class Event(Structure):
    _fields_ = [
        ("type", c_uint), ("timestamp", c_uint64),
        ("pid", c_uint32), ("ppid", c_uint32),
        ("comm", c_char * 16), ("parent_comm", c_char * 16),
        ("filename", c_char * 256),
        ("family", c_ushort), ("dport", c_ushort),
        ("daddr", Daddr),
    ]

# ==================== LOGGING ====================
def setup_logging(logfile_ids="ids_alerts.log", logfile_ips="ips_actions.log"):
    global IDS_LOGGER, IPS_LOGGER
    # IDS logger
    IDS_LOGGER = logging.getLogger('IDS')
    IDS_LOGGER.setLevel(logging.INFO)
    if IDS_LOGGER.handlers:
        IDS_LOGGER.handlers.clear()
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    fh = logging.FileHandler(logfile_ids)
    fh.setFormatter(formatter)
    IDS_LOGGER.addHandler(fh)
    IDS_LOGGER.addHandler(logging.StreamHandler(sys.stdout))

    # IPS logger (separate file)
    IPS_LOGGER = logging.getLogger('IPS')
    IPS_LOGGER.setLevel(logging.INFO)
    if IPS_LOGGER.handlers:
        IPS_LOGGER.handlers.clear()
    ips_fh = logging.FileHandler(logfile_ips)
    ips_fh.setFormatter(logging.Formatter('%(asctime)s - [IPS BLOCK] %(message)s'))
    IPS_LOGGER.addHandler(ips_fh)
   

# ==================== RULE LOADING ====================
def load_rules(rule_file):
    global RULES
    try:
        with open(rule_file) as f:
            data = yaml.safe_load(f) or {}
            # compile regexes
            for rule in data.get('rules', []):
                if not rule.get('enabled', False):
                    continue
                for k in list(rule.get('match', {})):
                    if k.endswith('_regex'):
                        rule['match'][k + '_compiled'] = re.compile(rule['match'][k])
                if rule.get('stateful') and 'source_event_match' in rule['stateful']:
                    sm = rule['stateful']['source_event_match']
                    for k in list(sm):
                        if k.endswith('_regex'):
                            sm[k + '_compiled'] = re.compile(sm[k])
            with RULES_LOCK:
                RULES = data
            IDS_LOGGER.info(f"Loaded {len(data.get('rules', []))} rules")
    except Exception as e:
        IDS_LOGGER.error(f"Rule load failed: {e}")

# ==================== WATCHDOG HANDLER ====================
class RuleChangeHandler(FileSystemEventHandler):
    def __init__(self, rule_file):
        self.rule_file = rule_file
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith(self.rule_file):
            IDS_LOGGER.info("Rules changed Ã¢â€ â€™ reloading")
            load_rules(self.rule_file)

# ==================== HELPERS ====================
def ip_to_str(union, family):
    if family == socket.AF_INET:
        return str(IPv4Address(union.v4_addr))
    if family == socket.AF_INET6:
        return str(IPv6Address(bytes(union.v6_addr)))
    return "unknown"

def log_alert(rule, event, details=""):
    alert = {
        "timestamp": datetime.now().isoformat(),
        "rule_name": rule['name'],
        "severity": rule.get('severity', 'info'),
        "description": rule['description'],
        "process_name": event.comm.decode('utf-8', 'replace').strip('\x00'),
        "pid": event.pid,
        "parent_process_name": event.parent_comm.decode('utf-8', 'replace').strip('\x00'),
        "ppid": event.ppid,
        "details": details
    }
    IDS_LOGGER.warning(json.dumps(alert))

def kill_and_log(pid, rule_name, info):
    try:
        os.kill(pid, signal.SIGKILL)
        IPS_LOGGER.warning(f"PID {pid} KILLED Ã¢â€ â€™ {info} | Rule: {rule_name}")
    except ProcessLookupError:
        IPS_LOGGER.error(f"Kill failed PID {pid}: process not found")
    except PermissionError:
        IPS_LOGGER.error(f"Kill failed PID {pid}: insufficient permissions")
    except Exception as e:
        IPS_LOGGER.error(f"Kill failed PID {pid}: {e}")

# ==================== EVENT CHECKS ====================
def check_exec_or_connect(rule, event):
    data = {}
    if event.type == 0:  # EXEC
        data['filename'] = event.filename.decode('utf-8','replace').strip('\x00')
        data['child_process'] = event.comm.decode('utf-8','replace').strip('\x00')
        data['parent_process'] = event.parent_comm.decode('utf-8','replace').strip('\x00')
    for k, regex in rule.get('match', {}).items():
        if not k.endswith('_compiled'):
            continue
        field = k.replace('_regex_compiled', '')
        if field not in data or not regex.search(data[field]):
            return False, ""
    return True, "Matched rule conditions"

def check_stateful(rule, event):
    """
    Uses ctypes keys/values consistently when accessing bpf map b['tainted_ppids'].
    """
    global b
    if b is None:
        IDS_LOGGER.error("BPF object not initialized in check_stateful()")
        return False, ""

    tainted = b["tainted_ppids"]
    key = c_uint32(event.ppid)

    # Check membership using ctypes key
    try:
        if key not in tainted:
            return False, ""
    except Exception as e:
        # defensive: sometimes bcc raises on membership checks; try lookup and handle KeyError
        try:
            _ = tainted[key]
        except KeyError:
            return False, ""
        except Exception as ex:
            IDS_LOGGER.error(f"Error accessing tainted_ppids map: {ex}")
            return False, ""

    try:
        ts = tainted[key].value
    except KeyError:
        return False, ""
    except Exception as e:
        IDS_LOGGER.error(f"Failed to read timestamp from tainted_ppids: {e}")
        return False, ""

    window_ns = rule['stateful']['time_window_seconds'] * 1_000_000_000
    if event.timestamp - ts <= window_ns:
        ip = ip_to_str(event.daddr, event.family)
        # delete using ctypes key
        try:
            del tainted[key]
        except KeyError:
            # already removed
            pass
        except Exception as e:
            IDS_LOGGER.error(f"Failed to delete tainted_ppids entry: {e}")
        return True, f"Tainted parent Ã¢â€ â€™ connection to {ip}:{event.dport}"
    return False, ""

def handle_open_event(event):
    """
    Mark parent as tainted when OPEN matches stateful source_event_match.
    Uses ctypes key/value for map operations.
    """
    global b
    if b is None:
        IDS_LOGGER.error("BPF object not initialized in handle_open_event()")
        return

    filename = event.filename.decode('utf-8','replace').strip('\x00')
    tainted = b["tainted_ppids"]
    key = c_uint32(event.ppid)
    value = c_uint64(event.timestamp)

    with RULES_LOCK:
        for rule in RULES.get('rules', []):
            if not rule.get('enabled', False) or not rule.get('stateful'):
                continue
            src = rule['stateful'].get('source_event_match', {})
            if src.get('event', '').upper() != 'OPEN':
                continue
            regex = src.get('filename_regex_compiled')
            if regex and regex.search(filename):
                try:
                    tainted[key] = value
                except Exception as e:
                    IDS_LOGGER.error(f"Failed to write to tainted_ppids map: {e}")
                break

# ==================== MAIN EVENT HANDLER ====================
def process_event(cpu, data, size):
    try:
        event = cast(data, POINTER(Event)).contents

        if event.type == 2:  # OPEN
            handle_open_event(event)
            return

        with RULES_LOCK:
            if not RULES:
                return
            for rule in RULES.get('rules', []):
                if not rule.get('enabled', False):
                    continue

                matched = False
                details = ""

                # Single-event rules (EXEC / CONNECT)
                if not rule.get('stateful'):
                    if (event.type == 0 and rule['event'].upper() == "EXEC") or \
                       (event.type == 1 and rule['event'].upper() == "CONNECT"):
                        matched, details = check_exec_or_connect(rule, event)

                # Stateful: CONNECT after tainted OPEN
                elif rule.get('stateful') and event.type == 1 and rule['event'].upper() == "CONNECT":
                    matched, details = check_stateful(rule, event)

                if matched:
                    log_alert(rule, event, details)

                    # IPS action: kill only HIGH severity
                    if IPS_MODE and rule.get('severity', '').lower() == 'high' and event.pid > 1:
                        proc = event.comm.decode('utf-8','replace').strip('\x00')
                        dest = f" Ã¢â€ â€™ {ip_to_str(event.daddr, event.family)}:{event.dport}" if event.type == 1 else ""
                        kill_and_log(event.pid, rule['name'], f"{proc}{dest} | {details}")

    except Exception as e:
        # Use IDS_LOGGER if available
        try:
            IDS_LOGGER.error(f"Event processing error: {e}")
        except Exception:
            print(f"Event processing error: {e}", file=sys.stderr)

# ==================== INTERACTIVE MENU ====================
def menu():
    print("\n" + "="*50)
    print("     eBPF Professional IDS/IPS")
    print("="*50)
    print("1. IDS Only (Monitoring)")
    print("2. IDS + IPS (Auto-kill HIGH severity)")
    print("3. Exit")
    print("-"*50)
    while True:
        try:
            c = input("Choose 1/2/3: ").strip()
        except EOFError:
            return "3"
        if c in ("1","2","3"):
            return c

# ==================== ENTRYPOINT ====================
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--rules", default="pro_rules.yaml")
    parser.add_argument("--kernel", default="pro_ids_kernel.c", help="Path to eBPF C file")
    args = parser.parse_args()

    choice = menu()
    if choice == "3":
        sys.exit(0)

    IPS_MODE = (choice == "2")

    setup_logging()
    load_rules(args.rules)

    print(f"\nStarting in {'IDS + IPS (BLOCKING)' if IPS_MODE else 'IDS (Monitoring)'} mode...\n")

    # Watchdog for rules
    observer = None
    if WATCHDOG_AVAILABLE:
        try:
            observer = Observer()
            observer.schedule(RuleChangeHandler(args.rules), path='.', recursive=False)
            observer.start()
            IDS_LOGGER.info(f"Started watching {args.rules} for changes.")
        except Exception as e:
            IDS_LOGGER.warning(f"Failed to start watchdog observer: {e}")
    else:
        IDS_LOGGER.warning("watchdog library not found. Rule reloading is disabled.")

    # Load BPF program
    try:
        b = BPF(src_file=args.kernel)
    except Exception as e:
        IDS_LOGGER.error(f"Failed to load BPF program from {args.kernel}: {e}")
        sys.exit(1)

    # Attach probes/tracepoints 
    try:
        b.attach_kprobe(event="tcp_connect", fn_name="trace_connect")
    except Exception as e:
        IDS_LOGGER.error(f"Failed to attach kprobe tcp_connect: {e}")
    try:
        b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="trace_exec_entry")
        b.attach_tracepoint(tp="syscalls:sys_enter_open", fn_name="trace_open_entry")
        b.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="trace_openat_entry")
    except Exception as e:
        IDS_LOGGER.error(f"Failed to attach tracepoints: {e}")

    # Setup perf buffer
    try:
        b["events"].open_perf_buffer(process_event)
    except Exception as e:
        IDS_LOGGER.error(f"Failed to open perf buffer: {e}")
        sys.exit(1)

    IDS_LOGGER.info("System armed. Press Ctrl+C to stop.")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        if observer:
            observer.stop()
            observer.join()
        IDS_LOGGER.info("Stopped.")
        sys.exit(0)

