# Raqhive — Network of Watchers

**Raqhive** is a powerful, lightweight **eBPF-based IDS/IPS** that monitors critical system events in real time:

-   Process execution (`execve`)
-   Outbound network connections (`connect`)
-   Sensitive file access (`open` / `openat`)

Features **stateful correlation rules**, **live rule reloading**, and optional **automatic process termination** (IPS mode).

All events are logged locally and can be forwarded to a centralized web dashboard.

---

### Features

-   Pure eBPF kernel instrumentation (no kernel modules)
-   Stateful detection (e.g., "alert if `/etc/shadow` is opened → then outbound connection within 5 minutes")
-   YAML rule engine with automatic hot-reload
-   IDS + optional IPS (auto-kill high-severity processes)
-   Clean JSON alerts + separate IPS action log
-   Central dashboard: https://log-manager-idsips.vercel.app

---

### Project Structure

```text
├── pro_ids_kernel.c       # eBPF program
├── pro_ids_userspace.py   # Main userspace controller
├── pro_rules.yaml         # Rule configuration (hot-reloadable)
├── send_logs.py           # Upload logs to central dashboard
├── ids_alerts.log         # IDS alerts (JSON lines)
└── ips_actions.log        # IPS kill actions
```
---

### Full Installation (Ubuntu / Debian)

**1. Update system**
```bash
sudo apt-get update
```

**2. Install required tools and kernel headers**
```bash
sudo apt-get install -y build-essential python3-dev python3-pip \
    linux-headers-$(uname -r) \
    bpfcc-tools libbpfcc-dev
```

 **3. Install Python dependencies**
 ```bash
pip3 install --upgrade pip
pip3 install bcc pyyaml watchdog requests ipaddress
```

**4. (Optional) Verify bcc is working**
```bash
python3 -c "from bcc import BPF; print('eBPF ready!')"
```

### Works on Ubuntu 20.04 / 22.04 / 24.04, Debian 11/12, Kali Linux, WSL(with limitations)


### Quick Start

1.  **Clone the repository**
    ```bash
    git clone https://github.com/yourusername/raqhive.git
    cd raqhive
    ```

2.  **Run Raqhive (requires root)**
    ```bash
    sudo python3 pro_ids_userspace.py
    ```

    You will see the following menu:
    ```text
    ==================================================
         eBPF Professional IDS/IPS
    ==================================================
    1. IDS Only (Monitoring)
    2. IDS + IPS (Auto-kill HIGH severity)
    3. Exit
    --------------------------------------------------
    Choose 1/2/3:
    ```
    -   Choose `1` for **Monitoring only**.
    -   Choose `2` for **Full IPS mode**, which automatically terminates high-severity threats.

> Rules in `pro_rules.yaml` are reloaded automatically on change. Press `Ctrl+C` to stop the program.

---

### Sending Logs to Centralized Dashboard

1.  Navigate to **https://log-manager-idsips.vercel.app** and create a free account.
2.  Run the log uploader script:
    ```bash
    python3 send_logs.py
    ```
3.  Enter your credentials when prompted. All alerts and IPS actions will be uploaded in real-time. You can then view, search, and manage alerts from all your hosts on the web dashboard.

---

### Example Rule: Data Exfiltration Detection

This rule detects when a process accesses a sensitive file and then establishes an outbound network connection within a 5-minute window.

```yaml
- name: "Potential Data Exfiltration"
  description: "Process accessed sensitive file then connected outbound"
  enabled: true
  event: "connect"
  severity: "high"
  stateful:
    source_event_match:
      event: "open"
      filename_regex: "^/etc/(shadow|passwd|sudoers)|/root/.ssh/id_rsa$"
    time_window_seconds: 300  # 5 minutes
```


### Requirements Summary

| Component          | Requirement                               |
| ------------------ | ----------------------------------------- |
| **Kernel**         | Linux ≥ 5.4 (eBPF + BTF recommended)      |
| **Privileges**     | Root or `CAP_BPF` + `CAP_SYS_ADMIN`         |
| **Python**         | Python 3.8+                               |
| **Tested Distros** | Ubuntu 22.04/24.04, Debian 12, Kali, Fedora |

---

### License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

### Author

Built with passion for kernel security.

*Raqhive, A hive never sleeps. Your system is being watched.*