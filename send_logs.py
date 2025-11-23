import requests
import json
from datetime import datetime
import getpass
import re

API_BASE = "https://logmanageridsipsbackend.onrender.com/api" 

IPS_LOG_FILE = "ips_actions.log"
IDS_LOG_FILE = "ids_alerts.log"


# -----------------------
# LOGIN (GET JWT TOKEN)
# -----------------------
def login():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")

    resp = requests.post(f"{API_BASE}/signin", json={
        "username": username,
        "password": password
    })

    if resp.status_code != 200:
        print("Login failed:", resp.text)
        exit(1)

    print("Login successful!")
    return resp.json()["token"]


# -----------------------
# TIMESTAMP FIXER
# -----------------------
def fix_timestamp(t):
    """
    Convert timestamps like:
    2025-11-18 15:24:49,433
    Ã¢â€ â€™ 2025-11-18T15:24:49.433Z
    """
    try:
        dt = datetime.strptime(t, "%Y-%m-%d %H:%M:%S,%f")
        return dt.isoformat() + "Z"
    except:
        return datetime.utcnow().isoformat() + "Z"


# -----------------------
# PARSE IPS LOGS
# -----------------------
def parse_ips_logs():
    logs = []

    regex = r"^(.*?) - \[IPS BLOCK\] PID (\d+) KILLED .*? ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):(\d+).*? \| Rule: (.*)$"

    with open(IPS_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = re.search(regex, line)
            if not match:
                continue

            ts_raw, pid, ip, port, rule = match.groups()

            logs.append({
                "timestamp": fix_timestamp(ts_raw),
                "pid": int(pid),
                "ip": ip,
                "port": port,
                "rule": rule
            })

    return logs


# -----------------------
# PARSE IDS LOGS
# -----------------------
def parse_ids_logs():
    logs = []

    with open(IDS_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            # IDS JSON lines look like:
            # 2025-11-18 15:23:01,912 - {"timestamp": "...", ... }
            if "{" not in line:
                continue

            try:
                json_part = line.split(" - ", 1)[1]
                data = json.loads(json_part)
                logs.append(data)
            except:
                pass

    return logs


# -----------------------
# SEND LOG TO BACKEND
# -----------------------
def send_log(token, log_type, data):
    headers = {
        "Authorization": f"Bearer {token}"
    }

    payload = {
        "logType": log_type,
        "logData": data,
        "timestamp": data.get("timestamp", datetime.utcnow().isoformat() + "Z")
    }

    resp = requests.post(f"{API_BASE}/logs", json=payload, headers=headers)

    if resp.status_code == 201:
        print(f"[OK] Sent {log_type} log")
    else:
        print(f"[ERR] Failed to send {log_type} log: {resp.text}")


# -----------------------
# MAIN
# -----------------------
def main():
    token = login()

    print("\nReading IPS logs...")
    ips_logs = parse_ips_logs()
    print(f"Found {len(ips_logs)} IPS logs")

    print("Reading IDS logs...")
    ids_logs = parse_ids_logs()
    print(f"Found {len(ids_logs)} IDS logs")

    print("\nSending logs...\n")

    for log in ips_logs:
        send_log(token, "ips", log)

    for log in ids_logs:
        send_log(token, "ids", log)

    print("\nAll logs sent!")


if __name__ == "__main__":
    main()

