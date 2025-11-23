<div align="center">

![Linux](https://img.shields.io/badge/Linux-5.4%2B-yellow?style=for-the-badge&logo=linux)
![eBPF](https://img.shields.io/badge/eBPF-powered-brightgreen?style=for-the-badge&logo=ebpf)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![Dashboard](https://img.shields.io/badge/Live_Dashboard-000000?style=for-the-badge&logo=vercel&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

<div align="center">



<br/>

**Raqhive - Network of Watchers**  
**Lightweight eBPF IDS/IPS + Real-time AI Security Platform**


[Central Dashboard](https://log-manager-idsips.vercel.app) • 
[Quick Start](#quick-start) • 
[Example Rules](#example-rule-data-exfiltration-detection) • 
[Report Bug](https://github.com/Sazidul0/Raqhive/issues) • 
[Request Feature](https://github.com/Sazidul0/Raqhive/issues)

<br/>

</div>

<img src="https://github.com/Sazidul0/Raqhive/blob/main/images/raqhive-banner.png" alt="Raqhive - eBPF IDS/IPS" width="900"/>


| Real-time kernel visibility (exec • connect • open) |
| Stateful correlation rules with instant hot-reload |
| Optional automatic process kill (IPS mode) |
| Central SIEM-like dashboard |
| **Live AI that instantly tells you:** attack type • suspicious IPs/domains • tools used • exact actions to take |


<!-- <br/>

<span style="font-size:1.4em; color:#e91e63; font-weight:bold;">A hive never sleeps.</span>  
<span style="font-size:1.4em; color:#00e676; font-weight:bold;">The AI never blinks.</span>

<br/> -->



</div>


<!-- # Raqhive - Network of Watchers -->


---

### Features

-   Pure eBPF kernel instrumentation (no kernel modules)
-   Stateful detection (e.g., "alert if `/etc/shadow` is opened → then outbound connection within 5 minutes")
-   YAML rule engine with automatic hot-reload
-   IDS + optional IPS (auto-kill high-severity processes)
-   Clean JSON alerts + separate IPS action log
-   Central dashboard: https://log-manager-idsips.vercel.app
-   AI based thread detection

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
    git clone https://github.com/Sazidul0/Raqhive.git
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

## 📝 Use Cases

### Ideal for
- Linux servers & cloud VMs (Ubuntu, Debian, Rocky, etc.)  
- Kubernetes nodes & container hosts  
- Honeypots, exposed services, VPS, home labs  
- Production environments needing real-time kernel visibility  
- Compliance, audit, red/blue team exercises  
- Any system running **Linux kernel 5.4+** with root access  

### Not suitable for
- **Windows** systems (no eBPF)  
- **macOS** (limited & unstable eBPF support)  
- **Android / iOS** devices  
- **Old kernels (< 5.4)** without BTF  
- **Serverless / FaaS** environments (no host kernel access)  
- **Embedded / IoT** with locked-down or header-less kernels  
- **Air-gapped or highly restricted** systems without CAP_BPF + headers  

**In short:**  
If it’s modern Linux and you have root - Raqhive is ready.  
If it’s not Linux - look elsewhere (for now).

<div align="center">
  <strong>Linux is our domain. We protect it better than anyone.</strong>
</div>






---


## 🚀 Contributing to Raqhive

Raqhive is **open-source and community-driven** - we welcome contributions of all kinds!

Whether you're fixing a bug, adding new detection rules, improving the eBPF probe, enhancing the AI analysis, or just improving documentation - your help makes the entire ecosystem safer.

### Ways to contribute
- 🐛 **Report bugs** or suspicious false positives
- ✨ **Submit new detection rules** (especially real-world attack patterns)
- 🛠️ **Improve performance** of the eBPF program
- 🤖 **Enhance AI prompt logic** or dashboard features



### How to contribute
1. Fork the repository
2. Create a branch (`git checkout -b feature/amazing-detection`)
3. Make your changes
4. Test thoroughly (especially eBPF changes!)
5. Submit a Pull Request with a clear description




---

### License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


---
---
<div align="center">

## ✨ Show Your Support - Keep the Hive Alive

If **Raqhive** helped secure your systems, caught a threat, or saved you time -  
**please give it a star!** Every star fuels development and helps others discover it.

<br/>

<a href="https://github.com/Sazidul0/Raqhive/stargazers">
  <img src="https://img.shields.io/github/stars/Sazidul0/Raqhive?color=ffe203&label=Stars&logo=github&style=for-the-badge" alt="GitHub stars"/>
</a>
<a href="https://github.com/Sazidul0/Raqhive/fork">
  <img src="https://img.shields.io/github/forks/Sazidul0/Raqhive?color=ff8c00&label=Forks&logo=github&style=for-the-badge" alt="GitHub forks"/>
</a>
<a href="https://github.com/Sazidul0/Raqhive">
  <img src="https://img.shields.io/github/watchers/Sazidul0/Raqhive?label=Watchers&style=for-the-badge&color=8b5cf6" alt="GitHub watchers"/>
</a>

<br/><br/>

**One click makes a huge difference** - thank you for being part of the hive!

<br/>

<span style="font-size:1.2em;">
  <a href="https://github.com/Sazidul0/Raqhive">Star</a> • 
  <a href="https://github.com/Sazidul0/Raqhive/fork">Fork</a> • 
  <a href="https://github.com/Sazidul0/Raqhive/issues">Report Issue</a> • 
  <a href="https://github.com/Sazidul0/Raqhive/pulls">Contribute</a>
</span>

<br/><br/>

**A watched system is a secure system.**  
Thank you for watching with us.

</div>

---
---
