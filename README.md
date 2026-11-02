# AEGIS // Host-Level XDR & Active Deception Platform

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-00e5ff?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20%7C%20Linux-lightgrey?style=flat-square)](https://microsoft.com)
[![Architecture](https://img.shields.io/badge/Architecture-Modular%20EDR%2FXDR-red?style=flat-square)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-00ff66?style=flat-square)](LICENSE)

```text
    ___    ______ _____ ____ _____
   /   |  / ____// ___//  _// ___/
  / /| | / __/  / / __ / /  \__ \ 
 / ___ |/ /___ / /_/ // /  ___/ / 
/_/  |_/_____/ \____/___/ /____/  
   [ Host-Level Endpoint Detection, Forensic Telemetry & Autonomous Response ]
```

**AEGIS** is a modular, zero-dependency Host-Level Endpoint Detection and Response (EDR) platform designed for real-time behavioral telemetry, active deception (canary files and multi-port honeypots), hardware access enforcement, and automated incident mitigation.

---

## System Architecture

```text
                           +------------------------+
                           |  Correlation Engine    | <--- Scoring & Decay (1.5s)
                           |  (core/engine.py)      | ---> Autonomous Response
                           +-----------+------------+
                                       |
    +------------------+---------------+----------------+------------------+
    |                  |                                |                  |
[Sensors]          [Deception]                      [Hardware]         [Mitigation]
- Behavior Watch   - Canary Traps (Entropy > 7.2)   - PnP USB Audit    - Suspend / Terminate
- RWX Memory Scan  - Honeypot Ports (21,22,80,3306) - JIT Override     - XOR Quarantine (.vir)
- Socket Sniffer   - Brute-Force Extraction         - SetupAPI Log     - NetFirewall Block
```

---

## Key Defense Vectors

* **Process Memory & Heuristics (`sensors/behavior_sensor.py`):**
  * Direct inspection of committed `PAGE_EXECUTE_READWRITE` memory via Windows API (`VirtualQueryEx`, `ReadProcessMemory`).
  * Real-time detection of payload artifacts (`mimikatz`, `beacon.dll`, `metasploit`).
  * Pattern inspection: double extensions (`.pdf.exe`), temporary path executions (`%TEMP%`, `%APPDATA%`), and LOLBin abuse (`certutil`, `bitsadmin`, `mshta`).

* **Active Anti-Ransomware Decoys (`sensors/canary_sensor.py`):**
  * High-priority hidden files (`_critical_ledger.docx`, `00_database_backup.db`, `0_auth_vault.txt`) monitored at a 50ms interval.
  * Mathematical **Shannon Entropy calculation** (threshold > 7.2 bits/byte) to distinguish legitimate writes from encrypted payloads.
  * Process attribution with fallback write-rate tracking to eliminate file-closure blind spots.

* **Perimeter Deception & Host IPS (`sensors/deception_sensor.py`):**
  * Emulated protocol listeners for FTP (21), SSH (22), HTTP (80), and MySQL (3306).
  * Payload and credential interception.
  * Automated host-firewall blacklisting (`New-NetFirewallRule` / `iptables`) upon reaching intrusion thresholds.

* **Peripheral Lockdown & Forensic Timeline (`sensors/usb_sensor.py`):**
  * Deep Windows registry analysis (`USBSTOR`, `Enum\USB`) correlated with `setupapi.dev.log` for initial connection timestamps.
  * Default-Deny PnP device disabling (`Disable-PnpDevice`) to neutralize unauthorized BadUSB / Rubber Ducky hardware.
  * Cryptographic JIT (Just-In-Time) temporary access override backed by salted password authentication.

* **Autonomous Containment Pipeline (`mitigation/`):**
  * Target process tree suspension to prevent cascading payload execution.
  * Extraction and XOR encryption (`0x5A`) of binaries into an isolated quarantine storage (`EDR_Quarantine/*.vir`) with a 100 MB automatic quota.
  * Autorun registry persistence cleanup across `HKCU` and `HKLM` Run keys.
  * Final process tree termination.

---

## Detection & Scoring Matrix

| Indicator ID | Trigger Description | Default Weight | Response Vector |
| :--- | :--- | :---: | :--- |
| `RANSOMWARE_INHIBIT_RECOVERY` | System recovery manipulation (`vssadmin delete shadows`, `bcdedit`) | **+100 pts** | Process Tree Terminated |
| `HIGH_ENTROPY_CANARY_ALTERATION` | Canary file modification with Shannon Entropy >= 7.2 | **+100 pts** | Process Tree Terminated & XOR Isolated |
| `KNOWN_MALICIOUS_HASH` | Binary SHA-256 matches threat intelligence database | **+100 pts** | Immediate Quarantine |
| `MALICIOUS_MEMORY_SIGNATURE` | Payload signature found in RWX memory (`VirtualQueryEx`) | **+90 pts** | Process Tree Terminated |
| `SUSPICIOUS_PARENT_CHILD` | Shell/Script spawner from untrusted parent (Office, Browser -> PowerShell) | **+50 pts** | Score Escalation |
| `REGISTRY_PERSISTENCE` | Untrusted binary registered in Run/RunOnce keys | **+40 pts** | Persistence Cleaned & Logged |
| `TEMP_DIR_EXEC_PATH` | Process executed from `%TEMP%`, `/tmp/`, or Local AppData | **+40 pts** | Score Escalation |
| `EVASION_PATH_PATTERN` | Masquerading extension pattern (`.exe.exe`, `.pdf.exe`, RecycleBin) | **+35 pts** | Score Escalation |
| `EXTERNAL_TCP_ESTABLISHED` | Non-browser process established external TCP connection | **+25 pts** | Sockets Indexed |

*Threshold for autonomous mitigation: **100 points** (customizable in `config.json`).*

---

## Repository Structure

```text
AEGIS/
├── core/
│   ├── database.py             # SQLite persistence, whitelist storage, and event logging
│   ├── engine.py               # Central correlation engine, decay loop, and scoring
│   └── event_bus.py            # Async pub/sub event bus with SSE client multiplexing
├── dashboard/
│   ├── app.js                  # High-contrast DOM-diffing controller, filter, and stream bridge
│   ├── index.html              # Monospace pitch-black SOC operations interface
│   └── server.py               # Threaded HTTP server, REST endpoints, and telemetry router
├── mitigation/
│   ├── firewall_blocker.py     # Automated NetFirewall / iptables ban engine
│   ├── process_killer.py       # Tree suspension, autorun registry purge, and termination
│   └── quarantine.py           # XOR (0x5A) isolation subsystem with quota enforcement
├── sensors/
│   ├── behavior_sensor.py      # Path, hash, parent-child, and RWX memory inspector
│   ├── canary_sensor.py        # Shannon entropy ransomware tripwires
│   ├── deception_sensor.py     # Low-interaction honeypots (FTP, SSH, HTTP, MySQL)
│   ├── net_sensor.py           # Socket sniffer, reputation scoring, and ARP subnet auditor
│   └── usb_sensor.py           # SetupAPI/USBSTOR hardware analyzer and PnP lockdown
├── aegis.py                    # Root orchestrator with auto-elevation routines
├── config.json                 # Global thresholds, honeypot ports, and sensor timings
├── requirements.txt            # Python dependencies (psutil)
└── run.bat                     # Verified one-click launcher for Windows
```

---

## Quick Start

### 1. Requirements
* Python 3.8+ (64-bit recommended)
* Administrator privileges (required for PnP device lockdown, memory reads, and firewall rules)

### 2. Installation
Clone the repository and install the single dependency:
```bash
git clone https://github.com/d3fuse99/AEGIS.git
cd AEGIS
pip install -r requirements.txt
```

### 3. Execution
Launch natively on Windows:
```bash
# Via double-click:
run.bat

# Or via Command Line (elevated):
python aegis.py
```

*The core engine will verify administrative privileges, initialize the local SQLite ledger, arm all sensors, and launch the dark-mode SOC dashboard at `http://127.0.0.1:8080`.*

---

## Configuration (`config.json`)

All heuristic weights, decoy lists, honeypot bindings, and decay timings can be tuned without modifying the codebase:

```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 8080
  },
  "threat_engine": {
    "global_threshold": 100,
    "decay_rate": 5,
    "decay_interval_sec": 3.0
  },
  "sensors": {
    "behavior": {
      "enabled": true,
      "interval_sec": 1.5,
      "points_memory_signature": 90
    },
    "canary": {
      "entropy_threshold": 7.2
    },
    "deception": {
      "threat_limit": 10
    }
  }
}
```

---

## Disclaimer
This software is developed strictly for defensive infrastructure monitoring, host forensics, and cybersecurity research. Running active mitigation engines on production environments should only be performed with proper authorization.
