# 🚀 unifi-bnu-bridge

BitLocker Network Unlock (BNU) bridge for UniFi Express 7.

This project provides an automated installation script that deploys a persistent Python-based relay to forward DHCP/BOOTP traffic between a local LAN and a WDS server over a tunnel interface.

---

## 📋 Table of Contents

- [📖 Overview](#-overview)
- [✨ Features](#-features)
- [⚙️ Requirements](#️-requirements)
- [📦 Installation](#-installation)
- [🚀 Usage](#-usage)
- [🧠 How It Works](#-how-it-works)
- [📁 Project Structure](#-project-structure)
- [🛠️ Debug & Troubleshooting](#️-debug--troubleshooting)
- [🧹 Uninstall](#-uninstall)
- [🛡️ Security Notes](#️-security-notes)
- [📌 TODO / Improvements](#-todo--improvements)
- [📜 License](#-license)

---

## 📖 Overview

This repository allows you to deploy a **BitLocker Network Unlock relay** on a UniFi Express 7 device.

It bridges DHCP/BOOTP traffic between:
- 🌐 Local network (`br0`)
- 🔐 Tunnel interface (`tun1`)
- 🖥️ Windows Deployment Services (WDS)

This enables BitLocker Network Unlock across routed or tunneled environments where native broadcast forwarding is not possible.

---

## ✨ Features

- ⚡ One-command installation
- 🔁 Persistent execution via `udm-boot`
- 🧠 Smart detection of BitLocker DHCP requests
- 🔀 Relay between LAN and WDS over tunnel
- 📡 Broadcast rebroadcasting to clients
- 🧾 Detailed logging (file + stdout)
- 🔐 SHA-256 integrity check of deployed script
- 🛠️ Built-in dependency handling (Python, Scapy, curl)

---

## ⚙️ Requirements

- UniFi Express 7 (or compatible UniFi OS device)
- Root access (`sudo`)
- Network setup including:
  - LAN interface (`br0`)
  - Tunnel interface (`tun1`)
- Accessible WDS server (default: `192.168.5.222`)
- Internet access (for package installation)

---

## 📦 Installation

```bash
chmod +x install-bnu-express7.sh
sudo ./install-bnu-express7.sh
```

---

## 🚀 Usage

After installation:

* ✅ The bridge starts automatically at boot
* ✅ The service is managed via `udm-boot`
* ✅ Logs are available in:

```bash
/data/bnu-proxy/bnu-bridge.log
/data/bnu-proxy/bnu-bridge.stdout
```

To check status:

```bash
systemctl status udm-boot
pgrep -af bnu_bridge.py
```

---

## 🧠 How It Works

### 🔍 Detection

The Python script listens for DHCP/BOOTP packets and detects BitLocker requests using:

* Presence of `BITLOCKER` in payload
* DHCP magic cookie (`0x63825363`)
* Destination UDP port 67

---

### 🔁 Forwarding (LAN → WDS)

When a valid request is detected:

* The packet is modified:

  * `hops` incremented
  * `siaddr` set to WDS
  * `giaddr` set to relay IP
* Sent to WDS via `tun1`

---

### 📡 Response Handling (WDS → LAN)

* Replies from WDS are validated
* Only matching `xid` are accepted
* Responses are rebroadcast on LAN (`br0`)
* Destination: `255.255.255.255`

---

### 🧠 State Tracking

* Maintains a table of pending requests (`xid`)
* Prevents unsolicited or malicious responses
* Automatic cleanup after 30 seconds

---

## 📁 Project Structure

```
.
├── install-bnu-express7.sh   # Main installer script
├── commandes_helpers.txt    # Debug / cleanup commands
├── README.md                # Documentation
└── .gitattributes           # Git configuration
```

Deployed files:

```
/data/bnu-proxy/
├── bnu_bridge.py
├── bnu_bridge.py.ok
├── bnu_bridge.sha256
├── bnu-bridge.log
└── bnu-bridge.stdout

/data/on_boot.d/
└── 22-bnu-bridge.sh
```

---

## 🛠️ Debug & Troubleshooting

### 📜 Live logs

```bash
tail -f /data/bnu-proxy/bnu-bridge.log
```

---

### 📡 Packet capture (LAN)

```bash
tcpdump -ni br0 -vvv -e -s0 \
'((udp port 67 or udp port 68 or udp port 4011))'
```

---

### 📡 Packet capture (Tunnel)

```bash
tcpdump -ni tun1 -vvv -e -s0 \
'(udp port 67 or udp port 68 or udp port 4011)'
```

---

### ⚠️ Common issues

* ❌ No traffic → check interfaces (`br0`, `tun1`)
* ❌ No response → verify WDS accessibility
* ❌ Service not running → check `udm-boot`
* ❌ Missing Scapy → ensure `apt-get` works

---

## 🧹 Uninstall

Use the helper commands:

```bash
sh commandes_helpers.txt
```

This will:

* 🛑 Stop the bridge
* 🗑️ Remove scripts and files
* 🔧 Disable `udm-boot`
* 🧹 Clean routes and cache

---

## 🛡️ Security Notes

* 🔐 Only responses matching known requests are accepted
* 🧠 Prevents unsolicited DHCP injection
* ⚠️ Requires root privileges
* 🌐 Ensure your WDS server is secured and trusted

---

## 📌 TODO / Improvements

* [ ] Multi-WDS support
* [ ] Configurable interfaces via CLI/env
* [ ] Enhanced logging levels
* [ ] Systemd-native service alternative
* [ ] Metrics / monitoring integration

---

## 👨‍💻 Author

Developed by Lukas MAUFFRÉ  
🚀 Cybersecurity & Infrastructure Engineering  
Information Systems Department (UFCV)

---

## 📜 License

**UFCV DSI – Infrastructure & Systems**

This repository is intended for internal professional use within an organizational context.

All rights reserved.  
Unauthorized use, reproduction, modification, or distribution outside the company or authorized scope is prohibited without prior permission.
