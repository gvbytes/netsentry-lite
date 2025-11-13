# 🦅 Network Intrusion Detector (`network_intrusion_detector.py`)

## 💡 What is it?
This tool watches live network traffic on your computer and raises an alarm when it spots attack patterns — like someone doing a port scan, flooding you with connection requests, or bombarding you with pings.

---

## 🚪 The Analogy
Imagine a security camera at the entrance of a building. Unlike a **firewall** (a locked door that blocks visitors), the **Network Intrusion Detector** is a *camera + alarm system*. It watches everything that enters and sets off an alarm when it sees suspicious behavior — like the same person trying to open 50 different doors in 5 seconds.

### IDS vs Firewall vs IPS:
| Tool | What it does |
|---|---|
| **Firewall** | Blocks/allows traffic based on rules. Like a locked door. |
| **IDS** | Watches traffic and alerts. Like a security camera with an alarm. |
| **IPS** | Watches AND automatically blocks. Like a camera that also locks the door. |

---

## ⚙️ How it Works

The tool uses **Scapy** to capture every packet passing through your network card. For each packet, it checks three danger patterns within a 5-second time window:

### 🔴 Alert 1: Port Scan Detection
**What is it?** An attacker tries to connect to many different ports on your machine to find open services.

**How we detect it:** If a single IP address tries to connect to more than **10 different ports** within 5 seconds → **ALERT: Port Scan Detected!**

### 🔴 Alert 2: SYN Flood Detection
**What is it?** A SYN flood is a type of DoS (Denial of Service) attack. TCP connections start with a SYN packet (short for "synchronize"). Attackers send thousands of SYN packets without ever finishing the connection, exhausting the server.

**How we detect it:** If a single IP sends more than **20 SYN packets** without completing connections within 5 seconds → **ALERT: SYN Flood!**

### 🔴 Alert 3: ICMP Flood Detection
**What is it?** ICMP packets are "ping" messages. An attacker can flood a target with pings to overload it (called a "Ping Flood" or "Smurf Attack").

**How we detect it:** If a single IP sends more than **15 ICMP packets** within 5 seconds → **ALERT: ICMP Flood!**

---

## 🛠️ Key Code Concepts
* `scapy.sniff(prn=callback, filter="ip")`: Sniffs live packets and runs your function on each one.
* `defaultdict(set)` / `defaultdict(int)`: Efficiently tracks counts and sets per IP address.
* BPF Filter `"ip"`: Drops all non-IP frames at the kernel level before Python processes them.

---

## 🚀 How to Run

### Install Scapy:
```bash
pip install scapy
```

### Run as Administrator (required for packet capture):
```bash
python network_intrusion_detector.py
```
*On Windows: Right-click PowerShell → Run as Administrator, then execute the script.*

---

## 🔐 Real-World Use
This is a simplified version of **Snort** and **Suricata** — two of the most famous real-world IDS tools used by companies worldwide.
