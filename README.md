# NetSentry Lite

## What it does
NetSentry Lite watches live network traffic and raises alerts for simple attack patterns such as port scans, SYN floods, and ICMP floods.

---

## How it works

The script uses **Scapy** to capture every packet passing through your network card. For each packet, it checks three danger patterns within a 5-second time window:

### Alert 1: Port Scan Detection
**What is it?** An attacker tries to connect to many different ports on your machine to find open services.

**How we detect it:** If a single IP address tries to connect to more than **10 different ports** within 5 seconds → **ALERT: Port Scan Detected!**

### Alert 2: SYN Flood Detection
**What is it?** A SYN flood is a type of DoS (Denial of Service) attack. TCP connections start with a SYN packet (short for "synchronize"). Attackers send thousands of SYN packets without ever finishing the connection, exhausting the server.

**How we detect it:** If a single IP sends more than **20 SYN packets** without completing connections within 5 seconds → **ALERT: SYN Flood!**

### Alert 3: ICMP Flood Detection
**What is it?** ICMP packets are "ping" messages. An attacker can flood a target with pings to overload it (called a "Ping Flood" or "Smurf Attack").

**How we detect it:** If a single IP sends more than **15 ICMP packets** within 5 seconds → **ALERT: ICMP Flood!**

---

## Implementation notes
* `scapy.sniff(prn=callback, filter="ip")`: Sniffs live packets and runs your function on each one.
* `defaultdict(set)` / `defaultdict(int)`: Efficiently tracks counts and sets per IP address.
* BPF Filter `"ip"`: Drops all non-IP frames at the kernel level before Python processes them.

---

## Running it

### Install Scapy:
```bash
pip install -r requirements.txt
```

### Run as Administrator (required for packet capture):
```bash
python network_intrusion_detector.py
```
*On Windows: Right-click PowerShell → Run as Administrator, then execute the script.*

---

## 🔐 Real-World Use
This is a simplified version of **Snort** and **Suricata** — two of the most famous real-world IDS tools used by companies worldwide.


