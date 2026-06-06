#!/usr/bin/env python3
"""
=============================================================================
  EDUCATIONAL BASIC NETWORK INTRUSION DETECTOR
  File   : network_intrusion_detector.py
  Author : Educational Demo
  Target : Loopback / local interface only
  Requires: scapy  (pip install scapy)
            Run as Administrator / root (raw-socket capture needs elevated privs)
=============================================================================

EDUCATIONAL OVERVIEW
--------------------

What is an IDS / IPS?
~~~~~~~~~~~~~~~~~~~~~
An Intrusion Detection System (IDS) passively watches network traffic and
ALERTS when it spots something suspicious -- like a smoke detector that beeps
but doesn't call the fire department for you.

An Intrusion Prevention System (IPS) goes one step further: it can actively
BLOCK or DROP the suspicious packets in real time, like a sprinkler system
that also puts out the fire.

How is an IDS/IPS different from a firewall?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
A firewall works on RULES set in advance:
  "Block all traffic from port 23" -- simple allow/deny lists.

An IDS/IPS watches the BEHAVIOUR of traffic over time:
  "This IP just hit 200 different ports in 2 seconds -- that looks like a scan!"
It can detect sophisticated attacks that slip past a simple firewall because
the individual packets look legitimate on their own.

The Three Detection Families
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1. Signature / Pattern-based  <- what this script uses
   Maintains known-bad patterns (e.g., port-scan rate thresholds) and raises
   an alert when traffic matches. Fast and precise for known attacks; blind to
   novel (zero-day) ones.

2. Anomaly / Statistical-based
   Learns a "normal" baseline first, then flags deviations. Can catch new
   attacks but produces more false positives during the learning period.

3. Heuristic / Behaviour-based
   Uses rules-of-thumb about what malicious behaviour LOOKS like (e.g., a
   process that opens a socket AND writes to disk AND starts a child process
   is suspicious). Common in modern EDR / endpoint products.

What is a Port Scan?
~~~~~~~~~~~~~~~~~~~~~
An attacker probes many destination ports on a target to see which ones are
open (i.e., which services are running). Think of it as knocking on every
door of a building to find which ones are unlocked. Nmap is the classic tool.
Signature: one source IP -> many DIFFERENT destination ports in a short window.

What is a SYN Flood?
~~~~~~~~~~~~~~~~~~~~~
TCP uses a three-way handshake to set up a connection:
  Client -> SYN  -> Server
  Client <- SYN-ACK <- Server
  Client -> ACK  -> Server
In a SYN flood the attacker sends HUGE numbers of SYN packets but never
completes the handshake. Each half-open connection consumes server memory.
When thousands pile up, the server can't accept real connections -- a classic
Denial-of-Service (DoS) attack.
Signature: one source IP -> many SYN packets (TCP flag "S") in a short window.

What is an ICMP Flood (Ping Flood)?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ICMP Echo Requests ("pings") are used to test connectivity. An attacker can
flood a target with thousands of pings per second to saturate its bandwidth
or CPU -- another DoS technique.
Signature: one source IP -> many ICMP packets in a short window.

=============================================================================
"""

import sys
import time
import datetime
import argparse
from collections import defaultdict

# ---------------------------------------------------------------------------
# Scapy import -- scapy is a powerful Python packet-crafting/sniffing library.
# It can read raw network frames at the kernel level, which is why we need
# Administrator / root privileges.
# ---------------------------------------------------------------------------
try:
    from scapy.all import sniff, IP, TCP, ICMP
    from scapy.error import Scapy_Exception
except ImportError:
    sniff = IP = TCP = ICMP = Scapy_Exception = None


# =============================================================================
#  CONFIGURATION -- tweak these thresholds to change sensitivity
# =============================================================================

# Time window (in seconds) over which we measure packet rates.
# All counters are reset every WINDOW_SECONDS.
WINDOW_SECONDS = 5

# --- Port Scan ---
# Alert when a single source IP connects to MORE than this many unique
# destination ports within one time window.
PORT_SCAN_THRESHOLD = 10

# --- SYN Flood ---
# Alert when a single source IP sends MORE than this many TCP SYN packets
# within one time window.
SYN_FLOOD_THRESHOLD = 20

# --- ICMP Flood ---
# Alert when a single source IP sends MORE than this many ICMP packets
# within one time window.
ICMP_FLOOD_THRESHOLD = 15

# Interface to sniff on.  None = Scapy picks the default interface.
# Change to e.g. "Ethernet", "Wi-Fi", "lo" as needed.
INTERFACE = None


# =============================================================================
#  STATE -- data structures that accumulate per-window statistics
# =============================================================================

# Total packets seen since the script started.
packet_counter = 0

# Timestamp (epoch seconds) when the current measurement window opened.
window_start = time.time()

# --- Port scan tracking ---
# Maps  source_IP  ->  set of unique destination ports seen this window.
port_scan_tracker = defaultdict(set)

# --- SYN flood tracking ---
# Maps  source_IP  ->  count of SYN packets seen this window.
syn_flood_tracker = defaultdict(int)

# --- ICMP flood tracking ---
# Maps  source_IP  ->  count of ICMP packets seen this window.
icmp_flood_tracker = defaultdict(int)

# Keep track of which alerts we have already printed this window so we do not
# spam the console with the same alert hundreds of times.
alerts_fired = set()


# =============================================================================
#  HELPER FUNCTIONS
# =============================================================================

def get_timestamp():
    """Return a human-readable timestamp for alert messages."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def reset_window():
    """
    Clear all per-window counters and mark the start of the next window.
    Called once per WINDOW_SECONDS.
    """
    global window_start, port_scan_tracker, syn_flood_tracker
    global icmp_flood_tracker, alerts_fired

    window_start        = time.time()
    port_scan_tracker   = defaultdict(set)
    syn_flood_tracker   = defaultdict(int)
    icmp_flood_tracker  = defaultdict(int)
    alerts_fired        = set()


def fire_alert(alert_type, src_ip, count, explanation):
    """
    Print a formatted alert to stdout.

    Parameters
    ----------
    alert_type  : short label, e.g. "PORT SCAN DETECTED"
    src_ip      : offending source IP address
    count       : the metric that triggered the alert (packets, ports, etc.)
    explanation : one-sentence plain-English description of the attack
    """
    # Build a unique key so we only print each alert once per window.
    alert_key = (alert_type, src_ip)
    if alert_key in alerts_fired:
        return

    alerts_fired.add(alert_key)

    # Build the alert banner.
    border = "=" * 70
    print(f"\n{border}")
    print(f"  [ALERT]  {alert_type}")
    print(f"  Time    : {get_timestamp()}")
    print(f"  Source  : {src_ip}")
    print(f"  Count   : {count}  (within the last {WINDOW_SECONDS}s window)")
    print(f"  Meaning : {explanation}")
    print(f"{border}\n")


# =============================================================================
#  PACKET HANDLER -- called by Scapy for every captured packet
# =============================================================================

def process_packet(packet):
    """
    Core IDS logic.  Scapy calls this function once for every packet that
    arrives on the monitored interface.

    The function:
      1. Increments the global packet counter.
      2. Checks whether the current time window has expired; resets if so.
      3. Applies each detection rule in turn.
    """
    global packet_counter

    # -------------------------------------------------------------------------
    # Step 1 -- Count every packet regardless of protocol.
    # -------------------------------------------------------------------------
    packet_counter += 1

    # Print a lightweight progress line every 50 packets so the user knows
    # the tool is alive even when no attacks are detected.
    if packet_counter % 50 == 0:
        elapsed = time.time() - window_start
        print(f"[INFO]  Packets captured: {packet_counter}  |  "
              f"Window: {elapsed:.1f}s / {WINDOW_SECONDS}s")

    # -------------------------------------------------------------------------
    # Step 2 -- Rolling time window reset.
    # If WINDOW_SECONDS have elapsed since the last reset, start a fresh window.
    # All counters reset to zero so old traffic does not accumulate indefinitely.
    # -------------------------------------------------------------------------
    if time.time() - window_start >= WINDOW_SECONDS:
        reset_window()

    # -------------------------------------------------------------------------
    # Step 3 -- Only analyse packets that have an IP layer.
    # Raw Ethernet broadcasts, ARP frames, etc. do not carry an IP source address
    # so we cannot attribute them to a particular host.
    # -------------------------------------------------------------------------
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src  # The IP address of the sender.

    # =========================================================================
    #  RULE 1: PORT SCAN DETECTION
    # =========================================================================
    # A port scanner probes many ports rapidly looking for open services.
    # We detect this by tracking the SET of unique destination ports contacted
    # by each source IP within the window.  A set ignores duplicates, so
    # retransmits do not inflate the count -- we only care about *unique* ports.
    # =========================================================================
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport   # Destination port the sender is targeting.
        port_scan_tracker[src_ip].add(dst_port)

        unique_ports = len(port_scan_tracker[src_ip])
        if unique_ports > PORT_SCAN_THRESHOLD:
            fire_alert(
                alert_type="PORT SCAN DETECTED",
                src_ip=src_ip,
                count=unique_ports,
                explanation=(
                    "This IP has probed many different ports rapidly. "
                    "Port scanning is a reconnaissance technique attackers use "
                    "to discover open services before mounting an attack."
                )
            )

    # =========================================================================
    #  RULE 2: SYN FLOOD DETECTION
    # =========================================================================
    # TCP connections start with a SYN packet (the 'S' flag).  An attacker can
    # send thousands of SYNs without completing the handshake, exhausting the
    # target's connection table -- a Denial-of-Service attack.
    #
    # Scapy represents TCP flags as a FlagValue object.
    # We check for the 'S' (SYN) flag being set while 'A' (ACK) is NOT set,
    # which identifies pure SYN packets (not SYN-ACK replies from servers).
    #   flags & 0x02  -> SYN bit
    #   flags & 0x10  -> ACK bit
    # =========================================================================
    if packet.haslayer(TCP):
        tcp_flags = packet[TCP].flags
        is_syn    = bool(tcp_flags & 0x02)
        is_ack    = bool(tcp_flags & 0x10)

        if is_syn and not is_ack:
            syn_flood_tracker[src_ip] += 1
            syn_count = syn_flood_tracker[src_ip]

            if syn_count > SYN_FLOOD_THRESHOLD:
                fire_alert(
                    alert_type="SYN FLOOD DETECTED",
                    src_ip=src_ip,
                    count=syn_count,
                    explanation=(
                        "This IP is sending many TCP SYN packets without completing "
                        "the handshake. A SYN flood is a Denial-of-Service (DoS) attack "
                        "designed to exhaust the target server's connection resources."
                    )
                )

    # =========================================================================
    #  RULE 3: ICMP FLOOD DETECTION
    # =========================================================================
    # ICMP (Internet Control Message Protocol) is used for ping/traceroute.
    # A ping flood overwhelms the target with Echo Requests, consuming bandwidth
    # and CPU -- a simple but effective DoS method.
    # =========================================================================
    if packet.haslayer(ICMP):
        icmp_flood_tracker[src_ip] += 1
        icmp_count = icmp_flood_tracker[src_ip]

        if icmp_count > ICMP_FLOOD_THRESHOLD:
            fire_alert(
                alert_type="ICMP FLOOD DETECTED",
                src_ip=src_ip,
                count=icmp_count,
                explanation=(
                    "This IP is sending an excessive number of ICMP (ping) packets. "
                    "An ICMP flood is a volumetric Denial-of-Service attack that can "
                    "saturate network bandwidth or overwhelm a host's network stack."
                )
            )


# =============================================================================
#  MAIN ENTRY POINT
# =============================================================================

def main():
    """
    Start the sniffer and handle top-level errors gracefully.

    Scapy's sniff() function enters a loop, captures packets from the chosen
    interface, and calls process_packet() for each one.  It runs until the
    user presses Ctrl-C (KeyboardInterrupt).
    """

    parser = argparse.ArgumentParser(
        description="Pattern-based network intrusion detector for port scans, SYN floods, and ICMP floods."
    )
    parser.add_argument(
        "-i", "--interface",
        default=INTERFACE,
        help="Network interface to sniff on. Defaults to Scapy's auto-selected interface."
    )
    args = parser.parse_args()

    if sniff is None:
        print("[ERROR] Scapy is not installed.", file=sys.stderr)
        print("[INFO] Install it with: pip install -r requirements.txt", file=sys.stderr)
        print("[INFO] On Windows, install Npcap as well: https://npcap.com/", file=sys.stderr)
        sys.exit(1)

    print("=" * 70)
    print("  EDUCATIONAL NETWORK INTRUSION DETECTOR")
    print("  Pattern-based IDS -- Port Scan / SYN Flood / ICMP Flood")
    print("=" * 70)
    print(f"  Thresholds (per {WINDOW_SECONDS}s window):")
    print(f"    Port Scan  : >{PORT_SCAN_THRESHOLD} unique destination ports")
    print(f"    SYN Flood  : >{SYN_FLOOD_THRESHOLD} SYN packets")
    print(f"    ICMP Flood : >{ICMP_FLOOD_THRESHOLD} ICMP packets")
    print(f"  Interface   : {args.interface or 'default (auto-detected)'}")
    print("  Press Ctrl-C to stop.\n")

    try:
        # -----------------------------------------------------------------------
        # sniff() -- Scapy's packet capture function.
        #
        # prn=process_packet  -> our callback is invoked for every captured frame.
        # store=False         -> do NOT store packets in memory; we only need the
        #                        callback, not a replay buffer. Keeps RAM low.
        # iface=INTERFACE     -> which network adapter to listen on.
        #                        None = Scapy auto-selects the default interface.
        # filter="ip"         -> BPF filter: only pass IP packets to the kernel-
        #                        level capture, dropping raw Ethernet frames before
        #                        they reach Python. Reduces CPU on busy networks.
        # -----------------------------------------------------------------------
        sniff(
            prn=process_packet,
            store=False,
            iface=args.interface,
            filter="ip",
        )

    except PermissionError:
        # Raw-socket capture requires Administrator on Windows / root on Linux.
        # If the user forgot, give a clear actionable message instead of a
        # cryptic traceback.
        print("\n[ERROR] Permission denied -- raw socket capture requires elevated privileges.")
        print("        On Windows : Right-click the terminal -> 'Run as Administrator'")
        print("        On Linux   : Run with  sudo python network_intrusion_detector.py")
        print("        On macOS   : Run with  sudo python network_intrusion_detector.py\n")
        sys.exit(1)

    except OSError as exc:
        # This can happen if the specified interface name does not exist.
        print(f"\n[ERROR] Could not open interface: {exc}")
        print("        Check INTERFACE at the top of this script.")
        print("        Use Scapy's  conf.ifaces  to list available interfaces.\n")
        sys.exit(1)

    except Scapy_Exception as exc:
        print(f"\n[ERROR] Scapy error: {exc}\n")
        sys.exit(1)

    except KeyboardInterrupt:
        # Ctrl-C -- clean shutdown.
        print(f"\n\n[INFO]  Capture stopped by user.")
        print(f"[INFO]  Total packets captured: {packet_counter}")
        print("[INFO]  Goodbye!\n")
        sys.exit(0)


# =============================================================================
#  Script entry guard -- only run main() when executed directly, not when
#  imported as a module.
# =============================================================================
if __name__ == "__main__":
    main()
