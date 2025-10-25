"""
sniffer.py

- Prefers the Wi-Fi interface (tries exact "Wi-Fi" first, then looks for common Wi-Fi keywords).
- Prints available interfaces and the chosen one.
- Keeps your anomaly detection logic (SYN/ICMP/UDP/HTTP/Port-scan/unusual-protocol).
- Runs tracker reset in a background thread.
- Handles errors with helpful messages.

Requirements:
    pip install scapy psutil
    Install Npcap on Windows and run this script as Administrator.
"""
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, conf
from collections import defaultdict, Counter
from database import log_packet
from alerts import send_alert
from config import (
    ALERT_THRESHOLD,
    WHITELISTED_PROTOCOLS,
    ALERT_TIME_WINDOW,
)
import threading
import time
import psutil
import sys

# -----------------------
# Trackers for anomalies
# -----------------------
port_scan_tracker = defaultdict(set)
syn_flood_tracker = defaultdict(int)
icmp_flood_tracker = defaultdict(int)
udp_flood_tracker = defaultdict(int)
http_flood_tracker = defaultdict(int)
protocol_tracker = Counter()

# -----------------------
# Packet processing
# -----------------------
def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        length = len(packet)
        src_port = dst_port = flags = None

        # Track protocol usage
        protocol_tracker[protocol] += 1
        if ALERT_THRESHOLD.get("unusual_protocol") and protocol not in WHITELISTED_PROTOCOLS:
            send_alert(f"⚠️ Unusual protocol detected from {src_ip}: Protocol {protocol}")

        # TCP packets
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags

            # SYN flood detection (S without A)
            try:
                if "S" in flags and "A" not in flags:
                    syn_flood_tracker[src_ip] += 1
                    if syn_flood_tracker[src_ip] > ALERT_THRESHOLD["syn_flood"]:
                        send_alert(f"🚨 SYN flood detected from {src_ip}")
                        syn_flood_tracker[src_ip] = 0
            except Exception:
                # flags may be of a type that doesn't support "in" checks; ignore safely
                pass

            # Port scan detection
            port_scan_tracker[src_ip].add(dst_port)
            if len(port_scan_tracker[src_ip]) > ALERT_THRESHOLD["port_scan"]:
                send_alert(f"🚨 Port scan detected from {src_ip}")
                port_scan_tracker[src_ip].clear()

            # HTTP flood detection (ports 80 / 443)
            if dst_port in (80, 443):
                http_flood_tracker[src_ip] += 1
                if http_flood_tracker[src_ip] > ALERT_THRESHOLD["http_flood"]:
                    send_alert(f"🚨 HTTP flood detected from {src_ip}")
                    http_flood_tracker[src_ip] = 0

        # UDP packets
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            udp_flood_tracker[src_ip] += 1
            if udp_flood_tracker[src_ip] > ALERT_THRESHOLD["udp_flood"]:
                send_alert(f"🚨 UDP flood detected from {src_ip}")
                udp_flood_tracker[src_ip] = 0

        # ICMP packets
        elif ICMP in packet:
            icmp_flood_tracker[src_ip] += 1
            if icmp_flood_tracker[src_ip] > ALERT_THRESHOLD["icmp_flood"]:
                send_alert(f"🚨 ICMP flood detected from {src_ip}")
                icmp_flood_tracker[src_ip] = 0

        # Log every packet (db schema assumed handled in database.log_packet)
        try:
            log_packet(src_ip, dst_ip, src_port, dst_port, protocol, length, flags)
        except Exception as e:
            # Fail-safe: don't crash sniffer if logging/database has an error
            print(f"[!] log_packet error: {e}")


# -----------------------
# Reset trackers thread
# -----------------------
def reset_trackers():
    """Reset rate-based trackers every ALERT_TIME_WINDOW seconds."""
    while True:
        time.sleep(ALERT_TIME_WINDOW)
        syn_flood_tracker.clear()
        icmp_flood_tracker.clear()
        udp_flood_tracker.clear()
        http_flood_tracker.clear()


# -----------------------
# Interface selection
# -----------------------
def choose_wifi_interface(preferred_name="Wi-Fi"):
    """
    Return a Wi-Fi interface name if available.

    Strategy:
    1) If 'preferred_name' exists in get_if_list() -> use it.
    2) Search for interfaces that contain common Wi-Fi keywords (case-insensitive).
    3) Fallback to Scapy's conf.iface (default) if nothing found.
    """
    interfaces = get_if_list()
    print("[*] Available interfaces:", interfaces)

    # 1) Exact preferred match
    for ifname in interfaces:
        if ifname == preferred_name:
            return ifname

    # 2) Heuristic search for wifi-like names
    wifi_keywords = ["wi-fi", "wifi", "wireless", "wlan"]
    for ifname in interfaces:
        lname = ifname.lower()
        if any(k in lname for k in wifi_keywords):
            return ifname

    # 3) Try psutil to pick an 'up' non-loopback interface that seems wireless (best-effort)
    try:
        stats = psutil.net_if_stats()
        for ifname, s in stats.items():
            if s.isup and "loop" not in ifname.lower():
                # prefer ones with wifi keywords
                lname = ifname.lower()
                if any(k in lname for k in wifi_keywords):
                    return ifname
        # if none matched heuristics, pick first up non-loopback interface
        for ifname, s in stats.items():
            if s.isup and "loop" not in ifname.lower():
                return ifname
    except Exception:
        pass

    # 4) fallback
    return conf.iface


# -----------------------
# Start sniffer
# -----------------------
def start_sniffer(force_interface_name=None):
    """
    If force_interface_name is provided, try to use it verbatim; otherwise choose Wi-Fi heuristically.
    """
    if force_interface_name:
        chosen_iface = force_interface_name
    else:
        chosen_iface = choose_wifi_interface(preferred_name="Wi-Fi")

    print(f"[*] Using interface: '{chosen_iface}'")
    print("[*] Starting packet sniffer... (Ctrl+C to stop)")

    # start tracker reset thread
    t = threading.Thread(target=reset_trackers, daemon=True)
    t.start()

    try:
        sniff(iface=chosen_iface, prn=process_packet, store=False)
    except PermissionError:
        print("❌ Permission denied. Please run this script as Administrator.")
        sys.exit(1)
    except OSError as e:
        print(f"❌ Error opening adapter '{chosen_iface}': {e}")
        print("💡 Tip: run 'from scapy.all import get_if_list; print(get_if_list())' to see valid interface names.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)


# -----------------------
# Entry point
# -----------------------
if __name__ == "__main__":
    # If you want to force a specific interface name regardless of heuristics, set it here:
    # e.g. force_iface = "Wi-Fi" or "Wi-Fi 3"
    force_iface = None

    # If you explicitly want to force "Wi-Fi", uncomment the next line:
    # force_iface = "Wi-Fi"

    start_sniffer(force_interface_name=force_iface)
