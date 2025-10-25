from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict, Counter
from database import log_packet
from alerts import send_alert
from config import (
    ALERT_THRESHOLD,
    WHITELISTED_PROTOCOLS,
    ALERT_TIME_WINDOW,
)
import time

# Anomaly trackers
port_scan_tracker = defaultdict(set)
syn_flood_tracker = defaultdict(int)
icmp_flood_tracker = defaultdict(int)
udp_flood_tracker = defaultdict(int)
http_flood_tracker = defaultdict(int)
protocol_tracker = Counter()

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        length = len(packet)

        src_port = dst_port = flags = None

        # Track protocol usage
        protocol_tracker[protocol] += 1
        if ALERT_THRESHOLD["unusual_protocol"] and protocol not in WHITELISTED_PROTOCOLS:
            send_alert(f"Unusual protocol detected from {src_ip}: Protocol {protocol}")

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags

            # SYN Flood Detection
            if "S" in flags and "A" not in flags:
                syn_flood_tracker[src_ip] += 1
                if syn_flood_tracker[src_ip] > ALERT_THRESHOLD["syn_flood"]:
                    send_alert(f"SYN flood detected from {src_ip}")
                    syn_flood_tracker[src_ip] = 0

            # Port Scan Detection
            port_scan_tracker[src_ip].add(dst_port)
            if len(port_scan_tracker[src_ip]) > ALERT_THRESHOLD["port_scan"]:
                send_alert(f"Port scan detected from {src_ip}")
                port_scan_tracker[src_ip].clear()

            # HTTP Flood Detection
            if dst_port == 80 or dst_port == 443:
                http_flood_tracker[src_ip] += 1
                if http_flood_tracker[src_ip] > ALERT_THRESHOLD["http_flood"]:
                    send_alert(f"HTTP flood detected from {src_ip}")
                    http_flood_tracker[src_ip] = 0

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            # UDP Flood Detection
            udp_flood_tracker[src_ip] += 1
            if udp_flood_tracker[src_ip] > ALERT_THRESHOLD["udp_flood"]:
                send_alert(f"UDP flood detected from {src_ip}")
                udp_flood_tracker[src_ip] = 0

        elif ICMP in packet:
            # ICMP Flood Detection
            icmp_flood_tracker[src_ip] += 1
            if icmp_flood_tracker[src_ip] > ALERT_THRESHOLD["icmp_flood"]:
                send_alert(f"ICMP flood detected from {src_ip}")
                icmp_flood_tracker[src_ip] = 0

        log_packet(src_ip, dst_ip, src_port, dst_port, protocol, length, flags)

def reset_trackers():
    """Reset rate-based trackers every ALERT_TIME_WINDOW seconds."""
    while True:
        time.sleep(ALERT_TIME_WINDOW)
        syn_flood_tracker.clear()
        icmp_flood_tracker.clear()
        udp_flood_tracker.clear()
        http_flood_tracker.clear()

def start_sniffer(interface="Wi-Fi"):
    print(f"[*] Starting packet sniffer on interface {interface}...")
    import threading
    threading.Thread(target=reset_trackers, daemon=True).start()
    sniff(iface=interface, prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffer()