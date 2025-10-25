# syn_probe.py
import sys
from scapy.all import IP, TCP, sr1, conf

def syn_probe(target, dport=80, timeout=3, src_port=None):
    # Optional: pick a random source port if not provided
    if src_port is None:
        from random import randint
        src_port = randint(1024, 65535)

    pkt = IP(dst=target) / TCP(sport=src_port, dport=dport, flags="S", seq=1000)
    print(f"[+] Sending SYN -> {target}:{dport} (sport={src_port})")
    # sr1 sends packet and waits for 1 reply
    resp = sr1(pkt, timeout=timeout, verbose=False)
    if resp is None:
        print("[-] No response (filtered or host down).")
        return None

    # show high-level info
    resp.summary()
    # Detailed print
    if resp.haslayer(TCP):
        tcp = resp.getlayer(TCP)
        flags = tcp.sprintf("%flags%")
        print(f"[+] TCP flags in response: {flags}")
        if flags == "SA":  # SYN-ACK
            print("[+] Port appears OPEN (SYN-ACK received).")
        elif "R" in flags:  # RST or RST-ACK
            print("[-] Port appears CLOSED (RST received).")
        else:
            print("[*] Unexpected TCP flags:", flags)
    else:
        print("[*] Received non-TCP response:", resp.summary())

    return resp

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python syn_probe.py <target> [port]")
        sys.exit(1)
    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80

    # On Windows, you may need to set conf.iface or let scapy auto choose
    # conf.iface = "Wi-Fi"  # example
    syn_probe(target, dport=port)
