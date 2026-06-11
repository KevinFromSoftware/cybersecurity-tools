#!/usr/bin/env python3
"""
Network Sniffer - Capture and analyze live network traffic
Author: [Ditt navn]
Description: Captures packets flowing across a network interface and
             analyzes them in real time — showing protocols, source/destination,
             DNS queries, HTTP requests, and potential credentials in plaintext.

Why this matters for cybersecurity:
  - See exactly what data travels across a network
  - Understand WHY unencrypted protocols (HTTP, FTP, Telnet) are dangerous
  - Detect suspicious traffic (Blue Team / network monitoring)
  - Foundation for understanding man-in-the-middle attacks

How it fits your toolkit:
  Most tools ACT on the network (scan, probe).
  This tool LISTENS to the network — a completely different skill.

⚠️  IMPORTANT — LEGAL & TECHNICAL NOTES:
  - Requires ROOT/sudo (raw socket access): sudo python3 network_sniffer.py
  - Requires the 'scapy' library: pip install scapy
  - Only sniff networks you OWN or have explicit permission to monitor.
    Capturing other people's traffic without consent is illegal in most
    countries (in Norway: straffeloven). Your own Kali VM, your own home
    network, or an isolated lab are fine.
  - This tool only READS traffic. It does not modify or inject anything.
"""

import argparse
import sys
from datetime import datetime
from collections import defaultdict

# Scapy is required — give a friendly message if it's missing
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, ARP, Ether
except ImportError:
    print("\n[ERROR] This tool requires Scapy.")
    print("Install it with:  pip install scapy --break-system-packages")
    print("Then run with sudo:  sudo python3 network_sniffer.py\n")
    sys.exit(1)


# -------------------------------------------------------------------
# STATISTICS — track what we see
# -------------------------------------------------------------------
stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "dns": 0,
    "arp": 0,
    "other": 0,
    "protocols": defaultdict(int),
    "talkers": defaultdict(int),       # IP → packet count
    "dns_queries": [],
    "http_requests": [],
    "credentials_warning": [],
}

# Common ports → protocol names
PORT_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt",
}

# Plaintext protocols where credentials might be exposed
PLAINTEXT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP"}


# -------------------------------------------------------------------
# PACKET HANDLER — called for every captured packet
# -------------------------------------------------------------------
def process_packet(packet, verbose=False):
    """
    Analyzes a single packet and updates statistics.
    This is the heart of the sniffer — it inspects each layer.
    """
    stats["total"] += 1
    timestamp = datetime.now().strftime("%H:%M:%S")

    # --- ARP packets (address resolution) ---
    if packet.haslayer(ARP):
        stats["arp"] += 1
        stats["protocols"]["ARP"] += 1
        if verbose:
            arp = packet[ARP]
            op = "request" if arp.op == 1 else "reply"
            print(f"  [{timestamp}] ARP {op}: {arp.psrc} → {arp.pdst}")
        return

    # --- IP packets ---
    if not packet.haslayer(IP):
        stats["other"] += 1
        return

    ip = packet[IP]
    src, dst = ip.src, ip.dst
    stats["talkers"][src] += 1

    # --- ICMP (ping) ---
    if packet.haslayer(ICMP):
        stats["icmp"] += 1
        stats["protocols"]["ICMP"] += 1
        if verbose:
            print(f"  [{timestamp}] ICMP  {src} → {dst}")
        return

    # --- TCP ---
    if packet.haslayer(TCP):
        stats["tcp"] += 1
        tcp = packet[TCP]
        sport, dport = tcp.sport, tcp.dport

        # Identify the service by port
        service = PORT_NAMES.get(dport) or PORT_NAMES.get(sport) or "TCP"
        stats["protocols"][service] += 1

        if verbose:
            flags = tcp.sprintf("%TCP.flags%")
            print(f"  [{timestamp}] {service:8} {src}:{sport} → {dst}:{dport} [{flags}]")

        # --- Inspect payload for HTTP and possible credentials ---
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode("utf-8", errors="ignore")
            except Exception:
                payload = ""

            # Detect HTTP requests
            if any(payload.startswith(m) for m in ["GET ", "POST ", "PUT ", "HEAD "]):
                first_line = payload.split("\r\n")[0]
                host_line = ""
                for line in payload.split("\r\n"):
                    if line.lower().startswith("host:"):
                        host_line = line.split(":", 1)[1].strip()
                        break
                req = f"{first_line} (Host: {host_line})"
                stats["http_requests"].append(req)
                if verbose:
                    print(f"            └─ HTTP: {first_line}")

            # Detect possible plaintext credentials (educational warning)
            if dport in PLAINTEXT_PORTS or sport in PLAINTEXT_PORTS:
                lower = payload.lower()
                if any(kw in lower for kw in ["password", "passwd", "pass=", "user=", "login", "pwd="]):
                    proto = PLAINTEXT_PORTS.get(dport) or PLAINTEXT_PORTS.get(sport)
                    warning = f"Possible plaintext credentials over {proto} ({src} → {dst})"
                    if warning not in stats["credentials_warning"]:
                        stats["credentials_warning"].append(warning)
                        if verbose:
                            print(f"            └─ ⚠  {warning}")
        return

    # --- UDP (includes DNS) ---
    if packet.haslayer(UDP):
        stats["udp"] += 1

        # DNS queries are especially interesting
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            stats["dns"] += 1
            stats["protocols"]["DNS"] += 1
            try:
                query = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                stats["dns_queries"].append(query)
                if verbose:
                    print(f"  [{timestamp}] DNS   {src} querying: {query}")
            except Exception:
                pass
        else:
            udp = packet[UDP]
            service = PORT_NAMES.get(udp.dport) or PORT_NAMES.get(udp.sport) or "UDP"
            stats["protocols"][service] += 1
            if verbose:
                print(f"  [{timestamp}] {service:8} {src}:{udp.sport} → {dst}:{udp.dport}")


# -------------------------------------------------------------------
# DISPLAY SUMMARY
# -------------------------------------------------------------------
def display_summary():
    """Print a summary of everything captured."""
    print(f"\n\n{'='*62}")
    print(f"  CAPTURE SUMMARY")
    print(f"{'='*62}")

    print(f"\n  Total packets captured: {stats['total']}")
    if stats["total"] == 0:
        print("  (No packets seen — try generating some traffic while sniffing)")
        return

    # Protocol breakdown
    print(f"\n  --- Protocol Breakdown ---")
    print(f"  TCP : {stats['tcp']}")
    print(f"  UDP : {stats['udp']}")
    print(f"  ICMP: {stats['icmp']}")
    print(f"  DNS : {stats['dns']}")
    print(f"  ARP : {stats['arp']}")

    # Top services
    if stats["protocols"]:
        print(f"\n  --- Services Seen ---")
        top = sorted(stats["protocols"].items(), key=lambda x: -x[1])[:10]
        for service, count in top:
            print(f"  {service:12} {count} packets")

    # Top talkers (most active IPs)
    if stats["talkers"]:
        print(f"\n  --- Top Talkers (most active source IPs) ---")
        top = sorted(stats["talkers"].items(), key=lambda x: -x[1])[:8]
        for ip, count in top:
            print(f"  {ip:18} {count} packets")

    # DNS queries (shows what domains were visited)
    if stats["dns_queries"]:
        print(f"\n  --- DNS Queries ({len(stats['dns_queries'])} total) ---")
        unique = list(dict.fromkeys(stats["dns_queries"]))  # Dedupe, keep order
        for query in unique[:15]:
            print(f"  {query}")

    # HTTP requests
    if stats["http_requests"]:
        print(f"\n  --- HTTP Requests ({len(stats['http_requests'])} total) ---")
        for req in stats["http_requests"][:10]:
            print(f"  {req}")

    # Security warnings
    if stats["credentials_warning"]:
        print(f"\n  --- ⚠  Security Warnings ---")
        for warning in stats["credentials_warning"]:
            print(f"  🔴 {warning}")
        print(f"\n  This demonstrates why plaintext protocols are dangerous:")
        print(f"  anyone sniffing the network can read credentials!")
        print(f"  Always use encrypted alternatives (HTTPS, SSH, FTPS).")

    print(f"\n{'='*62}\n")


# -------------------------------------------------------------------
# ARGUMENT PARSING
# -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Sniffer — Capture and analyze live network traffic",
        epilog=(
            "Examples (all need sudo):\n"
            "  sudo python3 network_sniffer.py -c 50\n"
            "  sudo python3 network_sniffer.py -i eth0 -v\n"
            "  sudo python3 network_sniffer.py --filter 'tcp port 80' -v\n"
            "  sudo python3 network_sniffer.py -t 30\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to sniff (default: auto-detect)"
    )
    parser.add_argument(
        "-c", "--count",
        type=int, default=0,
        help="Number of packets to capture (0 = unlimited, Ctrl+C to stop)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        help="Stop after this many seconds"
    )
    parser.add_argument(
        "-f", "--filter",
        default="",
        help="BPF filter (e.g. 'tcp port 80', 'udp', 'host 1.2.3.4')"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print each packet live as it's captured"
    )
    return parser.parse_args()


# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
def main():
    args = parse_args()

    # Check for root (required for raw socket access)
    if hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() != 0:
        print("\n[ERROR] This tool requires root privileges for packet capture.")
        print("Run it with sudo:  sudo python3 network_sniffer.py\n")
        sys.exit(1)

    print(f"\n{'#'*62}")
    print(f"#  Network Sniffer")
    print(f"#  Interface : {args.interface or 'auto-detect'}")
    print(f"#  Filter    : {args.filter or '(none — all traffic)'}")
    print(f"#  Count     : {args.count or 'unlimited (Ctrl+C to stop)'}")
    if args.timeout:
        print(f"#  Timeout   : {args.timeout} seconds")
    print(f"#  Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'#'*62}")
    print(f"\n  Listening... (generate some traffic to see packets)\n")

    # Build sniff arguments
    sniff_kwargs = {
        "prn": lambda pkt: process_packet(pkt, args.verbose),
        "store": False,  # Don't keep packets in memory
    }
    if args.interface:
        sniff_kwargs["iface"] = args.interface
    if args.count > 0:
        sniff_kwargs["count"] = args.count
    if args.timeout:
        sniff_kwargs["timeout"] = args.timeout
    if args.filter:
        sniff_kwargs["filter"] = args.filter

    # Start sniffing
    try:
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        print("\n\n  Stopped by user (Ctrl+C)")
    except PermissionError:
        print("\n[ERROR] Permission denied — run with sudo")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        if args.interface:
            print(f"Check that interface '{args.interface}' exists (run: ip link)")
        sys.exit(1)

    # Show results
    display_summary()


if __name__ == "__main__":
    main()
