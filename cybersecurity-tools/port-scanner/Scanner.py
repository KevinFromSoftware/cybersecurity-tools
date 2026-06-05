#!/usr/bin/env python3
"""
Port Scanner - A simple cybersecurity learning tool
Author: [Ditt navn]
Description: Scans a target host for open TCP ports
"""

import socket
import argparse
import sys
from datetime import datetime


# -------------------------------------------------------------------
# COMMON PORTS with service names (for readability in output)
# -------------------------------------------------------------------
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


# -------------------------------------------------------------------
# CORE FUNCTION: scan a single port
# -------------------------------------------------------------------
def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Try to connect to host:port.
    Returns True if the port is open, False if closed/filtered.
    """
    try:
        # AF_INET = IPv4, SOCK_STREAM = TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))  # 0 = success (open)
            return result == 0
    except socket.error:
        return False


# -------------------------------------------------------------------
# SCAN RANGE OF PORTS
# -------------------------------------------------------------------
def scan_range(host: str, start_port: int, end_port: int, timeout: float = 1.0) -> list:
    """
    Scans ports from start_port to end_port (inclusive).
    Returns a list of open ports.
    """
    open_ports = []

    print(f"\n{'='*52}")
    print(f"  Target  : {host}")
    print(f"  Ports   : {start_port} - {end_port}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*52}\n")

    for port in range(start_port, end_port + 1):
        if scan_port(host, port, timeout):
            service = COMMON_PORTS.get(port, "Unknown")
            print(f"  [OPEN]  Port {port:>5}  →  {service}")
            open_ports.append(port)
        else:
            # Show progress every 100 ports so the user knows it's working
            if port % 100 == 0:
                print(f"  [ -- ]  Scanned up to port {port}...")

    return open_ports


# -------------------------------------------------------------------
# RESOLVE HOSTNAME → IP
# -------------------------------------------------------------------
def resolve_host(host: str) -> str:
    """
    Converts a hostname (e.g. 'example.com') to an IP address.
    Exits the program if the host cannot be resolved.
    """
    try:
        ip = socket.gethostbyname(host)
        if ip != host:
            print(f"  Resolved {host} → {ip}")
        return ip
    except socket.gaierror:
        print(f"[ERROR] Could not resolve hostname: {host}")
        sys.exit(1)


# -------------------------------------------------------------------
# ARGUMENT PARSING (command-line interface)
# -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Simple Port Scanner - Cybersecurity Learning Tool",
        epilog="Example: python scanner.py scanme.nmap.org -s 1 -e 1024"
    )
    parser.add_argument(
        "host",
        help="Target hostname or IP address (only scan hosts you have permission to scan!)"
    )
    parser.add_argument(
        "-s", "--start",
        type=int,
        default=1,
        help="Start port (default: 1)"
    )
    parser.add_argument(
        "-e", "--end",
        type=int,
        default=1024,
        help="End port (default: 1024)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=0.5,
        help="Connection timeout in seconds (default: 0.5)"
    )
    return parser.parse_args()


# -------------------------------------------------------------------
# MAIN ENTRY POINT
# -------------------------------------------------------------------
def main():
    args = parse_args()

    # Validate port range
    if not (1 <= args.start <= 65535) or not (1 <= args.end <= 65535):
        print("[ERROR] Ports must be between 1 and 65535.")
        sys.exit(1)
    if args.start > args.end:
        print("[ERROR] Start port must be less than or equal to end port.")
        sys.exit(1)

    # Resolve and scan
    ip = resolve_host(args.host)
    open_ports = scan_range(ip, args.start, args.end, args.timeout)

    # Summary
    print(f"\n{'='*52}")
    print(f"  Scan complete! {len(open_ports)} open port(s) found.")
    if open_ports:
        print(f"  Open ports: {', '.join(str(p) for p in open_ports)}")
    print(f"  Finished : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*52}\n")


if __name__ == "__main__":
    main()