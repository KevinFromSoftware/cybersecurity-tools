#!/usr/bin/env python3
"""
Banner Grabber - Reads service banners from open ports
Author: [Ditt navn]
Description: Connects to open ports and reads what the service responds with.
             This reveals software names and versions — critical info for a pentester
             because outdated software = known vulnerabilities.

⚠️  FOR EDUCATIONAL USE ONLY — only scan hosts you have permission to scan.
"""

import socket
import argparse
import sys
from datetime import datetime


# -------------------------------------------------------------------
# COMMON PORTS — what to expect on each
# -------------------------------------------------------------------
COMMON_PORTS = {
    21:   ("FTP",        "File Transfer"),
    22:   ("SSH",        "Secure Shell"),
    23:   ("Telnet",     "Unencrypted Remote Access"),
    25:   ("SMTP",       "Email Sending"),
    53:   ("DNS",        "Domain Name System"),
    80:   ("HTTP",       "Web Server"),
    110:  ("POP3",       "Email Retrieval"),
    143:  ("IMAP",       "Email Retrieval"),
    443:  ("HTTPS",      "Secure Web Server"),
    445:  ("SMB",        "File Sharing"),
    3306: ("MySQL",      "Database"),
    3389: ("RDP",        "Remote Desktop"),
    5432: ("PostgreSQL", "Database"),
    6379: ("Redis",      "Cache/Database"),
    8080: ("HTTP-Alt",   "Web Server (alternative)"),
    8443: ("HTTPS-Alt",  "Secure Web (alternative)"),
}


# -------------------------------------------------------------------
# GRAB BANNER — the core function
# -------------------------------------------------------------------
def grab_banner(host: str, port: int, timeout: float = 2.0) -> dict:
    """
    Connects to a port and tries to read the service banner.

    How it works:
      1. Open a TCP connection (same as port scanner)
      2. Some services send a greeting immediately (FTP, SSH, SMTP)
      3. For HTTP, we need to send a request first (GET / HTTP/1.1)
      4. Read whatever the service sends back — that's the banner

    Why this matters for pentesting:
      A banner like "OpenSSH 7.2" tells you the exact version.
      You can then search for known vulnerabilities (CVEs) for that version.
    """
    result = {
        "port": port,
        "open": False,
        "banner": None,
        "service": COMMON_PORTS.get(port, ("Unknown", ""))[0],
        "description": COMMON_PORTS.get(port, ("", "Unknown"))[1],
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            conn = sock.connect_ex((host, port))

            if conn != 0:
                return result  # Port is closed

            result["open"] = True

            # --- Try to grab banner ---
            try:
                # HTTP ports need a request to get a response
                if port in (80, 8080, 443, 8443):
                    request = (
                        f"HEAD / HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                    )
                    sock.sendall(request.encode())

                # Other services (FTP, SSH, SMTP) usually send banner automatically
                banner_raw = sock.recv(1024)
                banner = banner_raw.decode("utf-8", errors="replace").strip()

                # Clean up the banner — take the first meaningful line
                if banner:
                    lines = banner.split("\n")
                    result["banner"] = lines[0].strip()[:200]

            except (socket.timeout, ConnectionResetError, OSError):
                result["banner"] = "(no response — service may require specific protocol)"

    except socket.error as e:
        result["banner"] = f"(connection error: {e})"

    return result


# -------------------------------------------------------------------
# SCAN AND GRAB — scan ports and grab banners
# -------------------------------------------------------------------
def scan_and_grab(
    host: str,
    ports: list[int],
    timeout: float = 2.0
) -> list[dict]:
    """
    Scans a list of ports and grabs banners from open ones.
    Returns a list of results for open ports.
    """
    print(f"\n{'='*60}")
    print(f"  Banner Grabber")
    print(f"  Target  : {host}")
    print(f"  Ports   : {len(ports)} ports to scan")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    open_results = []

    for i, port in enumerate(ports):
        result = grab_banner(host, port, timeout)

        if result["open"]:
            open_results.append(result)
            banner_display = result["banner"] or "(empty)"
            print(f"  [OPEN]  Port {port:>5}  ({result['service']})")
            print(f"          Banner: {banner_display}")
            print()
        else:
            # Progress indicator every 50 ports
            if (i + 1) % 50 == 0:
                print(f"  [ -- ]  Scanned {i + 1}/{len(ports)} ports...")

    return open_results


# -------------------------------------------------------------------
# QUICK SCAN — scan only the most interesting ports
# -------------------------------------------------------------------
def get_top_ports() -> list[int]:
    """Returns the most commonly open ports — faster than scanning all 1024."""
    return [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
        443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900,
        6379, 8080, 8443, 8888, 9090
    ]


# -------------------------------------------------------------------
# DISPLAY RESULTS — nice summary table
# -------------------------------------------------------------------
def display_results(results: list[dict], host: str):
    """Prints a clean summary of all findings."""
    print(f"{'='*60}")
    print(f"  RESULTS SUMMARY — {host}")
    print(f"{'='*60}")

    if not results:
        print(f"\n  No open ports found.\n")
        return

    print(f"\n  {'Port':<8} {'Service':<12} {'Banner'}")
    print(f"  {'-'*8} {'-'*12} {'-'*35}")

    for r in results:
        banner = r['banner'] or '(no banner)'
        # Truncate long banners for display
        if len(banner) > 50:
            banner = banner[:47] + "..."
        print(f"  {r['port']:<8} {r['service']:<12} {banner}")

    print(f"\n  Total open ports: {len(results)}")

    # Security insights
    print(f"\n  --- Security Notes ---")
    for r in results:
        if r["port"] == 23:
            print(f"  ⚠  Port 23 (Telnet) is UNENCRYPTED — should use SSH instead")
        if r["port"] == 21:
            print(f"  ⚠  Port 21 (FTP) — check if anonymous login is allowed")
        if r["banner"] and any(v in r["banner"].lower() for v in ["apache/2.2", "openssh 6", "openssh 7.0", "vsftpd 2"]):
            print(f"  ⚠  Port {r['port']} — banner suggests an older version, check for CVEs!")
        if r["port"] == 3389:
            print(f"  ⚠  Port 3389 (RDP) — exposed remote desktop, potential attack surface")

    print(f"\n{'='*60}\n")


# -------------------------------------------------------------------
# ARGUMENT PARSING
# -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Banner Grabber — Identify services and versions on open ports",
        epilog="Example: python banner_grabber.py scanme.nmap.org --top-ports"
    )
    parser.add_argument(
        "host",
        help="Target hostname or IP address"
    )
    parser.add_argument(
        "-p", "--ports",
        help="Comma-separated ports (e.g. 22,80,443) or range (e.g. 1-100)"
    )
    parser.add_argument(
        "--top-ports",
        action="store_true",
        help="Scan the 25 most common ports (fast!)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=2.0,
        help="Connection timeout in seconds (default: 2.0)"
    )
    return parser.parse_args()


def parse_ports(port_string: str) -> list[int]:
    """Parse port input like '22,80,443' or '1-100' or '22,80,100-200'."""
    ports = []
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
def main():
    args = parse_args()

    # Resolve hostname
    try:
        ip = socket.gethostbyname(args.host)
        if ip != args.host:
            print(f"\n  Resolved {args.host} → {ip}")
    except socket.gaierror:
        print(f"[ERROR] Could not resolve: {args.host}")
        sys.exit(1)

    # Determine which ports to scan
    if args.top_ports:
        ports = get_top_ports()
    elif args.ports:
        try:
            ports = parse_ports(args.ports)
        except ValueError:
            print("[ERROR] Invalid port format. Use: 22,80,443 or 1-100")
            sys.exit(1)
    else:
        ports = get_top_ports()
        print("  (No ports specified — using top 25 common ports)")

    # Scan and grab banners
    results = scan_and_grab(ip, ports, args.timeout)

    # Display summary
    display_results(results, args.host)


if __name__ == "__main__":
    main()
