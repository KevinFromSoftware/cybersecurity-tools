#!/usr/bin/env python3
"""
Banner Grabber v2 - Reads service banners from open ports
Author: [Ditt navn]
Description: Connects to open ports and reads what the service responds with.
             This reveals software names and versions — critical info for a pentester
             because outdated software = known vulnerabilities.

v2 improvements:
  - Tries HTTP on ANY port if normal banner read fails (not just 80/443/8080/8443)
  - Automatically parses the Server and X-Powered-By headers
  - Multi-threaded for much faster scanning
  - Suggests CVE lookup commands based on what it finds

FOR EDUCATIONAL USE ONLY — only scan hosts you have permission to scan.
"""

import socket
import ssl
import argparse
import sys
import re
import concurrent.futures
from datetime import datetime


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

TLS_PORTS = {443, 8443}


def http_probe(host, port, timeout=2.0, use_tls=False):
    """Sends a HEAD request and reads HTTP response. Tries on ANY port (v2 upgrade)."""
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((host, port))

        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: BannerGrabber/2.0\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())

        response = b""
        while len(response) < 4096:
            chunk = sock.recv(1024)
            if not chunk:
                break
            response += chunk
            if b"\r\n\r\n" in response:
                break
        sock.close()

        text = response.decode("utf-8", errors="replace")
        if not text.startswith("HTTP/"):
            return None

        lines = text.split("\r\n")
        result = {
            "is_http": True,
            "status_line": lines[0],
            "server": None,
            "powered_by": None,
        }
        for line in lines[1:]:
            low = line.lower()
            if low.startswith("server:"):
                result["server"] = line.split(":", 1)[1].strip()
            elif low.startswith("x-powered-by:"):
                result["powered_by"] = line.split(":", 1)[1].strip()
        return result
    except Exception:
        return None


def grab_banner(host, port, timeout=2.0):
    """Connects to a port and reads the banner, with HTTP fallback on any port (v2)."""
    result = {
        "port": port,
        "open": False,
        "banner": None,
        "server": None,
        "powered_by": None,
        "service": COMMON_PORTS.get(port, ("Unknown", ""))[0],
        "description": COMMON_PORTS.get(port, ("", "Unknown"))[1],
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            conn = sock.connect_ex((host, port))
            if conn != 0:
                return result
            result["open"] = True
            try:
                sock.settimeout(timeout)
                banner_raw = sock.recv(1024)
                banner = banner_raw.decode("utf-8", errors="replace").strip()
                if banner:
                    result["banner"] = banner.split("\n")[0].strip()[:200]
            except (socket.timeout, ConnectionResetError, OSError):
                pass
    except socket.error:
        return result

    # v2 UPGRADE: if no banner, try HTTP on ANY port
    if result["open"] and not result["banner"]:
        http_info = http_probe(host, port, timeout, use_tls=(port in TLS_PORTS))
        if not http_info and port not in TLS_PORTS:
            http_info = http_probe(host, port, timeout, use_tls=True)
        if http_info:
            result["banner"] = http_info["status_line"]
            result["server"] = http_info["server"]
            result["powered_by"] = http_info["powered_by"]
            if result["service"] == "Unknown":
                result["service"] = "HTTP"

    return result


def scan_and_grab(host, ports, timeout=2.0, threads=20):
    """Scans ports and grabs banners using multiple threads (v2)."""
    print(f"\n{'='*60}")
    print(f"  Banner Grabber v2")
    print(f"  Target  : {host}")
    print(f"  Ports   : {len(ports)} ports to scan")
    print(f"  Threads : {threads}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    open_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {
            executor.submit(grab_banner, host, port, timeout): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result["open"]:
                open_results.append(result)
                print(f"  [OPEN]  Port {result['port']:>5}  ({result['service']})")
                if result["banner"]:
                    print(f"          Banner : {result['banner']}")
                if result["server"]:
                    print(f"          Server : {result['server']}")
                if result["powered_by"]:
                    print(f"          Powered: {result['powered_by']}")
                print()
    open_results.sort(key=lambda r: r["port"])
    return open_results


def extract_versions(results):
    """Extracts software + version strings to suggest CVE lookups."""
    versions = set()
    patterns = [
        r"(OpenSSH[_/\s]?[\d.]+)",
        r"(Apache/[\d.]+)",
        r"(nginx/[\d.]+)",
        r"(PHP/[\d.]+)",
        r"(MySQL[\s\-]?[\d.]+)",
        r"(vsFTPd\s[\d.]+)",
        r"(ProFTPD\s[\d.]+)",
        r"(Microsoft-IIS/[\d.]+)",
    ]
    for r in results:
        text = " ".join(filter(None, [r.get("banner"), r.get("server"), r.get("powered_by")]))
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                clean = match.group(1).replace("/", " ").replace("_", " ")
                versions.add(clean.strip())
    return sorted(versions)


def display_results(results, host):
    print(f"{'='*60}")
    print(f"  RESULTS SUMMARY — {host}")
    print(f"{'='*60}")
    if not results:
        print(f"\n  No open ports found.\n")
        return
    print(f"\n  {'Port':<8} {'Service':<12} {'Version Info'}")
    print(f"  {'-'*8} {'-'*12} {'-'*35}")
    for r in results:
        version = r.get("server") or r.get("banner") or "(no banner)"
        if len(version) > 45:
            version = version[:42] + "..."
        print(f"  {r['port']:<8} {r['service']:<12} {version}")
    print(f"\n  Total open ports: {len(results)}")
    print(f"\n  --- Security Notes ---")
    for r in results:
        if r["port"] == 23:
            print(f"  !  Port 23 (Telnet) is UNENCRYPTED — should use SSH instead")
        if r["port"] == 3306:
            print(f"  !  Port 3306 (MySQL) exposed — should not be internet-facing")
        if r["powered_by"]:
            print(f"  !  Port {r['port']} leaks technology: {r['powered_by']}")
    versions = extract_versions(results)
    if versions:
        print(f"\n  --- Suggested CVE Lookups ---")
        print(f"  Run these to check for known vulnerabilities:")
        for v in versions:
            print(f"    python3 cve_lookup.py \"{v}\"")
    print(f"\n{'='*60}\n")


def get_top_ports():
    return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
            443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900,
            6379, 8080, 8443, 8888, 9090]


def parse_ports(port_string):
    ports = []
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Banner Grabber v2 — Identify services and versions on open ports",
        epilog="Example: python3 banner_grabber.py 127.0.0.1 -p 22,3306,42001"
    )
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument("-p", "--ports",
        help="Comma-separated ports (e.g. 22,80,443) or range (e.g. 1-100)")
    parser.add_argument("--top-ports", action="store_true",
        help="Scan the 25 most common ports")
    parser.add_argument("-t", "--timeout", type=float, default=2.0,
        help="Connection timeout in seconds (default: 2.0)")
    parser.add_argument("--threads", type=int, default=20,
        help="Number of threads (default: 20)")
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        ip = socket.gethostbyname(args.host)
        if ip != args.host:
            print(f"\n  Resolved {args.host} -> {ip}")
    except socket.gaierror:
        print(f"[ERROR] Could not resolve: {args.host}")
        sys.exit(1)
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
    results = scan_and_grab(ip, ports, args.timeout, args.threads)
    display_results(results, args.host)


if __name__ == "__main__":
    main()