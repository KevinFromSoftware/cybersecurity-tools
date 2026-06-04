#!/usr/bin/env python3
"""
Subdomain Finder - Discover subdomains via DNS brute force
Author: [Ditt navn]
Description: Tries common subdomain names against a target domain
             to find hidden services (admin panels, dev servers, APIs).

Why this matters:
  Companies often have subdomains like:
    admin.example.com    → Admin panel (often less protected)
    dev.example.com      → Development server (may have debug mode on)
    staging.example.com  → Staging environment (may have test data)
    api.example.com      → API endpoint (may lack authentication)
    mail.example.com     → Mail server
    vpn.example.com      → VPN gateway

  Finding these is the FIRST step in reconnaissance — before port scanning.

The updated attack chain:
  0. Subdomain Finder  → Find targets         ← YOU ARE HERE
  1. Port Scanner      → Find open ports
  2. Banner Grabber    → Identify software
  3. CVE Lookup        → Find vulnerabilities
  4. Hash Cracker      → Crack credentials

⚠️  FOR EDUCATIONAL USE ONLY — only scan domains you have permission to scan.
"""

import socket
import argparse
import sys
import concurrent.futures
from datetime import datetime


# -------------------------------------------------------------------
# BUILT-IN WORDLIST — most common subdomain names
# -------------------------------------------------------------------
DEFAULT_SUBDOMAINS = [
    # Administration
    "admin", "administrator", "panel", "dashboard", "manage",
    "portal", "control", "backend", "cms",

    # Development & Staging
    "dev", "development", "staging", "stage", "test", "testing",
    "sandbox", "demo", "beta", "alpha", "uat", "qa",
    "pre-prod", "preprod",

    # Web & Apps
    "www", "app", "apps", "web", "mobile", "m",
    "api", "api2", "api-v2", "rest", "graphql",
    "cdn", "static", "assets", "media", "images", "img",

    # Mail & Communication
    "mail", "email", "smtp", "pop", "imap", "webmail",
    "exchange", "outlook",

    # Network & Infrastructure
    "vpn", "remote", "gateway", "proxy", "firewall",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "ftp", "sftp", "ssh", "rdp",

    # Databases & Storage
    "db", "database", "mysql", "postgres", "mongo", "redis",
    "elastic", "elasticsearch", "kibana", "grafana",
    "storage", "backup", "backups", "s3",

    # Monitoring & Tools
    "monitor", "monitoring", "nagios", "zabbix", "status",
    "log", "logs", "syslog", "jenkins", "ci", "cd",
    "git", "gitlab", "github", "bitbucket", "repo",
    "jira", "confluence", "wiki", "docs", "documentation",

    # Security
    "sso", "auth", "login", "oauth", "identity", "id",
    "cert", "certs", "ssl", "secure",

    # Services
    "shop", "store", "pay", "payment", "billing",
    "support", "help", "helpdesk", "ticket",
    "forum", "community", "blog", "news",
    "search", "analytics", "track", "tracking",

    # Cloud & Hosting
    "cloud", "aws", "azure", "gcp",
    "server", "server1", "server2", "host",
    "node1", "node2", "worker", "lb", "loadbalancer",

    # Internal
    "intranet", "internal", "corp", "corporate",
    "hr", "finance", "sales", "marketing",
    "office", "erp", "crm",

    # Misc
    "old", "new", "legacy", "archive",
    "temp", "tmp", "cache",
]


# -------------------------------------------------------------------
# CORE: check if a subdomain exists via DNS resolution
# -------------------------------------------------------------------
def check_subdomain(subdomain: str, domain: str, timeout: float = 2.0) -> dict | None:
    """
    Tries to resolve subdomain.domain via DNS.
    If it resolves to an IP → the subdomain exists!

    This is essentially a DNS brute force attack:
    try thousands of names and see which ones resolve.
    """
    full_domain = f"{subdomain}.{domain}"

    try:
        socket.setdefaulttimeout(timeout)
        ip = socket.gethostbyname(full_domain)
        return {
            "subdomain": subdomain,
            "full_domain": full_domain,
            "ip": ip,
        }
    except (socket.gaierror, socket.timeout):
        return None


# -------------------------------------------------------------------
# HTTP CHECK — optionally check if web server responds
# -------------------------------------------------------------------
def check_http(domain: str, timeout: float = 3.0) -> str | None:
    """
    Tries to connect to port 80 to see if a web server is running.
    Returns the HTTP status line if successful.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((domain, 80))
            request = f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode())
            response = sock.recv(256).decode("utf-8", errors="replace")
            first_line = response.split("\r\n")[0]
            return first_line
    except (socket.error, socket.timeout):
        return None


# -------------------------------------------------------------------
# LOAD WORDLIST from file
# -------------------------------------------------------------------
def load_wordlist(path: str) -> list[str]:
    """Load subdomain names from a file (one per line)."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]
            print(f"  Loaded {len(words)} subdomains from {path}")
            return words
    except FileNotFoundError:
        print(f"[ERROR] Wordlist not found: {path}")
        sys.exit(1)


# -------------------------------------------------------------------
# MAIN SCAN — with threading for speed
# -------------------------------------------------------------------
def scan_subdomains(
    domain: str,
    wordlist: list[str],
    timeout: float = 2.0,
    threads: int = 10,
    check_web: bool = False,
) -> list[dict]:
    """
    Scans for subdomains using multiple threads for speed.

    Threading explanation:
      Without threading: check 150 subdomains one by one = ~300 seconds
      With 10 threads: check 10 at a time = ~30 seconds
    """
    print(f"\n{'='*60}")
    print(f"  Subdomain Finder")
    print(f"  Target    : {domain}")
    print(f"  Wordlist  : {len(wordlist)} subdomains to try")
    print(f"  Threads   : {threads}")
    print(f"  Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    found = []
    checked = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all tasks
        future_to_sub = {
            executor.submit(check_subdomain, sub, domain, timeout): sub
            for sub in wordlist
        }

        for future in concurrent.futures.as_completed(future_to_sub):
            checked += 1
            result = future.result()

            if result:
                # Optionally check HTTP
                if check_web:
                    http_status = check_http(result["full_domain"])
                    result["http"] = http_status
                else:
                    result["http"] = None

                found.append(result)
                http_info = f"  [{result['http']}]" if result["http"] else ""
                print(f"  [FOUND]  {result['full_domain']:<35} → {result['ip']}{http_info}")

            # Progress update
            if checked % 25 == 0:
                print(f"  [ -- ]   Checked {checked}/{len(wordlist)} subdomains...")

    return found


# -------------------------------------------------------------------
# DISPLAY RESULTS
# -------------------------------------------------------------------
def display_results(results: list[dict], domain: str):
    """Pretty-print all discovered subdomains."""
    print(f"\n{'='*60}")
    print(f"  RESULTS — {domain}")
    print(f"{'='*60}")

    if not results:
        print(f"\n  No subdomains found for {domain}.")
        print(f"  Tips:")
        print(f"    - Try a larger wordlist (-w biglist.txt)")
        print(f"    - The domain may use wildcard DNS (all resolve)")
        print(f"    - Some subdomains may be internal-only\n")
        return

    # Sort by subdomain name
    results.sort(key=lambda r: r["subdomain"])

    # Group by IP to spot shared hosting
    ip_groups = {}
    for r in results:
        ip_groups.setdefault(r["ip"], []).append(r["full_domain"])

    print(f"\n  {'Subdomain':<35} {'IP Address':<18} {'HTTP'}")
    print(f"  {'-'*35} {'-'*18} {'-'*25}")

    for r in results:
        http_col = r.get("http") or ""
        print(f"  {r['full_domain']:<35} {r['ip']:<18} {http_col}")

    print(f"\n  Total found: {len(results)} subdomains")
    print(f"  Unique IPs : {len(ip_groups)}")

    # Show shared IPs (interesting for pentesting)
    shared = {ip: domains for ip, domains in ip_groups.items() if len(domains) > 1}
    if shared:
        print(f"\n  --- Shared IP Addresses ---")
        print(f"  (Multiple subdomains on same server = shared hosting)")
        for ip, domains in shared.items():
            print(f"    {ip}:")
            for d in domains:
                print(f"      - {d}")

    # Security observations
    print(f"\n  --- Security Notes ---")
    for r in results:
        sub = r["subdomain"]
        if sub in ("admin", "administrator", "panel", "dashboard", "backend"):
            print(f"  ⚠  {r['full_domain']} — Admin panel exposed!")
        elif sub in ("dev", "development", "staging", "test", "sandbox", "uat"):
            print(f"  ⚠  {r['full_domain']} — Dev/staging environment (may have debug mode)")
        elif sub in ("db", "database", "mysql", "postgres", "mongo", "redis"):
            print(f"  ⚠  {r['full_domain']} — Database subdomain exposed!")
        elif sub in ("git", "gitlab", "repo", "jenkins", "ci"):
            print(f"  ⚠  {r['full_domain']} — Source code / CI system exposed!")
        elif sub in ("vpn", "remote", "rdp", "ssh"):
            print(f"  ⚠  {r['full_domain']} — Remote access point!")
        elif sub in ("backup", "backups", "old", "legacy", "archive"):
            print(f"  ⚠  {r['full_domain']} — Backup/legacy system (often unpatched)")

    print(f"\n  Next step: Run port scanner and banner grabber on found subdomains!")
    print(f"    python3 scanner.py {results[0]['full_domain']} -s 1 -e 1024")
    print(f"\n{'='*60}\n")


# -------------------------------------------------------------------
# ARGUMENT PARSING
# -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Subdomain Finder — Discover subdomains via DNS brute force",
        epilog=(
            "Examples:\n"
            "  python3 subdomain_finder.py example.com\n"
            "  python3 subdomain_finder.py example.com -w big_wordlist.txt\n"
            "  python3 subdomain_finder.py example.com --threads 20 --check-http\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "domain",
        help="Target domain (e.g. example.com)"
    )
    parser.add_argument(
        "-w", "--wordlist",
        help="Path to custom wordlist file (one subdomain per line)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=2.0,
        help="DNS timeout in seconds (default: 2.0)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of threads (default: 10, max recommended: 50)"
    )
    parser.add_argument(
        "--check-http",
        action="store_true",
        help="Also check if port 80 responds (slower but more info)"
    )
    return parser.parse_args()


# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
def main():
    args = parse_args()

    # Validate domain
    if "." not in args.domain:
        print("[ERROR] Please provide a valid domain (e.g. example.com)")
        sys.exit(1)

    # Strip protocol if user accidentally included it
    domain = args.domain.replace("https://", "").replace("http://", "").strip("/")

    # Load wordlist
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
    else:
        wordlist = DEFAULT_SUBDOMAINS
        print(f"  Using built-in wordlist ({len(wordlist)} subdomains)")

    # Check if base domain resolves
    try:
        base_ip = socket.gethostbyname(domain)
        print(f"  Base domain {domain} → {base_ip}")
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve {domain} — check the domain name")
        sys.exit(1)

    # Scan
    results = scan_subdomains(
        domain, wordlist, args.timeout, args.threads, args.check_http
    )

    # Display
    display_results(results, domain)


if __name__ == "__main__":
    main()
