#!/usr/bin/env python3
"""
Log Analyzer - Blue Team Security Log Analysis Tool
Author: [Ditt navn]
Description: Parses system and web server logs to detect attack patterns.
             This is a BLUE TEAM tool — the defender's perspective.

What it detects:
  - SSH brute force attempts (many failed logins)
  - Username enumeration (trying many different usernames)
  - SQL injection attempts
  - Cross-Site Scripting (XSS) attempts
  - Directory traversal / Local File Inclusion (LFI)
  - Vulnerability scanner activity (Nikto, sqlmap, etc.)
  - Suspicious admin commands (data exfiltration, backdoors)
  - Successful logins after failed attempts (compromised accounts)

This is how a SOC (Security Operations Center) analyst works:
  Red Team attacks → logs are generated → Blue Team analyzes them

⚠️  FOR EDUCATIONAL USE ONLY
"""

import re
import argparse
import sys
from collections import defaultdict
from datetime import datetime


# -------------------------------------------------------------------
# ATTACK SIGNATURES — patterns that indicate malicious activity
# -------------------------------------------------------------------

# SQL Injection patterns
SQL_INJECTION_PATTERNS = [
    r"(?i)(\bOR\b.*=.*)",
    r"(?i)(UNION\s+SELECT)",
    r"(?i)(DROP\s+TABLE)",
    r"(?i)(INSERT\s+INTO)",
    r"(?i)(\bAND\b\s+\d+=\d+)",
    r"(?i)(SLEEP\s*\(\d+\))",
    r"(?i)(BENCHMARK\s*\()",
    r"(?i)(--|#|/\*)",
    r"(?i)(LOAD_FILE\s*\()",
    r"(?i)(INTO\s+OUTFILE)",
]

# XSS patterns
XSS_PATTERNS = [
    r"(?i)(<script.*?>)",
    r"(?i)(javascript\s*:)",
    r"(?i)(onerror\s*=)",
    r"(?i)(onload\s*=)",
    r"(?i)(onclick\s*=)",
    r"(?i)(onmouseover\s*=)",
    r"(?i)(<img.*?src\s*=.*?onerror)",
    r"(?i)(alert\s*\()",
    r"(?i)(document\.cookie)",
    r"(?i)(eval\s*\()",
]

# Directory Traversal / LFI patterns
TRAVERSAL_PATTERNS = [
    r"(\.\./)",
    r"(\.\.\\)",
    r"(?i)(/etc/passwd)",
    r"(?i)(/etc/shadow)",
    r"(?i)(c:\\windows)",
    r"(?i)(/proc/self)",
    r"(?i)(web\.config)",
    r"(?i)(\.env)",
]

# Known scanner/attack tool user agents
SCANNER_AGENTS = [
    r"(?i)(nikto)",
    r"(?i)(sqlmap)",
    r"(?i)(nmap)",
    r"(?i)(masscan)",
    r"(?i)(dirbuster)",
    r"(?i)(gobuster)",
    r"(?i)(wfuzz)",
    r"(?i)(burp\s*suite)",
    r"(?i)(zap)",
    r"(?i)(whatweb)",
]

# Sensitive files that shouldn't be accessible
SENSITIVE_FILES = [
    r"(?i)(\.git/)",
    r"(?i)(\.env)",
    r"(?i)(\.htaccess)",
    r"(?i)(wp-admin)",
    r"(?i)(phpmyadmin)",
    r"(?i)(server-status)",
    r"(?i)(backup\.sql)",
    r"(?i)(\.bak)",
    r"(?i)(config\.php)",
    r"(?i)(database\.yml)",
]

# Suspicious commands in auth/sudo logs
SUSPICIOUS_COMMANDS = [
    r"(?i)(/etc/shadow)",
    r"(?i)(mysqldump)",
    r"(?i)(wget\s+http)",
    r"(?i)(curl\s+http)",
    r"(?i)(chmod\s+\+x)",
    r"(?i)(/tmp/.*\.sh)",
    r"(?i)(nc\s+-.*-e)",
    r"(?i)(python.*-c.*import)",
    r"(?i)(base64\s+--decode)",
    r"(?i)(ncat|netcat)",
    r"(?i)(reverse.*shell)",
]


# -------------------------------------------------------------------
# AUTH LOG PARSER — parse SSH/sudo logs
# -------------------------------------------------------------------
def parse_auth_log(filepath: str) -> dict:
    """
    Parses auth.log format (SSH login attempts, sudo commands).
    Detects: brute force, username enumeration, suspicious commands.
    """
    results = {
        "failed_logins": defaultdict(lambda: defaultdict(int)),  # ip → user → count
        "successful_logins": [],
        "invalid_users": defaultdict(list),  # ip → [usernames tried]
        "suspicious_commands": [],
        "brute_force_then_success": [],
        "total_lines": 0,
    }

    failed_by_ip = defaultdict(list)  # track timing for brute force detection

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                results["total_lines"] += 1
                line = line.strip()

                # Failed password
                match = re.search(
                    r"Failed password for (?:invalid user )?(\S+) from (\S+) port",
                    line
                )
                if match:
                    user, ip = match.group(1), match.group(2)
                    results["failed_logins"][ip][user] += 1
                    failed_by_ip[ip].append(user)

                    if "invalid user" in line:
                        if user not in results["invalid_users"][ip]:
                            results["invalid_users"][ip].append(user)
                    continue

                # Successful login
                match = re.search(
                    r"Accepted (\S+) for (\S+) from (\S+) port",
                    line
                )
                if match:
                    method, user, ip = match.group(1), match.group(2), match.group(3)
                    results["successful_logins"].append({
                        "user": user, "ip": ip, "method": method, "line": line
                    })

                    # Check if this IP had failed attempts before
                    if ip in failed_by_ip:
                        results["brute_force_then_success"].append({
                            "ip": ip,
                            "user": user,
                            "failed_attempts": len(failed_by_ip[ip]),
                        })
                    continue

                # Sudo commands
                match = re.search(r"COMMAND=(.*)", line)
                if match:
                    command = match.group(1)
                    for pattern in SUSPICIOUS_COMMANDS:
                        if re.search(pattern, command):
                            results["suspicious_commands"].append({
                                "command": command,
                                "line": line,
                            })
                            break

    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    return results


# -------------------------------------------------------------------
# WEB LOG PARSER — parse Apache/Nginx access logs
# -------------------------------------------------------------------
def parse_web_log(filepath: str) -> dict:
    """
    Parses Apache/Nginx combined log format.
    Detects: SQL injection, XSS, traversal, scanner activity.
    """
    # Apache combined log regex
    log_pattern = re.compile(
        r'(\S+) \S+ \S+ \[(.+?)\] "(\S+) (.+?) \S+" (\d{3}) (\d+|-) "(.*?)" "(.*?)"'
    )

    results = {
        "sql_injection": [],
        "xss_attempts": [],
        "traversal_attempts": [],
        "scanner_activity": defaultdict(list),
        "sensitive_file_access": [],
        "failed_logins_web": defaultdict(int),
        "requests_by_ip": defaultdict(int),
        "status_codes": defaultdict(int),
        "total_lines": 0,
        "parsed_lines": 0,
    }

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                results["total_lines"] += 1
                match = log_pattern.match(line.strip())
                if not match:
                    continue

                results["parsed_lines"] += 1
                ip, timestamp, method, path, status, size, referer, agent = match.groups()

                results["requests_by_ip"][ip] += 1
                results["status_codes"][status] += 1

                # Check for SQL injection
                for pattern in SQL_INJECTION_PATTERNS:
                    if re.search(pattern, path):
                        results["sql_injection"].append({
                            "ip": ip, "path": path, "timestamp": timestamp
                        })
                        break

                # Check for XSS
                for pattern in XSS_PATTERNS:
                    if re.search(pattern, path):
                        results["xss_attempts"].append({
                            "ip": ip, "path": path, "timestamp": timestamp
                        })
                        break

                # Check for directory traversal
                for pattern in TRAVERSAL_PATTERNS:
                    if re.search(pattern, path):
                        results["traversal_attempts"].append({
                            "ip": ip, "path": path, "timestamp": timestamp
                        })
                        break

                # Check for scanner tools
                for pattern in SCANNER_AGENTS:
                    if re.search(pattern, agent):
                        tool = re.search(pattern, agent).group(1)
                        results["scanner_activity"][ip].append({
                            "tool": tool, "path": path, "timestamp": timestamp
                        })
                        break

                # Check for sensitive file access
                for pattern in SENSITIVE_FILES:
                    if re.search(pattern, path):
                        results["sensitive_file_access"].append({
                            "ip": ip, "path": path, "status": status,
                            "timestamp": timestamp
                        })
                        break

                # Track web login failures (401 on login paths)
                if status == "401" and "login" in path.lower():
                    results["failed_logins_web"][ip] += 1

    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    return results


# -------------------------------------------------------------------
# THREAT ASSESSMENT — classify severity of findings
# -------------------------------------------------------------------
def assess_threats(auth_results: dict | None, web_results: dict | None) -> list[dict]:
    """
    Combines findings and assigns threat levels.
    This is how a SOC analyst prioritizes alerts.
    """
    threats = []

    if auth_results:
        # Brute force detection (>5 failed attempts from same IP)
        for ip, users in auth_results["failed_logins"].items():
            total = sum(users.values())
            if total >= 5:
                threats.append({
                    "severity": "HIGH",
                    "type": "SSH Brute Force",
                    "source_ip": ip,
                    "detail": f"{total} failed login attempts across {len(users)} user(s): "
                              f"{', '.join(f'{u}({c}x)' for u, c in users.items())}",
                })

        # Username enumeration (trying many invalid usernames)
        for ip, usernames in auth_results["invalid_users"].items():
            if len(usernames) >= 3:
                threats.append({
                    "severity": "MEDIUM",
                    "type": "Username Enumeration",
                    "source_ip": ip,
                    "detail": f"Tried {len(usernames)} invalid usernames: "
                              f"{', '.join(usernames[:10])}",
                })

        # Compromised account (failed then succeeded)
        for entry in auth_results["brute_force_then_success"]:
            if entry["failed_attempts"] >= 3:
                threats.append({
                    "severity": "CRITICAL",
                    "type": "Possible Account Compromise",
                    "source_ip": entry["ip"],
                    "detail": f"User '{entry['user']}' logged in after "
                              f"{entry['failed_attempts']} failed attempts",
                })

        # Suspicious commands
        for cmd in auth_results["suspicious_commands"]:
            threats.append({
                "severity": "CRITICAL",
                "type": "Suspicious Command Execution",
                "source_ip": "local",
                "detail": f"Command: {cmd['command']}",
            })

    if web_results:
        # SQL injection
        ips_sqli = set(e["ip"] for e in web_results["sql_injection"])
        for ip in ips_sqli:
            count = sum(1 for e in web_results["sql_injection"] if e["ip"] == ip)
            threats.append({
                "severity": "CRITICAL",
                "type": "SQL Injection Attempt",
                "source_ip": ip,
                "detail": f"{count} SQL injection attempts detected",
            })

        # XSS
        ips_xss = set(e["ip"] for e in web_results["xss_attempts"])
        for ip in ips_xss:
            count = sum(1 for e in web_results["xss_attempts"] if e["ip"] == ip)
            threats.append({
                "severity": "HIGH",
                "type": "XSS Attempt",
                "source_ip": ip,
                "detail": f"{count} cross-site scripting attempts",
            })

        # Directory traversal
        ips_trav = set(e["ip"] for e in web_results["traversal_attempts"])
        for ip in ips_trav:
            count = sum(1 for e in web_results["traversal_attempts"] if e["ip"] == ip)
            threats.append({
                "severity": "HIGH",
                "type": "Directory Traversal / LFI",
                "source_ip": ip,
                "detail": f"{count} path traversal attempts",
            })

        # Scanner activity
        for ip, scans in web_results["scanner_activity"].items():
            tools = set(s["tool"] for s in scans)
            threats.append({
                "severity": "MEDIUM",
                "type": "Vulnerability Scanner Detected",
                "source_ip": ip,
                "detail": f"Tool(s): {', '.join(tools)} — {len(scans)} requests",
            })

        # Sensitive file access (with 200 status = actually exposed!)
        exposed = [e for e in web_results["sensitive_file_access"] if e["status"] == "200"]
        if exposed:
            for e in exposed:
                threats.append({
                    "severity": "CRITICAL",
                    "type": "Sensitive File Exposed",
                    "source_ip": e["ip"],
                    "detail": f"File accessible: {e['path']} (HTTP 200)",
                })

        # Web brute force
        for ip, count in web_results["failed_logins_web"].items():
            if count >= 3:
                threats.append({
                    "severity": "HIGH",
                    "type": "Web Login Brute Force",
                    "source_ip": ip,
                    "detail": f"{count} failed login attempts on web panel",
                })

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    threats.sort(key=lambda t: severity_order.get(t["severity"], 4))

    return threats


# -------------------------------------------------------------------
# DISPLAY REPORT
# -------------------------------------------------------------------
def display_report(threats: list[dict], auth_results: dict | None, web_results: dict | None):
    """Display the full analysis report."""

    severity_icons = {
        "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"
    }

    print(f"\n{'='*65}")
    print(f"  LOG ANALYSIS REPORT — Blue Team Security Review")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*65}")

    # Stats
    print(f"\n  --- Log Statistics ---")
    if auth_results:
        total_failed = sum(
            sum(u.values()) for u in auth_results["failed_logins"].values()
        )
        print(f"  Auth log lines    : {auth_results['total_lines']}")
        print(f"  Failed logins     : {total_failed}")
        print(f"  Successful logins : {len(auth_results['successful_logins'])}")
        print(f"  Suspicious cmds   : {len(auth_results['suspicious_commands'])}")

    if web_results:
        print(f"  Web log lines     : {web_results['total_lines']} ({web_results['parsed_lines']} parsed)")
        print(f"  Unique IPs        : {len(web_results['requests_by_ip'])}")
        print(f"  SQL injection     : {len(web_results['sql_injection'])} attempts")
        print(f"  XSS attempts      : {len(web_results['xss_attempts'])}")
        print(f"  Traversal attempts: {len(web_results['traversal_attempts'])}")

    # Threat summary
    print(f"\n  --- Threat Summary ---")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = sum(1 for t in threats if t["severity"] == level)
        if count:
            print(f"  {severity_icons[level]}  {level}: {count} alert(s)")

    if not threats:
        print(f"  ✅ No threats detected!")
        return

    # Detailed findings
    print(f"\n  --- Detailed Findings ---")
    for i, threat in enumerate(threats, 1):
        icon = severity_icons.get(threat["severity"], "⚪")
        print(f"\n  [{i}] {icon} {threat['severity']}: {threat['type']}")
        print(f"      Source: {threat['source_ip']}")
        print(f"      Detail: {threat['detail']}")

    # Unique attacker IPs
    attacker_ips = set(
        t["source_ip"] for t in threats if t["source_ip"] != "local"
    )
    if attacker_ips:
        print(f"\n  --- Attacker IPs to Block ---")
        for ip in sorted(attacker_ips):
            ip_threats = [t for t in threats if t["source_ip"] == ip]
            max_sev = ip_threats[0]["severity"]
            print(f"    {ip:<20} ({max_sev}) — "
                  f"{', '.join(set(t['type'] for t in ip_threats))}")

    # Recommendations
    print(f"\n  --- Recommendations ---")
    has_brute_force = any(t["type"] in ("SSH Brute Force", "Web Login Brute Force") for t in threats)
    has_sqli = any(t["type"] == "SQL Injection Attempt" for t in threats)
    has_compromise = any(t["type"] == "Possible Account Compromise" for t in threats)
    has_suspicious = any(t["type"] == "Suspicious Command Execution" for t in threats)
    has_exposed = any(t["type"] == "Sensitive File Exposed" for t in threats)

    if has_compromise:
        print(f"  🔴 URGENT: Account may be compromised — disable account, rotate credentials")
    if has_suspicious:
        print(f"  🔴 URGENT: Suspicious commands detected — check for backdoors, isolate system")
    if has_brute_force:
        print(f"  🟠 Block attacker IPs in firewall, implement fail2ban, enforce MFA")
    if has_sqli:
        print(f"  🟠 SQL injection detected — review input validation, use parameterized queries")
    if has_exposed:
        print(f"  🟠 Sensitive files exposed — restrict access immediately")
    if attacker_ips:
        print(f"  🟡 Add all attacker IPs to blocklist / firewall rules")

    print(f"\n{'='*65}\n")


# -------------------------------------------------------------------
# ARGUMENT PARSING
# -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Log Analyzer — Blue Team Security Log Analysis",
        epilog=(
            "Examples:\n"
            "  python3 log_analyzer.py --auth sample_logs/auth.log\n"
            "  python3 log_analyzer.py --web sample_logs/access.log\n"
            "  python3 log_analyzer.py --auth auth.log --web access.log\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--auth",
        help="Path to auth/syslog file (SSH logins, sudo commands)"
    )
    parser.add_argument(
        "--web",
        help="Path to web access log (Apache/Nginx combined format)"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run with included sample logs"
    )
    return parser.parse_args()


# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
def main():
    args = parse_args()

    if args.demo:
        args.auth = "sample_logs/auth.log"
        args.web = "sample_logs/access.log"
        print("\n  Running demo with sample logs...")

    if not args.auth and not args.web:
        print("\n  No log files specified. Try --demo for a quick example!")
        print("  Use -h for all options.\n")
        return

    auth_results = None
    web_results = None

    if args.auth:
        print(f"\n  Analyzing auth log: {args.auth}")
        auth_results = parse_auth_log(args.auth)

    if args.web:
        print(f"  Analyzing web log: {args.web}")
        web_results = parse_web_log(args.web)

    # Assess threats
    threats = assess_threats(auth_results, web_results)

    # Display report
    display_report(threats, auth_results, web_results)


if __name__ == "__main__":
    main()
