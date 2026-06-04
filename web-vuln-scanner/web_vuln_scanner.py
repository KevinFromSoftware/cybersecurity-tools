#!/usr/bin/env python3
"""
Web Vulnerability Scanner - Test websites for common security flaws
Author: [Ditt navn]
Description: Scans a target website for SQL injection, XSS, directory traversal,
             security headers, and exposed sensitive files.

How this connects to your other tools:
  - Subdomain Finder finds targets (e.g. admin.target.com)
  - Port Scanner confirms port 80/443 is open
  - Banner Grabber reveals the web server version
  - Web Vuln Scanner tests the actual web application  ← YOU ARE HERE
  - Log Analyzer (Blue Team) detects these exact attacks in logs

⚠️  FOR EDUCATIONAL USE ONLY — only scan websites you own or have
    explicit written permission to test. Unauthorized scanning is illegal.
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import re
import argparse
import sys
import html
from datetime import datetime
from html.parser import HTMLParser


# -------------------------------------------------------------------
# HTML FORM PARSER — finds input fields to test
# -------------------------------------------------------------------
class FormParser(HTMLParser):
    """
    Extracts forms and their input fields from HTML.
    Forms are the main attack surface for web vulnerabilities —
    anywhere a user can input data is a potential injection point.
    """
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        if tag == "form":
            self.current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": [],
            }

        if tag == "input" and self.current_form is not None:
            self.current_form["inputs"].append({
                "name": attrs_dict.get("name", ""),
                "type": attrs_dict.get("type", "text"),
                "value": attrs_dict.get("value", ""),
            })

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


# -------------------------------------------------------------------
# HTTP HELPER — make requests safely
# -------------------------------------------------------------------
def make_request(url: str, method: str = "GET", data: dict = None,
                 timeout: float = 5.0) -> dict:
    """
    Makes an HTTP request and returns the response.
    Handles errors gracefully — during scanning, many requests will fail.
    """
    try:
        # Allow self-signed certs in lab environments
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if method == "POST" and data:
            encoded = urllib.parse.urlencode(data).encode("utf-8")
            req = urllib.request.Request(url, data=encoded, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        else:
            if data:
                url = f"{url}?{urllib.parse.urlencode(data)}"
            req = urllib.request.Request(url)

        req.add_header("User-Agent", "SecurityScanner/1.0 (Educational)")

        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            headers = dict(resp.headers)
            return {
                "status": resp.status,
                "body": body,
                "headers": headers,
                "url": resp.url,
            }

    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": "", "headers": {}, "url": url}
    except Exception as e:
        return {"status": 0, "body": "", "headers": {}, "url": url, "error": str(e)}


# -------------------------------------------------------------------
# FIND FORMS — discover input points on a page
# -------------------------------------------------------------------
def find_forms(url: str) -> list[dict]:
    """Fetches a page and extracts all HTML forms."""
    resp = make_request(url)
    if not resp["body"]:
        return []

    parser = FormParser()
    try:
        parser.feed(resp["body"])
    except Exception:
        pass

    # Resolve relative form actions to full URLs
    for form in parser.forms:
        action = form["action"]
        if not action or action.startswith("/"):
            base = url.rstrip("/")
            form["action"] = f"{base}{action}" if action else url
        elif not action.startswith("http"):
            form["action"] = f"{url.rstrip('/')}/{action}"

    return parser.forms


# -------------------------------------------------------------------
# FIND LINKS — discover pages to scan
# -------------------------------------------------------------------
def find_links(url: str, body: str) -> list[str]:
    """Extract internal links from HTML to expand scan scope."""
    parsed = urllib.parse.urlparse(url)
    base_domain = f"{parsed.scheme}://{parsed.netloc}"

    links = set()
    href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)

    for match in href_pattern.finditer(body):
        link = match.group(1)

        # Skip anchors, javascript, mailto
        if link.startswith(("#", "javascript:", "mailto:")):
            continue

        # Resolve relative URLs
        if link.startswith("/"):
            link = f"{base_domain}{link}"
        elif not link.startswith("http"):
            link = f"{url.rstrip('/')}/{link}"

        # Only include same-domain links
        if parsed.netloc in link:
            links.add(link.split("#")[0])  # Remove fragments

    return list(links)[:20]  # Limit to avoid scanning too much


# -------------------------------------------------------------------
# TEST: SQL INJECTION
# -------------------------------------------------------------------
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "1' UNION SELECT NULL--",
    "1; DROP TABLE test--",
    "' AND SLEEP(3)--",
]

SQL_ERROR_PATTERNS = [
    r"(?i)(sql syntax)",
    r"(?i)(mysql_fetch)",
    r"(?i)(unclosed quotation)",
    r"(?i)(postgresql.*error)",
    r"(?i)(sqlite.*error)",
    r"(?i)(ORA-\d{5})",
    r"(?i)(syntax error.*near)",
    r"(?i)(microsoft.*odbc)",
    r"(?i)(warning.*mysql)",
    r"(?i)(division by zero)",
]


def test_sql_injection(url: str, forms: list[dict]) -> list[dict]:
    """
    Tests for SQL injection by sending malicious SQL in form inputs
    and checking if the response contains database error messages.

    A database error in response = the input reached the SQL query
    without proper sanitization = VULNERABLE.
    """
    findings = []

    # Test URL parameters
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    for param_name in params:
        for payload in SQL_PAYLOADS:
            test_params = {param_name: payload}
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            resp = make_request(test_url, data=test_params)

            for pattern in SQL_ERROR_PATTERNS:
                if re.search(pattern, resp["body"]):
                    findings.append({
                        "type": "SQL Injection",
                        "severity": "CRITICAL",
                        "location": f"URL parameter: {param_name}",
                        "payload": payload,
                        "evidence": re.search(pattern, resp["body"]).group(0)[:100],
                        "url": url,
                    })
                    break

    # Test form inputs
    for form in forms:
        testable_inputs = [
            inp for inp in form["inputs"]
            if inp["name"] and inp["type"] not in ("submit", "button", "hidden", "checkbox")
        ]

        for inp in testable_inputs:
            for payload in SQL_PAYLOADS[:3]:  # Limit payloads per input
                data = {inp["name"]: payload}
                # Fill other fields with dummy data
                for other in form["inputs"]:
                    if other["name"] and other["name"] != inp["name"]:
                        data[other["name"]] = "test"

                resp = make_request(form["action"], form["method"], data)

                for pattern in SQL_ERROR_PATTERNS:
                    if re.search(pattern, resp["body"]):
                        findings.append({
                            "type": "SQL Injection",
                            "severity": "CRITICAL",
                            "location": f"Form input: {inp['name']} ({form['action']})",
                            "payload": payload,
                            "evidence": re.search(pattern, resp["body"]).group(0)[:100],
                            "url": form["action"],
                        })
                        break

    return findings


# -------------------------------------------------------------------
# TEST: CROSS-SITE SCRIPTING (XSS)
# -------------------------------------------------------------------
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><img src=x onerror=alert(1)>',
    "';alert('XSS');//",
    '<svg onload=alert(1)>',
]


def test_xss(url: str, forms: list[dict]) -> list[dict]:
    """
    Tests for reflected XSS by injecting script tags and checking
    if they appear unescaped in the response.

    If the payload appears in the HTML without encoding = VULNERABLE.
    The browser would execute the script.
    """
    findings = []

    # Test URL parameters
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    for param_name in params:
        for payload in XSS_PAYLOADS:
            test_params = {param_name: payload}
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            resp = make_request(test_url, data=test_params)

            # Check if payload is reflected without encoding
            if payload in resp["body"]:
                findings.append({
                    "type": "Reflected XSS",
                    "severity": "HIGH",
                    "location": f"URL parameter: {param_name}",
                    "payload": payload,
                    "evidence": "Payload reflected unescaped in response",
                    "url": url,
                })
                break

    # Test form inputs
    for form in forms:
        testable_inputs = [
            inp for inp in form["inputs"]
            if inp["name"] and inp["type"] not in ("submit", "button", "hidden")
        ]

        for inp in testable_inputs:
            for payload in XSS_PAYLOADS[:2]:
                data = {inp["name"]: payload}
                for other in form["inputs"]:
                    if other["name"] and other["name"] != inp["name"]:
                        data[other["name"]] = "test"

                resp = make_request(form["action"], form["method"], data)

                if payload in resp["body"]:
                    findings.append({
                        "type": "Reflected XSS",
                        "severity": "HIGH",
                        "location": f"Form input: {inp['name']} ({form['action']})",
                        "payload": payload,
                        "evidence": "Payload reflected unescaped in response",
                        "url": form["action"],
                    })
                    break

    return findings


# -------------------------------------------------------------------
# TEST: DIRECTORY TRAVERSAL / LFI
# -------------------------------------------------------------------
TRAVERSAL_PAYLOADS = [
    ("../../../../etc/passwd", "root:"),
    ("....//....//....//etc/passwd", "root:"),
    ("../../../../windows/system.ini", "[drivers]"),
    ("..%2f..%2f..%2fetc/passwd", "root:"),
]


def test_traversal(url: str) -> list[dict]:
    """
    Tests for directory traversal / Local File Inclusion (LFI).
    Tries to read system files by manipulating file path parameters.
    """
    findings = []

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    # Look for file-related parameters
    file_params = [p for p in params if any(
        kw in p.lower() for kw in ["file", "path", "page", "doc", "template", "include"]
    )]

    for param_name in file_params:
        for payload, evidence_str in TRAVERSAL_PAYLOADS:
            test_params = {param_name: payload}
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            resp = make_request(test_url, data=test_params)

            if evidence_str in resp["body"]:
                findings.append({
                    "type": "Directory Traversal / LFI",
                    "severity": "CRITICAL",
                    "location": f"Parameter: {param_name}",
                    "payload": payload,
                    "evidence": f"System file content detected ('{evidence_str}...')",
                    "url": url,
                })
                break

    return findings


# -------------------------------------------------------------------
# TEST: SECURITY HEADERS
# -------------------------------------------------------------------
def test_security_headers(url: str) -> list[dict]:
    """
    Checks for missing security headers.
    These headers protect against various attacks when properly configured.
    """
    findings = []
    resp = make_request(url)

    headers_to_check = {
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "detail": "Missing X-Frame-Options — vulnerable to clickjacking attacks",
        },
        "X-Content-Type-Options": {
            "severity": "LOW",
            "detail": "Missing X-Content-Type-Options — browser may MIME-sniff content",
        },
        "Strict-Transport-Security": {
            "severity": "MEDIUM",
            "detail": "Missing HSTS header — connections could be downgraded to HTTP",
        },
        "Content-Security-Policy": {
            "severity": "MEDIUM",
            "detail": "Missing CSP header — no protection against inline script injection",
        },
        "X-XSS-Protection": {
            "severity": "LOW",
            "detail": "Missing X-XSS-Protection header (legacy but still useful)",
        },
    }

    # Normalize header names to lowercase for comparison
    resp_headers_lower = {k.lower(): v for k, v in resp["headers"].items()}

    for header, info in headers_to_check.items():
        if header.lower() not in resp_headers_lower:
            findings.append({
                "type": "Missing Security Header",
                "severity": info["severity"],
                "location": f"Header: {header}",
                "payload": "N/A",
                "evidence": info["detail"],
                "url": url,
            })

    # Check for information leakage in headers
    server = resp_headers_lower.get("server", "")
    if server and re.search(r"\d+\.\d+", server):
        findings.append({
            "type": "Information Leakage",
            "severity": "LOW",
            "location": "Server header",
            "payload": "N/A",
            "evidence": f"Server version exposed: {server}",
            "url": url,
        })

    x_powered = resp_headers_lower.get("x-powered-by", "")
    if x_powered:
        findings.append({
            "type": "Information Leakage",
            "severity": "LOW",
            "location": "X-Powered-By header",
            "payload": "N/A",
            "evidence": f"Technology exposed: {x_powered}",
            "url": url,
        })

    return findings


# -------------------------------------------------------------------
# TEST: SENSITIVE FILES
# -------------------------------------------------------------------
SENSITIVE_PATHS = [
    ("/.env", "Environment variables (may contain credentials)"),
    ("/.git/config", "Git repository exposed (source code leak)"),
    ("/robots.txt", "Robots file (reveals hidden paths)"),
    ("/.htaccess", "Apache configuration file"),
    ("/phpmyadmin/", "phpMyAdmin database interface"),
    ("/wp-admin/", "WordPress admin panel"),
    ("/admin/", "Admin panel"),
    ("/server-status", "Apache server status page"),
    ("/backup.sql", "Database backup file"),
    ("/config.php.bak", "PHP config backup"),
    ("/api/", "API endpoint"),
    ("/.well-known/security.txt", "Security contact info"),
    ("/sitemap.xml", "Site structure map"),
    ("/crossdomain.xml", "Flash cross-domain policy"),
]


def test_sensitive_files(base_url: str) -> list[dict]:
    """
    Checks for commonly exposed sensitive files and directories.
    Many of these should never be publicly accessible.
    """
    findings = []
    base = base_url.rstrip("/")

    print(f"  Checking {len(SENSITIVE_PATHS)} sensitive paths...")

    for path, description in SENSITIVE_PATHS:
        resp = make_request(f"{base}{path}", timeout=3.0)

        if resp["status"] == 200 and len(resp.get("body", "")) > 0:
            severity = "CRITICAL" if path in (
                "/.env", "/.git/config", "/backup.sql",
                "/config.php.bak", "/server-status"
            ) else "MEDIUM" if path in (
                "/phpmyadmin/", "/wp-admin/", "/admin/"
            ) else "LOW"

            findings.append({
                "type": "Sensitive File/Path Accessible",
                "severity": severity,
                "location": path,
                "payload": "N/A",
                "evidence": f"{description} (HTTP 200, {len(resp['body'])} bytes)",
                "url": f"{base}{path}",
            })

    return findings


# -------------------------------------------------------------------
# DISPLAY REPORT
# -------------------------------------------------------------------
def display_report(findings: list[dict], target: str, pages_scanned: int):
    """Display scan results."""

    severity_icons = {
        "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"
    }
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 4))

    print(f"\n{'='*65}")
    print(f"  WEB VULNERABILITY SCAN REPORT")
    print(f"  Target   : {target}")
    print(f"  Pages    : {pages_scanned} scanned")
    print(f"  Findings : {len(findings)}")
    print(f"  Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*65}")

    # Summary
    print(f"\n  --- Summary ---")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = sum(1 for f in findings if f["severity"] == level)
        if count:
            print(f"  {severity_icons[level]}  {level}: {count}")

    if not findings:
        print(f"  ✅ No vulnerabilities detected!")
        print(f"  Note: this scanner checks common patterns only.")
        print(f"  A clean scan does not guarantee the site is secure.\n")
        return

    # Group by type
    types_seen = []
    for f in findings:
        if f["type"] not in types_seen:
            types_seen.append(f["type"])

    for vuln_type in types_seen:
        type_findings = [f for f in findings if f["type"] == vuln_type]
        icon = severity_icons.get(type_findings[0]["severity"], "⚪")

        print(f"\n  --- {icon} {vuln_type} ({len(type_findings)} finding(s)) ---")

        for i, f in enumerate(type_findings, 1):
            print(f"    [{f['severity']}] {f['location']}")
            if f["payload"] != "N/A":
                # Truncate long payloads
                payload_display = f["payload"][:60]
                print(f"           Payload : {payload_display}")
            print(f"           Evidence: {f['evidence']}")

    # Recommendations
    print(f"\n  --- Recommendations ---")

    has_type = lambda t: any(f["type"] == t for f in findings)

    if has_type("SQL Injection"):
        print(f"  🔴 Use parameterized queries / prepared statements")
        print(f"     Never concatenate user input into SQL strings")
    if has_type("Reflected XSS"):
        print(f"  🟠 Encode all user input before rendering in HTML")
        print(f"     Implement Content-Security-Policy header")
    if has_type("Directory Traversal / LFI"):
        print(f"  🔴 Validate file paths, use whitelists, never pass user input to file operations")
    if has_type("Sensitive File/Path Accessible"):
        print(f"  🟠 Remove or restrict access to sensitive files")
        print(f"     Add rules in .htaccess or nginx config")
    if has_type("Missing Security Header"):
        print(f"  🟡 Add security headers to web server configuration")
    if has_type("Information Leakage"):
        print(f"  🟢 Hide server version info (ServerTokens Prod)")

    print(f"\n{'='*65}\n")


# -------------------------------------------------------------------
# ARGUMENT PARSING
# -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner — Test websites for common security flaws",
        epilog=(
            "Examples:\n"
            "  python3 web_vuln_scanner.py http://testsite.local\n"
            "  python3 web_vuln_scanner.py http://testsite.local --deep\n"
            "  python3 web_vuln_scanner.py http://testsite.local --skip-files\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "url",
        help="Target URL (e.g. http://testsite.local)"
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Follow links and scan discovered pages too"
    )
    parser.add_argument(
        "--skip-sqli",
        action="store_true",
        help="Skip SQL injection tests"
    )
    parser.add_argument(
        "--skip-xss",
        action="store_true",
        help="Skip XSS tests"
    )
    parser.add_argument(
        "--skip-files",
        action="store_true",
        help="Skip sensitive file checks"
    )
    parser.add_argument(
        "--skip-headers",
        action="store_true",
        help="Skip security header checks"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=5.0,
        help="Request timeout in seconds (default: 5.0)"
    )
    return parser.parse_args()


# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
def main():
    args = parse_args()

    url = args.url.rstrip("/")
    if not url.startswith("http"):
        url = f"http://{url}"

    print(f"\n{'='*65}")
    print(f"  Web Vulnerability Scanner")
    print(f"  Target: {url}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*65}")

    # Check if target is reachable
    print(f"\n  [*] Checking target...")
    resp = make_request(url)
    if resp["status"] == 0:
        print(f"  [ERROR] Cannot reach {url}: {resp.get('error', 'Unknown error')}")
        sys.exit(1)
    print(f"  [+] Target is up (HTTP {resp['status']})")

    all_findings = []
    pages_to_scan = [url]

    # Deep mode: discover more pages
    if args.deep:
        print(f"  [*] Discovering pages...")
        links = find_links(url, resp["body"])
        pages_to_scan.extend(links)
        print(f"  [+] Found {len(links)} additional pages")

    # Scan each page
    for page_url in pages_to_scan:
        print(f"\n  [*] Scanning: {page_url}")

        # Find forms
        forms = find_forms(page_url)
        if forms:
            print(f"  [+] Found {len(forms)} form(s)")

        # SQL Injection
        if not args.skip_sqli:
            print(f"  [*] Testing for SQL injection...")
            findings = test_sql_injection(page_url, forms)
            all_findings.extend(findings)
            if findings:
                print(f"  [!] Found {len(findings)} SQL injection issue(s)")

        # XSS
        if not args.skip_xss:
            print(f"  [*] Testing for XSS...")
            findings = test_xss(page_url, forms)
            all_findings.extend(findings)
            if findings:
                print(f"  [!] Found {len(findings)} XSS issue(s)")

        # Directory traversal
        print(f"  [*] Testing for directory traversal...")
        findings = test_traversal(page_url)
        all_findings.extend(findings)
        if findings:
            print(f"  [!] Found {len(findings)} traversal issue(s)")

    # Security headers (once for base URL)
    if not args.skip_headers:
        print(f"\n  [*] Checking security headers...")
        findings = test_security_headers(url)
        all_findings.extend(findings)

    # Sensitive files (once for base URL)
    if not args.skip_files:
        print(f"\n  [*] Checking for exposed sensitive files...")
        findings = test_sensitive_files(url)
        all_findings.extend(findings)

    # Report
    display_report(all_findings, url, len(pages_to_scan))


if __name__ == "__main__":
    main()
