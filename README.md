# 🛡️ Cybersecurity Toolkit

A collection of ten security tools built from scratch in Python, covering the full penetration-testing workflow — from reconnaissance to reporting. Built as a hands-on learning project alongside my Bachelor in Cyber Security at Noroff University College.

> **Why build my own tools?** Anyone can run Nmap or Metasploit. Building these from scratch means I understand exactly what happens under the hood — TCP handshakes, DNS resolution, packet structure, hash cracking — not just which button to press. Each tool maps to a real phase of a professional penetration test.

---

## ⚠️ Legal & Ethical Use

These tools are for **education and authorized testing only**. Only use them on systems you own or have explicit written permission to test (your own lab, isolated VMs, or dedicated practice targets like `scanme.nmap.org`, DVWA, and TryHackMe).

Unauthorized scanning, sniffing, or packet injection is illegal in most countries (in Norway, under straffeloven). Use responsibly.

---

## 🧰 The Toolkit

The tools are organized by their role in a penetration test. The arrow shows how they chain together in a real engagement.

```
RECON  ───────────►  ANALYSIS  ───────►  POST-EXPLOIT  ───►  DEFENSE
subdomain-finder     cve-lookup          privesc-enum        log-analyzer
port-scanner         web-vuln-scanner                        network-sniffer
banner-grabber                                               packet-spoofer
hash-cracker
```

### Reconnaissance

| Tool | Description |
|------|-------------|
| **subdomain-finder** | Discovers subdomains via DNS brute force (multi-threaded). Finds hidden admin panels, dev servers, and APIs before port scanning begins. |
| **port-scanner** | TCP port scanner using raw sockets. Identifies open ports and the services likely behind them. |
| **banner-grabber** | Connects to open ports and reads service banners to reveal software and version numbers. v2 adds HTTP probing on any port, header parsing, and threading. |
| **hash-cracker** | Reverses password hashes (MD5/SHA family) via dictionary and brute-force attacks. Demonstrates why weak passwords fall in seconds. |

### Vulnerability Analysis

| Tool | Description |
|------|-------------|
| **cve-lookup** | Queries the NIST National Vulnerability Database (NVD) for known CVEs affecting a given software version. |
| **web-vuln-scanner** | Tests web applications for SQL injection, XSS, directory traversal, missing security headers, and exposed sensitive files. |

### Post-Exploitation

| Tool | Description |
|------|-------------|
| **privesc-enum** | Read-only Linux privilege-escalation enumerator. Checks SUID binaries, sudo rules, cron jobs, writable files, and readable secrets — everything an attacker (or defender) needs to find a path to root. |

### Defense & Network Analysis

| Tool | Description |
|------|-------------|
| **log-analyzer** | Blue Team tool that parses auth and web-server logs to detect brute force, SQL injection, scanner activity, and account compromise. |
| **network-sniffer** | Captures and analyzes live network traffic with Scapy. Breaks down protocols, tracks top talkers, and flags plaintext credentials. |
| **packet-spoofer** | Educational packet crafter. Shows how packets are built layer by layer and demonstrates source-IP spoofing and the ARP mechanism behind man-in-the-middle attacks. |

---

## 🚀 Quick Start

Every tool is standalone Python 3 and supports `-h` for help.

```bash
# Clone the repository
git clone https://github.com/KevinFromSoftware/cybersecurity-tools.git
cd cybersecurity-tools

# Reconnaissance
python3 port-scanner/scanner.py scanme.nmap.org -s 1 -e 1024
python3 banner-grabber/banner_grabber.py scanme.nmap.org --top-ports
python3 subdomain-finder/subdomain_finder.py example.com

# Analysis
python3 cve-lookup/cve_lookup.py "OpenSSH 8.9"
python3 web-vuln-scanner/web_vuln_scanner.py http://testphp.vulnweb.com

# Defense
python3 log-analyzer/log_analyzer.py --demo
python3 hash-cracker/hash_cracker.py --demo
```

Tools that capture or send packets require root and Scapy (run these in Kali Linux):

```bash
sudo apt install python3-scapy -y
sudo python3 network-sniffer/network_sniffer.py -t 30 -v
sudo python3 packet-spoofer/packet_crafter.py arp
```

---

## 🔗 The Attack Chain in Action

These tools aren't isolated — they form a workflow that mirrors a real infrastructure pentest:

1. **subdomain-finder** discovers `admin.target.com`
2. **port-scanner** finds ports 22, 80, and 3306 open
3. **banner-grabber** reveals the host runs OpenSSH 6.6.1 and nginx
4. **cve-lookup** finds known vulnerabilities for those versions
5. **web-vuln-scanner** tests the web app for injectable inputs
6. *(initial access gained)*
7. **privesc-enum** finds a path from user to root
8. **log-analyzer** shows the same attack from the **defender's** side

This Red Team / Blue Team duality is intentional: the same knowledge that finds a weakness is what fixes it.

---

## 🛠️ Built With

- **Python 3** — no heavy frameworks; mostly standard library
- **Scapy** — for packet capture and crafting
- **NIST NVD API** — for live vulnerability data

---

## 📚 What I Learned

- How core protocols actually work: TCP/IP, DNS, ARP, HTTP
- The full penetration-testing methodology (enumeration → reporting)
- Why encryption matters — seeing plaintext credentials cross a wire makes it concrete
- The defender's perspective: every offensive technique has a defensive countermeasure
- Writing clean, documented, reusable code and version-controlling it with Git

---

## 📄 License

For educational use. Built as a learning project — contributions and feedback welcome.

---

*Part of my journey into cybersecurity at Noroff University College.*
