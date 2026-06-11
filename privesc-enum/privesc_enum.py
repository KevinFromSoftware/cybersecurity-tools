#!/usr/bin/env python3
"""
PrivEsc Enumerator - Linux Privilege Escalation Enumeration
Author: [Ditt navn]
Description: Runs AFTER you have a foothold on a Linux system.
             Enumerates the system from the inside to find ways to
             escalate from a normal user to root.

This covers the "Privilege Escalation" phase from the TryHackMe
Infrastructure pentest methodology:
  1. Enumeration       → scanner.py, banner_grabber.py
  2. Vuln analysis     → cve_lookup.py
  3. Initial access    → (Metasploit / manual exploit)
  4. Privilege esc.    → THIS TOOL
  5. Reporting         → pentest report PDF

What it checks (all read-only, non-destructive):
  - SUID/SGID binaries (can run as the file owner = often root)
  - Sudo permissions (what can you run as root?)
  - World-writable files and directories
  - Files containing the word "password"
  - Readable sensitive files (/etc/shadow, SSH keys, configs)
  - Cron jobs (scheduled tasks that might run as root)
  - Kernel version (for known kernel exploits)
  - PATH and environment issues
  - Interesting capabilities

⚠️  FOR EDUCATIONAL USE ONLY — run only on systems you own or have
    explicit permission to test (your Kali VM, TryHackMe boxes, etc.)

This is a READ-ONLY tool. It does not modify anything or exploit anything.
It only reports what a privilege-escalation attacker would look for —
which is exactly what a defender needs to know to harden the system.
"""

import os
import subprocess
import argparse
import pwd
import grp
import stat
import sys
from datetime import datetime


# -------------------------------------------------------------------
# HELPER: run a shell command safely and return output
# -------------------------------------------------------------------
def run(cmd: str, timeout: int = 15) -> str:
    """Runs a shell command and returns stdout. Errors are suppressed."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, Exception):
        return ""


# -------------------------------------------------------------------
# SECTION HELPER
# -------------------------------------------------------------------
def section(title: str):
    print(f"\n{'='*62}")
    print(f"  {title}")
    print(f"{'='*62}")


def finding(severity: str, text: str):
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "ℹ️ "}
    print(f"  {icons.get(severity, '•')} [{severity}] {text}")


# -------------------------------------------------------------------
# 1. SYSTEM INFO
# -------------------------------------------------------------------
def check_system_info():
    section("System Information")

    kernel = run("uname -r")
    os_release = run("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME")
    hostname = run("hostname")
    arch = run("uname -m")

    print(f"  Hostname : {hostname}")
    print(f"  Kernel   : {kernel}")
    print(f"  Arch     : {arch}")
    if os_release:
        os_name = os_release.split("=", 1)[-1].strip().strip('"')
        print(f"  OS       : {os_name}")

    # Old kernels may have known privilege escalation exploits
    print()
    finding("INFO", f"Search for kernel exploits with: searchsploit linux kernel {kernel}")
    finding("INFO", f"Or check CVEs with: python3 cve_lookup.py \"linux kernel {kernel.split('-')[0]}\"")


# -------------------------------------------------------------------
# 2. CURRENT USER CONTEXT
# -------------------------------------------------------------------
def check_user_context():
    section("Current User Context")

    uid = os.getuid()
    user = pwd.getpwuid(uid).pw_name
    groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]

    print(f"  User   : {user} (uid={uid})")
    print(f"  Groups : {', '.join(groups)}")

    # Being in certain groups is a privesc vector
    dangerous_groups = {
        "docker": "CRITICAL — docker group = trivial root (mount host filesystem)",
        "lxd": "CRITICAL — lxd group = trivial root via container",
        "sudo": "HIGH — user can run sudo (check what)",
        "wheel": "HIGH — admin group, often sudo access",
        "adm": "MEDIUM — can read many log files",
        "disk": "HIGH — raw disk access = read any file",
        "shadow": "HIGH — can read /etc/shadow (password hashes)",
    }

    print()
    for g in groups:
        if g in dangerous_groups:
            sev = dangerous_groups[g].split(" — ")[0]
            finding(sev, f"Member of '{g}' group: {dangerous_groups[g]}")


# -------------------------------------------------------------------
# 3. SUDO PERMISSIONS
# -------------------------------------------------------------------
def check_sudo():
    section("Sudo Permissions")

    # sudo -l shows what the user can run as root (without password if NOPASSWD)
    sudo_out = run("sudo -n -l 2>/dev/null")

    if not sudo_out:
        print("  Could not determine sudo rights without a password.")
        finding("INFO", "Try 'sudo -l' manually (may require your password)")
        return

    print(sudo_out)
    print()

    # NOPASSWD entries are especially dangerous
    if "NOPASSWD" in sudo_out:
        finding("HIGH", "NOPASSWD sudo entries found — can run commands as root without password!")

    # Check for known GTFOBins-style escalation binaries
    gtfo_binaries = ["vim", "nano", "less", "more", "find", "nmap", "python",
                     "perl", "ruby", "awk", "bash", "sh", "cp", "mv", "tar",
                     "zip", "man", "vi", "env", "ftp", "gdb"]
    for binary in gtfo_binaries:
        if binary in sudo_out.lower():
            finding("HIGH", f"'{binary}' in sudo rights — likely exploitable (see GTFOBins.github.io)")


# -------------------------------------------------------------------
# 4. SUID / SGID BINARIES
# -------------------------------------------------------------------
def check_suid_sgid():
    section("SUID / SGID Binaries")
    print("  (SUID binaries run with the file OWNER's privileges,")
    print("   so a SUID-root binary runs as root.)\n")

    # Find SUID binaries
    suid_out = run("find / -perm -4000 -type f 2>/dev/null")
    suid_files = suid_out.split("\n") if suid_out else []

    # Known-exploitable SUID binaries (GTFOBins)
    known_exploitable = {
        "nmap", "vim", "find", "bash", "more", "less", "nano", "cp",
        "mv", "python", "python3", "perl", "ruby", "awk", "man",
        "tar", "zip", "env", "ftp", "gdb", "make", "node", "ed",
    }

    # Standard SUID binaries that are usually fine
    standard = {
        "sudo", "su", "passwd", "chsh", "chfn", "newgrp", "gpasswd",
        "mount", "umount", "ping", "pkexec", "fusermount", "ssh-keysign",
        "polkit-agent-helper-1", "dbus-daemon-launch-helper",
    }

    if not suid_files or suid_files == [""]:
        print("  No SUID binaries found (or no permission to search).")
        return

    print(f"  Found {len(suid_files)} SUID binaries:\n")

    for path in suid_files:
        if not path:
            continue
        name = os.path.basename(path)

        if name in known_exploitable:
            finding("HIGH", f"{path} — potentially exploitable (check GTFOBins)")
        elif name in standard:
            print(f"     (standard) {path}")
        else:
            finding("MEDIUM", f"{path} — unusual SUID binary, investigate")


# -------------------------------------------------------------------
# 5. WORLD-WRITABLE FILES & DIRECTORIES
# -------------------------------------------------------------------
def check_world_writable():
    section("World-Writable Files & Directories")

    # World-writable files owned by root are interesting
    print("  Checking for world-writable files (excluding /proc, /sys)...\n")

    ww_files = run(
        "find / -path /proc -prune -o -path /sys -prune -o "
        "-type f -perm -0002 -print 2>/dev/null | head -30"
    )

    if ww_files:
        files = [f for f in ww_files.split("\n") if f]
        for f in files[:20]:
            # World-writable scripts/configs are the dangerous ones
            if any(f.endswith(ext) for ext in [".sh", ".py", ".pl", ".conf", ".cfg", ".service"]):
                finding("HIGH", f"World-writable script/config: {f}")
            else:
                finding("LOW", f"World-writable: {f}")
    else:
        print("  None found in common locations.")


# -------------------------------------------------------------------
# 6. PASSWORD FILES (the TryHackMe trick!)
# -------------------------------------------------------------------
def check_password_files():
    section("Files Containing 'password'")
    print("  (This is the exact technique from the TryHackMe room:")
    print("   find / -name password* 2>/dev/null)\n")

    pw_files = run("find / -name '*password*' -type f 2>/dev/null | grep -v -E '/(proc|sys|snap)/'")

    if pw_files:
        files = [f for f in pw_files.split("\n") if f]
        for f in files[:25]:
            # Files outside standard system locations are suspicious
            if f.startswith(("/etc/", "/home/", "/root/", "/var/www/", "/opt/", "/tmp/")):
                # Check if readable
                readable = os.access(f, os.R_OK)
                if readable and not any(x in f for x in ["/pam/", "/lib/", ".mod"]):
                    finding("HIGH", f"Readable password file: {f}")
                else:
                    finding("LOW", f"Password-named file: {f}")
    else:
        print("  None found.")

    # Also grep for password= in common config locations
    print()
    print("  Searching config files for hardcoded passwords...")
    cfg_pw = run(
        "grep -rl -i 'password' /etc /var/www /opt 2>/dev/null | head -10"
    )
    if cfg_pw:
        for f in cfg_pw.split("\n"):
            if f and os.access(f, os.R_OK):
                finding("MEDIUM", f"Config may contain credentials: {f}")


# -------------------------------------------------------------------
# 7. SENSITIVE READABLE FILES
# -------------------------------------------------------------------
def check_sensitive_files():
    section("Sensitive File Permissions")

    sensitive = {
        "/etc/shadow": "CRITICAL — password hashes (should NOT be readable)",
        "/etc/passwd": "INFO — user list (normally readable)",
        "/etc/sudoers": "HIGH — sudo config (should NOT be readable)",
        "/root/.ssh/id_rsa": "CRITICAL — root's private SSH key!",
        "/root/.bash_history": "MEDIUM — root command history",
        "/etc/crontab": "INFO — system cron jobs",
    }

    for path, desc in sensitive.items():
        if os.path.exists(path):
            if os.access(path, os.R_OK):
                sev = desc.split(" — ")[0]
                if sev in ("CRITICAL", "HIGH"):
                    finding(sev, f"READABLE: {path} — {desc.split(' — ')[1]}")
                else:
                    finding("INFO", f"Readable: {path}")
            if os.access(path, os.W_OK):
                finding("CRITICAL", f"WRITABLE: {path} — you can modify this!")

    # Look for SSH private keys anywhere readable
    print()
    print("  Searching for SSH private keys...")
    keys = run("find / -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null | head -10")
    if keys:
        for k in keys.split("\n"):
            if k and os.access(k, os.R_OK):
                finding("HIGH", f"Readable SSH private key: {k}")


# -------------------------------------------------------------------
# 8. CRON JOBS
# -------------------------------------------------------------------
def check_cron():
    section("Scheduled Tasks (Cron)")
    print("  (Cron jobs often run as root. A writable script in a")
    print("   root cron job = root access.)\n")

    crontab = run("cat /etc/crontab 2>/dev/null")
    if crontab:
        print("  /etc/crontab contents:")
        for line in crontab.split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and ("*" in line or "@" in line):
                print(f"    {line}")
                # Extract script paths and check if writable
                parts = line.split()
                for part in parts:
                    if part.startswith("/") and os.path.exists(part):
                        if os.access(part, os.W_OK):
                            finding("CRITICAL", f"Writable script in cron: {part}")

    # Cron directories
    cron_dirs = run("ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly 2>/dev/null | head -20")
    if cron_dirs:
        print(f"\n  Cron directories exist — check for writable scripts there too.")


# -------------------------------------------------------------------
# 9. CAPABILITIES
# -------------------------------------------------------------------
def check_capabilities():
    section("File Capabilities")
    print("  (Linux capabilities can grant specific root-like powers")
    print("   to binaries without full SUID.)\n")

    caps = run("getcap -r / 2>/dev/null | head -20")
    if caps:
        for line in caps.split("\n"):
            if not line:
                continue
            # cap_setuid is the dangerous one
            if "cap_setuid" in line or "cap_dac_override" in line or "cap_sys_admin" in line:
                finding("HIGH", f"Dangerous capability: {line}")
            else:
                finding("LOW", f"Capability: {line}")
    else:
        print("  No special capabilities found (or getcap unavailable).")


# -------------------------------------------------------------------
# 10. SUMMARY
# -------------------------------------------------------------------
def print_summary():
    section("Next Steps")
    print("""  Review the findings above, focusing on CRITICAL and HIGH items.

  Common escalation paths:
    • SUID binary in GTFOBins  → check gtfobins.github.io for the exploit
    • Sudo NOPASSWD entry      → run the allowed command to spawn a root shell
    • Writable cron script     → inject a command, wait for it to run as root
    • Readable password file   → use credentials with su/ssh
    • docker/lxd group         → mount host filesystem as root

  For DEFENDERS (Blue Team), each finding is something to fix:
    • Remove unnecessary SUID bits (chmod -s)
    • Restrict sudo rules to specific commands
    • Never store plaintext passwords on disk
    • Make cron scripts root-owned and non-writable
    • Set correct permissions on sensitive files

  Reference: gtfobins.github.io  (the definitive SUID/sudo exploit list)
""")


# -------------------------------------------------------------------
# ARGUMENT PARSING
# -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="PrivEsc Enumerator — Linux privilege escalation enumeration (read-only)",
        epilog="Example: python3 privesc_enum.py        (runs all checks)\n"
               "         python3 privesc_enum.py --quick  (skips slow filesystem searches)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Skip slow full-filesystem searches (SUID, world-writable, etc.)"
    )
    return parser.parse_args()


# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
def main():
    args = parse_args()

    print(f"\n{'#'*62}")
    print(f"#  PrivEsc Enumerator — Linux Privilege Escalation Recon")
    print(f"#  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"#  READ-ONLY: this tool only reports, it never modifies or exploits")
    print(f"{'#'*62}")

    # Always run these (fast)
    check_system_info()
    check_user_context()
    check_sudo()
    check_sensitive_files()
    check_cron()

    # Slower filesystem-wide searches
    if not args.quick:
        check_suid_sgid()
        check_world_writable()
        check_password_files()
        check_capabilities()
    else:
        print("\n  [Quick mode: skipped SUID, world-writable, password, capability searches]")

    print_summary()


if __name__ == "__main__":
    main()
