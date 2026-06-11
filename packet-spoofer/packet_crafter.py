#!/usr/bin/env python3
"""
Packet Crafter - Build and send custom network packets (educational)
Author: [Ditt navn]
Description: Demonstrates how network packets are constructed layer by layer,
             and how fields like source IP can be "spoofed" (forged).
             Understanding this is essential for grasping how many network
             attacks work — and how to defend against them.

This completes your toolkit by covering packet manipulation, the
counterpart to the network sniffer (which only listens).

What it demonstrates:
  - How a packet is built layer by layer (Ethernet → IP → TCP/UDP → data)
  - Source IP spoofing (and why it usually doesn't get replies)
  - Crafting custom ICMP, TCP, and DNS packets
  - ARP — the protocol behind man-in-the-middle attacks (explained, demoed safely)

⚠️  CRITICAL — LEGAL & ETHICAL BOUNDARIES:
  - Requires ROOT/sudo and the 'scapy' library
  - ONLY send packets on networks you OWN or have explicit permission to test
    (your own isolated Kali lab, your own home network).
  - Spoofing/injecting packets on networks you don't control is illegal in
    most countries (Norway: straffeloven). Doing it on the internet or a
    workplace/school network without authorization is a crime.
  - This tool is built for LEARNING how protocols work in an isolated lab.
    It deliberately does NOT include attack automation (no ARP-poisoning
    loops, no flooding). It crafts single, observable packets so you can
    SEE how they're structured — pair it with your sniffer to watch them.
"""

import argparse
import sys

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, DNS, DNSQR, ARP, Ether, Raw, send, sr1, srp
    )
except ImportError:
    print("\n[ERROR] This tool requires Scapy.")
    print("In Kali:  sudo apt install python3-scapy -y")
    print("Then run with sudo:  sudo python3 packet_crafter.py <command>\n")
    sys.exit(1)


# -------------------------------------------------------------------
# DEMO 1: Show how a packet is built layer by layer
# -------------------------------------------------------------------
def demo_layers(target_ip: str):
    """
    Builds a packet step by step and shows each layer.
    This is the foundation: every network packet is layers stacked together.
    """
    print(f"\n{'='*62}")
    print(f"  How a Packet is Built — Layer by Layer")
    print(f"{'='*62}\n")

    print("  Network packets are built like nested envelopes.")
    print("  Each layer adds its own header with specific information.\n")

    # Layer 3: IP
    print("  Layer 3 — IP (handles addressing/routing):")
    ip_layer = IP(dst=target_ip)
    print(f"    IP(dst='{target_ip}')")
    print(f"    → src: {ip_layer.src} (your machine, filled in automatically)")
    print(f"    → dst: {ip_layer.dst}")
    print(f"    → ttl: {ip_layer.ttl} (time-to-live: max hops before discarded)\n")

    # Layer 4: TCP
    print("  Layer 4 — TCP (handles ports/connections):")
    tcp_layer = TCP(dport=80, sport=12345, flags="S")
    print(f"    TCP(dport=80, sport=12345, flags='S')")
    print(f"    → dport: 80 (destination port — HTTP)")
    print(f"    → sport: 12345 (source port)")
    print(f"    → flags: S (SYN — the first step of a TCP handshake)\n")

    # Stack them
    print("  Stacking the layers with the '/' operator:")
    packet = ip_layer / tcp_layer
    print(f"    packet = IP(dst='{target_ip}') / TCP(dport=80, flags='S')\n")

    print("  The complete packet structure:")
    print("  " + "-"*58)
    # Show scapy's packet summary
    for line in packet.show(dump=True).split("\n"):
        print(f"  {line}")


# -------------------------------------------------------------------
# DEMO 2: Send a ping (ICMP) and get a reply
# -------------------------------------------------------------------
def demo_ping(target_ip: str, timeout: int = 3):
    """
    Crafts an ICMP echo request (ping) manually and sends it.
    Shows that 'ping' is just a crafted packet under the hood.
    """
    print(f"\n{'='*62}")
    print(f"  Crafting a Ping (ICMP Echo) to {target_ip}")
    print(f"{'='*62}\n")

    packet = IP(dst=target_ip) / ICMP()
    print(f"  Built: IP(dst='{target_ip}') / ICMP()")
    print(f"  Sending and waiting for a reply...\n")

    reply = sr1(packet, timeout=timeout, verbose=False)

    if reply:
        print(f"  ✓ Got a reply from {reply.src}!")
        print(f"    The host is alive. TTL={reply.ttl}")
        print(f"    (TTL hints at the OS: ~64=Linux, ~128=Windows)")
    else:
        print(f"  ✗ No reply (host may be down, or blocking ICMP)")


# -------------------------------------------------------------------
# DEMO 3: Source IP spoofing — and why it usually fails
# -------------------------------------------------------------------
def demo_spoof(target_ip: str, fake_src: str):
    """
    Demonstrates source IP spoofing: forging the 'from' address.
    Crucially, also explains WHY you usually won't see a reply —
    which teaches a core networking concept.
    """
    print(f"\n{'='*62}")
    print(f"  Source IP Spoofing — Educational Demo")
    print(f"{'='*62}\n")

    print(f"  We'll build a packet that CLAIMS to come from {fake_src}")
    print(f"  but is actually sent from your machine.\n")

    packet = IP(src=fake_src, dst=target_ip) / ICMP()
    print(f"  Built: IP(src='{fake_src}', dst='{target_ip}') / ICMP()")
    print(f"    → The packet's 'src' field says: {fake_src}")
    print(f"    → But it physically leaves YOUR network card\n")

    print(f"  Sending the spoofed packet...")
    send(packet, verbose=False)
    print(f"  ✓ Packet sent.\n")

    print(f"  --- Why you (probably) won't get a reply ---")
    print(f"  The target will send its reply to {fake_src}, NOT to you,")
    print(f"  because that's what the packet said the source was.")
    print(f"  So YOU never see the answer — it goes to the spoofed address.\n")

    print(f"  --- Why this matters for security ---")
    print(f"  • This is how DDoS reflection/amplification attacks work:")
    print(f"    attackers spoof the victim's IP so replies flood the victim.")
    print(f"  • It's why 'source IP' alone is NEVER trustworthy for auth.")
    print(f"  • Defenders use 'ingress/egress filtering' (BCP38) to drop")
    print(f"    packets with forged source addresses at the network edge.\n")

    print(f"  Tip: run your network_sniffer.py on the target to SEE")
    print(f"  this packet arrive with the fake source address!")


# -------------------------------------------------------------------
# DEMO 4: Craft a custom DNS query
# -------------------------------------------------------------------
def demo_dns(domain: str, dns_server: str = "8.8.8.8", timeout: int = 3):
    """
    Manually builds a DNS query packet and sends it.
    Shows that DNS lookups are just crafted UDP packets.
    """
    print(f"\n{'='*62}")
    print(f"  Crafting a DNS Query for '{domain}'")
    print(f"{'='*62}\n")

    packet = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
    print(f"  Built a DNS query:")
    print(f"    IP(dst='{dns_server}') / UDP(dport=53) / DNS(qd=DNSQR(qname='{domain}'))")
    print(f"  Sending to DNS server {dns_server}...\n")

    reply = sr1(packet, timeout=timeout, verbose=False)

    if reply and reply.haslayer(DNS):
        dns = reply[DNS]
        print(f"  ✓ Got a DNS response with {dns.ancount} answer(s):\n")
        for i in range(dns.ancount):
            try:
                answer = dns.an[i]
                rrname = answer.rrname.decode("utf-8", errors="ignore").rstrip(".")
                rdata = answer.rdata
                print(f"    {rrname} → {rdata}")
            except Exception:
                pass
    else:
        print(f"  ✗ No DNS response received")


# -------------------------------------------------------------------
# DEMO 5: ARP explained (the MITM protocol)
# -------------------------------------------------------------------
def demo_arp(network_hint: str = None):
    """
    Explains ARP and how it relates to man-in-the-middle attacks.
    Does NOT perform ARP poisoning — only explains and shows a
    legitimate ARP request, so you understand the mechanism.
    """
    print(f"\n{'='*62}")
    print(f"  ARP — The Protocol Behind Man-in-the-Middle Attacks")
    print(f"{'='*62}\n")

    print("  ARP (Address Resolution Protocol) maps IP addresses to")
    print("  physical MAC addresses on a local network.\n")

    print("  Normal flow:")
    print("    Computer A: 'Who has IP 192.168.1.1? Tell me your MAC.'")
    print("    Router:     'I have 192.168.1.1, my MAC is aa:bb:cc:dd:ee:ff'")
    print("    → A now sends traffic for the router to that MAC.\n")

    print("  The vulnerability (ARP spoofing / poisoning):")
    print("    ARP has NO authentication. An attacker can lie:")
    print("    Attacker: 'Actually, *I* have 192.168.1.1, here's MY MAC'")
    print("    → Victim now sends router-bound traffic to the ATTACKER.")
    print("    → Attacker forwards it on, silently reading everything.")
    print("    → This is a classic man-in-the-middle (MITM) attack.\n")

    print("  --- Why we DON'T automate this here ---")
    print("  Performing ARP poisoning on a real network you don't fully")
    print("  control is illegal and disruptive. This tool only EXPLAINS it.")
    print("  To practice MITM legally, use an isolated lab with intentionally")
    print("  vulnerable VMs (e.g. in your own Kali + a target VM).\n")

    print("  --- Defenses ---")
    print("  • Static ARP entries for critical hosts")
    print("  • Dynamic ARP Inspection (DAI) on managed switches")
    print("  • Encryption (HTTPS/SSH) so MITM sees only ciphertext")
    print("  • ARP-monitoring tools (e.g. arpwatch) that alert on changes")


# -------------------------------------------------------------------
# ARGUMENT PARSING
# -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Packet Crafter — Learn how packets are built and sent (educational)",
        epilog=(
            "Examples (all need sudo in Kali):\n"
            "  sudo python3 packet_crafter.py layers 192.168.1.1\n"
            "  sudo python3 packet_crafter.py ping 8.8.8.8\n"
            "  sudo python3 packet_crafter.py dns github.com\n"
            "  sudo python3 packet_crafter.py spoof 192.168.1.50 --fake-src 192.168.1.99\n"
            "  sudo python3 packet_crafter.py arp\n\n"
            "Tip: run network_sniffer.py in another terminal to watch your packets!"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    sub = parser.add_subparsers(dest="command", help="What to demonstrate")

    p_layers = sub.add_parser("layers", help="Show how a packet is built layer by layer")
    p_layers.add_argument("target", help="Target IP (for demonstration)")

    p_ping = sub.add_parser("ping", help="Craft and send an ICMP ping")
    p_ping.add_argument("target", help="Target IP to ping")

    p_dns = sub.add_parser("dns", help="Craft and send a DNS query")
    p_dns.add_argument("domain", help="Domain to look up")
    p_dns.add_argument("--server", default="8.8.8.8", help="DNS server (default 8.8.8.8)")

    p_spoof = sub.add_parser("spoof", help="Demonstrate source IP spoofing")
    p_spoof.add_argument("target", help="Target IP")
    p_spoof.add_argument("--fake-src", required=True, help="Forged source IP")

    sub.add_parser("arp", help="Explain ARP and man-in-the-middle (no attack performed)")

    return parser.parse_args()


# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
def main():
    args = parse_args()

    if not args.command:
        print("\n  Packet Crafter — pick something to demonstrate:")
        print("    layers <ip>   — see how a packet is built")
        print("    ping <ip>     — craft and send a ping")
        print("    dns <domain>  — craft and send a DNS query")
        print("    spoof <ip> --fake-src <ip> — source IP spoofing demo")
        print("    arp           — learn how MITM attacks work")
        print("\n  Use -h for full help.\n")
        return

    # ARP demo doesn't need root (it only explains)
    if args.command == "arp":
        demo_arp()
        return

    # Everything else needs root
    import os
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("\n[ERROR] Sending packets requires root.")
        print("Run with sudo:  sudo python3 packet_crafter.py ...\n")
        sys.exit(1)

    if args.command == "layers":
        demo_layers(args.target)
    elif args.command == "ping":
        demo_ping(args.target)
    elif args.command == "dns":
        demo_dns(args.domain, args.server)
    elif args.command == "spoof":
        demo_spoof(args.target, args.fake_src)


if __name__ == "__main__":
    main()
