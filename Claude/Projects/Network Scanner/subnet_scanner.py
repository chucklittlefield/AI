#!/usr/bin/env python3
"""
Subnet Scanner
Scans a subnet and reports MAC Address, IP Address, Hostname, and OS for each live host.

Requirements:
    pip install scapy python-nmap

Must be run as Administrator (Windows) or root (Linux/macOS) for ARP and OS detection.
"""

import argparse
import socket
import sys
from datetime import datetime

try:
    import nmap
except ImportError:
    sys.exit("[!] python-nmap not found. Run: pip install python-nmap")

try:
    from scapy.all import ARP, Ether, srp
except ImportError:
    sys.exit("[!] scapy not found. Run: pip install scapy")


def resolve_hostname(ip: str) -> str:
    """Attempt reverse DNS lookup; return IP if lookup fails."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "N/A"


def arp_scan(subnet: str, timeout: int = 2) -> list[dict]:
    """
    Send ARP requests across the subnet.
    Returns a list of dicts with 'ip' and 'mac'.
    """
    print(f"[*] ARP scanning {subnet} ...")
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _ = srp(packet, timeout=timeout, verbose=False)

    hosts = []
    for sent, received in answered:
        hosts.append({"ip": received.psrc, "mac": received.hwsrc.upper()})

    return hosts


def os_detect(ip: str, nm: nmap.PortScanner) -> str:
    """
    Use nmap OS detection (-O) on a single host.
    Returns a best-guess OS string or 'Unknown'.
    """
    try:
        nm.scan(hosts=ip, arguments="-O --osscan-guess -T4 --max-retries 1")
        if ip in nm.all_hosts():
            os_matches = nm[ip].get("osmatch", [])
            if os_matches:
                best = os_matches[0]
                name = best.get("name", "Unknown")
                accuracy = best.get("accuracy", "?")
                return f"{name} ({accuracy}% match)"
    except Exception:
        pass
    return "Unknown"


def print_table(results: list[dict]) -> None:
    """Pretty-print results as a fixed-width table."""
    col_widths = {
        "ip":       max(len("IP Address"),    max(len(r["ip"])       for r in results)),
        "mac":      max(len("MAC Address"),   max(len(r["mac"])      for r in results)),
        "hostname": max(len("Hostname"),      max(len(r["hostname"]) for r in results)),
        "os":       max(len("OS"),            max(len(r["os"])       for r in results)),
    }

    header = (
        f"{'IP Address':<{col_widths['ip']}}  "
        f"{'MAC Address':<{col_widths['mac']}}  "
        f"{'Hostname':<{col_widths['hostname']}}  "
        f"{'OS':<{col_widths['os']}}"
    )
    separator = "-" * len(header)

    print(f"\n{separator}")
    print(header)
    print(separator)
    for r in sorted(results, key=lambda x: socket.inet_aton(x["ip"])):
        print(
            f"{r['ip']:<{col_widths['ip']}}  "
            f"{r['mac']:<{col_widths['mac']}}  "
            f"{r['hostname']:<{col_widths['hostname']}}  "
            f"{r['os']:<{col_widths['os']}}"
        )
    print(separator)


def save_csv(results: list[dict], filename: str) -> None:
    """Save results to a CSV file."""
    import csv
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "mac", "hostname", "os"])
        writer.writeheader()
        writer.writerows(sorted(results, key=lambda x: socket.inet_aton(x["ip"])))
    print(f"[+] Results saved to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="Subnet scanner — reports IP, MAC, Hostname, and OS for each live host.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python subnet_scanner.py 192.168.1.0/24\n"
               "  python subnet_scanner.py 10.0.0.0/24 --no-os\n"
               "  python subnet_scanner.py 192.168.1.0/24 --csv results.csv",
    )
    parser.add_argument("subnet", help="Target subnet in CIDR notation (e.g. 192.168.1.0/24)")
    parser.add_argument("--timeout", type=int, default=2, help="ARP timeout in seconds (default: 2)")
    parser.add_argument("--no-os", action="store_true", help="Skip OS detection (faster)")
    parser.add_argument("--csv", metavar="FILE", help="Also save results to a CSV file")
    args = parser.parse_args()

    print("=" * 60)
    print(f"  Subnet Scanner")
    print(f"  Target  : {args.subnet}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  OS Scan : {'Disabled' if args.no_os else 'Enabled (requires admin/root)'}")
    print("=" * 60)

    # Step 1 — ARP scan to find live hosts and MAC addresses
    hosts = arp_scan(args.subnet, timeout=args.timeout)
    if not hosts:
        print("[!] No hosts found. Verify the subnet and that you are running as administrator.")
        sys.exit(1)
    print(f"[+] Found {len(hosts)} live host(s).\n")

    # Step 2 — Resolve hostnames and (optionally) detect OS
    nm = nmap.PortScanner() if not args.no_os else None
    results = []

    for i, host in enumerate(hosts, 1):
        ip = host["ip"]
        print(f"[{i}/{len(hosts)}] Processing {ip} ...", end=" ", flush=True)

        hostname = resolve_hostname(ip)
        os_info = os_detect(ip, nm) if not args.no_os else "Skipped"

        print("done")
        results.append({"ip": ip, "mac": host["mac"], "hostname": hostname, "os": os_info})

    # Step 3 — Display and optionally save
    print_table(results)

    if args.csv:
        save_csv(results, args.csv)

    print(f"\n[*] Scan complete at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
