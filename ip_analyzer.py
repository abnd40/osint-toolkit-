#!/usr/bin/env python3
"""
IP Geolocation and Reputation Analyzer
=======================================

This module provides IP address intelligence gathering including:
- Geolocation data (country, city, ISP, coordinates)
- WHOIS/ASN information
- Reputation checks via multiple threat intelligence sources
- Reverse DNS lookup

Author: OSINT Toolkit
License: MIT
"""

import argparse
import socket
import sys
import re
from datetime import datetime
from typing import Optional, Tuple

try:
    import requests
    from ipwhois import IPWhois
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] Run: pip install -r requirements.txt")
    sys.exit(1)

console = Console()

# Free IP geolocation APIs (no API key required)
GEOLOCATION_APIS = {
    "ip-api": "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query",
    "ipapi": "https://ipapi.co/{ip}/json/",
}

# AbuseIPDB categories
ABUSE_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


def validate_ip(ip: str) -> bool:
    """
    Validate if the input is a valid IPv4 or IPv6 address.

    Args:
        ip: IP address string

    Returns:
        True if valid, False otherwise
    """
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # IPv6 pattern (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'

    if re.match(ipv4_pattern, ip):
        # Validate each octet
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    elif re.match(ipv6_pattern, ip):
        return True

    return False


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is in a private range.

    Args:
        ip: IP address string

    Returns:
        True if private, False otherwise
    """
    private_ranges = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'),
        ('127.0.0.0', '127.255.255.255'),
    ]

    try:
        ip_parts = [int(p) for p in ip.split('.')]
        ip_num = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]

        for start, end in private_ranges:
            start_parts = [int(p) for p in start.split('.')]
            end_parts = [int(p) for p in end.split('.')]
            start_num = (start_parts[0] << 24) + (start_parts[1] << 16) + (start_parts[2] << 8) + start_parts[3]
            end_num = (end_parts[0] << 24) + (end_parts[1] << 16) + (end_parts[2] << 8) + end_parts[3]

            if start_num <= ip_num <= end_num:
                return True
    except:
        pass

    return False


def resolve_hostname(hostname: str) -> Optional[str]:
    """
    Resolve a hostname to its IP address.

    Args:
        hostname: Domain or hostname

    Returns:
        IP address string or None
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def reverse_dns_lookup(ip: str) -> Optional[str]:
    """
    Perform reverse DNS lookup on an IP address.

    Args:
        ip: IP address string

    Returns:
        Hostname or None
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


def get_geolocation(ip: str) -> Optional[dict]:
    """
    Get geolocation data for an IP address using free APIs.

    Args:
        ip: IP address string

    Returns:
        Dictionary containing geolocation data or None
    """
    console.print(f"\n[cyan][*] Fetching geolocation data for {ip}...[/cyan]")

    # Try ip-api first (more fields, higher rate limit)
    try:
        url = GEOLOCATION_APIS["ip-api"].format(ip=ip)
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            data = response.json()

            if data.get("status") == "success":
                return {
                    "ip": data.get("query", ip),
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "zip_code": data.get("zip"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("isp"),
                    "organization": data.get("org"),
                    "asn": data.get("as"),
                    "as_name": data.get("asname"),
                    "reverse_dns": data.get("reverse"),
                    "is_mobile": data.get("mobile"),
                    "is_proxy": data.get("proxy"),
                    "is_hosting": data.get("hosting"),
                }

    except requests.RequestException as e:
        console.print(f"[yellow][!] ip-api request failed: {e}[/yellow]")

    # Fallback to ipapi.co
    try:
        url = GEOLOCATION_APIS["ipapi"].format(ip=ip)
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            data = response.json()

            if not data.get("error"):
                return {
                    "ip": data.get("ip", ip),
                    "country": data.get("country_name"),
                    "country_code": data.get("country_code"),
                    "region": data.get("region"),
                    "city": data.get("city"),
                    "zip_code": data.get("postal"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("org"),
                    "organization": data.get("org"),
                    "asn": data.get("asn"),
                    "as_name": data.get("org"),
                    "reverse_dns": None,
                    "is_mobile": None,
                    "is_proxy": None,
                    "is_hosting": None,
                }

    except requests.RequestException as e:
        console.print(f"[yellow][!] ipapi.co request failed: {e}[/yellow]")

    return None


def display_geolocation(geo_data: dict) -> None:
    """
    Display geolocation data in a formatted table.

    Args:
        geo_data: Dictionary containing geolocation information
    """
    if not geo_data:
        console.print("[yellow][!] No geolocation data available[/yellow]")
        return

    table = Table(title="IP Geolocation", show_header=True, header_style="bold magenta")
    table.add_column("Field", style="cyan", width=20)
    table.add_column("Value", style="green")

    # Define display order and labels
    fields = [
        ("ip", "IP Address"),
        ("country", "Country"),
        ("country_code", "Country Code"),
        ("region", "Region"),
        ("city", "City"),
        ("zip_code", "ZIP/Postal Code"),
        ("latitude", "Latitude"),
        ("longitude", "Longitude"),
        ("timezone", "Timezone"),
        ("isp", "ISP"),
        ("organization", "Organization"),
        ("asn", "ASN"),
        ("as_name", "AS Name"),
        ("reverse_dns", "Reverse DNS"),
    ]

    for key, label in fields:
        value = geo_data.get(key)
        if value is not None:
            table.add_row(label, str(value))

    console.print(table)

    # Display flags
    flags = []
    if geo_data.get("is_mobile"):
        flags.append("[yellow]Mobile Network[/yellow]")
    if geo_data.get("is_proxy"):
        flags.append("[red]Proxy/VPN Detected[/red]")
    if geo_data.get("is_hosting"):
        flags.append("[cyan]Hosting/Datacenter[/cyan]")

    if flags:
        console.print(f"\n[bold]Flags:[/bold] {' | '.join(flags)}")

    # Display map link
    if geo_data.get("latitude") and geo_data.get("longitude"):
        lat, lon = geo_data["latitude"], geo_data["longitude"]
        map_url = f"https://www.google.com/maps?q={lat},{lon}"
        console.print(f"\n[dim]Map: {map_url}[/dim]")


def get_whois_info(ip: str) -> Optional[dict]:
    """
    Get WHOIS/ASN information for an IP address.

    Args:
        ip: IP address string

    Returns:
        Dictionary containing WHOIS data or None
    """
    console.print(f"\n[cyan][*] Fetching WHOIS/ASN information for {ip}...[/cyan]")

    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap(depth=1)

        return {
            "asn": results.get("asn"),
            "asn_cidr": results.get("asn_cidr"),
            "asn_country_code": results.get("asn_country_code"),
            "asn_date": results.get("asn_date"),
            "asn_registry": results.get("asn_registry"),
            "asn_description": results.get("asn_description"),
            "network_name": results.get("network", {}).get("name"),
            "network_cidr": results.get("network", {}).get("cidr"),
            "network_start": results.get("network", {}).get("start_address"),
            "network_end": results.get("network", {}).get("end_address"),
        }

    except Exception as e:
        console.print(f"[yellow][!] WHOIS lookup failed: {e}[/yellow]")
        return None


def display_whois_info(whois_data: dict) -> None:
    """
    Display WHOIS/ASN information in a formatted table.

    Args:
        whois_data: Dictionary containing WHOIS information
    """
    if not whois_data:
        console.print("[yellow][!] No WHOIS data available[/yellow]")
        return

    table = Table(title="WHOIS/ASN Information", show_header=True, header_style="bold magenta")
    table.add_column("Field", style="cyan", width=20)
    table.add_column("Value", style="green")

    fields = [
        ("asn", "ASN"),
        ("asn_description", "ASN Description"),
        ("asn_cidr", "ASN CIDR"),
        ("asn_country_code", "ASN Country"),
        ("asn_date", "ASN Date"),
        ("asn_registry", "Registry"),
        ("network_name", "Network Name"),
        ("network_cidr", "Network CIDR"),
        ("network_start", "Network Start"),
        ("network_end", "Network End"),
    ]

    for key, label in fields:
        value = whois_data.get(key)
        if value is not None:
            table.add_row(label, str(value))

    console.print(table)


def check_reputation(ip: str) -> dict:
    """
    Check IP reputation using free threat intelligence sources.

    Args:
        ip: IP address string

    Returns:
        Dictionary containing reputation data
    """
    console.print(f"\n[cyan][*] Checking IP reputation for {ip}...[/cyan]")

    reputation = {
        "ip": ip,
        "checks_performed": [],
        "threats_detected": [],
        "risk_score": 0,
        "is_known_bad": False,
    }

    # Check various blocklists and reputation sources
    # Note: In production, you would integrate with actual threat intelligence APIs

    # Check if it's a known Tor exit node (simplified check)
    try:
        response = requests.get(
            "https://check.torproject.org/torbulkexitlist",
            timeout=10
        )
        if response.status_code == 200:
            reputation["checks_performed"].append("Tor Exit Node List")
            if ip in response.text:
                reputation["threats_detected"].append("Tor Exit Node")
                reputation["risk_score"] += 30
                reputation["is_known_bad"] = True
    except:
        pass

    # Simulated reputation checks (in production, integrate with real APIs)
    # These would typically require API keys
    simulated_checks = [
        "AbuseIPDB",
        "VirusTotal",
        "Shodan",
        "GreyNoise",
        "AlienVault OTX",
    ]

    for check in simulated_checks:
        reputation["checks_performed"].append(f"{check} (API key required)")

    return reputation


def display_reputation(rep_data: dict) -> None:
    """
    Display reputation data in a formatted panel.

    Args:
        rep_data: Dictionary containing reputation information
    """
    if not rep_data:
        return

    # Determine risk level color
    risk_score = rep_data.get("risk_score", 0)
    if risk_score >= 70:
        risk_color = "red"
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_color = "yellow"
        risk_level = "MEDIUM"
    else:
        risk_color = "green"
        risk_level = "LOW"

    console.print(Panel(
        f"[bold]IP:[/bold] {rep_data['ip']}\n"
        f"[bold]Risk Score:[/bold] [{risk_color}]{risk_score}/100 ({risk_level})[/{risk_color}]\n"
        f"[bold]Checks Performed:[/bold] {len(rep_data['checks_performed'])}\n"
        f"[bold]Threats Detected:[/bold] {len(rep_data['threats_detected'])}",
        title="IP Reputation Summary",
        style="blue"
    ))

    if rep_data["threats_detected"]:
        console.print("\n[bold red]Detected Threats:[/bold red]")
        for threat in rep_data["threats_detected"]:
            console.print(f"  [red]- {threat}[/red]")

    console.print("\n[dim]Note: Full reputation checks require API keys for services like AbuseIPDB, VirusTotal, etc.[/dim]")


def full_ip_analysis(ip: str) -> dict:
    """
    Perform comprehensive IP address analysis.

    Args:
        ip: IP address string

    Returns:
        Dictionary containing all analysis results
    """
    console.print(Panel(
        f"[bold cyan]IP Address Analysis: {ip}[/bold cyan]",
        subtitle="OSINT Toolkit",
        style="blue"
    ))

    results = {
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "is_private": is_private_ip(ip),
        "geolocation": None,
        "whois": None,
        "reputation": None,
    }

    # Check if private IP
    if results["is_private"]:
        console.print("[yellow][!] This is a private IP address. Limited information available.[/yellow]")
        return results

    # Geolocation
    geo_data = get_geolocation(ip)
    if geo_data:
        results["geolocation"] = geo_data
        display_geolocation(geo_data)

    # WHOIS/ASN
    whois_data = get_whois_info(ip)
    if whois_data:
        results["whois"] = whois_data
        display_whois_info(whois_data)

    # Reputation
    rep_data = check_reputation(ip)
    results["reputation"] = rep_data
    display_reputation(rep_data)

    return results


def main():
    """Main entry point for IP analyzer module."""
    parser = argparse.ArgumentParser(
        description="IP Geolocation and Reputation Analyzer - OSINT Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 8.8.8.8                    # Full analysis
  %(prog)s 8.8.8.8 --geo-only         # Geolocation only
  %(prog)s 8.8.8.8 --whois-only       # WHOIS/ASN only
  %(prog)s 8.8.8.8 --reputation-only  # Reputation check only
  %(prog)s google.com                 # Resolve hostname first

LEGAL DISCLAIMER:
  This tool is intended for authorized security testing and educational
  purposes only. Ensure you have proper authorization before analyzing
  IP addresses.
        """
    )

    parser.add_argument("target", help="IP address or hostname to analyze")
    parser.add_argument("--geo-only", action="store_true", help="Geolocation lookup only")
    parser.add_argument("--whois-only", action="store_true", help="WHOIS/ASN lookup only")
    parser.add_argument("--reputation-only", action="store_true", help="Reputation check only")
    parser.add_argument("-o", "--output", help="Output results to JSON file")

    args = parser.parse_args()

    target = args.target.strip()

    # Check if it's a hostname that needs resolution
    if not validate_ip(target):
        console.print(f"[cyan][*] Resolving hostname: {target}[/cyan]")
        ip = resolve_hostname(target)
        if ip:
            console.print(f"[green][+] Resolved to: {ip}[/green]")
        else:
            console.print(f"[red][!] Failed to resolve hostname: {target}[/red]")
            sys.exit(1)
    else:
        ip = target

    try:
        if args.geo_only:
            geo_data = get_geolocation(ip)
            display_geolocation(geo_data)
        elif args.whois_only:
            whois_data = get_whois_info(ip)
            display_whois_info(whois_data)
        elif args.reputation_only:
            rep_data = check_reputation(ip)
            display_reputation(rep_data)
        else:
            results = full_ip_analysis(ip)

            if args.output:
                import json
                with open(args.output, "w") as f:
                    json.dump(results, f, indent=2, default=str)
                console.print(f"\n[green][+] Results saved to {args.output}[/green]")

    except KeyboardInterrupt:
        console.print("\n[yellow][!] Analysis interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red][!] Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
