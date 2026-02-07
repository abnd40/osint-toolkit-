#!/usr/bin/env python3
"""
Domain Reconnaissance Module
============================

This module provides comprehensive domain intelligence gathering capabilities including:
- WHOIS lookup for domain registration information
- DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)
- Subdomain discovery using common wordlists

Author: OSINT Toolkit
License: MIT
"""

import argparse
import socket
import sys
from datetime import datetime
from typing import Optional

try:
    import whois
    import dns.resolver
    import dns.exception
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] Run: pip install -r requirements.txt")
    sys.exit(1)

console = Console()

# Common subdomains for enumeration
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "remote", "blog",
    "webdisk", "server", "cpanel", "whm", "autodiscover", "autoconfig", "vpn",
    "api", "dev", "staging", "test", "admin", "portal", "shop", "store", "app",
    "mobile", "m", "cdn", "static", "assets", "img", "images", "video", "media",
    "secure", "ssl", "login", "intranet", "internal", "docs", "support", "help",
    "status", "monitor", "stats", "analytics", "tracking", "git", "svn", "hg",
    "jenkins", "ci", "build", "deploy", "prod", "production", "backup", "db",
    "database", "mysql", "postgres", "redis", "mongo", "elastic", "search"
]


def perform_whois_lookup(domain: str) -> Optional[dict]:
    """
    Perform WHOIS lookup on the target domain.

    Args:
        domain: Target domain name (e.g., 'example.com')

    Returns:
        Dictionary containing WHOIS information or None if lookup fails
    """
    try:
        console.print(f"\n[cyan][*] Performing WHOIS lookup for {domain}...[/cyan]")
        w = whois.whois(domain)

        # Extract relevant information
        whois_data = {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "whois_server": w.whois_server,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "updated_date": w.updated_date,
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "dnssec": w.dnssec,
            "name": w.name,
            "org": w.org,
            "address": w.address,
            "city": w.city,
            "state": w.state,
            "country": w.country,
            "registrant_postal_code": w.registrant_postal_code,
        }

        return whois_data

    except Exception as e:
        console.print(f"[red][!] WHOIS lookup failed: {e}[/red]")
        return None


def display_whois_results(whois_data: dict) -> None:
    """
    Display WHOIS results in a formatted table.

    Args:
        whois_data: Dictionary containing WHOIS information
    """
    if not whois_data:
        return

    table = Table(title="WHOIS Information", show_header=True, header_style="bold magenta")
    table.add_column("Field", style="cyan", width=25)
    table.add_column("Value", style="green")

    for key, value in whois_data.items():
        if value is not None:
            # Format dates nicely
            if isinstance(value, datetime):
                value = value.strftime("%Y-%m-%d %H:%M:%S")
            elif isinstance(value, list):
                value = ", ".join(str(v) for v in value[:5])  # Limit list display
                if len(whois_data.get(key, [])) > 5:
                    value += f" (+{len(whois_data[key]) - 5} more)"

            table.add_row(key.replace("_", " ").title(), str(value))

    console.print(table)


def enumerate_dns_records(domain: str) -> dict:
    """
    Enumerate all common DNS record types for a domain.

    Args:
        domain: Target domain name

    Returns:
        Dictionary containing DNS records by type
    """
    console.print(f"\n[cyan][*] Enumerating DNS records for {domain}...[/cyan]")

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR"]
    dns_records = {}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            records = []

            for rdata in answers:
                if record_type == "MX":
                    records.append(f"{rdata.preference} {rdata.exchange}")
                elif record_type == "SOA":
                    records.append(f"Primary NS: {rdata.mname}, Email: {rdata.rname}")
                else:
                    records.append(str(rdata))

            dns_records[record_type] = records

        except dns.resolver.NoAnswer:
            pass  # No records of this type
        except dns.resolver.NXDOMAIN:
            console.print(f"[red][!] Domain {domain} does not exist[/red]")
            break
        except dns.exception.Timeout:
            console.print(f"[yellow][!] Timeout querying {record_type} records[/yellow]")
        except Exception as e:
            pass  # Skip other errors silently

    return dns_records


def display_dns_records(dns_records: dict, domain: str) -> None:
    """
    Display DNS records in a formatted table.

    Args:
        dns_records: Dictionary containing DNS records
        domain: Target domain name
    """
    if not dns_records:
        console.print("[yellow][!] No DNS records found[/yellow]")
        return

    table = Table(title=f"DNS Records for {domain}", show_header=True, header_style="bold magenta")
    table.add_column("Record Type", style="cyan", width=15)
    table.add_column("Value", style="green")

    for record_type, records in dns_records.items():
        for i, record in enumerate(records):
            if i == 0:
                table.add_row(record_type, record)
            else:
                table.add_row("", record)

    console.print(table)


def discover_subdomains(domain: str, wordlist: list = None, threads: int = 10) -> list:
    """
    Discover subdomains using DNS brute-forcing.

    Args:
        domain: Target domain name
        wordlist: List of subdomain prefixes to try
        threads: Number of concurrent threads (not implemented yet)

    Returns:
        List of discovered subdomains with their IP addresses
    """
    console.print(f"\n[cyan][*] Discovering subdomains for {domain}...[/cyan]")

    if wordlist is None:
        wordlist = COMMON_SUBDOMAINS

    discovered = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 5

    total = len(wordlist)

    for i, subdomain in enumerate(wordlist, 1):
        fqdn = f"{subdomain}.{domain}"

        # Progress indicator
        if i % 20 == 0:
            console.print(f"[dim]  Progress: {i}/{total} ({(i/total)*100:.1f}%)[/dim]", end="\r")

        try:
            answers = resolver.resolve(fqdn, "A")
            ips = [str(rdata) for rdata in answers]
            discovered.append({
                "subdomain": fqdn,
                "ips": ips
            })
            console.print(f"[green][+] Found: {fqdn} -> {', '.join(ips)}[/green]")

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass
        except Exception:
            pass

    console.print(f"\n[cyan][*] Subdomain enumeration complete. Found {len(discovered)} subdomains.[/cyan]")
    return discovered


def display_subdomains(subdomains: list) -> None:
    """
    Display discovered subdomains in a formatted table.

    Args:
        subdomains: List of discovered subdomain dictionaries
    """
    if not subdomains:
        console.print("[yellow][!] No subdomains discovered[/yellow]")
        return

    table = Table(title="Discovered Subdomains", show_header=True, header_style="bold magenta")
    table.add_column("#", style="dim", width=5)
    table.add_column("Subdomain", style="cyan")
    table.add_column("IP Address(es)", style="green")

    for i, sub in enumerate(subdomains, 1):
        table.add_row(str(i), sub["subdomain"], ", ".join(sub["ips"]))

    console.print(table)


def full_domain_recon(domain: str, skip_subdomains: bool = False) -> dict:
    """
    Perform comprehensive domain reconnaissance.

    Args:
        domain: Target domain name
        skip_subdomains: Skip subdomain enumeration if True

    Returns:
        Dictionary containing all reconnaissance results
    """
    console.print(Panel(
        f"[bold cyan]Domain Reconnaissance: {domain}[/bold cyan]",
        subtitle="OSINT Toolkit",
        style="blue"
    ))

    results = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "whois": None,
        "dns_records": None,
        "subdomains": None
    }

    # WHOIS lookup
    whois_data = perform_whois_lookup(domain)
    if whois_data:
        results["whois"] = whois_data
        display_whois_results(whois_data)

    # DNS enumeration
    dns_records = enumerate_dns_records(domain)
    if dns_records:
        results["dns_records"] = dns_records
        display_dns_records(dns_records, domain)

    # Subdomain discovery
    if not skip_subdomains:
        subdomains = discover_subdomains(domain)
        if subdomains:
            results["subdomains"] = subdomains
            display_subdomains(subdomains)

    return results


def main():
    """Main entry point for domain reconnaissance module."""
    parser = argparse.ArgumentParser(
        description="Domain Reconnaissance Tool - OSINT Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com                    # Full reconnaissance
  %(prog)s example.com --whois-only       # WHOIS lookup only
  %(prog)s example.com --dns-only         # DNS records only
  %(prog)s example.com --subdomains-only  # Subdomain enumeration only
  %(prog)s example.com --skip-subdomains  # Skip subdomain enumeration

LEGAL DISCLAIMER:
  This tool is intended for authorized security testing and educational
  purposes only. Ensure you have proper authorization before scanning
  any domain you do not own.
        """
    )

    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--whois-only", action="store_true", help="Perform WHOIS lookup only")
    parser.add_argument("--dns-only", action="store_true", help="Enumerate DNS records only")
    parser.add_argument("--subdomains-only", action="store_true", help="Subdomain enumeration only")
    parser.add_argument("--skip-subdomains", action="store_true", help="Skip subdomain enumeration")
    parser.add_argument("-o", "--output", help="Output results to JSON file")

    args = parser.parse_args()

    # Clean domain input
    domain = args.domain.lower().strip()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//")[1].split("/")[0]

    try:
        if args.whois_only:
            whois_data = perform_whois_lookup(domain)
            display_whois_results(whois_data)
        elif args.dns_only:
            dns_records = enumerate_dns_records(domain)
            display_dns_records(dns_records, domain)
        elif args.subdomains_only:
            subdomains = discover_subdomains(domain)
            display_subdomains(subdomains)
        else:
            results = full_domain_recon(domain, skip_subdomains=args.skip_subdomains)

            if args.output:
                import json
                with open(args.output, "w") as f:
                    json.dump(results, f, indent=2, default=str)
                console.print(f"\n[green][+] Results saved to {args.output}[/green]")

    except KeyboardInterrupt:
        console.print("\n[yellow][!] Scan interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red][!] Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
