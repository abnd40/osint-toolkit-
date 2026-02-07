#!/usr/bin/env python3
"""
OSINT Toolkit - Main CLI Interface
===================================

A comprehensive Open Source Intelligence (OSINT) toolkit for security
professionals, researchers, and analysts. This tool provides a unified
interface to various reconnaissance and intelligence gathering modules.

Modules:
- Domain Reconnaissance (WHOIS, DNS, Subdomains)
- IP Geolocation & Reputation Analysis
- Email Header Forensics
- Social Media Username Search
- File Metadata Extraction

Author: OSINT Toolkit
License: MIT

LEGAL DISCLAIMER:
This toolkit is intended for authorized security testing, research,
and educational purposes only. Users are responsible for ensuring
they have proper authorization before using these tools against
any target.
"""

import argparse
import sys
import os
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("[!] Missing 'rich' library. Run: pip install -r requirements.txt")
    sys.exit(1)

# Import our modules
try:
    from domain_recon import full_domain_recon, perform_whois_lookup, enumerate_dns_records, discover_subdomains
    from ip_analyzer import full_ip_analysis, get_geolocation, get_whois_info, check_reputation, validate_ip, resolve_hostname
    from email_analyzer import analyze_email_headers
    from username_checker import check_all_platforms, display_results, validate_username, list_platforms, PLATFORMS
    from metadata_extractor import analyze_file, analyze_directory
except ImportError as e:
    print(f"[!] Error importing module: {e}")
    print("[*] Make sure all toolkit modules are in the same directory")
    sys.exit(1)

console = Console()

VERSION = "1.0.0"

BANNER = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║     ██████╗ ███████╗██╗███╗   ██╗████████╗    ████████╗ ██████╗  ██████╗ ██╗     ███████╗ ║
║    ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝ ║
║    ██║   ██║███████╗██║██╔██╗ ██║   ██║          ██║   ██║   ██║██║   ██║██║     ███████╗ ║
║    ██║   ██║╚════██║██║██║╚██╗██║   ██║          ██║   ██║   ██║██║   ██║██║     ╚════██║ ║
║    ╚██████╔╝███████║██║██║ ╚████║   ██║          ██║   ╚██████╔╝╚██████╔╝███████╗███████║ ║
║     ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝          ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝ ║
║                                                                           ║
║                    Open Source Intelligence Toolkit                       ║
║                           v{version}                                        ║
╚═══════════════════════════════════════════════════════════════════════════╝
""".format(version=VERSION)

SIMPLE_BANNER = """
 ██████╗ ███████╗██╗███╗   ██╗████████╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
██║   ██║███████╗██║██╔██╗ ██║   ██║
██║   ██║╚════██║██║██║╚██╗██║   ██║
╚██████╔╝███████║██║██║ ╚████║   ██║
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
    Open Source Intelligence Toolkit v{version}
""".format(version=VERSION)


def display_banner():
    """Display the toolkit banner."""
    console.print(SIMPLE_BANNER, style="cyan")


def display_menu():
    """Display the main menu options."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Option", style="cyan bold", width=5)
    table.add_column("Module", style="green", width=25)
    table.add_column("Description", style="white")

    modules = [
        ("1", "Domain Reconnaissance", "WHOIS, DNS records, subdomain enumeration"),
        ("2", "IP Analysis", "Geolocation, WHOIS, reputation check"),
        ("3", "Email Header Analysis", "Header parsing, routing, authentication"),
        ("4", "Username Search", "Check username across 45+ platforms"),
        ("5", "Metadata Extractor", "Extract EXIF, PDF metadata, GPS data"),
        ("", "", ""),
        ("0", "Exit", "Exit the toolkit"),
    ]

    for option, module, desc in modules:
        table.add_row(option, module, desc)

    console.print(Panel(table, title="[bold cyan]Main Menu[/bold cyan]", border_style="cyan"))


def run_domain_recon():
    """Run domain reconnaissance module."""
    console.print("\n[bold cyan]Domain Reconnaissance[/bold cyan]\n")

    domain = console.input("[cyan]Enter domain (e.g., example.com): [/cyan]").strip()
    if not domain:
        console.print("[red]No domain provided[/red]")
        return

    # Clean domain
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//")[1].split("/")[0]

    console.print("\n[dim]Options:[/dim]")
    console.print("  1. Full reconnaissance (WHOIS + DNS + Subdomains)")
    console.print("  2. WHOIS only")
    console.print("  3. DNS records only")
    console.print("  4. Subdomain enumeration only")

    choice = console.input("\n[cyan]Select option (1-4) [1]: [/cyan]").strip() or "1"

    try:
        if choice == "1":
            full_domain_recon(domain)
        elif choice == "2":
            from domain_recon import display_whois_results
            whois_data = perform_whois_lookup(domain)
            display_whois_results(whois_data)
        elif choice == "3":
            from domain_recon import display_dns_records
            dns_records = enumerate_dns_records(domain)
            display_dns_records(dns_records, domain)
        elif choice == "4":
            from domain_recon import display_subdomains
            subdomains = discover_subdomains(domain)
            display_subdomains(subdomains)
        else:
            console.print("[yellow]Invalid option, running full reconnaissance[/yellow]")
            full_domain_recon(domain)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def run_ip_analysis():
    """Run IP analysis module."""
    console.print("\n[bold cyan]IP Address Analysis[/bold cyan]\n")

    target = console.input("[cyan]Enter IP address or hostname: [/cyan]").strip()
    if not target:
        console.print("[red]No target provided[/red]")
        return

    # Resolve if hostname
    if not validate_ip(target):
        console.print(f"[cyan]Resolving hostname: {target}[/cyan]")
        ip = resolve_hostname(target)
        if ip:
            console.print(f"[green]Resolved to: {ip}[/green]")
            target = ip
        else:
            console.print(f"[red]Failed to resolve: {target}[/red]")
            return

    console.print("\n[dim]Options:[/dim]")
    console.print("  1. Full analysis (Geolocation + WHOIS + Reputation)")
    console.print("  2. Geolocation only")
    console.print("  3. WHOIS/ASN only")
    console.print("  4. Reputation check only")

    choice = console.input("\n[cyan]Select option (1-4) [1]: [/cyan]").strip() or "1"

    try:
        if choice == "1":
            full_ip_analysis(target)
        elif choice == "2":
            from ip_analyzer import display_geolocation
            geo_data = get_geolocation(target)
            display_geolocation(geo_data)
        elif choice == "3":
            from ip_analyzer import display_whois_info
            whois_data = get_whois_info(target)
            display_whois_info(whois_data)
        elif choice == "4":
            from ip_analyzer import display_reputation
            rep_data = check_reputation(target)
            display_reputation(rep_data)
        else:
            console.print("[yellow]Invalid option, running full analysis[/yellow]")
            full_ip_analysis(target)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def run_email_analysis():
    """Run email header analysis module."""
    console.print("\n[bold cyan]Email Header Analysis[/bold cyan]\n")

    console.print("[dim]Options:[/dim]")
    console.print("  1. Paste headers interactively")
    console.print("  2. Load from file")

    choice = console.input("\n[cyan]Select option (1-2) [1]: [/cyan]").strip() or "1"

    if choice == "1":
        console.print("\n[cyan]Paste email headers below (press Ctrl+D or Ctrl+Z when done):[/cyan]")
        console.print("[dim](Copy from 'View Source' or 'Show Original' in your email client)[/dim]\n")

        try:
            lines = []
            while True:
                try:
                    line = input()
                    lines.append(line)
                except EOFError:
                    break
            raw_headers = "\n".join(lines)
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled[/yellow]")
            return

    elif choice == "2":
        file_path = console.input("[cyan]Enter file path: [/cyan]").strip()
        if not file_path or not os.path.exists(file_path):
            console.print("[red]File not found[/red]")
            return

        with open(file_path, "r") as f:
            raw_headers = f.read()

    else:
        console.print("[red]Invalid option[/red]")
        return

    if not raw_headers.strip():
        console.print("[red]No headers provided[/red]")
        return

    try:
        analyze_email_headers(raw_headers)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def run_username_search():
    """Run username search module."""
    import asyncio

    console.print("\n[bold cyan]Social Media Username Search[/bold cyan]\n")

    console.print("[dim]Options:[/dim]")
    console.print("  1. Search all platforms")
    console.print("  2. Search by category")
    console.print("  3. List available platforms")

    choice = console.input("\n[cyan]Select option (1-3) [1]: [/cyan]").strip() or "1"

    if choice == "3":
        list_platforms()
        return

    username = console.input("\n[cyan]Enter username to search: [/cyan]").strip().lstrip('@')

    if not username or not validate_username(username):
        console.print("[red]Invalid username[/red]")
        return

    categories = None
    if choice == "2":
        console.print("\n[dim]Available categories:[/dim]")
        console.print("  Social Media, Developer, Creative, Gaming, Professional, Other")
        cat_input = console.input("[cyan]Enter categories (comma-separated): [/cyan]").strip()
        if cat_input:
            categories = [c.strip() for c in cat_input.split(",")]

    try:
        console.print(Panel(
            f"[bold cyan]Searching for: {username}[/bold cyan]",
            subtitle="OSINT Toolkit",
            style="blue"
        ))

        results = asyncio.run(check_all_platforms(username, categories=categories))
        display_results(results, username)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def run_metadata_extractor():
    """Run metadata extractor module."""
    console.print("\n[bold cyan]File Metadata Extractor[/bold cyan]\n")

    path = console.input("[cyan]Enter file or directory path: [/cyan]").strip()

    if not path:
        console.print("[red]No path provided[/red]")
        return

    if not os.path.exists(path):
        console.print(f"[red]Path not found: {path}[/red]")
        return

    try:
        if os.path.isdir(path):
            recursive = console.input("[cyan]Search recursively? (y/n) [n]: [/cyan]").strip().lower() == 'y'
            analyze_directory(path, recursive=recursive)
        else:
            analyze_file(path)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def interactive_mode():
    """Run the toolkit in interactive mode."""
    display_banner()

    console.print(Panel(
        "[yellow]LEGAL DISCLAIMER[/yellow]\n\n"
        "This toolkit is for authorized security testing and educational purposes only.\n"
        "Ensure you have proper authorization before scanning any target.\n"
        "The authors are not responsible for misuse of this tool.",
        style="yellow"
    ))

    while True:
        console.print()
        display_menu()

        try:
            choice = console.input("\n[cyan]Select module (0-5): [/cyan]").strip()

            if choice == "0":
                console.print("\n[cyan]Goodbye![/cyan]\n")
                break
            elif choice == "1":
                run_domain_recon()
            elif choice == "2":
                run_ip_analysis()
            elif choice == "3":
                run_email_analysis()
            elif choice == "4":
                run_username_search()
            elif choice == "5":
                run_metadata_extractor()
            else:
                console.print("[yellow]Invalid option. Please select 0-5.[/yellow]")

            console.input("\n[dim]Press Enter to continue...[/dim]")

        except KeyboardInterrupt:
            console.print("\n\n[cyan]Goodbye![/cyan]\n")
            break
        except Exception as e:
            console.print(f"\n[red]Error: {e}[/red]")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="OSINT Toolkit - Open Source Intelligence Gathering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modules:
  domain      Domain reconnaissance (WHOIS, DNS, subdomains)
  ip          IP geolocation and reputation analysis
  email       Email header forensics
  username    Social media username search
  metadata    File metadata extraction

Examples:
  %(prog)s                          # Interactive mode
  %(prog)s domain example.com       # Domain recon
  %(prog)s ip 8.8.8.8              # IP analysis
  %(prog)s username johndoe        # Username search
  %(prog)s metadata photo.jpg      # Extract metadata

LEGAL DISCLAIMER:
  This toolkit is for authorized use only. Ensure proper authorization
  before scanning any target you do not own.
        """
    )

    parser.add_argument("--version", "-V", action="version", version=f"OSINT Toolkit v{VERSION}")

    subparsers = parser.add_subparsers(dest="module", help="Module to run")

    # Domain subparser
    domain_parser = subparsers.add_parser("domain", help="Domain reconnaissance")
    domain_parser.add_argument("target", help="Target domain")
    domain_parser.add_argument("--whois-only", action="store_true")
    domain_parser.add_argument("--dns-only", action="store_true")
    domain_parser.add_argument("--subdomains-only", action="store_true")
    domain_parser.add_argument("--skip-subdomains", action="store_true")
    domain_parser.add_argument("-o", "--output", help="Output JSON file")

    # IP subparser
    ip_parser = subparsers.add_parser("ip", help="IP analysis")
    ip_parser.add_argument("target", help="IP address or hostname")
    ip_parser.add_argument("--geo-only", action="store_true")
    ip_parser.add_argument("--whois-only", action="store_true")
    ip_parser.add_argument("--reputation-only", action="store_true")
    ip_parser.add_argument("-o", "--output", help="Output JSON file")

    # Email subparser
    email_parser = subparsers.add_parser("email", help="Email header analysis")
    email_parser.add_argument("file", nargs="?", help="File containing headers")
    email_parser.add_argument("-o", "--output", help="Output JSON file")

    # Username subparser
    username_parser = subparsers.add_parser("username", help="Username search")
    username_parser.add_argument("target", nargs="?", help="Username to search")
    username_parser.add_argument("-c", "--category", nargs="+", help="Filter by category")
    username_parser.add_argument("-l", "--list", action="store_true", help="List platforms")
    username_parser.add_argument("-o", "--output", help="Output JSON file")

    # Metadata subparser
    metadata_parser = subparsers.add_parser("metadata", help="Metadata extraction")
    metadata_parser.add_argument("path", help="File or directory path")
    metadata_parser.add_argument("-r", "--recursive", action="store_true")
    metadata_parser.add_argument("-o", "--output", help="Output JSON file")

    args = parser.parse_args()

    # If no module specified, run interactive mode
    if not args.module:
        interactive_mode()
        return

    # Run specific module
    try:
        if args.module == "domain":
            from domain_recon import display_whois_results, display_dns_records, display_subdomains

            domain = args.target.lower().strip()
            if domain.startswith("http"):
                domain = domain.split("//")[1].split("/")[0]

            if args.whois_only:
                data = perform_whois_lookup(domain)
                display_whois_results(data)
            elif args.dns_only:
                data = enumerate_dns_records(domain)
                display_dns_records(data, domain)
            elif args.subdomains_only:
                data = discover_subdomains(domain)
                display_subdomains(data)
            else:
                full_domain_recon(domain, skip_subdomains=args.skip_subdomains)

        elif args.module == "ip":
            from ip_analyzer import display_geolocation, display_whois_info, display_reputation

            target = args.target
            if not validate_ip(target):
                ip = resolve_hostname(target)
                if ip:
                    console.print(f"[green]Resolved {target} to {ip}[/green]")
                    target = ip
                else:
                    console.print(f"[red]Failed to resolve: {target}[/red]")
                    sys.exit(1)

            if args.geo_only:
                data = get_geolocation(target)
                display_geolocation(data)
            elif args.whois_only:
                data = get_whois_info(target)
                display_whois_info(data)
            elif args.reputation_only:
                data = check_reputation(target)
                display_reputation(data)
            else:
                full_ip_analysis(target)

        elif args.module == "email":
            if args.file:
                with open(args.file, "r") as f:
                    headers = f.read()
            else:
                console.print("[cyan]Paste headers (Ctrl+D when done):[/cyan]")
                lines = []
                while True:
                    try:
                        lines.append(input())
                    except EOFError:
                        break
                headers = "\n".join(lines)

            analyze_email_headers(headers)

        elif args.module == "username":
            import asyncio

            if args.list:
                list_platforms()
                return

            if not args.target:
                console.print("[red]Username required[/red]")
                sys.exit(1)

            username = args.target.strip().lstrip('@')
            results = asyncio.run(check_all_platforms(username, categories=args.category))
            display_results(results, username)

        elif args.module == "metadata":
            if os.path.isdir(args.path):
                analyze_directory(args.path, recursive=args.recursive)
            else:
                analyze_file(args.path)

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
