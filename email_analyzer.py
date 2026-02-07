#!/usr/bin/env python3
"""
Email Header Analyzer
=====================

This module provides comprehensive email header analysis including:
- Header parsing and extraction
- Sender verification and authentication checks (SPF, DKIM, DMARC)
- Routing path analysis (hop-by-hop tracking)
- Timestamp analysis for delay detection
- IP extraction and geolocation
- Phishing indicator detection

Author: OSINT Toolkit
License: MIT
"""

import argparse
import email
import re
import sys
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Optional, List, Tuple

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] Run: pip install -r requirements.txt")
    sys.exit(1)

console = Console()

# Common headers to extract
IMPORTANT_HEADERS = [
    "From",
    "To",
    "Cc",
    "Bcc",
    "Subject",
    "Date",
    "Message-ID",
    "Reply-To",
    "Return-Path",
    "X-Originating-IP",
    "X-Sender-IP",
    "X-Mailer",
    "User-Agent",
    "Content-Type",
    "MIME-Version",
]

# Authentication headers
AUTH_HEADERS = [
    "Authentication-Results",
    "DKIM-Signature",
    "DomainKey-Signature",
    "Received-SPF",
    "ARC-Authentication-Results",
    "ARC-Message-Signature",
    "ARC-Seal",
]

# Phishing indicators in headers
PHISHING_INDICATORS = [
    (r"X-Spam-Flag:\s*YES", "Marked as spam by mail server"),
    (r"X-Spam-Status:\s*Yes", "Spam status positive"),
    (r"Reply-To:.*@(?!.*\bFrom:)", "Reply-To differs from sender domain"),
    (r"X-Originating-IP:.*\[(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)", "Originated from private IP"),
]


def parse_email_headers(raw_headers: str) -> email.message.Message:
    """
    Parse raw email headers into a Message object.

    Args:
        raw_headers: Raw email headers as string

    Returns:
        email.message.Message object
    """
    return email.message_from_string(raw_headers)


def extract_received_chain(msg: email.message.Message) -> List[dict]:
    """
    Extract and parse the Received header chain.

    Args:
        msg: Parsed email message

    Returns:
        List of dictionaries containing hop information
    """
    received_headers = msg.get_all("Received", [])
    hops = []

    for i, header in enumerate(received_headers):
        hop = {
            "hop_number": len(received_headers) - i,
            "raw": header,
            "from_server": None,
            "by_server": None,
            "timestamp": None,
            "ip_addresses": [],
            "delay": None,
        }

        # Extract 'from' server
        from_match = re.search(r'from\s+([\w\.-]+)', header, re.IGNORECASE)
        if from_match:
            hop["from_server"] = from_match.group(1)

        # Extract 'by' server
        by_match = re.search(r'by\s+([\w\.-]+)', header, re.IGNORECASE)
        if by_match:
            hop["by_server"] = by_match.group(1)

        # Extract timestamp
        date_match = re.search(
            r';\s*(.+?(?:\d{4}|\d{2}:\d{2}:\d{2}).+?)(?:\(|$)',
            header
        )
        if date_match:
            try:
                hop["timestamp"] = parsedate_to_datetime(date_match.group(1).strip())
            except:
                pass

        # Extract IP addresses
        ip_pattern = r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?'
        ips = re.findall(ip_pattern, header)
        hop["ip_addresses"] = list(set(ips))

        hops.append(hop)

    # Calculate delays between hops
    for i in range(len(hops) - 1):
        if hops[i]["timestamp"] and hops[i + 1]["timestamp"]:
            delay = hops[i]["timestamp"] - hops[i + 1]["timestamp"]
            hops[i]["delay"] = delay.total_seconds()

    return hops


def extract_authentication_results(msg: email.message.Message) -> dict:
    """
    Extract email authentication results (SPF, DKIM, DMARC).

    Args:
        msg: Parsed email message

    Returns:
        Dictionary containing authentication results
    """
    auth_results = {
        "spf": {"result": "unknown", "details": None},
        "dkim": {"result": "unknown", "details": None},
        "dmarc": {"result": "unknown", "details": None},
        "raw_results": [],
    }

    # Check Authentication-Results header
    auth_header = msg.get("Authentication-Results", "")
    if auth_header:
        auth_results["raw_results"].append(auth_header)

        # Parse SPF
        spf_match = re.search(r'spf=(\w+)', auth_header, re.IGNORECASE)
        if spf_match:
            auth_results["spf"]["result"] = spf_match.group(1).lower()

        # Parse DKIM
        dkim_match = re.search(r'dkim=(\w+)', auth_header, re.IGNORECASE)
        if dkim_match:
            auth_results["dkim"]["result"] = dkim_match.group(1).lower()

        # Parse DMARC
        dmarc_match = re.search(r'dmarc=(\w+)', auth_header, re.IGNORECASE)
        if dmarc_match:
            auth_results["dmarc"]["result"] = dmarc_match.group(1).lower()

    # Check Received-SPF header
    spf_header = msg.get("Received-SPF", "")
    if spf_header:
        spf_result_match = re.search(r'^(\w+)', spf_header)
        if spf_result_match:
            auth_results["spf"]["result"] = spf_result_match.group(1).lower()
            auth_results["spf"]["details"] = spf_header

    # Check for DKIM-Signature
    dkim_sig = msg.get("DKIM-Signature", "")
    if dkim_sig:
        auth_results["dkim"]["details"] = "DKIM signature present"
        # Extract signing domain
        d_match = re.search(r'd=([^;]+)', dkim_sig)
        if d_match:
            auth_results["dkim"]["signing_domain"] = d_match.group(1).strip()

    return auth_results


def extract_all_ips(msg: email.message.Message) -> List[str]:
    """
    Extract all IP addresses from email headers.

    Args:
        msg: Parsed email message

    Returns:
        List of unique IP addresses found
    """
    all_headers = str(msg)
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    ips = re.findall(ip_pattern, all_headers)

    # Remove duplicates and invalid IPs
    valid_ips = []
    for ip in set(ips):
        octets = ip.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            valid_ips.append(ip)

    return valid_ips


def detect_phishing_indicators(msg: email.message.Message, raw_headers: str) -> List[str]:
    """
    Detect potential phishing indicators in email headers.

    Args:
        msg: Parsed email message
        raw_headers: Raw headers string

    Returns:
        List of detected phishing indicators
    """
    indicators = []

    # Check common phishing patterns
    for pattern, description in PHISHING_INDICATORS:
        if re.search(pattern, raw_headers, re.IGNORECASE):
            indicators.append(description)

    # Check if From and Reply-To domains differ
    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")

    if from_header and reply_to:
        from_domain_match = re.search(r'@([\w\.-]+)', from_header)
        reply_domain_match = re.search(r'@([\w\.-]+)', reply_to)

        if from_domain_match and reply_domain_match:
            if from_domain_match.group(1).lower() != reply_domain_match.group(1).lower():
                indicators.append(f"Reply-To domain ({reply_domain_match.group(1)}) differs from From domain ({from_domain_match.group(1)})")

    # Check for suspicious X-Mailer values
    x_mailer = msg.get("X-Mailer", "")
    suspicious_mailers = ["PHPMailer", "mass mailer", "bulk mail"]
    for mailer in suspicious_mailers:
        if mailer.lower() in x_mailer.lower():
            indicators.append(f"Suspicious mailer: {x_mailer}")

    # Check for missing common headers
    if not msg.get("Message-ID"):
        indicators.append("Missing Message-ID header")

    if not msg.get("Date"):
        indicators.append("Missing Date header")

    return indicators


def display_basic_headers(msg: email.message.Message) -> None:
    """
    Display basic email headers in a formatted table.

    Args:
        msg: Parsed email message
    """
    table = Table(title="Email Headers", show_header=True, header_style="bold magenta")
    table.add_column("Header", style="cyan", width=20)
    table.add_column("Value", style="green")

    for header in IMPORTANT_HEADERS:
        value = msg.get(header)
        if value:
            # Truncate long values
            if len(value) > 80:
                value = value[:77] + "..."
            table.add_row(header, value)

    console.print(table)


def display_routing_analysis(hops: List[dict]) -> None:
    """
    Display email routing analysis.

    Args:
        hops: List of hop dictionaries
    """
    if not hops:
        console.print("[yellow][!] No routing information found[/yellow]")
        return

    table = Table(title="Email Routing Path", show_header=True, header_style="bold magenta")
    table.add_column("Hop", style="dim", width=5)
    table.add_column("From Server", style="cyan", width=30)
    table.add_column("To Server", style="green", width=30)
    table.add_column("Timestamp", style="yellow", width=22)
    table.add_column("Delay", style="red", width=10)
    table.add_column("IPs", style="dim", width=15)

    for hop in hops:
        delay_str = ""
        if hop["delay"] is not None:
            if hop["delay"] > 300:  # More than 5 minutes
                delay_str = f"[red]{hop['delay']:.1f}s[/red]"
            elif hop["delay"] > 60:
                delay_str = f"[yellow]{hop['delay']:.1f}s[/yellow]"
            else:
                delay_str = f"{hop['delay']:.1f}s"

        timestamp_str = ""
        if hop["timestamp"]:
            timestamp_str = hop["timestamp"].strftime("%Y-%m-%d %H:%M:%S")

        table.add_row(
            str(hop["hop_number"]),
            hop["from_server"] or "-",
            hop["by_server"] or "-",
            timestamp_str,
            delay_str,
            ", ".join(hop["ip_addresses"][:2]) if hop["ip_addresses"] else "-"
        )

    console.print(table)

    # Calculate total transit time
    if len(hops) >= 2 and hops[0]["timestamp"] and hops[-1]["timestamp"]:
        total_time = (hops[0]["timestamp"] - hops[-1]["timestamp"]).total_seconds()
        console.print(f"\n[cyan]Total Transit Time:[/cyan] {total_time:.1f} seconds ({total_time/60:.2f} minutes)")


def display_authentication_results(auth_results: dict) -> None:
    """
    Display email authentication results.

    Args:
        auth_results: Dictionary containing authentication data
    """
    table = Table(title="Email Authentication", show_header=True, header_style="bold magenta")
    table.add_column("Check", style="cyan", width=15)
    table.add_column("Result", width=15)
    table.add_column("Details", style="dim")

    auth_checks = [
        ("SPF", auth_results["spf"]),
        ("DKIM", auth_results["dkim"]),
        ("DMARC", auth_results["dmarc"]),
    ]

    for name, data in auth_checks:
        result = data.get("result", "unknown")

        # Color code results
        if result in ["pass", "passed"]:
            result_display = f"[green]{result.upper()}[/green]"
        elif result in ["fail", "failed", "softfail"]:
            result_display = f"[red]{result.upper()}[/red]"
        elif result in ["neutral", "none"]:
            result_display = f"[yellow]{result.upper()}[/yellow]"
        else:
            result_display = f"[dim]{result.upper()}[/dim]"

        details = data.get("details", "")
        if len(str(details)) > 50:
            details = str(details)[:47] + "..."

        table.add_row(name, result_display, str(details) if details else "-")

    console.print(table)


def display_phishing_analysis(indicators: List[str]) -> None:
    """
    Display phishing analysis results.

    Args:
        indicators: List of detected phishing indicators
    """
    if not indicators:
        console.print(Panel(
            "[green]No obvious phishing indicators detected[/green]",
            title="Phishing Analysis",
            style="green"
        ))
    else:
        indicator_text = "\n".join(f"[red]- {ind}[/red]" for ind in indicators)
        console.print(Panel(
            f"[bold red]Warning: Potential phishing indicators detected![/bold red]\n\n{indicator_text}",
            title="Phishing Analysis",
            style="red"
        ))


def display_extracted_ips(ips: List[str]) -> None:
    """
    Display extracted IP addresses.

    Args:
        ips: List of IP addresses
    """
    if not ips:
        return

    console.print(f"\n[cyan]Extracted IP Addresses ({len(ips)}):[/cyan]")
    for ip in ips:
        console.print(f"  - {ip}")


def analyze_email_headers(raw_headers: str) -> dict:
    """
    Perform comprehensive email header analysis.

    Args:
        raw_headers: Raw email headers as string

    Returns:
        Dictionary containing all analysis results
    """
    console.print(Panel(
        "[bold cyan]Email Header Analysis[/bold cyan]",
        subtitle="OSINT Toolkit",
        style="blue"
    ))

    # Parse headers
    msg = parse_email_headers(raw_headers)

    results = {
        "timestamp": datetime.now().isoformat(),
        "basic_headers": {},
        "routing": [],
        "authentication": {},
        "extracted_ips": [],
        "phishing_indicators": [],
    }

    # Extract basic headers
    for header in IMPORTANT_HEADERS:
        value = msg.get(header)
        if value:
            results["basic_headers"][header] = value

    display_basic_headers(msg)

    # Routing analysis
    console.print()
    hops = extract_received_chain(msg)
    results["routing"] = hops
    display_routing_analysis(hops)

    # Authentication analysis
    console.print()
    auth_results = extract_authentication_results(msg)
    results["authentication"] = auth_results
    display_authentication_results(auth_results)

    # Extract IPs
    ips = extract_all_ips(msg)
    results["extracted_ips"] = ips
    display_extracted_ips(ips)

    # Phishing analysis
    console.print()
    indicators = detect_phishing_indicators(msg, raw_headers)
    results["phishing_indicators"] = indicators
    display_phishing_analysis(indicators)

    return results


def main():
    """Main entry point for email header analyzer."""
    parser = argparse.ArgumentParser(
        description="Email Header Analyzer - OSINT Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s email_headers.txt          # Analyze headers from file
  %(prog)s --interactive              # Paste headers interactively
  cat headers.txt | %(prog)s -        # Read from stdin

LEGAL DISCLAIMER:
  This tool is intended for authorized security testing and educational
  purposes only. Only analyze email headers you have permission to access.
        """
    )

    parser.add_argument("input", nargs="?", help="File containing email headers, or '-' for stdin")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive mode - paste headers directly")
    parser.add_argument("-o", "--output", help="Output results to JSON file")

    args = parser.parse_args()

    raw_headers = None

    if args.interactive or (args.input is None and not args.interactive):
        console.print("[cyan][*] Paste email headers below (press Ctrl+D or Ctrl+Z when done):[/cyan]")
        console.print("[dim](Copy headers from your email client's 'View Source' or 'Show Original' option)[/dim]\n")

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
            console.print("\n[yellow][!] Input cancelled[/yellow]")
            sys.exit(0)

    elif args.input == "-":
        raw_headers = sys.stdin.read()
    else:
        try:
            with open(args.input, "r") as f:
                raw_headers = f.read()
        except FileNotFoundError:
            console.print(f"[red][!] File not found: {args.input}[/red]")
            sys.exit(1)
        except IOError as e:
            console.print(f"[red][!] Error reading file: {e}[/red]")
            sys.exit(1)

    if not raw_headers or not raw_headers.strip():
        console.print("[red][!] No email headers provided[/red]")
        sys.exit(1)

    try:
        results = analyze_email_headers(raw_headers)

        if args.output:
            import json
            # Convert datetime objects to strings
            for hop in results.get("routing", []):
                if hop.get("timestamp"):
                    hop["timestamp"] = hop["timestamp"].isoformat()

            with open(args.output, "w") as f:
                json.dump(results, f, indent=2, default=str)
            console.print(f"\n[green][+] Results saved to {args.output}[/green]")

    except Exception as e:
        console.print(f"[red][!] Error analyzing headers: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
