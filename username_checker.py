#!/usr/bin/env python3
"""
Social Media Username Checker
==============================

This module checks if a username exists across multiple social media platforms
and online services. Useful for:
- Digital footprint analysis
- Brand monitoring
- Identity verification
- OSINT investigations

Author: OSINT Toolkit
License: MIT
"""

import argparse
import asyncio
import sys
from datetime import datetime
from typing import Optional, List, Tuple
from dataclasses import dataclass

try:
    import aiohttp
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] Run: pip install -r requirements.txt")
    sys.exit(1)

console = Console()


@dataclass
class Platform:
    """Represents a social media platform to check."""
    name: str
    url_template: str
    check_type: str  # 'status_code', 'response_text', 'redirect'
    exists_indicator: any  # Status code, text pattern, or expected behavior
    category: str


# Platform definitions
# Format: Platform(name, url_template, check_type, exists_indicator, category)
PLATFORMS = [
    # Social Media
    Platform("Twitter/X", "https://twitter.com/{}", "status_code", 200, "Social Media"),
    Platform("Instagram", "https://www.instagram.com/{}/", "status_code", 200, "Social Media"),
    Platform("Facebook", "https://www.facebook.com/{}", "status_code", 200, "Social Media"),
    Platform("TikTok", "https://www.tiktok.com/@{}", "status_code", 200, "Social Media"),
    Platform("LinkedIn", "https://www.linkedin.com/in/{}", "status_code", 200, "Social Media"),
    Platform("Pinterest", "https://www.pinterest.com/{}/", "status_code", 200, "Social Media"),
    Platform("Snapchat", "https://www.snapchat.com/add/{}", "status_code", 200, "Social Media"),
    Platform("Reddit", "https://www.reddit.com/user/{}", "status_code", 200, "Social Media"),
    Platform("Tumblr", "https://{}.tumblr.com", "status_code", 200, "Social Media"),

    # Developer Platforms
    Platform("GitHub", "https://github.com/{}", "status_code", 200, "Developer"),
    Platform("GitLab", "https://gitlab.com/{}", "status_code", 200, "Developer"),
    Platform("Bitbucket", "https://bitbucket.org/{}/", "status_code", 200, "Developer"),
    Platform("Stack Overflow", "https://stackoverflow.com/users/{}?tab=profile", "status_code", 200, "Developer"),
    Platform("Dev.to", "https://dev.to/{}", "status_code", 200, "Developer"),
    Platform("Codepen", "https://codepen.io/{}", "status_code", 200, "Developer"),
    Platform("Replit", "https://replit.com/@{}", "status_code", 200, "Developer"),
    Platform("HackerRank", "https://www.hackerrank.com/{}", "status_code", 200, "Developer"),
    Platform("LeetCode", "https://leetcode.com/{}/", "status_code", 200, "Developer"),

    # Creative Platforms
    Platform("Dribbble", "https://dribbble.com/{}", "status_code", 200, "Creative"),
    Platform("Behance", "https://www.behance.net/{}", "status_code", 200, "Creative"),
    Platform("DeviantArt", "https://www.deviantart.com/{}", "status_code", 200, "Creative"),
    Platform("Medium", "https://medium.com/@{}", "status_code", 200, "Creative"),
    Platform("Flickr", "https://www.flickr.com/people/{}/", "status_code", 200, "Creative"),
    Platform("500px", "https://500px.com/{}", "status_code", 200, "Creative"),
    Platform("SoundCloud", "https://soundcloud.com/{}", "status_code", 200, "Creative"),
    Platform("Spotify", "https://open.spotify.com/user/{}", "status_code", 200, "Creative"),
    Platform("Vimeo", "https://vimeo.com/{}", "status_code", 200, "Creative"),

    # Gaming
    Platform("Twitch", "https://www.twitch.tv/{}", "status_code", 200, "Gaming"),
    Platform("Steam", "https://steamcommunity.com/id/{}", "status_code", 200, "Gaming"),
    Platform("Xbox Gamertag", "https://xboxgamertag.com/search/{}", "status_code", 200, "Gaming"),
    Platform("Chess.com", "https://www.chess.com/member/{}", "status_code", 200, "Gaming"),

    # Professional/Business
    Platform("About.me", "https://about.me/{}", "status_code", 200, "Professional"),
    Platform("Gravatar", "https://en.gravatar.com/{}", "status_code", 200, "Professional"),
    Platform("Keybase", "https://keybase.io/{}", "status_code", 200, "Professional"),
    Platform("Product Hunt", "https://www.producthunt.com/@{}", "status_code", 200, "Professional"),
    Platform("AngelList", "https://angel.co/u/{}", "status_code", 200, "Professional"),

    # Other
    Platform("Patreon", "https://www.patreon.com/{}", "status_code", 200, "Other"),
    Platform("Telegram", "https://t.me/{}", "status_code", 200, "Other"),
    Platform("Linktree", "https://linktr.ee/{}", "status_code", 200, "Other"),
    Platform("Cash App", "https://cash.app/${}", "status_code", 200, "Other"),
    Platform("Venmo", "https://venmo.com/{}", "status_code", 200, "Other"),
    Platform("PayPal", "https://www.paypal.me/{}", "status_code", 200, "Other"),
]


async def check_platform(
    session: aiohttp.ClientSession,
    platform: Platform,
    username: str
) -> Tuple[Platform, str, Optional[str]]:
    """
    Check if a username exists on a specific platform.

    Args:
        session: aiohttp client session
        platform: Platform to check
        username: Username to search for

    Returns:
        Tuple of (Platform, status, profile_url)
    """
    url = platform.url_template.format(username)

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as response:
            if platform.check_type == "status_code":
                if response.status == platform.exists_indicator:
                    return (platform, "found", url)
                elif response.status == 404:
                    return (platform, "not_found", None)
                else:
                    return (platform, "unknown", None)

            elif platform.check_type == "response_text":
                text = await response.text()
                if platform.exists_indicator in text:
                    return (platform, "found", url)
                else:
                    return (platform, "not_found", None)

            elif platform.check_type == "redirect":
                # If redirected to a different page, username might not exist
                if str(response.url) == url:
                    return (platform, "found", url)
                else:
                    return (platform, "not_found", None)

    except asyncio.TimeoutError:
        return (platform, "timeout", None)
    except aiohttp.ClientError:
        return (platform, "error", None)
    except Exception:
        return (platform, "error", None)

    return (platform, "unknown", None)


async def check_all_platforms(
    username: str,
    platforms: List[Platform] = None,
    categories: List[str] = None
) -> List[Tuple[Platform, str, Optional[str]]]:
    """
    Check username across all platforms concurrently.

    Args:
        username: Username to search for
        platforms: List of platforms to check (default: all)
        categories: Filter by categories (default: all)

    Returns:
        List of results
    """
    if platforms is None:
        platforms = PLATFORMS

    if categories:
        platforms = [p for p in platforms if p.category.lower() in [c.lower() for c in categories]]

    console.print(f"\n[cyan][*] Checking username '{username}' across {len(platforms)} platforms...[/cyan]")

    # Use connection pooling for efficiency
    connector = aiohttp.TCPConnector(limit=20, limit_per_host=2)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [check_platform(session, platform, username) for platform in platforms]

        results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Checking platforms...", total=len(tasks))

            for coro in asyncio.as_completed(tasks):
                result = await coro
                results.append(result)
                progress.update(task, advance=1)

    return results


def display_results(results: List[Tuple[Platform, str, Optional[str]]], username: str) -> dict:
    """
    Display check results in formatted tables.

    Args:
        results: List of check results
        username: Username that was checked

    Returns:
        Summary statistics
    """
    # Sort results by status (found first) then by platform name
    status_order = {"found": 0, "not_found": 1, "unknown": 2, "timeout": 3, "error": 4}
    sorted_results = sorted(results, key=lambda x: (status_order.get(x[1], 5), x[0].name))

    # Separate found and not found
    found = [(p, s, u) for p, s, u in sorted_results if s == "found"]
    not_found = [(p, s, u) for p, s, u in sorted_results if s == "not_found"]
    errors = [(p, s, u) for p, s, u in sorted_results if s in ["timeout", "error", "unknown"]]

    stats = {
        "username": username,
        "total_checked": len(results),
        "found": len(found),
        "not_found": len(not_found),
        "errors": len(errors),
    }

    # Display found accounts
    if found:
        table = Table(
            title=f"Accounts Found ({len(found)})",
            show_header=True,
            header_style="bold green"
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Platform", style="cyan", width=20)
        table.add_column("Category", style="yellow", width=15)
        table.add_column("Profile URL", style="green")

        for i, (platform, status, url) in enumerate(found, 1):
            table.add_row(str(i), platform.name, platform.category, url or "-")

        console.print(table)

    # Display not found
    if not_found:
        console.print(f"\n[dim]Not Found ({len(not_found)}): ", end="")
        platform_names = [p.name for p, _, _ in not_found]
        console.print(", ".join(platform_names[:10]))
        if len(platform_names) > 10:
            console.print(f"  ... and {len(platform_names) - 10} more")
        console.print("[/dim]")

    # Display errors
    if errors:
        console.print(f"\n[yellow]Errors/Timeouts ({len(errors)}): ", end="")
        platform_names = [p.name for p, _, _ in errors]
        console.print(", ".join(platform_names))
        console.print("[/yellow]")

    # Summary panel
    console.print(Panel(
        f"[bold]Username:[/bold] {username}\n"
        f"[bold]Platforms Checked:[/bold] {stats['total_checked']}\n"
        f"[bold green]Found:[/bold green] {stats['found']}\n"
        f"[bold red]Not Found:[/bold red] {stats['not_found']}\n"
        f"[bold yellow]Errors:[/bold yellow] {stats['errors']}",
        title="Summary",
        style="blue"
    ))

    return stats


def validate_username(username: str) -> bool:
    """
    Validate username format.

    Args:
        username: Username to validate

    Returns:
        True if valid, False otherwise
    """
    # Most platforms allow alphanumeric + underscores, 3-30 chars
    if not username:
        return False
    if len(username) < 1 or len(username) > 50:
        return False
    # Allow alphanumeric, underscores, hyphens, and dots
    import re
    if not re.match(r'^[\w\.-]+$', username):
        return False
    return True


def list_platforms() -> None:
    """Display all supported platforms grouped by category."""
    table = Table(title="Supported Platforms", show_header=True, header_style="bold magenta")
    table.add_column("Category", style="yellow", width=15)
    table.add_column("Platforms", style="cyan")

    # Group by category
    categories = {}
    for platform in PLATFORMS:
        if platform.category not in categories:
            categories[platform.category] = []
        categories[platform.category].append(platform.name)

    for category, platforms in sorted(categories.items()):
        table.add_row(category, ", ".join(sorted(platforms)))

    console.print(table)
    console.print(f"\n[dim]Total: {len(PLATFORMS)} platforms[/dim]")


def main():
    """Main entry point for username checker."""
    parser = argparse.ArgumentParser(
        description="Social Media Username Checker - OSINT Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s johndoe                              # Check across all platforms
  %(prog)s johndoe --category "Social Media"   # Check only social media
  %(prog)s johndoe --category Developer Gaming  # Check multiple categories
  %(prog)s --list                              # List all supported platforms

Categories:
  Social Media, Developer, Creative, Gaming, Professional, Other

LEGAL DISCLAIMER:
  This tool is intended for authorized security testing and educational
  purposes only. Respect the terms of service of each platform.
  Only search for usernames you have authorization to investigate.
        """
    )

    parser.add_argument("username", nargs="?", help="Username to search for")
    parser.add_argument("--category", "-c", nargs="+", help="Filter by category")
    parser.add_argument("--list", "-l", action="store_true", help="List all supported platforms")
    parser.add_argument("-o", "--output", help="Output results to JSON file")

    args = parser.parse_args()

    if args.list:
        list_platforms()
        return

    if not args.username:
        parser.error("Username is required (unless using --list)")

    username = args.username.strip().lstrip('@')

    if not validate_username(username):
        console.print("[red][!] Invalid username format[/red]")
        sys.exit(1)

    console.print(Panel(
        f"[bold cyan]Social Media Username Check: {username}[/bold cyan]",
        subtitle="OSINT Toolkit",
        style="blue"
    ))

    try:
        # Run async check
        results = asyncio.run(check_all_platforms(username, categories=args.category))

        # Display results
        stats = display_results(results, username)

        if args.output:
            import json
            output_data = {
                "username": username,
                "timestamp": datetime.now().isoformat(),
                "statistics": stats,
                "results": [
                    {
                        "platform": p.name,
                        "category": p.category,
                        "status": s,
                        "url": u
                    }
                    for p, s, u in results
                ]
            }

            with open(args.output, "w") as f:
                json.dump(output_data, f, indent=2)
            console.print(f"\n[green][+] Results saved to {args.output}[/green]")

    except KeyboardInterrupt:
        console.print("\n[yellow][!] Check interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red][!] Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
