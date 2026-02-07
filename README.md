# OSINT Toolkit

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Version-1.0.0-orange.svg" alt="Version">
</p>

A comprehensive **Open Source Intelligence (OSINT)** toolkit designed for security professionals, penetration testers, and researchers. This toolkit provides a unified command-line interface for conducting reconnaissance, gathering intelligence, and analyzing digital artifacts.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Modules](#modules)
  - [Domain Reconnaissance](#1-domain-reconnaissance)
  - [IP Analysis](#2-ip-analysis)
  - [Email Header Analysis](#3-email-header-analysis)
  - [Username Search](#4-username-search)
  - [Metadata Extractor](#5-metadata-extractor)
- [Usage Examples](#usage-examples)
- [Sample Output](#sample-output)
- [Technologies](#technologies)
- [Legal Disclaimer](#legal-disclaimer)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Domain Reconnaissance**: WHOIS lookups, DNS enumeration, subdomain discovery
- **IP Intelligence**: Geolocation, ASN/WHOIS data, reputation analysis
- **Email Forensics**: Header parsing, routing analysis, authentication verification, phishing detection
- **Social Media OSINT**: Username availability across 45+ platforms
- **File Analysis**: EXIF data extraction, GPS coordinates, PDF metadata
- **Unified CLI**: Both interactive menu and command-line modes
- **JSON Export**: Save results for further analysis or reporting
- **Professional Output**: Rich, formatted terminal output with color coding

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

```bash
# Clone or navigate to the toolkit directory
cd 02-osint-toolkit

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### Verify Installation

```bash
python osint.py --version
```

---

## Quick Start

### Interactive Mode

Launch the interactive menu-driven interface:

```bash
python osint.py
```

### Command-Line Mode

Run specific modules directly:

```bash
# Domain reconnaissance
python osint.py domain example.com

# IP analysis
python osint.py ip 8.8.8.8

# Username search
python osint.py username johndoe

# Metadata extraction
python osint.py metadata photo.jpg
```

---

## Modules

### 1. Domain Reconnaissance

Comprehensive domain intelligence gathering including registration data, DNS infrastructure, and subdomain enumeration.

**Capabilities:**
- **WHOIS Lookup**: Registrar, creation/expiration dates, registrant information, name servers
- **DNS Enumeration**: A, AAAA, MX, NS, TXT, SOA, CNAME, PTR records
- **Subdomain Discovery**: Brute-force enumeration using common subdomain wordlist (80+ entries)

**Usage:**

```bash
# Full reconnaissance
python domain_recon.py example.com

# WHOIS only
python domain_recon.py example.com --whois-only

# DNS records only
python domain_recon.py example.com --dns-only

# Subdomain enumeration only
python domain_recon.py example.com --subdomains-only

# Skip subdomain enumeration (faster)
python domain_recon.py example.com --skip-subdomains

# Save results to JSON
python domain_recon.py example.com -o results.json
```

---

### 2. IP Analysis

Geolocation, network ownership, and threat intelligence for IP addresses.

**Capabilities:**
- **Geolocation**: Country, city, ISP, coordinates, timezone
- **WHOIS/ASN**: Network ownership, CIDR ranges, registry information
- **Reputation Check**: Tor exit node detection, proxy/VPN detection, hosting identification
- **Reverse DNS**: Hostname resolution

**Usage:**

```bash
# Full analysis
python ip_analyzer.py 8.8.8.8

# Resolve hostname first
python ip_analyzer.py google.com

# Geolocation only
python ip_analyzer.py 8.8.8.8 --geo-only

# WHOIS/ASN only
python ip_analyzer.py 8.8.8.8 --whois-only

# Reputation check only
python ip_analyzer.py 8.8.8.8 --reputation-only
```

---

### 3. Email Header Analysis

Forensic analysis of email headers to trace message routing, verify authentication, and detect potential phishing.

**Capabilities:**
- **Header Parsing**: Extract all standard and X-headers
- **Routing Analysis**: Hop-by-hop path tracing with delay calculation
- **Authentication Verification**: SPF, DKIM, DMARC status checks
- **IP Extraction**: All IP addresses mentioned in headers
- **Phishing Detection**: Suspicious patterns, mismatched domains, spam indicators

**Usage:**

```bash
# Interactive mode (paste headers)
python email_analyzer.py --interactive

# From file
python email_analyzer.py headers.txt

# From stdin
cat headers.txt | python email_analyzer.py -

# Save analysis to JSON
python email_analyzer.py headers.txt -o analysis.json
```

**How to get email headers:**
- **Gmail**: Open email -> Three dots menu -> "Show original"
- **Outlook**: Open email -> File -> Properties -> Internet headers
- **Apple Mail**: View -> Message -> All Headers

---

### 4. Username Search

Check username availability across 45+ social media platforms and online services.

**Capabilities:**
- **Multi-Platform Search**: Social media, developer platforms, creative sites, gaming, professional networks
- **Concurrent Checking**: Asynchronous requests for fast results
- **Category Filtering**: Search specific platform categories
- **Direct Profile Links**: URLs to found profiles

**Supported Platforms:**
- **Social Media**: Twitter/X, Instagram, Facebook, TikTok, LinkedIn, Reddit, Pinterest, Snapchat, Tumblr
- **Developer**: GitHub, GitLab, Stack Overflow, Dev.to, HackerRank, LeetCode, Codepen, Replit
- **Creative**: Dribbble, Behance, Medium, DeviantArt, SoundCloud, Spotify, Vimeo
- **Gaming**: Twitch, Steam, Chess.com
- **Professional**: About.me, Keybase, Product Hunt, AngelList
- **Other**: Patreon, Telegram, Linktree, PayPal, Venmo

**Usage:**

```bash
# Search all platforms
python username_checker.py johndoe

# Search specific category
python username_checker.py johndoe --category "Social Media"

# Search multiple categories
python username_checker.py johndoe --category Developer Gaming

# List all supported platforms
python username_checker.py --list

# Save results to JSON
python username_checker.py johndoe -o results.json
```

---

### 5. Metadata Extractor

Extract hidden metadata from files that may reveal sensitive information.

**Capabilities:**
- **Image EXIF Data**: Camera make/model, software, dates, settings
- **GPS Coordinates**: Extract and display location with Google Maps link
- **PDF Metadata**: Author, creator software, creation/modification dates
- **File System Info**: Size, timestamps, permissions

**Supported Formats:**
- **Images**: JPEG, PNG, GIF, TIFF, BMP, WebP
- **Documents**: PDF

**Usage:**

```bash
# Analyze single file
python metadata_extractor.py photo.jpg
python metadata_extractor.py document.pdf

# Analyze directory
python metadata_extractor.py /path/to/images/

# Recursive directory scan
python metadata_extractor.py /path/to/files/ -r

# Save results to JSON
python metadata_extractor.py photo.jpg -o metadata.json
```

---

## Usage Examples

### Complete Workflow Example

```bash
# 1. Start with domain reconnaissance
python osint.py domain targetcompany.com -o domain_intel.json

# 2. Analyze discovered IP addresses
python osint.py ip 203.0.113.50 -o ip_intel.json

# 3. Search for associated usernames
python osint.py username targetcompany -o username_intel.json

# 4. Analyze suspicious emails
python osint.py email suspicious_headers.txt -o email_analysis.json

# 5. Extract metadata from downloaded files
python osint.py metadata downloaded_files/ -r -o file_metadata.json
```

---

## Sample Output

### Domain Reconnaissance

```
╭──────────────────────────────────────────────────────────────╮
│              Domain Reconnaissance: example.com              │
╰──────────────────────────────────────────────────────────────╯

┏━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Field                   ┃ Value                             ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Domain Name             │ EXAMPLE.COM                       │
│ Registrar               │ RESERVED-Internet Assigned...     │
│ Creation Date           │ 1995-08-14 04:00:00               │
│ Expiration Date         │ 2024-08-13 04:00:00               │
│ Name Servers            │ A.IANA-SERVERS.NET, B.IANA...     │
└─────────────────────────┴───────────────────────────────────┘

┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Record Type    ┃ Value                                      ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ A              │ 93.184.216.34                              │
│ AAAA           │ 2606:2800:220:1:248:1893:25c8:1946         │
│ MX             │ 0 .                                        │
│ NS             │ a.iana-servers.net.                        │
│                │ b.iana-servers.net.                        │
└────────────────┴────────────────────────────────────────────┘
```

### IP Geolocation

```
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Field                ┃ Value                                ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ IP Address           │ 8.8.8.8                              │
│ Country              │ United States                        │
│ Region               │ California                           │
│ City                 │ Mountain View                        │
│ Latitude             │ 37.4056                              │
│ Longitude            │ -122.0775                            │
│ ISP                  │ Google LLC                           │
│ Organization         │ Google Public DNS                    │
│ ASN                  │ AS15169 Google LLC                   │
└──────────────────────┴──────────────────────────────────────┘

Flags: Hosting/Datacenter

Map: https://www.google.com/maps?q=37.4056,-122.0775
```

### Username Search Results

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                  Accounts Found (12)                        ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│  #  │ Platform        │ Category      │ Profile URL        │
├─────┼─────────────────┼───────────────┼────────────────────┤
│  1  │ GitHub          │ Developer     │ github.com/johndoe │
│  2  │ Twitter/X       │ Social Media  │ twitter.com/johnd..│
│  3  │ LinkedIn        │ Social Media  │ linkedin.com/in/...│
│  4  │ Instagram       │ Social Media  │ instagram.com/joh..│
└─────┴─────────────────┴───────────────┴────────────────────┘

╭────────────────────── Summary ──────────────────────╮
│ Username: johndoe                                   │
│ Platforms Checked: 45                               │
│ Found: 12                                           │
│ Not Found: 30                                       │
│ Errors: 3                                           │
╰─────────────────────────────────────────────────────╯
```

---

## Technologies

| Component | Technology |
|-----------|------------|
| Language | Python 3.8+ |
| CLI Framework | argparse |
| DNS Resolution | dnspython |
| WHOIS Lookups | python-whois, ipwhois |
| HTTP Requests | requests, aiohttp |
| Image Processing | Pillow, exifread |
| PDF Processing | PyPDF2 |
| Terminal UI | rich |
| Async Operations | asyncio |

---

## Legal Disclaimer

**IMPORTANT: READ BEFORE USE**

This toolkit is provided for **authorized security testing, research, and educational purposes only**.

By using this software, you agree to:

1. **Only use these tools against systems you own or have explicit written permission to test**
2. **Comply with all applicable local, state, national, and international laws**
3. **Respect the terms of service of any third-party platforms or services**
4. **Not use this toolkit for malicious purposes, harassment, or unauthorized access**

The authors and contributors of this toolkit:
- Are NOT responsible for any misuse or damage caused by this software
- Do NOT endorse illegal or unethical use of these tools
- Provide this software "AS IS" without warranty of any kind

**Unauthorized access to computer systems is illegal.** Always obtain proper authorization before conducting any security testing.

---

## Project Structure

```
02-osint-toolkit/
├── osint.py              # Main CLI interface
├── domain_recon.py       # Domain reconnaissance module
├── ip_analyzer.py        # IP analysis module
├── email_analyzer.py     # Email header analyzer
├── username_checker.py   # Social media username checker
├── metadata_extractor.py # File metadata extractor
├── requirements.txt      # Python dependencies
└── README.md            # This documentation
```

---

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- Built with Python and the open-source community
- Inspired by various OSINT tools and methodologies
- Designed for security professionals and researchers

---

<p align="center">
  <strong>Built for Defense & Intelligence Applications</strong><br>
  <em>Use responsibly. Stay ethical. Stay legal.</em>
</p>
