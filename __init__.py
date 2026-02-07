"""
OSINT Toolkit
=============

A comprehensive Open Source Intelligence (OSINT) toolkit for security
professionals, researchers, and analysts.

Modules:
    - domain_recon: Domain reconnaissance (WHOIS, DNS, subdomains)
    - ip_analyzer: IP geolocation and reputation analysis
    - email_analyzer: Email header forensics
    - username_checker: Social media username search
    - metadata_extractor: File metadata extraction

Usage:
    python osint.py              # Interactive mode
    python osint.py domain ...   # Domain reconnaissance
    python osint.py ip ...       # IP analysis
    python osint.py email ...    # Email analysis
    python osint.py username ... # Username search
    python osint.py metadata ... # Metadata extraction

Author: OSINT Toolkit
License: MIT
"""

__version__ = "1.0.0"
__author__ = "OSINT Toolkit"
__license__ = "MIT"

from . import domain_recon
from . import ip_analyzer
from . import email_analyzer
from . import username_checker
from . import metadata_extractor
