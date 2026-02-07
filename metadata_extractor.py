#!/usr/bin/env python3
"""
File Metadata Extractor
========================

This module extracts metadata from various file types including:
- Images (JPEG, PNG, TIFF, GIF) - EXIF data, GPS coordinates, camera info
- PDF documents - Author, creation date, software used, modification history
- Office documents (via file analysis)
- General file metadata (size, creation time, modification time)

Author: OSINT Toolkit
License: MIT
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    import exifread
    from PyPDF2 import PdfReader
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] Run: pip install -r requirements.txt")
    sys.exit(1)

console = Console()

# EXIF tags of interest for OSINT
EXIF_TAGS_OF_INTEREST = [
    "Make",  # Camera manufacturer
    "Model",  # Camera model
    "DateTime",  # Date/time taken
    "DateTimeOriginal",
    "DateTimeDigitized",
    "Software",  # Software used
    "Artist",  # Creator/owner
    "Copyright",
    "ImageDescription",
    "XPAuthor",
    "XPComment",
    "XPKeywords",
    "HostComputer",
    "ExifImageWidth",
    "ExifImageHeight",
    "Orientation",
    "Flash",
    "FocalLength",
    "ExposureTime",
    "FNumber",
    "ISOSpeedRatings",
    "GPSInfo",
]


def get_file_info(file_path: str) -> Dict[str, Any]:
    """
    Get basic file system information.

    Args:
        file_path: Path to the file

    Returns:
        Dictionary containing file info
    """
    path = Path(file_path)
    stat = path.stat()

    return {
        "filename": path.name,
        "full_path": str(path.absolute()),
        "extension": path.suffix.lower(),
        "size_bytes": stat.st_size,
        "size_human": format_size(stat.st_size),
        "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
    }


def format_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"


def extract_gps_coordinates(gps_info: dict) -> Optional[Dict[str, Any]]:
    """
    Extract and convert GPS coordinates from EXIF data.

    Args:
        gps_info: GPS EXIF data dictionary

    Returns:
        Dictionary with decimal coordinates or None
    """
    try:
        def convert_to_degrees(value):
            """Convert GPS coordinates to decimal degrees."""
            d = float(value[0])
            m = float(value[1])
            s = float(value[2])
            return d + (m / 60.0) + (s / 3600.0)

        lat = gps_info.get(2)  # GPSLatitude
        lat_ref = gps_info.get(1)  # GPSLatitudeRef
        lon = gps_info.get(4)  # GPSLongitude
        lon_ref = gps_info.get(3)  # GPSLongitudeRef

        if lat and lon:
            lat_decimal = convert_to_degrees(lat)
            lon_decimal = convert_to_degrees(lon)

            if lat_ref == 'S':
                lat_decimal = -lat_decimal
            if lon_ref == 'W':
                lon_decimal = -lon_decimal

            return {
                "latitude": lat_decimal,
                "longitude": lon_decimal,
                "latitude_ref": lat_ref,
                "longitude_ref": lon_ref,
                "google_maps_url": f"https://www.google.com/maps?q={lat_decimal},{lon_decimal}",
                "dms": f"{abs(lat_decimal):.6f}{'S' if lat_decimal < 0 else 'N'}, {abs(lon_decimal):.6f}{'W' if lon_decimal < 0 else 'E'}"
            }
    except Exception as e:
        console.print(f"[yellow][!] Error parsing GPS data: {e}[/yellow]")

    return None


def extract_image_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract metadata from image files.

    Args:
        file_path: Path to the image file

    Returns:
        Dictionary containing image metadata
    """
    metadata = {
        "format": None,
        "dimensions": None,
        "mode": None,
        "exif": {},
        "gps": None,
        "camera": None,
        "software": None,
        "dates": {},
    }

    try:
        # Basic image info using PIL
        with Image.open(file_path) as img:
            metadata["format"] = img.format
            metadata["dimensions"] = f"{img.width}x{img.height}"
            metadata["mode"] = img.mode

            # Extract EXIF using PIL
            exif_data = img._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)

                    # Handle GPS data specially
                    if tag_name == "GPSInfo":
                        gps_dict = {}
                        for gps_tag_id, gps_value in value.items():
                            gps_tag_name = GPSTAGS.get(gps_tag_id, gps_tag_id)
                            gps_dict[gps_tag_id] = gps_value
                        metadata["gps"] = extract_gps_coordinates(gps_dict)
                    elif isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except:
                            value = str(value)

                    # Store relevant EXIF data
                    if tag_name in EXIF_TAGS_OF_INTEREST or str(tag_id) in EXIF_TAGS_OF_INTEREST:
                        metadata["exif"][tag_name] = str(value)

                        # Extract specific fields
                        if tag_name in ["Make", "Model"]:
                            if not metadata["camera"]:
                                metadata["camera"] = {}
                            metadata["camera"][tag_name.lower()] = str(value)
                        elif tag_name == "Software":
                            metadata["software"] = str(value)
                        elif "Date" in tag_name:
                            metadata["dates"][tag_name] = str(value)

    except Exception as e:
        console.print(f"[yellow][!] PIL extraction error: {e}[/yellow]")

    # Additional extraction using exifread for more complete data
    try:
        with open(file_path, 'rb') as f:
            tags = exifread.process_file(f, details=True)

            for tag, value in tags.items():
                if tag.startswith('Image ') or tag.startswith('EXIF ') or tag.startswith('GPS '):
                    clean_tag = tag.replace('Image ', '').replace('EXIF ', '').replace('GPS ', '')
                    if clean_tag not in metadata["exif"]:
                        metadata["exif"][clean_tag] = str(value)

    except Exception as e:
        console.print(f"[yellow][!] ExifRead extraction error: {e}[/yellow]")

    return metadata


def extract_pdf_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract metadata from PDF files.

    Args:
        file_path: Path to the PDF file

    Returns:
        Dictionary containing PDF metadata
    """
    metadata = {
        "pages": 0,
        "encrypted": False,
        "author": None,
        "creator": None,
        "producer": None,
        "subject": None,
        "title": None,
        "creation_date": None,
        "modification_date": None,
        "keywords": None,
        "raw_info": {},
    }

    try:
        reader = PdfReader(file_path)

        metadata["pages"] = len(reader.pages)
        metadata["encrypted"] = reader.is_encrypted

        # Extract document info
        if reader.metadata:
            info = reader.metadata

            # Map common fields
            field_map = {
                "/Author": "author",
                "/Creator": "creator",
                "/Producer": "producer",
                "/Subject": "subject",
                "/Title": "title",
                "/Keywords": "keywords",
                "/CreationDate": "creation_date",
                "/ModDate": "modification_date",
            }

            for pdf_field, our_field in field_map.items():
                value = info.get(pdf_field)
                if value:
                    # Clean up date fields
                    if "Date" in pdf_field and isinstance(value, str):
                        if value.startswith("D:"):
                            # Parse PDF date format: D:YYYYMMDDHHmmSS
                            try:
                                date_str = value[2:16]  # Extract YYYYMMDDHHMMSS
                                parsed_date = datetime.strptime(date_str, "%Y%m%d%H%M%S")
                                value = parsed_date.isoformat()
                            except:
                                pass
                    metadata[our_field] = value

            # Store all raw info
            for key, value in info.items():
                if value:
                    metadata["raw_info"][key] = str(value)

    except Exception as e:
        console.print(f"[yellow][!] PDF extraction error: {e}[/yellow]")

    return metadata


def display_file_info(file_info: Dict[str, Any]) -> None:
    """Display basic file information."""
    table = Table(title="File Information", show_header=True, header_style="bold magenta")
    table.add_column("Property", style="cyan", width=20)
    table.add_column("Value", style="green")

    for key, value in file_info.items():
        table.add_row(key.replace("_", " ").title(), str(value))

    console.print(table)


def display_image_metadata(metadata: Dict[str, Any], file_path: str) -> None:
    """Display image metadata."""
    console.print(Panel(
        f"[bold cyan]Image Metadata Analysis[/bold cyan]",
        subtitle=Path(file_path).name,
        style="blue"
    ))

    # Basic info table
    table = Table(title="Image Properties", show_header=True, header_style="bold magenta")
    table.add_column("Property", style="cyan", width=20)
    table.add_column("Value", style="green")

    table.add_row("Format", metadata.get("format") or "Unknown")
    table.add_row("Dimensions", metadata.get("dimensions") or "Unknown")
    table.add_row("Color Mode", metadata.get("mode") or "Unknown")

    if metadata.get("camera"):
        camera = metadata["camera"]
        camera_str = f"{camera.get('make', '')} {camera.get('model', '')}".strip()
        table.add_row("Camera", camera_str or "Unknown")

    if metadata.get("software"):
        table.add_row("Software", metadata["software"])

    console.print(table)

    # Dates table
    if metadata.get("dates"):
        date_table = Table(title="Date Information", show_header=True, header_style="bold magenta")
        date_table.add_column("Field", style="cyan", width=25)
        date_table.add_column("Value", style="yellow")

        for field, value in metadata["dates"].items():
            date_table.add_row(field, value)

        console.print(date_table)

    # GPS Information
    if metadata.get("gps"):
        gps = metadata["gps"]
        console.print(Panel(
            f"[bold green]GPS COORDINATES FOUND![/bold green]\n\n"
            f"[bold]Latitude:[/bold] {gps['latitude']:.6f}\n"
            f"[bold]Longitude:[/bold] {gps['longitude']:.6f}\n"
            f"[bold]DMS:[/bold] {gps['dms']}\n\n"
            f"[cyan]Google Maps:[/cyan] {gps['google_maps_url']}",
            title="Geolocation Data",
            style="green"
        ))

    # EXIF data table
    if metadata.get("exif"):
        exif_table = Table(title="EXIF Metadata", show_header=True, header_style="bold magenta")
        exif_table.add_column("Tag", style="cyan", width=25)
        exif_table.add_column("Value", style="green")

        for tag, value in sorted(metadata["exif"].items()):
            # Truncate long values
            value_str = str(value)
            if len(value_str) > 60:
                value_str = value_str[:57] + "..."
            exif_table.add_row(tag, value_str)

        console.print(exif_table)


def display_pdf_metadata(metadata: Dict[str, Any], file_path: str) -> None:
    """Display PDF metadata."""
    console.print(Panel(
        f"[bold cyan]PDF Metadata Analysis[/bold cyan]",
        subtitle=Path(file_path).name,
        style="blue"
    ))

    # Document info table
    table = Table(title="Document Information", show_header=True, header_style="bold magenta")
    table.add_column("Property", style="cyan", width=20)
    table.add_column("Value", style="green")

    table.add_row("Pages", str(metadata.get("pages", 0)))
    table.add_row("Encrypted", "Yes" if metadata.get("encrypted") else "No")

    important_fields = ["title", "author", "creator", "producer", "subject", "keywords"]
    for field in important_fields:
        value = metadata.get(field)
        if value:
            table.add_row(field.title(), str(value))

    console.print(table)

    # Dates
    date_fields = ["creation_date", "modification_date"]
    dates_found = {f: metadata.get(f) for f in date_fields if metadata.get(f)}

    if dates_found:
        date_table = Table(title="Date Information", show_header=True, header_style="bold magenta")
        date_table.add_column("Field", style="cyan", width=20)
        date_table.add_column("Value", style="yellow")

        for field, value in dates_found.items():
            date_table.add_row(field.replace("_", " ").title(), str(value))

        console.print(date_table)

    # Highlight interesting findings
    findings = []
    if metadata.get("author"):
        findings.append(f"[green]Author identified:[/green] {metadata['author']}")
    if metadata.get("creator"):
        findings.append(f"[cyan]Creator software:[/cyan] {metadata['creator']}")
    if metadata.get("producer"):
        findings.append(f"[cyan]PDF producer:[/cyan] {metadata['producer']}")

    if findings:
        console.print(Panel(
            "\n".join(findings),
            title="Notable Findings",
            style="yellow"
        ))


def analyze_file(file_path: str) -> Dict[str, Any]:
    """
    Analyze a file and extract all available metadata.

    Args:
        file_path: Path to the file

    Returns:
        Dictionary containing all extracted metadata
    """
    if not os.path.exists(file_path):
        console.print(f"[red][!] File not found: {file_path}[/red]")
        return None

    results = {
        "file_path": file_path,
        "timestamp": datetime.now().isoformat(),
        "file_info": get_file_info(file_path),
        "metadata": None,
        "file_type": None,
    }

    # Get file extension
    ext = Path(file_path).suffix.lower()

    # Display basic file info
    display_file_info(results["file_info"])

    # Process based on file type
    image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.tiff', '.tif', '.bmp', '.webp']
    pdf_extensions = ['.pdf']

    if ext in image_extensions:
        results["file_type"] = "image"
        results["metadata"] = extract_image_metadata(file_path)
        display_image_metadata(results["metadata"], file_path)

    elif ext in pdf_extensions:
        results["file_type"] = "pdf"
        results["metadata"] = extract_pdf_metadata(file_path)
        display_pdf_metadata(results["metadata"], file_path)

    else:
        console.print(f"[yellow][!] Unsupported file type: {ext}[/yellow]")
        console.print("[dim]Supported types: Images (JPG, PNG, GIF, TIFF), PDF documents[/dim]")
        results["file_type"] = "unsupported"

    return results


def analyze_directory(dir_path: str, recursive: bool = False) -> List[Dict[str, Any]]:
    """
    Analyze all supported files in a directory.

    Args:
        dir_path: Path to the directory
        recursive: Whether to search recursively

    Returns:
        List of analysis results
    """
    supported_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.tiff', '.tif', '.bmp', '.webp', '.pdf']

    path = Path(dir_path)
    if recursive:
        files = [f for f in path.rglob('*') if f.suffix.lower() in supported_extensions]
    else:
        files = [f for f in path.glob('*') if f.suffix.lower() in supported_extensions]

    console.print(f"[cyan][*] Found {len(files)} supported files[/cyan]\n")

    results = []
    for file_path in files:
        console.print(f"\n[bold]{'=' * 60}[/bold]")
        result = analyze_file(str(file_path))
        if result:
            results.append(result)

    return results


def main():
    """Main entry point for metadata extractor."""
    parser = argparse.ArgumentParser(
        description="File Metadata Extractor - OSINT Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s photo.jpg                    # Extract metadata from image
  %(prog)s document.pdf                 # Extract metadata from PDF
  %(prog)s /path/to/directory           # Analyze all files in directory
  %(prog)s /path/to/directory -r        # Recursive directory scan

Supported File Types:
  Images: JPG, JPEG, PNG, GIF, TIFF, BMP, WEBP
  Documents: PDF

LEGAL DISCLAIMER:
  This tool is intended for authorized security testing and educational
  purposes only. Only analyze files you have permission to access.
        """
    )

    parser.add_argument("path", help="File or directory to analyze")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan directories")
    parser.add_argument("-o", "--output", help="Output results to JSON file")

    args = parser.parse_args()

    target_path = args.path

    console.print(Panel(
        "[bold cyan]File Metadata Extractor[/bold cyan]",
        subtitle="OSINT Toolkit",
        style="blue"
    ))

    try:
        if os.path.isdir(target_path):
            results = analyze_directory(target_path, recursive=args.recursive)
        elif os.path.isfile(target_path):
            results = analyze_file(target_path)
        else:
            console.print(f"[red][!] Path not found: {target_path}[/red]")
            sys.exit(1)

        if args.output and results:
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
