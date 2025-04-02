#!/usr/bin/env python
import os
import sys
import time
import json
import argparse
import requests
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.text import Text
from rich import box
from dotenv import load_dotenv

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import scanner module directly for local scanning
from backend.scanner import SecurityScanner
from backend.database import init_db, get_db
from backend.utils import normalize_url, format_scan_duration, logger

# Load environment variables
load_dotenv()

# Set up console
console = Console()

def print_banner():
    """Print application banner"""
    banner = """
    ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
   ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
   ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║         ███████╗██║     ███████║██╔██╗ ██║
   ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║         ╚════██║██║     ██╔══██║██║╚██╗██║
   ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗╚██████╗    ███████║╚██████╗██║  ██║██║ ╚████║
    ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                                                           
    [bold cyan]Web Application Security Scanner[/bold cyan] | [bold red]v1.0.0[/bold red]
    """
    console.print(Panel(banner, border_style="cyan", expand=False))

def print_vulnerability_table(vulnerabilities):
    """Print vulnerability table"""
    if not vulnerabilities:
        console.print("[yellow]No vulnerabilities found.[/yellow]")
        return
        
    table = Table(show_header=True, header_style="bold magenta", box=box.DOUBLE_EDGE)
    table.add_column("Type", style="cyan")
    table.add_column("Severity", style="bold")
    table.add_column("URL", style="blue")
    table.add_column("Description")
    
    for vuln in vulnerabilities:
        severity_style = {
            "Critical": "bold red",
            "High": "red",
            "Medium": "yellow",
            "Low": "green",
            "Info": "blue"
        }.get(vuln.get("severity", ""), "white")
        
        table.add_row(
            vuln.get("type", "Unknown"),
            f"[{severity_style}]{vuln.get('severity', 'Unknown')}[/{severity_style}]",
            vuln.get("url", ""),
            Text(vuln.get("description", ""), no_wrap=False)
        )
    
    console.print(table)

def print_scan_summary(results):
    """Print scan summary"""
    console.print(Panel(
        f"[bold cyan]Scan Summary[/bold cyan]\n\n"
        f"[bold]Target URL:[/bold] {results.get('target_url', 'Unknown')}\n"
        f"[bold]Scan Duration:[/bold] {results.get('scan_duration', 'Unknown')}\n"
        f"[bold]Pages Scanned:[/bold] {results.get('pages_scanned', 0)}\n"
        f"[bold]Vulnerabilities Found:[/bold] {results.get('vulnerabilities_found', 0)}\n",
        title="Results",
        border_style="green"
    ))

def run_local_scan(args):
    """Run a scan locally using the scanner module"""
    url = normalize_url(args.url)
    
    console.print(f"[bold cyan]Starting scan on:[/bold cyan] {url}")
    console.print(f"[bold cyan]Scan depth:[/bold cyan] {args.depth}")
    console.print(f"[bold cyan]Include subdomains:[/bold cyan] {args.subdomains}")
    
    # Build scan configuration
    config = {
        "check_sql_injection": not args.no_sqli,
        "check_xss": not args.no_xss,
        "check_csrf": not args.no_csrf,
        "check_ssrf": not args.no_ssrf,
        "check_xxe": not args.no_xxe,
        "check_auth": not args.no_auth,
        "max_urls_to_scan": args.max_urls,
        "request_timeout": args.timeout
    }
    
    # Initialize scanner
    scanner = SecurityScanner()
    
    # Show progress bar
    with Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[bold cyan]{task.fields[pages]} pages scanned"),
        TextColumn("[bold red]{task.fields[vulns]} vulnerabilities"),
        TimeElapsedColumn(),
    ) as progress:
        scan_task = progress.add_task(
            "Scanning...", 
            total=None, 
            pages=0, 
            vulns=0
        )
        
        # Start scan in a separate thread
        scanner.start_scan(url, args.depth, args.subdomains, config)
        
        # Update progress
        try:
            while scanner.active:
                pages = len(scanner.visited_urls)
                vulns = scanner.vulnerability_count
                progress.update(scan_task, pages=pages, vulns=vulns)
                time.sleep(0.5)
        except KeyboardInterrupt:
            console.print("[yellow]Scan interrupted by user. Stopping...[/yellow]")
            scanner.stop_scan()
    
    # Get results
    scan_duration = time.time() - scanner.start_time if scanner.start_time else 0
    results = {
        "target_url": url,
        "scan_duration": format_scan_duration(scan_duration),
        "pages_scanned": len(scanner.visited_urls),
        "vulnerabilities_found": scanner.vulnerability_count,
        "vulnerabilities": scanner.results
    }
    
    # Print results
    print_scan_summary(results)
    print_vulnerability_table(results.get("vulnerabilities", []))
    
    # Export results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        console.print(f"[green]Results exported to:[/green] {args.output}")
    
    return results

def run_api_scan(args):
    """Run a scan using the API"""
    url = normalize_url(args.url)
    api_url = args.api_url.rstrip("/")
    
    console.print(f"[bold cyan]Starting scan via API:[/bold cyan] {api_url}")
    console.print(f"[bold cyan]Target URL:[/bold cyan] {url}")
    
    # Build scan configuration
    config = {
        "check_sql_injection": not args.no_sqli,
        "check_xss": not args.no_xss,
        "check_csrf": not args.no_csrf,
        "check_ssrf": not args.no_ssrf,
        "check_xxe": not args.no_xxe,
        "check_auth": not args.no_auth,
        "max_urls_to_scan": args.max_urls,
        "request_timeout": args.timeout
    }
    
    # Start scan
    try:
        response = requests.post(
            f"{api_url}/api/scans",
            json={
                "url": url,
                "scan_depth": args.depth,
                "include_subdomains": args.subdomains,
                "configuration": config
            }
        )
        response.raise_for_status()
        scan_data = response.json()
        scan_id = scan_data.get("scan_id")
        
        if not scan_id:
            console.print("[bold red]Error:[/bold red] Failed to get scan ID from API")
            return
            
        console.print(f"[green]Scan started with ID:[/green] {scan_id}")
        
        # Show progress bar
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[bold cyan]{task.fields[pages]} pages scanned"),
            TextColumn("[bold red]{task.fields[vulns]} vulnerabilities"),
            TextColumn("{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        ) as progress:
            scan_task = progress.add_task(
                "Scanning...", 
                total=100, 
                pages=0, 
                vulns=0
            )
            
            # Poll for status
            completed = False
            while not completed:
                try:
                    status_response = requests.get(f"{api_url}/api/scans/{scan_id}")
                    status_response.raise_for_status()
                    status_data = status_response.json()
                    
                    status = status_data.get("status", "")
                    pages = status_data.get("pages_scanned", 0)
                    vulns = status_data.get("vulnerabilities_found", 0)
                    progress_percentage = status_data.get("progress_percentage", 0)
                    
                    progress.update(
                        scan_task, 
                        completed=progress_percentage, 
                        pages=pages, 
                        vulns=vulns
                    )
                    
                    if status in ["completed", "failed", "stopped"]:
                        completed = True
                    
                    time.sleep(1)
                except KeyboardInterrupt:
                    console.print("[yellow]Polling interrupted by user. Attempting to stop scan...[/yellow]")
                    try:
                        requests.post(f"{api_url}/api/scans/{scan_id}/stop")
                        console.print("[green]Scan stop request sent.[/green]")
                    except Exception as e:
                        console.print(f"[red]Failed to stop scan: {str(e)}[/red]")
                    break
                except Exception as e:
                    console.print(f"[yellow]Error polling status: {str(e)}. Retrying...[/yellow]")
                    time.sleep(2)
        
        # Get final results
        try:
            detail_response = requests.get(f"{api_url}/api/scans/{scan_id}/detail")
            detail_response.raise_for_status()
            results = detail_response.json()
            
            print_scan_summary({
                "target_url": results.get("url", ""),
                "scan_duration": results.get("scan_duration", ""),
                "pages_scanned": results.get("pages_scanned", 0),
                "vulnerabilities_found": results.get("vulnerabilities_found", 0)
            })
            
            print_vulnerability_table(results.get("vulnerabilities", []))
            
            # Export results if requested
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                console.print(f"[green]Results exported to:[/green] {args.output}")
                
            return results
            
        except Exception as e:
            console.print(f"[bold red]Error getting scan results: {str(e)}[/bold red]")
            
    except Exception as e:
        console.print(f"[bold red]Error starting scan: {str(e)}[/bold red]")

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description="CyberSec Scan - Web Application Security Scanner")
    
    # Main arguments
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Crawling depth (default: 1)")
    parser.add_argument("-o", "--output", help="Output file for JSON results")
    
    # Scan configuration
    parser.add_argument("--subdomains", action="store_true", help="Include subdomains in scan")
    parser.add_argument("--max-urls", type=int, default=100, help="Maximum URLs to scan (default: 100)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    
    # Disable specific checks
    parser.add_argument("--no-sqli", action="store_true", help="Disable SQL injection checks")
    parser.add_argument("--no-xss", action="store_true", help="Disable XSS checks")
    parser.add_argument("--no-csrf", action="store_true", help="Disable CSRF checks")
    parser.add_argument("--no-ssrf", action="store_true", help="Disable SSRF checks")
    parser.add_argument("--no-xxe", action="store_true", help="Disable XXE checks")
    parser.add_argument("--no-auth", action="store_true", help="Disable authentication vulnerability checks")
    
    # API mode
    parser.add_argument("--api", action="store_true", help="Use API instead of local scanning")
    parser.add_argument("--api-url", default="http://localhost:8000", help="API base URL (default: http://localhost:8000)")
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Run scan
    if args.api:
        run_api_scan(args)
    else:
        run_local_scan(args)

if __name__ == "__main__":
    main() 