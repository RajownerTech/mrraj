#!/usr/bin/env python3
import os, re, socket, ipaddress, threading, requests
import concurrent.futures, time
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn, MofNCompleteColumn
from rich.panel import Panel
from rich.table import Table
from colorama import init
from urllib3.exceptions import InsecureRequestWarning
import warnings

# ============ SETUP ============
init(autoreset=True)
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

console = Console()
lock = threading.Lock()

BASE_DIR = "/storage/emulated/0/Download/Scan_Results"
os.makedirs(BASE_DIR, exist_ok=True)

def banner():
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]╔═══════════════════════════════════╗\n"
        "║    [bold yellow]    Mr Tech Hacker[/bold yellow]             ║\n"
    "║                                   ║\n"
        "║    Multi Advanced Tool v2.0       ║\n"
        "║    Developed by: Mr Raj           ║\n"
        "║    Redirect Filter: PERMANENT ON  ║\n"
        "╚═══════════════════════════════════╝[/bold cyan]",
        border_style="blue"
    ))

def make_out(name):
    path = os.path.join(BASE_DIR, name)
    os.makedirs(path, exist_ok=True)
    return path

def refresh_tool():
    """Refresh the tool"""
    console.print("\n[bold yellow]Refreshing tool...[/bold yellow]")
    time.sleep(1)
    return

# ============ 1 HOST SCANNER (Based on Text Scanner) ============
def host_scanner():
    banner()
    console.print("[bold yellow]┌──────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│      HOST SCANNER MODULE     │[/bold yellow]")
    console.print("[bold yellow]└──────────────────────────────┘[/bold yellow]\n")
    
    infile = input("[bold cyan]Enter domain list file path: ").strip()
    if not os.path.exists(infile):
        console.print("[bold red]File not found![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    outdir_name = input("[bold cyan]Output folder name: ").strip() or "Host_Scanner"
    outdir = make_out(outdir_name)
    
    ports_input = input("[bold cyan]Ports (comma separated, default: 80,443,8080): ").strip()
    ports = [p.strip() for p in ports_input.split(",")] if ports_input else ["80", "443", "8080"]
    
    try:
        threads = int(input("[bold cyan]Threads (default: 80): ").strip() or 80)
    except:
        threads = 80
    
    # Add HTTP method selection
    console.print("\n[bold cyan]Select HTTP Method:[/bold cyan]")
    console.print("1. GET (Default)")
    console.print("2. HEAD")
    console.print("3. POST")
    console.print("4. PUT")
    method_choice = input("[bold cyan]Select method (1-4, default: 1): ").strip() or "1"
    
    methods = {
        "1": "GET",
        "2": "HEAD",
        "3": "POST",
        "4": "PUT"
    }
    method = methods.get(method_choice, "GET")
    
    # PERMANENT REDIRECT FILTER - ALWAYS ON
    filter_redirect = True
    
    try:
        with open(infile, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    except:
        console.print("[bold red]Error reading file![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    total = len(domains) * len(ports)
    
    results_file = os.path.join(outdir, "host_scan_results.txt")
    results_ip_file = os.path.join(outdir, "host_ips.txt")
    
    # Clear result files
    open(results_file, 'w').close()
    open(results_ip_file, 'w').close()
    
    console.print(f"\n[bold green]Starting scan of {len(domains)} domains on ports {ports}...[/bold green]")
    console.print(f"[bold green]Method: {method}[/bold green]")
    console.print(f"[bold yellow]Redirect Filter: PERMANENTLY ON (302/Jio/Airtel responses filtered)[/bold yellow]")
    console.print(f"[bold green]Output Directory: {outdir}[/bold green]")
    console.print("[bold white]Code | Server | IP | Domain:Port[/bold white]")
    console.print("-" * 70)
    
    def get_ip(domain):
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return "N/A"
    
    def scan_host(domain, port, progress, task_id):
        try:
            if port == "443":
                url = f"https://{domain}"
            else:
                url = f"http://{domain}:{port}"
            
            ip = get_ip(domain)
            headers = {"User-Agent": "Mozilla/5.0"}
            
            # Use selected HTTP method
            if method == "GET":
                resp = requests.get(url, timeout=3, verify=False, headers=headers, allow_redirects=False)
            elif method == "HEAD":
                resp = requests.head(url, timeout=3, verify=False, headers=headers, allow_redirects=False)
            elif method == "POST":
                resp = requests.post(url, timeout=3, verify=False, headers=headers, allow_redirects=False)
            elif method == "PUT":
                resp = requests.put(url, timeout=3, verify=False, headers=headers, allow_redirects=False)
            
            status = resp.status_code
            server = resp.headers.get("Server", "Unknown")
            
            # PERMANENT REDIRECT FILTERING - ALWAYS ACTIVE
            if status == 302:
                # Check if it's redirecting to Jio or similar captive portal
                location = resp.headers.get("Location", "")
                location_lower = location.lower()
                if any(x in location_lower for x in ["jio.com", "airtel", "airtel.in", "captive", "portal", "login"]):
                    # This is a captive portal/redirect, skip it
                    return
            
            # Also check for other redirect status codes
            if status in [301, 302, 303, 307, 308]:
                # Check response text for captive portal indicators
                response_text = resp.text.lower()
                if any(x in response_text for x in ["jio", "airtel", "reliance", "captive", "login", "wifi", "hotspot"]):
                    return
            
            line = f"{status} | {server[:20]} | {ip} | {domain}:{port}"
            result_line = f"{status} | {server} | {ip} | {domain}:{port}"
            
            with lock:
                console.print(
                    f"[cyan]{status:^4}[/cyan] | "
                    f"[green]{server[:20]:^20}[/green] | "
                    f"[yellow]{ip:^15}[/yellow] | "
                    f"[bold white]{domain}:{port}[/bold white]"
                )
                
                # Save results
                with open(results_file, "a") as f:
                    f.write(result_line + "\n")
                with open(results_ip_file, "a") as ip_file:
                    if ip != "N/A":
                        ip_file.write(ip + "\n")
                        
        except Exception as e:
            pass
        finally:
            progress.update(task_id, advance=1)
    
    start_time = time.time()
    with Progress(
        SpinnerColumn(),
        TaskProgressColumn(),
        BarColumn(bar_width=40, complete_style="bold green"),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task_id = progress.add_task("[cyan]Scanning domains...", total=total)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for domain in domains:
                for port in ports:
                    futures.append(executor.submit(scan_host, domain, port, progress, task_id))
            
            # Wait for all tasks to complete
            concurrent.futures.wait(futures)
    
    elapsed = time.time() - start_time
    rate = total / elapsed if elapsed > 0 else 0
    
    console.print(f"\n[bold magenta]📋 Scan Summary:[/bold magenta]")
    console.print(f"[green]✔ Completed[/green] | {total} scans | [cyan]{rate:.2f} scans/second[/cyan]")
    console.print(f"[yellow]💾 Results saved in: {results_file}[/yellow]")
    console.print(f"[yellow]💾 IPs saved in: {results_ip_file}[/yellow]")
    
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 2 CIDR SCANNER (Based on CIDR Scanner) ============
def cidr_scanner():
    banner()
    console.print("[bold yellow]┌──────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│      CIDR SCANNER MODULE     │[/bold yellow]")
    console.print("[bold yellow]└──────────────────────────────┘[/bold yellow]\n")
    
    cidr_input = input("[bold cyan]Enter CIDR (e.g., 192.168.1.0/24): ").strip()
    try:
        net = ipaddress.ip_network(cidr_input, strict=False)
    except:
        console.print("[bold red]Invalid CIDR notation![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    outdir_name = input("[bold cyan]Output folder name: ").strip() or "CIDR_Scanner"
    outdir = make_out(outdir_name)
    
    ports_input = input("[bold cyan]Ports (comma separated, default: 80,443): ").strip()
    ports = [p.strip() for p in ports_input.split(",")] if ports_input else ["80", "443"]
    
    try:
        threads = int(input("[bold cyan]Threads (default: 150): ").strip() or 150)
    except:
        threads = 150
    
    # Add HTTP method selection
    console.print("\n[bold cyan]Select HTTP Method:[/bold cyan]")
    console.print("1. GET (Default)")
    console.print("2. HEAD")
    console.print("3. POST")
    console.print("4. PUT")
    method_choice = input("[bold cyan]Select method (1-4, default: 1): ").strip() or "1"
    
    methods = {
        "1": "GET",
        "2": "HEAD",
        "3": "POST",
        "4": "PUT"
    }
    method = methods.get(method_choice, "GET")
    
    # PERMANENT REDIRECT FILTER - ALWAYS ON
    filter_redirect = True
    
    hosts = [str(ip) for ip in net.hosts()]
    total = len(hosts) * len(ports)
    
    results_file = os.path.join(outdir, "cidr_scan_results.txt")
    
    # Clear result file
    open(results_file, 'w').close()
    
    console.print(f"\n[bold green]Starting scan of {len(hosts)} hosts on ports {ports}...[/bold green]")
    console.print(f"[bold green]Method: {method}[/bold green]")
    console.print(f"[bold yellow]Redirect Filter: PERMANENTLY ON (302/Jio/Airtel responses filtered)[/bold yellow]")
    console.print(f"[bold green]Output Directory: {outdir}[/bold green]")
    console.print("[bold white]Code | Server | IP:Port[/bold white]")
    console.print("-" * 60)
    
    responsive_hosts = []
    
    def scan_ip(ip, port, progress, task_id):
        try:
            url = f"http://{ip}:{port}"
            headers = {"User-Agent": "Mozilla/5.0"}
            
            # Use selected HTTP method
            if method == "GET":
                response = requests.get(url, timeout=2, verify=False, headers=headers, allow_redirects=False)
            elif method == "HEAD":
                response = requests.head(url, timeout=2, verify=False, headers=headers, allow_redirects=False)
            elif method == "POST":
                response = requests.post(url, timeout=2, verify=False, headers=headers, allow_redirects=False)
            elif method == "PUT":
                response = requests.put(url, timeout=2, verify=False, headers=headers, allow_redirects=False)
            
            server = response.headers.get('Server', 'Unknown')
            
            # PERMANENT REDIRECT FILTERING - ALWAYS ACTIVE
            if response.status_code == 302:
                # Check if it's redirecting to Jio or similar captive portal
                location = response.headers.get("Location", "")
                location_lower = location.lower()
                if any(x in location_lower for x in ["jio.com", "airtel", "airtel.in", "captive", "portal", "login"]):
                    # This is a captive portal/redirect, skip it
                    return
            
            # Also check for other redirect status codes
            if response.status_code in [301, 302, 303, 307, 308]:
                # Check response text for captive portal indicators
                response_text = response.text.lower()
                if any(x in response_text for x in ["jio", "airtel", "reliance", "captive", "login", "wifi", "hotspot"]):
                    return
            
            line = f"{response.status_code} | {server[:15]} | {ip}:{port}"
            result_line = f"{response.status_code} | {server} | {ip}:{port}"
            
            with lock:
                console.print(f"[green][{response.status_code}][/green] {ip}:{port} - {server[:20]}")
                
                with open(results_file, "a") as f:
                    f.write(result_line + "\n")
                
                responsive_hosts.append({
                    "ip": ip,
                    "port": port,
                    "code": response.status_code,
                    "server": server
                })
        except:
            pass
        finally:
            progress.update(task_id, advance=1)
    
    start_time = time.time()
    with Progress(
        SpinnerColumn(),
        TaskProgressColumn(),
        BarColumn(bar_width=40, complete_style="bold green"),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task_id = progress.add_task(f"[cyan]Scanning {cidr_input}...", total=total)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for ip in hosts:
                for port in ports:
                    future = executor.submit(scan_ip, ip, port, progress, task_id)
                    futures.append(future)
            
            # Wait for all tasks to complete
            concurrent.futures.wait(futures)
    
    elapsed = time.time() - start_time
    rate = total / elapsed if elapsed > 0 else 0
    
    console.print(f"\n[bold magenta]📋 Scan Summary for {cidr_input}[/bold magenta]")
    if responsive_hosts:
        table = Table(show_header=True, header_style="bold magenta", box=None)
        table.add_column("Code", style="cyan", justify="center")
        table.add_column("IP", style="yellow")
        table.add_column("Port", style="white", justify="center")
        table.add_column("Server", style="green")
        
        for r in responsive_hosts:
            table.add_row(str(r["code"]), r["ip"], str(r["port"]), r["server"][:30])
        console.print(table)
    else:
        console.print("[yellow]⚠️  No responsive hosts found.[/yellow]")
    
    console.print(f"[green]✔ Completed[/green] | {total} scans | [cyan]{rate:.2f} scans/second[/cyan]")
    console.print(f"[yellow]💾 Results saved in: {results_file}[/yellow]")
    
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 3 DOMAIN EXTRACTOR ============
def domain_extractor():
    banner()
    console.print("[bold yellow]┌──────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│    DOMAIN EXTRACTOR MODULE   │[/bold yellow]")
    console.print("[bold yellow]└──────────────────────────────┘[/bold yellow]\n")
    
    outdir_name = input("[bold cyan]Output folder name: ").strip() or "Domain_Extractor"
    outdir = make_out(outdir_name)
    
    console.print("\n[bold cyan]Choose input method:[/bold cyan]")
    console.print("1. Paste text directly")
    console.print("2. Read from file")
    choice = input("\n[bold cyan]Select (1/2): ").strip()
    
    text = ""
    if choice == "1":
        console.print("\n[bold cyan]Paste your text (press Enter twice when done):[/bold cyan]\n")
        lines = []
        blank_count = 0
        
        while True:
            try:
                line = input()
                if line.strip() == "":
                    blank_count += 1
                    if blank_count == 2:
                        break
                else:
                    blank_count = 0
                    lines.append(line)
            except KeyboardInterrupt:
                console.print("\n[yellow]Input cancelled[/yellow]")
                return
        
        text = "\n".join(lines)
    elif choice == "2":
        filepath = input("[bold cyan]Enter file path: ").strip()
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
        except:
            console.print("[bold red]Error reading file![/bold red]")
            input("\nPress Enter to continue...")
            refresh_tool()
            return
    
    domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
    domains = set(domain_pattern.findall(text))
    
    filtered_domains = []
    for domain in domains:
        if len(domain) > 4 and not domain.startswith("www.") and not domain.endswith(".com.com"):
            filtered_domains.append(domain.lower())
    
    filtered_domains = sorted(set(filtered_domains))
    
    output_file = os.path.join(outdir, "extracted_domains.txt")
    
    console.print(f"\n[bold green]Found {len(filtered_domains)} unique domains[/bold green]")
    console.print(f"[bold green]Output Directory: {outdir}[/bold green]")
    console.print("[bold white]Extracted Domains:[/bold white]")
    console.print("-" * 50)
    
    with open(output_file, 'w') as f:
        for domain in filtered_domains:
            console.print(domain)
            f.write(domain + "\n")
    
    console.print(f"\n[bold green]Domains saved to: {output_file}[/bold green]")
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 4 MULTI CIDR ============
def multi_cidr():
    banner()
    console.print("[bold yellow]┌──────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│    MULTI CIDR SCANNER        │[/bold yellow]")
    console.print("[bold yellow]└──────────────────────────────┘[/bold yellow]\n")
    
    infile = input("[bold cyan]Enter CIDR list file path: ").strip()
    if not os.path.exists(infile):
        console.print("[bold red]File not found![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    outdir_name = input("[bold cyan]Output folder name: ").strip() or "Multi_CIDR"
    outdir = make_out(outdir_name)
    
    port = input("[bold cyan]Port to scan (default: 80): ").strip() or "80"
    
    try:
        threads = int(input("[bold cyan]Threads (default: 200): ").strip() or 200)
    except:
        threads = 200
    
    # Add HTTP method selection
    console.print("\n[bold cyan]Select HTTP Method:[/bold cyan]")
    console.print("1. GET (Default)")
    console.print("2. HEAD")
    console.print("3. POST")
    console.print("4. PUT")
    method_choice = input("[bold cyan]Select method (1-4, default: 1): ").strip() or "1"
    
    methods = {
        "1": "GET",
        "2": "HEAD",
        "3": "POST",
        "4": "PUT"
    }
    method = methods.get(method_choice, "GET")
    
    # PERMANENT REDIRECT FILTER - ALWAYS ON
    filter_redirect = True
    
    try:
        with open(infile, 'r') as f:
            cidr_list = [line.strip() for line in f if line.strip()]
    except:
        console.print("[bold red]Error reading file![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    all_ips = []
    for cidr_str in cidr_list:
        try:
            cidr = ipaddress.ip_network(cidr_str, strict=False)
            all_ips.extend([str(ip) for ip in cidr.hosts()])
        except:
            console.print(f"[yellow]Skipping invalid CIDR: {cidr_str}[/yellow]")
    
    total = len(all_ips)
    results_file = os.path.join(outdir, "multi_cidr_results.txt")
    
    # Clear result file
    open(results_file, 'w').close()
    
    console.print(f"\n[bold green]Scanning {total} IPs on port {port}...[/bold green]")
    console.print(f"[bold green]Method: {method}[/bold green]")
    console.print(f"[bold yellow]Redirect Filter: PERMANENTLY ON (302/Jio/Airtel responses filtered)[/bold yellow]")
    console.print(f"[bold green]Output Directory: {outdir}[/bold green]")
    console.print("[bold white]Code | Server | IP:Port[/bold white]")
    console.print("-" * 60)
    
    responsive_hosts = []
    
    def scan_single_ip(ip, port, progress, task_id):
        try:
            url = f"http://{ip}:{port}"
            headers = {"User-Agent": "Mozilla/5.0"}
            
            # Use selected HTTP method
            if method == "GET":
                response = requests.get(url, timeout=2, verify=False, headers=headers, allow_redirects=False)
            elif method == "HEAD":
                response = requests.head(url, timeout=2, verify=False, headers=headers, allow_redirects=False)
            elif method == "POST":
                response = requests.post(url, timeout=2, verify=False, headers=headers, allow_redirects=False)
            elif method == "PUT":
                response = requests.put(url, timeout=2, verify=False, headers=headers, allow_redirects=False)
            
            server = response.headers.get('Server', 'Unknown')
            
            # PERMANENT REDIRECT FILTERING - ALWAYS ACTIVE
            if response.status_code == 302:
                # Check if it's redirecting to Jio or similar captive portal
                location = response.headers.get("Location", "")
                location_lower = location.lower()
                if any(x in location_lower for x in ["jio.com", "airtel", "airtel.in", "captive", "portal", "login"]):
                    # This is a captive portal/redirect, skip it
                    return
            
            # Also check for other redirect status codes
            if response.status_code in [301, 302, 303, 307, 308]:
                # Check response text for captive portal indicators
                response_text = response.text.lower()
                if any(x in response_text for x in ["jio", "airtel", "reliance", "captive", "login", "wifi", "hotspot"]):
                    return
            
            line = f"{response.status_code} | {server[:15]} | {ip}:{port}"
            result_line = f"{response.status_code} | {server} | {ip}:{port}"
            
            with lock:
                console.print(f"[green][{response.status_code}][/green] {ip}:{port} - {server[:20]}")
                
                with open(results_file, "a") as f:
                    f.write(result_line + "\n")
                
                responsive_hosts.append({
                    "ip": ip,
                    "port": port,
                    "code": response.status_code,
                    "server": server
                })
        except:
            pass
        finally:
            progress.update(task_id, advance=1)
    
    start_time = time.time()
    with Progress(
        SpinnerColumn(),
        TaskProgressColumn(),
        BarColumn(bar_width=40, complete_style="bold green"),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task_id = progress.add_task(f"[cyan]Scanning {total} IPs...", total=total)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for ip in all_ips:
                future = executor.submit(scan_single_ip, ip, port, progress, task_id)
                futures.append(future)
            
            # Wait for all tasks to complete
            concurrent.futures.wait(futures)
    
    elapsed = time.time() - start_time
    rate = total / elapsed if elapsed > 0 else 0
    
    console.print(f"\n[bold magenta]📋 Scan Summary[/bold magenta]")
    if responsive_hosts:
        table = Table(show_header=True, header_style="bold magenta", box=None)
        table.add_column("Code", style="cyan", justify="center")
        table.add_column("IP", style="yellow")
        table.add_column("Port", style="white", justify="center")
        table.add_column("Server", style="green")
        
        for r in responsive_hosts:
            table.add_row(str(r["code"]), r["ip"], str(r["port"]), r["server"][:30])
        console.print(table)
    else:
        console.print("[yellow]⚠️  No responsive hosts found.[/yellow]")
    
    console.print(f"[green]✔ Completed[/green] | {total} scans | [cyan]{rate:.2f} scans/second[/cyan]")
    console.print(f"[yellow]💾 Results saved in: {results_file}[/yellow]")
    
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 5 MULTI PORT ============
def multi_port():
    banner()
    console.print("[bold yellow]┌──────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│    MULTI PORT SCANNER        │[/bold yellow]")
    console.print("[bold yellow]└──────────────────────────────┘[/bold yellow]\n")
    
    domain = input("[bold cyan]Enter domain/IP: ").strip()
    ports_input = input("[bold cyan]Enter ports (comma separated or range 1-100): ").strip()
    
    ports = []
    if '-' in ports_input:
        try:
            start, end = map(int, ports_input.split('-'))
            ports = list(range(start, end + 1))
        except:
            console.print("[bold red]Invalid port range![/bold red]")
            input("\nPress Enter to continue...")
            refresh_tool()
            return
    elif ports_input:
        try:
            ports = [int(p.strip()) for p in ports_input.split(",")]
        except:
            console.print("[bold red]Invalid ports! Use comma separated numbers or range.[/bold red]")
            input("\nPress Enter to continue...")
            refresh_tool()
            return
    else:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389]
    
    try:
        threads = int(input("[bold cyan]Threads (default: 100): ").strip() or 100)
    except:
        threads = 100
    
    # PERMANENT REDIRECT FILTER FOR WEB PORTS - ALWAYS ON
    filter_redirect = True
    
    # Add HTTP method selection for web ports
    console.print("\n[bold cyan]Select HTTP Method (for web ports only):[/bold cyan]")
    console.print("1. GET (Default)")
    console.print("2. HEAD")
    console.print("3. POST")
    console.print("4. PUT")
    method_choice = input("[bold cyan]Select method (1-4, default: 1): ").strip() or "1"
    
    methods = {
        "1": "GET",
        "2": "HEAD",
        "3": "POST",
        "4": "PUT"
    }
    method = methods.get(method_choice, "GET")
    
    console.print(f"\n[bold green]Scanning {domain} on {len(ports)} ports...[/bold green]")
    console.print(f"[bold green]Method: {method}[/bold green]")
    console.print(f"[bold yellow]Redirect Filter: PERMANENTLY ON (302/Jio/Airtel responses filtered)[/bold yellow]\n")
    
    table = Table(title=f"Port Scan Results for {domain}")
    table.add_column("Port", style="cyan", justify="center")
    table.add_column("Status", style="bold", justify="center")
    table.add_column("Service", style="yellow", justify="left")
    
    try:
        ip_addr = socket.gethostbyname(domain)
        console.print(f"[green]Resolved IP: {ip_addr}[/green]\n")
    except:
        ip_addr = domain
        console.print(f"[yellow]Using provided host: {ip_addr}[/yellow]\n")
    
    def check_web_service(port, ip):
        """Check web service and filter redirects - PERMANENT FILTER"""
        try:
            url = f"http://{ip}:{port}"
            headers = {"User-Agent": "Mozilla/5.0"}
            
            # Use selected HTTP method
            if method == "GET":
                response = requests.get(url, timeout=2, verify=False, headers=headers, allow_redirects=False)
            elif method == "HEAD":
                response = requests.head(url, timeout=2, verify=False, headers=headers, allow_redirects=False)
            elif method == "POST":
                response = requests.post(url, timeout=2, verify=False, headers=headers, allow_redirects=False)
            elif method == "PUT":
                response = requests.put(url, timeout=2, verify=False, headers=headers, allow_redirects=False)
            
            # PERMANENT REDIRECT FILTERING - ALWAYS ACTIVE
            if response.status_code == 302:
                location = response.headers.get("Location", "")
                location_lower = location.lower()
                if any(x in location_lower for x in ["jio.com", "airtel", "airtel.in", "captive", "portal", "login"]):
                    return False, "REDIRECT (Filtered)"
            
            if response.status_code in [301, 302, 303, 307, 308]:
                response_text = response.text.lower()
                if any(x in response_text for x in ["jio", "airtel", "reliance", "captive", "login", "wifi", "hotspot"]):
                    return False, "REDIRECT (Filtered)"
            
            return True, response.status_code
        except:
            return False, None
    
    def scan_port(port):
        # First check if port is open
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip_addr, port))
            sock.close()
            
            if result == 0:  # Port is open
                # For web ports, check if it's a valid web service (not redirect)
                if port in [80, 443, 8080, 8443, 8000, 3000, 5000]:
                    is_valid, status = check_web_service(port, ip_addr)
                    if is_valid:
                        service = "HTTP/HTTPS"
                        if status:
                            service += f" ({status})"
                        return port, True, service
                    else:
                        return port, False, "REDIRECT"
                else:
                    # For non-web ports, just return open
                    service = "Unknown"
                    if port == 21:
                        service = "FTP"
                    elif port == 22:
                        service = "SSH"
                    elif port == 23:
                        service = "Telnet"
                    elif port == 25:
                        service = "SMTP"
                    elif port == 53:
                        service = "DNS"
                    elif port == 110:
                        service = "POP3"
                    elif port == 143:
                        service = "IMAP"
                    elif port == 3306:
                        service = "MySQL"
                    elif port == 3389:
                        service = "RDP"
                    elif port == 5432:
                        service = "PostgreSQL"
                    elif port == 27017:
                        service = "MongoDB"
                    
                    return port, True, service
            else:
                return port, False, None
        except:
            return port, False, None
    
    open_ports = []
    filtered_redirects = []
    
    with Progress(
        SpinnerColumn(),
        TaskProgressColumn(),
        BarColumn(bar_width=40, complete_style="bold green"),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task_id = progress.add_task("[cyan]Scanning ports...", total=len(ports))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                port, is_open, service = future.result()
                if is_open and service != "REDIRECT":
                    table.add_row(str(port), "[bold green]OPEN[/bold green]", service)
                    open_ports.append(port)
                elif is_open and service == "REDIRECT":
                    table.add_row(str(port), "[yellow]FILTERED[/yellow]", "Redirect (Jio/Airtel)")
                    filtered_redirects.append(port)
                else:
                    table.add_row(str(port), "[red]CLOSED[/red]", "-")
                
                progress.update(task_id, advance=1)
    
    console.print(table)
    
    if open_ports:
        console.print(f"\n[bold green]✓ Found {len(open_ports)} open ports: {sorted(open_ports)}[/bold green]")
    
    if filtered_redirects:
        console.print(f"\n[bold yellow]⚠ Filtered {len(filtered_redirects)} redirect ports: {sorted(filtered_redirects)}[/bold yellow]")
        console.print("[dim]These are likely Jio/Airtel captive portals[/dim]")
    
    if not open_ports and not filtered_redirects:
        console.print(f"\n[yellow]✗ No open ports found on {domain}[/yellow]")
    
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 6 SUBDOMAIN HUNT ============
def subdomain_hunt():
    banner()
    console.print("[bold yellow]┌──────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│    SUBDOMAIN ENUMERATOR      │[/bold yellow]")
    console.print("[bold yellow]└──────────────────────────────┘[/bold yellow]\n")
    
    domain = input("[bold cyan]Enter domain (example.com): ").strip()
    wordlist_file = input("[bold cyan]Wordlist file (press Enter for default): ").strip()
    
    common_subs = [
        "www", "mail", "ftp", "admin", "api", "blog", "cdn", "dev", 
        "test", "staging", "portal", "webmail", "cpanel", "webdisk",
        "ns1", "ns2", "mx", "pop", "imap", "smtp", "secure", "vpn",
        "mobile", "m", "shop", "store", "support", "help", "docs",
        "status", "monitor", "dashboard", "app", "apps", "beta",
        "alpha", "demo", "staging", "prod", "production", "backup"
    ]
    
    if wordlist_file and os.path.exists(wordlist_file):
        with open(wordlist_file, 'r') as f:
            subs = [line.strip() for line in f if line.strip()]
    else:
        subs = common_subs
    
    outdir_name = input("[bold cyan]Output folder name: ").strip() or "Subdomain_Hunter"
    outdir = make_out(outdir_name)
    
    try:
        threads = int(input("[bold cyan]Threads (default: 50): ").strip() or 50)
    except:
        threads = 50
    
    results_file = os.path.join(outdir, f"subdomains_{domain}.txt")
    
    console.print(f"\n[bold green]Checking {len(subs)} subdomains for {domain}...[/bold green]")
    console.print(f"[bold green]Output Directory: {outdir}[/bold green]\n")
    
    found_subs = []
    
    def check_subdomain(sub):
        full_domain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full_domain)
            return full_domain
        except:
            return None
    
    with Progress(
        SpinnerColumn(),
        TaskProgressColumn(),
        BarColumn(bar_width=40, complete_style="bold green"),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task_id = progress.add_task("[cyan]Checking subdomains...", total=len(subs))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in subs}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    console.print(f"[green]✓ Found: {result}[/green]")
                    found_subs.append(result)
                progress.update(task_id, advance=1)
    
    # Save results
    with open(results_file, 'w') as f:
        for sub in found_subs:
            try:
                ip = socket.gethostbyname(sub)
                f.write(f"{sub} - {ip}\n")
            except:
                f.write(f"{sub}\n")
    
    console.print(f"\n[bold green]✓ Found {len(found_subs)} subdomains[/bold green]")
    console.print(f"[bold green]Results saved to: {results_file}[/bold green]")
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 7 SPLIT TXT ============
def split_txt():
    banner()
    console.print("[bold yellow]┌──────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│       FILE SPLITTER          │[/bold yellow]")
    console.print("[bold yellow]└──────────────────────────────┘[/bold yellow]\n")
    
    infile = input("[bold cyan]Enter file to split: ").strip()
    if not os.path.exists(infile):
        console.print("[bold red]File not found![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    lines_per_file = int(input("[bold cyan]Lines per file (default: 1000): ").strip() or 1000)
    outdir_name = input("[bold cyan]Output folder name: ").strip() or "File_Splitter"
    outdir = make_out(outdir_name)
    
    try:
        with open(infile, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except:
        console.print("[bold red]Error reading file![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    total_lines = len(lines)
    num_files = (total_lines + lines_per_file - 1) // lines_per_file
    
    console.print(f"\n[bold green]Splitting {total_lines} lines into {num_files} files...[/bold green]")
    console.print(f"[bold green]Output Directory: {outdir}[/bold green]\n")
    
    for i in range(num_files):
        start = i * lines_per_file
        end = start + lines_per_file
        chunk = lines[start:end]
        
        filename = os.path.join(outdir, f"split_part_{i+1}.txt")
        with open(filename, 'w', encoding='utf-8') as f:
            f.writelines(chunk)
        
        console.print(f"[cyan]Created: {filename} ({len(chunk)} lines)[/cyan]")
    
    console.print(f"\n[bold green]Successfully split into {num_files} files in '{outdir}'[/bold green]")
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 8 CIDR TO DOMAIN ============
def cidr_to_domain():
    banner()
    console.print("[bold yellow]┌──────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│   CIDR TO DOMAIN RESOLVER    │[/bold yellow]")
    console.print("[bold yellow]└──────────────────────────────┘[/bold yellow]\n")
    
    cidr_input = input("[bold cyan]Enter CIDR (e.g., 192.168.1.0/24): ").strip()
    try:
        cidr = ipaddress.ip_network(cidr_input, strict=False)
    except:
        console.print("[bold red]Invalid CIDR notation![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    outdir_name = input("[bold cyan]Output folder name: ").strip() or "CIDR_To_Domain"
    outdir = make_out(outdir_name)
    
    try:
        threads = int(input("[bold cyan]Threads (default: 100): ").strip() or 100)
    except:
        threads = 100
    
    hosts = list(cidr.hosts())
    results_file = os.path.join(outdir, f"reverse_lookup_{cidr_input.replace('/', '_')}.txt")
    
    console.print(f"\n[bold green]Performing reverse DNS lookup on {len(hosts)} IPs...[/bold green]")
    console.print(f"[bold green]Output Directory: {outdir}[/bold green]\n")
    
    def reverse_lookup(ip, progress, task_id):
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
            result = f"{ip} -> {hostname}"
            with lock:
                console.print(f"[green]{result}[/green]")
                with open(results_file, 'a') as f:
                    f.write(result + "\n")
        except:
            pass
        finally:
            progress.update(task_id, advance=1)
    
    with Progress(
        SpinnerColumn(),
        TaskProgressColumn(),
        BarColumn(bar_width=40, complete_style="bold green"),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task_id = progress.add_task("[cyan]Resolving...", total=len(hosts))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for ip in hosts:
                futures.append(executor.submit(reverse_lookup, ip, progress, task_id))
            
            concurrent.futures.wait(futures)
    
    console.print(f"\n[bold green]Results saved to: {results_file}[/bold green]")
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 9 REMOVE DUPLICATES ============
def remove_domain():
    banner()
    console.print("[bold yellow]┌──────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│  REMOVE DUPLICATE DOMAINS    │[/bold yellow]")
    console.print("[bold yellow]└──────────────────────────────┘[/bold yellow]\n")
    
    infile = input("[bold cyan]Enter domain list file: ").strip()
    if not os.path.exists(infile):
        console.print("[bold red]File not found![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    outdir_name = input("[bold cyan]Output folder name: ").strip() or "Remove_Duplicates"
    outdir = make_out(outdir_name)
    
    try:
        with open(infile, 'r', encoding='utf-8', errors='ignore') as f:
            domains = [line.strip().lower() for line in f if line.strip()]
    except:
        console.print("[bold red]Error reading file![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    original_count = len(domains)
    unique_domains = sorted(set(domains))
    new_count = len(unique_domains)
    
    output_file = os.path.join(outdir, "deduplicated_domains.txt")
    
    with open(output_file, 'w') as f:
        for domain in unique_domains:
            f.write(domain + "\n")
    
    console.print(f"\n[bold green]Original: {original_count} domains[/bold green]")
    console.print(f"[bold green]Unique: {new_count} domains[/bold green]")
    console.print(f"[bold green]Removed: {original_count - new_count} duplicates[/bold green]")
    console.print(f"[bold green]Output Directory: {outdir}[/bold green]")
    console.print(f"\n[bold green]Results saved to: {output_file}[/bold green]")
    
    if unique_domains:
        console.print(f"\n[bold white]Sample of cleaned domains:[/bold white]")
        for i, domain in enumerate(unique_domains[:10], 1):
            console.print(f"{i}. {domain}")
        if len(unique_domains) > 10:
            console.print(f"... and {len(unique_domains) - 10} more")
    
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 10 REVERSE IP ============
def reverse_ip():
    banner()
    console.print("[bold yellow]┌──────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│    REVERSE IP LOOKUP         │[/bold yellow]")
    console.print("[bold yellow]└──────────────────────────────┘[/bold yellow]\n")
    
    domain = input("[bold cyan]Enter domain: ").strip()
    
    try:
        ip = socket.gethostbyname(domain)
        console.print(f"\n[bold green]Domain: {domain}[/bold green]")
        console.print(f"[bold green]IP Address: {ip}[/bold green]")
        
        try:
            hostname, aliases, ips = socket.gethostbyaddr(ip)
            console.print(f"[bold green]Hostname: {hostname}[/bold green]")
            if aliases:
                console.print(f"[bold green]Aliases: {', '.join(aliases)}[/bold green]")
        except:
            pass
            
    except socket.gaierror:
        console.print(f"[bold red]Could not resolve domain: {domain}[/bold red]")
    
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 11 HOST INFO ============
def host_info():
    banner()
    console.print("[bold yellow]┌──────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│    HOST INFORMATION          │[/bold yellow]")
    console.print("[bold yellow]└──────────────────────────────┘[/bold yellow]\n")
    
    domain = input("[bold cyan]Enter domain/IP: ").strip()
    
    console.print("\n[bold white]Gathering information...[/bold white]\n")
    
    try:
        ip = socket.gethostbyname(domain)
        
        table = Table(title=f"Information for {domain}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Domain", domain)
        table.add_row("IP Address", ip)
        
        try:
            hostname, aliases, ips = socket.gethostbyaddr(ip)
            table.add_row("Reverse DNS", hostname)
            if aliases:
                table.add_row("DNS Aliases", ", ".join(aliases))
        except:
            table.add_row("Reverse DNS", "Not available")
        
        table.add_row("\n[bold]Port Scan[/bold]", "")
        
        common_ports = [
            (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"), 
            (53, "DNS"), (80, "HTTP"), (110, "POP3"), (143, "IMAP"), 
            (443, "HTTPS"), (465, "SMTPS"), (587, "SMTP"), (993, "IMAPS"),
            (995, "POP3S"), (3306, "MySQL"), (3389, "RDP")
        ]
        
        for port, service in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                status = "[bold green]OPEN[/bold green]" if result == 0 else "[dim]CLOSED[/dim]"
                table.add_row(f"{service} (Port {port})", status)
            except:
                table.add_row(f"{service} (Port {port})", "[red]ERROR[/red]")
        
        console.print(table)
        
    except socket.gaierror:
        console.print(f"[bold red]Could not resolve: {domain}[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
    
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 12 DEVELOPER INFO ============
def dev_info():
    banner()
    console.print(Panel.fit(
        "[bold cyan]DEVELOPER INFORMATION[/bold cyan]\n\n"
        "[bold]Name:[/bold] Mr Raj\n"
        "[bold]YouTube:[/bold] Mr Tech Hacker\n"
        "[bold]Tool:[/bold] Multi Advanced Tool v2.0\n"
        "[bold]Version:[/bold] 2.0\n"
        "[bold]Release Date:[/bold] 2025\n\n"
        "[yellow]This tool is povred by Mr raj (don't copy tool).[/yellow]\n"
        "[yellow]Use responsibly and only on systems you own.[/yellow]",
        border_style="green"
    ))
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 13 SCRIPT UPDATE ============
def update():
    banner()
    console.print(Panel.fit(
        "[bold cyan]UPDATE INFORMATION[/bold cyan]\n\n"
        "[green]✓ Current Version: 2.0[/green]\n"
        "[green]✓ All modules are working[/green]\n"
        "[green]✓ Latest updates applied[/green]\n\n"
        "[yellow]Check GitHub for future updates:[/yellow]\n"
        "[white]https://github.com/mrtechhacker[/white]",
        border_style="blue"
    ))
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ MAIN MENU ============
def main():
    while True:
        banner()
        console.print("[bold cyan]┌──────────────────────────────┐[/bold cyan]")
        console.print("[bold cyan]│         MAIN MENU            │[/bold cyan]")
        console.print("[bold cyan]└──────────────────────────────┘[/bold cyan]\n")
        
        console.print(f"[bold yellow]Output Directory:[/bold yellow] [bold green]{BASE_DIR}[/bold green]\n")
        
        menu_items = [
            ("1", "HOST SCANNER", "Scan domains on multiple ports"),
            ("2", "CIDR SCANNER", "Scan IP ranges for web servers"),
            ("3", "DOMAIN EXTRACTOR", "Extract domains from text/files"),
            ("4", "MULTI CIDR SCANNER", "Scan multiple CIDR ranges"),
            ("5", "MULTI PORT SCANNER", "Scan multiple ports on a host"),
            ("6", "SUBDOMAIN HUNTER", "Find subdomains of a domain"),
            ("7", "FILE SPLITTER", "Split large text files"),
            ("8", "CIDR TO DOMAIN", "Reverse DNS lookup for IP ranges"),
            ("9", "REMOVE DUPLICATES", "Remove duplicate domains from list"),
            ("10", "REVERSE IP LOOKUP", "Get IP address of domain"),
            ("11", "HOST INFORMATION", "Get detailed host information"),
            ("12", "DEVELOPER INFO", "About the developer"),
            ("13", "CHECK UPDATE", "Check for updates"),
            ("14", "EXIT", "Exit the tool")
        ]
        
        for num, name, desc in menu_items:
            console.print(f"[bold yellow][{num}][/bold yellow] [bold white]{name:<20}[/bold white] [dim]{desc}[/dim]")
        
        console.print("\n[bold cyan]┌──────────────────────────────┐[/bold cyan]")
        choice = input("Choose option (1-14):").strip()
        console.print("[bold cyan]└──────────────────────────────┘[/bold cyan]")
        
        options = {
            "1": host_scanner,
            "2": cidr_scanner,
            "3": domain_extractor,
            "4": multi_cidr,
            "5": multi_port,
            "6": subdomain_hunt,
            "7": split_txt,
            "8": cidr_to_domain,
            "9": remove_domain,
            "10": reverse_ip,
            "11": host_info,
            "12": dev_info,
            "13": update
        }
        
        if choice == "14":
            banner()
            console.print(Panel.fit("[bold green]Thank you for using Mr Tech Hacker Tool![/bold green]\n[yellow]Goodbye![/yellow]", border_style="red"))
            break
        elif choice in options:
            try:
                options[choice]()
            except KeyboardInterrupt:
                console.print("\n[yellow]Operation cancelled by user[/yellow]")
                input("\nPress Enter to continue...")
            except Exception as e:
                console.print(f"\n[bold red]Error: {str(e)}[/bold red]")
                input("\nPress Enter to continue...")
        else:
            console.print("\n[bold red]Invalid option! Please choose 1-14[/bold red]")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Tool terminated by user[/yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Fatal error: {str(e)}[/bold red]")