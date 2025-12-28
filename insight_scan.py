#!/usr/bin/env python3
import nmap
import argparse
import pandas as pd
from datetime import datetime
from colorama import init, Fore

# Initialize colorama for colored terminal output
init(autoreset=True)


class InsightScan:
    def __init__(self):
        # Initialize the Nmap PortScanner object
        try:
            self.scanner = nmap.PortScanner()
        except nmap.PortScannerError:
            print(f"{Fore.RED}[!] Nmap (python-nmap) not available. Install Nmap and python-nmap.")
            exit(1)

    def print_banner(self):
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}    INSIGHT SCAN: Real-Time Network Mapping & Enumeration")
        print(f"{Fore.CYAN}{'='*60}")
        # Project synopsis placeholder (refer to the system model)

    def host_discovery(self, target):
        """
        PHASE 1: HOST DISCOVERY (Ping Sweep)
        Uses Nmap '-sn' to detect live hosts in the target range.
        """
        print(f"\n{Fore.YELLOW}[*] Phase 1: Initiating Host Discovery (Ping Sweep) on {target}...")
        try:
            self.scanner.scan(hosts=target, arguments='-sn')

            # Extract hosts that are 'up'
            hosts_list = []
            for h in self.scanner.all_hosts():
                status = self.scanner[h].get('status', {}).get('state', 'unknown')
                hosts_list.append((h, status))

            live_hosts = [h for h, s in hosts_list if s == 'up']

            print(f"{Fore.GREEN}[+] Found {len(live_hosts)} live hosts.")
            for host in live_hosts:
                print(f"    - {host}")

            return live_hosts

        except Exception as e:
            print(f"{Fore.RED}[!] Error during host discovery: {e}")
            return []

    def port_scan_and_enum(self, live_hosts):
        """
        PHASE 2 & 3: PORT SCANNING & SERVICE ENUMERATION
        Uses Nmap '-sV' to probe services and versions.
        """
        scan_data = []

        print(f"\n{Fore.YELLOW}[*] Phase 2: Starting Port Scan & Service Enumeration...")

        if not live_hosts:
            print(f"{Fore.RED}[!] No live hosts to scan.")
            return []

        for host in live_hosts:
            print(f"    Scanning Host: {host}...")
            try:
                # -sV: service/version detection, -T5: very aggressive timing, --host-timeout: skip slow hosts
                self.scanner.scan(host, arguments='-sV -T5 --host-timeout 30s')

                if host not in self.scanner.all_hosts():
                    print(f"{Fore.RED}    [!] {host} returned no scan results.")
                    continue

                for proto in self.scanner[host].all_protocols():
                    ports = self.scanner[host][proto].keys()
                    for port in sorted(ports):
                        service_info = self.scanner[host][proto][port]

                        state = service_info.get('state', '')
                        name = service_info.get('name', '')
                        product = service_info.get('product', '')
                        version = service_info.get('version', '')
                        full_version = f"{product} {version}".strip()

                        if state == 'open':
                            print(f"{Fore.GREEN}        [+] {port}/{proto} - {name} ({full_version})")

                            scan_data.append({
                                'IP Address': host,
                                'Port': int(port),
                                'Protocol': proto,
                                'Service': name,
                                'Version': full_version,
                                'State': state,
                                'Timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            })

            except Exception as e:
                print(f"{Fore.RED}    [!] Error scanning {host}: {e}")

        return scan_data

    def generate_report(self, data):
        """
        PHASE 4: REPORT GENERATION
        Saves results to a timestamped CSV using pandas.
        """
        if not data:
            print(f"\n{Fore.RED}[!] No data collected. Report generation skipped.")
            return

        print(f"\n{Fore.YELLOW}[*] Phase 4: Generating Report...")

        df = pd.DataFrame(data)

        filename = f"InsightScan_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

        df.to_csv(filename, index=False)
        print(f"{Fore.GREEN}[SUCCESS] Report saved successfully: {filename}")
        print(f"{Fore.WHITE}Total Services Identified: {len(data)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Insight Scan: Network Mapping Tool")
    parser.add_argument("target", help="Target IP or Range (e.g., 192.168.1.1 or 192.168.1.0/24)")
    args = parser.parse_args()

    app = InsightScan()
    app.print_banner()

    # 1. Host Discovery (Sweep)
    active_hosts = app.host_discovery(args.target)

    # 2. Port Scan & Enumeration (if hosts are found)
    if active_hosts:
        results = app.port_scan_and_enum(active_hosts)

        # 3. Report Generation
        app.generate_report(results)
    else:
        print(f"{Fore.RED}[!] No hosts found. Exiting.")
