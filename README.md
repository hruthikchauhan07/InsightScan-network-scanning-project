# Insight Scan 🔍

**Insight Scan** is a powerful yet user-friendly Python network reconnaissance tool that automates real-time network mapping and service enumeration. It streamlines the network discovery process into four automated phases, producing detailed CSV reports for further analysis.

## Features

✨ **4-Phase Network Reconnaissance:**
1. **Host Discovery** - Ping sweep to identify live hosts
2. **Port Scanning** - Comprehensive port enumeration with aggressive timing
3. **Service Enumeration** - Service and version detection via Nmap
4. **Report Generation** - Timestamped CSV exports with detailed findings

🎯 **Key Capabilities:**
- Automatic host discovery using Nmap ping sweeps
- Service and version detection for open ports
- Support for single IPs and CIDR ranges
- Color-coded terminal output for better readability
- Structured data export (CSV format)
- Aggressive scanning profiles for speed

## Prerequisites

- **Nmap** (required) - Download from [nmap.org](https://nmap.org) or install via package manager
- **Python 3.8+**
- Administrative/sudo privileges (for network scanning)

### Install Nmap

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install nmap
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install nmap
```

**macOS:**
```bash
brew install nmap
```

**Windows:**
Download installer from [nmap.org](https://nmap.org/download.html)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/insight-scan.git
cd insight-scan
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic scan of a single host:
```bash
python insight_scan.py 192.168.1.1
```

Scan an entire subnet:
```bash
python insight_scan.py 192.168.1.0/24
```

Scan a range of IPs:
```bash
python insight_scan.py 192.168.1.1-50
```

## Output

The tool generates timestamped CSV reports containing:
- **IP Address** - Target host IP
- **Port** - Open port number
- **Protocol** - TCP/UDP
- **Service** - Service name detected by Nmap
- **Version** - Software version information
- **State** - Port state (open, closed, filtered)
- **Timestamp** - Scan completion time

Example report: `InsightScan_Report_20251226_225504.csv`

## Requirements

See [requirements.txt](requirements.txt) for all dependencies:
- `python-nmap>=0.6.4` - Python Nmap wrapper
- `pandas>=1.0` - Data manipulation and export
- `colorama>=0.4.0` - Cross-platform colored terminal text

## Security & Legal Notice

⚠️ **Important:** 
- Only scan networks you own or have explicit written permission to scan
- Unauthorized network scanning may violate local laws
- This tool is provided for educational and authorized security testing purposes only
- The authors assume no liability for misuse or damage caused by this tool

## Troubleshooting

**Error: "Nmap (python-nmap) not available"**
- Ensure Nmap is installed: `nmap -V`
- Reinstall python-nmap: `pip install --upgrade python-nmap`

**Permission Denied**
- Network scanning typically requires elevated privileges:
```bash
sudo python insight_scan.py 192.168.1.0/24
```

**No Hosts Found**
- Verify the target network is reachable
- Check firewall rules blocking ping packets
- Try with a specific IP first

## Architecture

```
Insight Scan Workflow:
├── Phase 1: Host Discovery (-sn ping sweep)
├── Phase 2: Port Scanning (-sV service detection)
├── Phase 3: Service Enumeration (version probing)
└── Phase 4: Report Generation (CSV export)
```

## Example Report Output

```
IP Address,Port,Protocol,Service,Version,State,Timestamp
192.168.31.1,53,tcp,domain,Cloudflare public DNS,open,2025-12-26 22:55:04
192.168.31.1,80,tcp,http,,open,2025-12-26 22:55:04
192.168.31.1,443,tcp,https,,open,2025-12-26 22:55:04
192.168.31.1,8080,tcp,http-proxy,JIDU6801/JUICEJFV-1.5.3,open,2025-12-26 22:55:04
```

## License

This project is provided as-is for educational and authorized use only.

## Author

Insight Scan - Network Reconnaissance Tool
~ Hruthik Chauhan

---

**Disclaimer:** This tool is for authorized security testing only. Unauthorized access to computer networks is illegal.
