# NetScaler Citrix Bleed2 Scanner (CVE-2025-5777) 

A Python-based vulnerability scanner designed to detect Citrix NetScaler Bleed2 vulnerability by scanning HTTPS endpoints for specific response patterns.
[NetScaler Critical Security Updates](https://www.netscaler.com/blog/news/netscaler-critical-security-updates-for-cve-2025-6543-and-cve-2025-5777/)

The Cybersecurity and Infrastructure Security Agency (CISA) has just added this CVE to its KEV list (Known Exploited Vulnerabilities Catalog) under [Citrix NetScaler ADC and Gateway Out-of-Bounds Read Vulnerability](https://www.cve.org/CVERecord?id=CVE-2025-5777)

## Description

This tool performs targeted HTTPS POST requests to detect the Citrix NetScaler Bleed2 vulnerability by analyzing server responses for the pattern `<InitialValue>.*</InitialValue>`. The scanner supports both single target and CIDR range scanning with multi-threading capabilities.

## Features

- **HTTPS Only Scanning**: Targets port 443.
- **Pattern Detection**: Identifies vulnerable targets using specific XML response patterns
- **Multi-threading**: Concurrent scanning for improved performance
- **Dual Logging**: Separate logs for vulnerable targets and all responses
- **CIDR Support**: Scan entire network ranges using CIDR notation
- **Progress Tracking**: Real-time scanning progress and statistics

## Installation

```bash
git clone https://github.com/abraham-surf/citrix-bleed2-scanner.git
cd citrix-bleed2-scanner
pip install requests
```

## Usage

### Single Target Scan
```bash
python bleed2.py example.com
```

### IP Address Scan
```bash
python bleed2.py 192.168.1.100
```

### CIDR Range Scan
```bash
python bleed22.py 192.168.1.0/24
```

### Interactive Mode
```bash
python bleed2.py
# Enter target when prompted
```

## Output Files

- **result.txt**: Contains only vulnerable targets with detailed information
- **http.txt**: Contains all HTTPS responses for comprehensive analysis

## Sample Output

```
=========================================================
=======Citrix Bleed2 Scanner by Abraham-Surf=========
=========================================================

Scanning 254 targets on HTTPS (port 443)...
Pattern filter: <InitialValue>.*</InitialValue>
Vulnerable targets -> result.txt
All HTTPS responses -> http.txt
==================================================

Scanning 192.168.1.1... HTTPS:✓ - Not Vulnerable
Scanning 192.168.1.2... HTTPS:✓ - VULNERABLE!
*** LOGGED: 192.168.1.2 - Pattern found! ***
```

## Legal Disclaimer

This tool is intended for authorized security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. The author is not responsible for any misuse of this tool and you may use this tool at your own risk!

## Requirements

- Python 3.6+
- requests library
- urllib3 library (for SSL warning suppression)

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

MIT License - See LICENSE file for details
