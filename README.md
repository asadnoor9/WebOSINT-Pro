# WebOSINT Pro

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg">
  <img src="https://img.shields.io/badge/Platform-Linux-success.svg">
  <img src="https://img.shields.io/badge/License-MIT-red.svg">
  <img src="https://img.shields.io/badge/Status-Active-success.svg">
</p>

<p align="center">
  Advanced Web Application OSINT & Reconnaissance Framework for Bug Bounty Hunters, Penetration Testers, and Red Teamers.
</p>

---

# Overview

WebOSINT Pro is a modular reconnaissance and intelligence gathering framework designed for advanced web application analysis and security research.

The framework combines passive and active reconnaissance techniques with integrations from popular security tools such as:

- Nmap
- WPScan
- Shodan
- TheHarvester
- Amass
- Subfinder
- WAFW00F
- Nuclei (optional)

It provides detailed analysis of:

- Web infrastructure
- DNS & domain intelligence
- SSL/TLS security
- WAF & IDS detection
- SIEM exposure
- API & JWT analysis
- WebSockets
- Database exposure
- Honeypot & decoy detection
- CVE/CWE mapping
- Public IP reputation
- Directory enumeration
- JavaScript endpoint discovery

---

# Features

## Core Reconnaissance

- Domain Intelligence
- WHOIS Information
- DNS Enumeration
- Subdomain Enumeration
- Reverse DNS (PTR)
- ASN & ISP Detection
- GeoIP Lookup

## Web Application Analysis

- HTTP Header Analysis
- Security Header Detection
- Web Technology Fingerprinting
- API Endpoint Detection
- JWT Analysis
- WebSocket Detection
- Directory & File Discovery
- Sensitive File Detection
- JavaScript Recon

## Security Detection

- WAF Detection
- Firewall Detection
- IDS/IPS Inference
- Honeypot Detection
- Decoy Service Detection
- SIEM Exposure Checks
- SSL/TLS Weakness Detection

## Vulnerability Intelligence

- CVE Mapping
- CWE Mapping
- Service Version Analysis
- Public IP Reputation Checks
- Blacklist Detection

## Integrations

- Nmap
- WPScan
- Shodan
- TheHarvester
- Amass
- Subfinder
- WAFW00F
- Nuclei

## Reporting

- JSON Reports
- HTML Reports
- Scan Logs
- Historical Scan Retention

---

# Project Structure

```bash
webosint-pro/
│
├── core/
├── integrations/
├── modules/
├── reports/
├── utils/
├── logs/
├── wordlists/
│
├── config.json
├── install.sh
├── requirements.txt
├── webosint.py
└── README.md
```

---

# Installation

## Clone Repository

```bash
git clone https://github.com/asadnoor9/webosint-pro.git
cd webosint-pro
```

---

# Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

---

# Install Python Dependencies

```bash
pip install -r requirements.txt
```

---

# Install External Tools

```bash
chmod +x install.sh
./install.sh
```

---

# Required External Tools

The framework supports integration with:

| Tool | Purpose |
|------|----------|
| Nmap | Port scanning & service detection |
| WPScan | WordPress enumeration |
| WAFW00F | WAF detection |
| Amass | Subdomain enumeration |
| Subfinder | Passive subdomain enumeration |
| TheHarvester | OSINT collection |
| Nuclei | Vulnerability scanning |
| Shodan API | Internet-wide intelligence |

---

# Usage

## Basic Scan

```bash
python3 webosint.py -t example.com
```

---

## Full Scan

```bash
python3 webosint.py -t example.com --full
```

---

## Specific Modules

```bash
python3 webosint.py -t example.com --modules dns,ssl,waf
```

---

## Aggressive Mode

```bash
python3 webosint.py -t example.com --mode aggressive
```

---

## Stealth Mode

```bash
python3 webosint.py -t example.com --mode stealth
```

---

## Verbose Levels

```bash
-v      Basic verbosity
-vv     Advanced verbosity
-vvv    Debug verbosity
```

Example:

```bash
python3 webosint.py -t example.com --full -vvv
```

---

# Scan Modes

| Mode | Description |
|------|-------------|
| Safe | Passive & low-noise scanning |
| Medium | Balanced scanning |
| Aggressive | Deep enumeration & fingerprinting |
| Stealth | Slow randomized requests |

---

# Modules

| Module | Description |
|--------|-------------|
| ip | IP intelligence |
| whois | WHOIS information |
| dns | DNS enumeration |
| ssl | SSL/TLS analysis |
| subdomains | Subdomain enumeration |
| ports | Port scanning |
| waf | Firewall/WAF detection |
| ids | IDS/IPS detection |
| siem | SIEM exposure checks |
| honeypot | Honeypot detection |
| database | Database exposure |
| api | API & JWT analysis |
| websocket | WebSocket detection |
| javascript | JS endpoint extraction |
| webapp | Web application structure |
| cve | CVE/CWE mapping |

---

# Reporting

Reports are automatically saved in:

```bash
reports/
```

Formats:

- JSON
- HTML

Logs are stored in:

```bash
logs/
```

---

# Example Output

```bash
[+] Target Resolved: 104.21.x.x
[+] WAF Detected: Cloudflare
[+] SSL Grade: TLS 1.3
[+] API Endpoint Found: /api/v1/login
[+] JWT Token Detected
[+] Open Port: 443/tcp
[+] SIEM Interface Exposed: Kibana
```

---

# Screenshots

Future versions will include:

- Dashboard UI
- Live monitoring
- Visual recon maps
- Screenshot engine

---

# Roadmap

## Upcoming Features

- AI-based finding prioritization
- Telegram/Slack notifications
- Distributed scanning
- Docker support
- Dashboard frontend
- Elasticsearch integration
- Automated bug bounty reporting

---

# Security & Ethics

This tool is intended for:

- Authorized penetration testing
- Security research
- Bug bounty programs
- Educational purposes

Do NOT use against systems without explicit authorization.

The author is not responsible for misuse.

---

# Contributing

Pull requests and improvements are welcome.

## Steps

1. Fork repository
2. Create feature branch
3. Commit changes
4. Push branch
5. Create pull request

---

# License

MIT License

---

# Author

## Asad Noor

- Assistant Manager – Data Center
- Cybersecurity Enthusiast
- Network & System Administrator

LinkedIn:
https://www.linkedin.com/in/asadnoor951

---

# Disclaimer

This framework is provided for educational and authorized security testing purposes only.

Unauthorized usage against third-party systems may violate laws and regulations.

Use responsibly.