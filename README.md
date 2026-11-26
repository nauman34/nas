# Python Nmap Network Scanner

A small Flask + Bootstrap interface for Nmap-based network discovery and authorized host assessment.

## Features

- LAN discovery with Nmap ping scan (`-sn`).
- Single-host scan of the top 1,000 TCP ports with service/version detection (`-sV`).
- Parses Nmap XML output and displays live hosts, open ports, and detected services.
- CIDR size guard: network discovery is limited to 256 addresses.
- No shell invocation; targets are validated as IP addresses or CIDR networks.

## Requirements

- Python 3.10+
- Nmap installed on the scanning machine and available in PATH.
- Administrator/root privileges may be needed for some Nmap discovery techniques.

## Install

### Windows

1. Install Nmap from https://nmap.org/download.html.
2. Open PowerShell in this project directory.
3. Create and activate a virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000.

### Kali Linux / Debian / Ubuntu

```bash
sudo apt update
sudo apt install nmap python3-venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000.

## Scan modes

- **LAN host discovery:** example `192.168.1.0/24`. Discovers hosts only; it does not enumerate ports.
- **Single host scan:** example `192.168.1.10`. Checks the top 1,000 TCP ports and attempts service/version detection.

## Safety

Use this tool only on networks and devices you own or are explicitly authorized to assess. Start with a small scope. Service detection sends probes to target services and may be logged or trigger security controls. This project is intended for local administrative use, not public unauthenticated deployment.

Before deployment beyond localhost, configure a strong secret key, authentication, CSRF protection, access controls, HTTPS, and rate limiting. The development server is intentionally bound to 127.0.0.1.
