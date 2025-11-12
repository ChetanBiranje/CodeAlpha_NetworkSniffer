# CodeAlpha_NetworkSniffer

Basic Network Sniffer (Task 1 for CodeAlpha internship)

## Files
- `main.py` : main sniffer script (Python + scapy)
- `requirements.txt` : Python dependencies
- `README.md` : this file

## Description
This project captures network packets using `scapy`, prints readable summaries (timestamp, src/dst IP, protocol, ports, truncated payload) and can save captures to a .pcap file for later analysis.

**Important:** Only use this on networks you own or have permission to test. Sniffing other people's networks may be illegal.

## Setup (Linux / macOS)
1. Create a virtualenv (recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
