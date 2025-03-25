# Network Analyzer and Packet Logger

**Author**: Nik Pevnev  
**Date**: 3/24/2025

## Description

This Python script captures and logs TCP and ICMP packet details. It uses Scapy for packet sniffing and Python's `socket` library for reverse DNS lookups to provide the hostname associated with an IP address. The logged data is saved in a CSV file and can optionally be printed to the terminal for real-time analysis.

The captured packet data can also be integrated into a **Security Information and Event Management (SIEM)** system for further analysis, monitoring, and detection of suspicious network activity.

### The following information is captured:
- **Timestamp**
- **Source IP** (with reverse DNS lookup for hostname)
- **Source Port**
- **Destination IP** (with reverse DNS lookup for hostname)
- **Destination Port**
- **Packet Size**
- **TCP Flags** (e.g., SYN, ACK)
- **Time To Live (TTL)**

### The script can either:
- Print details to the terminal without saving to a CSV file (`-v` option)
- Log packet details into a CSV file (`packet_log.csv`)

---

## Usage

### Command to run the script:

```bash
python3 nws.py
