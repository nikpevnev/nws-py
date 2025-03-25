##########################################################
# Nik Pevnev
# 3/24/2025
# ----------------
# Network analyzer and packet logger
# This script captures TCP, ICMP and logs the following information to a CSV file:
# - Timestamp
# - Source IP   (with reverse DNS lookup for hostname)
# - Source Port
# - Destination IP (with reverse DNS lookup for hostname)
# - Destination Port
# - Packet Size
# - TCP Flags
# - Time To Live (TTL)
#
# The script uses Scapy for packet sniffing and socket for reverse DNS lookups.
#
# Usage: python3 nws.py 
#
# Optional arguments:
# -v, --verbose: Print packet details to terminal without logging to CSV file  
#
# Example:
# python3 nws.py -v # Print packet details to terminal without logging to CSV file
#
# Dependencies:
# - Scapy: Packet manipulation library
# - Python 3.x  (Tested on Python 3.8)
#
# Tested on:
# - Linux (Ubuntu 20.04)
# - Windows 10
#
# Disclaimer:
# This script is for educational purposes only and should be used in a legal and ethical manner.
# The author is not responsible for any misuse or damage caused by this script.
# Use it at your own risk.
#
# GitHub:
#
#
# Credits:
# - Scapy: https://scapy.net/
# - Python: https://www.python.org/
# - Socket: https://docs.python.org/3/library/socket.html
#
# License:
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
##########################################################
# Note: This script requires root/administrator privileges to capture packets.
#       Run the script with sudo on Linux or as Administrator on Windows.
##########################################################

import csv
import argparse
from scapy.all import sniff, IP, TCP, ICMP
import socket
import time
from collections import defaultdict

# Setup argparse to handle command-line arguments
parser = argparse.ArgumentParser(description="Packet capture script with optional verbose logging.")
parser.add_argument('-v', '--verbose', action='store_true', help="Print to terminal without logging to file")
args = parser.parse_args()

# Set this variable based on the argument
save_to_csv = not args.verbose  # If -v is provided, don't save to CSV, else save to CSV

# Open the CSV file for writing if logging is enabled
csvfile = None
writer = None
if save_to_csv:
    csvfile = open('packet_log.csv', 'w', newline='')
    # Define the column names (headers)
    fieldnames = ['Timestamp', 'Source IP', 'Source Hostname', 'Source Port', 'Destination IP', 'Destination Hostname', 'Destination Port', 'Packet Size', 'Flags', 'TTL', 'Protocol']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    # Write the header to the CSV file
    writer.writeheader()

# Create a dictionary to hold summary info for each source-destination pair
connection_summary = defaultdict(lambda: {'count': 0, 'total_size': 0})

# Callback function to process captured packets
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_size = len(packet)  # Get packet size
        ttl = packet[IP].ttl  # Get Time To Live (TTL)
        timestamp = packet.time  # Get timestamp of when the packet was captured

        # Determine the protocol
        protocol = None
        src_port = None
        dst_port = None
        flags = None
        
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags  # Get TCP flags (SYN, ACK, etc.)
            protocol = 'TCP'
        elif packet.haslayer(ICMP):
            protocol = 'ICMP'
        
        # Reverse DNS lookup for source IP
        try:
            src_hostname = socket.gethostbyaddr(ip_src)[0]
        except socket.herror:
            src_hostname = "Unknown Hostname"
        
        # Reverse DNS lookup for destination IP
        try:
            dst_hostname = socket.gethostbyaddr(ip_dst)[0]
        except socket.herror:
            dst_hostname = "Unknown Hostname"

        # Update the connection summary for this source-destination pair
        connection_key = (ip_src, ip_dst)
        connection_summary[connection_key]['count'] += 1
        connection_summary[connection_key]['total_size'] += packet_size

        # If verbose, print concise packet details
        if args.verbose:
            # Print packet info to terminal
            print(f"Timestamp: {timestamp}, Source: {ip_src} ({src_hostname}):{src_port} -> Destination: {ip_dst} ({dst_hostname}):{dst_port}")
            print(f"Packet Size: {packet_size} bytes, Flags: {flags}, TTL: {ttl}, Protocol: {protocol}")
            print("-" * 50)
        else:
            print(f"From: {ip_src} ({src_hostname}) -> To: {ip_dst} ({dst_hostname}), Size: {packet_size} bytes, Protocol: {protocol}")

        # Save to CSV if not in verbose mode
        if save_to_csv and not args.verbose:
            packet_info = {
                'Timestamp': timestamp,
                'Source IP': ip_src,
                'Source Hostname': src_hostname,
                'Source Port': src_port,
                'Destination IP': ip_dst,
                'Destination Hostname': dst_hostname,
                'Destination Port': dst_port,
                'Packet Size': packet_size,
                'Flags': flags,
                'TTL': ttl,
                'Protocol': protocol
            }
            writer.writerow(packet_info)

# Sniffing for TCP, ICMP, and major ports (FTP, HTTP, HTTPS, DNS)
sniff(prn=packet_callback, filter="tcp or icmp or port 21 or port 80 or port 443 or port 53", store=0)

# Note: The 'store=0' argument disables storing packets in memory, which is useful for long-term packet capturing.
#       If you want to store packets in memory, remove the 'store=0' argument.