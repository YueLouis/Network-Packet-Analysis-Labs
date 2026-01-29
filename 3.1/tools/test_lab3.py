#!/usr/bin/env python3
"""
Lab 3.1: Test Script
Chạy các phân tích một cách tự động
"""

import subprocess
import os
from pathlib import Path

def run_cmd(cmd, desc):
    """Run command and report"""
    print(f"\n{'='*80}")
    print(f"[*] {desc}")
    print(f"{'='*80}")
    result = subprocess.run(cmd, shell=True)
    return result.returncode == 0

# Tạo folder output
os.makedirs("pcap_files", exist_ok=True)

print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                    LAB 3.1: BASIC PACKET PARSER - TEST                     ║
║                                                                            ║
║ Tasks:                                                                     ║
║ 1. Capture packets từ mạng                                                ║
║ 2. Parse UDP packets                                                       ║
║ 3. Extract HTTP requests                                                   ║
║ 4. Detect TCP retransmissions                                              ║
║ 5. Visualize packet flow                                                   ║
╚════════════════════════════════════════════════════════════════════════════╝
""")

# Step 1: Capture
print("\n[*] Step 1: Capturing packets...")
print("[*] Note: This will capture network traffic for 20 seconds")
print("[*] Make sure you have internet connection\n")

python_exe = "C:\\Users\\phttr\\AppData\\Local\\Programs\\Python\\Python310\\python.exe"

run_cmd(f"{python_exe} capture_packets.py", "Capture Packets")

# Check if pcap file exists
pcap_file = "pcap_files/captured_packets.pcap"
if not os.path.exists(pcap_file):
    print(f"\n[!] Error: {pcap_file} not created!")
    exit(1)

size = os.path.getsize(pcap_file)
print(f"[+] PCAP file created: {pcap_file} ({size} bytes)")

if size < 100:
    print("[!] Warning: PCAP file is very small")

# Step 2-5: Analysis
analyses = [
    (f"{python_exe} udp_parser.py {pcap_file}", "UDP Packet Analysis"),
    (f"{python_exe} http_extractor.py {pcap_file}", "HTTP Request/Response Extraction"),
    (f"{python_exe} retransmission_detector.py {pcap_file}", "TCP Retransmission Detection"),
    (f"{python_exe} packet_visualizer.py {pcap_file}", "Packet Flow Visualization"),
]

results = {}
for cmd, desc in analyses:
    results[desc] = run_cmd(cmd, desc)

# Summary
print(f"\n{'='*80}")
print("SUMMARY")
print(f"{'='*80}\n")

for task, success in results.items():
    status = "[+]" if success else "[!]"
    print(f"{status} {task}")

# List output files
print(f"\n{'='*80}")
print("OUTPUT FILES")
print(f"{'='*80}\n")

output_files = [
    "pcap_files/captured_packets.pcap",
    "udp_analysis.json",
    "http_requests.json",
    "http_responses.json",
    "tcp_anomalies.json",
    "packet_flow_analysis.json",
    "sequence_diagram.txt",
]

for fname in output_files:
    if os.path.exists(fname):
        size = os.path.getsize(fname)
        print(f"[+] {fname:<40} ({size:>10} bytes)")
    else:
        print(f"[-] {fname:<40} (not found)")

print(f"\n[+] All done! Check JSON files and sequence_diagram.txt for results")
