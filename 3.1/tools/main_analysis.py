#!/usr/bin/env python3
"""
Lab 3.1: Master Packet Analysis Script
Run all analysis tasks in sequence
"""

import os
import sys
import subprocess
from pathlib import Path

def run_command(cmd, description):
    """
    Run a shell command and report status
    """
    print(f"\n{'='*100}")
    print(f"[*] {description}")
    print(f"{'='*100}")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=False)
        if result.returncode == 0:
            print(f"[+] {description} - COMPLETED")
            return True
        else:
            print(f"[!] {description} - FAILED (exit code: {result.returncode})")
            return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False


def check_requirements():
    """
    Check if required packages are installed
    """
    print("[*] Checking requirements...")
    
    try:
        import scapy
        print("[+] Scapy: OK")
    except ImportError:
        print("[!] Scapy not installed. Install with: pip install scapy")
        return False
    
    # Check for curl (optional)
    result = subprocess.run("curl --version", shell=True, capture_output=True)
    if result.returncode == 0:
        print("[+] curl: OK")
    else:
        print("[!] curl not available (optional, for capturing)")
    
    # tcpdump optional on Windows
    import platform
    if platform.system() != "Windows":
        result = subprocess.run("tcpdump --version", shell=True, capture_output=True)
        if result.returncode == 0:
            print("[+] tcpdump: OK")
        else:
            print("[*] tcpdump not installed (optional on Windows)")
    else:
        print("[+] Windows detected - using Python packet capture")
    
    return True


def main():
    """
    Main analysis pipeline
    """
    print("╔" + "="*98 + "╗")
    print("║" + " "*98 + "║")
    print("║" + "LAB 3.1: BASIC PACKET PARSER - COMPLETE ANALYSIS".center(98) + "║")
    print("║" + " "*98 + "║")
    print("╚" + "="*98 + "╝")
    
    # Check requirements
    if not check_requirements():
        print("\n[!] Please install required packages and try again")
        sys.exit(1)
    
    # Create output directory
    os.makedirs("pcap_files", exist_ok=True)
    
    # Menu
    print("\n" + "="*100)
    print("SELECT ANALYSIS MODE:")
    print("="*100)
    print("1. Run complete analysis (capture + all analysis)")
    print("2. Analyze existing PCAP file")
    print("3. Quick test (analyze provided sample)")
    print("4. Exit")
    
    choice = input("\nEnter choice (1-4): ").strip()
    
    if choice == "1":
        # Check if user has sudo privilege for packet capture
        result = subprocess.run("sudo -n true", shell=True, capture_output=True)
        if result.returncode != 0:
            print("[!] Root privileges required for packet capture. Please enter password:")
        
        # Run capture
        print("\n[*] This will capture packets while accessing websites...")
        print("[*] Make sure you're connected to the internet")
        run_command("bash capture.sh", "Packet Capture")
        
        pcap_file = "pcap_files/captured_packets.pcap"
        
    elif choice == "2":
        pcap_file = input("Enter path to PCAP file: ").strip()
        if not os.path.exists(pcap_file):
            print(f"[!] File not found: {pcap_file}")
            sys.exit(1)
    
    elif choice == "3":
        print("[*] Quick test mode - you can use any existing PCAP file")
        pcap_file = input("Enter path to PCAP file (or press Enter for default): ").strip()
        if not pcap_file:
            pcap_file = "pcap_files/captured_packets.pcap"
        
        if not os.path.exists(pcap_file):
            print(f"[!] Sample file not found. Please capture packets first.")
            sys.exit(1)
    
    elif choice == "4":
        print("[*] Exiting...")
        sys.exit(0)
    
    else:
        print("[!] Invalid choice")
        sys.exit(1)
    
    # Check if pcap file exists
    if not os.path.exists(pcap_file):
        print(f"\n[!] PCAP file not found: {pcap_file}")
        print("[*] Please capture packets first using option 1")
        sys.exit(1)
    
    print(f"\n[+] Using PCAP file: {pcap_file}")
    print(f"[+] File size: {os.path.getsize(pcap_file) / 1024:.2f} KB")
    
    # Run analysis tasks
    print("\n" + "="*100)
    print("ANALYSIS TASKS:")
    print("="*100)
    
    analyses = [
        (f"python3 udp_parser.py {pcap_file}", "UDP Packet Analysis"),
        (f"python3 http_extractor.py {pcap_file}", "HTTP Request/Response Extraction"),
        (f"python3 retransmission_detector.py {pcap_file}", "TCP Retransmission Detection"),
        (f"python3 packet_visualizer.py {pcap_file}", "Packet Flow Visualization"),
    ]
    
    results = {}
    for cmd, desc in analyses:
        results[desc] = run_command(cmd, desc)
    
    # Summary
    print("\n" + "="*100)
    print("ANALYSIS SUMMARY")
    print("="*100)
    
    for task, success in results.items():
        status = "[+] PASSED" if success else "[!] FAILED"
        print(f"{status}: {task}")
    
    # List generated files
    print("\n" + "="*100)
    print("GENERATED FILES:")
    print("="*100)
    
    output_files = [
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
            print(f"[+] {fname:<40} ({size} bytes)")
        else:
            print(f"[-] {fname:<40} (not generated)")
    
    print("\n[+] Analysis complete!")
    print("[*] View results in:")
    print("    - *.json files for structured data")
    print("    - sequence_diagram.txt for ASCII diagram")
    print("    - Console output above for detailed analysis")


if __name__ == "__main__":
    main()
