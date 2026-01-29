#!/usr/bin/env python3
"""
Lab 3.1: Packet Capture Script (Python version)
Alternative to bash script for cross-platform compatibility
"""

import subprocess
import time
import os
import sys
from pathlib import Path

def create_output_dir():
    """Create output directory"""
    os.makedirs("pcap_files", exist_ok=True)
    return "pcap_files/captured_packets.pcap"


def get_network_interface():
    """
    Detect network interface
    Returns first active non-loopback interface
    """
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        
        # Filter out loopback
        active_interfaces = [i for i in interfaces if i not in ['lo', 'lo0', 'Loopback']]
        
        if active_interfaces:
            return active_interfaces[0]
        return None
    except:
        return None


def capture_with_scapy(duration=30, count=None):
    """
    Capture packets using Scapy (pure Python, no tcpdump needed)
    """
    from scapy.all import sniff
    
    print(f"[*] Capturing packets for {duration} seconds using Scapy...")
    print("[*] Accessing websites in parallel...")
    
    # Start accessing websites in background
    import threading
    
    websites = [
        "http://google.com",
        "http://github.com",
        "http://wikipedia.org",
        "http://example.com",
    ]
    
    def access_website(url):
        try:
            subprocess.run(f"curl -m 5 {url} -o /dev/null", 
                          shell=True, capture_output=True)
        except:
            pass
    
    # Start threads to access websites
    threads = []
    for website in websites:
        t = threading.Thread(target=access_website, args=(website,))
        t.daemon = True
        t.start()
        threads.append(t)
        time.sleep(1)
    
    # Capture packets
    try:
        packets = sniff(timeout=duration, prn=lambda x: print(".", end="", flush=True))
    except Exception as e:
        print(f"[!] Capture error: {e}")
        return []
    
    # Wait for threads
    for t in threads:
        t.join(timeout=5)
    
    return packets


def capture_with_tcpdump(pcap_file, duration=30):
    """
    Capture packets using tcpdump (Linux/Mac)
    """
    import platform
    
    # Get network interface
    iface = get_network_interface()
    if not iface:
        print("[!] Could not detect network interface")
        return False
    
    print(f"[*] Using interface: {iface}")
    
    # Build tcpdump command
    if platform.system() == "Windows":
        # Windows: use -i Ethernet or similar
        cmd = f"tcpdump -i Ethernet -w {pcap_file} -c 1000 -G {duration}"
    else:
        # Linux/Mac: use sudo
        cmd = f"sudo tcpdump -i {iface} -w {pcap_file} -c 1000 -G {duration} 'tcp or udp'"
    
    print(f"[*] Command: {cmd}")
    print(f"[*] Accessing websites...")
    
    # Start tcpdump in background
    import threading
    
    def run_capture():
        try:
            subprocess.run(cmd, shell=True, timeout=duration + 5)
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            print(f"[!] Capture error: {e}")
    
    # Access websites while capturing
    websites = [
        "http://google.com",
        "http://github.com",
        "http://wikipedia.org",
        "http://example.com",
        "http://httpbin.org/get",
    ]
    
    def access_websites():
        for website in websites:
            try:
                print(f"[*] Accessing: {website}")
                subprocess.run(f"curl -m 5 {website} -o /dev/null", 
                             shell=True, capture_output=True)
            except:
                pass
            time.sleep(1)
    
    # Run capture and website access in parallel
    capture_thread = threading.Thread(target=run_capture)
    capture_thread.start()
    
    time.sleep(2)  # Let tcpdump start
    
    access_websites()
    
    capture_thread.join(timeout=duration + 10)
    
    # Check if file was created
    if os.path.exists(pcap_file):
        size = os.path.getsize(pcap_file)
        print(f"[+] PCAP file created: {pcap_file} ({size} bytes)")
        return True
    else:
        print("[!] PCAP file not created")
        return False


def capture_with_netsh(pcap_file):
    """
    Capture packets using netsh (Windows native, no dependencies)
    Requires elevated privileges (Run as Administrator)
    """
    print("[*] Using netsh trace for capture (Windows)...")
    print("[*] Note: Requires Administrator privilege")
    
    # Start trace
    trace_file = pcap_file.replace('.pcap', '.etl')
    
    cmd_start = f"netsh trace start capture=yes tracefile={trace_file}"
    
    print(f"[*] Starting: {cmd_start}")
    
    try:
        subprocess.run(cmd_start, shell=True, timeout=2)
    except:
        pass
    
    time.sleep(2)
    
    # Access websites
    websites = [
        "http://google.com",
        "http://github.com",
        "http://wikipedia.org",
    ]
    
    for website in websites:
        try:
            print(f"[*] Accessing: {website}")
            subprocess.run(f"curl -m 5 {website} -o nul", 
                          shell=True, capture_output=True)
        except:
            pass
        time.sleep(1)
    
    # Stop trace
    cmd_stop = "netsh trace stop"
    print(f"[*] Stopping trace...")
    
    try:
        subprocess.run(cmd_stop, shell=True, timeout=5)
    except:
        pass
    
    # Convert ETL to PCAP using tshark
    if os.path.exists(trace_file):
        print(f"[+] Trace file created: {trace_file}")
        print("[*] Note: ETL format, can be opened with Wireshark")
        return True
    
    return False


def main():
    """
    Main capture function with platform detection
    """
    import platform
    
    print("╔" + "="*98 + "╗")
    print("║" + " "*98 + "║")
    print("║" + "LAB 3.1: PACKET CAPTURE".center(98) + "║")
    print("║" + " "*98 + "║")
    print("╚" + "="*98 + "╝")
    
    # Create output directory
    pcap_file = create_output_dir()
    
    os_name = platform.system()
    print(f"\n[*] Detected OS: {os_name}")
    
    # Choose capture method
    if os_name == "Linux":
        print("[*] Using tcpdump (Linux)")
        success = capture_with_tcpdump(pcap_file, duration=30)
    
    elif os_name == "Darwin":  # macOS
        print("[*] Using tcpdump (macOS)")
        success = capture_with_tcpdump(pcap_file, duration=30)
    
    elif os_name == "Windows":
        print("[*] Available methods:")
        print("  1. Scapy (pure Python, cross-platform)")
        print("  2. netsh trace (native Windows, needs admin)")
        print("  3. WSL with tcpdump")
        
        choice = input("\nSelect method (1-3, default 1): ").strip() or "1"
        
        if choice == "1":
            from scapy.all import wrpcap
            packets = capture_with_scapy(duration=30)
            if packets:
                wrpcap(pcap_file, packets)
                print(f"[+] Saved {len(packets)} packets to: {pcap_file}")
                success = True
            else:
                success = False
        
        elif choice == "2":
            success = capture_with_netsh(pcap_file)
        
        elif choice == "3":
            print("[*] Using WSL/tcpdump...")
            success = capture_with_tcpdump(pcap_file, duration=30)
        
        else:
            print("[!] Invalid choice")
            sys.exit(1)
    
    else:
        print(f"[!] Unsupported OS: {os_name}")
        print("[*] Trying Scapy (pure Python)...")
        from scapy.all import wrpcap
        packets = capture_with_scapy(duration=30)
        if packets:
            wrpcap(pcap_file, packets)
            success = True
        else:
            success = False
    
    # Summary
    print("\n" + "="*100)
    if success and os.path.exists(pcap_file):
        size = os.path.getsize(pcap_file)
        print(f"[+] Capture successful!")
        print(f"[+] Output: {pcap_file}")
        print(f"[+] Size: {size} bytes")
        print("\n[*] Next: Run analysis scripts")
        print("    python3 udp_parser.py", pcap_file)
        print("    python3 http_extractor.py", pcap_file)
        print("    python3 retransmission_detector.py", pcap_file)
        print("    python3 packet_visualizer.py", pcap_file)
    else:
        print("[!] Capture failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
