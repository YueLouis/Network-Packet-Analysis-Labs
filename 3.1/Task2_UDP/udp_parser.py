#!/usr/bin/env python3
"""
Lab 3.1: UDP Packet Parser
Parse and analyze UDP packets
"""

from scapy.all import *
import json

def parse_udp_packet(packet):
    """
    Parse UDP packet and extract key information
    """
    if not packet.haslayer(UDP):
        return None
    
    udp = packet[UDP]
    ip = packet[IP]
    
    info = {
        'src_ip': ip.src,
        'dst_ip': ip.dst,
        'src_port': udp.sport,
        'dst_port': udp.dport,
        'length': udp.len,
        'checksum': udp.chksum,
        'payload_len': len(udp.payload),
        'timestamp': packet.time if hasattr(packet, 'time') else None,
    }
    
    # Try to identify common protocols
    if udp.dport == 53 or udp.sport == 53:
        info['protocol'] = 'DNS'
    elif udp.dport == 67 or udp.dport == 68:
        info['protocol'] = 'DHCP'
    elif udp.dport == 123 or udp.sport == 123:
        info['protocol'] = 'NTP'
    elif udp.dport == 5353 or udp.sport == 5353:
        info['protocol'] = 'mDNS'
    else:
        info['protocol'] = 'Unknown'
    
    return info


def track_udp_connections(packets):
    """
    Track UDP connections (flows)
    Note: UDP is stateless, so we group by src/dst pair
    """
    connections = {}
    
    for packet in packets:
        if not packet.haslayer(UDP):
            continue
        
        udp = packet[UDP]
        ip = packet[IP]
        
        # Connection key: (src_ip, src_port, dst_ip, dst_port)
        conn_key = (ip.src, udp.sport, ip.dst, udp.dport)
        
        if conn_key not in connections:
            connections[conn_key] = {
                'packets': [],
                'total_bytes': 0,
                'protocol': 'Unknown',
                'start_time': packet.time if hasattr(packet, 'time') else None,
                'end_time': packet.time if hasattr(packet, 'time') else None,
            }
        
        connections[conn_key]['packets'].append(packet)
        connections[conn_key]['total_bytes'] += len(udp.payload)
        connections[conn_key]['end_time'] = packet.time if hasattr(packet, 'time') else None
        
        # Identify protocol
        if udp.dport == 53 or udp.sport == 53:
            connections[conn_key]['protocol'] = 'DNS'
        elif udp.dport == 67 or udp.dport == 68:
            connections[conn_key]['protocol'] = 'DHCP'
        elif udp.dport == 123:
            connections[conn_key]['protocol'] = 'NTP'
    
    return connections


def print_udp_summary(connections):
    """
    Print summary of UDP connections
    """
    print("\n" + "="*80)
    print("UDP CONNECTION SUMMARY")
    print("="*80)
    
    for conn_key, info in sorted(connections.items()):
        src_ip, src_port, dst_ip, dst_port = conn_key
        
        print(f"\n{src_ip}:{src_port} → {dst_ip}:{dst_port}")
        print(f"  Protocol: {info['protocol']}")
        print(f"  Packets: {len(info['packets'])}")
        print(f"  Total bytes: {info['total_bytes']}")
        if info['start_time'] and info['end_time']:
            duration = info['end_time'] - info['start_time']
            print(f"  Duration: {duration:.3f}s")


def main():
    """
    Main function - analyze UDP packets from pcap file
    """
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 udp_parser.py <pcap_file>")
        print("Example: python3 udp_parser.py pcap_files/captured_packets.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    try:
        print(f"[*] Loading packets from: {pcap_file}")
        packets = rdpcap(pcap_file)
        print(f"[+] Loaded {len(packets)} packets")
    except Exception as e:
        print(f"[!] Error loading pcap file: {e}")
        return
    
    # Filter UDP packets
    udp_packets = [pkt for pkt in packets if pkt.haslayer(UDP)]
    print(f"[+] Found {len(udp_packets)} UDP packets")
    
    if len(udp_packets) == 0:
        print("[!] No UDP packets found in capture file")
        return
    
    # Parse individual packets
    print("\n" + "="*80)
    print("UDP PACKET DETAILS (First 10)")
    print("="*80)
    for i, packet in enumerate(udp_packets[:10]):
        info = parse_udp_packet(packet)
        if info:
            print(f"\nPacket {i+1}:")
            for key, value in info.items():
                print(f"  {key}: {value}")
    
    # Track connections
    connections = track_udp_connections(udp_packets)
    print_udp_summary(connections)
    
    # Save results to JSON
    output_file = "udp_analysis.json"
    try:
        json_data = {
            'total_packets': len(udp_packets),
            'connections': {}
        }
        
        for conn_key, info in connections.items():
            src_ip, src_port, dst_ip, dst_port = conn_key
            json_data['connections'][f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"] = {
                'protocol': info['protocol'],
                'packets': len(info['packets']),
                'total_bytes': info['total_bytes'],
            }
        
        with open(output_file, 'w') as f:
            json.dump(json_data, f, indent=2)
        print(f"\n[+] Results saved to: {output_file}")
    except Exception as e:
        print(f"[!] Error saving results: {e}")


if __name__ == "__main__":
    main()
