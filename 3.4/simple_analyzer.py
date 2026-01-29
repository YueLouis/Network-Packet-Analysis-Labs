"""
Lab 3.4: Real-time High-Performance Packet Analysis (Simple Version)
=====================================================================

Simplified version for Windows - single-threaded but still fast!

Author: Network Programming Lab
Date: January 2026
"""

from scapy.all import *
import time
import json
import random
from collections import defaultdict

class SimpleAnalyzer:
    """Fast single-threaded packet analyzer"""
    
    def __init__(self):
        """Initialize analyzer"""
        self.stats = {
            'packets_processed': 0,
            'bytes_processed': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'other_packets': 0,
            'start_time': time.time()
        }
        self.protocol_counts = defaultdict(int)
        self.results = []
    
    def analyze_packet(self, packet):
        """
        Fast packet analysis
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict with analysis results
        """
        analysis = {
            'timestamp': packet.time if hasattr(packet, 'time') else time.time(),
            'size': len(packet)
        }
        
        # Quick protocol detection
        if packet.haslayer(TCP):
            analysis['protocol'] = 'TCP'
            analysis['sport'] = packet[TCP].sport
            analysis['dport'] = packet[TCP].dport
            analysis['flags'] = str(packet[TCP].flags)
            
            # Detect common protocols by port
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                analysis['application'] = 'HTTP'
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                analysis['application'] = 'HTTPS'
            elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                analysis['application'] = 'SSH'
            
        elif packet.haslayer(UDP):
            analysis['protocol'] = 'UDP'
            analysis['sport'] = packet[UDP].sport
            analysis['dport'] = packet[UDP].dport
            
            # Detect common protocols by port
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                analysis['application'] = 'DNS'
            elif packet[UDP].dport == 67 or packet[UDP].sport == 67:
                analysis['application'] = 'DHCP'
        else:
            analysis['protocol'] = 'OTHER'
        
        # Extract IP info if available
        if packet.haslayer(IP):
            analysis['src_ip'] = packet[IP].src
            analysis['dst_ip'] = packet[IP].dst
        
        return analysis
    
    def process_packet(self, packet):
        """Process a single packet"""
        # Analyze
        result = self.analyze_packet(packet)
        self.results.append(result)
        
        # Update statistics
        self.stats['packets_processed'] += 1
        self.stats['bytes_processed'] += len(packet)
        
        protocol = result.get('protocol', 'OTHER')
        if protocol == 'TCP':
            self.stats['tcp_packets'] += 1
        elif protocol == 'UDP':
            self.stats['udp_packets'] += 1
        else:
            self.stats['other_packets'] += 1
        
        self.protocol_counts[protocol] += 1
    
    def get_stats(self):
        """Get processing statistics"""
        duration = time.time() - self.stats['start_time']
        pps = self.stats['packets_processed'] / duration if duration > 0 else 0
        mbps = (self.stats['bytes_processed'] * 8 / 1_000_000) / duration if duration > 0 else 0
        
        return {
            'packets_processed': self.stats['packets_processed'],
            'bytes_processed': self.stats['bytes_processed'],
            'tcp_packets': self.stats['tcp_packets'],
            'udp_packets': self.stats['udp_packets'],
            'other_packets': self.stats['other_packets'],
            'duration_seconds': duration,
            'packets_per_second': pps,
            'megabits_per_second': mbps,
            'protocol_distribution': dict(self.protocol_counts)
        }
    
    def print_stats(self):
        """Print statistics"""
        stats = self.get_stats()
        
        print("\n" + "=" * 60)
        print("Performance Statistics")
        print("=" * 60)
        print(f"Duration:           {stats['duration_seconds']:.2f} seconds")
        print(f"Packets processed:  {stats['packets_processed']:,}")
        print(f"Bytes processed:    {stats['bytes_processed']:,} bytes")
        print(f"Throughput:         {stats['packets_per_second']:.2f} packets/sec")
        print(f"Bandwidth:          {stats['megabits_per_second']:.2f} Mbps")
        print()
        print("Protocol Distribution:")
        print(f"  TCP:    {stats['tcp_packets']:,}")
        print(f"  UDP:    {stats['udp_packets']:,}")
        print(f"  Other:  {stats['other_packets']:,}")
        print()
        
        if stats['protocol_distribution']:
            print("Detailed Protocol Counts:")
            for proto, count in sorted(stats['protocol_distribution'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {proto:10s}: {count:,}")
        
        print("=" * 60)
    
    def save_stats(self, filepath='stats.json'):
        """Save statistics to JSON"""
        stats = self.get_stats()
        with open(filepath, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f"[✓] Statistics saved to {filepath}")


def pcap_file_demo(pcap_file):
    """Demo: Analyze PCAP file"""
    print("=" * 60)
    print("Lab 3.4: PCAP File Analysis (Simple Version)")
    print("=" * 60)
    print()
    
    # Create analyzer
    analyzer = SimpleAnalyzer()
    
    # Read PCAP
    print(f"[*] Reading PCAP file: {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"[*] Loaded {len(packets)} packets")
    print()
    
    # Process packets
    print("[*] Processing packets...")
    for pkt in packets:
        analyzer.process_packet(pkt)
    
    # Print stats
    analyzer.print_stats()
    
    # Save stats
    analyzer.save_stats('performance_stats.json')
    
    # Show sample results
    print("\n[*] Sample Analysis Results (first 10):")
    for i, result in enumerate(analyzer.results[:10], 1):
        print(f"\nPacket {i}:")
        print(f"  Protocol: {result.get('protocol', 'UNKNOWN')}")
        if 'application' in result:
            print(f"  Application: {result['application']}")
        if 'src_ip' in result and 'dst_ip' in result:
            print(f"  Flow: {result['src_ip']}:{result.get('sport', '?')} → {result['dst_ip']}:{result.get('dport', '?')}")


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        # Analyze provided PCAP file
        pcap_file = sys.argv[1]
        pcap_file_demo(pcap_file)
    else:
        # Create demo PCAP
        print("[*] No PCAP file provided, creating demo data...")
        print()
        
        demo_packets = []
        for i in range(100):
            if i % 3 == 0:
                pkt = IP(dst="93.184.216.34")/TCP(sport=random.randint(50000, 60000), dport=80)/Raw(load=b'GET / HTTP/1.1\r\n')
            elif i % 3 == 1:
                pkt = IP(dst="192.168.1.100")/TCP(sport=random.randint(50000, 60000), dport=22)/Raw(load=b'SSH-2.0\r\n')
            else:
                pkt = IP(dst="8.8.8.8")/UDP(sport=random.randint(50000, 60000), dport=53)/Raw(load=b'\x00\x01')
            demo_packets.append(pkt)
        
        wrpcap('demo.pcap', demo_packets)
        print("[✓] Created demo.pcap with 100 packets")
        print()
        
        # Analyze it
        pcap_file_demo('demo.pcap')
