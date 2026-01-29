#!/usr/bin/env python3
"""
Lab 3.1: Packet Flow Visualization
Create sequence diagrams and flow analysis
"""

from scapy.all import *
import json

def generate_sequence_diagram(packets, output_file="sequence_diagram.txt"):
    """
    Generate ASCII sequence diagram of TCP handshakes and flows
    """
    connections = {}
    
    for packet in packets:
        if not packet.haslayer(TCP):
            continue
        
        tcp = packet[TCP]
        ip = packet[IP]
        
        # Connection key
        conn_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        
        if conn_key not in connections:
            connections[conn_key] = []
        
        # Record packet info
        connections[conn_key].append({
            'time': packet.time if hasattr(packet, 'time') else 0,
            'flags': tcp.flags,
            'seq': tcp.seq,
            'ack': tcp.ack,
            'len': len(tcp.payload),
            'sport': tcp.sport,
            'dport': tcp.dport,
            'src_ip': ip.src,
            'dst_ip': ip.dst,
        })
    
    # Generate diagrams
    output = []
    output.append("="*120)
    output.append("TCP PACKET FLOW SEQUENCE DIAGRAM")
    output.append("="*120)
    
    for conn_key, pkts in sorted(connections.items()):
        src_ip, src_port, dst_ip, dst_port = conn_key
        
        output.append(f"\n\nConnection: {src_ip}:{src_port} <-> {dst_ip}:{dst_port}")
        output.append("-" * 120)
        
        # Create simplified diagram
        src_name = f"{src_ip.split('.')[-1]}:{src_port}"
        dst_name = f"{dst_ip.split('.')[-1]}:{dst_port}"
        
        src_width = len(src_name)
        dst_width = len(dst_name)
        
        # Header
        output.append(f"{src_name:<20} {' '*60} {dst_name:<20}")
        output.append(f"{'|':<20} {' '*60} {'|':<20}")
        
        # Packets
        for i, pkt in enumerate(sorted(pkts, key=lambda x: x['time'])[:30]):  # Max 30 packets per diagram
            flags_str = format_flags(pkt['flags'])
            
            if pkt['src_ip'] == src_ip:
                # Packet going right (src -> dst)
                arrow = "--->"
                msg = f"SEQ:{pkt['seq']} ACK:{pkt['ack']} {flags_str}"
            else:
                # Packet going left (dst -> src)
                arrow = "<---"
                msg = f"SEQ:{pkt['seq']} ACK:{pkt['ack']} {flags_str}"
            
            line = f"{'|':<20} {arrow:>30} {msg:<30} {arrow:<30}"
            output.append(line)
        
        output.append(f"{'|':<20} {' '*60} {'|':<20}")
        output.append(f"\nTotal packets: {len(pkts)}")
    
    # Write to file
    with open(output_file, 'w') as f:
        f.write('\n'.join(output))
    
    return '\n'.join(output)


def format_flags(flags):
    """
    Format TCP flags as string
    """
    flag_str = ""
    if flags & 0x01:  # FIN
        flag_str += "F"
    if flags & 0x02:  # SYN
        flag_str += "S"
    if flags & 0x04:  # RST
        flag_str += "R"
    if flags & 0x08:  # PSH
        flag_str += "P"
    if flags & 0x10:  # ACK
        flag_str += "A"
    if flags & 0x20:  # URG
        flag_str += "U"
    
    return f"[{flag_str}]"


def analyze_packet_timeline(packets):
    """
    Analyze packet timing and create timeline
    """
    if not packets:
        return None
    
    timeline = []
    start_time = packets[0].time if hasattr(packets[0], 'time') else 0
    
    for packet in packets:
        if not packet.haslayer(IP):
            continue
        
        current_time = packet.time if hasattr(packet, 'time') else 0
        relative_time = current_time - start_time
        
        ip = packet[IP]
        protocol = "TCP" if packet.haslayer(TCP) else \
                   "UDP" if packet.haslayer(UDP) else \
                   "Other"
        
        size = len(packet)
        
        timeline.append({
            'relative_time': relative_time,
            'absolute_time': current_time,
            'protocol': protocol,
            'src': ip.src,
            'dst': ip.dst,
            'size': size,
        })
    
    return timeline


def print_timeline(timeline):
    """
    Print packet timeline
    """
    print("\n" + "="*100)
    print("PACKET TIMELINE")
    print("="*100)
    
    print(f"\n{'Time (s)':>12} {'Protocol':>8} {'Source':>15} → {'Destination':>15} {'Size':>8}")
    print("-" * 100)
    
    for pkt in timeline[:50]:  # Show first 50
        print(f"{pkt['relative_time']:>12.6f} {pkt['protocol']:>8} {pkt['src']:>15} → {pkt['dst']:>15} {pkt['size']:>8}")


def analyze_traffic_volume(packets):
    """
    Analyze traffic volume by protocol and conversation
    """
    traffic = {
        'by_protocol': {},
        'by_source': {},
        'by_destination': {},
        'by_conversation': {}
    }
    
    for packet in packets:
        if not packet.haslayer(IP):
            continue
        
        ip = packet[IP]
        protocol = "TCP" if packet.haslayer(TCP) else \
                   "UDP" if packet.haslayer(UDP) else \
                   "Other"
        
        size = len(packet)
        
        # By protocol
        if protocol not in traffic['by_protocol']:
            traffic['by_protocol'][protocol] = {'count': 0, 'bytes': 0}
        traffic['by_protocol'][protocol]['count'] += 1
        traffic['by_protocol'][protocol]['bytes'] += size
        
        # By source
        if ip.src not in traffic['by_source']:
            traffic['by_source'][ip.src] = {'count': 0, 'bytes': 0}
        traffic['by_source'][ip.src]['count'] += 1
        traffic['by_source'][ip.src]['bytes'] += size
        
        # By destination
        if ip.dst not in traffic['by_destination']:
            traffic['by_destination'][ip.dst] = {'count': 0, 'bytes': 0}
        traffic['by_destination'][ip.dst]['count'] += 1
        traffic['by_destination'][ip.dst]['bytes'] += size
        
        # By conversation
        conv_key = f"{ip.src} <-> {ip.dst}"
        if conv_key not in traffic['by_conversation']:
            traffic['by_conversation'][conv_key] = {'count': 0, 'bytes': 0}
        traffic['by_conversation'][conv_key]['count'] += 1
        traffic['by_conversation'][conv_key]['bytes'] += size
    
    return traffic


def print_traffic_analysis(traffic):
    """
    Print traffic analysis
    """
    print("\n" + "="*100)
    print("TRAFFIC ANALYSIS")
    print("="*100)
    
    # By protocol
    print("\n[*] Traffic by Protocol:")
    print(f"{'Protocol':<15} {'Packets':>15} {'Bytes':>15} {'Avg Size':>15}")
    print("-" * 65)
    for proto, data in sorted(traffic['by_protocol'].items(), 
                              key=lambda x: x[1]['bytes'], reverse=True):
        avg_size = data['bytes'] / data['count'] if data['count'] > 0 else 0
        print(f"{proto:<15} {data['count']:>15} {data['bytes']:>15} {avg_size:>15.2f}")
    
    # By source
    print("\n[*] Top 10 Sources:")
    print(f"{'Source IP':<15} {'Packets':>15} {'Bytes':>15}")
    print("-" * 50)
    for src, data in sorted(traffic['by_source'].items(), 
                             key=lambda x: x[1]['bytes'], reverse=True)[:10]:
        print(f"{src:<15} {data['count']:>15} {data['bytes']:>15}")
    
    # By conversation
    print("\n[*] Top 10 Conversations:")
    print(f"{'Conversation':<30} {'Packets':>15} {'Bytes':>15}")
    print("-" * 65)
    for conv, data in sorted(traffic['by_conversation'].items(), 
                              key=lambda x: x[1]['bytes'], reverse=True)[:10]:
        print(f"{conv:<30} {data['count']:>15} {data['bytes']:>15}")


def main():
    """
    Main function - visualize packet flow
    """
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 packet_visualizer.py <pcap_file>")
        print("Example: python3 packet_visualizer.py pcap_files/captured_packets.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    try:
        print(f"[*] Loading packets from: {pcap_file}")
        packets = rdpcap(pcap_file)
        print(f"[+] Loaded {len(packets)} packets")
    except Exception as e:
        print(f"[!] Error loading pcap file: {e}")
        return
    
    # Generate sequence diagram
    print("\n[*] Generating sequence diagrams...")
    diagram = generate_sequence_diagram(packets)
    print(diagram)
    print(f"[+] Sequence diagram saved to: sequence_diagram.txt")
    
    # Analyze timeline
    print("\n[*] Analyzing packet timeline...")
    timeline = analyze_packet_timeline(packets)
    if timeline:
        print_timeline(timeline)
    
    # Traffic analysis
    print("\n[*] Analyzing traffic volume...")
    traffic = analyze_traffic_volume(packets)
    print_traffic_analysis(traffic)
    
    # Save to JSON
    json_data = {
        'total_packets': len(packets),
        'traffic_by_protocol': traffic['by_protocol'],
        'traffic_by_source': traffic['by_source'],
        'traffic_by_destination': traffic['by_destination'],
        'traffic_by_conversation': traffic['by_conversation'],
    }
    
    with open('packet_flow_analysis.json', 'w') as f:
        json.dump(json_data, f, indent=2)
    print(f"\n[+] Analysis results saved to: packet_flow_analysis.json")


if __name__ == "__main__":
    main()
