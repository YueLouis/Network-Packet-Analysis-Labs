#!/usr/bin/env python3
"""
Lab 3.1: TCP Retransmission Detector
Detect and analyze TCP retransmissions
"""

from scapy.all import *
import json

def detect_retransmissions(packets):
    """
    Detect TCP retransmissions by tracking sequence numbers and timestamps
    """
    # Track TCP segments by (src_ip, dst_ip, src_port, dst_port, seq)
    segments = {}
    retransmissions = []
    
    for packet in packets:
        if not packet.haslayer(TCP):
            continue
        
        tcp = packet[TCP]
        ip = packet[IP]
        
        # Skip packets with no payload or only ACK
        if len(tcp.payload) == 0:
            continue
        
        # Key for tracking segments
        flow_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        seq_num = tcp.seq
        payload_len = len(tcp.payload)
        timestamp = packet.time if hasattr(packet, 'time') else 0
        
        # Create unique key for this segment
        segment_key = (flow_key, seq_num, payload_len)
        
        if segment_key in segments:
            # This is a retransmission!
            prev_time = segments[segment_key]['timestamp']
            rto = timestamp - prev_time  # Estimated RTO (Retransmission Timeout)
            
            retrans = {
                'flow': f"{flow_key[0]}:{flow_key[1]} → {flow_key[2]}:{flow_key[3]}",
                'src_ip': flow_key[0],
                'src_port': flow_key[1],
                'dst_ip': flow_key[2],
                'dst_port': flow_key[3],
                'seq': seq_num,
                'payload_len': payload_len,
                'first_sent': prev_time,
                'retrans_time': timestamp,
                'rto': rto,
                'flags': str(tcp.flags),
                'packet': packet  # Keep reference for details
            }
            
            retransmissions.append(retrans)
            segments[segment_key]['count'] += 1
        else:
            segments[segment_key] = {
                'timestamp': timestamp,
                'count': 1,
                'flags': str(tcp.flags),
                'ttl': ip.ttl
            }
    
    return retransmissions, segments


def detect_out_of_order(packets):
    """
    Detect out-of-order TCP packets
    """
    flow_seqs = {}  # Track expected sequence number for each flow
    out_of_order = []
    
    for packet in packets:
        if not packet.haslayer(TCP):
            continue
        
        tcp = packet[TCP]
        ip = packet[IP]
        
        if len(tcp.payload) == 0:
            continue
        
        flow_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        
        if flow_key not in flow_seqs:
            flow_seqs[flow_key] = {
                'expected_seq': tcp.seq + len(tcp.payload),
                'packets': []
            }
        else:
            expected = flow_seqs[flow_key]['expected_seq']
            if tcp.seq != expected:
                out_of_order.append({
                    'flow': f"{flow_key[0]}:{flow_key[1]} → {flow_key[2]}:{flow_key[3]}",
                    'expected_seq': expected,
                    'actual_seq': tcp.seq,
                    'payload_len': len(tcp.payload),
                    'gap': tcp.seq - expected if tcp.seq > expected else "Duplicate"
                })
            
            flow_seqs[flow_key]['expected_seq'] = tcp.seq + len(tcp.payload)
        
        flow_seqs[flow_key]['packets'].append(tcp.seq)
    
    return out_of_order


def detect_duplicate_acks(packets):
    """
    Detect duplicate ACKs (can indicate packet loss or retransmissions)
    """
    flow_acks = {}
    duplicate_acks = []
    
    for packet in packets:
        if not packet.haslayer(TCP):
            continue
        
        tcp = packet[TCP]
        ip = packet[IP]
        
        # Focus on packets with ACK flag
        if not (tcp.flags & 0x10):  # ACK flag
            continue
        
        flow_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        
        if flow_key not in flow_acks:
            flow_acks[flow_key] = {
                'last_ack': tcp.ack,
                'dup_count': 0,
                'acks': []
            }
        else:
            if tcp.ack == flow_acks[flow_key]['last_ack']:
                flow_acks[flow_key]['dup_count'] += 1
                
                if flow_acks[flow_key]['dup_count'] == 2:  # Report on 3rd occurrence
                    duplicate_acks.append({
                        'flow': f"{flow_key[0]}:{flow_key[1]} ← {flow_key[2]}:{flow_key[3]}",
                        'ack_num': tcp.ack,
                        'dup_count': flow_acks[flow_key]['dup_count'] + 1  # +1 for the original
                    })
            else:
                flow_acks[flow_key]['last_ack'] = tcp.ack
                flow_acks[flow_key]['dup_count'] = 0
        
        flow_acks[flow_key]['acks'].append(tcp.ack)
    
    return duplicate_acks


def print_retransmissions(retransmissions):
    """
    Print retransmission details
    """
    print("\n" + "="*100)
    print("TCP RETRANSMISSIONS DETECTED")
    print("="*100)
    
    if not retransmissions:
        print("\n[+] No retransmissions detected!")
        return
    
    for i, rt in enumerate(retransmissions, 1):
        print(f"\n[{i}] {rt['flow']}")
        print(f"    Sequence: {rt['seq']}")
        print(f"    Payload: {rt['payload_len']} bytes")
        print(f"    First sent: {rt['first_sent']:.6f}")
        print(f"    Retransmitted: {rt['retrans_time']:.6f}")
        print(f"    RTO: {rt['rto']:.6f}s")
        print(f"    Flags: {rt['flags']}")


def print_out_of_order(out_of_order):
    """
    Print out-of-order packet details
    """
    print("\n" + "="*100)
    print("OUT-OF-ORDER PACKETS DETECTED")
    print("="*100)
    
    if not out_of_order:
        print("\n[+] No out-of-order packets detected!")
        return
    
    for i, ooo in enumerate(out_of_order[:20], 1):  # Show first 20
        print(f"\n[{i}] {ooo['flow']}")
        print(f"    Expected SEQ: {ooo['expected_seq']}")
        print(f"    Actual SEQ: {ooo['actual_seq']}")
        print(f"    Gap: {ooo['gap']}")
        print(f"    Payload: {ooo['payload_len']} bytes")


def print_duplicate_acks(dup_acks):
    """
    Print duplicate ACK details
    """
    print("\n" + "="*100)
    print("DUPLICATE ACKS DETECTED")
    print("="*100)
    
    if not dup_acks:
        print("\n[+] No duplicate ACKs detected!")
        return
    
    for i, da in enumerate(dup_acks[:20], 1):
        print(f"\n[{i}] {da['flow']}")
        print(f"    ACK number: {da['ack_num']}")
        print(f"    Duplicate count: {da['dup_count']}")


def main():
    """
    Main function - detect TCP anomalies in pcap file
    """
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 retransmission_detector.py <pcap_file>")
        print("Example: python3 retransmission_detector.py pcap_files/captured_packets.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    try:
        print(f"[*] Loading packets from: {pcap_file}")
        packets = rdpcap(pcap_file)
        print(f"[+] Loaded {len(packets)} packets")
    except Exception as e:
        print(f"[!] Error loading pcap file: {e}")
        return
    
    # Filter TCP packets
    tcp_packets = [pkt for pkt in packets if pkt.haslayer(TCP)]
    print(f"[+] Found {len(tcp_packets)} TCP packets")
    
    if len(tcp_packets) == 0:
        print("[!] No TCP packets found")
        return
    
    # Detect retransmissions
    print("\n[*] Analyzing for retransmissions...")
    retransmissions, segments = detect_retransmissions(tcp_packets)
    print_retransmissions(retransmissions)
    
    # Detect out-of-order
    print("\n[*] Analyzing for out-of-order packets...")
    out_of_order = detect_out_of_order(tcp_packets)
    print_out_of_order(out_of_order)
    
    # Detect duplicate ACKs
    print("\n[*] Analyzing for duplicate ACKs...")
    dup_acks = detect_duplicate_acks(tcp_packets)
    print_duplicate_acks(dup_acks)
    
    # Summary
    print("\n" + "="*100)
    print("SUMMARY")
    print("="*100)
    print(f"Total retransmissions: {len(retransmissions)}")
    print(f"Total out-of-order packets: {len(out_of_order)}")
    print(f"Flows with duplicate ACKs: {len(dup_acks)}")
    
    if retransmissions:
        rtx_rtos = [rt['rto'] for rt in retransmissions]
        print(f"Average RTO: {sum(rtx_rtos)/len(rtx_rtos):.6f}s")
        print(f"Min RTO: {min(rtx_rtos):.6f}s")
        print(f"Max RTO: {max(rtx_rtos):.6f}s")
    
    # Save results to JSON
    results = {
        'total_packets': len(tcp_packets),
        'retransmissions_count': len(retransmissions),
        'out_of_order_count': len(out_of_order),
        'duplicate_acks_count': len(dup_acks),
    }
    
    with open('tcp_anomalies.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Results saved to: tcp_anomalies.json")


if __name__ == "__main__":
    main()
