#!/usr/bin/env python3
"""
Lab 3.1: HTTP Request Extractor
Extract HTTP requests from TCP payloads
"""

from scapy.all import *
import re

def extract_http_requests(packets):
    """
    Extract HTTP requests from TCP payloads
    """
    http_requests = []
    
    for packet in packets:
        if not packet.haslayer(TCP):
            continue
        
        tcp = packet[TCP]
        ip = packet[IP]
        
        # Check if packet has payload
        if len(tcp.payload) == 0:
            continue
        
        payload = bytes(tcp.payload)
        
        # Check if payload contains HTTP request (starts with HTTP methods)
        if payload.startswith(b'GET') or payload.startswith(b'POST') or \
           payload.startswith(b'HEAD') or payload.startswith(b'PUT') or \
           payload.startswith(b'DELETE') or payload.startswith(b'CONNECT'):
            
            try:
                # Decode payload to string
                payload_str = payload.decode('utf-8', errors='ignore')
                
                # Extract HTTP request line
                lines = payload_str.split('\r\n')
                if lines:
                    request_line = lines[0]
                    
                    # Parse request
                    parts = request_line.split()
                    if len(parts) >= 3:
                        method = parts[0]
                        path = parts[1]
                        version = parts[2] if len(parts) > 2 else 'HTTP/1.1'
                        
                        # Extract host from headers
                        host = ''
                        for line in lines[1:]:
                            if line.lower().startswith('host:'):
                                host = line.split(':', 1)[1].strip()
                                break
                        
                        http_req = {
                            'src_ip': ip.src,
                            'dst_ip': ip.dst,
                            'src_port': tcp.sport,
                            'dst_port': tcp.dport,
                            'method': method,
                            'path': path,
                            'version': version,
                            'host': host,
                            'full_url': f"http://{host}{path}" if host else f"http://{ip.dst}:{tcp.dport}{path}",
                            'headers': {},
                            'payload_size': len(tcp.payload)
                        }
                        
                        # Extract headers
                        for line in lines[1:]:
                            if ':' in line and line.strip():
                                key, value = line.split(':', 1)
                                http_req['headers'][key.strip()] = value.strip()
                        
                        http_requests.append(http_req)
            except Exception as e:
                pass
    
    return http_requests


def extract_http_responses(packets):
    """
    Extract HTTP responses from TCP payloads
    """
    http_responses = []
    
    for packet in packets:
        if not packet.haslayer(TCP):
            continue
        
        tcp = packet[TCP]
        ip = packet[IP]
        
        # Check if packet has payload
        if len(tcp.payload) == 0:
            continue
        
        payload = bytes(tcp.payload)
        
        # Check if payload contains HTTP response (starts with HTTP/)
        if payload.startswith(b'HTTP/'):
            try:
                # Decode payload to string
                payload_str = payload.decode('utf-8', errors='ignore')
                
                # Extract HTTP response line
                lines = payload_str.split('\r\n')
                if lines:
                    response_line = lines[0]
                    
                    # Parse response
                    parts = response_line.split()
                    if len(parts) >= 2:
                        version = parts[0]
                        status_code = int(parts[1]) if parts[1].isdigit() else 0
                        reason = ' '.join(parts[2:]) if len(parts) > 2 else ''
                        
                        http_resp = {
                            'src_ip': ip.src,
                            'dst_ip': ip.dst,
                            'src_port': tcp.sport,
                            'dst_port': tcp.dport,
                            'version': version,
                            'status_code': status_code,
                            'reason': reason,
                            'headers': {},
                            'payload_size': len(tcp.payload)
                        }
                        
                        # Extract headers
                        for line in lines[1:]:
                            if ':' in line and line.strip():
                                key, value = line.split(':', 1)
                                http_resp['headers'][key.strip()] = value.strip()
                        
                        http_responses.append(http_resp)
            except Exception as e:
                pass
    
    return http_responses


def print_http_requests(requests):
    """
    Print extracted HTTP requests
    """
    print("\n" + "="*100)
    print("EXTRACTED HTTP REQUESTS")
    print("="*100)
    
    for i, req in enumerate(requests, 1):
        print(f"\n[{i}] {req['method']} {req['path']}")
        print(f"    Host: {req['host']}")
        print(f"    URL: {req['full_url']}")
        print(f"    From: {req['src_ip']}:{req['src_port']} → {req['dst_ip']}:{req['dst_port']}")
        print(f"    Payload size: {req['payload_size']} bytes")
        
        if req['headers']:
            print(f"    Headers:")
            for key, value in list(req['headers'].items())[:5]:  # Show first 5 headers
                print(f"      {key}: {value[:100]}")  # Limit value length


def print_http_responses(responses):
    """
    Print extracted HTTP responses
    """
    print("\n" + "="*100)
    print("EXTRACTED HTTP RESPONSES")
    print("="*100)
    
    for i, resp in enumerate(responses, 1):
        status_text = f"{resp['status_code']} {resp['reason']}"
        print(f"\n[{i}] {resp['version']} {status_text}")
        print(f"    From: {resp['src_ip']}:{resp['src_port']} ← {resp['dst_ip']}:{resp['dst_port']}")
        print(f"    Payload size: {resp['payload_size']} bytes")
        
        if resp['headers']:
            print(f"    Headers:")
            for key, value in list(resp['headers'].items())[:5]:
                print(f"      {key}: {value[:100]}")


def main():
    """
    Main function - extract HTTP from pcap file
    """
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python3 http_extractor.py <pcap_file>")
        print("Example: python3 http_extractor.py pcap_files/captured_packets.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    try:
        print(f"[*] Loading packets from: {pcap_file}")
        packets = rdpcap(pcap_file)
        print(f"[+] Loaded {len(packets)} packets")
    except Exception as e:
        print(f"[!] Error loading pcap file: {e}")
        return
    
    # Extract HTTP requests
    http_requests = extract_http_requests(packets)
    print(f"\n[+] Found {len(http_requests)} HTTP requests")
    
    if http_requests:
        print_http_requests(http_requests)
        
        # Save to JSON
        with open('http_requests.json', 'w') as f:
            json.dump(http_requests, f, indent=2)
        print(f"\n[+] Requests saved to: http_requests.json")
    
    # Extract HTTP responses
    http_responses = extract_http_responses(packets)
    print(f"\n[+] Found {len(http_responses)} HTTP responses")
    
    if http_responses:
        print_http_responses(http_responses)
        
        # Save to JSON
        with open('http_responses.json', 'w') as f:
            json.dump(http_responses, f, indent=2)
        print(f"\n[+] Responses saved to: http_responses.json")
    
    # Summary
    print("\n" + "="*100)
    print("SUMMARY")
    print("="*100)
    print(f"Total HTTP Requests: {len(http_requests)}")
    print(f"Total HTTP Responses: {len(http_responses)}")
    
    if http_requests:
        methods = {}
        for req in http_requests:
            methods[req['method']] = methods.get(req['method'], 0) + 1
        print(f"Methods used: {methods}")
    
    if http_responses:
        status_codes = {}
        for resp in http_responses:
            code = resp['status_code']
            status_codes[code] = status_codes.get(code, 0) + 1
        print(f"Status codes: {status_codes}")


if __name__ == "__main__":
    main()
