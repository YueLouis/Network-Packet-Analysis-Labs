"""
Lab 3.2: Example Usage
Demonstrate AI-powered packet dissection
"""

from scapy.all import *
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.ai_dissector import create_dissector_with_ai, smart_field_extraction, analyze_unknown_protocol

# Check if API key is set
if not os.getenv("GROQ_API_KEY"):
    print("ERROR: GROQ_API_KEY environment variable not set!")
    print("Please set it before running examples:")
    print("  Windows: set GROQ_API_KEY=your_key_here")
    print("  Linux/Mac: export GROQ_API_KEY=your_key_here")
    sys.exit(1)

def example1_generate_http_dissector():
    """
    Example 1: Generate HTTP dissector from sample packets
    """
    print("\n" + "="*80)
    print("EXAMPLE 1: Generate HTTP Dissector")
    print("="*80)
    
    # Create sample HTTP packets
    http_packets = [
        Ether()/IP(dst="93.184.216.34")/TCP(dport=80)/Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        Ether()/IP(dst="93.184.216.34")/TCP(dport=80)/Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.68.0\r\n\r\n"),
        Ether()/IP(dst="93.184.216.34")/TCP(dport=80)/Raw(load=b"POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\ntest=hello"),
    ]
    
    print(f"[*] Created {len(http_packets)} sample HTTP packets")
    
    # Generate dissector
    print("[*] Generating dissector with AI...")
    code, filename = create_dissector_with_ai("HTTP", http_packets, "RFC 2616")
    
    if code:
        print(f"\n[+] Success! Generated: {filename}")
        print("\n[Preview]")
        print("-" * 80)
        print(code[:500] + "\n..." if len(code) > 500 else code)
        print("-" * 80)


def example2_smart_field_extraction():
    """
    Example 2: Extract specific fields using natural language
    """
    print("\n" + "="*80)
    print("EXAMPLE 2: Smart Field Extraction")
    print("="*80)
    
    # Create sample packets
    packets = [
        ("TCP Packet", IP(dst="8.8.8.8")/TCP(dport=443, flags="S", seq=12345, ack=0, window=65535)),
        ("UDP Packet", IP(dst="8.8.8.8")/UDP(sport=53, dport=1024)),
        ("ICMP Packet", IP(dst="8.8.8.8")/ICMP(type=8, code=0, id=100)),
    ]
    
    fields_to_extract = [
        "TCP sequence number",
        "TCP window size",
        "IP destination address",
    ]
    
    for name, packet in packets[:1]:  # Test với packet đầu tiên
        print(f"\n[*] Packet: {name}")
        print(f"    {packet.summary()}")
        
        for field_desc in fields_to_extract[:1]:  # Test 1 field
            print(f"\n[*] Extracting: '{field_desc}'...")
            result = smart_field_extraction(packet, field_desc)
            
            if result:
                print("[+] AI Response:")
                print("-" * 80)
                print(result)
                print("-" * 80)
                break  # Chỉ test 1 field để tiết kiệm API calls


def example3_analyze_unknown_protocol():
    """
    Example 3: Analyze unknown protocol structure
    """
    print("\n" + "="*80)
    print("EXAMPLE 3: Analyze Unknown Protocol")
    print("="*80)
    
    # Create custom protocol packets (simulated)
    class CustomProtocol(Packet):
        name = "CustomProto"
        fields_desc = [
            ShortField("magic", 0xDEAD),
            ByteField("version", 1),
            ByteField("flags", 0),
            IntField("length", 0),
            IntField("sequence", 0),
        ]
    
    custom_packets = [
        Ether()/IP()/UDP()/CustomProtocol(magic=0xDEAD, version=1, flags=0, length=64, sequence=1),
        Ether()/IP()/UDP()/CustomProtocol(magic=0xDEAD, version=1, flags=1, length=128, sequence=2),
        Ether()/IP()/UDP()/CustomProtocol(magic=0xDEAD, version=1, flags=0, length=256, sequence=3),
    ]
    
    print(f"[*] Created {len(custom_packets)} packets with unknown protocol")
    
    # Analyze
    print("[*] Analyzing protocol structure with AI...")
    analysis = analyze_unknown_protocol(custom_packets, "binary protocol with header")
    
    if analysis:
        print("\n[+] Protocol Analysis:")
        print("=" * 80)
        print(analysis)
        print("=" * 80)


def example4_generate_dns_dissector():
    """
    Example 4: Generate DNS dissector
    """
    print("\n" + "="*80)
    print("EXAMPLE 4: Generate DNS Dissector")
    print("="*80)
    
    # Create sample DNS packets
    dns_packets = [
        Ether()/IP(dst="8.8.8.8")/UDP(dport=53)/DNS(qd=DNSQR(qname="google.com")),
        Ether()/IP(dst="8.8.8.8")/UDP(dport=53)/DNS(qd=DNSQR(qname="github.com")),
        Ether()/IP(src="8.8.8.8")/UDP(sport=53)/DNS(an=DNSRR(rrname="google.com", rdata="142.250.185.46")),
    ]
    
    print(f"[*] Created {len(dns_packets)} sample DNS packets")
    
    # Generate dissector
    print("[*] Generating DNS dissector with AI...")
    code, filename = create_dissector_with_ai("DNS", dns_packets, "RFC 1035")
    
    if code:
        print(f"\n[+] Success! Generated: {filename}")
        print("\n[Preview]")
        print("-" * 80)
        print(code[:400] + "\n..." if len(code) > 400 else code)
        print("-" * 80)


def main():
    """
    Run all examples
    """
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║          LAB 3.2: AI-POWERED PACKET DISSECTORS - EXAMPLES                  ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Check API key
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key or api_key == "your-groq-api-key-here":
        print("[!] Error: GROQ_API_KEY not set!")
        print("[*] Set environment variable:")
        print("    $env:GROQ_API_KEY='your-key'")
        print("\n[*] Get free API key at: https://console.groq.com/")
        print("\n[*] Running in demo mode (will show errors)...")
        input("\nPress Enter to continue anyway...")
    
    # Run examples
    try:
        # Example 1: HTTP dissector
        example1_generate_http_dissector()
        input("\nPress Enter to continue to next example...")
        
        # Example 2: Smart extraction
        example2_smart_field_extraction()
        input("\nPress Enter to continue to next example...")
        
        # Example 3: Unknown protocol
        example3_analyze_unknown_protocol()
        input("\nPress Enter to continue to next example...")
        
        # Example 4: DNS dissector
        example4_generate_dns_dissector()
        
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n[+] Examples complete!")


if __name__ == "__main__":
    main()
