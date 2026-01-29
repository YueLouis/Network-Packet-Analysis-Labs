"""
Lab 3.2: AI-Powered Packet Dissectors
Generate packet dissector code using AI (Groq LLM)
"""

import os
import sys
from scapy.all import *
from openai import OpenAI

# Groq API configuration - MUST set GROQ_API_KEY environment variable
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not GROQ_API_KEY:
    print("ERROR: GROQ_API_KEY environment variable not set!")
    print("Please set it using one of these methods:")
    print("  Windows: set GROQ_API_KEY=your_key_here")
    print("  Linux/Mac: export GROQ_API_KEY=your_key_here")
    print("  Or create a .env file with: GROQ_API_KEY=your_key_here")
    sys.exit(1)

def create_dissector_with_ai(protocol_name, sample_packets, rfc_reference=None):
    """
    Generate complete packet dissector using AI
    
    Args:
        protocol_name: Name of protocol (e.g., "HTTP", "DNS", "Custom")
        sample_packets: List of sample packets to analyze
        rfc_reference: Optional RFC number or reference
        
    Returns:
        tuple: (generated_code, filename)
    """
    
    # Analyze samples
    packet_hex = [bytes(pkt).hex() for pkt in sample_packets[:5]]
    
    # Build context for AI
    context = f"""Create a complete Scapy packet dissector for {protocol_name}.

Sample packets (hex):
{chr(10).join(packet_hex)}
"""
    
    if rfc_reference:
        context += f"\nRFC Reference: {rfc_reference}\n"
    
    context += """
Generate Python code that:
1. Defines a Scapy Packet class with all fields
2. Implements field parsing and building
3. Includes bind_layers() for auto-detection
4. Adds helper methods for common operations
5. Includes usage examples

Make it production-ready with error handling.
Return ONLY the Python code, no explanations."""

    try:
        # Initialize Groq client
        client = OpenAI(                      
            api_key=GROQ_API_KEY,
            base_url="https://api.groq.com/openai/v1",
        )
        
        # Call AI
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": context}],
            temperature=0.3,
            max_tokens=2000,
        )
        
        # Extract code from response
        code = response.choices[0].message.content
        
        # Clean up code (remove markdown if present)
        if "```python" in code:
            code = code.split("```python")[1].split("```")[0].strip()
        elif "```" in code:
            code = code.split("```")[1].split("```")[0].strip()
        
        # Save to file
        filename = f"{protocol_name.lower()}_dissector.py"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f'"""\nAI-Generated Dissector for {protocol_name}\n"""\n\n')
            f.write(code)
        
        print(f"[+] Dissector saved to {filename}")
        return code, filename
        
    except Exception as e:
        print(f"[!] Error generating dissector: {e}")
        return None, None


def smart_field_extraction(packet, field_description):
    """
    Use LLM to extract specific fields based on natural language description
    
    Args:
        packet: Scapy packet object
        field_description: Natural language description of field to extract
        
    Returns:
        str: AI response with field details
    """
    
    packet_hex = bytes(packet).hex()
    
    prompt = f"""Extract the following field from this network packet:

Field to extract: {field_description}

Packet (hex): {packet_hex}

Packet (Scapy summary): {packet.summary()}

Provide:
1. Byte offset where field starts
2. Field length in bytes
3. Extracted value (hex and decoded if applicable)
4. Explanation of how you identified it

Be specific and accurate."""

    try:
        client = OpenAI(                      
            api_key=GROQ_API_KEY,
            base_url="https://api.groq.com/openai/v1",
        )
        
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=1000,
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        print(f"[!] Error extracting field: {e}")
        return None


def analyze_unknown_protocol(packets, protocol_hint=None):
    """
    Analyze unknown protocol and suggest field structure
    
    Args:
        packets: List of packets containing unknown protocol
        protocol_hint: Optional hint about protocol (e.g., "binary", "text-based")
        
    Returns:
        str: AI analysis of protocol structure
    """
    
    # Analyze first few packets
    analysis_data = []
    for i, pkt in enumerate(packets[:3]):
        analysis_data.append({
            'packet_num': i + 1,
            'hex': bytes(pkt).hex(),
            'length': len(pkt),
            'summary': pkt.summary() if hasattr(pkt, 'summary') else str(pkt)
        })
    
    prompt = f"""Analyze this unknown network protocol and suggest its structure.

Protocol hint: {protocol_hint or 'Unknown'}

Packets:
"""
    
    for data in analysis_data:
        prompt += f"\nPacket {data['packet_num']} ({data['length']} bytes):\n"
        prompt += f"Hex: {data['hex']}\n"
        prompt += f"Summary: {data['summary']}\n"
    
    prompt += """
Provide:
1. Likely protocol type (binary/text-based)
2. Possible field structure with offsets
3. Common patterns identified
4. Suggested Scapy field definitions
5. Any recognizable headers or signatures"""

    try:
        client = OpenAI(                      
            api_key=GROQ_API_KEY,
            base_url="https://api.groq.com/openai/v1",
        )
        
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=1500,
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        print(f"[!] Error analyzing protocol: {e}")
        return None


def main():
    """
    Main function - demonstrate AI-powered packet dissection
    """
    import sys
    
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║              LAB 3.2: AI-POWERED PACKET DISSECTORS                         ║
║                                                                            ║
║  Generate packet dissectors using Groq LLM (llama-3.1-8b-instant)          ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Check API key
    if GROQ_API_KEY == "your-groq-api-key-here":
        print("[!] Error: GROQ_API_KEY not set!")
        print("[*] Set environment variable: $env:GROQ_API_KEY='your-key'")
        print("[*] Or edit this file and set GROQ_API_KEY variable")
        print("\n[*] Get free API key at: https://console.groq.com/")
        sys.exit(1)
    
    # Menu
    print("\nSelect option:")
    print("1. Generate dissector from PCAP file")
    print("2. Extract field from packet (smart extraction)")
    print("3. Analyze unknown protocol")
    print("4. Demo with sample packets")
    print("5. Exit")
    
    choice = input("\nEnter choice (1-5): ").strip()
    
    if choice == "1":
        # Generate dissector
        pcap_file = input("Enter PCAP file path: ").strip()
        protocol_name = input("Enter protocol name: ").strip()
        rfc = input("Enter RFC reference (optional): ").strip() or None
        
        if not os.path.exists(pcap_file):
            print(f"[!] File not found: {pcap_file}")
            sys.exit(1)
        
        print(f"\n[*] Loading packets from {pcap_file}...")
        packets = rdpcap(pcap_file)
        print(f"[+] Loaded {len(packets)} packets")
        
        print(f"\n[*] Generating dissector for {protocol_name}...")
        code, filename = create_dissector_with_ai(protocol_name, packets, rfc)
        
        if code:
            print(f"\n[+] Success! Generated dissector:")
            print("-" * 80)
            print(code[:500] + "..." if len(code) > 500 else code)
            print("-" * 80)
    
    elif choice == "2":
        # Smart field extraction
        print("\n[*] Creating sample packet...")
        packet = IP(dst="8.8.8.8")/TCP(dport=80, flags="S", seq=12345)
        print(f"[+] Packet: {packet.summary()}")
        
        field_desc = input("\nDescribe field to extract (e.g., 'TCP sequence number'): ").strip()
        
        print(f"\n[*] Extracting field: {field_desc}...")
        result = smart_field_extraction(packet, field_desc)
        
        if result:
            print("\n[+] AI Analysis:")
            print("-" * 80)
            print(result)
            print("-" * 80)
    
    elif choice == "3":
        # Analyze unknown protocol
        pcap_file = input("Enter PCAP file with unknown protocol: ").strip()
        hint = input("Protocol hint (optional): ").strip() or None
        
        if not os.path.exists(pcap_file):
            print(f"[!] File not found: {pcap_file}")
            sys.exit(1)
        
        print(f"\n[*] Loading packets...")
        packets = rdpcap(pcap_file)
        print(f"[+] Loaded {len(packets)} packets")
        
        print(f"\n[*] Analyzing protocol...")
        analysis = analyze_unknown_protocol(packets, hint)
        
        if analysis:
            print("\n[+] Protocol Analysis:")
            print("=" * 80)
            print(analysis)
            print("=" * 80)
    
    elif choice == "4":
        # Demo mode
        print("\n[*] Demo: Creating sample HTTP packets...")
        
        # Create sample HTTP packets
        http_packets = [
            Ether()/IP(dst="93.184.216.34")/TCP(dport=80)/Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            Ether()/IP(dst="93.184.216.34")/TCP(dport=80)/Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        ]
        
        print(f"[+] Created {len(http_packets)} sample packets")
        
        print("\n[*] Generating HTTP dissector with AI...")
        code, filename = create_dissector_with_ai("HTTP", http_packets, "RFC 2616")
        
        if code:
            print(f"\n[+] Generated dissector preview:")
            print("-" * 80)
            print(code[:800] + "\n..." if len(code) > 800 else code)
            print("-" * 80)
        
        # Demo field extraction
        print("\n[*] Demo: Smart field extraction...")
        packet = IP(dst="8.8.8.8")/TCP(dport=443, flags="S", seq=100000)
        
        print(f"[+] Sample packet: {packet.summary()}")
        print(f"\n[*] Extracting 'TCP flags field'...")
        
        result = smart_field_extraction(packet, "TCP flags field")
        if result:
            print("\n[+] AI Response:")
            print("-" * 80)
            print(result)
            print("-" * 80)
    
    elif choice == "5":
        print("\n[*] Exiting...")
        sys.exit(0)
    
    else:
        print("[!] Invalid choice")
        sys.exit(1)
    
    print("\n[+] Done!")


if __name__ == "__main__":
    main()
