#!/bin/bash

# Lab 3.1: Packet Capture Script
# Capture network packets while accessing websites using tcpdump

# Create output directory
OUTPUT_DIR="pcap_files"
mkdir -p $OUTPUT_DIR

# List of websites to access
WEBSITES=(
    "http://google.com"
    "http://github.com"
    "http://wikipedia.org"
    "http://example.com"
    "http://httpbin.org"
)

PCAP_FILE="$OUTPUT_DIR/captured_packets.pcap"
TSHARK_OUTPUT="$OUTPUT_DIR/packet_analysis.txt"

echo "[*] Starting packet capture..."
echo "[*] Output file: $PCAP_FILE"

# Start tcpdump in background to capture all TCP/UDP traffic
# Note: On Windows with WSL, use: netsh trace start capture=yes tracefile=pcap_file
# On Linux/Mac, use: sudo tcpdump -i any -w pcap_file

# For Linux/Mac:
if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
    sudo tcpdump -i any -w $PCAP_FILE 'tcp or udp' &
    TCPDUMP_PID=$!
    sleep 2
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    echo "[!] Windows detected. Using netsh for packet capture..."
    netsh trace start capture=yes tracefile=$PCAP_FILE &
fi

# Access each website
for website in "${WEBSITES[@]}"; do
    echo "[*] Accessing: $website"
    curl -m 5 "$website" -o /dev/null 2>/dev/null &
    sleep 1
done

# Wait for curl requests to complete
wait

# Stop packet capture
echo "[*] Stopping packet capture..."
if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
    sudo kill $TCPDUMP_PID 2>/dev/null
    wait $TCPDUMP_PID 2>/dev/null
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    netsh trace stop
fi

# Analyze with tshark (if available)
if command -v tshark &> /dev/null; then
    echo "[*] Analyzing packets with tshark..."
    tshark -r $PCAP_FILE -Y "tcp or udp" > $TSHARK_OUTPUT 2>/dev/null
    echo "[+] Analysis saved to: $TSHARK_OUTPUT"
else
    echo "[!] tshark not found. Install wireshark package."
fi

echo "[+] Capture complete! PCAP file: $PCAP_FILE"
