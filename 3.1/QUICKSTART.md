# Lab 3.1: Basic Packet Parser - QUICKSTART

## 🚀 QUICK START (3 bước)

### Step 1: Cài đặt
```bash
pip install -r requirements.txt
```

### Step 2: Capture Packets (Windows/Linux/Mac)
```bash
cd Task1_Capture
python capture_packets.py

# Hoặc Bash version (Linux/Mac)
bash capture.sh
```

### Step 3: Chạy Phân Tích
```bash
# Option 1: Run all tasks
cd tools
python main_analysis.py

# Option 2: Run each task manually
cd Task2_UDP
python udp_parser.py ../Task1_Capture/pcap_files/captured_packets.pcap

cd ../Task3_HTTP
python http_extractor.py ../Task1_Capture/pcap_files/captured_packets.pcap

cd ../Task4_Visualize
python packet_visualizer.py ../Task1_Capture/pcap_files/captured_packets.pcap

cd ../Task5_Detect_Anomalies
python retransmission_detector.py ../Task1_Capture/pcap_files/captured_packets.pcap
```

---

## 📋 NEW File Structure (Organized by Tasks!)

```
📁 3.1/
├── 📁 Task1_Capture/              ⭐ Task 1: Capture packets
│   ├── capture_packets.py
│   ├── capture.sh
│   ├── pcap_files/
│   └── README.md
├── 📁 Task2_UDP/                  ⭐ Task 2: Parse UDP
│   ├── udp_parser.py
│   └── README.md
├── 📁 Task3_HTTP/                 ⭐ Task 3: Extract HTTP
│   ├── http_extractor.py
│   └── README.md
├── 📁 Task4_Visualize/            ⭐ Task 4: Visualize
│   ├── packet_visualizer.py
│   └── README.md
├── 📁 Task5_Detect_Anomalies/     ⭐ Task 5: Detect anomalies
│   ├── retransmission_detector.py
│   └── README.md
├── 📁 outputs/                    📊 All results (JSON/TXT)
├── 📁 tools/                      🛠️ Helper scripts
│   ├── main_analysis.py
│   ├── test_lab3.py
│   └── run.bat
├── 📄 README.md                   Documentation
├── 📄 QUICKSTART.md               This file
├── 📄 TONG_KET.md                 Vietnamese summary
└── 📄 requirements.txt            Dependencies
```

---

## ⚙️ Hệ thống yêu cầu

| Tool | Purpose | Cài đặt |
|------|---------|--------|
| Python 3.7+ | Runtime | Có sẵn |
| Scapy | Packet analysis | `pip install scapy` |
| curl | HTTP requests | Linux: `apt-get install curl` |
| tcpdump | Packet capture | Linux: `apt-get install tcpdump` |

**Windows Users**: Dùng WSL hoặc Python version (`capture_packets.py`)

---

## 🔧 Sử dụng

### Method 1: Interactive Menu (Khuyến khích)
```bash
python3 main_analysis.py
```
Menu sẽ hướng dẫn bạn từng bước.

### Method 2: Chạy từng script
```bash
# 1. Capture packets
python3 capture_packets.py

# 2. Analyze UDP
python3 udp_parser.py pcap_files/captured_packets.pcap

# 3. Extract HTTP
python3 http_extractor.py pcap_files/captured_packets.pcap

# 4. Detect anomalies
python3 retransmission_detector.py pcap_files/captured_packets.pcap

# 5. Visualize flow
python3 packet_visualizer.py pcap_files/captured_packets.pcap
```

---

## 📊 Outputs

Sau khi chạy, bạn sẽ nhận được:

| File | Chứa gì |
|------|---------|
| `pcap_files/captured_packets.pcap` | Raw packet data |
| `udp_analysis.json` | UDP packet statistics |
| `http_requests.json` | Extracted HTTP requests |
| `http_responses.json` | HTTP responses |
| `tcp_anomalies.json` | Retransmissions & anomalies |
| `packet_flow_analysis.json` | Traffic analysis |
| `sequence_diagram.txt` | ASCII sequence diagram |

---

## 📌 Ví dụ Output

### UDP Analysis
```json
{
  "total_packets": 10,
  "connections": {
    "192.168.1.100:54321-8.8.8.8:53": {
      "protocol": "DNS",
      "packets": 5,
      "total_bytes": 500
    }
  }
}
```

### HTTP Extraction
```json
[
  {
    "method": "GET",
    "path": "/",
    "host": "example.com",
    "full_url": "http://example.com/",
    "headers": {"Host": "example.com", "User-Agent": "curl/7.68.0"}
  }
]
```

### TCP Anomalies
```
TCP RETRANSMISSIONS DETECTED
[1] 192.168.1.100:12345 → 93.184.216.34:80
    Sequence: 1000
    RTO: 0.667s
    Flags: [A]
```

---

## 🐛 Troubleshooting

### ❌ "No module named 'scapy'"
```bash
pip install scapy
```

### ❌ "Permission denied" (Linux/Mac)
```bash
sudo python3 capture_packets.py
```

### ❌ "No packets captured"
- Kiểm tra internet connection
- Thử timeout lâu hơn
- Dùng network interface khác

### ❌ "File not found: pcap file"
- Chạy capture trước: `python3 capture_packets.py`
- Hoặc dùng file PCAP có sẵn

---

## 💡 Tips & Tricks

### 1. Capture lâu hơn
Edit trong `capture_packets.py` hoặc `capture.sh`:
```python
capture_with_scapy(duration=60)  # 60 seconds
```

### 2. Chỉ capture TCP
```python
packets = sniff(filter="tcp", count=100)
```

### 3. Phân tích file có sẵn
```bash
python3 udp_parser.py your_file.pcap
```

### 4. Save kết quả đẹp hơn
Dùng `json.dumps()` với indent:
```python
print(json.dumps(data, indent=2))
```

---

## 📚 Learn More

- [Scapy Official Docs](https://scapy.readthedocs.io/)
- [TCP/IP Basics](https://en.wikipedia.org/wiki/Internet_protocol_suite)
- [Wireshark User Guide](https://www.wireshark.org/docs/)
- [tcpdump Tutorial](https://www.tcpdump.org/papers/sniffing-faq.html)

---

## ✅ Checklist

- [ ] Cài đặt dependencies: `pip install -r requirements.txt`
- [ ] Chạy capture: `python3 capture_packets.py`
- [ ] Chạy UDP analysis: `python3 udp_parser.py pcap_files/captured_packets.pcap`
- [ ] Chạy HTTP extraction: `python3 http_extractor.py pcap_files/captured_packets.pcap`
- [ ] Chạy anomaly detection: `python3 retransmission_detector.py pcap_files/captured_packets.pcap`
- [ ] Chạy visualization: `python3 packet_visualizer.py pcap_files/captured_packets.pcap`
- [ ] Review kết quả trong JSON files
- [ ] Check sequence diagram: `cat sequence_diagram.txt`

---

## 🎯 Learning Objectives Hoàn Thành

✅ Capture TCP/UDP packets từ network
✅ Parse UDP packets & track connections
✅ Extract HTTP requests/responses từ TCP payload
✅ Phát hiện TCP retransmissions & anomalies
✅ Vẽ sequence diagrams & analyze traffic flow
✅ Export kết quả dưới dạng JSON

---

**Lab 3.1 - Network Programming (Lập trình mạng NPRO)**
