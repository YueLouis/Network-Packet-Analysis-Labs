# Lab 3.1: Basic Packet Parser

## 📂 Folder Structure (Organized by Tasks)

```
3.1/
├── Task1_Capture/           ← 🎯 Task 1: Capture packets
│   ├── capture_packets.py
│   ├── capture.sh
│   ├── pcap_files/
│   └── README.md
│
├── Task2_UDP/               ← 🎯 Task 2: Parse UDP
│   ├── udp_parser.py
│   └── README.md
│
├── Task3_HTTP/              ← 🎯 Task 3: Extract HTTP
│   ├── http_extractor.py
│   └── README.md
│
├── Task4_Visualize/         ← 🎯 Task 4: Visualize flows
│   ├── packet_visualizer.py
│   └── README.md
│
├── Task5_Detect_Anomalies/  ← 🎯 Task 5: Detect retransmissions
│   ├── retransmission_detector.py
│   └── README.md
│
├── outputs/                 ← 📊 All JSON/TXT results
│   ├── *.json
│   └── *.txt
│
├── tools/                   ← 🛠️ Helper scripts
│   ├── main_analysis.py    (Run all tasks)
│   ├── test_lab3.py        (Unit tests)
│   └── run.bat             (Quick launch)
│
├── README.md               ← You are here!
├── QUICKSTART.md           ← Quick guide
├── TONG_KET.md             ← Vietnamese summary
└── requirements.txt        ← Dependencies
```

---

## 🚀 Quick Start

**Option 1: Run individual tasks**
```bash
cd Task1_Capture
python capture_packets.py

cd ../Task2_UDP
python udp_parser.py ../Task1_Capture/pcap_files/captured_packets.pcap

# ... follow each task's README
```

**Option 2: Run all tasks at once**
```bash
cd tools
python main_analysis.py
```

---

## 📋 Tasks Overview

| Task | Script | Input | Output | Purpose |
|------|--------|-------|--------|---------|
| 1️⃣ | `capture_packets.py` | Live network | `.pcap` | Capture traffic |
| 2️⃣ | `udp_parser.py` | `.pcap` | `udp_analysis.json` | Parse UDP packets |
| 3️⃣ | `http_extractor.py` | `.pcap` | `http_*.json` | Extract HTTP |
| 4️⃣ | `packet_visualizer.py` | `.pcap` | Sequence diagrams | Visualize flows |
| 5️⃣ | `retransmission_detector.py` | `.pcap` | `retransmissions.json` | Detect anomalies |

---

## Mục đích
Phân tích gói TCP/UDP, trích xuất thông tin HTTP, phát hiện retransmissions và vẽ biểu đồ packet flow.

## Yêu cầu

### Cài đặt Dependencies

```bash
# Cài đặt Scapy
pip install scapy

# Linux/Mac: Cài đặt tcpdump
sudo apt-get install tcpdump tshark

# Windows: 
# - Cài đặt Wireshark (bao gồm tcpdump và tshark)
# - Hoặc dùng WSL (Windows Subsystem for Linux)
```

## Cấu trúc File (OLD - See folder structure above)

```
├── main_analysis.py              # Script chính (chạy menu interactive)
├── capture.sh                    # Bash script capture packets
├── udp_parser.py                 # Phân tích UDP packets
├── http_extractor.py             # Trích xuất HTTP requests/responses
├── retransmission_detector.py    # Phát hiện TCP anomalies
├── packet_visualizer.py          # Vẽ biểu đồ packet flow
└── README.md                     # File này
```

## Hướng dẫn sử dụng

### Cách 1: Chạy Complete Analysis (Khuyến khích)

```bash
python3 main_analysis.py
```

Menu sẽ hiển thị các option:
1. **Run complete analysis** - Capture packets + phân tích tất cả
2. **Analyze existing PCAP** - Phân tích file PCAP có sẵn
3. **Quick test** - Test với file có sẵn
4. **Exit** - Thoát

### Cách 2: Chạy từng script riêng lẻ

#### 1. Capture Packets
```bash
# Linux/Mac (cần sudo)
sudo bash capture.sh

# Windows WSL
bash capture.sh

# Hoặc dùng Python script
python3 capture_packets.py
```

Output: `pcap_files/captured_packets.pcap`

#### 2. Phân tích UDP Packets
```bash
python3 udp_parser.py pcap_files/captured_packets.pcap
```

Output: `udp_analysis.json`

#### 3. Trích xuất HTTP Requests/Responses
```bash
python3 http_extractor.py pcap_files/captured_packets.pcap
```

Output: 
- `http_requests.json`
- `http_responses.json`

#### 4. Phát hiện TCP Anomalies
```bash
python3 retransmission_detector.py pcap_files/captured_packets.pcap
```

Phát hiện:
- TCP Retransmissions
- Out-of-order packets
- Duplicate ACKs

Output: `tcp_anomalies.json`

#### 5. Vẽ Packet Flow Visualization
```bash
python3 packet_visualizer.py pcap_files/captured_packets.pcap
```

Output:
- `sequence_diagram.txt` - ASCII sequence diagram
- `packet_flow_analysis.json` - Traffic analysis

## Outputs Chi tiết

### 1. UDP Analysis (`udp_analysis.json`)
```json
{
  "total_packets": 25,
  "connections": {
    "192.168.1.100:50000-8.8.8.8:53": {
      "protocol": "DNS",
      "packets": 5,
      "total_bytes": 500
    }
  }
}
```

### 2. HTTP Extraction (`http_requests.json`)
```json
[
  {
    "method": "GET",
    "path": "/",
    "host": "example.com",
    "full_url": "http://example.com/",
    "headers": {
      "Host": "example.com",
      "User-Agent": "curl/7.68.0"
    }
  }
]
```

### 3. TCP Anomalies (`tcp_anomalies.json`)
```json
{
  "total_packets": 100,
  "retransmissions_count": 3,
  "out_of_order_count": 2,
  "duplicate_acks_count": 1
}
```

### 4. Sequence Diagram (`sequence_diagram.txt`)
```
Connection: 192.168.1.100:12345 <-> 93.184.216.34:80
───────────────────────────────────────────────────────
     192.168.1.100:12345          93.184.216.34:80
            |                              |
            |----> SEQ:1000 ACK:0 [S]      |
            |      (SYN)                   |
            |                              |
            |<---- SEQ:2000 ACK:1001 [SA]  |
            |      (SYN-ACK)               |
            |                              |
            |----> SEQ:1001 ACK:2001 [A]   |
            |      (ACK)                   |
```

## Các Task Hoàn Thành

✅ **Task 1: Capture Packets**
- Bash script `capture.sh` dùng curl + tcpdump
- Capture TCP/UDP traffic khi truy cập websites
- Output: PCAP file

✅ **Task 2: Parse UDP Packets**
- UDP không có state (không như TCP)
- Trích xuất: src_ip, dst_ip, ports, protocol (DNS, DHCP, NTP, v.v.)
- Track UDP flows (src:port → dst:port)

✅ **Task 3: Extract HTTP Requests**
- Nhận diện HTTP methods (GET, POST, HEAD, v.v.)
- Trích xuất: method, path, host, headers
- Phân tích HTTP responses (status code, reason)

✅ **Task 4: Visualize Packet Flow**
- ASCII sequence diagram cho TCP handshake
- Packet timeline analysis
- Traffic volume analysis by protocol, source, destination
- Conversation analysis

✅ **Task 5: Detect TCP Retransmissions**
- Phát hiện duplicate segments (same SEQ + payload)
- Tính RTO (Retransmission Timeout)
- Phát hiện out-of-order packets
- Phát hiện duplicate ACKs (chỉ báo packet loss)

## Ví dụ Kết quả

### Thông tin UDP Connection
```
UDP CONNECTION SUMMARY
════════════════════════════════════════════════════════

192.168.1.100:53 → 8.8.8.8:53
  Protocol: DNS
  Packets: 10
  Total bytes: 1500
  Duration: 2.345s
```

### HTTP Request Extraction
```
EXTRACTED HTTP REQUESTS
════════════════════════════════════════════════════════

[1] GET /index.html
    Host: example.com
    URL: http://example.com/index.html
    From: 192.168.1.100:54321 → 93.184.216.34:80
    Payload size: 256 bytes
    Headers:
      Host: example.com
      User-Agent: curl/7.68.0
```

### TCP Retransmission Report
```
TCP RETRANSMISSIONS DETECTED
════════════════════════════════════════════════════════

[1] 192.168.1.100:12345 → 93.184.216.34:80
    Sequence: 1000
    Payload: 1024 bytes
    First sent: 123.456789
    Retransmitted: 124.123456
    RTO: 0.666667s
    Flags: [A]
```

## Troubleshooting

### Problem: "Permission denied" khi chạy capture.sh
**Solution**: Cần sudo privilege
```bash
sudo bash capture.sh
```

### Problem: "No packets captured"
**Solution**: 
1. Đảm bảo network interface đúng
2. Đảm bảo có traffic khi đang capture
3. Thử với filter cụ thể

### Problem: "tshark not found"
**Solution**: Cài đặt wireshark
```bash
sudo apt-get install wireshark
```

### Problem: "No UDP/HTTP packets found"
**Solution**: 
1. PCAP file có thể chỉ có TCP traffic
2. Thử capture lại với DNS queries hoặc HTTP requests
3. Kiểm tra content file: `tcpdump -r pcap_file | head`

## Ghi chú

1. **Permissions**: Windows users cần chạy dưới WSL hoặc PowerShell with admin
2. **Network**: Script capture sẽ gửi requests đến websites thực
3. **Data**: Tất cả data được phân tích local, không upload lên internet
4. **Performance**: Với file lớn (>100MB), phân tích có thể mất vài phút

## Mở Rộng

### Thêm Detection cho Protocols khác
Chỉnh sửa `http_extractor.py`:
```python
# Add protocol detection
if payload.startswith(b'SMTP'):
    # SMTP detection
elif payload.startswith(b'FTP'):
    # FTP detection
```

### Tạo Real-time Monitoring
Dùng `sniff()` thay vì `rdpcap()`:
```python
from scapy.all import sniff
packets = sniff(filter="tcp", count=100)
```

### Lưu Results vào Database
```python
import sqlite3
conn = sqlite3.connect('packets.db')
# Save analysis results
```

## Tài liệu Tham Khảo

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [TCP/IP Illustrated](https://en.wikipedia.org/wiki/TCP/IP_Illustrated)
- [Wireshark Wiki](https://wiki.wireshark.org/)
- [RFC 793 - TCP](https://tools.ietf.org/html/rfc793)
- [RFC 768 - UDP](https://tools.ietf.org/html/rfc768)

## Author
Lab 3.1 - Network Programming Course (Lập trình mạng NPRO)

## License
Educational Purpose Only
