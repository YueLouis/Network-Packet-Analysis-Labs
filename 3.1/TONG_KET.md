# 📚 LAB 3.1: GIẢI THÍCH CHI TIẾT

## 🎯 Lab 3.1 là gì?

**Lab 3.1: Basic Packet Parser** là bài lab về **phân tích gói dữ liệu mạng (Network Packets)**

Đơn giản thôi: 
- **Gói mạng (Packet)** = Những đơn vị dữ liệu nhỏ được gửi qua internet
- **Parser** = Công cụ để "tách riêng" và phân tích từng phần của gói

---

## 💡 Ví dụ thực tế

Khi bạn vào **google.com**, điều gì xảy ra?

```
1. Bạn gõ google.com
   ↓
2. Máy tính gửi hàng trăm gói nhỏ qua mạng
   ↓
3. Google server nhận gói, xử lý
   ↓
4. Google gửi gói trả lời về
   ↓
5. Máy bạn nhận gói, hiển thị trang web
```

**Lab này giúp bạn:**
- 👁️ **Nhìn thấy** những gói dữ liệu
- 🔍 **Phân tích** từng gói chứa gì
- 📊 **Thống kê** tổng cộng bao nhiêu gói, loại gì
- 🎯 **Phát hiện lỗi** (gói gửi lại, gói bị mất, v.v.)

---

## 📋 5 TASKS CHI TIẾT

### **Task 1: Capture Packets (Bắt gói mạng)**

**Làm gì?**
- Dùng `capture_packets.py` để ghi lại tất cả gói dữ liệu khi bạn truy cập websites
- Lưu vào file `.pcap` (Packet Capture format)

**Ví dụ:**
```
Bạn chạy: capture_packets.py
    ↓
Script truy cập: google.com, github.com, wikipedia.org...
    ↓
Trong lúc đó, ghi lại tất cả gói tin
    ↓
Kết quả: pcap_files/captured_packets.pcap (173 KB)
```

**Output:**
```
pcap_files/captured_packets.pcap
- Chứa 535 gói TCP + UDP
- Dung lượng: 173 KB
```

---

### **Task 2: Parse UDP Packets (Phân tích gói UDP)**

**UDP là gì?**
- Loại giao thức mạng (như TCP nhưng đơn giản hơn)
- Dùng cho: DNS queries, video call, online games (không cần đảm bảo gói đến)
- Không có "kết nối" (không handshake như TCP)

**Làm gì?**
```python
udp_parser.py pcap_files/captured_packets.pcap
    ↓
Đọc file pcap, tìm gói UDP
    ↓
Trích xuất:
  - Source IP + Port
  - Destination IP + Port
  - Kích thước gói
  - Loại protocol (DNS, DHCP, mDNS...)
    ↓
Lưu vào: udp_analysis.json
```

**Output ví dụ:**
```json
{
  "total_packets": 96,
  "connections": {
    "10.0.0.1:5353 → 224.0.0.251:5353": {
      "protocol": "mDNS",
      "packets": 8,
      "total_bytes": 2000
    }
  }
}
```

**Ý nghĩa:** Bạn biết được có bao nhiêu UDP packets, từ đâu đến đâu, để làm gì

---

### **Task 3: Extract HTTP Requests (Trích HTTP)**

**HTTP là gì?**
- Giao thức để browse web
- GET request = "Ê, lấy trang web cho tôi"
- HTTP response = "Vâng, đây là trang web của bạn"

**Làm gì?**
```python
http_extractor.py pcap_files/captured_packets.pcap
    ↓
Đọc gói TCP, tìm HTTP request/response
    ↓
Trích xuất:
  - HTTP method (GET, POST, HEAD...)
  - URL/Path (/index.html, /api/users...)
  - Headers (Host, User-Agent, Content-Length...)
  - Status code (200 OK, 404 Not Found...)
    ↓
Lưu vào: http_requests.json, http_responses.json
```

**Output ví dụ:**
```json
[
  {
    "method": "GET",
    "path": "/",
    "host": "google.com",
    "full_url": "http://google.com/",
    "headers": {
      "Host": "google.com",
      "User-Agent": "curl/7.68.0"
    }
  }
]
```

**Ý nghĩa:** Bạn thấy được trang nào được truy cập, cách truy cập

---

### **Task 4: Visualize Packet Flow (Vẽ sơ đồ gói)**

**Làm gì?**
```python
packet_visualizer.py pcap_files/captured_packets.pcap
    ↓
Vẽ ASCII diagram:
    
    Máy bạn               Server
        |                   |
        |-----> SYN ------->| (Bạn yêu cầu kết nối)
        |                   |
        |<---- SYN-ACK <----|  (Server chấp nhận)
        |                   |
        |-----> ACK ------->| (Xác nhận)
        |                   |
        |-----> DATA ------>| (Gửi dữ liệu)
        |<----- DATA <------|  (Nhận dữ liệu)
        |                   |
        |-----> FIN ------->| (Đóng kết nối)
        |<----- FIN <-------|
        |
    
    ↓
Thống kê:
  - Bao nhiêu gói TCP
  - Bao nhiêu gói UDP  
  - Top 10 sources (máy gửi nhiều nhất)
  - Top 10 conversations (cặp máy nói chuyện)
    ↓
Lưu vào: sequence_diagram.txt, packet_flow_analysis.json
```

**Output ví dụ:**
```
Traffic by Protocol:
  TCP: 439 packets, 115 KB
  UDP: 96 packets, 49 KB

Top Conversations:
  140.82.114.21 ← → 10.0.106.178: 64 packets
  10.0.106.178 ← → 104.18.32.47: 24 packets
```

**Ý nghĩa:** Bạn thấy bức tranh toàn cảnh - máy nào nói chuyện với máy nào, bao nhiêu dữ liệu

---

### **Task 5: Detect TCP Retransmissions (Phát hiện gói gửi lại)**

**Retransmission là gì?**
- Khi gói bị mất hoặc bị trễ, TCP sẽ gửi lại
- Dấu hiệu: Sequence number (SEQ) giống nhau

**Ví dụ:**
```
Lần 1: Gửi SEQ:1000 (gói có dữ liệu)
       ... chờ ACK (xác nhận)...
       Hết timeout, không nhận được ACK
       
Lần 2: Gửi lại SEQ:1000 (cùng dữ liệu)
       Lần này nhận được ACK
       
→ Này là 1 retransmission!
```

**Làm gì?**
```python
retransmission_detector.py pcap_files/captured_packets.pcap
    ↓
Tìm gói có SEQ + Payload giống nhau
    ↓
Phát hiện:
  - Retransmissions (gói gửi lại)
  - Out-of-order packets (gói đến không theo thứ tự)
  - Duplicate ACKs (gửi xác nhận lặp lại)
    ↓
Tính RTO (Retransmission Timeout)
    ↓
Lưu vào: tcp_anomalies.json
```

**Output ví dụ:**
```json
{
  "total_packets": 439,
  "retransmissions_count": 3,
  "out_of_order_count": 2,
  "duplicate_acks_count": 1
}
```

**Ý nghĩa:** Bạn phát hiện network có vấn đề hay không

---

## 🎬 FLOW TỔNG QUÁT

```
Lab 3.1 Workflow:
┌─────────────────────────────────────────────────────────┐
│ 1. CAPTURE                                              │
│    capture_packets.py                                   │
│    → Bắt gói từ network                                 │
│    → Output: captured_packets.pcap                      │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 2. PARSE & ANALYZE (4 script chạy song song)            │
├──────────────────┬──────────────────┬──────────────────┤
│ udp_parser.py    │ http_extractor   │ retransmission   │
│ → UDP analysis   │ → HTTP requests  │ → TCP anomalies  │
│ → JSON output    │ → JSON output    │ → JSON output    │
└──────────────────┴──────────────────┴──────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 3. VISUALIZE                                            │
│    packet_visualizer.py                                 │
│    → Vẽ sequence diagram                                │
│    → Traffic analysis                                   │
│    → JSON output + ASCII diagram                        │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ OUTPUT: 7 files JSON + ASCII                            │
│ - captured_packets.pcap (raw data)                      │
│ - udp_analysis.json                                     │
│ - http_requests.json + http_responses.json              │
│ - tcp_anomalies.json                                    │
│ - packet_flow_analysis.json                             │
│ - sequence_diagram.txt (visual)                         │
└─────────────────────────────────────────────────────────┘
```

---

## 📊 KẾT QUẢ BẠN VỪA CHẠY

### **Thống kê:**
```
Total Packets: 535
├─ TCP: 439 packets (115 KB)
└─ UDP: 96 packets (49 KB)

Top Talkers:
├─ 10.0.106.178 (Your PC): 275 packets
├─ 140.82.114.21 (GitHub): 64 packets
├─ 137.117.182.202: 50 packets
└─ ...

Anomalies:
├─ Retransmissions: 0
├─ Out-of-order: 0
└─ Duplicate ACKs: 0
   → Network bình thường ✓
```

### **HTTP:**
```
HTTP Requests: 2
HTTP Responses: 2
→ Có website được truy cập
```

### **Sequence Diagram:**
```
Vẽ ra hàng trăm kết nối TCP
Cho thấy:
- Máy A → Máy B gửi cái gì
- Máy B → Máy A gửi cái gì
- Lúc nào kết nối, lúc nào đóng
```

---

## 🔍 DÙNG KẾT QUẢ ĐỂ LÀM GÌ?

### **1. Network Security (Bảo mật)**
```
- Phát hiện traffic lạ
- Phát hiện malware communicate
- Phát hiện DDoS attack
```

### **2. Network Debugging (Sửa lỗi mạng)**
```
- Tại sao website chậm?
  → Xem có retransmission không
  
- Tại sao ping cao?
  → Xem out-of-order packets
  
- Tại sao mất kết nối?
  → Xem duplicate ACKs
```

### **3. Network Monitoring (Giám sát)**
```
- Thống kê traffic mỗi ngày
- Xem user nào dùng bandwidth nhiều
- Xem protokol nào được dùng nhiều
```

### **4. Learning (Học tập)**
```
- Hiểu TCP/UDP hoạt động thế nào
- Hiểu HTTP request/response
- Hiểu DNS, DHCP, mDNS là gì
```

---

## 🛠️ CÔNG CỤ CHÍNH

| Tool | Mục đích | Input | Output |
|------|---------|-------|--------|
| `capture_packets.py` | Bắt gói | Mạng | `.pcap` |
| `udp_parser.py` | Phân tích UDP | `.pcap` | `JSON` |
| `http_extractor.py` | Trích HTTP | `.pcap` | `JSON` |
| `retransmission_detector.py` | Phát hiện TCP | `.pcap` | `JSON` |
| `packet_visualizer.py` | Vẽ sơ đồ | `.pcap` | `JSON` + `TXT` |

---

## 💻 CHẠY LẠI VỨA DỄ

Lần sau chỉ cần:

**Cách 1 (Dễ nhất):**
```powershell
# Double-click file run.bat
run.bat
```

**Cách 2:**
```powershell
C:\Users\phttr\AppData\Local\Programs\Python\Python310\python.exe test_lab3.py
```

**Cách 3 (Chạy từng bước):**
```powershell
# Bước 1: Capture
python capture_packets.py

# Bước 2: Analyze
python udp_parser.py pcap_files/captured_packets.pcap
python http_extractor.py pcap_files/captured_packets.pcap
python retransmission_detector.py pcap_files/captured_packets.pcap
python packet_visualizer.py pcap_files/captured_packets.pcap
```

---

## ❓ CÂU HỎI THƯỜNG GẶP

### **Q: Packet là gì?**
A: Đơn vị dữ liệu nhỏ được gửi qua mạng. Ví dụ: khi bạn gửi tin nhắn, nó được chia thành nhiều packet, gửi đi, rồi server ghép lại.

### **Q: Tại sao phải capture?**
A: Để nhìn thấy cái gì đang xảy ra "dưới vỏ" của internet. Bạn sẽ thấy máy tính bạn nói chuyện với ai, cách nó nói.

### **Q: UDP vs TCP khác gì?**
A:
- **TCP**: Đảm bảo gói đến đủ, đúng thứ tự (slow nhưng safe)
- **UDP**: Không đảm bảo (fast nhưng có thể mất gói)

### **Q: Retransmission là lỗi?**
A: Không. TCP sẽ tự động gửi lại nếu gói bị mất. Nhưng nếu quá nhiều retransmission → network có vấn đề.

### **Q: Làm sao biết network tốt hay xấu?**
A:
- ✓ **Tốt:** Ít retransmission, ít out-of-order, ít duplicate ACKs
- ✗ **Xấu:** Nhiều anomalies, ping cao, chậm

---

## 🎓 TÓM TẮT

```
Lab 3.1 dạy bạn:
✓ Mạng hoạt động thế nào (packets)
✓ Cách capture và phân tích gói
✓ TCP/UDP hoạt động khác nhau
✓ HTTP là gì
✓ Cách phát hiện network issues
✓ Cách dùng Python + Scapy
✓ Cách đọc và phân tích JSON data
```

**Mục tiêu cuối cùng:** Bạn có thể phân tích bất kỳ traffic mạng nào và nói được:
- "Traffic này từ đâu?"
- "Nó dùng cái gì?"
- "Network bình thường không?"

---

**Giờ bạn hiểu Lab 3.1 rồi! 🎉**

Nếu có câu hỏi gì, cứ hỏi nhé!
