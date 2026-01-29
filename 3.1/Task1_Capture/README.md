# Task 1: Capture Packets

## 🎯 Mục đích
Bắt gói tin từ network khi truy cập websites

## 📁 Files

### `capture_packets.py` (Khuyến khích - Cross-platform)
**Chạy:**
```bash
python capture_packets.py
```

**Input:** Không cần  
**Output:** `pcap_files/captured_packets.pcap`

**Làm gì:**
- Truy cập các websites (google.com, github.com, etc.)
- Capture tất cả TCP/UDP packets
- Lưu vào file .pcap

---

### `capture.sh` (Linux/Mac only)
**Chạy:**
```bash
bash capture.sh
```

**Input:** Không cần  
**Output:** `pcap_files/captured_packets.pcap`

**Làm gì:**
- Dùng `tcpdump` để capture
- Dùng `curl` để truy cập websites

---

## ⚙️ Options

### Windows
```powershell
python capture_packets.py
```

### Linux/Mac với tcpdump
```bash
sudo bash capture.sh
```

---

## 📊 Output Example

```
pcap_files/captured_packets.pcap
- Size: ~173 KB
- Packets: ~535 packets
- Protocols: TCP, UDP
- Duration: ~20 seconds
```

---

## ➡️ Next Step
Sau khi có file PCAP, sang **Task 2: Parse UDP**
