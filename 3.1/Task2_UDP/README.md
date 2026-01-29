# Task 2: Parse UDP Packets

## 🎯 Mục đích
Phân tích các gói UDP (DNS, DHCP, mDNS, etc.)

## 📁 Files

### `udp_parser.py`
**Chạy:**
```bash
python udp_parser.py ../Task1_Capture/pcap_files/captured_packets.pcap
```

**Input:** PCAP file  
**Output:** `../outputs/udp_analysis.json`

**Làm gì:**
- Đọc file PCAP
- Filter UDP packets
- Phân tích: src_ip, dst_ip, ports, protocol
- Track UDP flows
- Export JSON

---

## 📊 Output Example

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

---

## 🔍 Protocols Detected

- **DNS** (port 53)
- **DHCP** (ports 67, 68)
- **NTP** (port 123)
- **mDNS** (port 5353)

---

## ➡️ Next Step
Sang **Task 3: Extract HTTP**
