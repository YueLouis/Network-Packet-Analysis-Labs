# Task 5: Detect Anomalies

## 🎯 Mục đích
Phát hiện TCP retransmissions (gói tin truyền lại) - dấu hiệu packet loss

## 📁 Files

### `retransmission_detector.py`
**Chạy:**
```bash
python retransmission_detector.py ../Task1_Capture/pcap_files/captured_packets.pcap
```

**Input:** PCAP file  
**Output:**
- `../outputs/retransmissions.json`
- Console: Summary statistics

**Làm gì:**
- Track TCP sequence numbers
- Detect duplicate seq numbers
- Calculate retransmission rate
- Identify problematic connections

---

## 📊 Output Example

```json
{
  "total_tcp_packets": 150,
  "retransmissions": 5,
  "retransmission_rate": 3.33,
  "affected_connections": [
    {
      "src_ip": "192.168.1.100",
      "src_port": 54321,
      "dst_ip": "93.184.216.34",
      "dst_port": 80,
      "retransmitted_count": 3,
      "seq_numbers": [1000, 1000, 1000]
    }
  ]
}
```

---

## 🔍 How It Works

1. **Track TCP packets** in each connection (src_ip:port → dst_ip:port)
2. **Monitor sequence numbers** for duplicates
3. **Flag retransmissions** when same seq appears 2+ times
4. **Calculate metrics:**
   - Total retransmissions
   - Retransmission rate (%)
   - Top affected connections

---

## ⚠️ High Retransmission = Network Problem

- **> 1%:** Minor issues (acceptable)
- **> 5%:** Moderate problems
- **> 10%:** Serious network degradation

**Causes:**
- Packet loss
- Network congestion
- Firewall dropping packets
- Weak WiFi signal

---

## ✅ Final Step
Check `../outputs/` folder for all results!
