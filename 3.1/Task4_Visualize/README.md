# Task 4: Visualize Packet Flow

## 🎯 Mục đích
Tạo sequence diagram (sơ đồ tương tác) giữa các host trong network

## 📁 Files

### `packet_visualizer.py`
**Chạy:**
```bash
python packet_visualizer.py ../Task1_Capture/pcap_files/captured_packets.pcap
```

**Input:** PCAP file  
**Output:**
- `../outputs/tcp_sequence_diagram.txt`
- `../outputs/udp_sequence_diagram.txt`

**Làm gì:**
- Extract TCP flows
- Extract UDP flows
- Draw sequence diagram (text-based)
- Show: SYN, ACK, PSH, FIN flags
- Show packet direction (→)

---

## 📊 Output Example

### TCP Sequence Diagram:
```
192.168.1.100:54321 → 93.184.216.34:80 [SYN]
93.184.216.34:80 → 192.168.1.100:54321 [SYN-ACK]
192.168.1.100:54321 → 93.184.216.34:80 [ACK]
192.168.1.100:54321 → 93.184.216.34:80 [PSH-ACK] (HTTP Request)
93.184.216.34:80 → 192.168.1.100:54321 [PSH-ACK] (HTTP Response)
192.168.1.100:54321 → 93.184.216.34:80 [FIN-ACK]
93.184.216.34:80 → 192.168.1.100:54321 [FIN-ACK]
```

### UDP Sequence Diagram:
```
192.168.1.100:53128 → 8.8.8.8:53 (DNS Query)
8.8.8.8:53 → 192.168.1.100:53128 (DNS Response)
```

---

## 🔍 TCP Flags Explained

- `SYN`: Start connection
- `ACK`: Acknowledge
- `PSH`: Push data
- `FIN`: Close connection
- `RST`: Reset connection

---

## ➡️ Next Step
Sang **Task 5: Detect Anomalies**
