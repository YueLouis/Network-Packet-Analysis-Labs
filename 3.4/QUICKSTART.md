# Lab 3.4: Real-time Analyzer - QUICKSTART

## ⚡ 3 Bước Chạy Ngay

### Bước 1: Cài đặt
```bash
pip install -r requirements.txt
```

### Bước 2: Chọn chế độ

**Option A: Live Capture**
```bash
python realtime_analyzer.py
```

**Option B: Analyze PCAP File**
```bash
python realtime_analyzer.py captured_packets.pcap
```

### Bước 3: Xem kết quả
```
Duration:           5.23 seconds
Packets processed:  1,000
Throughput:         191.20 packets/sec
Bandwidth:          1.29 Mbps

Protocol Distribution:
  TCP:    654
  UDP:    321
  Other:  25
```

---

## 🏗️ Architecture

```
Packet Capture
    ↓
Queue (10,000 buffer)
    ↓
4 Worker Processes (parallel)
    ↓
Results + Statistics
```

---

## ⚡ Why It's Fast

1. **Multiprocessing** - Uses all CPU cores
2. **Queue-based** - Non-blocking packet insertion
3. **Parallel analysis** - 4 workers process simultaneously
4. **No storage** - Analyze on-the-fly

---

## 🎯 Quick Examples

### Example 1: Live Capture (100 packets)
```python
from realtime_analyzer import live_capture_demo

live_capture_demo(count=100)
```

### Example 2: Analyze PCAP File
```python
from realtime_analyzer import pcap_file_demo

pcap_file_demo('captured_packets.pcap')
```

### Example 3: Custom Configuration
```python
from realtime_analyzer import HighPerformanceAnalyzer

# 8 workers for high-speed networks
analyzer = HighPerformanceAnalyzer(num_workers=8)
analyzer.start()

# Process packets
def handler(pkt):
    analyzer.process_packet(pkt)

sniff(prn=handler, count=10000)

analyzer.stop()
analyzer.print_stats()
```

---

## 📊 Performance Comparison

| Mode | Speed | Use Case |
|------|-------|----------|
| Single-threaded | ~50 pps | Basic analysis |
| 4 workers | ~180 pps | Medium traffic |
| 8 workers | ~320 pps | High-speed networks |

*pps = packets per second*

---

## 🔧 Configuration

### Adjust Workers
```python
# More workers = faster (up to CPU cores)
analyzer = HighPerformanceAnalyzer(num_workers=8)
```

### Filter Packets
```python
# Only capture TCP port 80
sniff(prn=handler, filter="tcp port 80")
```

---

## 💾 Save Statistics

Statistics are automatically saved to `performance_stats.json`:
```json
{
  "packets_processed": 1000,
  "duration_seconds": 5.23,
  "packets_per_second": 191.20,
  "megabits_per_second": 1.29,
  "protocol_distribution": {
    "TCP": 654,
    "UDP": 321
  }
}
```

---

## 🎓 What It Analyzes

For each packet:
- ✅ Protocol (TCP/UDP)
- ✅ Ports (source/dest)
- ✅ Application (HTTP, HTTPS, SSH, DNS, DHCP)
- ✅ IP addresses
- ✅ TCP flags

---

## 📚 Full Documentation

See [README.md](README.md) for detailed architecture, API reference, and performance tips.
