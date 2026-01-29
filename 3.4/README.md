# Lab 3.4: Real-time High-Performance Packet Analysis

## 🎯 Mục đích
Phân tích packets real-time với tốc độ cao sử dụng multiprocessing (nhiều CPU cores).

---

## 🚀 Quick Start

**Step 1: Install dependencies**
```bash
pip install -r requirements.txt
```

**Step 2: Run analyzer**
```bash
# Windows - Live capture
run.bat

# Windows - Analyze PCAP file
run.bat captured_packets.pcap

# Linux/Mac - Live capture
python realtime_analyzer.py

# Linux/Mac - Analyze PCAP file
python realtime_analyzer.py captured_packets.pcap
```

---

## 🏗️ Architecture

```
┌─────────────┐
│ Packet      │
│ Capture     │
└──────┬──────┘
       │
       ▼
┌─────────────────────────┐
│   Packet Queue          │
│   (Max: 10,000 packets) │
└─────────┬───────────────┘
          │
    ┌─────┴─────┬─────────┬─────────┐
    ▼           ▼         ▼         ▼
┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
│Worker 0│ │Worker 1│ │Worker 2│ │Worker 3│
└────┬───┘ └────┬───┘ └────┬───┘ └────┬───┘
     │          │          │          │
     └──────────┴──────────┴──────────┘
                 │
                 ▼
          ┌──────────────┐
          │ Results      │
          │ Queue        │
          └──────────────┘
```

---

## ⚡ Performance Features

### 1. Multi-Process Architecture
- **4 worker processes** (configurable)
- Each worker runs on separate CPU core
- Parallel packet analysis

### 2. Queue-Based Processing
- **10,000 packet buffer**
- Non-blocking packet insertion
- Drop packets if queue full (backpressure)

### 3. Real-time Statistics
- Packets/second (pps)
- Megabits/second (Mbps)
- Protocol distribution
- Processing time

---

## 📊 Sample Output

```
====================================================================
Lab 3.4: Real-time High-Performance Packet Analysis
====================================================================

[*] Starting 4 worker processes...
[Worker 0] Started
[Worker 1] Started
[Worker 2] Started
[Worker 3] Started
[✓] All workers started

[*] Capturing 1000 packets...

[*] Stopping workers...
[✓] All workers stopped

============================================================
Performance Statistics
============================================================
Duration:           5.23 seconds
Packets processed:  1,000
Bytes processed:    845,632 bytes
Throughput:         191.20 packets/sec
Bandwidth:          1.29 Mbps

Protocol Distribution:
  TCP:    654
  UDP:    321
  Other:  25

Detailed Protocol Counts:
  TCP       : 654
  UDP       : 321
  OTHER     : 25
============================================================
```

---

## 🔧 API Reference

### HighPerformanceAnalyzer

**Constructor:**
```python
analyzer = HighPerformanceAnalyzer(num_workers=4)
```

**Methods:**
- `start()` - Start worker processes
- `stop()` - Stop all workers
- `process_packet(packet)` - Add packet to queue
- `get_stats()` - Get performance metrics
- `print_stats()` - Print statistics
- `save_stats(filepath)` - Save to JSON
- `collect_results(max_results)` - Get analysis results

---

## 📈 Performance Benchmarks

| Workers | Packets/sec | Speedup |
|---------|-------------|---------|
| 1       | ~50 pps     | 1x      |
| 2       | ~95 pps     | 1.9x    |
| 4       | ~180 pps    | 3.6x    |
| 8       | ~320 pps    | 6.4x    |

*Tested on Intel i7-8700K (6 cores, 12 threads)*

---

## 🎛️ Configuration

### Adjust Number of Workers
```python
# More workers = faster (up to CPU core count)
analyzer = HighPerformanceAnalyzer(num_workers=8)
```

### Queue Size
```python
# Modify in source code
self.packet_queue = mp.Queue(maxsize=20000)  # Larger buffer
```

---

## 💡 Use Cases

### 1. Live Network Monitoring
```python
live_capture_demo(interface='eth0', count=10000)
```

### 2. PCAP File Analysis
```python
pcap_file_demo('large_capture.pcap')
```

### 3. High-Speed Intrusion Detection
```python
analyzer = HighPerformanceAnalyzer(num_workers=8)
analyzer.start()

def detect_threats(packet):
    analyzer.process_packet(packet)

sniff(prn=detect_threats, store=False)
```

---

## 📊 Packet Analysis

Each packet is analyzed for:
- **Protocol** (TCP/UDP/Other)
- **Ports** (source/destination)
- **Flags** (TCP flags)
- **Application** (HTTP, HTTPS, SSH, DNS, DHCP)
- **IP addresses** (source/destination)

---

## 🔥 Performance Tips

1. **Use all CPU cores**
   - Set `num_workers` = number of CPU cores
   
2. **Disable packet storage**
   - Use `store=False` in `sniff()`
   
3. **Filter early**
   - Use BPF filter: `sniff(filter="tcp port 80")`
   
4. **Batch processing**
   - Process multiple packets before checking results

---

## ⚠️ Limitations

- **Queue overflow:** Drops packets if queue full
- **Memory usage:** 10,000 packets × avg size ≈ 60 MB
- **CPU intensive:** Uses 100% of all cores
- **No packet reassembly:** Analyzes individual packets only

---

## 🎓 What You'll Learn

- ✅ Python multiprocessing module
- ✅ Queue-based architecture
- ✅ Shared memory with Manager
- ✅ Process synchronization
- ✅ Real-time performance metrics
- ✅ High-speed packet processing

---

## 🔗 Related Labs

- **Lab 3.1** - Basic packet parsing (foundation)
- **Lab 3.3** - ML classification (integrate here)
- **Lab 3.2** - AI dissectors (apply to unknown protocols)
