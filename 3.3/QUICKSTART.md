# Lab 3.3: ML Protocol Classifier - QUICKSTART

## ⚡ 3 Bước Chạy Ngay

### Bước 1: Cài đặt
```bash
pip install -r requirements.txt
```

### Bước 2: Chạy
```bash
python protocol_classifier.py
```

### Bước 3: Xem kết quả
```
[✓] Training complete! Accuracy: 100.00%

Test 1 - HTTP packet:
  Predicted: HTTP (confidence: 95.23%)

Test 2 - SSH packet:
  Predicted: SSH (confidence: 98.15%)

Test 3 - DNS packet:
  Predicted: DNS (confidence: 96.78%)
```

---

## 🧠 ML Model

- **Algorithm:** Random Forest (100 trees)
- **Features:** 8 packet statistics
- **Classes:** HTTP, SSH, DNS
- **Accuracy:** ~95-100% on test data

---

## 🎯 Use Cases

### 1. Train on Synthetic Data (Demo)
```python
from protocol_classifier import ProtocolClassifier, create_synthetic_packets

classifier = ProtocolClassifier()
packets, labels = create_synthetic_packets()
classifier.train(packets, labels)
```

### 2. Train on Real PCAP Files
```python
from scapy.all import rdpcap

http = rdpcap('http.pcap')[:100]
ssh = rdpcap('ssh.pcap')[:100]
dns = rdpcap('dns.pcap')[:100]

packets = http + ssh + dns
labels = ['HTTP']*100 + ['SSH']*100 + ['DNS']*100

classifier.train(packets, labels)
```

### 3. Predict Protocol
```python
from scapy.all import IP, TCP, Raw

packet = IP()/TCP(dport=80)/Raw(load=b'GET / HTTP/1.1\r\n')
result = classifier.predict(packet)

print(result)
# {'protocol': 'HTTP', 'confidence': 0.95}
```

### 4. Save/Load Model
```python
# Save
classifier.save_model('my_model.pkl')

# Load
classifier.load_model('my_model.pkl')
result = classifier.predict(packet)
```

---

## 📊 8 Features Extracted

1. **Packet size** - Total bytes
2. **Has TCP** - 1 or 0
3. **Has UDP** - 1 or 0
4. **Source port** - 0-65535
5. **Dest port** - 0-65535
6. **Payload length** - Bytes
7. **First byte** - Payload[0]
8. **Avg byte** - Average payload value

---

## 🚀 Performance

- **Training:** ~0.1 seconds (300 packets)
- **Prediction:** ~0.001 seconds per packet
- **Batch prediction:** ~10x faster

**Batch Example:**
```python
results = classifier.predict_batch(packets)  # Fast!
```

---

## 📚 Full Documentation

See [README.md](README.md) for detailed API reference and examples.
