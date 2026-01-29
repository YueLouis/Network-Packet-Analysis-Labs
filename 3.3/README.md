# Lab 3.3: ML-Based Protocol Classification

## 🎯 Mục đích
Sử dụng Machine Learning (Random Forest) để tự động nhận diện protocol từ đặc điểm của packet (size, ports, payload).

---

## 🚀 Quick Start

**Step 1: Install dependencies**
```bash
pip install -r requirements.txt
```

**Step 2: Run classifier**
```bash
# Windows
run.bat

# Linux/Mac
python protocol_classifier.py
```

---

## 📊 How It Works

### 1. Feature Extraction (8 features)
```python
1. Packet size
2. Has TCP layer (0/1)
3. Has UDP layer (0/1)
4. Source port
5. Destination port
6. Payload length
7. First payload byte
8. Average payload byte value
```

### 2. Training
```python
classifier = ProtocolClassifier(n_estimators=100)
classifier.train(packets, labels)
```

### 3. Prediction
```python
result = classifier.predict(packet)
# {'protocol': 'HTTP', 'confidence': 0.95}
```

---

## 🧠 ML Model: Random Forest

- **Algorithm:** Random Forest Classifier
- **Trees:** 100 estimators
- **Features:** 8 statistical features
- **Classes:** HTTP, SSH, DNS (expandable)

**Why Random Forest?**
- Fast training & prediction
- Handles non-linear relationships
- Robust to overfitting
- Good for multi-class classification

---

## 📝 Example Output

```
[*] Extracting features from 300 packets...
[*] Training Random Forest with 3 classes...
    Classes: HTTP, SSH, DNS
[✓] Training complete! Accuracy: 100.00%

[*] Testing predictions...

Test 1 - HTTP packet:
  Predicted: HTTP (confidence: 95.23%)
  Probabilities: {'HTTP': 0.95, 'SSH': 0.03, 'DNS': 0.02}

Test 2 - SSH packet:
  Predicted: SSH (confidence: 98.15%)
  Probabilities: {'HTTP': 0.01, 'SSH': 0.98, 'DNS': 0.01}

Test 3 - DNS packet:
  Predicted: DNS (confidence: 96.78%)
  Probabilities: {'HTTP': 0.02, 'SSH': 0.01, 'DNS': 0.97}
```

---

## 🔧 API Reference

### ProtocolClassifier

**Methods:**
- `extract_features(packet)` - Extract 8 features from packet
- `train(packets, labels)` - Train on labeled packets
- `predict(packet)` - Predict protocol for single packet
- `predict_batch(packets)` - Predict for multiple packets (faster)
- `save_model(filepath)` - Save trained model to disk
- `load_model(filepath)` - Load trained model from disk
- `evaluate(test_packets, test_labels)` - Evaluate on test set

---

## 📚 Training Data

**Option 1: Synthetic Data (Default)**
```python
packets, labels = create_synthetic_packets()
# Creates 300 packets: 100 HTTP, 100 SSH, 100 DNS
```

**Option 2: Real PCAP Files**
```python
http_pkts = rdpcap('http.pcap')[:100]
ssh_pkts = rdpcap('ssh.pcap')[:100]
dns_pkts = rdpcap('dns.pcap')[:100]

all_pkts = http_pkts + ssh_pkts + dns_pkts
labels = ['HTTP']*100 + ['SSH']*100 + ['DNS']*100

classifier.train(all_pkts, labels)
```

---

## 💾 Save/Load Model

```python
# Save
classifier.save_model('protocol_classifier.pkl')

# Load
classifier.load_model('protocol_classifier.pkl')
result = classifier.predict(packet)
```

---

## 📈 Performance Tips

1. **More training data = better accuracy**
   - Use 1000+ packets per class
   
2. **Balance classes**
   - Equal number of samples per protocol
   
3. **Use real PCAP files**
   - Synthetic data is for demo only
   
4. **Batch prediction**
   - Use `predict_batch()` for multiple packets (10x faster)

---

## 🎓 What You'll Learn

- ✅ Feature engineering for network packets
- ✅ Random Forest classification
- ✅ Model training & evaluation
- ✅ Scikit-learn API usage
- ✅ Protocol fingerprinting techniques

---

## 🔗 Related Labs

- **Lab 3.1** - Basic packet parsing (data source)
- **Lab 3.2** - AI-powered dissectors (complementary)
- **Lab 3.4** - Real-time analysis (apply ML here)
