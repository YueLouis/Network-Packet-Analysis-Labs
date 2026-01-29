# Network Packet Analysis Labs

Complete suite of 4 labs covering network packet analysis - from basic parsing to AI-powered dissectors and ML classification.

## 📚 Labs Overview

| Lab | Name | Technologies | Level |
|-----|------|--------------|-------|
| [3.1](3.1/) | Basic Packet Parser | Scapy | ⭐⭐ |
| [3.2](3.2/) | AI-Powered Dissectors | Groq LLM + Scapy | ⭐⭐⭐ |
| [3.3](3.3/) | ML Protocol Classifier | Random Forest + Scapy | ⭐⭐⭐⭐ |
| [3.4](3.4/) | Real-time Analyzer | Python + Scapy | ⭐⭐⭐⭐⭐ |

---

## 🚀 Quick Start

### Install Dependencies
```bash
# Lab 3.1
cd 3.1
pip install -r requirements.txt

# Lab 3.2
cd 3.2
pip install -r requirements.txt

# Lab 3.3
cd 3.3
pip install -r requirements.txt

# Lab 3.4
cd 3.4
pip install -r requirements.txt
```

### Run Labs
```bash
# Lab 3.1: Basic Packet Parser
cd 3.1/tools
python main_analysis.py

# Lab 3.2: AI-Powered Dissectors
cd 3.2/examples
python examples.py

# Lab 3.3: ML Protocol Classifier
cd 3.3
python protocol_classifier.py

# Lab 3.4: Real-time Analyzer
cd 3.4
python simple_analyzer.py
```

---

## 📖 Lab Details

### [Lab 3.1: Basic Packet Parser](3.1/)
**Learn packet capture and parsing fundamentals**

**5 Tasks:**
- Task 1: Capture packets from network
- Task 2: Parse UDP packets
- Task 3: Extract HTTP requests/responses
- Task 4: Visualize packet flows
- Task 5: Detect TCP retransmissions

**Tech Stack:** Scapy, Python

---

### [Lab 3.2: AI-Powered Dissectors](3.2/)
**Use AI (Groq LLM) to auto-generate packet dissectors**

**⚠️ Requires API Key:** Get free API key from [Groq Console](https://console.groq.com/keys)

**3 Functions:**
- `create_dissector_with_ai()` - Generate dissector code
- `smart_field_extraction()` - Extract protocol fields
- `analyze_unknown_protocol()` - Analyze unknown protocols

**Setup:**
```bash
# Set API key (required!)
export GROQ_API_KEY=your_key_here

# Run examples
cd 3.2/examples
python examples.py
```

**Tech Stack:** Groq API (llama-3.1-8b-instant), Scapy

---

### [Lab 3.3: ML Protocol Classifier](3.3/)
**Machine Learning for automatic protocol identification**

**Features:**
- Extract 8 statistical features from packets
- Train Random Forest classifier (100 trees)
- Predict protocol with confidence scores
- Save/Load trained models
- Batch prediction support

**Tech Stack:** Scikit-learn, Scapy

---

### [Lab 3.4: Real-time Analyzer](3.4/)
**High-speed packet analysis**

**Features:**
- Fast single-threaded analyzer (~3000 pps)
- Real-time statistics (pps, Mbps)
- Protocol distribution analysis
- Application detection (HTTP, SSH, DNS, DHCP)
- JSON export

**Tech Stack:** Python, Scapy

---

## 🎯 Learning Path

**Recommended order:**
```
3.1 (Basics) → 3.2 (AI) → 3.3 (ML) → 3.4 (Real-time)
```

**By goal:**
- **Learn Scapy basics:** Start with Lab 3.1
- **Learn AI/LLM integration:** Lab 3.2
- **Learn Machine Learning:** Lab 3.3
- **Learn Performance optimization:** Lab 3.4

---

## 🛠️ Requirements

| Tool | Version | Required For |
|------|---------|--------------|
| Python | 3.7+ | All labs |
| Scapy | 2.5.0+ | All labs |
| OpenAI SDK | 2.16.0+ | Lab 3.2 only |
| Scikit-learn | 1.3.0+ | Lab 3.3 only |

**Install all dependencies:**
```bash
pip install scapy scikit-learn openai numpy
```

---

## 📁 Repository Structure

```
network-packet-analysis-labs/
├── 3.1/                      # Basic Packet Parser
│   ├── Task1_Capture/
│   ├── Task2_UDP/
│   ├── Task3_HTTP/
│   ├── Task4_Visualize/
│   ├── Task5_Detect_Anomalies/
│   ├── outputs/
│   └── tools/
│
├── 3.2/                      # AI-Powered Dissectors
│   ├── core/
│   ├── examples/
│   ├── generated/
│   └── docs/
│
├── 3.3/                      # ML Protocol Classifier
│   ├── protocol_classifier.py
│   ├── README.md
│   └── QUICKSTART.md
│
├── 3.4/                      # Real-time Analyzer
│   ├── simple_analyzer.py
│   ├── README.md
│   └── QUICKSTART.md
│
└── README.md                 # This file
```

---

## 🎓 What You'll Learn

### Lab 3.1
- ✅ Scapy packet manipulation
- ✅ TCP/UDP protocol parsing
- ✅ HTTP extraction techniques
- ✅ Network flow visualization
- ✅ Anomaly detection

### Lab 3.2
- ✅ LLM API integration
- ✅ AI-powered code generation
- ✅ Protocol reverse engineering
- ✅ Dynamic dissector creation

### Lab 3.3
- ✅ Feature engineering for packets
- ✅ Random Forest classification
- ✅ Model training & evaluation
- ✅ Protocol fingerprinting

### Lab 3.4
- ✅ High-performance packet processing
- ✅ Real-time metrics calculation
- ✅ Protocol detection optimization
- ✅ Statistics aggregation

---

## 🔗 Integration Ideas

**Combine multiple labs:**

1. **3.1 + 3.3:** Train ML model on Lab 3.1 captured packets
2. **3.1 + 3.4:** Use 3.4 for high-speed capture, 3.1 for detailed analysis
3. **3.2 + 3.3:** Use AI to generate features for ML model
4. **3.3 + 3.4:** Apply ML classification in real-time analyzer

---

## 🏆 Project Ideas

### 1. Network Intrusion Detection System
- Lab 3.4: Real-time capture
- Lab 3.3: Protocol classification
- Lab 3.1: Anomaly detection

### 2. Protocol Analyzer Tool
- Lab 3.2: Unknown protocol analysis
- Lab 3.3: Automatic classification
- Lab 3.1: Detailed parsing

### 3. Network Performance Monitor
- Lab 3.4: High-speed analysis
- Lab 3.1: Flow visualization
- Lab 3.3: Traffic categorization

---

## 📝 Documentation

Each lab includes:
- ✅ **README.md** - Detailed documentation
- ✅ **QUICKSTART.md** - Quick reference guide
- ✅ **requirements.txt** - Python dependencies
- ✅ **run.bat** - Windows quick launch script

---

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest new features
- Submit pull requests
- Improve documentation

---

## 📄 License

MIT License - Feel free to use for educational purposes

---

## 👨‍💻 Author

Network Programming Labs - January 2026

---

**Happy packet analyzing! 🚀**
