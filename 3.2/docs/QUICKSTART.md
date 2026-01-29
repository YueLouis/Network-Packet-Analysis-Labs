# 🚀 Lab 3.2: QUICKSTART

## ⚡ 3 Bước Bắt Đầu

### 1️⃣ Install
```bash
pip install scapy openai
```

### 2️⃣ Get API Key (FREE)
1. Vào: https://console.groq.com/
2. Sign up
3. Tạo API key (free tier: 30 requests/min)

### 3️⃣ Run
```powershell
# Set API key
$env:GROQ_API_KEY='gsk_your_key_here'

# Run
python ai_dissector.py
```

---

## 🎯 Lab 3.2 làm gì?

Dùng **AI** để tự động tạo code phân tích gói tin (packet dissector)

**Trước:** Viết dissector mất vài giờ ⏰  
**Giờ:** AI tạo trong vài giây ⚡

---

## 📋 3 Chức Năng

### 1. **Generate Dissector** 
```python
# Input: Sample packets
# Output: Complete dissector code

packets = rdpcap("my_protocol.pcap")
code = create_dissector_with_ai("MyProtocol", packets)
```

### 2. **Smart Field Extraction**
```python
# Input: Packet + field description (natural language)
# Output: Field location, value, explanation

packet = IP()/TCP(seq=12345)
result = smart_field_extraction(packet, "TCP sequence number")
# → AI tells you: offset, length, value
```

### 3. **Analyze Unknown Protocol**
```python
# Input: Unknown packets
# Output: Protocol structure analysis

packets = rdpcap("mystery.pcap")
analysis = analyze_unknown_protocol(packets)
# → AI suggests: field structure, types, patterns
```

---

## 💡 Ví Dụ Nhanh

### Generate HTTP Dissector
```bash
python ai_dissector.py
# Choose: 1
# File: http.pcap
# Protocol: HTTP
# RFC: RFC 2616
```

**Output:** `http_dissector.py`
```python
class HTTP(Packet):
    fields_desc = [
        StrField("method", "GET"),
        StrField("path", "/"),
        # ...
    ]
```

---

## 🔧 Menu Options

```
1. Generate dissector from PCAP file
   → Tạo dissector tự động

2. Extract field from packet
   → Trích xuất field (natural language)

3. Analyze unknown protocol
   → Phân tích protocol lạ

4. Demo with sample packets
   → Chạy demo tất cả tính năng

5. Exit
```

---

## 📊 Khi nào dùng?

| Scenario | Use AI? |
|----------|---------|
| Protocol mới | ✅ Yes |
| Reverse engineering | ✅ Yes |
| Học tập | ✅ Yes |
| Production critical | ❌ No (verify manually) |
| Offline work | ❌ No (needs internet) |

---

## ⚠️ Lưu ý

1. **API Key:** Cần Groq API key (free)
2. **Internet:** Cần kết nối để call API
3. **Privacy:** Packets gửi lên Groq (không dùng với data nhạy cảm)
4. **Accuracy:** AI ~90% đúng → luôn kiểm tra code

---

## 🎓 Học được gì?

- ✅ Dùng AI trong networking
- ✅ Tự động hóa packet analysis
- ✅ Reverse engineer protocols
- ✅ LLM integration

---

## 🔗 Links

- [Groq Console](https://console.groq.com/) - Get API key
- [Lab 3.2 README](README.md) - Chi tiết
- [Examples](examples.py) - Code examples

---

**Bắt đầu ngay:** `python ai_dissector.py` 🚀
