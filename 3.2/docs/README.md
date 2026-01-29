# Lab 3.2: AI-Powered Packet Dissectors

## 🎯 Mục đích

Sử dụng **AI (LLM)** để tự động tạo code phân tích gói tin (packet dissector) thay vì phải viết thủ công.

## 🤖 Công nghệ

- **Groq AI** - LLM API (llama-3.1-8b-instant)
- **Scapy** - Packet manipulation
- **OpenAI SDK** - Compatible với Groq

## � Setup API Key

**IMPORTANT:** This lab requires a Groq API key. DO NOT hardcode it in source code!

### Get Free API Key
1. Go to [https://console.groq.com/keys](https://console.groq.com/keys)
2. Sign up (free tier: 30 requests/minute)
3. Create API key

### Set Environment Variable

**Windows:**
```bash
set GROQ_API_KEY=your_key_here
```

**Linux/Mac:**
```bash
export GROQ_API_KEY=your_key_here
```

**Permanent (add to ~/.bashrc or ~/.zshrc):**
```bash
echo 'export GROQ_API_KEY=your_key_here' >> ~/.bashrc
source ~/.bashrc
```

### Using .env file (Optional)
```bash
# Copy example
cp .env.example .env

# Edit .env and add your key
GROQ_API_KEY=your_actual_key_here
```

## �💡 Tại sao dùng AI?

### Trước đây (Manual):
```python
# Phải tự viết dissector - mất nhiều giờ
class MyProtocol(Packet):
    fields_desc = [
        ByteField("version", 0),
        ShortField("length", 0),
        IntField("sequence", 0),
        # ... hàng trăm dòng code
    ]
```

### Bây giờ (AI):
```python
# AI tự generate dissector trong vài giây
code = create_dissector_with_ai("MyProtocol", sample_packets)
# → Tạo hoàn chỉnh dissector code
```

## 📋 3 Chức năng chính

### 1. **Generate Dissector** - Tạo dissector tự động
```python
create_dissector_with_ai(protocol_name, sample_packets, rfc_reference)
```

**Input:**
- Protocol name (e.g., "HTTP", "DNS")
- Sample packets (để AI phân tích)
- RFC reference (optional)

**Output:**
- Complete Python dissector code
- Ready to use với Scapy

**Ví dụ:**
```python
http_packets = rdpcap("http.pcap")
code, file = create_dissector_with_ai("HTTP", http_packets, "RFC 2616")
# → Tạo file: http_dissector.py
```

---

### 2. **Smart Field Extraction** - Trích xuất field thông minh
```python
smart_field_extraction(packet, field_description)
```

**Input:**
- Packet (Scapy object)
- Natural language description (e.g., "TCP sequence number")

**Output:**
- Byte offset
- Field length
- Extracted value
- Explanation

**Ví dụ:**
```python
packet = IP()/TCP(seq=12345)
result = smart_field_extraction(packet, "TCP sequence number")

# AI trả về:
# 1. Offset: 4 bytes (sau TCP header start)
# 2. Length: 4 bytes
# 3. Value: 0x00003039 (12345 decimal)
# 4. Explanation: Located at bytes 4-7 of TCP header
```

---

### 3. **Analyze Unknown Protocol** - Phân tích protocol lạ
```python
analyze_unknown_protocol(packets, protocol_hint)
```

**Input:**
- Packets chứa protocol không rõ
- Hint (optional, e.g., "binary", "text-based")

**Output:**
- Protocol type (binary/text)
- Suggested field structure
- Common patterns
- Scapy field definitions

**Ví dụ:**
```python
unknown_packets = rdpcap("mystery.pcap")
analysis = analyze_unknown_protocol(unknown_packets, "binary protocol")

# AI phân tích:
# - Protocol type: Binary
# - Header: 12 bytes
#   - Bytes 0-1: Magic number (0xABCD)
#   - Bytes 2-3: Version (0x0001)
#   - Bytes 4-7: Length
#   - Bytes 8-11: Checksum
# - Suggested Scapy code: ...
```

## 🚀 Cài đặt

### 1. Install dependencies
```bash
pip install scapy openai
```

### 2. Get Groq API Key
1. Đi tới: https://console.groq.com/
2. Sign up (free)
3. Tạo API key

### 3. Set API key
```powershell
# Windows PowerShell
$env:GROQ_API_KEY='your-groq-api-key-here'

# Hoặc edit trong file ai_dissector.py
GROQ_API_KEY = "your-key-here"
```

## 💻 Sử dụng

### Cách 1: Interactive Menu
```bash
python ai_dissector.py
```

Menu options:
```
1. Generate dissector from PCAP file
2. Extract field from packet (smart extraction)
3. Analyze unknown protocol
4. Demo with sample packets
5. Exit
```

### Cách 2: Import vào code
```python
from ai_dissector import create_dissector_with_ai

# Load packets
packets = rdpcap("my_protocol.pcap")

# Generate dissector
code, filename = create_dissector_with_ai(
    protocol_name="MyProtocol",
    sample_packets=packets,
    rfc_reference="RFC 1234"
)

print(f"Dissector saved to: {filename}")
```

## 📊 Demo Examples

### Example 1: Generate HTTP Dissector
```bash
python ai_dissector.py
# Choose option 1
# Enter: http.pcap
# Protocol: HTTP
# RFC: RFC 2616
```

**Output:** `http_dissector.py`
```python
from scapy.all import Packet, StrField, IntField

class HTTP(Packet):
    name = "HTTP"
    fields_desc = [
        StrField("method", "GET"),
        StrField("path", "/"),
        StrField("version", "HTTP/1.1"),
        # ... more fields
    ]
    
    def extract_padding(self, s):
        return "", s
```

### Example 2: Smart Field Extraction
```bash
python ai_dissector.py
# Choose option 2
# Field: "TCP window size"
```

**AI Response:**
```
Field: TCP Window Size

1. Byte offset: 14-15 (0x0E-0x0F)
2. Field length: 2 bytes (16 bits)
3. Extracted value: 
   - Hex: 0x7210
   - Decimal: 29200
4. Explanation:
   The TCP window size is located at offset 14 in the TCP header,
   immediately after the checksum field. It's a 16-bit unsigned integer
   indicating the size of the receive window.
```

### Example 3: Analyze Unknown Protocol
```bash
python ai_dissector.py
# Choose option 3
# File: mystery.pcap
# Hint: binary protocol
```

**AI Analysis:**
```
Protocol Analysis:

1. Protocol Type: Binary (non-text based)

2. Likely Structure:
   Header (12 bytes):
   - Offset 0-1: Magic bytes (0xDEAD) - protocol signature
   - Offset 2: Version (0x01)
   - Offset 3: Flags (0x00)
   - Offset 4-7: Payload length (big-endian)
   - Offset 8-11: Sequence number

3. Common Patterns:
   - All packets start with 0xDEAD
   - Payload length varies: 64-1500 bytes
   - Sequence numbers increment by 1

4. Suggested Scapy Definition:
   class CustomProtocol(Packet):
       fields_desc = [
           ShortField("magic", 0xDEAD),
           ByteField("version", 1),
           ByteField("flags", 0),
           IntField("length", 0),
           IntField("sequence", 0),
       ]
```

## 🎓 Khi nào dùng?

### ✅ Dùng AI khi:
- Protocol mới, chưa có dissector
- Cần prototype nhanh
- Protocol phức tạp (nhiều fields)
- Reverse engineering unknown protocol
- Học tập, nghiên cứu

### ❌ Không dùng AI khi:
- Protocol đã có dissector trong Scapy
- Cần performance cao (AI chậm hơn)
- Production critical (AI có thể sai)
- Không có internet/API key

## 🔧 Troubleshooting

### Error: "GROQ_API_KEY not set"
```bash
# Set environment variable
$env:GROQ_API_KEY='gsk_...'

# Or edit ai_dissector.py:
GROQ_API_KEY = "gsk_..."
```

### Error: "Rate limit exceeded"
- Groq free tier: Limited requests/minute
- Wait 1 minute và retry
- Hoặc upgrade plan

### Error: "Invalid API key"
- Check key có đúng không
- Tạo key mới tại: https://console.groq.com/keys

### AI generates wrong code
- Thử với nhiều sample packets hơn (5-10)
- Cung cấp RFC reference
- Kiểm tra và sửa code manually

## 📚 So sánh với Manual

| Aspect | Manual | AI-Powered |
|--------|--------|------------|
| **Time** | Hours/Days | Seconds |
| **Accuracy** | High (if done right) | Good (90%+) |
| **Learning** | Steep curve | Easy |
| **Flexibility** | Full control | Limited by AI |
| **Cost** | Free | API cost (cheap) |

## 🎯 Learning Outcomes

Sau Lab 3.2, bạn sẽ:
- ✅ Hiểu cách dùng AI trong networking
- ✅ Tự động hóa phân tích packet
- ✅ Reverse engineer protocols
- ✅ Integrate LLM vào network tools
- ✅ Tiết kiệm thời gian phát triển

## 🔗 Resources

- [Groq Console](https://console.groq.com/)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [OpenAI Python SDK](https://github.com/openai/openai-python)
- [RFC Index](https://www.rfc-editor.org/)

## 📝 Notes

1. **API Cost:** Groq miễn phí nhưng có rate limit
2. **Privacy:** Packets gửi lên Groq API (không dùng với sensitive data)
3. **Accuracy:** AI ~90% chính xác, luôn verify code
4. **Offline:** Cần internet để call API

---

**Lab 3.2 - Network Programming (NPRO)**
