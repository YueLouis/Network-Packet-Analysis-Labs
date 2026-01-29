# 📚 LAB 3.2: AI-POWERED PACKET DISSECTORS - GIẢI THÍCH

## 🎯 Lab 3.2 là gì?

Dùng **AI (Large Language Model)** để **tự động tạo code** phân tích gói tin, thay vì viết thủ công.

### Ví dụ đơn giản:

**Trước đây:**
```python
# Bạn phải tự viết dissector - mất 2-3 giờ
class CustomProtocol(Packet):
    fields_desc = [
        ByteField("version", 0),
        ShortField("length", 0),
        IntField("sequence", 0),
        StrLenField("data", "", length_from=lambda x: x.length),
    ]
    # ... hàng trăm dòng code nữa
```

**Bây giờ (với AI):**
```python
# AI tạo dissector trong 5 giây
packets = rdpcap("custom_protocol.pcap")
code = create_dissector_with_ai("CustomProtocol", packets)
# → Xong! AI đã tạo sẵn code
```

---

## 🤖 Công nghệ sử dụng

### **Groq AI**
- LLM provider (như ChatGPT nhưng nhanh hơn, rẻ hơn)
- Model: `llama-3.1-8b-instant`
- Free tier: 30 requests/phút
- Đăng ký: https://console.groq.com/

### **OpenAI SDK**
- Python library để gọi API
- Compatible với Groq
- Dễ dùng

---

## 💡 Tại sao cần AI?

### Problem: Viết dissector rất khó

```
1. Phải đọc RFC specification (hàng trăm trang)
2. Phải hiểu binary format
3. Phải map bytes → fields
4. Phải handle edge cases
5. Phải test với nhiều packets
```

→ **Mất hàng giờ, dễ sai**

### Solution: AI làm hộ

```
1. Cho AI xem sample packets
2. AI phân tích patterns
3. AI generate dissector code
4. Bạn verify & use
```

→ **Mất vài giây, 90% chính xác**

---

## 📋 3 CHỨC NĂNG CHÍNH

### **1. Generate Dissector (Tạo dissector tự động)**

#### Làm gì?
Cho AI xem vài packets mẫu → AI tạo complete dissector code

#### Input:
```python
protocol_name = "HTTP"
sample_packets = [packet1, packet2, packet3]  # Vài packets mẫu
rfc_reference = "RFC 2616"  # Optional
```

#### Process:
```
1. Convert packets → hex format
2. Gửi lên Groq AI với prompt:
   "Analyze these packets, create dissector"
3. AI phân tích:
   - Tìm patterns
   - Identify fields
   - Determine types
4. AI generate Python code
5. Save to file
```

#### Output:
```python
# http_dissector.py
class HTTP(Packet):
    name = "HTTP"
    fields_desc = [
        StrField("method", "GET"),
        StrField("path", "/"),
        StrField("version", "HTTP/1.1"),
        # ... complete dissector
    ]
    
    def extract_padding(self, s):
        return "", s
```

#### Ví dụ thực tế:
```python
# Load HTTP packets
http_packets = rdpcap("http.pcap")

# Generate dissector
code, filename = create_dissector_with_ai(
    protocol_name="HTTP",
    sample_packets=http_packets[:10],  # First 10 packets
    rfc_reference="RFC 2616"
)

print(f"Saved to: {filename}")
# → http_dissector.py created!
```

---

### **2. Smart Field Extraction (Trích xuất field thông minh)**

#### Làm gì?
Bạn mô tả field bằng **tiếng Anh bình thường** → AI tìm và trích xuất

#### Ví dụ:

**Traditional way:**
```python
# Bạn phải biết:
# - TCP sequence ở byte offset nào?
# - Length bao nhiêu bytes?
# - Format gì (big/little endian)?

seq = struct.unpack(">I", packet_bytes[4:8])[0]
# Phức tạp!
```

**AI way:**
```python
# Chỉ cần mô tả bằng tiếng Anh
result = smart_field_extraction(
    packet, 
    "TCP sequence number"  # ← Natural language!
)

# AI trả lời:
# Offset: 4 bytes
# Length: 4 bytes  
# Value: 12345
# Format: Big-endian unsigned int
```

#### AI Response Example:
```
Field: TCP Sequence Number

1. Byte Offset: 4-7 (0x04-0x07)
   Located immediately after Source/Dest ports

2. Field Length: 4 bytes (32 bits)

3. Extracted Value:
   - Hex: 0x00003039
   - Decimal: 12345
   
4. Explanation:
   The TCP sequence number is a 32-bit field used to track
   the order of segments. It starts at byte 4 of the TCP header,
   stored in big-endian format (network byte order).
```

#### Use cases:
- Học tập: "Tìm cho tôi field X ở đâu?"
- Debugging: "Extract giá trị của Y"
- Reverse engineering: "Field này là gì?"

---

### **3. Analyze Unknown Protocol (Phân tích protocol lạ)**

#### Làm gì?
Cho AI xem packets của protocol chưa biết → AI đoán cấu trúc

#### Ví dụ:

Bạn capture được packets từ một game/app lạ:
```
Packet 1: DEAD 01 00 00000040 00000001 [data...]
Packet 2: DEAD 01 00 00000080 00000002 [data...]
Packet 3: DEAD 01 01 00000100 00000003 [data...]
```

Gọi AI:
```python
packets = rdpcap("mystery.pcap")
analysis = analyze_unknown_protocol(
    packets,
    protocol_hint="binary protocol with header"
)
```

AI phân tích:
```
Protocol Analysis:

1. Protocol Type: Binary (non-text based)

2. Likely Header Structure (12 bytes):
   Offset 0-1: Magic bytes (0xDEAD)
              → Always constant, likely signature
              
   Offset 2:   Version (0x01)
              → Protocol version
              
   Offset 3:   Flags (0x00 or 0x01)
              → Control flags, appears to toggle
              
   Offset 4-7: Length field (big-endian)
              → Values: 64, 128, 256
              → Likely payload length
              
   Offset 8-11: Sequence number
              → Increments: 1, 2, 3, ...
              → Packet ordering

3. Common Patterns:
   - All packets start with 0xDEAD (signature)
   - Sequence numbers always increment
   - Length varies but always power of 2

4. Suggested Scapy Definition:
   class CustomProtocol(Packet):
       name = "CustomProto"
       fields_desc = [
           ShortField("magic", 0xDEAD),
           ByteField("version", 1),
           ByteField("flags", 0),
           IntField("length", 0),
           IntField("sequence", 0),
       ]
       
       def guess_payload_class(self, payload):
           # Add payload detection logic
           return Packet.guess_payload_class(self, payload)

5. Recommendations:
   - Verify magic bytes check: magic == 0xDEAD
   - Add payload length validation
   - Implement sequence number tracking
```

#### Use cases:
- Reverse engineering malware protocols
- Analyzing proprietary protocols
- Game protocol research
- IoT device communication

---

## 🎬 WORKFLOW TỔNG QUÁT

```
┌─────────────────────────────────────────────┐
│  1. Bạn có packets cần phân tích            │
│     (PCAP file hoặc live capture)           │
└─────────────────────┬───────────────────────┘
                      ↓
┌─────────────────────────────────────────────┐
│  2. Chọn AI function:                       │
│     A. Generate dissector                   │
│     B. Extract field                        │
│     C. Analyze unknown protocol             │
└─────────────────────┬───────────────────────┘
                      ↓
┌─────────────────────────────────────────────┐
│  3. AI Processing:                          │
│     • Convert packets to hex                │
│     • Build prompt with context             │
│     • Call Groq API (llama-3.1-8b)          │
│     • Parse AI response                     │
└─────────────────────┬───────────────────────┘
                      ↓
┌─────────────────────────────────────────────┐
│  4. Output:                                 │
│     • Python dissector code                 │
│     • Field extraction details              │
│     • Protocol structure analysis           │
└─────────────────────┬───────────────────────┘
                      ↓
┌─────────────────────────────────────────────┐
│  5. Bạn verify & use                        │
│     • Check code correctness                │
│     • Test with more packets                │
│     • Integrate vào workflow                │
└─────────────────────────────────────────────┘
```

---

## 📊 SO SÁNH: Manual vs AI

| Aspect | Manual Dissector | AI-Generated |
|--------|------------------|--------------|
| **Time** | 2-8 hours | 5-30 seconds |
| **Difficulty** | High (need RFC knowledge) | Easy (just provide samples) |
| **Accuracy** | 100% (if done right) | ~90% (needs verification) |
| **Learning Curve** | Steep | Gentle |
| **Cost** | Free (your time) | API cost (~$0.001/request) |
| **Flexibility** | Full control | Limited by AI |
| **Offline** | ✅ Works | ❌ Needs internet |

---

## 🎓 KHI NÀO DÙNG?

### ✅ Dùng AI khi:
1. **Prototype nhanh** - Cần dissector ASAP
2. **Protocol phức tạp** - Nhiều fields, khó parse
3. **Học tập** - Muốn hiểu protocol works như thế nào
4. **Reverse engineering** - Unknown protocol
5. **Time constraint** - Không có thời gian viết manual

### ❌ KHÔNG dùng AI khi:
1. **Production critical** - Cần 100% accuracy
2. **Performance critical** - AI call chậm
3. **Sensitive data** - Privacy concerns (data gửi lên Groq)
4. **Offline work** - Không có internet
5. **Protocol đã có** - Scapy đã support sẵn

---

## 🔧 SETUP & RUN

### Step 1: Install
```bash
pip install scapy openai
```

### Step 2: Get Groq API Key
```
1. https://console.groq.com/
2. Sign up (free)
3. Create API key
4. Copy key: gsk_...
```

### Step 3: Set API Key
```powershell
# Windows
$env:GROQ_API_KEY='gsk_your_key_here'

# Linux/Mac
export GROQ_API_KEY='gsk_your_key_here'
```

### Step 4: Run
```bash
python ai_dissector.py
```

---

## 💻 CODE EXAMPLES

### Example 1: Generate HTTP Dissector
```python
from scapy.all import rdpcap
from ai_dissector import create_dissector_with_ai

# Load packets
packets = rdpcap("http.pcap")

# Generate
code, file = create_dissector_with_ai(
    "HTTP", 
    packets[:10], 
    "RFC 2616"
)

print(f"Saved to: {file}")
```

### Example 2: Extract TCP Flags
```python
from scapy.all import IP, TCP
from ai_dissector import smart_field_extraction

# Create packet
pkt = IP()/TCP(flags="S")

# Extract
result = smart_field_extraction(
    pkt, 
    "TCP flags field - what is SYN flag value?"
)

print(result)
```

### Example 3: Analyze Custom Protocol
```python
from ai_dissector import analyze_unknown_protocol

packets = rdpcap("mystery.pcap")
analysis = analyze_unknown_protocol(
    packets, 
    "binary protocol"
)

print(analysis)
```

---

## ⚠️ LƯU Ý QUAN TRỌNG

### 1. Privacy
- Packets được gửi lên Groq API
- **KHÔNG dùng với sensitive data**
- Groq có thể log requests

### 2. Accuracy
- AI ~90% chính xác
- **LUÔN verify code** trước khi dùng production
- Test với nhiều packets

### 3. Cost
- Groq free tier: 30 req/min
- Sau đó: ~$0.001/request
- Rất rẻ nhưng cần track usage

### 4. Rate Limits
- Free tier có giới hạn
- Nếu quá limit → chờ 1 phút
- Hoặc upgrade plan

---

## 🎯 LEARNING OUTCOMES

Sau Lab 3.2, bạn sẽ:
- ✅ Hiểu cách AI analyze packets
- ✅ Biết integrate LLM vào tools
- ✅ Tự động hóa packet analysis
- ✅ Reverse engineer protocols
- ✅ Tiết kiệm thời gian development

---

## 📚 KẾT LUẬN

**Lab 3.2 = AI + Networking**

```
Traditional: Human writes dissector (slow, hard)
Modern:     AI generates dissector (fast, easy)

→ Future: AI-assisted network engineering
```

**Key Takeaway:**
> AI không thay thế network engineer, nhưng giúp engineer làm việc nhanh hơn 10x

---

**Questions? Check:**
- [README.md](README.md) - Full documentation
- [QUICKSTART.md](QUICKSTART.md) - Quick start guide
- [examples.py](examples.py) - Code examples

---

**Lab 3.2 - Network Programming (NPRO)**
