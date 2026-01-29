# Task 3: Extract HTTP Requests/Responses

## 🎯 Mục đích
Trích xuất HTTP requests và responses từ TCP payload

## 📁 Files

### `http_extractor.py`
**Chạy:**
```bash
python http_extractor.py ../Task1_Capture/pcap_files/captured_packets.pcap
```

**Input:** PCAP file  
**Output:**
- `../outputs/http_requests.json`
- `../outputs/http_responses.json`

**Làm gì:**
- Scan TCP packets
- Detect HTTP methods (GET, POST, HEAD, etc.)
- Extract: method, path, host, headers
- Extract HTTP responses (status code, reason)
- Export JSON

---

## 📊 Output Example

### Requests:
```json
[
  {
    "method": "GET",
    "path": "/",
    "host": "example.com",
    "full_url": "http://example.com/",
    "headers": {
      "Host": "example.com",
      "User-Agent": "curl/7.68.0"
    }
  }
]
```

### Responses:
```json
[
  {
    "status_code": 200,
    "reason": "OK",
    "headers": {
      "Content-Type": "text/html",
      "Content-Length": "1256"
    }
  }
]
```

---

## 🔍 Detected Methods

- GET
- POST
- HEAD
- PUT
- DELETE
- CONNECT

---

## ➡️ Next Step
Sang **Task 4: Visualize Packet Flow**
