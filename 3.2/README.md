# Lab 3.2: AI-Powered Protocol Dissectors

## 📂 Folder Structure

```
3.2/
├── core/                    ← 🧠 Main AI dissector engine
│   └── ai_dissector.py     (3 functions: create_dissector, extract_fields, analyze_unknown)
│
├── examples/                ← 📝 Usage examples
│   └── examples.py         (HTTP, DNS, TCP, Unknown protocol demos)
│
├── generated/               ← 🤖 AI-generated dissectors
│   ├── http_dissector.py
│   └── dns_dissector.py
│
├── docs/                    ← 📚 Documentation
│   ├── README.md           (Detailed guide)
│   ├── QUICKSTART.md       (Quick start)
│   └── TONG_KET.md         (Vietnamese summary)
│
├── README.md               ← You are here!
├── requirements.txt        ← Dependencies
├── run.bat                 ← Quick run AI dissector
└── run_examples.bat        ← Quick run examples
```

---

## 🚀 Quick Start

**Step 1: Get API Key**
- Visit [https://console.groq.com/keys](https://console.groq.com/keys)
- Sign up for free account
- Create API key

**Step 2: Set Environment Variable**
```bash
# Windows
set GROQ_API_KEY=your_key_here

# Linux/Mac
export GROQ_API_KEY=your_key_here
```

**Step 3: Install dependencies**
```bash
pip install openai scapy
```

**Step 4: Run examples**
```bash
# Windows
run_examples.bat

# Linux/Mac
chmod +x run_examples.sh
./run_examples.sh
```

---

## 🎯 Features

1. **AI-Generated Dissectors** - Use Groq LLM to auto-generate packet parsers
2. **Smart Field Extraction** - AI extracts unknown protocol fields
3. **Unknown Protocol Analysis** - Analyze mysterious protocols automatically

---

## 🔑 API Key Security

**NEVER commit API keys to Git!**

This lab uses environment variables to keep your API key secure:
- ✅ Set `GROQ_API_KEY` environment variable
- ✅ Use `.env` file (included in `.gitignore`)
- ❌ DO NOT hardcode API key in source code

See `.env.example` for template.

---

## 📊 3 Main Functions

| Function | Purpose | Input | Output |
|----------|---------|-------|--------|
| `create_dissector_with_ai()` | Generate dissector code | Protocol name | Python code |
| `smart_field_extraction()` | Extract fields using AI | Packet bytes | Field analysis |
| `analyze_unknown_protocol()` | Analyze unknown protocol | Packet bytes | Structure analysis |

---

## 📖 Full Documentation

See [docs/README.md](docs/README.md) for detailed usage, examples, and API reference.
