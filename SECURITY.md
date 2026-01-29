# Security Best Practices

## ✅ API Key Management

### DO:
- ✅ Use environment variables
- ✅ Use `.env` file (add to `.gitignore`)
- ✅ Use secret management services (for production)
- ✅ Rotate keys periodically

### DON'T:
- ❌ Hardcode API keys in source code
- ❌ Commit API keys to Git
- ❌ Share API keys in screenshots/logs
- ❌ Use same key for dev and production

---

## 🔒 Lab 3.2 Security

### Current Implementation

**Environment Variable:**
```python
# ai_dissector.py
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not GROQ_API_KEY:
    print("ERROR: GROQ_API_KEY not set!")
    sys.exit(1)
```

**How to use:**
```bash
# Windows
set GROQ_API_KEY=your_key_here
python examples.py

# Linux/Mac
export GROQ_API_KEY=your_key_here
python examples.py

# Using .env file
cp .env.example .env
# Edit .env and add your key
python examples.py
```

---

## 🎓 Why This Matters

**Bad practice (hardcoded):**
```python
API_KEY = "gsk_abc123xyz..."  # ❌ Anyone with code sees your key!
```

**Good practice (environment variable):**
```python
API_KEY = os.getenv("GROQ_API_KEY")  # ✅ Key is separate from code
```

**Benefits:**
1. **Security:** Keys not in source code
2. **Flexibility:** Different keys for dev/prod
3. **Team work:** Each developer uses their own key
4. **Compliance:** Follows industry standards

---

## 📚 References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [12-Factor App: Config](https://12factor.net/config)
- [GitHub: Removing sensitive data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
