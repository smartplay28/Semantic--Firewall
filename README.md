# 🛡️ Semantic Firewall
> An Agentic LLM-Based Semantic Firewall for Safe & Privacy-Preserving AI Systems

**Status: 🚧 Work in Progress**

---

## What is this?
A multi-agent AI safety system that sits between user inputs and LLM outputs, inspecting prompts and responses for threats in real-time using both rule-based and LLM-powered detection.

---

## 5 Agents
| Agent | Method | Detects |
|---|---|---|
| 🔍 PII Detector | Regex | Aadhaar, PAN, emails, cards, phone numbers |
| 🔑 Secrets Detector | Regex | API keys, tokens, DB credentials |
| 💥 Abuse Detector | Stats | DoS, path traversal, script injection |
| 💉 Injection Detector | LLM | Prompt injection, jailbreaks, role overrides |
| ⚠️ Unsafe Content | LLM | Violence, hate speech, illegal content |

---

## Quick Start
```bash
git clone https://github.com/smartplay28/Semantic--Firewall.git
cd Semantic--Firewall
pip install -r requirements.txt
```

Add your Groq API key to `.env`:
```
GROQ_API_KEY=your_key_here
```

```bash
# Run demo UI
streamlit run app.py

# Run REST API
python api.py

# Run tests
pytest tests/ -v
```

---

## Tech Stack
`Python` · `FastAPI` · `Streamlit` · `Groq (LLaMA 3.3 70B)` · `Plotly` · `Pytest`

---

*More updates coming soon.*
