# 🛡️ ThreatLens

### Lightweight Cybersecurity Reputation Checker powered by VirusTotal, WHOIS & Google Gemini

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-App-red)](https://streamlit.io/)
[![VirusTotal](https://img.shields.io/badge/Intelligence-VirusTotal-blue)](https://www.virustotal.com/)
[![License](https://img.shields.io/badge/Status-Testing-orange)](#project-status)

> **ThreatLens** analyzes an **IP address, domain, or URL** using VirusTotal and WHOIS intelligence, calculates a transparent risk assessment, and uses Google Gemini to explain the collected evidence at the user's knowledge level.

## 🚀 Live Testing Demo

**Try ThreatLens:** https://threatlens-test.streamlit.app/

> The public deployment is currently provided for **testing and demonstration**. Users enter their own VirusTotal and Gemini API keys in the app sidebar. Keys are used for the running session and are not stored in this repository.

## ✨ What ThreatLens Does

ThreatLens provides a simple interface for checking common reputation and registration signals without requiring users to interpret raw threat-intelligence data themselves.

- 🔎 Analyze **IP addresses, domains, and URLs**
- 🛡️ Collect reputation data from **VirusTotal**
- 🌐 Inspect domain registration information with **WHOIS**
- 📊 Produce a **0–100 risk score**
- 🚦 Show **Safe, Suspicious, Malicious, or Unknown** assessments
- 🤖 Generate evidence-based explanations with **Google Gemini**
- 🎓 Adapt explanations for **Beginner, Intermediate, and Expert** users
- 🔐 Accept API keys through the Streamlit UI instead of hardcoding credentials
- 🧩 Support future intelligence sources through a small registry-based architecture

## 🧠 How It Works

```text
User
  │
  ▼
Streamlit UI (app.py)
  │
  ├── Validate IP / Domain / URL
  │
  ▼
SOURCES registry (sources.py)
  │
  ├── VirusTotal
  └── WHOIS
  │
  ▼
Standardized source results
  │
  ├── Verdict
  ├── Risk score
  ├── Summary
  └── Raw intelligence
  │
  ▼
Overall assessment
  │
  ▼
Gemini explanation
```

The dependency direction is intentionally simple:

```text
app.py  ─────►  sources.py
```

Each intelligence provider is implemented as **one source function** and registered in `SOURCES`. The Streamlit orchestration loops over that registry, which keeps provider-specific logic out of the UI.

## 🧩 Project Structure

```text
ThreatLens/
├── app.py
├── sources.py
├── requirements.txt
├── README.md
└── .gitignore
```

### `sources.py`

Contains input validation, VirusTotal integration, WHOIS lookup logic, standardized result handling, and the `SOURCES` registry.

### `app.py`

Contains the Streamlit interface, generic source orchestration, overall risk aggregation, Gemini prompt/call, and results display.

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| Python 3.10+ | Application language |
| Streamlit | Web UI and deployment |
| VirusTotal API | Reputation and detection intelligence |
| python-whois | Domain registration intelligence |
| Google Gemini | Explanation of collected security evidence |
| Requests | HTTP communication |

## ⚙️ Run Locally

Clone the repository:

```bash
git clone https://github.com/sabirprogrammer/ThreatLens.git
cd ThreatLens
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start ThreatLens:

```bash
streamlit run app.py
```

Open the Streamlit URL shown in your terminal and enter your **VirusTotal API key** and **Gemini API key** in the sidebar.

## 🔑 API Keys

ThreatLens requires:

1. A **VirusTotal API key** for reputation intelligence.
2. A **Google Gemini API key** for AI-generated explanations.

API keys should **never be committed to GitHub**. The current application asks for them through password-style fields in the Streamlit sidebar.

The included `.gitignore` excludes common secret files such as `.env` and `.streamlit/secrets.toml`.

## 🧪 Example Workflow

```text
Target Type: URL
Target: https://example.com/
Knowledge Level: Beginner
                ↓
       VirusTotal Analysis
                +
          WHOIS Analysis
                ↓
       Overall Risk Score
                ↓
       Gemini Explanation
```

For URLs, ThreatLens checks the URL with VirusTotal and extracts its hostname for domain WHOIS analysis.

## 🧱 Extensible Source Design

A core goal of ThreatLens is making future integrations easy. A source returns a standard dictionary:

```python
{
    "source": "Source Name",
    "status": "success",
    "verdict": "safe",
    "summary": "Human-readable result",
    "risk_score": 10,
    "data": {},
    "error": None
}
```

A new intelligence source can follow the same contract and be registered in `SOURCES`, while the main orchestration continues to iterate over registered sources generically.

## 🔒 Security & Privacy

ThreatLens is designed as an intelligence checker rather than a URL crawler. It does **not directly visit submitted URLs** as part of its analysis flow.

API credentials are not hardcoded in the repository. Users provide their own credentials through the running application.

ThreatLens intentionally presents evidence and limitations because threat-intelligence results are not absolute guarantees.

## ⚠️ Limitations

- A **Safe** result does not guarantee that a target is harmless.
- VirusTotal detections can contain **false positives**.
- A lack of VirusTotal detections does not prove a target is safe.
- WHOIS privacy or missing fields can be legitimate.
- A new domain is not automatically malicious.
- An old domain is not automatically trustworthy.
- Results depend on intelligence available at the time of analysis.
- Gemini explains collected evidence; it is not the authoritative source of the verdict.

## 📌 Project Status

**Testing / Demo**

The current Streamlit deployment is intended for testing, portfolio demonstration, and continued development:

**https://threatlens-test.streamlit.app/**

## 👨‍💻 Author

**Sanaullah Sabir**  
GitHub: [@sabirprogrammer](https://github.com/sabirprogrammer)

---

If you find ThreatLens useful, consider giving the repository a ⭐.
