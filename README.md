# 🛡️ ThreatLens

ThreatLens is a lightweight Streamlit cybersecurity reputation checker for **IP addresses, domains, and URLs**.

It uses **VirusTotal**, **WHOIS**, and **Google Gemini** to collect and explain security intelligence.

## Features
- Analyze IP addresses, domains, and URLs
- Safe, Suspicious, Malicious, or Unknown verdict
- 0–100 risk score
- VirusTotal detection statistics
- WHOIS registration and domain-age signals
- Gemini explanations for Beginner, Intermediate, and Expert users
- API keys entered in the Streamlit UI and not stored in the repository
- Extensible source registry architecture

## Run

```bash
pip install -r requirements.txt
streamlit run app.py
```

Enter your VirusTotal and Gemini API keys in the sidebar after the app opens.

## Architecture

```
app.py  --->  sources.py
```

Each intelligence provider is implemented as one function in `sources.py` and registered in `SOURCES`. The UI and orchestration loop are generic.

## Security

ThreatLens does not directly visit submitted URLs. Results are security signals rather than absolute guarantees. VirusTotal detections can contain false positives, lack of detections does not guarantee safety, and WHOIS registration characteristics alone do not prove maliciousness.
