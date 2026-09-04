# ⚡ Phishing Threat Detector

[![Live Web Demo](https://img.shields.io/badge/Live_App-Vercel-black?style=for-the-badge&logo=vercel)](https://phishing-detector-web.vercel.app)
[![Portfolio Hub](https://img.shields.io/badge/Portfolio_Hub-Live-blue?style=for-the-badge)](https://portfolio-showcase-hub-web11.vercel.app)

🔗 **Production URL:** [https://phishing-detector-web.vercel.app](https://phishing-detector-web.vercel.app)  
🌐 **Showcase Hub:** [https://portfolio-showcase-hub-web11.vercel.app](https://portfolio-showcase-hub-web11.vercel.app)

---

## 📌 Architectural Overview
Lexical URL scanner and threat-intel classifier evaluating Punycode homograph typo-squatting, FQDN Shannon entropy, and SSL validity.

---

## 🛠️ Technology Ecosystem
* **Core Architecture:** FastAPI, tldextract, Cryptography, Python
* **Testing & Quality:** PyTest, Automated GitHub Actions CI
* **Deployment:** Vercel Edge Runtime

---

## 🛡️ Production Standards
* **Route Path Alignment:** Standardized contract on `/api/v1/phishing/scan`.
* **Explainability Attribution:** Outputs broken down by individual security threat signals.
* **Robust Parser:** Handles internationalized domain names and malformed URL structures without raising unhandled exceptions.

---

## 🚀 API Contracts
```http
POST /api/v1/phishing/scan
Request:
{
  "url": "[http://secure-login.paypa1-update.com/account/verify](http://secure-login.paypa1-update.com/account/verify)"
}

Response (200 OK):
{
  "url": "[http://secure-login.paypa1-update.com/account/verify](http://secure-login.paypa1-update.com/account/verify)",
  "phishing_score": 0.942,
  "verdict": "MALICIOUS",
  "signals": {
    "homograph_detected": true,
    "shannon_entropy": 4.32,
    "missing_ssl": true
  }
}

GET /health
Response: {"status": "healthy"}

💻 Local Quickstart

Bash

pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000
pytest tests/ -v