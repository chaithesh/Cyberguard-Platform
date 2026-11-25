# CyberGuard - Multi-Vector Phishing Detection & Security Platform

CyberGuard is a client-side, edge-first cybersecurity detection platform designed to detect social engineering, phishing, and scam attacks in real-time across multiple threat vectors without transmitting confidential user data to external servers.

---

## 🛡️ Key Features

- **📊 Risk Scores & Analytics Dashboard:** Real-time threat distribution breakdown, risk metrics aggregation, and persistent scan history using browser local storage.
- **🌐 URL & Domain Lexical Analyzer:** Shannon entropy calculation for DGA domain detection, Levenshtein distance brand typosquatting checks (28 target brands), Punycode `xn--` spoofing detection, raw IP host identification, and SSL/WHOIS heuristics.
- **✉️ Email Header & Content Inspector:** RFC 822 email header parser evaluating SPF, DKIM, and DMARC authentication records, Return-Path domain alignment spoof checks, and NLP psychological urgency trigger detection.
- **💬 SMS / SMiShing Detector:** Identifies postal re-delivery scams, bank lockout notices, and prize baits with automated shortened URL extraction and an interactive smartphone UI mockup.
- **📞 Fraud Phone Call (Vishing) Telemetry:** Reverse caller ID lookup, STIR/SHAKEN carrier attestation levels (A, B, C), call transcript threat NLP, and custom verified caller registration.
- **📷 QR Code & Image Forensics:** Quishing link inspection, EXIF metadata forensics, and HTML5 Canvas Error Level Analysis (ELA) compression variance heatmaps.
- **🧠 Explainable AI (XAI) Lab:** Tri-class threat probabilities (Legitimate, Suspicious, Phishing) with SHAP-style feature attribution breakdown and adversarial URL perturbation testing.

---

## 🚀 Quick Start

### Prerequisites
- [Node.js](https://nodejs.org/) (v16.0.0 or higher)
- npm (v7.0.0 or higher)

### Installation & Run

1. **Clone the repository:**
   ```bash
   git clone https://github.com/chaithesh/Cyberguard-Platform.git
   cd Cyberguard-Platform
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the application:**
   - **Standard Mode:**
     ```bash
     npm start
     ```
   - **Development Mode (Hot Reload):**
     ```bash
     npm run dev
     ```

4. **Access the application:**
   The server will launch automatically at:
   ```
   http://localhost:3000
   ```

---

## 🔒 Privacy & Architecture
CyberGuard utilizes a **Zero-Knowledge Edge Computing** model. All lexical algorithms, cryptographic header evaluations, and forensic canvas computations run locally in the client's browser sandbox, ensuring user emails, phone logs, and URLs are never leaked to cloud databases.
