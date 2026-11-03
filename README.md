# sona-final-year-mini-it-aids-d-sarveshpk-15-145
> **StartupFair Hackathon**: Solo Participant 80 (Final Year Mini Project - IT / AI&DS Dept)

---

# 🛡️ PhishGuard-XR

**A Zero-Trust Multimodal Framework for Real-Time Browser Protection, Platt-Scaled Probability Calibration, and Privacy-Preserving Telemetry**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![Manifest V3](https://img.shields.io/badge/Chrome%20Extension-Manifest%20V3-orange.svg)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-teal.svg)](https://fastapi.tiangolo.com/)

---

## 📖 Overview

Modern phishing campaigns employ sophisticated evasive techniques such as Unicode homoglyph domain spoofing, dynamic DOM obfuscation, multi-stage credential harvesting, and fast-flux infrastructure rotation. Traditional browser extensions and scanners exhibit critical vulnerabilities:
1. **Uncalibrated Probability Output**: Inflated confidence scores cause alert fatigue in SOC environments.
2. **Post-Facto Detection Window**: Scanning asynchronously *after* page render allows attackers to steal credentials upon fast form submissions.
3. **Privacy Violations**: Raw URLs and DOM trees are transmitted to cloud servers without user consent.

**PhishGuard-XR** solves these challenges with an enterprise-grade, zero-trust live browser protection framework featuring:
- **Synchronous Pre-Submit Credential Guard**: Blocks credential exfiltration before network dispatch using capture-phase event listeners.
- **Platt-Scaled Multimodal Risk Engine**: Fuses DistilBERT NLP, MobileNetV2 Vision, DOM heuristics, and GraphSAGE infrastructure topology with an Expected Calibration Error ($\text{ECE} \le 0.024$).
- **Zero-PII Privacy Protocol**: Never reads input `.value` properties, user keystrokes, passwords, or cookies.
- **Multi-Channel Scanning Suite**: Live Webpage scanner, Optical QR Code scanner (*Quishing*), and SMS/Email urgency parser (*Smishing*).
- **Interactive Evidence-Grounded AI Security Assistant**: Real-time context-aware conversational assistant embedded in an isolated closed Shadow DOM overlay.

---

## 🏗️ System Architecture

```
                               ┌─────────────────────────────────────────────────────────┐
                               │             BROWSER EXTENSION (MANIFEST V3)             │
                               │                                                         │
                               │  ┌───────────────────────┐   ┌───────────────────────┐  │
                               │  │   domExtractor.js     │   │preSubmitInterceptor.js│  │
                               │  └───────────┬───────────┘   └───────────┬───────────┘  │
                               └──────────────│───────────────────────────│──────────────┘
                                              │ Zero-PII Features         │ Pre-Submit Freeze
                                              v                           v
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        STANDALONE BACKEND ENGINE (FASTAPI / PYTHON)                    │
│                                                                                        │
│  ┌───────────────────────┐  ┌───────────────────────┐  ┌────────────────────────────┐  │
│  │ Channel 1: URL NLP    │  │ Channel 2: Visual CNN │  │ Channel 3: DOM Structural  │  │
│  │ (DistilBERT Encoder)  │  │ (MobileNetV2 Brand)   │  │ (Form & Origin Heuristics) │  │
│  └───────────┬───────────┘  └───────────┬───────────┘  └─────────────┬──────────────┘  │
│              │                          │                            │                 │
│              └──────────────────────────┼────────────────────────────┘                 │
│                                         v                                              │
│                        ┌─────────────────────────────────┐                             │
│                        │ Softmax Attention Fusion Engine │                             │
│                        └────────────────┬────────────────┘                             │
│                                         v                                              │
│                        ┌─────────────────────────────────┐                             │
│                        │  Platt Logistic Calibration     │                             │
│                        │       (ECE <= 0.024)            │                             │
│                        └────────────────┬────────────────┘                             │
└─────────────────────────────────────────│──────────────────────────────────────────────┘
                                          │ Decision & Calibrated Risk Score (0-100)
                                          v
                               ┌──────────────────────────────────┐
                               │  SHADOW DOM OVERLAY & AI CHATBOT │
                               └──────────────────────────────────┘
```

---

## ✨ Key Features

| Feature | Description |
|:---|:---|
| **⚡ Synchronous Pre-Submit Guard** | Intercepts HTML form submission events in the capture phase. If a password form has an action origin mismatch ($O_{\text{page}} \neq O_{\text{action}}$), submission is halted synchronously before any HTTP packet leaves the device. |
| **🎯 Platt-Scaled Risk Calibration** | Maps raw deep-learning logit activations to calibrated probabilities ($P_{\text{calibrated}} = \frac{1}{1 + \exp(-2.45 z + 0.15)}$), bounding ECE $\le 0.024$ and Brier score to $0.018$. |
| **🔒 100% Zero-PII Privacy** | Enforces cryptographic privacy guarantees: extracts only derived DOM node counts and SHA-256 domain root hashes. Never inspects `.value` properties or session tokens. |
| **📷 Quishing & Smishing Scanner** | Multi-channel popup interface decoding QR codes via canvas-based optical Reed-Solomon recognition (`jsQR`) and parsing SMS/Email urgency patterns. |
| **🤖 Context-Aware AI Chatbot** | Built-in AI security assistant providing instant ($<10\text{ ms}$) answers to queries like *"Can I enter my details?"* or *"Why is this flagged?"* based on the page's evaluated risk posture. |
| **🛡️ Closed Shadow DOM Encapsulation** | Overlays threat alert cards inside `attachShadow({ mode: 'closed' })` to prevent malicious webpage scripts or CSS from hiding the warning. |

---

## 📂 Codebase Structure

```
Phishguard-XR/
├── phishguard-xr-extension/          # Manifest V3 Chrome Extension
│   ├── manifest.json                 # Extension manifest and permissions
│   ├── public/
│   │   ├── popup.html                # Multi-channel scanner popup UI
│   │   ├── popup.js                  # QR code decoder & SMS analyzer
│   │   └── icons/                    # Extension icon assets (16px, 48px, 128px)
│   └── src/
│       ├── background/
│       │   └── serviceWorker.js      # Background event router & badge controller
│       └── content/
│           ├── domExtractor.js       # Zero-PII DOM extractor & Chatbot UI
│           └── preSubmitInterceptor.js # Capture-phase pre-submit origin guard
├── phishguard-xr-backend/            # Standalone Risk & Inference Engine
│   └── server_xr.py                  # Multi-channel Platt Risk Engine on Port 8007
├── src/                              # Model pipelines & Evaluation
│   ├── models/                       # Multimodal fusion, transformer, vision branches
│   ├── evaluation/                   # Adversarial and unseen domain benchmarks
│   ├── feature_extraction/           # URL & DOM pipeline builders
│   └── webpage/                      # HTML downloader and parsers
├── app/                              # Management & Dashboard interfaces
│   ├── api/                          # Auxiliary API services
│   ├── frontend/                     # React visualization components
│   └── phishguard-x-ui/              # React/Tailwind Security Dashboard
├── test_phishing_server.py           # Simulated PayPal phishing server (Port 8088 / 8080)
├── test_qr_portal.html               # Interactive Quishing test portal
└── docker-compose.yml                # Container orchestration
```

---

## 🚀 Quickstart Guide

### 1. Clone the Repository
```bash
git clone https://github.com/sarvesh-15-ai/Phishguard-XR.git
cd Phishguard-XR
```

### 2. Start the PhishGuard-XR Backend Engine
```bash
cd phishguard-xr-backend
python3 server_xr.py
```
*Health Check:* Open `http://localhost:8007/health` in your browser.

### 3. Load the Browser Extension in Chrome
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle in the top-right corner).
3. Click **Load unpacked** (top-left).
4. Select the `phishguard-xr-extension` directory.

### 4. Run the Test Phishing Portal (Simulation)
```bash
python3 test_phishing_server.py
```
1. Open `http://localhost:8088/login` in Chrome.
2. The **PhishGuard-XR Threat Alert** card will appear immediately with **Risk Score: 88/100 (CRITICAL THREAT)**.
3. Attempt to enter credentials and click *"Verify & Log In"* $\rightarrow$ the **Pre-Submit Guard** will synchronously freeze the submission!

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
