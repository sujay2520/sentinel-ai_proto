# 🛡️ Sentinel AI — Mobile Threat Defense & Sandbox

> **Real-time SMS, WhatsApp & URL threat intelligence engine with isolated browser sandboxing and automated emergency incident response.**

---

## 📌 Problem Statement

Mobile users are increasingly targeted by sophisticated social engineering attacks—including job task scams, fake courier alerts, phishing gateways (`pages.dev`, shorteners), and malicious WhatsApp redirects. Traditional filters either rely on static blacklists (which fail against zero-day domains) or lack safe previews, forcing users to click blindly.

## 💡 Solution

**Sentinel AI** acts as a proactive security layer before a link or payload interacts with the user's device:
1. **Zero-Click Sandboxing:** Opens suspicious links inside an isolated, headless Chromium cloud container to safely capture screenshots and inspect redirect chains without risking the user's phone.
2. **Contextual AI Threat Analysis:** Uses LLM reasoning alongside heuristic rules to explain complex scams in plain, everyday language.
3. **Automated Incident Response:** Generates immediate, step-by-step remediation plans—integrating national emergency resources (such as India's **1930 Cyber Fraud Helpline** and **cybercrime.gov.in**).
4. **Zero-Friction Mobile PWA:** Fully installable directly onto Android devices with zero app-store bloat.

---

## 🚀 Key Features

* **Stealth Sandbox Preview:** Emulates real mobile browsers to bypass anti-bot mechanisms and capture visual proof of phishing pages.
* **Smart Payload Extraction:** Detects unformatted URLs, hidden links (`api.whatsapp.com`, `t.me`), and UPI IDs embedded in raw text.
* **Social Engineering Heuristics:** Flags urgency pressure, fake salary lure patterns, and credential-harvesting triggers.
* **Plain-English Explanations:** Explains *why* an offer is fake or safe (e.g., distinguishing real Google Pay vouchers from credential theft).
* **Emergency Action Playbook:** Instant guidance for victims (freezing accounts, preserving evidence, reporting to authorities).

---

## 🏗️ Architecture & Pipeline[ User Input (SMS / WhatsApp / Link) ]
│
▼
[ FastAPI Backend Engine ]
├── 1. Regex & Pattern Extractor (URLs, UPI IDs, Keywords)
├── 2. Playwright Headless Sandbox (Isolated Context + Screenshot)
└── 3. LLM Threat Intelligence Engine
│
▼
[ Structured JSON Security Assessment ]
├── Risk Tier: Low / Medium / High
├── Plain-English Explanation
├── Live Sandbox Screenshot
└── Emergency Incident Action Plan
---

## 🛠️ Tech Stack

* **Backend:** FastAPI (Python 3.10+), Uvicorn, HTTPX
* **Sandboxing Engine:** Playwright (Headless Chromium)
* **Frontend:** Vanilla JavaScript, HTML5, CSS3 (No build tools, zero dependencies)
* **Mobile Delivery:** Progressive Web App (PWA) with Service Worker caching
* **AI Engine:** OpenRouter / OpenAI-compatible LLM endpoints

---

## ⚙️ Environment Variables

Create a `.env` file in the root directory with the following keys:

```env
LLM_API_KEY=your_openrouter_or_openai_api_key
LLM_BASE_URL=[https://openrouter.ai/api/v1](https://openrouter.ai/api/v1)
LLM_MODEL=openrouter/free
💻 Local Development Setup
1. Clone the Repository
Bash
git clone [https://github.com/sujay2520/sentinel-ai_proto.git](https://github.com/sujay2520/sentinel-ai_proto.git)
cd sentinel-ai_proto
2. Set Up Virtual Environment & Dependencies
Bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install requirements
pip install -r requirements.txt

# Install Playwright browser binaries
playwright install chromium
3. Run the Development Server
Bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
Open http://localhost:8000 in your browser.

📱 Mobile Installation (PWA)
Open the deployed HTTPS URL in Google Chrome on Android.

Tap the three-dot menu (⋮) in the top-right corner.

Tap "Install App" or "Add to Home Screen".

Sentinel AI will install and run in standalone full-screen mode.

📄 License
This prototype is built for demonstration and competition purposes under the MIT License.


---

### How to Commit and Push the Updated README:

Run these commands in your VS Code terminal:

```powershell
git add README.md
git commit -m "docs: add comprehensive hackathon README"
git push origin main
