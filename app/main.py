import os
import re
import json
import base64
from contextlib import asynccontextmanager
import httpx
from dotenv import load_dotenv
from pydantic import BaseModel
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from playwright.async_api import async_playwright

load_dotenv()

playwright_instance = None
browser_instance = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global playwright_instance, browser_instance
    playwright_instance = await async_playwright().start()
    # Stealth mode flags to bypass bot-blockers like pages.dev or Cloudflare
    browser_instance = await playwright_instance.chromium.launch(
        headless=True,
        args=[
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-blink-features=AutomationControlled",
            "--window-size=1280,720"
        ]
    )
    yield
    if browser_instance:
        await browser_instance.close()
    if playwright_instance:
        await playwright_instance.stop()

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def scan_url_sandbox(url: str) -> dict:
    # Auto-add https if the scammer hid it
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        # Emulate a real mobile/desktop user to trick the scam site
        context = await browser_instance.new_context(
            accept_downloads=False,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 720}
        )
        page = await context.new_page()
        
        redirects = []
        page.on("framenavigated", lambda frame: redirects.append(frame.url) if frame == page.main_frame else None)
        
        # wait_until="commit" ensures we grab a screenshot even if the site hangs trying to load malicious scripts
        await page.goto(url, timeout=12000, wait_until="commit")
        await page.wait_for_timeout(2000) # Give it 2 seconds to render visual elements
        
        final_url = page.url
        title = await page.title()
        
        text_content = await page.evaluate("document.body ? document.body.innerText : ''")
        text_snippet = text_content[:1500] if text_content else ""
        
        screenshot_bytes = await page.screenshot(type="png", full_page=False)
        screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")
        
        await context.close()
        return {
            "url": url,
            "final_url": final_url,
            "redirect_chain": redirects,
            "title": title,
            "text_snippet": text_snippet,
            "screenshot_base64": screenshot_b64
        }
    except Exception as e:
        return {
            "url": url,
            "error": "Site timed out or attempted to block automated access. This is a common tactic for phishing pages."
        }

class MessageRequest(BaseModel):
    text: str
    channel: str = "sms"

class AnalyzeRequest(BaseModel):
    evidence: dict
    type: str

@app.post("/scan/message")
async def scan_message(req: MessageRequest):
    text = req.text
    
    # Smarter regex: Catches URLs without http:// (like api.whatsapp.com, pages.dev, t.me)
    domain_pattern = r'(?:https?://|www\.)[^\s<>"]+|(?<!@)\b(?:[a-zA-Z0-9-]+\.)+(?:com|in|org|net|dev|xyz|io|app|co|me|vip|top|club|link|online|live|tech|site|cc|info|biz|icu|shop|store)(?:/[^\s<>"]*)?'
    urls = re.findall(domain_pattern, text)
    
    # Catch known Indian scam keywords
    flags = []
    text_lower = text.lower()
    if any(w in text_lower for w in ["salary", "part time", "work at home", "daily income", "earn money", "task", "passed", "rs "]):
        flags.append("FINANCIAL_JOB_SCAM")
    if any(w in text_lower for w in ["api.whatsapp.com", "wa.me", "t.me", "chat.whatsapp.com"]):
        flags.append("UNVERIFIED_MESSENGER_REDIRECT")
    if any(w in text_lower for w in ["urgent", "verify now", "act now", "suspended", "electricity", "pan update"]):
        flags.append("URGENCY_PRESSURE")
    
    url_analysis = []
    for u in urls:
        res = await scan_url_sandbox(u)
        url_analysis.append(res)
        
    return {
        "channel": req.channel,
        "extracted_urls": urls,
        "flags": flags,
        "url_analysis": url_analysis
    }

@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    base_url = os.getenv("LLM_BASE_URL", "https://openrouter.ai/api/v1").replace("[", "").replace("]", "").replace("(", "").replace(")", "").split("http")[1]
    base_url = "http" + base_url 
    
    api_key = os.getenv("LLM_API_KEY", "")
    model = os.getenv("LLM_MODEL", "openrouter/free")
    
    clean_evidence = dict(req.evidence)
    if "url_analysis" in clean_evidence:
        clean_urls = []
        for item in clean_evidence["url_analysis"]:
            sanitized = {k: v for k, v in item.items() if k != "screenshot_base64"}
            clean_urls.append(sanitized)
        clean_evidence["url_analysis"] = clean_urls

    prompt = f"""
Analyze this security evidence for a message/URL scan.
Return a STRICT JSON object with exactly these 4 keys:
1. "risk_level": "Low", "Medium", or "High".
2. "explanation": Explain the scam in very simple words (e.g., "This is a WhatsApp task scam pretending you got a salary"). If it's a normal promo (like Google Pay), say it's safe.
3. "fix": Immediate recommended action (e.g., "Do not click").
4. "incident_response": An array of 3-4 strings with emergency steps if the user already clicked or lost money. Include exactly these Indian cybercrime resources if High risk: "Call 1930 Cyber Helpline immediately", "File a complaint at cybercrime.gov.in", "Contact your bank/UPI app to freeze transactions", "Take screenshots of the chat as proof". If Low risk, return an empty array [].

Evidence:
{json.dumps(clean_evidence, indent=2)}
"""

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a cyber security AI. Always output valid raw JSON. No markdown formatting."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1
    }
    
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(f"{base_url}/chat/completions", headers=headers, json=payload)
            resp.raise_for_status()
            raw_content = resp.json()["choices"][0]["message"]["content"].strip()
            
            if raw_content.startswith("```json"): raw_content = raw_content[7:]
            elif raw_content.startswith("```"): raw_content = raw_content[3:]
            if raw_content.endswith("```"): raw_content = raw_content[:-3]
                
            return json.loads(raw_content.strip())
    except Exception as e:
        return {
            "risk_level": "High",
            "explanation": f"The security analysis engine encountered an error parsing the threat. Error: {str(e)}",
            "fix": "Do not interact with the message. Treat it as highly suspicious.",
            "incident_response": [
                "Call the National Cyber Crime Helpline at 1930 if you lost money.",
                "Report the incident at cybercrime.gov.in",
                "Freeze your bank accounts immediately."
            ]
        }

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def serve_index():
    return FileResponse("static/index.html")