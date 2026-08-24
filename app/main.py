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
    browser_instance = await playwright_instance.chromium.launch(
        headless=True,
        args=[
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu"
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
    try:
        context = await browser_instance.new_context(
            accept_downloads=False,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        page = await context.new_page()
        
        redirects = []
        page.on("framenavigated", lambda frame: redirects.append(frame.url) if frame == page.main_frame else None)
        
        await page.goto(url, timeout=10000, wait_until="domcontentloaded")
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
            "error": "The website blocked the security scanner or took too long to load."
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
    
    # Smarter regex to extract URLs even if they are mashed against text
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
    urls = [f"http://{u}" if u.startswith("www.") else u for u in urls]
    
    flags = []
    text_lower = text.lower()
    if any(w in text_lower for w in ["urgent", "verify now", "act now", "suspended"]):
        flags.append("URGENCY_PRESSURE")
    if any(w in text_lower for w in ["otp", "pin", "password", "cvv", "kyc"]):
        flags.append("CREDENTIAL_HARVESTING")
    
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
    raw_url = os.getenv("LLM_BASE_URL", "https://openrouter.ai/api/v1")
    
    # Auto-fix: Strip markdown brackets if accidentally pasted in Render
    url_match = re.search(r'https?://[^\s)\]]+', raw_url)
    base_url = url_match.group(0).rstrip("/") if url_match else "https://openrouter.ai/api/v1"
    
    api_key = os.getenv("LLM_API_KEY", "")
    model = os.getenv("LLM_MODEL", "gpt-4o-mini")
    
    clean_evidence = dict(req.evidence)
    if "url_analysis" in clean_evidence:
        clean_urls = []
        for item in clean_evidence["url_analysis"]:
            sanitized = {k: v for k, v in item.items() if k != "screenshot_base64"}
            clean_urls.append(sanitized)
        clean_evidence["url_analysis"] = clean_urls

    prompt = f"""
Analyze this security evidence for a message/URL scan.
Return a STRICT JSON object with exactly these 3 keys:
- "risk_level": Must be exactly "Low", "Medium", or "High"
- "explanation": Explain if it is safe or dangerous in VERY simple, everyday words. If it is a standard promotional voucher (like Lenskart/Google Pay), explicitly state that it is a safe promotional offer and explain why.
- "fix": Direct action recommended (e.g., "Safe to open" or "Delete immediately").

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
            {"role": "system", "content": "You are a cyber security AI. Always output valid raw JSON without markdown code fences."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2
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
            "explanation": f"Backend connection error to AI provider. Details: {str(e)}",
            "fix": "Please verify your LLM_API_KEY and LLM_BASE_URL in the Render dashboard."
        }

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def serve_index():
    return FileResponse("static/index.html")