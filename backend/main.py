from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import os
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
from apis.virustotal import check_virustotal
from apis.google_safebrowsing import check_google_safebrowsing
from apis.urlscan import check_urlscan
from apis.whois_check import check_domain_age
from apis.ip_info import get_ip_info
from analyzer import heuristic_analysis
from ai.verdict import get_ai_verdict
from database.db import init_db, save_scan, get_history
init_db()
app = FastAPI(
    title="PhishBuster 2.0",
    description="Agentic AI-powered phishing URL detector",
    version="2.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
class URLRequest(BaseModel):
    url: str

@app.get("/")
def root():
    return {"message": "PhishBuster 2.0 is running!", "version": "2.0.0"}

@app.post("/scan")
def scan(request: URLRequest):
    url = request.url.strip()
    if not url.startswith("http"):
        url = "https://" + url

    heuristic = heuristic_analysis(url)
    vt_result = check_virustotal(url)
    gsb_result = check_google_safebrowsing(url)
    domain_info = check_domain_age(url)
    ip_info = get_ip_info(url)
    urlscan_result = {"score": 0, "malicious": False}

    final_score = heuristic["heuristic_score"]
    if vt_result.get("malicious", 0) > 0:
        final_score += 40
    if not gsb_result["safe"]:
        final_score += 30
    if domain_info.get("young_domain"):
        final_score += 15
    if urlscan_result.get("malicious"):
        final_score += 20
    final_score = min(final_score, 100)

    if final_score >= 60:
        verdict = "MALICIOUS"
    elif final_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    ai_explanation = get_ai_verdict(
        url, heuristic, vt_result, gsb_result, domain_info
    )

    save_scan(
        url=url,
        verdict=verdict,
        risk_score=final_score,
        reasons=heuristic["reasons"],
        ai_explanation=ai_explanation
    )

    return {
        "url": url,
        "verdict": verdict,
        "risk_score": final_score,
        "heuristic": heuristic,
        "virustotal": vt_result,
        "google_safebrowsing": gsb_result,
        "domain_info": domain_info,
        "ip_info": ip_info,
        "ai_explanation": ai_explanation
    }

@app.get("/history")
def history():
    return get_history(20)