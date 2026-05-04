import os
import requests

def get_ai_verdict(url, heuristic, vt_result, gsb_result, domain_info):
    api_key = "AIzaSyDcTOq0r7ITdnVW4iwL6OMAxCJ4Nfgf5Sg"
    if not api_key:
        return "AI analysis unavailable - API key not set."
    try:
        flags = ", ".join(heuristic["reasons"]) if heuristic["reasons"] else "None"
        score = heuristic["heuristic_score"]
        vt_mal = vt_result.get("malicious", 0)
        vt_total = vt_result.get("total", 0)
        gsb = "UNSAFE" if not gsb_result["safe"] else "Clean"
        age = domain_info.get("age_days", "Unknown")

        prompt = (
            f"You are a cybersecurity expert analyzing a URL for phishing.\n"
            f"URL: {url}\n"
            f"Heuristic Score: {score}/100\n"
            f"Flags: {flags}\n"
            f"VirusTotal: {vt_mal} malicious out of {vt_total}\n"
            f"Google Safe Browsing: {gsb}\n"
            f"Domain Age: {age} days\n"
            f"Give verdict SAFE/SUSPICIOUS/MALICIOUS and 2-3 sentence explanation. No markdown."
        )

        res = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}",
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=10
        )
        data = res.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        return f"AI analysis error: {str(e)}"