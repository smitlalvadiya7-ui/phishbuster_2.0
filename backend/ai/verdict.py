import os
import requests

def get_ai_verdict(url, heuristic, vt_result, gsb_result, domain_info):
    api_key = os.getenv("AIzaSyDcTOq0r7ITdnVW4iwL6OMAxCJ4Nfgf5Sg")
    if not api_key:
        return "AI analysis unavailable - API key not set."
    try:
        prompt = f"""You are a cybersecurity expert analyzing a URL for phishing.
URL: {url}
Heuristic Score: {heuristic[\"heuristic_score\"]}/100
Flags: {", ".join(heuristic["reasons"]) if heuristic["reasons"] else "None"}
VirusTotal: {vt_result.get("malicious", 0)} malicious out of {vt_result.get("total", 0)}
Google Safe Browsing: {"UNSAFE" if not gsb_result["safe"] else "Clean"}
Domain Age: {domain_info.get("age_days", "Unknown")} days
Give verdict SAFE/SUSPICIOUS/MALICIOUS and 2-3 sentence explanation. No markdown."""

        res = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}",
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=10
        )
        data = res.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        return f"AI analysis error: {str(e)}"
