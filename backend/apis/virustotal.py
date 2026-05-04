import requests
import os
import base64

def check_virustotal(url: str) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key or api_key == "your_key_here":
        return {"malicious": 0, "suspicious": 0, "harmless": 0, "total": 0, "error": "No API key"}

    headers = {"x-apikey": api_key}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "total": sum(stats.values())
            }

        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )
        if submit.status_code == 200:
            return {"malicious": 0, "suspicious": 0, "harmless": 0, "total": 0, "note": "submitted"}

    except Exception as e:
        return {"malicious": 0, "suspicious": 0, "harmless": 0, "total": 0, "error": str(e)}

    return {"malicious": 0, "suspicious": 0, "harmless": 0, "total": 0}
