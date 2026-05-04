import requests
import os

def check_google_safebrowsing(url: str) -> dict:
    api_key = os.getenv("GOOGLE_SAFEBROWSING_API_KEY")
    if not api_key or api_key == "your_key_here":
        return {"safe": True, "threats": []}

    payload = {
        "client": {"clientId": "linkshield-ai", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=payload,
            timeout=10
        )
        data = response.json()
        if "matches" in data and data["matches"]:
            threats = [m["threatType"] for m in data["matches"]]
            return {"safe": False, "threats": threats}

    except Exception:
        pass

    return {"safe": True, "threats": []}
