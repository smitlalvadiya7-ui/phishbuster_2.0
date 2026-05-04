import requests
import os
import time

def check_urlscan(url: str) -> dict:
    api_key = os.getenv("URLSCAN_API_KEY")
    if not api_key or api_key == "your_key_here":
        return {"score": 0, "malicious": False}

    headers = {"API-Key": api_key, "Content-Type": "application/json"}

    try:
        submit = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={"url": url, "visibility": "unlisted"},
            timeout=10
        )
        if submit.status_code == 200:
            scan_id = submit.json().get("uuid")
            time.sleep(10)
            result = requests.get(
                f"https://urlscan.io/api/v1/result/{scan_id}/",
                timeout=10
            )
            if result.status_code == 200:
                verdict = result.json().get("verdicts", {}).get("overall", {})
                return {
                    "score": verdict.get("score", 0),
                    "malicious": verdict.get("malicious", False)
                }
    except Exception:
        pass

    return {"score": 0, "malicious": False}
