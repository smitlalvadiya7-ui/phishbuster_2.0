import re
import tldextract

PHISHING_KEYWORDS = [
    "login", "verify", "account", "secure", "update", "confirm",
    "banking", "password", "signin", "wallet", "suspended",
    "unusual", "activity", "urgent", "alert", "validate"
]

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"]

TRUSTED_BRANDS = [
    "paypal", "google", "facebook", "amazon", "apple", "microsoft",
    "netflix", "instagram", "twitter", "whatsapp", "bank"
]

def heuristic_analysis(url: str) -> dict:
    score = 0
    reasons = []
    url_lower = url.lower()

    if not url_lower.startswith("https://"):
        score += 15
        reasons.append("No HTTPS detected")

    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
        score += 35
        reasons.append("IP address used instead of domain")

    found = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
    if found:
        score += min(len(found) * 8, 25)
        reasons.append(f"Phishing keywords: {', '.join(found)}")

    ext = tldextract.extract(url)
    domain_full = f"{ext.domain}.{ext.suffix}".lower()
    for brand in TRUSTED_BRANDS:
        if brand in url_lower and brand not in domain_full:
            score += 30
            reasons.append(f"Brand impersonation: '{brand}'")
            break

    suffix = f".{ext.suffix}"
    if any(suffix == tld for tld in SUSPICIOUS_TLDS):
        score += 20
        reasons.append(f"Suspicious TLD: {suffix}")

    if ext.subdomain:
        sub_count = len(ext.subdomain.split("."))
        if sub_count > 2:
            score += 15
            reasons.append(f"Too many subdomains: {sub_count}")

    if len(url) > 100:
        score += 10
        reasons.append(f"Very long URL: {len(url)} chars")

    if "@" in url:
        score += 25
        reasons.append("@ symbol in URL")

    if url.count("-") > 3:
        score += 10
        reasons.append("Excessive hyphens")

    return {
        "heuristic_score": min(score, 100),
        "reasons": reasons
    }
