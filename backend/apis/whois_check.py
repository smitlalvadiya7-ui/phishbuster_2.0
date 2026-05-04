import whois
from datetime import datetime
from urllib.parse import urlparse

def check_domain_age(url: str) -> dict:
    try:
        domain = urlparse(url).netloc
        if domain.startswith("www."):
            domain = domain[4:]

        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return {
                "domain": domain,
                "age_days": age_days,
                "registrar": w.registrar or "Unknown",
                "young_domain": age_days < 30
            }
    except Exception:
        pass

    return {
        "domain": url,
        "age_days": -1,
        "registrar": "Unknown",
        "young_domain": False
    }
