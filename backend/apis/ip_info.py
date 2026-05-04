import socket
import requests
from urllib.parse import urlparse

def get_ip_info(url: str) -> dict:
    try:
        domain = urlparse(url).netloc
        if domain.startswith("www."):
            domain = domain[4:]
        domain = domain.split(":")[0]

        ip = socket.gethostbyname(domain)

        try:
            res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = res.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "hosting": data.get("as", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "platform": detect_platform(data.get("org", ""), data.get("isp", ""))
                }
        except:
            pass

        return {"ip": ip, "isp": "Unknown", "org": "Unknown",
                "hosting": "Unknown", "country": "Unknown",
                "city": "Unknown", "platform": "Unknown"}

    except Exception:
        return {"ip": "Not found", "isp": "Unknown", "org": "Unknown",
                "hosting": "Unknown", "country": "Unknown",
                "city": "Unknown", "platform": "Unknown"}

def detect_platform(org: str, isp: str) -> str:
    text = (org + " " + isp).lower()
    platforms = {
        "Cloudflare": "cloudflare",
        "Amazon AWS": "amazon",
        "Google Cloud": "google",
        "Microsoft Azure": "microsoft",
        "DigitalOcean": "digitalocean",
        "Hostinger": "hostinger",
        "GoDaddy": "godaddy",
        "Bluehost": "bluehost",
        "Namecheap": "namecheap",
        "OVH": "ovh",
        "Hetzner": "hetzner",
        "Vultr": "vultr",
        "Linode": "linode",
        "Render": "render",
    }
    for name, keyword in platforms.items():
        if keyword in text:
            return name
    return "Unknown Host"