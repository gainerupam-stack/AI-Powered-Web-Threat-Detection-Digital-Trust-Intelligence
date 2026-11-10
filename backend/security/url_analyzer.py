
import re
from urllib.parse import urlparse

# Common URL shorteners
URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy"
]

# Suspicious words often found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "password",
    "banking",
    "free",
    "gift"
]


def analyze_url(url):
    findings = []

    parsed_url = urlparse(url if "://" in url else "https://" + url)
    hostname = parsed_url.hostname or ""
    full_url = url.lower()

    # Check for IP address instead of domain name
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        findings.append("Uses an IP address instead of a domain name")

    # Check for URL shorteners
    if hostname.lower() in URL_SHORTENERS:
        findings.append("Uses a URL shortening service")

    # Check suspicious keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in full_url:
            findings.append(f"Contains suspicious keyword: {keyword}")

    # Check unusually long URLs
    if len(url) > 100:
        findings.append("Unusually long URL")

    # Check for misleading @ symbol
    if "@" in url:
        findings.append("Contains an @ symbol")

    # Calculate a simple preliminary risk score
    risk_score = min(len(findings) * 20, 100)

    if risk_score >= 60:
        risk_level = "High"
    elif risk_score >= 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "url": url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings": findings
    }

