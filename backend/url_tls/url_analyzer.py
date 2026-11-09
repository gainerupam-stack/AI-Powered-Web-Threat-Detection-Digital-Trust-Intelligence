"""
TrustGuard AI - URL Analyzer

Responsibilities:
1. Validate URLs.
2. Normalize URLs.
3. Detect suspicious URL patterns.
4. Detect possible typosquatting.
"""

import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import urlsplit, urlunsplit


# Domains commonly impersonated by phishing websites.
# This is a starter reference list, not a complete threat database.
KNOWN_BRANDS = [
    "google.com",
    "paypal.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "facebook.com",
    "instagram.com",
    "netflix.com",
    "github.com",
    "linkedin.com",
]

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "banking",
    "payment",
    "wallet",
    "password",
    "signin",
    "confirm",
]

SUSPICIOUS_PORTS = [8080, 8443, 4444, 3000, 5000]


def add_finding(findings, indicator, severity, evidence):
    """Add a consistently structured security finding."""

    findings.append({
        "indicator": indicator,
        "severity": severity,
        "evidence": evidence,
        "source": "url_analyzer"
    })


def get_registered_domain(hostname):
    """
    Get an approximate registered domain.

    A full public-suffix-aware implementation will be added
    when we integrate the domain analysis module.
    """

    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    parts = hostname.split(".")

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return hostname


def detect_typosquatting(hostname, findings):
    """Identify domains that closely resemble known brands."""

    registered_domain = get_registered_domain(hostname)

    try:
        ipaddress.ip_address(registered_domain)
        return []
    except ValueError:
        pass

    domain_name = registered_domain.split(".")[0]

    matches = []

    for brand in KNOWN_BRANDS:
        brand_name = brand.split(".")[0]

        if domain_name == brand_name:
            continue

        similarity = SequenceMatcher(
            None,
            domain_name,
            brand_name
        ).ratio()

        # Detect close spelling similarities.
        if similarity >= 0.80:
            matches.append({
                "suspected_brand": brand,
                "similarity": round(similarity, 2)
            })

    if matches:
        best_match = max(
            matches,
            key=lambda item: item["similarity"]
        )

        add_finding(
            findings,
            "possible_typosquatting",
            "high" if best_match["similarity"] >= 0.90 else "medium",
            (
                f"Domain '{registered_domain}' resembles "
                f"'{best_match['suspected_brand']}' "
                f"with similarity {best_match['similarity']}."
            )
        )

    return matches


def validate_and_analyze_url(raw_url):
    """
    Validate, normalize and inspect a submitted URL.

    This function does not visit the website.
    It performs local structural analysis only.
    """

    findings = []
    limitations = []

    if not isinstance(raw_url, str) or not raw_url.strip():
        return {
            "valid": False,
            "submitted_url": raw_url,
            "normalized_url": None,
            "hostname": None,
            "registered_domain": None,
            "typosquatting_matches": [],
            "findings": findings,
            "limitations": ["URL must be a non-empty string."]
        }

    submitted_url = raw_url.strip()

    # Reject whitespace and control characters.
    if any(ord(char) <= 32 or ord(char) == 127 for char in submitted_url):
        return {
            "valid": False,
            "submitted_url": submitted_url,
            "normalized_url": None,
            "hostname": None,
            "registered_domain": None,
            "typosquatting_matches": [],
            "findings": findings,
            "limitations": ["URL contains whitespace or control characters."]
        }

    # Backslashes can cause URL parsing inconsistencies.
    if "\\" in submitted_url:
        return {
            "valid": False,
            "submitted_url": submitted_url,
            "normalized_url": None,
            "hostname": None,
            "registered_domain": None,
            "typosquatting_matches": [],
            "findings": findings,
            "limitations": ["Backslashes are not accepted in URLs."]
        }

    try:
        parsed = urlsplit(submitted_url)

        scheme = parsed.scheme.lower()

        if scheme not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are supported.")

        if not parsed.netloc or not parsed.hostname:
            raise ValueError("URL must contain a valid hostname.")

        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing embedded credentials are rejected.")

        hostname = parsed.hostname.rstrip(".").lower()

        if not hostname:
            raise ValueError("Hostname cannot be empty.")

        # Validate and normalize the port.
        port = parsed.port

        # Convert internationalized hostnames to ASCII IDNA form.
        try:
            ip_address = ipaddress.ip_address(hostname)
            normalized_host = ip_address.compressed
            is_ip_address = True
        except ValueError:
            normalized_host = hostname.encode("idna").decode("ascii").lower()
            is_ip_address = False

        # Construct the normalized network location.
        if ":" in normalized_host:
            normalized_host = f"[{normalized_host}]"

        netloc = normalized_host

        if port is not None:
            netloc += f":{port}"

        # Add / if the URL has no path.
        path = parsed.path or "/"

        normalized_url = urlunsplit((
            scheme,
            netloc,
            path,
            parsed.query,
            parsed.fragment
        ))

    except (ValueError, UnicodeError) as error:
        return {
            "valid": False,
            "submitted_url": submitted_url,
            "normalized_url": None,
            "hostname": None,
            "registered_domain": None,
            "typosquatting_matches": [],
            "findings": findings,
            "limitations": [str(error)]
        }

    registered_domain = get_registered_domain(normalized_host)

    # Detect IP-based URLs.
    if is_ip_address:
        add_finding(
            findings,
            "ip_address_url",
            "medium",
            f"The URL uses an IP address instead of a domain: {hostname}."
        )

    # Detect unusually long hostnames.
    if len(hostname) > 100:
        add_finding(
            findings,
            "long_hostname",
            "medium",
            f"Hostname length is {len(hostname)} characters."
        )

    # Detect excessive subdomains.
    if not is_ip_address and len(hostname.split(".")) > 5:
        add_finding(
            findings,
            "excessive_subdomains",
            "medium",
            f"Hostname contains many subdomain levels: {hostname}."
        )

    # Detect multiple hyphens.
    if not is_ip_address and hostname.count("-") >= 3:
        add_finding(
            findings,
            "multiple_hyphens",
            "low",
            f"Hostname contains {hostname.count('-')} hyphens."
        )

    # Detect suspicious words.
    searchable_text = f"{hostname}{path}".lower()

    matched_keywords = [
        word for word in SUSPICIOUS_KEYWORDS
        if re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])",
                     searchable_text)
    ]

    if matched_keywords:
        add_finding(
            findings,
            "suspicious_keywords",
            "low",
            f"Suspicious keywords found: {', '.join(matched_keywords)}."
        )

    # Detect non-standard ports.
    if port in SUSPICIOUS_PORTS:
        add_finding(
            findings,
            "unusual_port",
            "low",
            f"URL uses non-standard port {port}."
        )

    # HTTP does not provide TLS encryption.
    if scheme == "http":
        add_finding(
            findings,
            "unencrypted_http",
            "medium",
            "URL uses HTTP instead of HTTPS."
        )

    # Detect internationalized / punycode hostnames.
    if not is_ip_address and (
        any(ord(char) > 127 for char in hostname)
        or "xn--" in normalized_host
    ):
        add_finding(
            findings,
            "internationalized_domain",
            "medium",
            "Hostname contains internationalized or punycode characters."
        )

    # Detect possible lookalike domains.
    typosquatting_matches = []

    if not is_ip_address:
        typosquatting_matches = detect_typosquatting(
            normalized_host,
            findings
        )

    return {
        "valid": True,
        "submitted_url": submitted_url,
        "normalized_url": normalized_url,
        "hostname": normalized_host,
        "registered_domain": registered_domain,
        "typosquatting_matches": typosquatting_matches,
        "findings": findings,
        "limitations": limitations
    }