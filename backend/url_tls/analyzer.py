from urllib.parse import urlsplit

from url_tls.url_analyzer import validate_and_analyze_url
from url_tls.domain_analyzer import analyze_domain
from url_tls.tls_analyzer import analyze_tls
from url_tls.redirect_analyzer import analyze_redirects

def analyze_url_tls(raw_url):
    """
    Run the complete URL, domain, TLS and redirect analysis.

    Returns a JSON-compatible security report.
    """

    report = {
        "module": "url_tls",
        "status": "completed",
        "findings": [],
        "limitations": [],
        "details": {}
    }

    # 1. Validate and analyze the URL
    url_result = validate_and_analyze_url(raw_url)

    report["details"]["url_analysis"] = url_result
    report["findings"].extend(url_result.get("findings", []))
    report["limitations"].extend(url_result.get("limitations", []))

    # Stop if the URL is invalid
    if not url_result.get("valid"):
        report["status"] = "failed"
        return report

    hostname = url_result["hostname"]
    parsed_url = urlsplit(url_result["normalized_url"])

    # 2. Analyze domain and DNS
    domain_result = analyze_domain(hostname)

    report["details"]["domain_analysis"] = domain_result
    report["findings"].extend(domain_result.get("findings", []))
    report["limitations"].extend(domain_result.get("limitations", []))

    # Stop network analysis if the destination is unsafe
    if domain_result.get("destination_safety") == "blocked":
        report["status"] = "blocked"
        return report

    # 3. Analyze TLS for HTTPS URLs
    if parsed_url.scheme == "https":
        tls_result = analyze_tls(
            hostname,
            port=parsed_url.port or 443
        )

        report["details"]["tls_analysis"] = tls_result
        report["findings"].extend(tls_result.get("findings", []))
        report["limitations"].extend(tls_result.get("limitations", []))

    else:
        report["limitations"].append(
            "TLS analysis skipped because the URL uses HTTP."
        )

    # 4. Analyze redirects
    redirect_result = analyze_redirects(
        url_result["normalized_url"]
    )

    report["details"]["redirect_analysis"] = redirect_result
    report["findings"].extend(redirect_result.get("findings", []))
    report["limitations"].extend(redirect_result.get("limitations", []))

    # Reflect unsuccessful or blocked analysis
    statuses = [
        domain_result.get("status"),
        report["details"].get("tls_analysis", {}).get("status"),
        redirect_result.get("status")
    ]

    if "blocked" in statuses:
        report["status"] = "blocked"
    elif "failed" in statuses:
        report["status"] = "partial"

    return report