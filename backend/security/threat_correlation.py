from url_analyzer import analyze_url

from threat_intel import (
    check_urlhaus,
    check_virustotal,
    check_virustotal_domain
)

from website_security import (
    check_https,
    check_security_headers,
    check_mixed_content,
    detect_website_technology
)
def analyze_website(url):

    results = {}

    results["url_analysis"] = analyze_url(url)

    results["urlhaus"] = check_urlhaus(url)

    results["virustotal_url"] = check_virustotal(url)

    results["virustotal_domain"] = check_virustotal_domain(url)

    results["https_security"] = check_https(url)

    results["security_headers"] = check_security_headers(url)

    results["mixed_content"] = check_mixed_content(url)

    results["technology"] = detect_website_technology(url)
    results["threat_summary"] = generate_threat_summary(results)

    return results

def generate_threat_summary(results):

    findings = []

    url_result = results.get("url_analysis", {})

    if url_result.get("findings"):
        findings.extend(url_result["findings"])

    urlhaus = results.get("urlhaus", {})

    if urlhaus.get("status") == "success":
        if urlhaus.get("query_status") == "ok":
            findings.append("URL found in URLhaus threat database")

    vt_url = results.get("virustotal_url", {})

    if vt_url.get("status") == "success":
        malicious = vt_url.get("malicious", 0)

        if malicious > 0:
            findings.append(
                f"VirusTotal detected {malicious} malicious engine(s)"
            )

    vt_domain = results.get("virustotal_domain", {})

    if vt_domain.get("status") == "success":
        malicious = vt_domain.get("malicious", 0)

        if malicious > 0:
            findings.append(
                f"Domain flagged by {malicious} VirusTotal engine(s)"
            )

    mixed = results.get("mixed_content", {})

    if mixed.get("mixed_content_found"):
        findings.append("Insecure mixed content detected")

    https = results.get("https_security", {})

    if https.get("status") == "success":
        if not https.get("https_enabled"):
            findings.append("HTTPS is not enabled")

    return {
        "total_findings": len(findings),
        "findings": findings
    }