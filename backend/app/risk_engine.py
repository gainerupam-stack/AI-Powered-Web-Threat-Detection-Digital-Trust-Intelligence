from typing import Any

WEIGHTS = {
    "confirmed_malicious": 100,
    "threat_feed_match": 70,
    "phishing_language": 25,
    "suspicious_redirect": 20,
    "tls_invalid": 20,
    "domain_very_new": 15,
    "brand_impersonation": 25,
    "url_obfuscation": 15,
    "ai_high_risk": 25,
}


def _truthy(*sources: dict[str, Any], key: str) -> bool:
    return any(bool(source.get(key, False)) for source in sources)


def assess_risk(
    url_tls: dict[str, Any],
    threat_intel: dict[str, Any],
    ai_analysis: dict[str, Any],
) -> dict:
    sources = (url_tls or {}, threat_intel or {}, ai_analysis or {})

    if _truthy(*sources, key="confirmed_malicious"):
        return {
            "risk_score": 100,
            "risk_category": "Confirmed Malicious",
            "rationale": [
                "An upstream threat-intelligence source confirmed malicious activity."
            ],
        }

    score = 0
    reasons = []

    for indicator, weight in WEIGHTS.items():
        if indicator == "confirmed_malicious":
            continue

        if _truthy(*sources, key=indicator):
            score += weight
            reasons.append(
                f"{indicator.replace('_', ' ').capitalize()} (+{weight})"
            )

    score = min(score, 99)

    # Raw reports and API errors alone must not be interpreted as evidence.
    has_evidence = any(
        any(bool(source.get(indicator, False)) for indicator in WEIGHTS)
        for source in sources
    )

    if not has_evidence:
        category = "Inconclusive"
    elif score >= 70:
        category = "High Risk"
    elif score >= 30:
        category = "Suspicious"
    else:
        category = "Low Risk"

    if not reasons and has_evidence:
        reasons.append("No configured risk indicators were triggered.")

    return {
        "risk_score": score,
        "risk_category": category,
        "rationale": reasons,
    }