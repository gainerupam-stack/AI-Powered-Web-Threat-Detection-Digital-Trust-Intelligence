from typing import Any

# Deterministic rules. Inputs are normalized booleans/indicators from upstream modules.
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
    return any(bool(s.get(key, False)) for s in sources)

def assess_risk(url_tls: dict, threat_intel: dict, ai_analysis: dict) -> dict:
    sources = (url_tls or {}, threat_intel or {}, ai_analysis or {})
    # A definitive upstream verdict takes precedence.
    if _truthy(*sources, key="confirmed_malicious"):
        return {"risk_score": 100, "risk_category": "Confirmed Malicious",
                "rationale": ["An upstream module explicitly marked the target confirmed malicious."]}

    score, reasons = 0, []
    for key, weight in WEIGHTS.items():
        if key == "confirmed_malicious":
            continue
        if _truthy(*sources, key=key):
            score += weight
            reasons.append(f"{key.replace('_', ' ').capitalize()} (+{weight})")

    score = min(score, 99)
    # If upstream modules provide no usable evidence, avoid falsely declaring safety.
    has_evidence = any(bool(s) for s in sources)
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
    return {"risk_score": score, "risk_category": category, "rationale": reasons}
