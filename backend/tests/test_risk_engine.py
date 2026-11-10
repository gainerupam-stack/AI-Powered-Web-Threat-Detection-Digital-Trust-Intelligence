from app.risk_engine import assess_risk

def test_confirmed_malicious():
    r = assess_risk({}, {"confirmed_malicious": True}, {})
    assert r["risk_category"] == "Confirmed Malicious" and r["risk_score"] == 100

def test_suspicious_score():
    r = assess_risk({"tls_invalid": True}, {"phishing_language": True}, {})
    assert r["risk_score"] == 45
    assert r["risk_category"] == "Suspicious"

def test_inconclusive_empty():
    assert assess_risk({}, {}, {})["risk_category"] == "Inconclusive"
