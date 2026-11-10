from url_analyzer import analyze_url

test_url = "http://192.168.1.1/login/verify"

result = analyze_url(test_url)

print("\nURL THREAT ANALYSIS")
print("-------------------")
print("URL:", result["url"])
print("Risk Score:", result["risk_score"])
print("Risk Level:", result["risk_level"])
print("Findings:", result["findings"])