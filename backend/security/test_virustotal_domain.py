from threat_intel import check_virustotal_domain

test_domain = "google.com"

result = check_virustotal_domain(test_domain)

print("\nVIRUSTOTAL DOMAIN INTELLIGENCE")
print("------------------------------")
print("Test Domain:", test_domain)
print("Source:", result.get("source"))
print("Status:", result.get("status"))
print("Result:", result)