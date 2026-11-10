from threat_intel import check_virustotal

test_url = "https://google.com"

result = check_virustotal(test_url)

print("\nVIRUSTOTAL THREAT INTELLIGENCE")
print("------------------------------")
print("Test URL:", test_url)
print("Source:", result.get("source"))
print("Status:", result.get("status"))
print("Result:", result)