
from threat_intel import check_urlhaus

test_url = "http://testsafebrowsing.appspot.com/s/malware.html"

result = check_urlhaus(test_url)

print("\nURLHAUS THREAT INTELLIGENCE")
print("---------------------------")
print("Test URL:", test_url)
print("Source:", result.get("source"))
print("Status:", result.get("status"))

query_status = result.get("query_status")

if query_status == "no_results":
    print("Result: No malicious URL record found.")

elif query_status == "ok":
    print("Result: MALICIOUS URL FOUND!")
    print("Threat:", result.get("threat"))
    print("Tags:", result.get("tags"))
    print("Date Added:", result.get("date_added"))
    print("Reference:", result.get("reference"))

else:
    print("Result: Unable to complete the threat check.")
    print("Details:", result)

