from threat_correlation import (
    analyze_website
)

test_url = "https://google.com"

result = analyze_website(test_url)

print("\nCOMPLETE WEBSITE THREAT REPORT")
print("--------------------------------")

for section, data in result.items():
    print(f"\n{section.upper()}")
    print(data)