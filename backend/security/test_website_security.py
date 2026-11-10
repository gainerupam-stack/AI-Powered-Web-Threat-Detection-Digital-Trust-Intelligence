from website_security import (
    check_https,
    check_security_headers,
    check_mixed_content,
    detect_website_technology
)

test_url = "https://google.com"

print("\nHTTPS SECURITY CHECK")
print("--------------------")
print(check_https(test_url))

print("\nHTTP SECURITY HEADERS CHECK")
print("---------------------------")
print(check_security_headers(test_url))

print("\nMIXED CONTENT CHECK")
print("-------------------")
print(check_mixed_content(test_url))
print("\nWEBSITE TECHNOLOGY DETECTION")
print("----------------------------")
print(detect_website_technology(test_url))