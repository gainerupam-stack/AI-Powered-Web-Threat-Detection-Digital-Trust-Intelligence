
import requests
import re
from urllib.parse import urlparse, urljoin
from html.parser import HTMLParser


def check_https(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        final_url = response.url
        final_scheme = urlparse(final_url).scheme.lower()

        return {
            "source": "Website Security Check",
            "status": "success",
            "https_enabled": final_scheme == "https",
            "tls_verified": final_scheme == "https",
            "final_url": final_url
        }

    except requests.exceptions.SSLError:
        return {
            "source": "Website Security Check",
            "status": "error",
            "https_enabled": False,
            "tls_verified": False,
            "message": "SSL/TLS certificate verification failed"
        }

    except requests.RequestException as error:
        return {
            "source": "Website Security Check",
            "status": "error",
            "message": str(error)
        }
    
def check_security_headers(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        headers = response.headers

        security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]

        present_headers = []
        missing_headers = []

        for header in security_headers:
            if header in headers:
                present_headers.append(header)
            else:
                missing_headers.append(header)

        return {
            "source": "Website Security Headers",
            "status": "success",
            "url": response.url,
            "status_code": response.status_code,
            "present_headers": present_headers,
            "missing_headers": missing_headers
        }

    except requests.RequestException as error:
        return {
            "source": "Website Security Headers",
            "status": "error",
            "message": str(error)
        }
    
class MixedContentParser(HTMLParser):

    def __init__(self):
        super().__init__()
        self.insecure_resources = []

    def check_resource(self, tag, attribute, value):
        if value and value.strip().lower().startswith("http://"):
            self.insecure_resources.append({
                "tag": tag,
                "attribute": attribute,
                "url": value.strip()
            })

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag in ["script", "img", "iframe", "audio", "video", "source"]:
            self.check_resource(tag, "src", attrs.get("src"))

        elif tag in ["link"]:
            self.check_resource(tag, "href", attrs.get("href"))

        elif tag in ["object"]:
            self.check_resource(tag, "data", attrs.get("data"))


def check_mixed_content(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        final_url = response.url

        if urlparse(final_url).scheme.lower() != "https":
            return {
                "source": "Mixed Content Check",
                "status": "skipped",
                "message": "Mixed-content check requires an HTTPS webpage."
            }

        parser = MixedContentParser()
        parser.feed(response.text)

        insecure_resources = []

        for resource in parser.insecure_resources:
            resource["url"] = urljoin(final_url, resource["url"])
            insecure_resources.append(resource)

        return {
            "source": "Mixed Content Check",
            "status": "success",
            "url": final_url,
            "mixed_content_found": len(insecure_resources) > 0,
            "insecure_resource_count": len(insecure_resources),
            "insecure_resources": insecure_resources
        }

    except requests.RequestException as error:
        return {
            "source": "Mixed Content Check",
            "status": "error",
            "message": str(error)
        }
    
def detect_website_technology(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        headers = response.headers
        html = response.text
        technologies = []

        # Detect web server
        server = headers.get("Server")
        if server:
            technologies.append({
                "type": "Web Server",
                "name": server,
                "source": "Server header"
            })

        # Detect programming language hints
        powered_by = headers.get("X-Powered-By")
        if powered_by:
            technologies.append({
                "type": "Backend Technology",
                "name": powered_by,
                "source": "X-Powered-By header"
            })

        # Detect WordPress
        if "wp-content" in html or "wp-includes" in html:
            technologies.append({
                "type": "CMS",
                "name": "WordPress",
                "source": "HTML content"
            })

        # Detect React
        if "react" in html.lower() or "data-reactroot" in html.lower():
            technologies.append({
                "type": "JavaScript Framework",
                "name": "React (possible)",
                "source": "HTML content"
            })

        # Detect generator information
        generator = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
            html,
            re.IGNORECASE
        )

        if generator:
            technologies.append({
                "type": "CMS or Platform",
                "name": generator.group(1),
                "source": "HTML generator metadata"
            })

        return {
            "source": "Technology Detection",
            "status": "success",
            "url": response.url,
            "technologies_found": technologies
        }

    except requests.RequestException as error:
        return {
            "source": "Technology Detection",
            "status": "error",
            "message": str(error)
        }



