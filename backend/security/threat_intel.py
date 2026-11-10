
import os
import requests
import base64
from dotenv import load_dotenv
from urllib.parse import urlparse

load_dotenv()

URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

VIRUSTOTAL_API = "https://www.virustotal.com/api/v3/urls/"
VIRUSTOTAL_DOMAIN_API = "https://www.virustotal.com/api/v3/domains/"


def check_urlhaus(url):

    if not URLHAUS_AUTH_KEY:
        return {
            "source": "URLhaus",
            "status": "error",
            "message": "API key missing from .env"
        }

    headers = {
        "Auth-Key": URLHAUS_AUTH_KEY
    }

    data = {
        "url": url
    }

    try:
        response = requests.post(
            URLHAUS_API,
            headers=headers,
            data=data,
            timeout=15
        )

        response.raise_for_status()
        result = response.json()

        return {
            "source": "URLhaus",
            "status": "success",
            "query_status": result.get("query_status"),
            "url": result.get("url"),
            "threat": result.get("threat"),
            "tags": result.get("tags", []),
            "date_added": result.get("date_added"),
            "reference": result.get("urlhaus_reference")
        }

    except requests.RequestException as error:
        return {
            "source": "URLhaus",
            "status": "error",
            "message": str(error)
        }
def check_virustotal(url):

    if not VIRUSTOTAL_API_KEY:
        return {
            "source": "VirusTotal",
            "status": "error",
            "message": "API key missing from .env"
        }

    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(
            VIRUSTOTAL_API + url_id,
            headers=headers,
            timeout=15
        )

        if response.status_code == 404:
            return {
                "source": "VirusTotal",
                "status": "success",
                "query_status": "no_report",
                "message": "No existing URL report found."
            }

        response.raise_for_status()
        result = response.json()

        stats = result.get("data", {}).get(
            "attributes", {}
        ).get("last_analysis_stats", {})

        return {
            "source": "VirusTotal",
            "status": "success",
            "query_status": "report_found",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reference": result.get("data", {}).get("links", {}).get("self")
        }

    except requests.RequestException as error:
        return {
            "source": "VirusTotal",
            "status": "error",
            "message": str(error)
        }
def check_virustotal_domain(domain):

    if not VIRUSTOTAL_API_KEY:
        return {
            "source": "VirusTotal",
            "status": "error",
            "message": "API key missing from .env"
        }

    parsed = urlparse(
        domain if "://" in domain else "https://" + domain
    )

    hostname = parsed.hostname

    if not hostname:
        return {
            "source": "VirusTotal",
            "status": "error",
            "message": "Invalid domain"
        }

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(
            VIRUSTOTAL_DOMAIN_API + hostname,
            headers=headers,
            timeout=15
        )

        if response.status_code == 404:
            return {
                "source": "VirusTotal",
                "status": "success",
                "query_status": "no_report",
                "domain": hostname
            }

        response.raise_for_status()
        result = response.json()

        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "source": "VirusTotal",
            "status": "success",
            "query_status": "report_found",
            "domain": hostname,
            "reputation": attributes.get("reputation"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reference": result.get("data", {}).get("links", {}).get("self")
        }

    except requests.RequestException as error:
        return {
            "source": "VirusTotal",
            "status": "error",
            "message": str(error)
        }