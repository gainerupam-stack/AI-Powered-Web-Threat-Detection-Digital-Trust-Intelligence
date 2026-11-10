"""
TrustGuard AI - Domain Analyzer

Responsibilities:
1. Extract registered domain information.
2. Retrieve DNS records.
3. Identify public and unsafe IP destinations.
4. Provide SSRF safety information.
"""

import ipaddress

import dns.exception
import dns.resolver
import tldextract


# Use the bundled public suffix data.
# This avoids downloading a suffix list at runtime.
DOMAIN_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CAA"]


def add_finding(findings, indicator, severity, evidence):
    findings.append({
        "indicator": indicator,
        "severity": severity,
        "evidence": evidence,
        "source": "domain_analyzer"
    })


def extract_domain_info(hostname):
    """Extract subdomain, registered domain and public suffix."""

    result = DOMAIN_EXTRACTOR(hostname)

    return {
        "subdomain": result.subdomain,
        "registered_domain": result.top_domain_under_public_suffix,
        "public_suffix": result.suffix
    }


def check_ip_safety(ip_address):
    """
    Determine whether an IP is globally routable.

    Non-global addresses are rejected as request destinations.
    """

    try:
        address = ipaddress.ip_address(ip_address)

        return {
            "ip": str(address),
            "version": address.version,
            "is_global": address.is_global,
            "is_private": address.is_private,
            "is_loopback": address.is_loopback,
            "is_link_local": address.is_link_local,
            "is_reserved": address.is_reserved,
            "safe_destination": address.is_global
        }

    except ValueError:
        return {
            "ip": ip_address,
            "safe_destination": False,
            "error": "Invalid IP address"
        }


def get_dns_records(hostname, timeout=2.0):
    """
    Retrieve common DNS records for a hostname.

    DNS failures are reported without crashing the analyzer.
    """

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    records = {}
    limitations = []

    for record_type in DNS_RECORD_TYPES:

        try:
            answers = resolver.resolve(
                hostname,
                record_type,
                raise_on_no_answer=False
            )

            if answers.rrset is None:
                records[record_type] = []
                continue

            records[record_type] = [
                answer.to_text() for answer in answers
            ]

        except dns.resolver.NXDOMAIN:
            records[record_type] = []
            limitations.append(
                f"Domain does not exist: {hostname}"
            )
            break

        except dns.resolver.NoAnswer:
            records[record_type] = []

        except (
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.exception.DNSException
        ) as error:
            records[record_type] = []
            limitations.append(
                f"{record_type} lookup unavailable: "
                f"{type(error).__name__}"
            )

    return records, limitations


def analyze_domain(hostname):
    """
    Analyze domain information and DNS destination safety.

    This function does not make HTTP requests.
    """

    findings = []
    limitations = []

    if not isinstance(hostname, str) or not hostname.strip():
        return {
            "status": "failed",
            "hostname": hostname,
            "domain_info": {},
            "dns_records": {},
            "ip_addresses": [],
            "destination_safety": "unverified",
            "findings": findings,
            "limitations": ["A valid hostname is required."]
        }

    hostname = hostname.strip().rstrip(".").lower()

    try:
        ipaddress.ip_address(hostname)

        # IP-based URLs do not require DNS resolution.
        ip_result = check_ip_safety(hostname)

        if not ip_result["safe_destination"]:
            add_finding(
                findings,
                "unsafe_ip_destination",
                "high",
                f"Non-global IP address rejected: {hostname}"
            )

        return {
            "status": "completed",
            "hostname": hostname,
            "domain_info": {
                "registered_domain": hostname,
                "subdomain": "",
                "public_suffix": ""
            },
            "dns_records": {},
            "ip_addresses": [ip_result],
            "destination_safety": (
                "safe" if ip_result["safe_destination"] else "blocked"
            ),
            "findings": findings,
            "limitations": limitations
        }

    except ValueError:
        pass

    try:
        domain_info = extract_domain_info(hostname)

        if not domain_info["registered_domain"]:
            raise ValueError("Could not identify a registered domain.")

    except Exception as error:
        return {
            "status": "failed",
            "hostname": hostname,
            "domain_info": {},
            "dns_records": {},
            "ip_addresses": [],
            "destination_safety": "unverified",
            "findings": findings,
            "limitations": [str(error)]
        }

    # Retrieve DNS information.
    records, dns_limitations = get_dns_records(hostname)
    limitations.extend(dns_limitations)

    # Collect IPv4 and IPv6 addresses.
    resolved_addresses = (
        records.get("A", []) + records.get("AAAA", [])
    )

    ip_results = [
        check_ip_safety(address)
        for address in resolved_addresses
    ]

    if not ip_results:
        destination_safety = "unverified"

        if not limitations:
            limitations.append(
                "No IP addresses were returned by DNS."
            )

    elif any(
        not result["safe_destination"]
        for result in ip_results
    ):
        destination_safety = "blocked"

        add_finding(
            findings,
            "unsafe_dns_destination",
            "high",
            "At least one DNS-resolved IP is not globally routable."
        )

    else:
        destination_safety = "safe"

    return {
        "status": "completed",
        "hostname": hostname,
        "domain_info": domain_info,
        "dns_records": records,
        "ip_addresses": ip_results,
        "destination_safety": destination_safety,
        "findings": findings,
        "limitations": limitations
    }