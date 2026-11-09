"""
TrustGuard AI - Safe HTTP Redirect Analyzer

Manually inspects HTTP redirects without automatically following them.
Every destination is validated and DNS-checked before a connection is made.
Website response bodies are never downloaded or executed.
"""

import socket
from urllib.parse import urljoin, urlsplit, quote

from url_tls.url_analyzer import validate_and_analyze_url
from url_tls.safe_connection import open_pinned_connection


REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 5
MAX_HEADER_BYTES = 16384


def add_finding(findings, indicator, severity, evidence, source):
    """Add a structured security finding."""
    findings.append({
        "indicator": indicator,
        "severity": severity,
        "evidence": evidence,
        "source": source
    })


def fetch_response_headers(url, timeout=5):
    """
    Make one safe HTTP/1.1 GET request.
    Read only the response headers, with a strict size limit.
    """

    parsed = urlsplit(url)

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname

    if scheme not in ("http", "https") or not hostname:
        raise ValueError("Unsupported URL or missing hostname.")

    port = parsed.port or (443 if scheme == "https" else 80)

    # Build the request path and query.
    path = quote(
        parsed.path or "/",
        safe="/%:@!$&'()*+,;=-._~"
    )

    query = quote(
        parsed.query,
        safe="/?%:@!$&'()*+,;=-._~"
    )

    request_target = path + (f"?{query}" if query else "")

    if "\r" in request_target or "\n" in request_target:
        raise ValueError("Invalid characters in request path.")

    # Build the Host header, including a non-default port.
    host_header = f"[{hostname}]" if ":" in hostname else hostname

    if parsed.port is not None:
        default_port = 443 if scheme == "https" else 80

        if parsed.port != default_port:
            host_header = f"{host_header}:{parsed.port}"

    request = (
        f"GET {request_target} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "User-Agent: TrustGuard-AI/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")

    # This helper validates DNS results and connects to a pinned IP.
    connection = open_pinned_connection(
        hostname,
        port=port,
        timeout=timeout,
        use_tls=(scheme == "https")
    )

    try:
        connection.sendall(request)

        # Read headers only. Never read or process the response body.
        response_data = b""

        while b"\r\n\r\n" not in response_data:
            remaining = MAX_HEADER_BYTES + 1 - len(response_data)

            if remaining <= 0:
                raise ValueError("Response headers exceed the size limit.")

            chunk = connection.recv(1)

            if not chunk:
                break

            response_data += chunk

        separator = response_data.find(b"\r\n\r\n")

        if separator == -1:
            raise ValueError(
                "Incomplete or oversized HTTP response headers."
            )

        header_text = response_data[:separator].decode(
            "iso-8859-1",
            errors="replace"
        )

        lines = header_text.split("\r\n")

        # Parse the HTTP status line.
        status_parts = lines[0].split()

        if (
            len(status_parts) < 2
            or not status_parts[0].startswith("HTTP/")
            or not status_parts[1].isdigit()
        ):
            raise ValueError("Invalid HTTP status line.")

        status_code = int(status_parts[1])

        # Parse response headers.
        headers = {}

        for line in lines[1:]:
            if not line:
                continue

            if ":" not in line:
                raise ValueError("Malformed HTTP response header.")

            name, value = line.split(":", 1)
            name = name.strip().lower()
            value = value.strip()

            headers.setdefault(name, []).append(value)

        return status_code, headers

    finally:
        connection.close()


def analyze_redirects(raw_url, max_redirects=MAX_REDIRECTS, timeout=5):
    """
    Safely inspect the redirect chain of a URL.

    Returns a JSON-compatible dictionary containing:
    status, initial_url, final_url, redirects, findings, limitations.
    """

    result = {
        "status": "completed",
        "initial_url": raw_url,
        "final_url": None,
        "redirects": [],
        "findings": [],
        "limitations": []
    }

    if not isinstance(max_redirects, int) or not 0 <= max_redirects <= 10:
        result["status"] = "failed"
        result["limitations"].append(
            "max_redirects must be an integer between 0 and 10."
        )
        return result

    if not isinstance(timeout, (int, float)) or timeout <= 0:
        result["status"] = "failed"
        result["limitations"].append("Timeout must be a positive number.")
        return result

    # Validate the initial URL.
    validation = validate_and_analyze_url(raw_url)

    if not validation.get("valid"):
        result["status"] = "failed"
        result["limitations"].extend(validation.get("limitations", []))
        return result

    current_url = validation["normalized_url"]
    result["initial_url"] = current_url

    visited_urls = {current_url}

    for redirect_number in range(max_redirects + 1):

        result["final_url"] = current_url

        try:
            status_code, headers = fetch_response_headers(
                current_url,
                timeout=timeout
            )

        except PermissionError as error:
            result["status"] = "blocked"

            add_finding(
                result["findings"],
                "unsafe_redirect_destination",
                "high",
                str(error),
                "safe_connection"
            )
            break

        except (socket.timeout, TimeoutError):
            result["status"] = "failed"
            result["limitations"].append(
                f"Connection timed out while checking {current_url}."
            )
            break

        except Exception as error:
            result["status"] = "failed"
            result["limitations"].append(
                f"Could not inspect {current_url}: {str(error)}"
            )
            break

        # Stop when the response is not a redirect.
        if status_code not in REDIRECT_STATUSES:
            break

        locations = headers.get("location", [])

        if not locations:
            result["limitations"].append(
                f"HTTP {status_code} response did not contain a Location header."
            )
            break

        if len(locations) != 1:
            result["limitations"].append(
                "Multiple Location headers found; redirect was not followed."
            )
            break


        location = locations[0]

        # Reject malformed or potentially manipulated redirect destinations.
        if (
            not location
            or any(ord(char) < 32 or ord(char) == 127 for char in location)
            or "\\" in location
        ):
            result["status"] = "blocked"
            add_finding(
                result["findings"],
                "invalid_redirect_destination",
                "high",
                "Redirect Location header contains invalid control characters or a backslash.",
                "redirect_analyzer"
            )
            break

        # Resolve relative redirect destinations.
        next_url = urljoin(current_url, location)

        # Validate the redirect destination before connecting.
        next_validation = validate_and_analyze_url(next_url)

        if not next_validation.get("valid"):
            result["status"] = "blocked"

            add_finding(
                result["findings"],
                "invalid_redirect_destination",
                "high",
                f"Redirect destination rejected: {next_url}",
                "url_analyzer"
            )

            result["limitations"].extend(
                next_validation.get("limitations", [])
            )
            break

        next_url = next_validation["normalized_url"]

        # Detect HTTPS-to-HTTP downgrade.
        current_scheme = urlsplit(current_url).scheme
        next_scheme = urlsplit(next_url).scheme

        if current_scheme == "https" and next_scheme == "http":
            add_finding(
                result["findings"],
                "https_to_http_downgrade",
                "high",
                f"Redirect changes from HTTPS to HTTP: {next_url}",
                "redirect_analyzer"
            )

        # Detect redirect loops.
        if next_url in visited_urls:
            add_finding(
                result["findings"],
                "redirect_loop",
                "medium",
                f"Redirect loop detected at {next_url}",
                "redirect_analyzer"
            )
            break

        result["redirects"].append({
            "status_code": status_code,
            "from": current_url,
            "to": next_url
        })

        visited_urls.add(next_url)
        current_url = next_url

        if redirect_number == max_redirects:
            add_finding(
                result["findings"],
                "redirect_limit_reached",
                "medium",
                f"More than {max_redirects} redirects may be present.",
                "redirect_analyzer"
            )

            result["limitations"].append(
                "Redirect inspection stopped at the configured limit."
            )
            break

    return result
