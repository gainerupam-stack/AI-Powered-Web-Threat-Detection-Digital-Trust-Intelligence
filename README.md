# TrustGuard AI — URL & TLS Security Analysis Module

## 1. Overview

The `url_tls` module analyzes URLs and their associated domain, DNS, SSL/TLS certificate, and HTTP redirect information.

It is designed as an independent Python module for integration into the main TrustGuard AI backend.

The module identifies suspicious URL patterns, possible typosquatting, unsafe IP destinations, TLS certificate issues, and potentially unsafe redirects.

## 2. Features

- URL validation and normalization.
- Detection of suspicious URL patterns and keywords.
- Possible typosquatting and lookalike-domain detection.
- Domain information and DNS record inspection.
- Public and unsafe IP address validation.
- SSL/TLS certificate inspection.
- Certificate validity, expiry, issuer, hostname and cryptographic information.
- Manual HTTP redirect inspection.
- Redirect-loop and HTTPS-to-HTTP downgrade detection.
- Structured security findings and limitations.
- Graceful handling of network errors and unavailable services.

## 3. Project Structure

```text
url_tls/
├── __init__.py
├── analyzer.py
├── url_analyzer.py
├── domain_analyzer.py
├── tls_analyzer.py
├── safe_connection.py
├── redirect_analyzer.py
├── requirements.txt
└── README.md
```

## 4. Technologies and Dependencies

- Python 3
- dnspython — DNS record inspection.
- tldextract — registered-domain extraction.
- cryptography — certificate inspection.
- httpx — HTTP client dependency.

Python standard libraries are also used for URL parsing, sockets, IP address validation and TLS connections.

## 5. Installation

Open a terminal in the `backend` directory.

Create and activate a virtual environment if one does not already exist:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r url_tls/requirements.txt
```

## 6. Usage

Import the main analysis function:

```python
from url_tls.analyzer import analyze_url_tls
```

Pass a URL to the function:

```python
result = analyze_url_tls("https://example.com")
print(result)
```

For formatted JSON output:

```python
import json
from url_tls.analyzer import analyze_url_tls

result = analyze_url_tls("https://example.com")

print(json.dumps(result, indent=2))
```

### Main Function

```python
analyze_url_tls(raw_url)
```

**Input:** A URL string.

**Output:** A JSON-compatible Python dictionary containing the overall status, findings, limitations and individual module results.

## 7. Output Structure

The main report follows this structure:

```json
{
  "module": "url_tls",
  "status": "completed",
  "findings": [],
  "limitations": [],
  "details": {
    "url_analysis": {},
    "domain_analysis": {},
    "tls_analysis": {},
    "redirect_analysis": {}
  }
}
```

### Finding Structure

Each security finding contains:

```json
{
  "indicator": "possible_typosquatting",
  "severity": "medium",
  "evidence": "Domain resembles a known brand.",
  "source": "url_analyzer"
}
```

### Status Values

- `completed` — Analysis completed successfully.
- `partial` — Some analysis components could not complete.
- `blocked` — An unsafe destination was rejected.
- `failed` — The URL or analysis could not be processed.

## 8. Module Responsibilities

| File | Responsibility |
|---|---|
| `url_analyzer.py` | URL validation, normalization and suspicious-pattern detection |
| `domain_analyzer.py` | Domain extraction, DNS records and IP safety checks |
| `tls_analyzer.py` | TLS connection and certificate inspection |
| `safe_connection.py` | DNS validation and IP-pinned network connections |
| `redirect_analyzer.py` | Manual HTTP redirect inspection |
| `analyzer.py` | Coordinates all modules and produces the combined report |

## 9. Security Measures

- Only HTTP and HTTPS URLs are accepted.
- Private, loopback, link-local and other non-global IP destinations are rejected.
- DNS results are validated before establishing connections.
- Connections use validated IP addresses to reduce DNS rebinding risk.
- Redirect destinations are validated before being followed.
- Redirect inspection is limited to a configurable maximum number of hops.
- HTTP response headers have a size limit.
- Response bodies are not downloaded or executed by the redirect analyzer.
- TLS verification uses Python's default certificate-verifying SSL context.
- Network operations use connection timeouts.

## 10. Error Handling and Limitations

The module handles invalid URLs, DNS lookup failures, connection timeouts, unavailable TLS certificates and malformed HTTP responses.

Some checks depend on external DNS and website availability. Therefore, network failures may produce a `partial` result or a limitation rather than a security finding.

The module performs passive URL, DNS, TLS and redirect analysis. It does not execute website code, download scripts, or perform intrusive vulnerability scanning.

Redirect inspection uses HTTP/1.1 and reads response headers only.

## 11. Running Tests

From the `backend` directory, run:

```powershell
python -m unittest discover -s tests -v
```

The test suite covers URL validation, suspicious patterns, integration behavior and redirect handling.

## 12. Example Test URLs

| Category | Example |
|---|---|
| Benign | `https://www.wikipedia.org` |
| Benign | `https://github.com` |
| Benign | `https://example.com` |
| Suspicious | `https://paypa1.com/login` |
| Suspicious | `https://example.com/login` |
| Unsafe destination | `http://127.0.0.1` |
| Invalid scheme | `javascript:alert(1)` |

These are test inputs, not hardcoded analysis results.

## 13. Backend Integration

The main backend can import the module using:

```python
from url_tls.analyzer import analyze_url_tls
```

Call the function with a submitted URL:

```python
security_report = analyze_url_tls(user_url)
```

The returned dictionary can be passed to the main TrustGuard report-generation layer, subject to the team's existing shared API and report schema.

**Important:** The module should be integrated without independently changing the team's shared API contract.