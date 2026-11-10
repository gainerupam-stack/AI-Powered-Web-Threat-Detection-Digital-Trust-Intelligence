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
# TrustGuard AI — Member 4: Risk, Reports, Database & Web3

Python/FastAPI service scaffold for deterministic risk assessment, report persistence,
and optional Ethereum Sepolia report-digest registration and verification.

## 1. Run in VS Code

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env   # Windows; on macOS/Linux use: cp .env.example .env
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs`.

## 2. API

- `GET /health`
- `POST /api/v1/investigations?register_on_chain=false`
- `GET /api/v1/reports/{report_id}?revision=1`
- `GET /api/v1/reports/{report_id}/verify?revision=1`

Example POST body:

```json
{
  "url": "https://example.test/login",
  "subject_ref": "case-2026-001",
  "url_tls": {"tls_invalid": true, "suspicious_redirect": false},
  "threat_intel": {"threat_feed_match": false},
  "ai_analysis": {"phishing_language": true, "ai_high_risk": false},
  "notes": "Internal analyst note"
}
```

The raw URL and notes are stored only in the private database table. The public report
and its hash exclude those fields. Do not pass passwords, tokens, or unnecessary PII.

## 3. Risk scoring rules

The score is deterministic and capped at 99 unless `confirmed_malicious` is explicitly
reported, which yields 100 / `Confirmed Malicious`.

| Indicator | Weight |
|---|---:|
| threat_feed_match | 70 |
| phishing_language | 25 |
| suspicious_redirect | 20 |
| tls_invalid | 20 |
| domain_very_new | 15 |
| brand_impersonation | 25 |
| url_obfuscation | 15 |
| ai_high_risk | 25 |

Classification: 0–29 Low Risk; 30–69 Suspicious; 70–99 High Risk;
explicit confirmed-malicious flag = Confirmed Malicious. If all module findings are
empty, classification is Inconclusive. A low score means no configured indicators
were triggered; it is not a guarantee of safety. Adjust weights only with team approval.

## 4. Sepolia deployment

1. Install Solidity compiler `solc` version 0.8.20 or compatible.
2. Compile from project root:
   `solc --combined-json abi,bin contracts/ReportRegistry.sol > build.json`
3. Copy `.env.example` to `.env`; set `SEPOLIA_RPC_URL` and `SEPOLIA_PRIVATE_KEY`.
4. Fund the deployer with Sepolia ETH from a faucet.
5. Run `python scripts/deploy_contract.py`.
6. Copy printed contract address into `REPORT_REGISTRY_ADDRESS` in `.env`.
7. Restart the API. Use `POST ...?register_on_chain=true`.

The deployment script prints the real contract address and deployment transaction
hash only after you run it with your own wallet/RPC. No address or transaction hash is
fabricated or embedded in this starter project.

## 5. Verification semantics

Verification reloads the stored canonical report, independently recalculates SHA-256,
compares it with the database digest, then queries the contract for that digest.
A positive result proves that the same digest was registered on-chain; it does **not**
prove the report's findings are true or that the original data source was trustworthy.

## 6. Database and failure handling

SQLite is used by default for local development. Set `DATABASE_URL` to a PostgreSQL
SQLAlchemy URL for team deployment (install the appropriate PostgreSQL driver).
Database persistence happens before the optional blockchain call. A failed transaction
is returned in the response as `blockchain.error`; the report remains stored locally.
Blockchain verification unavailability returns HTTP 503.

Tables:
- `investigation_reports`: report JSON, risk result, hash, revision, tx/block metadata.
- `private_inputs`: raw URL and private notes, kept off-chain.

## 7. Integration contract

This module accepts the following initial upstream envelope:
`url_tls`, `threat_intel`, `ai_analysis` (each JSON object of normalized indicators).
Coordinate this with the team before merging. Do not rename central API routes or alter
the team's shared schema unilaterally. The report schema is versioned as `1.0`.
For production, add authenticated access, retention policy, migrations (Alembic),
PostgreSQL, rate limiting, structured audit logs, and a revision-creation endpoint.

## 8. Tests

```bash
pytest -q
```

The included tests cover deterministic scoring and canonical hashing. Add integration
tests against a local EVM/test contract and a disposable test database before release.
