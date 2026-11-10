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
