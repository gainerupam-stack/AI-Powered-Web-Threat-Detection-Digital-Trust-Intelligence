from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from AI_msg_analyzer.message_analyzer import analyze_message
from app.database import get_db, init_db
from app.report_service import create_report, get_report, verify_report
from app.schemas import InvestigationCreate
from security.threat_intel import (
    check_urlhaus,
    check_virustotal,
    check_virustotal_domain,
)
from url_tls.analyzer import analyze_url_tls


app = FastAPI(
    title="TrustGuard AI",
    description="Unified digital trust and cyber-intelligence platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    init_db()


class URLRequest(BaseModel):
    url: str = Field(min_length=1)
    include_threat_intel: bool = False


class MessageRequest(BaseModel):
    message: str = Field(min_length=1)


class FullAnalysisRequest(BaseModel):
    url: str | None = None
    message: str | None = None
    subject_ref: str | None = None
    notes: str | None = None
    include_threat_intel: bool = False
    register_on_chain: bool = False


def findings_have(
    findings: list[dict[str, Any]],
    indicators: set[str],
) -> bool:
    return any(
        finding.get("indicator") in indicators
        for finding in findings
    )


def normalize_url_tls(report: dict[str, Any]) -> dict[str, Any]:
    findings = report.get("findings", [])

    return {
        "raw": report,
        "tls_invalid": findings_have(
            findings,
            {
                "tls_certificate_verification_failed",
                "expired_certificate",
                "certificate_not_yet_valid",
                "weak_certificate_signature",
                "weak_rsa_key",
                "weak_ec_key",
                "weak_dsa_key",
            },
        ),
        "suspicious_redirect": any(
            finding.get("source") == "redirect_analyzer"
            and finding.get("severity") in {"medium", "high"}
            for finding in findings
        ),
        "brand_impersonation": findings_have(
            findings,
            {"possible_typosquatting"},
        ),
        "url_obfuscation": findings_have(
            findings,
            {
                "ip_address_url",
                "internationalized_domain",
                "excessive_subdomains",
                "multiple_hyphens",
            },
        ),
    }


def get_threat_intelligence(url: str) -> dict[str, Any]:
    urlhaus = check_urlhaus(url)
    virustotal_url = check_virustotal(url)
    virustotal_domain = check_virustotal_domain(url)

    urlhaus_match = (
        urlhaus.get("status") == "success"
        and urlhaus.get("query_status") == "ok"
    )
    vt_url_match = (
        virustotal_url.get("status") == "success"
        and virustotal_url.get("malicious", 0) > 0
    )
    vt_domain_match = (
        virustotal_domain.get("status") == "success"
        and virustotal_domain.get("malicious", 0) > 0
    )

    return {
        "raw": {
            "urlhaus": urlhaus,
            "virustotal_url": virustotal_url,
            "virustotal_domain": virustotal_domain,
        },
        # A feed match is strong evidence, but is not treated as an absolute
        # malicious verdict by itself.
        "threat_feed_match": urlhaus_match or vt_url_match or vt_domain_match,
    }


def normalize_ai_analysis(result: dict[str, Any]) -> dict[str, Any]:
    if result.get("status") != "completed":
        return {
            "raw": result,
            "phishing_language": False,
            "ai_high_risk": False,
        }

    analysis = result.get("message_analysis", {})
    classification = str(analysis.get("classification", "")).lower()
    indicators = analysis.get("scam_indicators", [])

    high_severity_indicator = any(
        str(item.get("severity", "")).lower() == "high"
        for item in indicators
        if isinstance(item, dict)
    )

    return {
        "raw": result,
        "phishing_language": bool(indicators),
        "ai_high_risk": (
            classification == "high risk"
            or high_severity_indicator
        ),
    }


def run_url_analysis(
    url: str,
    include_threat_intel: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    url_tls_raw = analyze_url_tls(url)
    url_tls = normalize_url_tls(url_tls_raw)

    threat_intel: dict[str, Any] = {}

    # Never run enrichment for invalid or SSRF-blocked targets.
    if (
        include_threat_intel
        and url_tls_raw.get("status") not in {"failed", "blocked"}
    ):
        threat_intel = get_threat_intelligence(url)

    return url_tls, threat_intel


@app.get("/")
def home() -> dict:
    return {
        "status": "online",
        "service": "TrustGuard AI",
        "modules": [
            "url_tls",
            "gemini_message_analysis",
            "threat_intelligence",
            "risk_engine",
            "database_reports",
            "blockchain_verification",
        ],
    }


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze-url")
def analyze_url_endpoint(request: URLRequest) -> dict:
    url_tls, threat_intel = run_url_analysis(
        request.url.strip(),
        request.include_threat_intel,
    )

    return {
        "status": url_tls["raw"].get("status"),
        "url_tls": url_tls,
        "threat_intel": threat_intel,
    }


@app.post("/analyze-message")
def analyze_message_endpoint(request: MessageRequest) -> dict:
    result = analyze_message(request.message.strip())

    if result.get("status") == "error":
        raise HTTPException(
            status_code=502,
            detail=result.get("error", "Gemini message analysis failed."),
        )

    return result


@app.post("/api/v1/investigations", status_code=201)
def create_manual_investigation(
    payload: InvestigationCreate,
    register_on_chain: bool = False,
    db: Session = Depends(get_db),
) -> dict:
    return create_report(
        db,
        payload.model_dump(),
        register_on_chain,
    )


@app.post("/api/v1/analyze", status_code=201)
def analyze_and_create_report(
    request: FullAnalysisRequest,
    db: Session = Depends(get_db),
) -> dict:
    if not request.url and not request.message:
        raise HTTPException(
            status_code=400,
            detail="Provide at least a URL or a message.",
        )

    url_tls: dict[str, Any] = {}
    threat_intel: dict[str, Any] = {}
    ai_analysis: dict[str, Any] = {}

    if request.url:
        url_tls, threat_intel = run_url_analysis(
            request.url.strip(),
            request.include_threat_intel,
        )

    if request.message:
        message_result = analyze_message(request.message.strip())
        ai_analysis = normalize_ai_analysis(message_result)

    payload = {
        "url": request.url,
        "subject_ref": request.subject_ref,
        "notes": request.notes,
        "url_tls": url_tls,
        "threat_intel": threat_intel,
        "ai_analysis": ai_analysis,
    }

    return create_report(
        db,
        payload,
        request.register_on_chain,
    )


@app.get("/api/v1/reports/{report_id}")
def read_report(
    report_id: str,
    revision: int = 1,
    db: Session = Depends(get_db),
) -> dict:
    report = get_report(db, report_id, revision)

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return report


@app.get("/api/v1/reports/{report_id}/verify")
def verify_saved_report(
    report_id: str,
    revision: int = 1,
    db: Session = Depends(get_db),
) -> dict:
    try:
        return verify_report(db, report_id, revision)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail=f"Verification unavailable: {error}",
        )