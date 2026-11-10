from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from AI_msg_analyzer.message_analyzer import analyze_message
from security.threat_intel import (
    check_urlhaus,
    check_virustotal,
    check_virustotal_domain,
)
from url_tls.analyzer import analyze_url_tls


app = FastAPI(
    title="TrustGuard AI",
    description="Unified URL, TLS, threat-intelligence, and message analysis API",
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


class URLRequest(BaseModel):
    url: str = Field(min_length=1)
    include_threat_intel: bool = False


class MessageRequest(BaseModel):
    message: str = Field(min_length=1)


class CombinedAnalysisRequest(BaseModel):
    url: Optional[str] = None
    message: Optional[str] = None
    include_threat_intel: bool = False


def calculate_risk(findings: list[dict]) -> dict:
    severity_points = {"low": 10, "medium": 25, "high": 45}
    score = min(
        sum(severity_points.get(item.get("severity", "").lower(), 0)
            for item in findings),
        100,
    )

    if score >= 70:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"

    return {
        "score": score,
        "level": level,
        "finding_count": len(findings),
    }


def run_threat_intelligence(url: str) -> dict:
    """Query third-party reputation services only for a validated public URL."""
    return {
        "urlhaus": check_urlhaus(url),
        "virustotal_url": check_virustotal(url),
        "virustotal_domain": check_virustotal_domain(url),
    }


def analyze_url(url: str, include_threat_intel: bool) -> dict:
    url_tls_report = analyze_url_tls(url)

    result = {
        "status": url_tls_report["status"],
        "url_analysis": url_tls_report,
        "threat_intelligence": None,
        "risk": calculate_risk(url_tls_report.get("findings", [])),
    }

    # Never send blocked, invalid, or unresolved destinations into optional
    # enrichment workflows.
    if include_threat_intel and url_tls_report["status"] not in {"blocked", "failed"}:
        result["threat_intelligence"] = run_threat_intelligence(url)

    return result


@app.get("/")
def health() -> dict:
    return {
        "status": "online",
        "service": "TrustGuard AI",
        "modules": [
            "url_tls",
            "gemini_message_analysis",
            "threat_intelligence",
        ],
    }


@app.get("/health")
def health_check() -> dict:
    return {"status": "ok"}


@app.post("/analyze-url")
def analyze_url_endpoint(request: URLRequest) -> dict:
    return analyze_url(
        url=request.url.strip(),
        include_threat_intel=request.include_threat_intel,
    )


@app.post("/analyze-message")
def analyze_message_endpoint(request: MessageRequest) -> dict:
    result = analyze_message(request.message.strip())

    if result.get("status") == "error":
        raise HTTPException(
            status_code=502,
            detail=result.get("error", "Message analysis failed."),
        )

    return result


@app.post("/analyze")
def analyze_combined(request: CombinedAnalysisRequest) -> dict:
    if not request.url and not request.message:
        raise HTTPException(
            status_code=400,
            detail="Provide at least one of: url or message.",
        )

    response = {
        "status": "completed",
        "url_result": None,
        "message_result": None,
        "limitations": [],
    }

    if request.url:
        response["url_result"] = analyze_url(
            url=request.url.strip(),
            include_threat_intel=request.include_threat_intel,
        )

        if response["url_result"]["status"] in {"blocked", "failed"}:
            response["status"] = "partial"

    if request.message:
        message_result = analyze_message(request.message.strip())
        response["message_result"] = message_result

        if message_result.get("status") == "error":
            response["status"] = "partial"
            response["limitations"].append(
                message_result.get("error", "Message analysis failed.")
            )

    return response