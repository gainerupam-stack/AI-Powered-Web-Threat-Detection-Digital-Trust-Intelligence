from datetime import datetime, timezone
from typing import Any
from pydantic import BaseModel, Field, HttpUrl

class InvestigationCreate(BaseModel):
    # Keep raw URL in the private database only; it is never put on-chain.
    url: str | None = None
    subject_ref: str | None = None
    url_tls: dict[str, Any] = Field(default_factory=dict)
    threat_intel: dict[str, Any] = Field(default_factory=dict)
    ai_analysis: dict[str, Any] = Field(default_factory=dict)
    notes: str | None = None

class InvestigationReport(BaseModel):
    report_id: str
    schema_version: str = "1.0"
    created_at: datetime
    revision: int = 1
    subject_ref: str | None = None
    risk_score: int
    risk_category: str
    rationale: list[str]
    findings: dict[str, Any]
    # URL, notes, and PII are intentionally excluded from the public report.
    report_hash: str | None = None
