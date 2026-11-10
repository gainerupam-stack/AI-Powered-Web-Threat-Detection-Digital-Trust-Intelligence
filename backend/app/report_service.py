from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy.orm import Session
from app.risk_engine import assess_risk
from app.canonical import report_sha256
from app.database import ReportRecord, PrivateInput
from app.blockchain_service import register_report_hash, verify_report_hash

def create_report(db: Session, payload: dict, register_on_chain: bool = False) -> dict:
    risk = assess_risk(payload.get("url_tls", {}), payload.get("threat_intel", {}),
                       payload.get("ai_analysis", {}))
    report_id = str(uuid4())
    revision = 1
    report = {
        "report_id": report_id, "schema_version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "revision": revision, "subject_ref": payload.get("subject_ref"),
        **risk,
        "findings": {
            "url_tls": payload.get("url_tls", {}),
            "threat_intel": payload.get("threat_intel", {}),
            "ai_analysis": payload.get("ai_analysis", {}),
        }
    }
    digest = report_sha256(report)
    tx = None
    # Database and chain are deliberately separate operations. A chain failure
    # does not discard the locally persisted investigation report.
    record = ReportRecord(report_id=report_id, revision=revision,
        created_at=datetime.now(timezone.utc), risk_score=risk["risk_score"],
        risk_category=risk["risk_category"], report_json=report, report_hash=digest)
    db.add(record)
    db.add(PrivateInput(report_id=report_id, revision=revision,
        raw_url=payload.get("url"), private_notes=payload.get("notes")))
    db.commit()
    if register_on_chain:
        try:
            tx = register_report_hash(digest)
            record.tx_hash, record.block_number = tx["tx_hash"], tx["block_number"]
            db.commit()
        except Exception as exc:
            db.rollback()
            tx = {"error": str(exc)}
    return {**report, "report_hash": digest, "blockchain": tx}

def get_report(db: Session, report_id: str, revision: int = 1):
    row = db.get(ReportRecord, (report_id, revision))
    if not row: return None
    return {**row.report_json, "report_hash": row.report_hash,
            "tx_hash": row.tx_hash, "block_number": row.block_number}

def verify_report(db: Session, report_id: str, revision: int = 1) -> dict:
    row = db.get(ReportRecord, (report_id, revision))
    if not row: raise ValueError("Report not found")
    recalculated = report_sha256(row.report_json)
    local_ok = recalculated == row.report_hash
    chain = verify_report_hash(recalculated)
    return {"report_id": report_id, "revision": revision,
            "recalculated_hash": recalculated, "database_hash": row.report_hash,
            "local_integrity": local_ok, "on_chain": chain,
            "verified": local_ok and chain["exists"]}
