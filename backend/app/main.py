from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from app.database import init_db, get_db
from app.schemas import InvestigationCreate
from app.report_service import create_report, get_report, verify_report

app = FastAPI(title="TrustGuard AI - Risk & Report Service", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://aitrustguard.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()

@app.get("/health")
def health():
    return {"status": "ok", "module": "risk-report-blockchain"}

@app.post("/api/v1/investigations", status_code=201)
def investigate(payload: InvestigationCreate, register_on_chain: bool = False,
                db: Session = Depends(get_db)):
    return create_report(db, payload.model_dump(), register_on_chain)

@app.get("/api/v1/reports/{report_id}")
def read_report(report_id: str, revision: int = 1, db: Session = Depends(get_db)):
    report = get_report(db, report_id, revision)
    if not report: raise HTTPException(404, "Report not found")
    return report

@app.get("/api/v1/reports/{report_id}/verify")
def verify(report_id: str, revision: int = 1, db: Session = Depends(get_db)):
    try: return verify_report(db, report_id, revision)
    except ValueError as exc: raise HTTPException(404, str(exc))
    except Exception as exc: raise HTTPException(503, f"Verification unavailable: {exc}")
