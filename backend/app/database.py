from sqlalchemy import create_engine, String, Integer, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from datetime import datetime, timezone
from app.config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class Base(DeclarativeBase): pass

class ReportRecord(Base):
    __tablename__ = "investigation_reports"
    report_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    risk_score: Mapped[int] = mapped_column(Integer)
    risk_category: Mapped[str] = mapped_column(String(40))
    report_json: Mapped[dict] = mapped_column(JSON)
    report_hash: Mapped[str] = mapped_column(String(64), index=True)
    tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    block_number: Mapped[int | None] = mapped_column(Integer, nullable=True)

class PrivateInput(Base):
    __tablename__ = "private_inputs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(String(64), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    raw_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    private_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
