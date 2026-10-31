from datetime import datetime, timezone
import hashlib
import hmac

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import get_settings


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    # Keyed fingerprint used for distinct-reporter counting; the address is not stored.
    email: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    reports: Mapped[list["URLReport"]] = relationship(back_populates="user")


class URLReport(Base):
    __tablename__ = "url_reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    normalized_url: Mapped[str] = mapped_column(Text, index=True)
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    user: Mapped[User] = relationship(back_populates="reports")


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[str] = mapped_column(Text, unique=True, index=True)
    indicator_type: Mapped[str] = mapped_column(String(16), index=True)
    source: Mapped[str] = mapped_column(String(80))
    threat_type: Mapped[str] = mapped_column(String(80), default="malicious")
    confidence: Mapped[int] = mapped_column(Integer, default=90)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ExternalThreatCache(Base):
    """Short-lived cache containing confirmed positive provider matches only."""

    __tablename__ = "external_threat_cache"
    id: Mapped[int] = mapped_column(primary_key=True)
    normalized_url: Mapped[str] = mapped_column(Text, unique=True, index=True)
    evidence: Mapped[list[dict]] = mapped_column(JSON)
    sources: Mapped[str] = mapped_column(String(240))
    checked_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)


settings = get_settings()
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine_options = {"connect_args": connect_args, "pool_pre_ping": True}
if settings.database_url in {"sqlite://", "sqlite:///:memory:"}:
    engine_options["poolclass"] = StaticPool
engine = create_engine(settings.database_url, **engine_options)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def create_tables() -> None:
    Base.metadata.create_all(engine)
    # Upgrade older local databases by replacing previously stored addresses.
    with Session(engine) as db:
        legacy_users = db.query(User).filter(User.email.contains("@")).all()
        for user in legacy_users:
            user.email = hmac.new(
                settings.report_identity_secret.encode(),
                user.email.strip().lower().encode(),
                hashlib.sha256,
            ).hexdigest()
        if legacy_users:
            db.commit()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
