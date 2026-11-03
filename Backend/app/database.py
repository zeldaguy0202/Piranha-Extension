from datetime import datetime, timezone
import hashlib
import hmac

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, create_engine, inspect, text
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
database_url = settings.database_url
if database_url.startswith("postgresql://"):
    database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
engine_options = {"connect_args": connect_args, "pool_pre_ping": True}
if database_url in {"sqlite://", "sqlite:///:memory:"}:
    engine_options["poolclass"] = StaticPool
engine = create_engine(database_url, **engine_options)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def migrate_legacy_postgres_schema() -> None:
    """Add the normalized columns used by v2 without deleting teammate data."""
    if engine.dialect.name != "postgresql":
        return
    with engine.begin() as connection:
        tables = set(inspect(connection).get_table_names())
        if "users" in tables:
            columns = {item["name"] for item in inspect(connection).get_columns("users")}
            if "id" not in columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN id BIGSERIAL"))
                if "user_id" in columns:
                    connection.execute(text("UPDATE users SET id = user_id"))
                    connection.execute(text("SELECT setval(pg_get_serial_sequence('users', 'user_id'), COALESCE((SELECT MAX(user_id) FROM users), 0) + 1, false)"))
                connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_id ON users (id)"))
                connection.execute(text("SELECT setval(pg_get_serial_sequence('users', 'id'), COALESCE((SELECT MAX(id) FROM users), 0) + 1, false)"))
        if "url_reports" in tables:
            columns = {item["name"] for item in inspect(connection).get_columns("url_reports")}
            if "id" not in columns:
                connection.execute(text("ALTER TABLE url_reports ADD COLUMN id BIGSERIAL"))
                if "report_id" in columns:
                    connection.execute(text("UPDATE url_reports SET id = report_id"))
                connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_url_reports_id ON url_reports (id)"))
                connection.execute(text("SELECT setval(pg_get_serial_sequence('url_reports', 'id'), COALESCE((SELECT MAX(id) FROM url_reports), 0) + 1, false)"))
            if "normalized_url" not in columns:
                connection.execute(text("ALTER TABLE url_reports ADD COLUMN normalized_url TEXT"))
                if "malicious_url" in columns:
                    connection.execute(text("UPDATE url_reports SET normalized_url = malicious_url WHERE normalized_url IS NULL"))
                connection.execute(text("CREATE INDEX IF NOT EXISTS ix_url_reports_normalized_url ON url_reports (normalized_url)"))
            if "malicious_url" in columns:
                connection.execute(text("ALTER TABLE url_reports ALTER COLUMN malicious_url DROP NOT NULL"))
            if "status" in columns:
                connection.execute(text("ALTER TABLE url_reports ALTER COLUMN status SET DEFAULT 'pending'"))
            if "created_at" not in columns:
                connection.execute(text("ALTER TABLE url_reports ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now()"))


def create_tables() -> None:
    migrate_legacy_postgres_schema()
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
