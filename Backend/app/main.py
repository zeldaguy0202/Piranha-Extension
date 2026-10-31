from contextlib import asynccontextmanager
from collections import defaultdict, deque
from datetime import datetime, timezone
from datetime import timedelta
import asyncio
import hashlib
import hmac
import html
import ipaddress
import logging
import re
from pathlib import Path

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import get_settings
from .database import ExternalThreatCache, ThreatIndicator, URLReport, User, create_tables, get_db
from .providers import check_google_safe_browsing, check_hibp, check_phishtank, check_threatfox, check_urlhaus, check_virustotal, check_virustotal_ip, get_pwned_password_range
from .schemas import HIBPBreach, HIBPResponse, IPReputationResponse, IndicatorRequest, PasswordRangeResponse, ReportRequest, ReportResponse, URLScanRequest, URLScanResponse
from .url_analysis import InvalidURL, heuristic_evidence, normalize_url


@asynccontextmanager
async def lifespan(_: FastAPI):
    create_tables()
    yield


settings = get_settings()
app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)
DASHBOARD_DIR = Path(__file__).resolve().parents[2] / "Dashboard"
REPORT_WINDOW_SECONDS = 60
REPORT_LIMIT = 10
report_attempts: dict[str, deque[float]] = defaultdict(deque)
logger = logging.getLogger("piranha")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_origin_regex=r"chrome-extension://[a-p]{32}",
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Admin-Key"],
)


def parsed_url(raw_url: str):
    try:
        return normalize_url(raw_url)
    except InvalidURL as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def enforce_report_limit(request: Request) -> None:
    """Small deployment-safe guard for the public report form."""
    import time

    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    attempts = report_attempts[client]
    while attempts and now - attempts[0] > REPORT_WINDOW_SECONDS:
        attempts.popleft()
    if len(attempts) >= REPORT_LIMIT:
        raise HTTPException(status_code=429, detail="Too many reports; try again in one minute")
    attempts.append(now)


async def send_report_receipt(name: str, email: str, url: str) -> None:
    if not settings.resend_api_key:
        return
    safe_name = html.escape(name)
    safe_url = html.escape(url.replace(".", "[.]").replace("http", "hxxp", 1))
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {settings.resend_api_key}"},
                json={
                    "from": settings.email_from,
                    "to": [email],
                    "subject": "Piranha received your report",
                    "html": f"<p>Hi {safe_name},</p><p>Piranha received your report for <code>{safe_url}</code>. It will contribute to community protection after corroboration.</p>",
                },
            )
            response.raise_for_status()
    except httpx.HTTPError:
        logger.exception("Unable to send report receipt")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": settings.app_name}


@app.get("/", response_class=FileResponse, include_in_schema=False)
def dashboard_home():
    return FileResponse(DASHBOARD_DIR / "index.html")


@app.get("/api/dashboard/stats")
def dashboard_stats(db: Session = Depends(get_db)):
    reports = db.scalar(select(func.count()).select_from(URLReport)) or 0
    indicators = db.scalar(select(func.count()).select_from(ThreatIndicator)) or 0
    cached_threats = db.scalar(select(func.count()).select_from(ExternalThreatCache)) or 0
    reporters = db.scalar(select(func.count(func.distinct(URLReport.user_id)))) or 0
    recent = db.scalars(select(ExternalThreatCache).order_by(ExternalThreatCache.checked_at.desc()).limit(8)).all()
    return {
        "reports": reports,
        "reporters": reporters,
        "trusted_indicators": indicators,
        "confirmed_provider_matches": cached_threats,
        "recent_threats": [
            {
                "url": item.normalized_url,
                "sources": item.sources.split(","),
                "checked_at": item.checked_at.isoformat() + "Z",
                "expires_at": item.expires_at.isoformat() + "Z",
            }
            for item in recent
        ],
        "providers": {
            "PhishTank": settings.phishtank_enabled,
            "URLhaus": bool(settings.urlhaus_auth_key),
            "ThreatFox": bool(settings.threatfox_auth_key),
            "Google Safe Browsing": bool(settings.google_safe_browsing_api_key),
            "VirusTotal": bool(settings.virustotal_api_key),
            "HIBP Pwned Passwords": True,
            "HIBP Account Search": bool(settings.hibp_api_key),
        },
    }


@app.get("/test/password", response_class=HTMLResponse, include_in_schema=False)
def password_test_page():
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Piranha Password Test</title>
<style>body{font-family:system-ui;max-width:520px;margin:60px auto;padding:24px;background:#f5f6f8}
main{background:white;padding:28px;border-radius:12px;box-shadow:0 8px 30px #0002}label{display:block;margin:18px 0 6px}
input{width:100%;box-sizing:border-box;padding:12px;border:1px solid #aaa;border-radius:7px}button{margin-top:20px;padding:12px 18px}</style>
</head><body><main><h1>Piranha Password Test</h1>
<p>This form stays on your computer and does not submit anything. Enter a test password, then click outside the field.</p>
<form onsubmit="event.preventDefault()"><label for="new-password">New password</label>
<input id="new-password" name="new-password" type="password" autocomplete="new-password">
<label for="confirm-password">Confirm password</label>
<input id="confirm-password" name="confirm-password" type="password" autocomplete="new-password">
<button type="submit">Create test account</button></form></main></body></html>"""


@app.post("/api/scan", response_model=URLScanResponse)
async def scan_url(payload: URLScanRequest, db: Session = Depends(get_db)):
    target = parsed_url(payload.url)
    evidence = heuristic_evidence(target)
    indicators = db.scalars(select(ThreatIndicator).where(or_(
        (ThreatIndicator.indicator_type == "url") & (ThreatIndicator.value == target.url),
        (ThreatIndicator.indicator_type == "domain") & (ThreatIndicator.value == target.hostname),
    ))).all()
    for indicator in indicators:
        evidence.append({"source": indicator.source, "category": indicator.threat_type, "detail": f"Matched a locally stored {indicator.indicator_type} threat indicator.", "score": indicator.confidence})

    reporter_count = db.scalar(select(func.count(func.distinct(URLReport.user_id))).where(URLReport.normalized_url == target.url)) or 0
    if reporter_count >= 2:
        evidence.append({"source": "Piranha community", "category": "community_reports", "detail": f"Reported by {reporter_count} distinct community members; reports are not independently verified.", "score": min(50, 15 + reporter_count * 5)})

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cached = db.scalar(select(ExternalThreatCache).where(
        ExternalThreatCache.normalized_url == target.url,
        ExternalThreatCache.expires_at > now,
    ))
    provider_statuses = []
    if cached:
        evidence.extend(cached.evidence)
        provider_statuses = [{"provider": source, "status": "checked", "detail": "Confirmed match loaded from positive cache."} for source in cached.sources.split(",")]
    else:
        results = await asyncio.gather(
            check_urlhaus(target.url, settings),
            check_phishtank(target.url, settings),
            check_threatfox(target.hostname, settings),
            check_google_safe_browsing(target.url, settings),
            check_virustotal(target.url, settings),
        )
        positive_evidence = []
        for provider_evidence, provider_status in results:
            provider_statuses.append(provider_status)
            if provider_evidence:
                evidence.append(provider_evidence)
                positive_evidence.append(provider_evidence)
        if positive_evidence:
            default_seconds = settings.positive_cache_hours * 3600
            cache_seconds = min([default_seconds] + [item["cache_seconds"] for item in positive_evidence if "cache_seconds" in item])
            stored_evidence = [{key: value for key, value in item.items() if key != "cache_seconds"} for item in positive_evidence]
            cache_record = db.scalar(select(ExternalThreatCache).where(ExternalThreatCache.normalized_url == target.url))
            if cache_record is None:
                cache_record = ExternalThreatCache(normalized_url=target.url)
                db.add(cache_record)
            cache_record.evidence = stored_evidence
            cache_record.sources = ",".join(sorted({item["source"] for item in positive_evidence}))
            cache_record.checked_at = now
            cache_record.expires_at = now + timedelta(seconds=cache_seconds)
            db.commit()
    score = min(100, sum(item["score"] for item in evidence))
    known_match = any(item["category"] in {"known_malware_url", "malware", "phishing"} and item["score"] >= 80 for item in evidence)
    verdict = "malicious" if known_match else "suspicious" if score >= 35 else "unknown"
    return URLScanResponse(original_url=payload.url, normalized_url=target.url, hostname=target.hostname, verdict=verdict, risk_score=score, evidence=evidence, providers=provider_statuses, checked_at=datetime.now(timezone.utc))


@app.post("/api/report", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
def submit_report(
    payload: ReportRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    enforce_report_limit(request)
    target = parsed_url(payload.malicious_url)
    email = str(payload.email).strip().lower()
    identity = hmac.new(settings.report_identity_secret.encode(), email.encode(), hashlib.sha256).hexdigest()
    user = db.scalar(select(User).where(User.email == identity))
    if user is None:
        user = User(name=payload.name.strip(), email=identity)
        db.add(user)
        db.flush()
    else:
        user.name = payload.name.strip()
    existing = db.scalar(select(URLReport).where(
        URLReport.user_id == user.id,
        URLReport.normalized_url == target.url,
    ))
    if existing:
        existing.reason = payload.reason or existing.reason
        db.commit()
        background_tasks.add_task(send_report_receipt, payload.name.strip(), email, target.url)
        return ReportResponse(status="accepted", report_id=existing.id, normalized_url=target.url)
    report = URLReport(user_id=user.id, normalized_url=target.url, reason=payload.reason)
    db.add(report)
    db.commit()
    db.refresh(report)
    background_tasks.add_task(send_report_receipt, payload.name.strip(), email, target.url)
    return ReportResponse(status="accepted", report_id=report.id, normalized_url=target.url)


@app.get("/api/blocked-sites")
def community_blocked_sites(db: Session = Depends(get_db)):
    """Return corroborated community reports for extension background sync."""
    rows = db.execute(
        select(URLReport.normalized_url, func.count(func.distinct(URLReport.user_id)).label("reporters"))
        .group_by(URLReport.normalized_url)
        .having(func.count(func.distinct(URLReport.user_id)) >= 2)
        .order_by(URLReport.normalized_url)
    ).all()
    return {"sites": [row.normalized_url for row in rows]}


@app.get("/api/ip/{ip_address}", response_model=IPReputationResponse)
async def ip_reputation(ip_address: str):
    try:
        normalized = str(ipaddress.ip_address(ip_address))
        result = await check_virustotal_ip(normalized, settings)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Enter a valid IPv4 or IPv6 address") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="VirusTotal is temporarily unavailable") from exc
    malicious = result.get("malicious", 0)
    suspicious = result.get("suspicious", 0)
    score = 100 if malicious >= 2 else 50 if malicious == 1 or suspicious else 0
    verdict = "malicious" if malicious >= 2 else "suspicious" if score else "unknown"
    return IPReputationResponse(
        ip_address=normalized,
        verdict=verdict,
        risk_score=score,
        malicious_detections=malicious,
        suspicious_detections=suspicious,
        country=result.get("country"),
        network=result.get("network"),
        owner=result.get("owner"),
        checked_at=datetime.now(timezone.utc),
    )


@app.post("/api/indicators", status_code=status.HTTP_201_CREATED)
def add_indicator(payload: IndicatorRequest, x_admin_key: str | None = Header(default=None), db: Session = Depends(get_db)):
    if not settings.admin_api_key:
        raise HTTPException(status_code=503, detail="Indicator administration is disabled")
    if not x_admin_key or not hmac.compare_digest(x_admin_key, settings.admin_api_key):
        raise HTTPException(status_code=401, detail="Invalid admin API key")
    value = parsed_url(payload.value).url if payload.indicator_type == "url" else parsed_url(f"https://{payload.value}").hostname
    indicator = ThreatIndicator(value=value, indicator_type=payload.indicator_type, source=payload.source, threat_type=payload.threat_type, confidence=payload.confidence)
    db.add(indicator)
    try:
        db.commit()
        db.refresh(indicator)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Indicator already exists") from exc
    return {"status": "created", "indicator_id": indicator.id}


@app.get("/api/breaches/{email}", response_model=HIBPResponse)
async def breached_account(email: str):
    try:
        validated = ReportRequest(name="lookup", email=email, malicious_url="https://example.com").email
        breaches = await check_hibp(str(validated), settings)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail=f"HIBP returned HTTP {exc.response.status_code}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid email address") from exc
    result = [HIBPBreach(name=b["Name"], title=b["Title"], domain=b.get("Domain", ""), breach_date=b["BreachDate"], data_classes=b.get("DataClasses", [])) for b in breaches]
    return HIBPResponse(email=validated, breached=bool(result), breaches=result)


@app.get("/api/password/range/{prefix}", response_model=PasswordRangeResponse)
async def pwned_password_range(prefix: str):
    normalized = prefix.upper()
    if not re.fullmatch(r"[0-9A-F]{5}", normalized):
        raise HTTPException(status_code=422, detail="Prefix must contain exactly five hexadecimal characters")
    try:
        matches = await get_pwned_password_range(normalized, settings)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Pwned Passwords service is unavailable") from exc
    return PasswordRangeResponse(prefix=normalized, matches=matches)


app.mount("/dashboard", StaticFiles(directory=DASHBOARD_DIR), name="dashboard")
