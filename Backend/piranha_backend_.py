import asyncio
import base64
import html
import logging
import os
import time

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import create_engine, text

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Chrome extension requests come from chrome-extension://<extension-id>.
# Set CORS_ORIGINS to a comma-separated list, e.g. chrome-extension://abcd...
CORS_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("CORS_ORIGINS", "").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.get("/health")
def health():
    return {"status": "ok"}

# Set DATABASE_URL in the environment instead of committing real credentials.
DATABASE_URL = os.environ["DATABASE_URL"]


# Initialize Database Engine
engine = create_engine(DATABASE_URL)

# VirusTotal API key must stay server-side; We should never expose it to the extension.
VIRUSTOTAL_API_KEY = os.environ["VIRUSTOTAL_API_KEY"]
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
VIRUSTOTAL_POLL_TIMEOUT_SECONDS = 60
VIRUSTOTAL_POLL_INTERVAL_SECONDS = 5

REPORT_RECEIVED_MESSAGE = (
    "Thank you for your report. If it is confirmed, we will email you at the "
    "address you provided."
)

# Email is optional: without these, reports are still stored but no mail is sent.
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "Piranha <onboarding@resend.dev>")
RESEND_URL = "https://api.resend.com/emails"
logger = logging.getLogger("piranha")


def _defang(url: str) -> str:
    # Keep the reported link from being clickable in the email.
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


async def send_acceptance_email(user_id: int, name: str, email: str, url: str) -> None:
    if not RESEND_API_KEY:
        logger.warning("RESEND_API_KEY not set; skipping acceptance email")
        return
    body = (
        f"<p>Hi {html.escape(name)},</p>"
        "<p>Thank you for your report. We confirmed that the following site is "
        "malicious and added it to the Piranha community blocklist:</p>"
        f"<p><code>{html.escape(_defang(url))}</code></p>"
        "<p>Do not visit this address. You received this email because this "
        "address was entered in a Piranha report form.</p>"
    )
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(
                RESEND_URL,
                headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
                json={
                    "from": EMAIL_FROM,
                    "to": [email],
                    "subject": "Your Piranha report was accepted",
                    "html": body,
                },
            )
            response.raise_for_status()
        with engine.connect() as connection:
            connection.execute(
                text("""
                    UPDATE url_reports SET notified_at = now()
                    WHERE user_id = :user_id AND malicious_url = :url
                      AND notified_at IS NULL
                """),
                {"user_id": user_id, "url": url},
            )
            connection.commit()
    except Exception:
        # A failed email must never affect the report itself.
        logger.exception("Failed to send acceptance email")


def _url_to_virustotal_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


async def _get_existing_analysis_stats(client: httpx.AsyncClient, url: str) -> dict | None:
    url_id = _url_to_virustotal_id(url)
    response = await client.get(f"{VIRUSTOTAL_BASE_URL}/urls/{url_id}")
    if response.status_code != 200:
        return None
    return response.json()["data"]["attributes"]["last_analysis_stats"]


async def _submit_url_for_analysis(client: httpx.AsyncClient, url: str) -> str:
    response = await client.post(f"{VIRUSTOTAL_BASE_URL}/urls", data={"url": url})
    response.raise_for_status()
    return response.json()["data"]["id"]


async def _poll_analysis_stats(client: httpx.AsyncClient, analysis_id: str) -> dict | None:
    deadline = time.monotonic() + VIRUSTOTAL_POLL_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        response = await client.get(f"{VIRUSTOTAL_BASE_URL}/analyses/{analysis_id}")
        response.raise_for_status()
        attributes = response.json()["data"]["attributes"]
        if attributes["status"] == "completed":
            return attributes["stats"]
        await asyncio.sleep(VIRUSTOTAL_POLL_INTERVAL_SECONDS)
    return None


async def is_flagged_malicious(url: str) -> bool:
    # Any lookup/submission/polling failure is treated as "not confirmed malicious".
    try:
        async with httpx.AsyncClient(headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=30) as client:
            stats = await _get_existing_analysis_stats(client, url)
            if stats is None:
                analysis_id = await _submit_url_for_analysis(client, url)
                stats = await _poll_analysis_stats(client, analysis_id)

            if stats is None:
                return False

            return stats.get("malicious", 0) >= 1
    except (httpx.HTTPError, KeyError, ValueError):
        return False


# Data validation model for incoming extension requests
class ReportRequest(BaseModel):
    name: str = Field(max_length=100)
    email: EmailStr
    malicious_url: str = Field(max_length=2048)
    reason: str | None = Field(default=None, max_length=2000)

@app.post("/api/report")
@limiter.limit("10/minute")
async def submit_report(
    request: Request, payload: ReportRequest, background_tasks: BackgroundTasks
):

    # Only store reports VirusTotal confirms as malicious; everything else
    # still gets the same neutral acknowledgement below.
    if not await is_flagged_malicious(payload.malicious_url):
        return {"status": "received", "message": REPORT_RECEIVED_MESSAGE}

    try:
        with engine.connect() as connection:
            # 1. Insert or get User ID
            user_query = text("""
                INSERT INTO users (name, email) 
                VALUES (:name, :email) 
                ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name
                RETURNING user_id;
            """)
            result = connection.execute(user_query, {"name": payload.name, "email": payload.email})
            user_id = result.fetchone()[0]

            # 2. Insert the Malicious URL Report, approved since VirusTotal flagged it
            # Only the first report of a URL by a user triggers an email.
            already_notified = connection.execute(
                text("""
                    SELECT 1 FROM url_reports
                    WHERE user_id = :user_id AND malicious_url = :url
                      AND notified_at IS NOT NULL
                    LIMIT 1
                """),
                {"user_id": user_id, "url": payload.malicious_url},
            ).fetchone() is not None

            report_query = text("""
                INSERT INTO url_reports (user_id, malicious_url, reason, status) 
                VALUES (:user_id, :url, :reason, 'approved');
            """) 
            connection.execute(report_query, {
                "user_id": user_id, 
                "url": payload.malicious_url, 
                "reason": payload.reason
            })
            
            # Commit transaction to save changes
            connection.commit()

        if not already_notified:
            background_tasks.add_task(
                send_acceptance_email,
                user_id,
                payload.name,
                payload.email,
                payload.malicious_url,
            )

        return {"status": "received", "message": REPORT_RECEIVED_MESSAGE}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/blocked-sites")
async def get_blocked_sites():
    try:
        with engine.connect() as connection:
            query = text("""
                SELECT DISTINCT malicious_url
                FROM url_reports
                WHERE status = 'approved';
            """)
            result = connection.execute(query)
            sites = [row[0] for row in result.fetchall()]

        return {"sites": sites}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
