import asyncio
import base64
import os
import time

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, text

app = FastAPI()

# Chrome extension popups send requests from a chrome-extension:// origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# Set DATABASE_URL in the environment instead of committing real credentials.
DATABASE_URL = os.environ["DATABASE_URL"]


# Initialize Database Engine
engine = create_engine(DATABASE_URL)

# VirusTotal API key must stay server-side; never expose it to the extension.
VIRUSTOTAL_API_KEY = os.environ["VIRUSTOTAL_API_KEY"]
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
VIRUSTOTAL_POLL_TIMEOUT_SECONDS = 60
VIRUSTOTAL_POLL_INTERVAL_SECONDS = 5

REPORT_RECEIVED_MESSAGE = (
    "Thank you for your report. We will notify you at a later date if the "
    "site is approved for our list."
)


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
    name: str
    email: EmailStr
    malicious_url: str
    reason: str | None = None

@app.post("/api/report")
async def submit_report(payload: ReportRequest):

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
