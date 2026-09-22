import os

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

# Data validation model for incoming extension requests
class ReportRequest(BaseModel):
    name: str
    email: EmailStr
    malicious_url: str
    reason: str | None = None

@app.post("/api/report")
async def submit_report(payload: ReportRequest): 

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

            # 2. Insert the Malicious URL Report linked to that user
            report_query = text("""
                INSERT INTO url_reports (user_id, malicious_url, reason) 
                VALUES (:user_id, :url, :reason);
            """)
            connection.execute(report_query, {
                "user_id": user_id, 
                "url": payload.malicious_url, 
                "reason": payload.reason
            })
            
            # Commit transaction to save changes
            connection.commit()

        return {"status": "success", "message": "Report saved to Supabase backend successfully!"}

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
