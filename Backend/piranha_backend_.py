from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, text

app = FastAPI()

# Replace [PASSWORD] with your actual Supabase password
DATABASE_URL = "postgresql://postgres:yLdXx9Ph7YV%3FSKk@db.rggebvhkehryjwvjmwbj.supabase.co:5432/postgres"


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
