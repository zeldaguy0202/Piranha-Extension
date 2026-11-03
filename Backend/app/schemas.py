from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field


class URLScanRequest(BaseModel):
    url: str = Field(min_length=4, max_length=4096)


class Evidence(BaseModel):
    source: str
    category: str
    detail: str
    score: int = Field(ge=0, le=100)


class ProviderStatus(BaseModel):
    provider: str
    status: Literal["checked", "not_configured", "unavailable"]
    detail: str | None = None


class URLScanResponse(BaseModel):
    original_url: str
    normalized_url: str
    hostname: str
    verdict: Literal["malicious", "suspicious", "unknown"]
    risk_score: int = Field(ge=0, le=100)
    evidence: list[Evidence]
    providers: list[ProviderStatus]
    checked_at: datetime


class ReportRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    malicious_url: str = Field(min_length=4, max_length=4096)
    reason: str | None = Field(default=None, max_length=2000)


class ReportResponse(BaseModel):
    status: Literal["accepted"]
    report_id: int
    normalized_url: str


class IndicatorRequest(BaseModel):
    value: str = Field(min_length=1, max_length=4096)
    indicator_type: Literal["url", "domain"]
    source: str = Field(min_length=1, max_length=80)
    threat_type: str = Field(default="malicious", max_length=80)
    confidence: int = Field(default=90, ge=0, le=100)


class HIBPBreach(BaseModel):
    name: str
    title: str
    domain: str
    breach_date: str
    data_classes: list[str]


class HIBPResponse(BaseModel):
    email: EmailStr
    breached: bool
    breaches: list[HIBPBreach]
    source: str = "Have I Been Pwned"


class PasswordRangeResponse(BaseModel):
    prefix: str
    matches: dict[str, int]
    source: str = "Have I Been Pwned Pwned Passwords"


class IPReputationResponse(BaseModel):
    ip_address: str
    verdict: Literal["malicious", "suspicious", "unknown"]
    risk_score: int = Field(ge=0, le=100)
    malicious_detections: int = 0
    suspicious_detections: int = 0
    country: str | None = None
    network: str | None = None
    owner: str | None = None
    source: str = "VirusTotal"
    checked_at: datetime
