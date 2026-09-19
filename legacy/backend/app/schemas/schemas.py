"""Pydantic v2 schemas for API validation."""
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Any, Dict
from datetime import datetime
from enum import Enum


class UserRole(str, Enum):
    ANALYST = "ANALYST"
    SENIOR_ANALYST = "SENIOR_ANALYST"
    ADMINISTRATOR = "ADMINISTRATOR"


class CaseStatus(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"


# ─── Auth ─────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class CreateUserRequest(BaseModel):
    name: str
    email: EmailStr
    password: str = Field(min_length=8)
    role: UserRole = UserRole.ANALYST


class UpdateUserRequest(BaseModel):
    name: Optional[str] = None
    role: Optional[UserRole] = None
    status: Optional[str] = None


# ─── Email Analysis ──────────────────────────────────────────────────────────

class AnalyzeRawRequest(BaseModel):
    raw_email: str
    case_id: Optional[str] = None


# ─── Cases ────────────────────────────────────────────────────────────────────

class CaseNote(BaseModel):
    content: str


class CreateCaseRequest(BaseModel):
    title: str
    classification: str
    sender: str
    subject: str
    risk_score: int = 0
    email_analysis_id: Optional[str] = None


class UpdateCaseRequest(BaseModel):
    status: Optional[CaseStatus] = None
    title: Optional[str] = None
    classification: Optional[str] = None
    analyst_id: Optional[str] = None


# ─── Reports ──────────────────────────────────────────────────────────────────

class GenerateReportRequest(BaseModel):
    case_id: str
    title: Optional[str] = None
    include_iocs: bool = True
    include_headers: bool = True
    include_recommendations: bool = True


# ─── Settings ─────────────────────────────────────────────────────────────────

class VirusTotalSettingsRequest(BaseModel):
    api_key: str


class SystemSettingsUpdate(BaseModel):
    key: str
    value: Any = None
