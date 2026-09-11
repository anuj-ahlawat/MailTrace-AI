"""
MailTrace AI — FastAPI Backend
AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform

Start: uvicorn main:app --reload --port 8000
Docs:  http://localhost:8000/docs
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.database import connect_db, close_db

# Routers
from app.api.auth import router as auth_router
from app.api.emails import router as emails_router
from app.api.cases import router as cases_router
from app.api.intelligence import router as intel_router
from app.api.dashboard import router as dashboard_router
from app.api.admin import (
    audit_router, users_router, evidence_router,
    reports_router, campaigns_router, settings_router,
    notifications_router, search_router,
)
from app.gmail.routes import router as gmail_router

import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(name)s — %(levelname)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup + shutdown lifecycle."""
    logger.info("🚀 MailTrace AI backend starting...")
    await connect_db()
    logger.info("✅ MongoDB connected")
    yield
    await close_db()
    logger.info("👋 MongoDB connection closed")


app = FastAPI(
    title="MailTrace AI",
    description="AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all routers
app.include_router(auth_router)
app.include_router(emails_router)
app.include_router(cases_router)
app.include_router(intel_router)
app.include_router(dashboard_router)
app.include_router(audit_router)
app.include_router(users_router)
app.include_router(evidence_router)
app.include_router(reports_router)
app.include_router(campaigns_router)
app.include_router(settings_router)
app.include_router(notifications_router)
app.include_router(search_router)
app.include_router(gmail_router)


@app.get("/", tags=["Health"])
async def root():
    return {
        "service": "MailTrace AI Backend",
        "version": "1.0.0",
        "status": "operational",
        "gmail_configured": settings.gmail_enabled,
        "virustotal_configured": settings.virustotal_enabled,
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
async def health():
    from app.core.database import get_db
    db = get_db()
    try:
        await db.command("ping")
        db_status = "connected"
    except Exception:
        db_status = "disconnected"
    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "database": db_status,
        "gmail": "configured" if settings.gmail_enabled else "not_configured",
        "virustotal": "configured" if settings.virustotal_enabled else "not_configured",
    }
