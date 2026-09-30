"""Public API composition; route modules retain the existing URLs."""
from fastapi import APIRouter
from backend.api.routes import auth, analyze, intelligence, investigations, evidence, campaigns, reports, alerts, dashboard, search, settings

router = APIRouter(prefix="/api")
router.include_router(auth.router)
router.include_router(analyze.router)
router.include_router(intelligence.router)
router.include_router(investigations.router)
router.include_router(evidence.router)
router.include_router(campaigns.router)
router.include_router(reports.router)
router.include_router(alerts.router)
router.include_router(dashboard.router)
router.include_router(search.router)
router.include_router(settings.router)
