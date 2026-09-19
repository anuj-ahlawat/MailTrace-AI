"""Audit logging service — persists all analyst actions to MongoDB."""
from datetime import datetime, timezone
from typing import Optional
from fastapi import Request
from app.core.database import get_db
import logging

logger = logging.getLogger(__name__)


async def log_event(
    action: str,
    user: Optional[dict] = None,
    request: Optional[Request] = None,
    resource: Optional[str] = None,
    resource_id: Optional[str] = None,
    case_id: Optional[str] = None,
    result: str = "Success",
    details: Optional[dict] = None,
):
    """Persist an audit event to MongoDB."""
    try:
        db = get_db()
        ip_address = None
        if request:
            forwarded = request.headers.get("X-Forwarded-For")
            ip_address = forwarded.split(",")[0].strip() if forwarded else str(request.client.host) if request.client else None

        event = {
            "timestamp": datetime.now(timezone.utc),
            "user_id": str(user["_id"]) if user else None,
            "user_email": user.get("email") if user else None,
            "user_role": user.get("role") if user else None,
            "action": action,
            "resource": resource,
            "resource_id": resource_id,
            "case_id": case_id,
            "ip_address": ip_address,
            "result": result,
            "details": details or {},
        }
        await db.audit_logs.insert_one(event)
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")
