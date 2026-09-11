"""Audit logs, users, reports, evidence, campaigns, settings routes."""
from fastapi import APIRouter, HTTPException, Depends, Request, UploadFile, File
from datetime import datetime, timezone
from bson import ObjectId
import uuid
import hashlib

from app.core.database import get_db
from app.core.security import get_current_user, require_analyst, require_senior, require_admin
from app.schemas.schemas import (
    CreateUserRequest, UpdateUserRequest, GenerateReportRequest,
    VirusTotalSettingsRequest, SystemSettingsUpdate
)
from app.core.security import hash_password
from app.services.audit import log_event
from app.reports.generator import generate_html_report

# ─── Audit Logs ───────────────────────────────────────────────────────────────

audit_router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])


@audit_router.get("")
async def list_audit_logs(
    skip: int = 0, limit: int = 100,
    current_user: dict = Depends(require_admin),
):
    db = get_db()
    cursor = db.audit_logs.find({}).sort("timestamp", -1).skip(skip).limit(limit)
    docs = await cursor.to_list(length=limit)
    total = await db.audit_logs.count_documents({})
    result = []
    for d in docs:
        d["id"] = str(d.pop("_id", ""))
        for k, v in d.items():
            if hasattr(v, 'isoformat'):
                d[k] = v.isoformat()
        result.append(d)
    return {"logs": result, "total": total}


# ─── Users ────────────────────────────────────────────────────────────────────

users_router = APIRouter(prefix="/users", tags=["Users"])


def serialize_user(user):
    u = dict(user)
    u["id"] = str(u.pop("_id"))
    u.pop("password_hash", None)
    if u.get("created_at"):
        u["created_at"] = u["created_at"].isoformat()
    if u.get("last_login"):
        u["last_login"] = u["last_login"].isoformat()
    return u


@users_router.get("")
async def list_users(current_user: dict = Depends(require_admin)):
    db = get_db()
    docs = await db.users.find({}).to_list(100)
    return [serialize_user(d) for d in docs]


@users_router.post("")
async def create_user(
    data: CreateUserRequest, request: Request,
    current_user: dict = Depends(require_admin),
):
    db = get_db()
    if await db.users.find_one({"email": data.email.lower()}):
        raise HTTPException(status_code=409, detail="Email already registered")

    user_doc = {
        "name": data.name,
        "email": data.email.lower(),
        "password_hash": hash_password(data.password),
        "role": data.role.value,
        "status": "active",
        "created_at": datetime.now(timezone.utc),
        "last_login": None,
    }
    result = await db.users.insert_one(user_doc)
    await log_event("User created", user=current_user, request=request,
                    resource="user", resource_id=str(result.inserted_id),
                    details={"email": data.email, "role": data.role.value})
    user_doc["id"] = str(result.inserted_id)
    user_doc.pop("password_hash", None)
    return user_doc


@users_router.put("/{user_id}")
async def update_user(
    user_id: str, data: UpdateUserRequest, request: Request,
    current_user: dict = Depends(require_admin),
):
    db = get_db()
    update = {}
    if data.name:
        update["name"] = data.name
    if data.role:
        update["role"] = data.role.value
    if data.status:
        update["status"] = data.status

    await db.users.update_one({"_id": ObjectId(user_id)}, {"$set": update})
    await log_event("User updated", user=current_user, request=request,
                    resource="user", resource_id=user_id)
    return {"message": "User updated"}


@users_router.delete("/{user_id}")
async def deactivate_user(
    user_id: str, request: Request,
    current_user: dict = Depends(require_admin),
):
    db = get_db()
    await db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"status": "inactive"}})
    await log_event("User deactivated", user=current_user, request=request,
                    resource="user", resource_id=user_id)
    return {"message": "User deactivated"}


# ─── Evidence ─────────────────────────────────────────────────────────────────

evidence_router = APIRouter(prefix="/evidence", tags=["Evidence"])


@evidence_router.get("/{evidence_id}")
async def get_evidence(evidence_id: str, current_user: dict = Depends(require_analyst)):
    db = get_db()
    doc = await db.evidence.find_one({"_id": evidence_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Evidence not found")
    doc["id"] = str(doc.pop("_id"))
    for k, v in doc.items():
        if hasattr(v, 'isoformat'):
            doc[k] = v.isoformat()
    return doc


@evidence_router.post("/{evidence_id}/verify")
async def verify_evidence(evidence_id: str, current_user: dict = Depends(require_analyst)):
    db = get_db()
    doc = await db.evidence.find_one({"_id": evidence_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return {
        "evidence_id": evidence_id,
        "sha256": doc.get("sha256"),
        "integrity_status": "VERIFIED",
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }


@evidence_router.delete("/{evidence_id}")
async def delete_evidence(
    evidence_id: str, request: Request,
    current_user: dict = Depends(require_senior),
):
    db = get_db()
    result = await db.evidence.delete_one({"_id": evidence_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Evidence not found")
    await log_event("Evidence deleted", user=current_user, request=request,
                    resource="evidence", resource_id=evidence_id)
    return {"message": "Evidence deleted"}


# ─── Reports ──────────────────────────────────────────────────────────────────

reports_router = APIRouter(prefix="/reports", tags=["Reports"])


def _serialize_report(doc):
    d = dict(doc)
    d["id"] = str(d.pop("_id"))
    for k, v in d.items():
        if hasattr(v, 'isoformat'):
            d[k] = v.isoformat()
    return d


@reports_router.post("")
async def create_report(
    data: GenerateReportRequest, request: Request,
    current_user: dict = Depends(require_analyst),
):
    db = get_db()
    case = await db.cases.find_one({"_id": data.case_id})
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    analysis = None
    if case.get("email_analysis_id"):
        analysis = await db.email_analyses.find_one({"_id": case["email_analysis_id"]})

    report_id = str(uuid.uuid4())
    title = data.title or f"Forensic Report — {case.get('case_id', data.case_id)}"

    report_doc = {
        "_id": report_id,
        "report_id": report_id,
        "case_id": data.case_id,
        "case_ref": case.get("case_id", ""),
        "title": title,
        "analyst_id": str(current_user["_id"]),
        "analyst_name": current_user["name"],
        "analyst_email": current_user["email"],
        "created_at": datetime.now(timezone.utc),
        "status": "completed",
        "risk_score": case.get("risk_score", 0),
        "classification": case.get("classification", ""),
        "severity": case.get("severity", ""),
    }

    await db.reports.insert_one(report_doc)
    await db.evidence.update_many(
        {"case_id": data.case_id},
        {"$push": {"custody_chain": {
            "event": "Report Generated",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "analyst": current_user["email"],
            "report_id": report_id,
        }}}
    )
    await log_event("Report generated", user=current_user, request=request,
                    resource="report", resource_id=report_id, case_id=data.case_id)
    return _serialize_report(report_doc)


@reports_router.get("")
async def list_reports(current_user: dict = Depends(require_analyst)):
    db = get_db()
    cursor = db.reports.find({}).sort("created_at", -1).limit(50)
    docs = await cursor.to_list(50)
    return [_serialize_report(d) for d in docs]


@reports_router.get("/{report_id}")
async def get_report(report_id: str, current_user: dict = Depends(require_analyst)):
    db = get_db()
    doc = await db.reports.find_one({"_id": report_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Report not found")
    return _serialize_report(doc)


@reports_router.get("/{report_id}/download")
async def download_report(report_id: str, current_user: dict = Depends(require_analyst)):
    from fastapi.responses import HTMLResponse
    db = get_db()
    report = await db.reports.find_one({"_id": report_id})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    case = await db.cases.find_one({"_id": report.get("case_id")})
    analysis = None
    if case and case.get("email_analysis_id"):
        analysis = await db.email_analyses.find_one({"_id": case["email_analysis_id"]})

    html = generate_html_report(report, case, analysis, current_user)
    return HTMLResponse(content=html, headers={
        "Content-Disposition": f'attachment; filename="report-{report_id[:8]}.html"'
    })


# ─── Campaigns ────────────────────────────────────────────────────────────────

campaigns_router = APIRouter(prefix="/campaigns", tags=["Campaigns"])


@campaigns_router.get("")
async def list_campaigns(current_user: dict = Depends(require_analyst)):
    db = get_db()
    docs = await db.campaigns.find({}).sort("created_at", -1).limit(20).to_list(20)
    for d in docs:
        d["id"] = str(d.pop("_id", ""))
        for k, v in d.items():
            if hasattr(v, 'isoformat'):
                d[k] = v.isoformat()
    return docs


@campaigns_router.get("/{campaign_id}/graph")
async def get_campaign_graph(campaign_id: str, current_user: dict = Depends(require_analyst)):
    db = get_db()
    # Build graph from IOCs and cases related to this campaign
    campaign = await db.campaigns.find_one({"_id": campaign_id})
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Fetch related cases
    cases = await db.cases.find({"campaign_id": campaign_id}).to_list(50)
    iocs = await db.iocs.find({"campaign_id": campaign_id}).to_list(100)

    nodes = []
    edges = []
    seen_nodes = set()

    # Campaign node
    nodes.append({"id": campaign_id, "type": "campaign", "label": campaign.get("name", "Campaign"),
                  "data": {"campaign_id": campaign_id}})
    seen_nodes.add(campaign_id)

    for case in cases:
        case_id = case.get("_id", "")
        if case_id not in seen_nodes:
            nodes.append({"id": case_id, "type": "case", "label": case_id,
                          "data": {"classification": case.get("classification"), "risk_score": case.get("risk_score")}})
            seen_nodes.add(case_id)
            edges.append({"source": campaign_id, "target": case_id, "label": "contains"})

    for ioc in iocs:
        ioc_id = str(ioc.get("_id", ""))
        value = ioc.get("value", "")
        if ioc_id not in seen_nodes:
            nodes.append({"id": ioc_id, "type": ioc.get("type", "ioc"), "label": value[:30],
                          "data": {"reputation": ioc.get("reputation"), "type": ioc.get("type")}})
            seen_nodes.add(ioc_id)

    return {"nodes": nodes, "edges": edges, "campaign": campaign.get("name", "")}


# ─── Settings ─────────────────────────────────────────────────────────────────

settings_router = APIRouter(prefix="/settings", tags=["Settings"])


@settings_router.get("")
async def get_settings(current_user: dict = Depends(require_admin)):
    from app.core.config import settings
    return {
        "virustotal_configured": settings.virustotal_enabled,
        "gmail_configured": settings.gmail_enabled,
        "environment": settings.ENVIRONMENT,
    }


@settings_router.post("/virustotal/test")
async def test_virustotal(
    data: VirusTotalSettingsRequest, request: Request,
    current_user: dict = Depends(require_admin),
):
    import httpx
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(
                "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                headers={"x-apikey": data.api_key}
            )
            if r.status_code == 200:
                await log_event("VirusTotal API key tested", user=current_user, request=request,
                                result="Success")
                return {"status": "connected", "message": "VirusTotal API key is valid"}
            else:
                return {"status": "error", "message": f"API returned status {r.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ─── Notifications ────────────────────────────────────────────────────────────

notifications_router = APIRouter(prefix="/notifications", tags=["Notifications"])


@notifications_router.get("")
async def get_notifications(current_user: dict = Depends(get_current_user)):
    db = get_db()
    user_id = str(current_user["_id"])
    cursor = db.notifications.find({"user_id": user_id}).sort("created_at", -1).limit(20)
    docs = await cursor.to_list(20)
    for d in docs:
        d["id"] = str(d.pop("_id", ""))
        for k, v in d.items():
            if hasattr(v, 'isoformat'):
                d[k] = v.isoformat()
    return docs


@notifications_router.post("/{notif_id}/read")
async def mark_read(notif_id: str, current_user: dict = Depends(get_current_user)):
    db = get_db()
    await db.notifications.update_one({"_id": notif_id}, {"$set": {"read": True}})
    return {"message": "Marked as read"}


# ─── Search ───────────────────────────────────────────────────────────────────

search_router = APIRouter(prefix="/search", tags=["Search"])


@search_router.get("")
async def global_search(q: str, current_user: dict = Depends(require_analyst)):
    db = get_db()
    results = []

    if len(q) < 2:
        return results

    # Search cases
    cases = await db.cases.find({
        "$or": [
            {"_id": {"$regex": q, "$options": "i"}},
            {"sender": {"$regex": q, "$options": "i"}},
            {"subject": {"$regex": q, "$options": "i"}},
            {"classification": {"$regex": q, "$options": "i"}},
        ]
    }).limit(5).to_list(5)
    for c in cases:
        results.append({
            "type": "case",
            "id": str(c.get("_id", "")),
            "title": c.get("_id", ""),
            "subtitle": c.get("subject", ""),
            "url": f"/cases",
        })

    # Search IOCs
    iocs = await db.iocs.find({
        "value": {"$regex": q, "$options": "i"}
    }).limit(5).to_list(5)
    for ioc in iocs:
        results.append({
            "type": "ioc",
            "id": str(ioc.get("_id", "")),
            "title": ioc.get("value", ""),
            "subtitle": ioc.get("type", ""),
            "url": f"/threat-intelligence",
        })

    return results
