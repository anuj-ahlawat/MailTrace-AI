"""Email analysis routes — upload EML, paste raw, demo samples."""
from fastapi import APIRouter, HTTPException, UploadFile, File, Depends, Request
from datetime import datetime, timezone
from bson import ObjectId
import hashlib
import uuid
import re

from app.core.database import get_db
from app.core.security import get_current_user, require_analyst
from app.schemas.schemas import AnalyzeRawRequest
from app.analysis.parser import parse_email
from app.analysis.scorer import compute_threat_score
from app.services.audit import log_event
from app.intelligence.providers import get_intel_provider, LiveIPGeolocation
import logging

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Email Analysis"])

# ─── Demo emails ──────────────────────────────────────────────────────────────

DEMO_EMAILS = {
    "demo-1": {
        "id": "demo-1",
        "title": "Legitimate email",
        "description": "Microsoft 365 security summary",
        "risk_preview": 7,
        "raw": """From: Microsoft Security <security-noreply@microsoft.com>
To: user@acmecorp.com
Subject: Your Microsoft 365 security summary
Date: Mon, 26 Aug 2026 09:00:00 +0000
Message-ID: <secure-summary-83721@microsoft.com>
Authentication-Results: mx.acmecorp.com;
    spf=pass smtp.mailfrom=microsoft.com;
    dkim=pass header.d=microsoft.com;
    dmarc=pass header.from=microsoft.com
Received: from mail-eopbgr80066.outbound.protection.outlook.com (40.107.8.66)
    by mx.acmecorp.com; Mon, 26 Aug 2026 09:00:01 +0000
X-Mailer: Microsoft Exchange Server 2019

Dear User,

Here is your weekly Microsoft 365 security summary for the period Aug 19 - Aug 25, 2026.

Sign-in activity: 12 successful sign-ins from 2 devices
Security alerts: 0 new alerts
Blocked threats: 3 spam emails blocked

Your account is secure. No action required.

View detailed security report: https://account.microsoft.com/security

Microsoft Security Team
""",
    },
    "demo-2": {
        "id": "demo-2",
        "title": "Credential phishing",
        "description": "Action required: verify your payroll account",
        "risk_preview": 86,
        "raw": """From: Payroll System <payroll@microsOft-support.com>
To: finance@acmecorp.com
Reply-To: verify@proton-payroll.com
Subject: ACTION REQUIRED: Verify your payroll account immediately
Date: Mon, 26 Aug 2026 10:15:00 +0000
Message-ID: <payroll-verify-99211@microsOft-support.com>
Authentication-Results: mx.acmecorp.com;
    spf=fail smtp.mailfrom=microsOft-support.com;
    dkim=fail header.d=microsOft-support.com;
    dmarc=fail header.from=microsOft-support.com
Received: from mail.suspicious-relay.xyz (91.108.4.1)
    by mx.acmecorp.com; Mon, 26 Aug 2026 10:15:05 +0000
X-Originating-IP: 91.108.4.1

URGENT: Your payroll account requires immediate verification.

Your payroll direct deposit information must be verified within 24 hours to avoid 
payment suspension.

Click here to verify your account now:
https://payroll-verify.microsOft-support.com/login?redirect=acmecorp

Your access will be suspended if you do not verify immediately.

Payroll Administration Team
""",
    },
    "demo-3": {
        "id": "demo-3",
        "title": "Business Email Compromise",
        "description": "Urgent Vendor Payment Approval",
        "risk_preview": 94,
        "raw": """From: CEO <ceo@micros0ft-secure.com>
To: finance@acmecorp.com
Reply-To: finance.verify@proton-example.com
Return-Path: bounce@sendgrid-relay.net
Subject: Urgent Vendor Payment Approval
Date: Mon, 26 Aug 2026 11:30:00 +0000
Message-ID: <ceo-payment-112@micros0ft-secure.com>
Authentication-Results: mx.acmecorp.com;
    spf=fail smtp.mailfrom=micros0ft-secure.com;
    dkim=fail;
    dmarc=fail
Received: from mail-sg1.sendgrid-relay.net (185.231.72.12)
    by relay.example.com; Mon, 26 Aug 2026 11:28:00 +0000
Received: from origin.sg-infra.net (185.231.72.50)
    by mail-sg1.sendgrid-relay.net; Mon, 26 Aug 2026 11:27:45 +0000

Hi Sarah,

I need you to process an urgent vendor payment today before 3 PM. This is strictly 
confidential — please do not discuss with anyone else.

The payment is for a strategic acquisition we are finalizing. Our legal team requires
this to remain confidential until we make the public announcement next week.

Wire transfer details:
Amount: USD 87,500
Bank: First Asia Pacific Bank
Account: 8834-7721-003
Routing: 021000021
Reference: ACME-ACQ-2026

Please confirm once the transfer is complete. I am in a board meeting and cannot
take calls — reply by email only.

Best,
Michael Chen
CEO, Acme Corporation
""",
    },
}


async def run_full_analysis(raw_email: str, analyst_id: str, is_demo: bool = False,
                            demo_id: str = None, case_id: str = None) -> dict:
    """Parse email, score it, enrich with intelligence, save to MongoDB."""
    db = get_db()

    # Parse
    parsed = parse_email(raw_email)

    # Score
    score_result = compute_threat_score(parsed)

    # Enrich relay path with geolocation
    provider = get_intel_provider()
    enriched_relay = []
    for hop in parsed.get("relay_path", []):
        ip = hop.get("ip", "")
        if ip:
            geo = await LiveIPGeolocation.lookup(ip)
            if geo:
                hop["location"] = f"{geo.get('city', '')}, {geo.get('country', '')}".strip(", ") or hop.get("location", "Unknown")
            else:
                # Fallback to mock
                ip_data = await provider.lookup_ip(ip)
                hop["location"] = f"{ip_data.get('city', '')}, {ip_data.get('country', '')}".strip(", ") or hop.get("location", "Unknown")
        enriched_relay.append(hop)

    # Evidence hash of raw email
    evidence_hash = hashlib.sha256(raw_email.encode()).hexdigest()

    # Build analysis document
    analysis_id = str(uuid.uuid4())
    analysis_doc = {
        "_id": analysis_id,
        "analyst_id": analyst_id,
        "case_id": case_id,
        "is_demo": is_demo,
        "demo_id": demo_id,
        "created_at": datetime.now(timezone.utc),
        "email_metadata": {
            "from_address": parsed.get("from_address", ""),
            "from_raw": parsed.get("from_raw", ""),
            "to": parsed.get("to", []),
            "cc": parsed.get("cc", []),
            "subject": parsed.get("subject", ""),
            "date": parsed.get("date", ""),
            "message_id": parsed.get("message_id", ""),
            "reply_to": parsed.get("reply_to", ""),
            "return_path": parsed.get("return_path", ""),
            "x_originating_ip": parsed.get("x_originating_ip", ""),
            "mailer": parsed.get("mailer", ""),
            "raw_headers": parsed.get("raw_headers", ""),
            "body_text": parsed.get("body_text", "")[:5000],
            "body_html": "",  # Don't store HTML in DB
        },
        "auth": parsed.get("auth_results", {}),
        "overall_risk_score": score_result["overall_risk_score"],
        "risk_level": score_result["risk_level"],
        "classification": score_result["classification"],
        "classification_scores": score_result["classification_scores"],
        "scoring_breakdown": score_result["scoring_breakdown"],
        "social_engineering": score_result["social_engineering"],
        "risk_indicators": score_result["risk_indicators"],
        "iocs": parsed.get("iocs", []),
        "url_analysis": score_result["url_analysis"],
        "relay_path": enriched_relay,
        "attachments": parsed.get("attachments", []),
        "explainable_ai": score_result["explainable_ai"],
        "evidence_hash": evidence_hash,
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Save to MongoDB
    await db.email_analyses.insert_one(analysis_doc)

    # Store IOCs in iocs collection
    for ioc in parsed.get("iocs", []):
        await db.iocs.update_one(
            {"value": ioc["indicator"], "type": ioc["type"]},
            {"$set": {
                "value": ioc["indicator"],
                "type": ioc["type"],
                "source": ioc.get("source", "email_analysis"),
                "reputation": ioc.get("reputation", "unknown"),
                "risk_level": ioc.get("risk_level", "medium"),
                "last_seen": datetime.now(timezone.utc),
            }, "$addToSet": {"analysis_ids": analysis_id},
            "$setOnInsert": {"first_seen": datetime.now(timezone.utc)}},
            upsert=True
        )

    return analysis_doc


def _serialize_analysis(doc: dict) -> dict:
    """Convert MongoDB doc to JSON-serializable dict."""
    d = dict(doc)
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    # Convert datetime objects
    for k, v in d.items():
        if hasattr(v, 'isoformat'):
            d[k] = v.isoformat()
    return d


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.get("/demo/emails")
async def list_demo_emails():
    """List available demo email samples."""
    return [
        {"id": k, "title": v["title"], "description": v["description"], "risk_preview": v["risk_preview"]}
        for k, v in DEMO_EMAILS.items()
    ]


@router.post("/demo/emails/{demo_id}/analyze")
async def analyze_demo_email(
    demo_id: str,
    request: Request,
    current_user: dict = Depends(require_analyst),
):
    """Analyze a pre-loaded demo email sample."""
    if demo_id not in DEMO_EMAILS:
        raise HTTPException(status_code=404, detail="Demo email not found")

    demo = DEMO_EMAILS[demo_id]
    result = await run_full_analysis(
        raw_email=demo["raw"],
        analyst_id=str(current_user["_id"]),
        is_demo=True,
        demo_id=demo_id,
    )
    await log_event("Demo email analyzed", user=current_user, request=request,
                    resource="email_analysis", resource_id=result["_id"],
                    details={"demo_id": demo_id})
    return _serialize_analysis(result)


@router.post("/emails/analyze")
async def analyze_raw_email(
    data: AnalyzeRawRequest,
    request: Request,
    current_user: dict = Depends(require_analyst),
):
    """Analyze raw email text (pasted headers or full email)."""
    if len(data.raw_email.strip()) < 20:
        raise HTTPException(status_code=422, detail="Email content too short")

    result = await run_full_analysis(
        raw_email=data.raw_email,
        analyst_id=str(current_user["_id"]),
        case_id=data.case_id,
    )
    await log_event("Email analyzed (raw)", user=current_user, request=request,
                    resource="email_analysis", resource_id=result["_id"])
    return _serialize_analysis(result)


@router.post("/emails/upload")
async def upload_eml_file(
    request: Request,
    file: UploadFile = File(...),
    current_user: dict = Depends(require_analyst),
):
    """Upload a .eml file for analysis."""
    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=422, detail="Only .eml files are supported")

    content = await file.read()
    if len(content) > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(status_code=413, detail="File too large (max 10MB)")

    raw_email = content.decode("utf-8", errors="replace")

    # Store evidence record
    sha256 = hashlib.sha256(content).hexdigest()
    db = get_db()
    evidence_id = str(uuid.uuid4())
    await db.evidence.insert_one({
        "_id": evidence_id,
        "filename": file.filename,
        "sha256": sha256,
        "size": len(content),
        "upload_timestamp": datetime.now(timezone.utc),
        "analyst_id": str(current_user["_id"]),
        "analyst_email": current_user["email"],
        "case_id": None,
        "custody_chain": [{
            "event": "Uploaded",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "analyst": current_user["email"],
        }],
    })

    result = await run_full_analysis(
        raw_email=raw_email,
        analyst_id=str(current_user["_id"]),
    )

    # Link evidence to analysis
    await db.email_analyses.update_one(
        {"_id": result["_id"]},
        {"$set": {"evidence_id": evidence_id}}
    )

    await log_event("EML file uploaded and analyzed", user=current_user, request=request,
                    resource="evidence", resource_id=evidence_id,
                    details={"filename": file.filename, "sha256": sha256})

    result["evidence_id"] = evidence_id
    result["sha256"] = sha256
    return _serialize_analysis(result)


@router.get("/emails/{analysis_id}")
async def get_analysis(analysis_id: str, current_user: dict = Depends(require_analyst)):
    db = get_db()
    doc = await db.email_analyses.find_one({"_id": analysis_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return _serialize_analysis(doc)


@router.get("/emails")
async def list_analyses(
    skip: int = 0, limit: int = 20,
    current_user: dict = Depends(require_analyst),
):
    db = get_db()
    cursor = db.email_analyses.find({}).sort("created_at", -1).skip(skip).limit(limit)
    docs = await cursor.to_list(length=limit)
    return [_serialize_analysis(d) for d in docs]
