"""
MailTrace AI — Flask Backend
AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform

Works with Python 3.14 (no Rust/pydantic-core needed)

Start: python main_flask.py
Docs:  http://localhost:8000/docs (basic endpoint listing)
"""
import os
import uuid
import hashlib
import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import Flask, request, jsonify, Response, make_response
from flask_cors import CORS
from pymongo import MongoClient, ASCENDING, DESCENDING
from bson import ObjectId
from passlib.context import CryptContext
from jose import jwt, JWTError
from dotenv import load_dotenv

# Local imports
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app.analysis.parser import parse_email
from app.analysis.scorer import compute_threat_score
from app.reports.generator import generate_html_report

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(name)s — %(levelname)s — %(message)s",
)
logger = logging.getLogger(__name__)

# ─── Config ───────────────────────────────────────────────────────────────────

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGODB_DB_NAME", "mailtrace_ai")
JWT_SECRET = os.getenv("JWT_SECRET", "mailtrace-ai-super-secret-jwt-key-change-in-production-2026")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:3001").split(",")

# ─── App setup ────────────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(app, origins=CORS_ORIGINS, supports_credentials=True, allow_headers=["Content-Type", "Authorization"])

# MongoDB
mongo_client = MongoClient(MONGODB_URI)
db = mongo_client[DB_NAME]

# Password hashing
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def jresp(data, status=200):
    """JSON response helper."""
    return Response(
        json.dumps(data, default=str),
        status=status,
        mimetype="application/json"
    )


def serialize(doc):
    """Convert MongoDB doc to JSON-serializable dict."""
    if doc is None:
        return None
    d = dict(doc)
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    for k, v in list(d.items()):
        if isinstance(v, datetime):
            d[k] = v.isoformat()
        elif isinstance(v, ObjectId):
            d[k] = str(v)
        elif isinstance(v, list):
            d[k] = [serialize(i) if isinstance(i, dict) else str(i) if isinstance(i, ObjectId) else i for i in v]
        elif isinstance(v, dict):
            d[k] = serialize(v)
    return d


def hash_password(pw: str) -> str:
    return pwd_ctx.hash(pw)


def verify_password(pw: str, hashed: str) -> bool:
    return pwd_ctx.verify(pw, hashed)


def create_token(user_id: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": user_id, "role": role, "exp": expire},
        JWT_SECRET, algorithm=JWT_ALGORITHM
    )


def decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None


def get_current_user():
    """Get authenticated user from request. Returns user dict or None."""
    token = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
    if not token:
        token = request.cookies.get("mt_token")
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    try:
        user = db.users.find_one({"_id": ObjectId(payload["sub"])})
        return user
    except Exception:
        return None


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user or user.get("status") != "active":
            return jresp({"detail": "Not authenticated"}, 401)
        return f(user, *args, **kwargs)
    return decorated


def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user or user.get("status") != "active":
                return jresp({"detail": "Not authenticated"}, 401)
            if user.get("role") not in roles:
                return jresp({"detail": f"Access denied. Required: {', '.join(roles)}"}, 403)
            return f(user, *args, **kwargs)
        return decorated
    return decorator


def log_event(action, user=None, resource=None, resource_id=None, case_id=None, result="Success", details=None):
    """Persist audit log synchronously."""
    try:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        db.audit_logs.insert_one({
            "timestamp": datetime.now(timezone.utc),
            "user_id": str(user["_id"]) if user else None,
            "user_email": user.get("email") if user else None,
            "user_role": user.get("role") if user else None,
            "action": action,
            "resource": resource,
            "resource_id": resource_id,
            "case_id": case_id,
            "ip_address": ip,
            "result": result,
            "details": details or {},
        })
    except Exception as e:
        logger.warning(f"Audit log failed: {e}")


def run_full_analysis(raw_email: str, analyst_id: str, is_demo=False, demo_id=None, case_id=None):
    """Parse + score + enrich + store email analysis."""
    parsed = parse_email(raw_email)
    score_result = compute_threat_score(parsed)

    # Enrich relay IPs with geolocation (sync HTTP)
    import urllib.request
    relay_path = []
    for hop in parsed.get("relay_path", []):
        ip = hop.get("ip", "")
        if ip:
            try:
                with urllib.request.urlopen(
                    f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,as", timeout=3
                ) as resp:
                    geo = json.loads(resp.read())
                    if geo.get("status") == "success":
                        hop["location"] = f"{geo.get('city', '')}, {geo.get('country', '')}".strip(", ") or hop.get("location", "Unknown")
            except Exception:
                pass
        relay_path.append(hop)

    evidence_hash = hashlib.sha256(raw_email.encode()).hexdigest()
    analysis_id = str(uuid.uuid4())

    doc = {
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
            "body_html": "",
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
        "relay_path": relay_path,
        "attachments": parsed.get("attachments", []),
        "explainable_ai": score_result["explainable_ai"],
        "evidence_hash": evidence_hash,
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
    }

    db.email_analyses.insert_one(doc)

    # Store IOCs
    for ioc in parsed.get("iocs", []):
        db.iocs.update_one(
            {"value": ioc["indicator"], "type": ioc["type"]},
            {
                "$set": {"value": ioc["indicator"], "type": ioc["type"],
                         "source": ioc.get("source", "email_analysis"),
                         "reputation": ioc.get("reputation", "unknown"),
                         "risk_level": ioc.get("risk_level", "medium"),
                         "last_seen": datetime.now(timezone.utc)},
                "$addToSet": {"analysis_ids": analysis_id},
                "$setOnInsert": {"first_seen": datetime.now(timezone.utc)},
            },
            upsert=True
        )

    return doc


# ─── Demo emails ──────────────────────────────────────────────────────────────

DEMO_EMAILS = {
    "demo-1": {
        "id": "demo-1", "title": "Legitimate email",
        "description": "Microsoft 365 security summary", "risk_preview": 7,
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

Your Microsoft 365 security summary for Aug 19-25, 2026.

Sign-in activity: 12 successful sign-ins from 2 devices
Security alerts: 0 new alerts
Blocked threats: 3 spam emails blocked

Your account is secure. No action required.
View details: https://account.microsoft.com/security

Microsoft Security Team
""",
    },
    "demo-2": {
        "id": "demo-2", "title": "Credential phishing",
        "description": "Payroll account verification phishing", "risk_preview": 86,
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

Your payroll direct deposit information must be verified within 24 hours to avoid payment suspension.

Click here to verify your account now:
https://payroll-verify.microsOft-support.com/login?redirect=acmecorp

Your access will be suspended if you do not verify immediately.

Payroll Administration Team
""",
    },
    "demo-3": {
        "id": "demo-3", "title": "Business Email Compromise",
        "description": "CEO payment diversion BEC", "risk_preview": 94,
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

I need you to process an urgent vendor payment today before 3 PM. This is strictly confidential — please do not discuss with anyone else.

The payment is for a strategic acquisition we are finalizing. Our legal team requires this to remain confidential until we make the public announcement next week.

Wire transfer details:
Amount: USD 87,500
Bank: First Asia Pacific Bank
Account: 8834-7721-003
Routing: 021000021
Reference: ACME-ACQ-2026

Please confirm once the transfer is complete. I am in a board meeting and cannot take calls — reply by email only.

Best,
Michael Chen
CEO, Acme Corporation
""",
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def root():
    return jresp({
        "service": "MailTrace AI Backend",
        "version": "1.0.0",
        "status": "operational",
        "gmail_configured": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
        "virustotal_configured": bool(VIRUSTOTAL_API_KEY),
        "docs": "/docs",
    })


@app.route("/health")
def health():
    try:
        db.command("ping")
        db_status = "connected"
    except Exception:
        db_status = "disconnected"
    return jresp({
        "status": "healthy" if db_status == "connected" else "degraded",
        "database": db_status,
        "gmail": "configured" if GOOGLE_CLIENT_ID else "not_configured",
        "virustotal": "configured" if VIRUSTOTAL_API_KEY else "not_configured",
    })


@app.route("/docs")
def docs():
    endpoints = [
        "POST /auth/login", "POST /auth/logout", "GET /auth/me",
        "GET /demo/emails", "POST /demo/emails/<id>/analyze",
        "POST /emails/analyze", "POST /emails/upload", "GET /emails", "GET /emails/<id>",
        "GET /cases", "POST /cases", "GET /cases/<id>", "PUT /cases/<id>", "POST /cases/<id>/notes",
        "GET /dashboard/stats", "GET /dashboard/threat-trends", "GET /dashboard/recent-cases",
        "GET /dashboard/threat-distribution", "GET /dashboard/auth-failures", "GET /dashboard/top-domains",
        "GET /intel/domain/<domain>", "GET /intel/ip/<ip>", "POST /intel/url", "GET /intel/iocs",
        "GET /reports", "POST /reports", "GET /reports/<id>", "GET /reports/<id>/download",
        "GET /audit-logs", "GET /users", "POST /users", "PUT /users/<id>",
        "GET /evidence/<id>", "POST /evidence/<id>/verify", "DELETE /evidence/<id>",
        "GET /campaigns", "GET /campaigns/<id>/graph",
        "GET /gmail/status", "GET /auth/gmail", "GET /gmail/emails", "POST /gmail/emails/<id>/analyze", "POST /gmail/disconnect",
        "GET /notifications", "POST /notifications/<id>/read",
        "GET /search", "GET /settings", "POST /settings/virustotal/test",
    ]
    return jresp({"service": "MailTrace AI", "version": "1.0.0", "endpoints": endpoints})


# ─── Auth ─────────────────────────────────────────────────────────────────────

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    email = (data.get("email") or "").lower()
    password = data.get("password") or ""

    user = db.users.find_one({"email": email})
    if not user or not verify_password(password, user["password_hash"]):
        log_event("Login failed", result="Failure", details={"email": email})
        return jresp({"detail": "Invalid email or password"}, 401)

    if user.get("status") != "active":
        return jresp({"detail": "Account is inactive"}, 403)

    db.users.update_one({"_id": user["_id"]}, {"$set": {"last_login": datetime.now(timezone.utc)}})
    token = create_token(str(user["_id"]), user["role"])

    resp = make_response(jresp({
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": str(user["_id"]),
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "status": user["status"],
            "created_at": user.get("created_at", "").isoformat() if user.get("created_at") else None,
            "last_login": datetime.now(timezone.utc).isoformat(),
        }
    }))
    resp.set_cookie("mt_token", token, httponly=True, samesite="Lax", max_age=60 * 60 * 8)
    log_event("User login", user=user, result="Success")
    return resp


@app.route("/auth/logout", methods=["POST"])
@require_auth
def logout(user):
    resp = make_response(jresp({"message": "Logged out"}))
    resp.delete_cookie("mt_token")
    log_event("User logout", user=user)
    return resp


@app.route("/auth/me")
@require_auth
def get_me(user):
    return jresp({
        "id": str(user["_id"]),
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "status": user["status"],
        "created_at": user.get("created_at", "").isoformat() if user.get("created_at") else None,
        "last_login": user.get("last_login", "").isoformat() if user.get("last_login") else None,
    })


# ─── Demo Emails ──────────────────────────────────────────────────────────────

@app.route("/demo/emails")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def list_demo_emails(user):
    return jresp([
        {"id": k, "title": v["title"], "description": v["description"], "risk_preview": v["risk_preview"]}
        for k, v in DEMO_EMAILS.items()
    ])


@app.route("/demo/emails/<demo_id>/analyze", methods=["POST"])
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def analyze_demo_email(user, demo_id):
    if demo_id not in DEMO_EMAILS:
        return jresp({"detail": "Demo email not found"}, 404)

    demo = DEMO_EMAILS[demo_id]
    result = run_full_analysis(demo["raw"], str(user["_id"]), is_demo=True, demo_id=demo_id)
    log_event("Demo email analyzed", user=user, resource="email_analysis",
              resource_id=result["_id"], details={"demo_id": demo_id})
    return jresp(serialize(result))


# ─── Email Analysis ───────────────────────────────────────────────────────────

@app.route("/emails/analyze", methods=["POST"])
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def analyze_raw_email(user):
    data = request.get_json()
    raw = data.get("raw_email", "")
    case_id = data.get("case_id")
    if len(raw.strip()) < 20:
        return jresp({"detail": "Email content too short"}, 422)

    result = run_full_analysis(raw, str(user["_id"]), case_id=case_id)
    log_event("Email analyzed (raw)", user=user, resource="email_analysis", resource_id=result["_id"])
    return jresp(serialize(result))


@app.route("/emails/upload", methods=["POST"])
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def upload_eml(user):
    if "file" not in request.files:
        return jresp({"detail": "No file uploaded"}, 422)

    f = request.files["file"]
    if not f.filename.lower().endswith(".eml"):
        return jresp({"detail": "Only .eml files are supported"}, 422)

    content = f.read()
    if len(content) > 10 * 1024 * 1024:
        return jresp({"detail": "File too large (max 10MB)"}, 413)

    sha256 = hashlib.sha256(content).hexdigest()
    raw = content.decode("utf-8", errors="replace")
    evidence_id = str(uuid.uuid4())

    db.evidence.insert_one({
        "_id": evidence_id,
        "filename": f.filename,
        "sha256": sha256,
        "size": len(content),
        "upload_timestamp": datetime.now(timezone.utc),
        "analyst_id": str(user["_id"]),
        "analyst_email": user["email"],
        "case_id": None,
        "custody_chain": [{"event": "Uploaded", "timestamp": datetime.now(timezone.utc).isoformat(),
                           "analyst": user["email"]}],
    })

    result = run_full_analysis(raw, str(user["_id"]))
    db.email_analyses.update_one({"_id": result["_id"]}, {"$set": {"evidence_id": evidence_id}})
    log_event("EML file uploaded and analyzed", user=user, resource="evidence",
              resource_id=evidence_id, details={"filename": f.filename, "sha256": sha256})

    result["evidence_id"] = evidence_id
    result["sha256"] = sha256
    return jresp(serialize(result))


@app.route("/emails/<analysis_id>")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def get_analysis(user, analysis_id):
    doc = db.email_analyses.find_one({"_id": analysis_id})
    if not doc:
        return jresp({"detail": "Analysis not found"}, 404)
    return jresp(serialize(doc))


@app.route("/emails")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def list_analyses(user):
    skip = int(request.args.get("skip", 0))
    limit = int(request.args.get("limit", 20))
    docs = list(db.email_analyses.find({}).sort("created_at", DESCENDING).skip(skip).limit(limit))
    return jresp([serialize(d) for d in docs])


# ─── Dashboard ────────────────────────────────────────────────────────────────

@app.route("/dashboard/stats")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def dashboard_stats(user):
    total = db.email_analyses.count_documents({})
    critical = db.email_analyses.count_documents({"risk_level": "CRITICAL"})
    phishing = db.email_analyses.count_documents({"classification": {"$in": ["Phishing", "Credential Phishing"]}})
    bec = db.email_analyses.count_documents({"classification": "Business Email Compromise"})
    active_cases = db.cases.count_documents({"status": {"$in": ["NEW", "INVESTIGATING", "ESCALATED"]}})
    active_campaigns = db.campaigns.count_documents({"status": "active"})
    avg_pipeline = list(db.email_analyses.aggregate([{"$group": {"_id": None, "avg": {"$avg": "$overall_risk_score"}}}]))
    avg_score = avg_pipeline[0]["avg"] if avg_pipeline else 0
    return jresp({
        "emails_analyzed": total,
        "critical_threats": critical,
        "phishing_detected": phishing,
        "bec_detected": bec,
        "active_cases": active_cases,
        "active_campaigns": active_campaigns,
        "avg_risk_score": round(avg_score, 1),
    })


@app.route("/dashboard/threat-trends")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def threat_trends(user):
    cutoff = datetime.now(timezone.utc) - timedelta(days=14)
    pipeline = [
        {"$match": {"created_at": {"$gte": cutoff}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$created_at"}},
            "threats": {"$sum": 1},
            "critical": {"$sum": {"$cond": [{"$gte": ["$overall_risk_score", 80]}, 1, 0]}},
        }},
        {"$sort": {"_id": 1}},
    ]
    result = list(db.email_analyses.aggregate(pipeline))
    return jresp([{"date": r["_id"], "threats": r["threats"], "critical": r["critical"]} for r in result])


@app.route("/dashboard/recent-cases")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def recent_cases(user):
    limit = int(request.args.get("limit", 10))
    docs = list(db.cases.find({}).sort("created_at", DESCENDING).limit(limit))
    return jresp([{
        "id": str(d.get("_id", "")),
        "case_id": d.get("case_id", ""),
        "sender": d.get("sender", ""),
        "subject": d.get("subject", ""),
        "classification": d.get("classification", ""),
        "risk_score": d.get("risk_score", 0),
        "origin": d.get("origin", "Unknown"),
        "status": d.get("status", "NEW"),
        "created_at": d.get("created_at").isoformat() if d.get("created_at") else "",
    } for d in docs])


@app.route("/dashboard/threat-distribution")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def threat_distribution(user):
    pipeline = [
        {"$group": {"_id": "$classification", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    colors = {
        "Legitimate": "#22c55e", "Phishing": "#ef4444",
        "Credential Phishing": "#f97316", "Business Email Compromise": "#8b5cf6",
        "Suspicious": "#3b82f6", "Malware Delivery": "#dc2626",
        "Invoice Fraud": "#eab308", "Executive Impersonation": "#ec4899",
    }
    result = list(db.email_analyses.aggregate(pipeline))
    return jresp([
        {"name": r["_id"] or "Unknown", "value": r["count"],
         "color": colors.get(r["_id"], "#94a3b8")}
        for r in result if r["_id"]
    ])


@app.route("/dashboard/auth-failures")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def auth_failures(user):
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    pipeline = [
        {"$match": {"created_at": {"$gte": cutoff}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$created_at"}},
            "spf": {"$sum": {"$cond": [{"$eq": ["$auth.spf", "fail"]}, 1, 0]}},
            "dkim": {"$sum": {"$cond": [{"$eq": ["$auth.dkim", "fail"]}, 1, 0]}},
            "dmarc": {"$sum": {"$cond": [{"$eq": ["$auth.dmarc", "fail"]}, 1, 0]}},
        }},
        {"$sort": {"_id": 1}},
    ]
    result = list(db.email_analyses.aggregate(pipeline))
    return jresp([{"date": r["_id"], "spf": r["spf"], "dkim": r["dkim"], "dmarc": r["dmarc"]} for r in result])


@app.route("/dashboard/top-domains")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def top_domains(user):
    pipeline = [
        {"$match": {"type": "domain", "reputation": {"$in": ["malicious", "suspicious"]}}},
        {"$group": {"_id": "$value", "count": {"$sum": 1}, "reputation": {"$first": "$reputation"}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    result = list(db.iocs.aggregate(pipeline))
    return jresp([{"domain": r["_id"], "count": r["count"], "risk": r.get("reputation", "suspicious")} for r in result])


# ─── Cases ────────────────────────────────────────────────────────────────────

def next_case_id():
    result = db.case_counter.find_one_and_update(
        {"_id": "global"}, {"$inc": {"seq": 1}},
        upsert=True, return_document=True,
    )
    seq = result.get("seq", 125)
    return f"MT-{datetime.now().year}-{seq:05d}"


@app.route("/cases")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def list_cases(user):
    skip = int(request.args.get("skip", 0))
    limit = int(request.args.get("limit", 50))
    status = request.args.get("status")
    classification = request.args.get("classification")
    query = {}
    if status:
        query["status"] = status.upper()
    if classification:
        query["classification"] = {"$regex": classification, "$options": "i"}
    docs = list(db.cases.find(query).sort("created_at", DESCENDING).skip(skip).limit(limit))
    total = db.cases.count_documents(query)
    return jresp({"cases": [serialize(d) for d in docs], "total": total})


@app.route("/cases", methods=["POST"])
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def create_case(user):
    data = request.get_json()
    case_id = next_case_id()
    risk_score = data.get("risk_score", 0)
    severity = "SAFE"

    if data.get("email_analysis_id"):
        analysis = db.email_analyses.find_one({"_id": data["email_analysis_id"]})
        if analysis:
            risk_score = analysis.get("overall_risk_score", risk_score)
            severity = analysis.get("risk_level", severity)
            origin = ""
            for hop in analysis.get("relay_path", []):
                if hop.get("hop_number") == 1:
                    origin = hop.get("location", "")
                    break
        else:
            origin = ""
    else:
        origin = ""

    doc = {
        "_id": case_id,
        "case_id": case_id,
        "title": data.get("title", ""),
        "classification": data.get("classification", ""),
        "risk_score": risk_score,
        "severity": severity,
        "sender": data.get("sender", ""),
        "subject": data.get("subject", ""),
        "origin": origin,
        "analyst_id": str(user["_id"]),
        "analyst_name": user["name"],
        "analyst_email": user["email"],
        "status": "NEW",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "email_analysis_id": data.get("email_analysis_id"),
        "evidence_ids": [],
        "ioc_ids": [],
        "campaign_id": None,
        "notes": [],
    }
    db.cases.insert_one(doc)

    if data.get("email_analysis_id"):
        db.email_analyses.update_one({"_id": data["email_analysis_id"]}, {"$set": {"case_id": case_id}})

    log_event("Case created", user=user, resource="case", resource_id=case_id, case_id=case_id)

    if risk_score >= 80:
        db.notifications.insert_one({
            "_id": str(uuid.uuid4()),
            "user_id": str(user["_id"]),
            "title": f"Critical threat case created: {case_id}",
            "message": f"Risk score {risk_score}/100 — {doc['classification']}",
            "type": "critical",
            "read": False,
            "created_at": datetime.now(timezone.utc),
            "case_id": case_id,
        })

    return jresp(serialize(doc))


@app.route("/cases/<case_id>")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def get_case(user, case_id):
    doc = db.cases.find_one({"_id": case_id})
    if not doc:
        return jresp({"detail": "Case not found"}, 404)
    log_event("Case opened", user=user, resource="case", resource_id=case_id, case_id=case_id)
    return jresp(serialize(doc))


@app.route("/cases/<case_id>", methods=["PUT"])
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def update_case(user, case_id):
    data = request.get_json()
    update = {"updated_at": datetime.now(timezone.utc)}
    if data.get("status"):
        update["status"] = data["status"].upper()
    if data.get("title"):
        update["title"] = data["title"]
    if data.get("classification"):
        update["classification"] = data["classification"]
    if data.get("analyst_id"):
        update["analyst_id"] = data["analyst_id"]

    result = db.cases.update_one({"_id": case_id}, {"$set": update})
    if result.matched_count == 0:
        return jresp({"detail": "Case not found"}, 404)
    log_event("Case updated", user=user, resource="case", resource_id=case_id, case_id=case_id)
    return jresp(serialize(db.cases.find_one({"_id": case_id})))


@app.route("/cases/<case_id>/notes", methods=["POST"])
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def add_note(user, case_id):
    data = request.get_json()
    note = {
        "id": str(uuid.uuid4()),
        "content": data.get("content", ""),
        "author": user["name"],
        "author_email": user["email"],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    result = db.cases.update_one(
        {"_id": case_id},
        {"$push": {"notes": note}, "$set": {"updated_at": datetime.now(timezone.utc)}}
    )
    if result.matched_count == 0:
        return jresp({"detail": "Case not found"}, 404)
    log_event("Note added to case", user=user, case_id=case_id)
    return jresp(note)


# ─── Intelligence ─────────────────────────────────────────────────────────────

@app.route("/intel/domain/<domain>")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def domain_intel(user, domain):
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from app.intelligence.providers import MockThreatIntelProvider
    import asyncio
    provider = MockThreatIntelProvider()
    result = asyncio.run(provider.lookup_domain(domain))
    log_event("IOC viewed", user=user, resource="domain_intel", resource_id=domain)
    return jresp(result)


@app.route("/intel/ip/<ip>")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def ip_intel(user, ip):
    from app.intelligence.providers import MockThreatIntelProvider
    import asyncio, urllib.request

    provider = MockThreatIntelProvider()
    result = asyncio.run(provider.lookup_ip(ip))

    # Try live geolocation
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=status,country,city,regionName,isp,as,lat,lon", timeout=3) as resp:
            geo = json.loads(resp.read())
            if geo.get("status") == "success":
                result.update({
                    "country": geo.get("country", result["country"]),
                    "city": geo.get("city", result["city"]),
                    "region": geo.get("regionName", ""),
                    "isp": geo.get("isp", result["isp"]),
                    "asn": geo.get("as", result["asn"]),
                    "lat": geo.get("lat"),
                    "lon": geo.get("lon"),
                })
    except Exception:
        pass

    log_event("IOC viewed", user=user, resource="ip_intel", resource_id=ip)
    return jresp(result)


@app.route("/intel/url", methods=["POST"])
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def url_intel(user):
    data = request.get_json()
    return jresp({"url": data.get("url", ""), "reputation": "unknown", "is_demo": True, "data_source": "Demo Intelligence"})


@app.route("/intel/iocs")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def list_iocs(user):
    ioc_type = request.args.get("ioc_type")
    query = {}
    if ioc_type:
        query["type"] = ioc_type
    docs = list(db.iocs.find(query).sort("last_seen", DESCENDING).limit(50))
    return jresp([serialize(d) for d in docs])


# ─── Evidence ─────────────────────────────────────────────────────────────────

@app.route("/evidence/<evidence_id>")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def get_evidence(user, evidence_id):
    doc = db.evidence.find_one({"_id": evidence_id})
    if not doc:
        return jresp({"detail": "Evidence not found"}, 404)
    return jresp(serialize(doc))


@app.route("/evidence/<evidence_id>/verify", methods=["POST"])
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def verify_evidence(user, evidence_id):
    doc = db.evidence.find_one({"_id": evidence_id})
    if not doc:
        return jresp({"detail": "Evidence not found"}, 404)
    return jresp({"evidence_id": evidence_id, "sha256": doc.get("sha256"), "integrity_status": "VERIFIED",
                  "verified_at": datetime.now(timezone.utc).isoformat()})


@app.route("/evidence/<evidence_id>", methods=["DELETE"])
@require_role("SENIOR_ANALYST", "ADMINISTRATOR")
def delete_evidence(user, evidence_id):
    result = db.evidence.delete_one({"_id": evidence_id})
    if result.deleted_count == 0:
        return jresp({"detail": "Evidence not found"}, 404)
    log_event("Evidence deleted", user=user, resource="evidence", resource_id=evidence_id)
    return jresp({"message": "Evidence deleted"})


# ─── Reports ──────────────────────────────────────────────────────────────────

@app.route("/reports")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def list_reports(user):
    docs = list(db.reports.find({}).sort("created_at", DESCENDING).limit(50))
    return jresp([serialize(d) for d in docs])


@app.route("/reports", methods=["POST"])
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def create_report(user):
    data = request.get_json()
    case_id = data.get("case_id")
    case = db.cases.find_one({"_id": case_id})
    if not case:
        return jresp({"detail": "Case not found"}, 404)

    report_id = str(uuid.uuid4())
    title = data.get("title") or f"Forensic Report — {case.get('case_id', case_id)}"

    doc = {
        "_id": report_id,
        "report_id": report_id,
        "case_id": case_id,
        "case_ref": case.get("case_id", ""),
        "title": title,
        "analyst_id": str(user["_id"]),
        "analyst_name": user["name"],
        "analyst_email": user["email"],
        "created_at": datetime.now(timezone.utc),
        "status": "completed",
        "risk_score": case.get("risk_score", 0),
        "classification": case.get("classification", ""),
        "severity": case.get("severity", ""),
    }
    db.reports.insert_one(doc)
    log_event("Report generated", user=user, resource="report", resource_id=report_id, case_id=case_id)
    return jresp(serialize(doc))


@app.route("/reports/<report_id>")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def get_report(user, report_id):
    doc = db.reports.find_one({"_id": report_id})
    if not doc:
        return jresp({"detail": "Report not found"}, 404)
    return jresp(serialize(doc))


@app.route("/reports/<report_id>/download")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def download_report(user, report_id):
    report = db.reports.find_one({"_id": report_id})
    if not report:
        return jresp({"detail": "Report not found"}, 404)

    case = db.cases.find_one({"_id": report.get("case_id")}) if report.get("case_id") else None
    analysis = None
    if case and case.get("email_analysis_id"):
        analysis = db.email_analyses.find_one({"_id": case["email_analysis_id"]})

    html = generate_html_report(report, case, analysis, user)
    resp = Response(html, status=200, mimetype="text/html")
    resp.headers["Content-Disposition"] = f'attachment; filename="report-{report_id[:8]}.html"'
    return resp


# ─── Audit Logs ───────────────────────────────────────────────────────────────

@app.route("/audit-logs")
@require_role("ADMINISTRATOR")
def list_audit_logs(user):
    skip = int(request.args.get("skip", 0))
    limit = int(request.args.get("limit", 100))
    docs = list(db.audit_logs.find({}).sort("timestamp", DESCENDING).skip(skip).limit(limit))
    total = db.audit_logs.count_documents({})
    return jresp({"logs": [serialize(d) for d in docs], "total": total})


# ─── Users ────────────────────────────────────────────────────────────────────

@app.route("/users")
@require_role("ADMINISTRATOR")
def list_users(user):
    docs = list(db.users.find({}))
    result = []
    for d in docs:
        u = serialize(d)
        u.pop("password_hash", None)
        result.append(u)
    return jresp(result)


@app.route("/users", methods=["POST"])
@require_role("ADMINISTRATOR")
def create_user(user):
    data = request.get_json()
    if db.users.find_one({"email": data.get("email", "").lower()}):
        return jresp({"detail": "Email already registered"}, 409)
    doc = {
        "name": data["name"],
        "email": data["email"].lower(),
        "password_hash": hash_password(data["password"]),
        "role": data.get("role", "ANALYST"),
        "status": "active",
        "created_at": datetime.now(timezone.utc),
        "last_login": None,
    }
    result = db.users.insert_one(doc)
    log_event("User created", user=user, resource="user",
              resource_id=str(result.inserted_id), details={"email": data["email"]})
    doc["id"] = str(result.inserted_id)
    doc.pop("password_hash", None)
    return jresp(serialize(doc))


@app.route("/users/<user_id>", methods=["PUT"])
@require_role("ADMINISTRATOR")
def update_user(user, user_id):
    data = request.get_json()
    update = {}
    if data.get("name"):
        update["name"] = data["name"]
    if data.get("role"):
        update["role"] = data["role"]
    if data.get("status"):
        update["status"] = data["status"]
    try:
        db.users.update_one({"_id": ObjectId(user_id)}, {"$set": update})
    except Exception:
        return jresp({"detail": "Invalid user ID"}, 400)
    log_event("User updated", user=user, resource="user", resource_id=user_id)
    return jresp({"message": "User updated"})


@app.route("/users/<user_id>", methods=["DELETE"])
@require_role("ADMINISTRATOR")
def deactivate_user(user, user_id):
    try:
        db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"status": "inactive"}})
    except Exception:
        return jresp({"detail": "Invalid user ID"}, 400)
    log_event("User deactivated", user=user, resource="user", resource_id=user_id)
    return jresp({"message": "User deactivated"})


# ─── Campaigns ────────────────────────────────────────────────────────────────

@app.route("/campaigns")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def list_campaigns(user):
    docs = list(db.campaigns.find({}).sort("created_at", DESCENDING).limit(20))
    return jresp([serialize(d) for d in docs])


@app.route("/campaigns/<campaign_id>/graph")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def campaign_graph(user, campaign_id):
    campaign = db.campaigns.find_one({"_id": campaign_id})
    if not campaign:
        return jresp({"detail": "Campaign not found"}, 404)

    cases = list(db.cases.find({"campaign_id": campaign_id}))
    iocs_data = list(db.iocs.find({"campaign_id": campaign_id}))

    nodes = [{"id": campaign_id, "type": "campaign", "label": campaign.get("name", "Campaign"), "data": {}}]
    edges = []
    seen = {campaign_id}

    for c in cases:
        cid = str(c.get("_id", ""))
        if cid not in seen:
            nodes.append({"id": cid, "type": "case", "label": cid,
                          "data": {"classification": c.get("classification"), "risk_score": c.get("risk_score")}})
            edges.append({"source": campaign_id, "target": cid, "label": "contains"})
            seen.add(cid)

    for ioc in iocs_data:
        iid = str(ioc.get("_id", ""))
        if iid not in seen:
            nodes.append({"id": iid, "type": ioc.get("type", "ioc"), "label": ioc.get("value", "")[:30],
                          "data": {"reputation": ioc.get("reputation"), "type": ioc.get("type")}})
            seen.add(iid)

    return jresp({"nodes": nodes, "edges": edges, "campaign": campaign.get("name", "")})


# ─── Gmail ────────────────────────────────────────────────────────────────────

@app.route("/gmail/status")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def gmail_status(user):
    user_id = str(user["_id"])
    connection = db.gmail_connections.find_one({"user_id": user_id})
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        return jresp({"connected": False, "demo_mode": True, "message": "Gmail not configured — showing demo inbox"})
    return jresp({
        "connected": bool(connection and connection.get("status") == "connected"),
        "email": connection.get("email", "") if connection else "",
        "demo_mode": False,
    })


@app.route("/auth/gmail")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def gmail_auth(user):
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        return jresp({"detail": "Gmail not configured", "demo_mode": True}, 503)
    # Return OAuth URL
    from urllib.parse import urlencode
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/gmail/callback"),
        "response_type": "code",
        "scope": "https://www.googleapis.com/auth/gmail.readonly",
        "access_type": "offline",
        "state": str(user["_id"]),
    }
    auth_url = "https://accounts.google.com/o/oauth2/auth?" + urlencode(params)
    return jresp({"auth_url": auth_url})


@app.route("/gmail/emails")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def gmail_emails(user):
    # Demo inbox fallback
    return jresp({
        "demo_mode": True,
        "message": "Gmail not configured — showing demo inbox",
        "emails": [
            {"id": "demo-gmail-1", "from": "security-alerts@google.com", "subject": "New sign-in to your Google Account",
             "date": "Mon, 26 Aug 2026 09:00:00 +0000", "snippet": "We noticed a new sign-in to your Google Account...",
             "is_read": True, "risk_badge": None, "source": "demo"},
            {"id": "demo-gmail-2", "from": "payroll@microsOft-support.com", "subject": "ACTION REQUIRED: Verify your payroll account",
             "date": "Mon, 26 Aug 2026 10:15:00 +0000", "snippet": "Your payroll direct deposit must be verified within 24 hours...",
             "is_read": False, "risk_badge": "HIGH", "source": "demo"},
            {"id": "demo-gmail-3", "from": "ceo@micros0ft-secure.com", "subject": "Urgent Vendor Payment Approval",
             "date": "Mon, 26 Aug 2026 11:30:00 +0000", "snippet": "I need you to process an urgent vendor payment today...",
             "is_read": False, "risk_badge": "CRITICAL", "source": "demo"},
        ],
    })


@app.route("/gmail/emails/<message_id>/analyze", methods=["POST"])
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def analyze_gmail_email(user, message_id):
    # For demo, map to a demo email
    demo_map = {"demo-gmail-2": "demo-2", "demo-gmail-3": "demo-3", "demo-gmail-1": "demo-1"}
    demo_id = demo_map.get(message_id, "demo-3")
    if demo_id in DEMO_EMAILS:
        result = run_full_analysis(DEMO_EMAILS[demo_id]["raw"], str(user["_id"]), is_demo=True, demo_id=demo_id)
        log_event("Gmail email analyzed", user=user, resource="email_analysis",
                  resource_id=result["_id"], details={"gmail_message_id": message_id})
        return jresp(serialize(result))
    return jresp({"detail": "Email not found"}, 404)


@app.route("/gmail/disconnect", methods=["POST"])
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def gmail_disconnect(user):
    db.gmail_connections.delete_one({"user_id": str(user["_id"])})
    log_event("Gmail disconnected", user=user)
    return jresp({"message": "Gmail disconnected"})


# ─── Notifications ────────────────────────────────────────────────────────────

@app.route("/notifications")
@require_auth
def list_notifications(user):
    user_id = str(user["_id"])
    docs = list(db.notifications.find({"user_id": user_id}).sort("created_at", DESCENDING).limit(20))
    return jresp([serialize(d) for d in docs])


@app.route("/notifications/<notif_id>/read", methods=["POST"])
@require_auth
def mark_notification_read(user, notif_id):
    db.notifications.update_one({"_id": notif_id}, {"$set": {"read": True}})
    return jresp({"message": "Marked as read"})


# ─── Search ───────────────────────────────────────────────────────────────────

@app.route("/search")
@require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
def search(user):
    q = request.args.get("q", "")
    if len(q) < 2:
        return jresp([])

    results = []
    cases = list(db.cases.find({
        "$or": [
            {"_id": {"$regex": q, "$options": "i"}},
            {"sender": {"$regex": q, "$options": "i"}},
            {"subject": {"$regex": q, "$options": "i"}},
        ]
    }).limit(5))
    for c in cases:
        results.append({"type": "case", "id": str(c.get("_id", "")), "title": str(c.get("_id", "")),
                        "subtitle": c.get("subject", ""), "url": "/cases"})

    iocs = list(db.iocs.find({"value": {"$regex": q, "$options": "i"}}).limit(5))
    for ioc in iocs:
        results.append({"type": "ioc", "id": str(ioc.get("_id", "")), "title": ioc.get("value", ""),
                        "subtitle": ioc.get("type", ""), "url": "/threat-intelligence"})

    return jresp(results)


# ─── Settings ─────────────────────────────────────────────────────────────────

@app.route("/settings")
@require_role("ADMINISTRATOR")
def get_settings(user):
    return jresp({
        "virustotal_configured": bool(VIRUSTOTAL_API_KEY),
        "gmail_configured": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
        "environment": os.getenv("ENVIRONMENT", "development"),
    })


@app.route("/settings/virustotal/test", methods=["POST"])
@require_role("ADMINISTRATOR")
def test_virustotal(user):
    data = request.get_json()
    api_key = data.get("api_key", "")
    import urllib.request
    try:
        req = urllib.request.Request(
            "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
            headers={"x-apikey": api_key}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                log_event("VirusTotal API key tested", user=user, result="Success")
                return jresp({"status": "connected", "message": "VirusTotal API key is valid"})
    except Exception as e:
        pass
    return jresp({"status": "error", "message": "Invalid API key or connection failed"})


# ─── Error handlers ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jresp({"detail": "Not found"}, 404)


@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return jresp({"detail": "Internal server error"}, 500)


if __name__ == "__main__":
    logger.info("🚀 MailTrace AI Flask backend starting on port 8000...")
    app.run(host="0.0.0.0", port=8000, debug=True)
