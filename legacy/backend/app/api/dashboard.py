"""Dashboard statistics routes."""
from fastapi import APIRouter, Depends
from datetime import datetime, timezone, timedelta
from app.core.database import get_db
from app.core.security import require_analyst

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats")
async def get_stats(current_user: dict = Depends(require_analyst)):
    db = get_db()

    # Count from MongoDB
    total_analyses = await db.email_analyses.count_documents({})
    critical = await db.email_analyses.count_documents({"risk_level": "CRITICAL"})
    phishing = await db.email_analyses.count_documents({
        "classification": {"$in": ["Phishing", "Credential Phishing"]}
    })
    bec = await db.email_analyses.count_documents({"classification": "Business Email Compromise"})
    active_cases = await db.cases.count_documents({"status": {"$in": ["NEW", "INVESTIGATING", "ESCALATED"]}})
    active_campaigns = await db.campaigns.count_documents({"status": "active"})

    # Average risk score
    pipeline = [{"$group": {"_id": None, "avg": {"$avg": "$overall_risk_score"}}}]
    result = await db.email_analyses.aggregate(pipeline).to_list(1)
    avg_score = result[0]["avg"] if result else 0

    return {
        "emails_analyzed": total_analyses,
        "critical_threats": critical,
        "phishing_detected": phishing,
        "bec_detected": bec,
        "active_cases": active_cases,
        "active_campaigns": active_campaigns,
        "avg_risk_score": round(avg_score, 1),
    }


@router.get("/threat-trends")
async def get_threat_trends(current_user: dict = Depends(require_analyst)):
    db = get_db()

    # Last 14 days aggregation
    pipeline = [
        {"$match": {"created_at": {"$gte": datetime.now(timezone.utc) - timedelta(days=14)}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$created_at"}},
            "threats": {"$sum": 1},
            "critical": {"$sum": {"$cond": [{"$gte": ["$overall_risk_score", 80]}, 1, 0]}},
        }},
        {"$sort": {"_id": 1}},
    ]
    result = await db.email_analyses.aggregate(pipeline).to_list(14)
    return [{"date": r["_id"], "threats": r["threats"], "critical": r["critical"]} for r in result]


@router.get("/recent-cases")
async def get_recent_cases(limit: int = 10, current_user: dict = Depends(require_analyst)):
    db = get_db()
    cursor = db.cases.find({}).sort("created_at", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    result = []
    for d in docs:
        result.append({
            "id": str(d.get("_id", "")),
            "case_id": d.get("case_id", ""),
            "sender": d.get("sender", ""),
            "subject": d.get("subject", ""),
            "classification": d.get("classification", ""),
            "risk_score": d.get("risk_score", 0),
            "origin": d.get("origin", "Unknown"),
            "status": d.get("status", "NEW"),
            "created_at": d.get("created_at").isoformat() if d.get("created_at") else "",
        })
    return result


@router.get("/threat-distribution")
async def get_threat_distribution(current_user: dict = Depends(require_analyst)):
    db = get_db()
    pipeline = [
        {"$group": {"_id": "$classification", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    result = await db.email_analyses.aggregate(pipeline).to_list(20)
    colors = {
        "Legitimate": "#22c55e",
        "Phishing": "#ef4444",
        "Credential Phishing": "#f97316",
        "Business Email Compromise": "#8b5cf6",
        "Suspicious": "#3b82f6",
        "Malware Delivery": "#dc2626",
        "Invoice Fraud": "#eab308",
        "Executive Impersonation": "#ec4899",
    }
    return [
        {"name": r["_id"] or "Unknown", "value": r["count"],
         "color": colors.get(r["_id"], "#94a3b8")}
        for r in result if r["_id"]
    ]


@router.get("/auth-failures")
async def get_auth_failures(current_user: dict = Depends(require_analyst)):
    db = get_db()
    pipeline = [
        {"$match": {"created_at": {"$gte": datetime.now(timezone.utc) - timedelta(days=7)}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$created_at"}},
            "spf": {"$sum": {"$cond": [{"$eq": ["$auth.spf", "fail"]}, 1, 0]}},
            "dkim": {"$sum": {"$cond": [{"$eq": ["$auth.dkim", "fail"]}, 1, 0]}},
            "dmarc": {"$sum": {"$cond": [{"$eq": ["$auth.dmarc", "fail"]}, 1, 0]}},
        }},
        {"$sort": {"_id": 1}},
    ]
    result = await db.email_analyses.aggregate(pipeline).to_list(7)
    return [{"date": r["_id"], "spf": r["spf"], "dkim": r["dkim"], "dmarc": r["dmarc"]} for r in result]


@router.get("/top-domains")
async def get_top_malicious_domains(current_user: dict = Depends(require_analyst)):
    db = get_db()
    pipeline = [
        {"$match": {"reputation": {"$in": ["malicious", "suspicious"]}}},
        {"$group": {"_id": "$value", "count": {"$sum": 1}, "reputation": {"$first": "$reputation"}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    result = await db.iocs.aggregate(pipeline).to_list(10)
    return [{"domain": r["_id"], "count": r["count"], "risk": r.get("reputation", "suspicious")} for r in result]
