"""Cases CRUD, notes, status management."""
from fastapi import APIRouter, HTTPException, Depends, Request
from datetime import datetime, timezone
from bson import ObjectId
import uuid

from app.core.database import get_db
from app.core.security import get_current_user, require_analyst, require_senior
from app.schemas.schemas import CreateCaseRequest, UpdateCaseRequest, CaseNote
from app.services.audit import log_event

router = APIRouter(prefix="/cases", tags=["Cases"])

CASE_COUNTER_COLLECTION = "case_counter"


async def next_case_id(db) -> str:
    """Generate sequential case ID like MT-2026-00125."""
    result = await db.case_counter.find_one_and_update(
        {"_id": "global"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=True,
    )
    seq = result.get("seq", 125)
    year = datetime.now().year
    return f"MT-{year}-{seq:05d}"


def _serialize_case(doc: dict) -> dict:
    d = dict(doc)
    d["id"] = str(d.pop("_id"))
    for k, v in d.items():
        if hasattr(v, 'isoformat'):
            d[k] = v.isoformat()
    # Serialize nested notes
    notes = d.get("notes", [])
    for note in notes:
        for k, v in note.items():
            if hasattr(v, 'isoformat'):
                note[k] = v.isoformat()
    return d


@router.get("")
async def list_cases(
    skip: int = 0, limit: int = 50,
    status: str = None, classification: str = None,
    current_user: dict = Depends(require_analyst),
):
    db = get_db()
    query = {}
    if status:
        query["status"] = status.upper()
    if classification:
        query["classification"] = {"$regex": classification, "$options": "i"}

    cursor = db.cases.find(query).sort("created_at", -1).skip(skip).limit(limit)
    docs = await cursor.to_list(length=limit)
    total = await db.cases.count_documents(query)
    return {"cases": [_serialize_case(d) for d in docs], "total": total}


@router.post("")
async def create_case(
    data: CreateCaseRequest,
    request: Request,
    current_user: dict = Depends(require_analyst),
):
    db = get_db()
    case_id = await next_case_id(db)

    # Pull risk score from linked analysis
    risk_score = data.risk_score
    severity = "SAFE"
    if data.email_analysis_id:
        analysis = await db.email_analyses.find_one({"_id": data.email_analysis_id})
        if analysis:
            risk_score = analysis.get("overall_risk_score", risk_score)
            severity = analysis.get("risk_level", severity)

    for threshold, sev in [(80, "CRITICAL"), (60, "HIGH"), (40, "SUSPICIOUS"), (20, "LOW")]:
        if risk_score >= threshold:
            severity = sev
            break

    doc = {
        "_id": case_id,
        "case_id": case_id,
        "title": data.title,
        "classification": data.classification,
        "risk_score": risk_score,
        "severity": severity,
        "sender": data.sender,
        "subject": data.subject,
        "origin": "",
        "analyst_id": str(current_user["_id"]),
        "analyst_name": current_user["name"],
        "analyst_email": current_user["email"],
        "status": "NEW",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "email_analysis_id": data.email_analysis_id,
        "evidence_ids": [],
        "ioc_ids": [],
        "campaign_id": None,
        "notes": [],
    }

    await db.cases.insert_one(doc)

    # Update analysis with case_id
    if data.email_analysis_id:
        await db.email_analyses.update_one(
            {"_id": data.email_analysis_id},
            {"$set": {"case_id": case_id}}
        )

    await log_event("Case created", user=current_user, request=request,
                    resource="case", resource_id=case_id, case_id=case_id)

    # Create notification for critical cases
    if risk_score >= 80:
        await db.notifications.insert_one({
            "_id": str(uuid.uuid4()),
            "user_id": str(current_user["_id"]),
            "title": f"Critical threat case created: {case_id}",
            "message": f"Risk score {risk_score}/100 — {data.classification}",
            "type": "critical",
            "read": False,
            "created_at": datetime.now(timezone.utc),
            "case_id": case_id,
        })

    return _serialize_case(doc)


@router.get("/{case_id}")
async def get_case(case_id: str, request: Request,
                   current_user: dict = Depends(require_analyst)):
    db = get_db()
    doc = await db.cases.find_one({"_id": case_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Case not found")
    await log_event("Case opened", user=current_user, request=request,
                    resource="case", resource_id=case_id, case_id=case_id)
    return _serialize_case(doc)


@router.put("/{case_id}")
async def update_case(
    case_id: str,
    data: UpdateCaseRequest,
    request: Request,
    current_user: dict = Depends(require_analyst),
):
    db = get_db()
    update = {"updated_at": datetime.now(timezone.utc)}
    if data.status:
        update["status"] = data.status.value
    if data.title:
        update["title"] = data.title
    if data.classification:
        update["classification"] = data.classification
    if data.analyst_id:
        update["analyst_id"] = data.analyst_id

    result = await db.cases.update_one({"_id": case_id}, {"$set": update})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Case not found")

    await log_event("Case updated", user=current_user, request=request,
                    resource="case", resource_id=case_id, case_id=case_id,
                    details={"changes": list(update.keys())})

    doc = await db.cases.find_one({"_id": case_id})
    return _serialize_case(doc)


@router.post("/{case_id}/notes")
async def add_note(
    case_id: str,
    note: CaseNote,
    request: Request,
    current_user: dict = Depends(require_analyst),
):
    db = get_db()
    note_doc = {
        "id": str(uuid.uuid4()),
        "content": note.content,
        "author": current_user["name"],
        "author_email": current_user["email"],
        "created_at": datetime.now(timezone.utc),
    }
    result = await db.cases.update_one(
        {"_id": case_id},
        {"$push": {"notes": note_doc}, "$set": {"updated_at": datetime.now(timezone.utc)}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Case not found")

    await log_event("Note added to case", user=current_user, request=request,
                    case_id=case_id, resource="case_note")

    note_doc["created_at"] = note_doc["created_at"].isoformat()
    return note_doc


@router.post("/{case_id}/iocs")
async def add_ioc_to_case(
    case_id: str,
    request: Request,
    ioc_value: str = None,
    current_user: dict = Depends(require_analyst),
):
    db = get_db()
    await db.cases.update_one(
        {"_id": case_id},
        {"$addToSet": {"ioc_ids": ioc_value}, "$set": {"updated_at": datetime.now(timezone.utc)}}
    )
    return {"message": "IOC added to case"}
