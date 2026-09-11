"""
Supplementary seed — adds evidence + notifications data to MongoDB.
Run: python seed_extra.py
"""
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
import uuid
import hashlib

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGODB_DB_NAME", "mailtrace_ai")


DEMO_EVIDENCE = [
    {
        "_id": f"ev-{str(uuid.uuid4())[:8]}",
        "evidence_id": "EV-2026-001",
        "sha256": hashlib.sha256(b"demo-bec-payment-request").hexdigest(),
        "md5": hashlib.md5(b"demo-bec-payment-request").hexdigest(),
        "filename": "urgent_vendor_payment.eml",
        "size_bytes": 4832,
        "mime_type": "message/rfc822",
        "case_id": "MT-2026-00124",
        "analysis_id": None,
        "preserved_by": "admin@mailtrace.ai",
        "notes": "BEC email impersonating CEO — requesting $87,500 wire transfer",
        "custody_chain": [
            {"event": "Email Uploaded", "timestamp": "2026-08-26T11:45:33Z", "analyst": "admin@mailtrace.ai"},
            {"event": "Analysis Completed", "timestamp": "2026-08-26T11:46:01Z", "analyst": "admin@mailtrace.ai"},
            {"event": "Case Created", "timestamp": "2026-08-26T11:46:15Z", "analyst": "admin@mailtrace.ai"},
        ],
    },
    {
        "_id": f"ev-{str(uuid.uuid4())[:8]}",
        "evidence_id": "EV-2026-002",
        "sha256": hashlib.sha256(b"demo-payroll-phish").hexdigest(),
        "md5": hashlib.md5(b"demo-payroll-phish").hexdigest(),
        "filename": "payroll_verification_phishing.eml",
        "size_bytes": 3219,
        "mime_type": "message/rfc822",
        "case_id": "MT-2026-00123",
        "analysis_id": None,
        "preserved_by": "admin@mailtrace.ai",
        "notes": "Credential phishing from microsOft-support.com targeting payroll credentials",
        "custody_chain": [
            {"event": "Email Uploaded", "timestamp": "2026-08-26T10:18:10Z", "analyst": "admin@mailtrace.ai"},
            {"event": "Analysis Completed", "timestamp": "2026-08-26T10:18:45Z", "analyst": "admin@mailtrace.ai"},
            {"event": "Case Created", "timestamp": "2026-08-26T10:19:02Z", "analyst": "admin@mailtrace.ai"},
        ],
    },
    {
        "_id": f"ev-{str(uuid.uuid4())[:8]}",
        "evidence_id": "EV-2026-003",
        "sha256": hashlib.sha256(b"demo-invoice-fraud-pdf").hexdigest(),
        "md5": hashlib.md5(b"demo-invoice-fraud-pdf").hexdigest(),
        "filename": "invoice_fraud_attachment.pdf",
        "size_bytes": 128450,
        "mime_type": "application/pdf",
        "case_id": "MT-2026-00122",
        "analysis_id": None,
        "preserved_by": "senior@mailtrace.ai",
        "notes": "Fake invoice PDF with embedded macro — malware delivery vector",
        "custody_chain": [
            {"event": "Attachment Extracted", "timestamp": "2026-08-25T16:30:22Z", "analyst": "senior@mailtrace.ai"},
            {"event": "Analysis Completed", "timestamp": "2026-08-25T16:31:05Z", "analyst": "senior@mailtrace.ai"},
        ],
    },
    {
        "_id": f"ev-{str(uuid.uuid4())[:8]}",
        "evidence_id": "EV-2026-004",
        "sha256": hashlib.sha256(b"demo-google-phish").hexdigest(),
        "md5": hashlib.md5(b"demo-google-phish").hexdigest(),
        "filename": "google_account_verification.eml",
        "size_bytes": 6102,
        "mime_type": "message/rfc822",
        "case_id": "MT-2026-00121",
        "analysis_id": None,
        "preserved_by": "analyst@mailtrace.ai",
        "notes": "Lookalike Google domain — credential theft attempt targeting G Suite accounts",
        "custody_chain": [
            {"event": "Email Uploaded", "timestamp": "2026-08-22T10:14:00Z", "analyst": "analyst@mailtrace.ai"},
            {"event": "Analysis Completed", "timestamp": "2026-08-22T10:14:40Z", "analyst": "analyst@mailtrace.ai"},
        ],
    },
    {
        "_id": f"ev-{str(uuid.uuid4())[:8]}",
        "evidence_id": "EV-2026-005",
        "sha256": hashlib.sha256(b"demo-hr-malware-docx").hexdigest(),
        "md5": hashlib.md5(b"demo-hr-malware-docx").hexdigest(),
        "filename": "hr_salary_revision_letter.docx",
        "size_bytes": 45672,
        "mime_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "case_id": "MT-2026-00120",
        "analysis_id": None,
        "preserved_by": "senior@mailtrace.ai",
        "notes": "Word document with malicious macro claimed to be salary revision letter",
        "custody_chain": [
            {"event": "Attachment Extracted", "timestamp": "2026-08-22T14:28:19Z", "analyst": "senior@mailtrace.ai"},
        ],
    },
    {
        "_id": f"ev-{str(uuid.uuid4())[:8]}",
        "evidence_id": "EV-2026-006",
        "sha256": hashlib.sha256(b"demo-paypal-impersonation").hexdigest(),
        "md5": hashlib.md5(b"demo-paypal-impersonation").hexdigest(),
        "filename": "paypal_account_alert.eml",
        "size_bytes": 5230,
        "mime_type": "message/rfc822",
        "case_id": "MT-2026-00113",
        "analysis_id": None,
        "preserved_by": "senior@mailtrace.ai",
        "notes": "PayPal impersonation phishing with credential harvesting link",
        "custody_chain": [
            {"event": "Email Uploaded", "timestamp": "2026-08-20T09:15:30Z", "analyst": "senior@mailtrace.ai"},
            {"event": "Analysis Completed", "timestamp": "2026-08-20T09:16:12Z", "analyst": "senior@mailtrace.ai"},
            {"event": "Case Resolved", "timestamp": "2026-08-21T16:30:00Z", "analyst": "senior@mailtrace.ai"},
        ],
    },
]


DEMO_NOTIFICATIONS = [
    {
        "_id": str(uuid.uuid4()),
        "user_id": "user-admin-001",
        "type": "threat",
        "title": "Critical BEC Detected",
        "message": "A Business Email Compromise attempt targeting the finance department has been detected. Risk score: 94/100.",
        "case_id": "MT-2026-00124",
        "read": False,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=2),
    },
    {
        "_id": str(uuid.uuid4()),
        "user_id": "user-admin-001",
        "type": "threat",
        "title": "Credential Phishing Blocked",
        "message": "Payroll credential phishing email from microsOft-support.com blocked. Risk score: 86/100.",
        "case_id": "MT-2026-00123",
        "read": False,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=5),
    },
    {
        "_id": str(uuid.uuid4()),
        "user_id": "user-admin-001",
        "type": "case_update",
        "title": "Case Escalated",
        "message": "Case MT-2026-00124 has been escalated to Senior Analyst Sarah Kim for further investigation.",
        "case_id": "MT-2026-00124",
        "read": False,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=6),
    },
    {
        "_id": str(uuid.uuid4()),
        "user_id": "user-admin-001",
        "type": "system",
        "title": "New IOCs Extracted",
        "message": "3 new Indicators of Compromise (domains and IPs) have been extracted from recent analyses.",
        "case_id": None,
        "read": True,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=12),
    },
    {
        "_id": str(uuid.uuid4()),
        "user_id": "user-admin-001",
        "type": "report",
        "title": "Report Ready for Review",
        "message": "Forensic report RPT-003 for BEC investigation has been generated and is ready for review.",
        "case_id": "MT-2026-00118",
        "read": True,
        "created_at": datetime.now(timezone.utc) - timedelta(days=1),
    },
    {
        "_id": str(uuid.uuid4()),
        "user_id": "user-admin-001",
        "type": "campaign",
        "title": "Campaign Detected",
        "message": "New campaign 'Operation Phantom Invoice' identified linking 4 related BEC emails across 3 organizations.",
        "case_id": None,
        "read": True,
        "created_at": datetime.now(timezone.utc) - timedelta(days=2),
    },
]


async def seed_extra():
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]

    print("🌱 Seeding evidence and notifications...\n")

    # ── Evidence ──────────────────────────────────────────────────────────────
    for ev in DEMO_EVIDENCE:
        ev["created_at"] = datetime.now(timezone.utc) - timedelta(days=3, hours=2)
        ev["updated_at"] = datetime.now(timezone.utc) - timedelta(hours=1)
        ev["integrity_verified"] = True
        if not await db.evidence.find_one({"evidence_id": ev["evidence_id"]}):
            await db.evidence.insert_one(ev)
    count = await db.evidence.count_documents({})
    print(f"  ✅ Evidence collection: {count} items")

    # ── Notifications ─────────────────────────────────────────────────────────
    existing = await db.notifications.count_documents({})
    if existing < 3:
        await db.notifications.insert_many(DEMO_NOTIFICATIONS)
        print(f"  ✅ Seeded {len(DEMO_NOTIFICATIONS)} notifications")
    else:
        print(f"  ⏭️  Notifications already seeded ({existing} items)")

    # ── Indexes ───────────────────────────────────────────────────────────────
    await db.evidence.create_index([("case_id", 1)])
    await db.evidence.create_index([("created_at", -1)])
    await db.notifications.create_index([("user_id", 1), ("created_at", -1)])
    print("  ✅ Indexes created")

    client.close()
    print("\n🎉 Extra seed complete!")


if __name__ == "__main__":
    asyncio.run(seed_extra())
