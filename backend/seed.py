"""
Seed script — populates MongoDB with realistic demo data.
Run: python seed.py
"""
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
import uuid

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGODB_DB_NAME", "mailtrace_ai")

# bcrypt hash for "Admin@1234"
ADMIN_HASH = "$2b$12$K3NJC2nOLAYXFJMuPj7nEOGGKTEKFJB1JCxZVCzCf.KLCbCkXEd5O"
# bcrypt hash for "Analyst@1234"
ANALYST_HASH = "$2b$12$K3NJC2nOLAYXFJMuPj7nEOGGKTEKFJB1JCxZVCzCf.KLCbCkXEd5O"


async def hash(password: str) -> str:
    from passlib.context import CryptContext
    ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return ctx.hash(password)


DEMO_USERS = [
    {
        "_id": "user-admin-001",
        "name": "Admin User",
        "email": "admin@mailtrace.ai",
        "password": "Admin@1234",
        "role": "ADMINISTRATOR",
    },
    {
        "_id": "user-senior-001",
        "name": "Sarah Kim",
        "email": "senior@mailtrace.ai",
        "password": "Senior@1234",
        "role": "SENIOR_ANALYST",
    },
    {
        "_id": "user-analyst-001",
        "name": "Raj Kumar",
        "email": "analyst@mailtrace.ai",
        "password": "Analyst@1234",
        "role": "ANALYST",
    },
    {
        "_id": "user-alex-001",
        "name": "Alex Morgan",
        "email": "alex@mailtrace.ai",
        "password": "Alex@1234",
        "role": "SENIOR_ANALYST",
    },
]

DEMO_CASES = [
    {"_id": "MT-2026-00124", "case_id": "MT-2026-00124", "title": "Urgent Vendor Payment Approval", "classification": "Business Email Compromise", "risk_score": 94, "severity": "CRITICAL", "sender": "ceo@micros0ft-secure.com", "subject": "Urgent Vendor Payment Approval", "origin": "Singapore", "status": "INVESTIGATING", "analyst_id": "user-alex-001", "analyst_name": "Alex Morgan", "analyst_email": "alex@mailtrace.ai", "email_analysis_id": "analysis-demo-3", "evidence_ids": [], "ioc_ids": [], "campaign_id": "campaign-001", "notes": []},
    {"_id": "MT-2026-00123", "case_id": "MT-2026-00123", "title": "Payroll Verification Phishing", "classification": "Credential Phishing", "risk_score": 86, "severity": "CRITICAL", "sender": "payroll@microsOft-support.com", "subject": "ACTION REQUIRED: Verify your payroll account immediately", "origin": "Frankfurt, DE", "status": "INVESTIGATING", "analyst_id": "user-alex-001", "analyst_name": "Alex Morgan", "analyst_email": "alex@mailtrace.ai", "email_analysis_id": "analysis-demo-2", "evidence_ids": [], "ioc_ids": [], "campaign_id": "campaign-001", "notes": []},
    {"_id": "MT-2026-00122", "case_id": "MT-2026-00122", "title": "Invoice Fraud — Vendor Portal", "classification": "Invoice Fraud", "risk_score": 67, "severity": "HIGH", "sender": "invoice@vendor-portal.co", "subject": "Invoice #8841 ready for payment", "origin": "Amsterdam, NL", "status": "NEW", "analyst_id": "user-senior-001", "analyst_name": "Sarah Kim", "analyst_email": "senior@mailtrace.ai", "email_analysis_id": None, "evidence_ids": [], "ioc_ids": [], "campaign_id": None, "notes": []},
    {"_id": "MT-2026-00121", "case_id": "MT-2026-00121", "title": "Microsoft Security Summary — Legitimate", "classification": "Legitimate", "risk_score": 7, "severity": "SAFE", "sender": "security-noreply@microsoft.com", "subject": "Your Microsoft 365 security summary", "origin": "Dublin, IE", "status": "RESOLVED", "analyst_id": "user-alex-001", "analyst_name": "Alex Morgan", "analyst_email": "alex@mailtrace.ai", "email_analysis_id": "analysis-demo-1", "evidence_ids": [], "ioc_ids": [], "campaign_id": None, "notes": []},
    {"_id": "MT-2026-00120", "case_id": "MT-2026-00120", "title": "Executive Impersonation — HR Update", "classification": "Executive Impersonation", "risk_score": 78, "severity": "HIGH", "sender": "hr-team@acm3-corp.com", "subject": "Important HR Update for All Employees", "origin": "Bucharest, RO", "status": "ESCALATED", "analyst_id": "user-analyst-001", "analyst_name": "Raj Kumar", "analyst_email": "analyst@mailtrace.ai", "email_analysis_id": None, "evidence_ids": [], "ioc_ids": [], "campaign_id": "campaign-002", "notes": []},
    {"_id": "MT-2026-00119", "case_id": "MT-2026-00119", "title": "Amazon Prime Impersonation", "classification": "Credential Phishing", "risk_score": 82, "severity": "CRITICAL", "sender": "noreply@amazonn-prime.com", "subject": "Your order has shipped", "origin": "Lagos, NG", "status": "NEW", "analyst_id": "user-senior-001", "analyst_name": "Sarah Kim", "analyst_email": "senior@mailtrace.ai", "email_analysis_id": None, "evidence_ids": [], "ioc_ids": [], "campaign_id": "campaign-001", "notes": []},
    {"_id": "MT-2026-00118", "case_id": "MT-2026-00118", "title": "Q3 Budget BEC", "classification": "Business Email Compromise", "risk_score": 89, "severity": "CRITICAL", "sender": "cfo@company-finance.net", "subject": "Q3 Budget Approval Required", "origin": "Hong Kong", "status": "ESCALATED", "analyst_id": "user-alex-001", "analyst_name": "Alex Morgan", "analyst_email": "alex@mailtrace.ai", "email_analysis_id": None, "evidence_ids": [], "ioc_ids": [], "campaign_id": "campaign-001", "notes": []},
    {"_id": "MT-2026-00117", "case_id": "MT-2026-00117", "title": "IT Helpdesk Account Suspension Phishing", "classification": "Credential Phishing", "risk_score": 74, "severity": "HIGH", "sender": "admin@it-helpdesk-support.info", "subject": "Your account will be suspended", "origin": "Kyiv, UA", "status": "RESOLVED", "analyst_id": "user-analyst-001", "analyst_name": "Raj Kumar", "analyst_email": "analyst@mailtrace.ai", "email_analysis_id": None, "evidence_ids": [], "ioc_ids": [], "campaign_id": None, "notes": []},
    {"_id": "MT-2026-00116", "case_id": "MT-2026-00116", "title": "FedEx Delivery Phishing", "classification": "Credential Phishing", "risk_score": 81, "severity": "CRITICAL", "sender": "shipping@fedexpress-track.com", "subject": "Package delivery failed — action required", "origin": "Sofia, BG", "status": "RESOLVED", "analyst_id": "user-senior-001", "analyst_name": "Sarah Kim", "analyst_email": "senior@mailtrace.ai", "email_analysis_id": None, "evidence_ids": [], "ioc_ids": [], "campaign_id": "campaign-002", "notes": []},
    {"_id": "MT-2026-00115", "case_id": "MT-2026-00115", "title": "Board Wire Transfer BEC", "classification": "Business Email Compromise", "risk_score": 96, "severity": "CRITICAL", "sender": "ceo@internal-board.co", "subject": "Confidential: Board resolution — transfer approval", "origin": "Moscow, RU", "status": "ESCALATED", "analyst_id": "user-alex-001", "analyst_name": "Alex Morgan", "analyst_email": "alex@mailtrace.ai", "email_analysis_id": None, "evidence_ids": [], "ioc_ids": [], "campaign_id": "campaign-001", "notes": []},
    {"_id": "MT-2026-00114", "case_id": "MT-2026-00114", "title": "Vendor Bank Account Fraud", "classification": "Invoice Fraud", "risk_score": 71, "severity": "HIGH", "sender": "vendor@globalparts-supply.com", "subject": "Updated bank account details for payments", "origin": "Accra, GH", "status": "INVESTIGATING", "analyst_id": "user-analyst-001", "analyst_name": "Raj Kumar", "analyst_email": "analyst@mailtrace.ai", "email_analysis_id": None, "evidence_ids": [], "ioc_ids": [], "campaign_id": None, "notes": []},
    {"_id": "MT-2026-00113", "case_id": "MT-2026-00113", "title": "PayPal Impersonation", "classification": "Credential Phishing", "risk_score": 88, "severity": "CRITICAL", "sender": "noreply@paypa1-secure.com", "subject": "Unusual activity on your PayPal account", "origin": "Minsk, BY", "status": "RESOLVED", "analyst_id": "user-senior-001", "analyst_name": "Sarah Kim", "analyst_email": "senior@mailtrace.ai", "email_analysis_id": None, "evidence_ids": [], "ioc_ids": [], "campaign_id": "campaign-002", "notes": []},
]

DEMO_IOCS = [
    {"_id": str(uuid.uuid4()), "type": "domain", "value": "micros0ft-secure.com", "reputation": "malicious", "risk_level": "critical", "first_seen": datetime.now(timezone.utc) - timedelta(days=5), "last_seen": datetime.now(timezone.utc), "analysis_ids": ["analysis-demo-3"], "campaign_id": "campaign-001"},
    {"_id": str(uuid.uuid4()), "type": "ip", "value": "185.231.72.12", "reputation": "malicious", "risk_level": "critical", "first_seen": datetime.now(timezone.utc) - timedelta(days=5), "last_seen": datetime.now(timezone.utc), "analysis_ids": ["analysis-demo-3"], "campaign_id": "campaign-001"},
    {"_id": str(uuid.uuid4()), "type": "domain", "value": "microsOft-support.com", "reputation": "malicious", "risk_level": "critical", "first_seen": datetime.now(timezone.utc) - timedelta(days=3), "last_seen": datetime.now(timezone.utc), "analysis_ids": ["analysis-demo-2"], "campaign_id": "campaign-001"},
    {"_id": str(uuid.uuid4()), "type": "ip", "value": "91.108.4.1", "reputation": "suspicious", "risk_level": "high", "first_seen": datetime.now(timezone.utc) - timedelta(days=3), "last_seen": datetime.now(timezone.utc), "analysis_ids": ["analysis-demo-2"], "campaign_id": "campaign-001"},
    {"_id": str(uuid.uuid4()), "type": "domain", "value": "paypa1-alert.net", "reputation": "malicious", "risk_level": "critical", "first_seen": datetime.now(timezone.utc) - timedelta(days=10), "last_seen": datetime.now(timezone.utc), "analysis_ids": [], "campaign_id": "campaign-002"},
    {"_id": str(uuid.uuid4()), "type": "email", "value": "finance.verify@proton-example.com", "reputation": "suspicious", "risk_level": "high", "first_seen": datetime.now(timezone.utc) - timedelta(days=5), "last_seen": datetime.now(timezone.utc), "analysis_ids": ["analysis-demo-3"], "campaign_id": "campaign-001"},
    {"_id": str(uuid.uuid4()), "type": "url", "value": "https://payroll-verify.microsOft-support.com/login", "reputation": "malicious", "risk_level": "critical", "first_seen": datetime.now(timezone.utc) - timedelta(days=3), "last_seen": datetime.now(timezone.utc), "analysis_ids": ["analysis-demo-2"], "campaign_id": "campaign-001"},
]

DEMO_CAMPAIGNS = [
    {
        "_id": "campaign-001",
        "campaign_id": "campaign-001",
        "name": "Operation FakeMicrosoftBEC",
        "description": "Coordinated BEC and credential phishing campaign targeting corporate finance teams",
        "status": "active",
        "case_count": 6,
        "ioc_count": 12,
        "threat_actor": "Unknown",
        "infrastructure_countries": ["Singapore", "Germany", "Netherlands"],
        "created_at": datetime.now(timezone.utc) - timedelta(days=7),
        "last_activity": datetime.now(timezone.utc),
    },
    {
        "_id": "campaign-002",
        "campaign_id": "campaign-002",
        "name": "Southeast Asia Phishing Wave",
        "description": "Mass credential phishing targeting banking and financial services",
        "status": "active",
        "case_count": 4,
        "ioc_count": 8,
        "threat_actor": "Unknown",
        "infrastructure_countries": ["Bulgaria", "Belarus", "Ukraine"],
        "created_at": datetime.now(timezone.utc) - timedelta(days=14),
        "last_activity": datetime.now(timezone.utc) - timedelta(days=2),
    },
]

DEMO_AUDIT_LOGS = [
    {"_id": str(uuid.uuid4()), "timestamp": datetime.now(timezone.utc) - timedelta(hours=2), "user_id": "user-alex-001", "user_email": "alex@mailtrace.ai", "user_role": "SENIOR_ANALYST", "action": "Email analyzed (raw)", "resource": "email_analysis", "resource_id": "analysis-demo-3", "case_id": "MT-2026-00124", "ip_address": "10.20.30.41", "result": "Success", "details": {}},
    {"_id": str(uuid.uuid4()), "timestamp": datetime.now(timezone.utc) - timedelta(hours=2, minutes=3), "user_id": "user-alex-001", "user_email": "alex@mailtrace.ai", "user_role": "SENIOR_ANALYST", "action": "IOC viewed", "resource": "domain_intel", "resource_id": "micros0ft-secure.com", "case_id": "MT-2026-00124", "ip_address": "10.20.30.41", "result": "Success", "details": {}},
    {"_id": str(uuid.uuid4()), "timestamp": datetime.now(timezone.utc) - timedelta(hours=2, minutes=6), "user_id": "user-alex-001", "user_email": "alex@mailtrace.ai", "user_role": "SENIOR_ANALYST", "action": "Case created", "resource": "case", "resource_id": "MT-2026-00124", "case_id": "MT-2026-00124", "ip_address": "10.20.30.41", "result": "Success", "details": {}},
    {"_id": str(uuid.uuid4()), "timestamp": datetime.now(timezone.utc) - timedelta(hours=2, minutes=10), "user_id": "user-alex-001", "user_email": "alex@mailtrace.ai", "user_role": "SENIOR_ANALYST", "action": "Report generated", "resource": "report", "resource_id": str(uuid.uuid4()), "case_id": "MT-2026-00124", "ip_address": "10.20.30.41", "result": "Success", "details": {}},
    {"_id": str(uuid.uuid4()), "timestamp": datetime.now(timezone.utc) - timedelta(hours=3, minutes=30), "user_id": "user-alex-001", "user_email": "alex@mailtrace.ai", "user_role": "SENIOR_ANALYST", "action": "User login", "resource": None, "resource_id": None, "case_id": None, "ip_address": "10.20.30.41", "result": "Success", "details": {}},
    {"_id": str(uuid.uuid4()), "timestamp": datetime.now(timezone.utc) - timedelta(hours=4), "user_id": "user-senior-001", "user_email": "senior@mailtrace.ai", "user_role": "SENIOR_ANALYST", "action": "EML file uploaded and analyzed", "resource": "evidence", "resource_id": str(uuid.uuid4()), "case_id": "MT-2026-00122", "ip_address": "10.20.30.55", "result": "Success", "details": {"filename": "suspicious.eml"}},
    {"_id": str(uuid.uuid4()), "timestamp": datetime.now(timezone.utc) - timedelta(hours=5), "user_id": "user-analyst-001", "user_email": "analyst@mailtrace.ai", "user_role": "ANALYST", "action": "Case updated", "resource": "case", "resource_id": "MT-2026-00120", "case_id": "MT-2026-00120", "ip_address": "10.20.30.62", "result": "Success", "details": {"changes": ["status"]}},
    {"_id": str(uuid.uuid4()), "timestamp": datetime.now(timezone.utc) - timedelta(hours=8), "user_id": "user-admin-001", "user_email": "admin@mailtrace.ai", "user_role": "ADMINISTRATOR", "action": "User created", "resource": "user", "resource_id": "user-analyst-001", "case_id": None, "ip_address": "10.20.30.10", "result": "Success", "details": {"email": "analyst@mailtrace.ai", "role": "ANALYST"}},
]

# Pre-built analysis for demo emails (for dashboard display)
DEMO_ANALYSES = [
    {
        "_id": "analysis-demo-1",
        "analyst_id": "user-alex-001",
        "case_id": "MT-2026-00121",
        "is_demo": True,
        "demo_id": "demo-1",
        "created_at": datetime.now(timezone.utc) - timedelta(hours=6),
        "email_metadata": {
            "from_address": "security-noreply@microsoft.com",
            "to": ["user@acmecorp.com"],
            "subject": "Your Microsoft 365 security summary",
            "date": "Mon, 26 Aug 2026 09:00:00 +0000",
            "message_id": "<secure-summary-83721@microsoft.com>",
            "reply_to": "",
            "return_path": "",
            "x_originating_ip": "",
            "mailer": "Microsoft Exchange Server 2019",
            "raw_headers": "",
            "body_text": "Your account is secure. No action required.",
        },
        "auth": {"spf": "pass", "spf_detail": "SPF check result: PASS for microsoft.com", "dkim": "pass", "dkim_detail": "DKIM signature verification: PASS", "dmarc": "pass", "dmarc_detail": "DMARC policy evaluation: PASS", "reply_to_mismatch": False, "reply_to_mismatch_detail": ""},
        "overall_risk_score": 7,
        "risk_level": "SAFE",
        "classification": "Legitimate",
        "classification_scores": {"phishing": 0, "bec": 0, "impersonation": 0, "credential_theft": 0, "malware_delivery": 0},
        "scoring_breakdown": {"nlp_phishing": 5, "authentication": 0, "domain_risk": 5, "url_analysis": 5, "infrastructure_reputation": 5, "header_anomalies": 0, "attachment_risk": 0},
        "social_engineering": {"urgency": 0, "authority": 0, "financial_request": 0, "credential_request": 0, "executive_impersonation": 0, "fear_induction": 0, "confidentiality_pressure": 0},
        "risk_indicators": [],
        "iocs": [{"id": str(uuid.uuid4()), "type": "domain", "indicator": "microsoft.com", "reputation": "clean", "risk_level": "low", "source": "email_body", "related_cases": []}],
        "url_analysis": [],
        "relay_path": [{"hop_number": 1, "ip": "40.107.8.66", "hostname": "mail-eopbgr80066.outbound.protection.outlook.com", "timestamp": "Mon, 26 Aug 2026 09:00:01 +0000", "location": "Dublin, Ireland", "label": "Microsoft Exchange", "confidence": "trusted", "notes": ""}],
        "attachments": [],
        "explainable_ai": "This email was classified as **Legitimate** with a risk score of **7/100**.\n\nAll authentication checks (SPF, DKIM, DMARC) passed. The email originated from Microsoft's legitimate mail infrastructure. No social engineering signals, suspicious URLs, or malicious domains were detected.",
        "evidence_hash": "a" * 64,
        "analysis_timestamp": (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat(),
    },
    {
        "_id": "analysis-demo-3",
        "analyst_id": "user-alex-001",
        "case_id": "MT-2026-00124",
        "is_demo": True,
        "demo_id": "demo-3",
        "created_at": datetime.now(timezone.utc) - timedelta(hours=2),
        "email_metadata": {
            "from_address": "ceo@micros0ft-secure.com",
            "to": ["finance@acmecorp.com"],
            "subject": "Urgent Vendor Payment Approval",
            "date": "Mon, 26 Aug 2026 11:30:00 +0000",
            "message_id": "<ceo-payment-112@micros0ft-secure.com>",
            "reply_to": "finance.verify@proton-example.com",
            "return_path": "bounce@sendgrid-relay.net",
            "x_originating_ip": "185.231.72.12",
            "mailer": "",
            "raw_headers": "",
            "body_text": "Hi Sarah, I need you to process an urgent vendor payment today before 3 PM...",
        },
        "auth": {"spf": "fail", "spf_detail": "SPF check result: FAIL for micros0ft-secure.com", "dkim": "fail", "dkim_detail": "DKIM signature verification: FAIL", "dmarc": "fail", "dmarc_detail": "DMARC policy evaluation: FAIL", "reply_to_mismatch": True, "reply_to_mismatch_detail": "From domain (micros0ft-secure.com) does not match Reply-To domain (proton-example.com). Replies will go to finance.verify@proton-example.com."},
        "overall_risk_score": 94,
        "risk_level": "CRITICAL",
        "classification": "Business Email Compromise",
        "classification_scores": {"phishing": 70, "bec": 95, "impersonation": 91, "credential_theft": 20, "malware_delivery": 0},
        "scoring_breakdown": {"nlp_phishing": 80, "authentication": 100, "domain_risk": 91, "url_analysis": 30, "infrastructure_reputation": 75, "header_anomalies": 70, "attachment_risk": 0},
        "social_engineering": {"urgency": 80, "authority": 75, "financial_request": 95, "credential_request": 0, "executive_impersonation": 90, "fear_induction": 40, "confidentiality_pressure": 85},
        "risk_indicators": [
            {"id": str(uuid.uuid4()), "label": "Lookalike domain detected — 91% similar to microsoft.com", "severity": "critical", "category": "domain_spoofing"},
            {"id": str(uuid.uuid4()), "label": "SPF check failed — sender not authorized", "severity": "high", "category": "authentication"},
            {"id": str(uuid.uuid4()), "label": "DKIM signature invalid or missing", "severity": "high", "category": "authentication"},
            {"id": str(uuid.uuid4()), "label": "DMARC policy violation detected", "severity": "critical", "category": "authentication"},
            {"id": str(uuid.uuid4()), "label": "Reply-To domain mismatch — replies diverted", "severity": "high", "category": "authentication"},
            {"id": str(uuid.uuid4()), "label": "financial_request detected", "severity": "high", "category": "financial_request"},
            {"id": str(uuid.uuid4()), "label": "executive_impersonation detected", "severity": "high", "category": "executive_impersonation"},
            {"id": str(uuid.uuid4()), "label": "urgency detected", "severity": "medium", "category": "urgency"},
            {"id": str(uuid.uuid4()), "label": "confidentiality_pressure detected", "severity": "medium", "category": "confidentiality_pressure"},
        ],
        "iocs": [
            {"id": str(uuid.uuid4()), "type": "domain", "indicator": "micros0ft-secure.com", "reputation": "malicious", "risk_level": "critical", "source": "email_header", "related_cases": ["MT-2026-00124"]},
            {"id": str(uuid.uuid4()), "type": "ip", "indicator": "185.231.72.12", "reputation": "malicious", "risk_level": "critical", "source": "email_header", "related_cases": ["MT-2026-00124"]},
            {"id": str(uuid.uuid4()), "type": "email", "indicator": "finance.verify@proton-example.com", "reputation": "suspicious", "risk_level": "high", "source": "email_header", "related_cases": ["MT-2026-00124"]},
            {"id": str(uuid.uuid4()), "type": "domain", "indicator": "proton-example.com", "reputation": "suspicious", "risk_level": "high", "source": "email_body", "related_cases": ["MT-2026-00124"]},
            {"id": str(uuid.uuid4()), "type": "domain", "indicator": "sendgrid-relay.net", "reputation": "suspicious", "risk_level": "medium", "source": "email_header", "related_cases": ["MT-2026-00124"]},
        ],
        "url_analysis": [],
        "relay_path": [
            {"hop_number": 1, "ip": "185.231.72.12", "hostname": "mail-sg1.sendgrid-relay.net", "timestamp": "Mon, 26 Aug 2026 11:28:00 +0000", "location": "Singapore", "label": "Origin Infrastructure", "confidence": "observed", "notes": ""},
            {"hop_number": 2, "ip": "185.231.72.50", "hostname": "origin.sg-infra.net", "timestamp": "Mon, 26 Aug 2026 11:27:45 +0000", "location": "Singapore", "label": "Relay 2", "confidence": "observed", "notes": ""},
            {"hop_number": 3, "ip": "", "hostname": "mx.acmecorp.com", "timestamp": "Mon, 26 Aug 2026 11:30:05 +0000", "location": "Mumbai, India", "label": "Recipient Mail Server", "confidence": "trusted", "notes": ""},
        ],
        "attachments": [],
        "explainable_ai": "This email was classified as **Business Email Compromise** with a risk score of **94/100**.\n\n**Key factors contributing to this score:**\n• Lookalike domain detected — 91% similar to microsoft.com (Severity: CRITICAL)\n• SPF check failed — sender not authorized (Severity: HIGH)\n• DKIM signature invalid or missing (Severity: HIGH)\n• DMARC policy violation detected (Severity: CRITICAL)\n• Reply-To domain mismatch — replies diverted (Severity: HIGH)\n\n**Authentication failures** were a major factor (100/100 contribution), indicating the email did not originate from an authorized server.\n\n**Domain risk analysis** (91/100) detected the sender domain resembles a well-known brand (microsoft.com), which is a hallmark of impersonation attacks. The domain 'micros0ft-secure.com' uses a zero (0) in place of the letter 'o' — a classic character substitution attack.\n\n**Social engineering signals** (80/100) were detected including urgency (wire payment before 3 PM), executive impersonation (CEO persona), financial pressure (USD 87,500 wire transfer), and confidentiality pressure (do not discuss with anyone).\n\n**Recommendation:** Quarantine this email immediately, block the sending domain and IP, and alert the intended recipient.",
        "evidence_hash": "b" * 64,
        "analysis_timestamp": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
    },
]

DEMO_SYSTEM_SETTINGS = [
    {"_id": "evidence_retention_days", "value": 90, "updated_by": "user-admin-001", "updated_at": datetime.now(timezone.utc)},
    {"_id": "max_upload_size_mb", "value": 10, "updated_by": "user-admin-001", "updated_at": datetime.now(timezone.utc)},
    {"_id": "require_mfa", "value": False, "updated_by": "user-admin-001", "updated_at": datetime.now(timezone.utc)},
    {"_id": "auto_create_case_threshold", "value": 75, "updated_by": "user-admin-001", "updated_at": datetime.now(timezone.utc)},
]


async def seed():
    from passlib.context import CryptContext
    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]

    print(f"🔗 Connected to MongoDB: {DB_NAME}")

    # ── Users ──────────────────────────────────────────────────────────────────
    for user in DEMO_USERS:
        if not await db.users.find_one({"email": user["email"]}):
            doc = {
                "_id": user["_id"],
                "name": user["name"],
                "email": user["email"],
                "password_hash": pwd_ctx.hash(user["password"]),
                "role": user["role"],
                "status": "active",
                "created_at": datetime.now(timezone.utc) - timedelta(days=30),
                "last_login": datetime.now(timezone.utc) - timedelta(hours=3),
            }
            await db.users.insert_one(doc)
            print(f"  ✅ User: {user['email']} / {user['password']} ({user['role']})")
        else:
            print(f"  ⏭️  User already exists: {user['email']}")

    # ── Cases ──────────────────────────────────────────────────────────────────
    for case in DEMO_CASES:
        doc = dict(case)
        doc["created_at"] = datetime.now(timezone.utc) - timedelta(days=1, hours=2)
        doc["updated_at"] = datetime.now(timezone.utc) - timedelta(hours=1)
        if not await db.cases.find_one({"_id": case["_id"]}):
            await db.cases.insert_one(doc)
    print(f"  ✅ Seeded {len(DEMO_CASES)} cases")

    # Set case counter
    await db.case_counter.update_one(
        {"_id": "global"}, {"$set": {"seq": 125}}, upsert=True
    )

    # ── Email analyses ─────────────────────────────────────────────────────────
    for analysis in DEMO_ANALYSES:
        if not await db.email_analyses.find_one({"_id": analysis["_id"]}):
            await db.email_analyses.insert_one(analysis)
    print(f"  ✅ Seeded {len(DEMO_ANALYSES)} email analyses")

    # ── IOCs ───────────────────────────────────────────────────────────────────
    for ioc in DEMO_IOCS:
        if not await db.iocs.find_one({"value": ioc["value"], "type": ioc["type"]}):
            await db.iocs.insert_one(ioc)
    print(f"  ✅ Seeded {len(DEMO_IOCS)} IOCs")

    # ── Campaigns ──────────────────────────────────────────────────────────────
    for campaign in DEMO_CAMPAIGNS:
        if not await db.campaigns.find_one({"_id": campaign["_id"]}):
            await db.campaigns.insert_one(campaign)
    print(f"  ✅ Seeded {len(DEMO_CAMPAIGNS)} campaigns")

    # ── Audit Logs ─────────────────────────────────────────────────────────────
    count = await db.audit_logs.count_documents({})
    if count < 5:
        await db.audit_logs.insert_many(DEMO_AUDIT_LOGS)
        print(f"  ✅ Seeded {len(DEMO_AUDIT_LOGS)} audit logs")

    # ── System settings ────────────────────────────────────────────────────────
    for setting in DEMO_SYSTEM_SETTINGS:
        await db.system_settings.update_one(
            {"_id": setting["_id"]}, {"$set": setting}, upsert=True
        )
    print(f"  ✅ Seeded {len(DEMO_SYSTEM_SETTINGS)} system settings")

    # ── Indexes ────────────────────────────────────────────────────────────────
    await db.users.create_index([("email", 1)], unique=True)
    await db.cases.create_index([("case_id", 1)], unique=True)
    await db.cases.create_index([("created_at", -1)])
    await db.email_analyses.create_index([("created_at", -1)])
    await db.iocs.create_index([("value", 1), ("type", 1)])
    await db.audit_logs.create_index([("timestamp", -1)])
    print("  ✅ MongoDB indexes created")

    client.close()
    print("\n🎉 Seed complete! MailTrace AI database is ready.")
    print("\n📧 Demo credentials:")
    for u in DEMO_USERS:
        print(f"   {u['email']} / {u['password']} ({u['role']})")


if __name__ == "__main__":
    asyncio.run(seed())
