from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, DESCENDING
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

client: AsyncIOMotorClient = None
db = None


async def connect_db():
    global client, db
    client = AsyncIOMotorClient(settings.MONGODB_URI)
    db = client[settings.MONGODB_DB_NAME]
    await create_indexes()
    logger.info(f"Connected to MongoDB: {settings.MONGODB_DB_NAME}")


async def close_db():
    global client
    if client:
        client.close()
        logger.info("MongoDB connection closed")


async def create_indexes():
    # Users
    await db.users.create_index([("email", ASCENDING)], unique=True)
    # Cases
    await db.cases.create_index([("case_id", ASCENDING)], unique=True)
    await db.cases.create_index([("status", ASCENDING)])
    await db.cases.create_index([("created_at", DESCENDING)])
    await db.cases.create_index([("analyst_id", ASCENDING)])
    # Email analyses
    await db.email_analyses.create_index([("case_id", ASCENDING)])
    await db.email_analyses.create_index([("created_at", DESCENDING)])
    # IOCs
    await db.iocs.create_index([("value", ASCENDING)])
    await db.iocs.create_index([("type", ASCENDING)])
    await db.iocs.create_index([("case_ids", ASCENDING)])
    # Audit logs
    await db.audit_logs.create_index([("timestamp", DESCENDING)])
    await db.audit_logs.create_index([("user_id", ASCENDING)])
    await db.audit_logs.create_index([("case_id", ASCENDING)])
    # Campaigns
    await db.campaigns.create_index([("campaign_id", ASCENDING)], unique=True)
    # Reports
    await db.reports.create_index([("case_id", ASCENDING)])
    await db.reports.create_index([("created_at", DESCENDING)])
    # Evidence
    await db.evidence.create_index([("sha256", ASCENDING)])
    await db.evidence.create_index([("case_id", ASCENDING)])
    # Notifications
    await db.notifications.create_index([("user_id", ASCENDING), ("read", ASCENDING)])
    logger.info("MongoDB indexes created")


def get_db():
    return db
