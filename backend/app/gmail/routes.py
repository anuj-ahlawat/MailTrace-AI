"""Gmail OAuth 2.0 integration."""
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import RedirectResponse
from datetime import datetime, timezone
from app.core.database import get_db
from app.core.config import settings
from app.core.security import get_current_user, require_analyst
from app.services.audit import log_event
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="", tags=["Gmail"])

GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


@router.get("/auth/gmail")
async def gmail_auth(request: Request, current_user: dict = Depends(require_analyst)):
    """Initiate Gmail OAuth flow."""
    if not settings.gmail_enabled:
        raise HTTPException(status_code=503, detail={
            "error": "gmail_not_configured",
            "message": "Gmail OAuth is not configured. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to .env",
            "demo_mode": True,
        })

    from google_auth_oauthlib.flow import Flow
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "redirect_uris": [settings.GOOGLE_REDIRECT_URI],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=GMAIL_SCOPES,
    )
    flow.redirect_uri = settings.GOOGLE_REDIRECT_URI

    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        state=str(current_user["_id"]),
    )
    return {"auth_url": auth_url}


@router.get("/auth/gmail/callback")
async def gmail_callback(code: str, state: str, request: Request):
    """Handle OAuth callback, store token."""
    if not settings.gmail_enabled:
        return RedirectResponse("/gmail-inbox?error=not_configured")

    try:
        from google_auth_oauthlib.flow import Flow
        from bson import ObjectId

        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "redirect_uris": [settings.GOOGLE_REDIRECT_URI],
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            },
            scopes=GMAIL_SCOPES,
            state=state,
        )
        flow.redirect_uri = settings.GOOGLE_REDIRECT_URI
        flow.fetch_token(code=code)

        credentials = flow.credentials
        db = get_db()
        user = await db.users.find_one({"_id": ObjectId(state)})

        await db.gmail_connections.update_one(
            {"user_id": state},
            {"$set": {
                "user_id": state,
                "token": credentials.token,
                "refresh_token": credentials.refresh_token,
                "token_uri": credentials.token_uri,
                "client_id": credentials.client_id,
                "client_secret": credentials.client_secret,
                "scopes": list(credentials.scopes or GMAIL_SCOPES),
                "connected_at": datetime.now(timezone.utc),
                "status": "connected",
            }},
            upsert=True,
        )

        if user:
            await log_event("Gmail connected", user=user, request=request)

        return RedirectResponse("http://localhost:3000/gmail-inbox?connected=true")
    except Exception as e:
        logger.error(f"Gmail OAuth callback error: {e}")
        return RedirectResponse(f"http://localhost:3000/gmail-inbox?error={str(e)[:50]}")


@router.get("/gmail/status")
async def gmail_status(current_user: dict = Depends(require_analyst)):
    db = get_db()
    user_id = str(current_user["_id"])
    connection = await db.gmail_connections.find_one({"user_id": user_id})

    if not settings.gmail_enabled:
        return {
            "connected": False,
            "demo_mode": True,
            "message": "Gmail not configured — showing demo inbox",
        }

    return {
        "connected": bool(connection and connection.get("status") == "connected"),
        "email": connection.get("email", "") if connection else "",
        "connected_at": connection.get("connected_at").isoformat() if connection and connection.get("connected_at") else None,
        "demo_mode": False,
    }


@router.get("/gmail/emails")
async def list_gmail_emails(
    max_results: int = 20,
    current_user: dict = Depends(require_analyst),
):
    """List Gmail inbox emails. Falls back to demo inbox if not configured."""
    if not settings.gmail_enabled:
        # Return demo inbox
        return _demo_gmail_inbox()

    db = get_db()
    user_id = str(current_user["_id"])
    connection = await db.gmail_connections.find_one({"user_id": user_id})

    if not connection or connection.get("status") != "connected":
        return _demo_gmail_inbox()

    try:
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build

        creds = Credentials(
            token=connection["token"],
            refresh_token=connection.get("refresh_token"),
            token_uri=connection.get("token_uri", "https://oauth2.googleapis.com/token"),
            client_id=connection.get("client_id"),
            client_secret=connection.get("client_secret"),
            scopes=connection.get("scopes", GMAIL_SCOPES),
        )
        service = build("gmail", "v1", credentials=creds)
        results = service.users().messages().list(userId="me", maxResults=max_results).execute()
        messages = results.get("messages", [])

        emails = []
        for msg in messages[:max_results]:
            msg_detail = service.users().messages().get(userId="me", id=msg["id"], format="metadata").execute()
            headers = {h["name"].lower(): h["value"] for h in msg_detail.get("payload", {}).get("headers", [])}
            emails.append({
                "id": msg["id"],
                "from": headers.get("from", ""),
                "subject": headers.get("subject", "(No Subject)"),
                "date": headers.get("date", ""),
                "snippet": msg_detail.get("snippet", ""),
                "is_read": "UNREAD" not in msg_detail.get("labelIds", []),
                "source": "gmail_live",
            })
        return {"emails": emails, "demo_mode": False}
    except Exception as e:
        logger.error(f"Gmail list error: {e}")
        return _demo_gmail_inbox()


@router.get("/gmail/emails/{message_id}")
async def get_gmail_email(
    message_id: str,
    current_user: dict = Depends(require_analyst),
):
    if not settings.gmail_enabled:
        raise HTTPException(status_code=503, detail="Gmail not configured")

    db = get_db()
    user_id = str(current_user["_id"])
    connection = await db.gmail_connections.find_one({"user_id": user_id})
    if not connection:
        raise HTTPException(status_code=400, detail="Gmail not connected")

    try:
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build
        import base64

        creds = Credentials(
            token=connection["token"],
            refresh_token=connection.get("refresh_token"),
            token_uri=connection.get("token_uri", "https://oauth2.googleapis.com/token"),
            client_id=connection.get("client_id"),
            client_secret=connection.get("client_secret"),
            scopes=connection.get("scopes", GMAIL_SCOPES),
        )
        service = build("gmail", "v1", credentials=creds)
        msg = service.users().messages().get(userId="me", id=message_id, format="raw").execute()
        raw = base64.urlsafe_b64decode(msg["raw"]).decode("utf-8", errors="replace")
        return {"id": message_id, "raw": raw, "source": "gmail_live"}
    except Exception as e:
        logger.error(f"Gmail get message error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/gmail/emails/{message_id}/analyze")
async def analyze_gmail_email(
    message_id: str,
    request: Request,
    current_user: dict = Depends(require_analyst),
):
    """Fetch and analyze a Gmail message through the same pipeline."""
    from app.api.emails import run_full_analysis, _serialize_analysis

    email_data = await get_gmail_email(message_id, current_user)
    raw = email_data.get("raw", "")
    if not raw:
        raise HTTPException(status_code=400, detail="Could not retrieve email content")

    result = await run_full_analysis(raw_email=raw, analyst_id=str(current_user["_id"]))
    await log_event("Gmail email analyzed", user=current_user, request=request,
                    resource="email_analysis", resource_id=result["_id"],
                    details={"gmail_message_id": message_id})
    return _serialize_analysis(result)


@router.post("/gmail/disconnect")
async def disconnect_gmail(request: Request, current_user: dict = Depends(require_analyst)):
    db = get_db()
    user_id = str(current_user["_id"])
    await db.gmail_connections.delete_one({"user_id": user_id})
    await log_event("Gmail disconnected", user=current_user, request=request)
    return {"message": "Gmail disconnected"}


def _demo_gmail_inbox() -> dict:
    """Return a demo inbox for when Gmail is not configured."""
    return {
        "demo_mode": True,
        "message": "Gmail not configured — showing demo inbox. Add Google OAuth credentials to enable live Gmail.",
        "emails": [
            {
                "id": "demo-gmail-1",
                "from": "security-alerts@google.com",
                "subject": "New sign-in to your Google Account",
                "date": "Mon, 26 Aug 2026 09:00:00 +0000",
                "snippet": "We noticed a new sign-in to your Google Account...",
                "is_read": True,
                "risk_badge": None,
                "source": "demo",
            },
            {
                "id": "demo-gmail-2",
                "from": "payroll@microsOft-support.com",
                "subject": "ACTION REQUIRED: Verify your payroll account",
                "date": "Mon, 26 Aug 2026 10:15:00 +0000",
                "snippet": "Your payroll direct deposit must be verified within 24 hours...",
                "is_read": False,
                "risk_badge": "HIGH",
                "source": "demo",
            },
            {
                "id": "demo-gmail-3",
                "from": "ceo@micros0ft-secure.com",
                "subject": "Urgent Vendor Payment Approval",
                "date": "Mon, 26 Aug 2026 11:30:00 +0000",
                "snippet": "I need you to process an urgent vendor payment today...",
                "is_read": False,
                "risk_badge": "CRITICAL",
                "source": "demo",
            },
        ],
    }
