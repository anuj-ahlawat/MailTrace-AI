"""Authentication routes."""
from fastapi import APIRouter, HTTPException, status, Depends, Response, Request
from datetime import datetime, timezone
from bson import ObjectId
from app.core.database import get_db
from app.core.security import (
    verify_password, create_access_token, get_current_user, hash_password
)
from app.schemas.schemas import LoginRequest, CreateUserRequest, UpdateUserRequest
from app.services.audit import log_event
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])


def serialize_user(user: dict) -> dict:
    return {
        "id": str(user["_id"]),
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "status": user["status"],
        "created_at": user.get("created_at", "").isoformat() if user.get("created_at") else None,
        "last_login": user.get("last_login", "").isoformat() if user.get("last_login") else None,
    }


@router.post("/login")
async def login(data: LoginRequest, response: Response, request: Request):
    db = get_db()
    user = await db.users.find_one({"email": data.email.lower()})
    if not user or not verify_password(data.password, user["password_hash"]):
        await log_event("Login failed", request=request, result="Failure",
                        details={"email": data.email})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid email or password")

    if user.get("status") != "active":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Account is inactive")

    # Update last login
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"last_login": datetime.now(timezone.utc)}}
    )

    token = create_access_token({"sub": str(user["_id"]), "role": user["role"]})

    # Set httpOnly cookie
    response.set_cookie(
        key="mt_token", value=token,
        httponly=True, samesite="lax",
        max_age=60 * 60 * 8,  # 8 hours
    )

    await log_event("User login", user=user, request=request, result="Success")

    return {"access_token": token, "token_type": "bearer", "user": serialize_user(user)}


@router.post("/logout")
async def logout(response: Response, request: Request,
                 current_user: dict = Depends(get_current_user)):
    response.delete_cookie("mt_token")
    await log_event("User logout", user=current_user, request=request)
    return {"message": "Logged out successfully"}


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return serialize_user(current_user)
