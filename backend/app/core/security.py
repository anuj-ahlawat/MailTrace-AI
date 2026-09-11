from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Request
from app.core.config import settings
from app.core.database import get_db
import logging

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except JWTError:
        return None


async def get_current_user(request: Request):
    """Extract user from Authorization header or cookie."""
    token = None

    # Try Authorization header first
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]

    # Fallback to cookie
    if not token:
        token = request.cookies.get("mt_token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    db = get_db()
    from bson import ObjectId
    user_id = payload.get("sub")
    user = None

    # Try string _id first (seeded demo users use string IDs like 'user-admin-001')
    user = await db.users.find_one({"_id": user_id})

    # Fall back to ObjectId _id (dynamically created users)
    if not user:
        try:
            user = await db.users.find_one({"_id": ObjectId(user_id)})
        except Exception:
            pass

    if not user or user.get("status") != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return user


def require_role(*roles: str):
    """Factory that returns a dependency requiring specific roles."""
    async def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user.get("role") not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {', '.join(roles)}",
            )
        return current_user
    return role_checker


# Convenience role dependencies
require_analyst = require_role("ANALYST", "SENIOR_ANALYST", "ADMINISTRATOR")
require_senior = require_role("SENIOR_ANALYST", "ADMINISTRATOR")
require_admin = require_role("ADMINISTRATOR")
