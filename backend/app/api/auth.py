from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel

from ..config import get_settings
from ..security import (
    COOKIE_NAME,
    _user_from,
    auth_configured,
    issue_token,
    login_limiter,
    verify_admin,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str
    password: str


@router.post("/login")
async def login(body: LoginIn, request: Request, response: Response) -> dict:
    s = get_settings()
    client = request.client.host if request.client else "unknown"
    login_limiter.check(client)
    if not (s.admin_password or s.admin_password_hash):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "No admin password configured. Set NV_ADMIN_PASSWORD or NV_ADMIN_PASSWORD_HASH.")
    if not verify_admin(body.username, body.password):
        login_limiter.fail(client)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    login_limiter.reset(client)
    response.set_cookie(
        COOKIE_NAME, issue_token(body.username), max_age=s.session_hours * 3600, httponly=True,
        secure=s.cookie_secure, samesite="strict", path="/",
    )
    return {"user": body.username}


@router.post("/logout")
async def logout(response: Response) -> dict:
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/me")
async def me(request: Request) -> dict:
    s = get_settings()
    return {
        "user": _user_from(request.headers, request.cookies),
        "auth_disabled": s.auth_disabled,
        "configured": auth_configured(),
    }
