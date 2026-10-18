from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from ..config import get_settings
from ..security import (
    COOKIE_NAME,
    _user_from,
    admin_password_configured,
    admin_username,
    auth_configured,
    decode_token,
    issue_token,
    login_limiter,
    require_user,
    setup_required,
    verify_admin,
)
from ..services.account import SetupLocked, account
from ..services.mfa import mfa

router = APIRouter(prefix="/api/auth", tags=["auth"])
MFA_TOKEN_TTL = 300  # seconds to type the code after the password step


class LoginIn(BaseModel):
    username: str
    password: str


class SetupIn(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._@-]+$")
    password: str = Field(min_length=8, max_length=256)


class MfaLoginIn(BaseModel):
    mfa_token: str
    code: str = Field(min_length=6, max_length=20)


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=20)


class ReauthIn(BaseModel):
    password: str
    code: str = Field(min_length=6, max_length=20)


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _set_session(response: Response, username: str) -> None:
    s = get_settings()
    response.set_cookie(
        COOKIE_NAME, issue_token(username), max_age=s.session_hours * 3600, httponly=True,
        secure=s.cookie_secure, samesite="strict", path="/",
    )


@router.post("/login")
async def login(body: LoginIn, request: Request, response: Response) -> dict:
    client = _client(request)
    login_limiter.check(client)
    if not admin_password_configured():
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "No admin account yet. Create one on the setup page, or set NV_ADMIN_PASSWORD(_HASH).")
    if not verify_admin(body.username, body.password):
        login_limiter.fail(client)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    if mfa.enabled:
        # Password OK, but no session yet: hand out a short-lived token that only /mfa accepts.
        return {"mfa_required": True, "mfa_token": issue_token(body.username, purpose="mfa", ttl=MFA_TOKEN_TTL)}
    login_limiter.reset(client)
    _set_session(response, body.username)
    return {"user": body.username}


@router.post("/setup")
async def setup(body: SetupIn, request: Request, response: Response) -> dict:
    """First-run only: create the admin account and sign in. Locked once any admin exists."""
    login_limiter.check(_client(request))
    if not setup_required():
        raise HTTPException(status.HTTP_409_CONFLICT, "Setup is already complete - sign in instead")
    try:
        await account.create(body.username, body.password)
    except SetupLocked as e:
        raise HTTPException(status.HTTP_409_CONFLICT, "Setup is already complete - sign in instead") from e
    _set_session(response, body.username)
    return {"user": body.username}


@router.post("/mfa")
async def login_mfa(body: MfaLoginIn, request: Request, response: Response) -> dict:
    client = _client(request)
    login_limiter.check(client)
    username = decode_token(body.mfa_token, purpose="mfa")
    if not username:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign-in expired - enter your password again")
    if not await mfa.verify(body.code):
        login_limiter.fail(client)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid authentication code")
    login_limiter.reset(client)
    _set_session(response, username)
    return {"user": username}


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
        "setup_required": setup_required(),
        "mfa_enabled": mfa.enabled,
        "sso": bool(s.trusted_proxy_header) or s.auth_disabled,
    }


# --------------------------------------------------------------------------- #
# MFA management (requires a session)
# --------------------------------------------------------------------------- #
def _reauth(user: str, body: ReauthIn, request: Request) -> None:
    client = _client(request)
    login_limiter.check(client)
    if not verify_admin(admin_username(), body.password):
        login_limiter.fail(client)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Password is incorrect")


@router.get("/mfa/status")
async def mfa_status(_: str = Depends(require_user)) -> dict:
    return mfa.status()


@router.post("/mfa/setup")
async def mfa_setup(user: str = Depends(require_user)) -> dict:
    if mfa.status()["source"] == "database":
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is already enabled - disable it first to re-enroll")
    try:
        return await mfa.begin_setup(admin_username())
    except ValueError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e)) from e


@router.post("/mfa/enable")
async def mfa_enable(body: ReauthIn, request: Request, response: Response, user: str = Depends(require_user)) -> dict:
    _reauth(user, body, request)
    try:
        codes = await mfa.enable(body.code)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    _set_session(response, user)  # epoch changed: keep *this* browser signed in, log out the rest
    return {"recovery_codes": codes}


@router.post("/mfa/disable")
async def mfa_disable(body: ReauthIn, request: Request, response: Response, user: str = Depends(require_user)) -> dict:
    _reauth(user, body, request)
    if not await mfa.verify(body.code):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid authentication code")
    try:
        await mfa.disable()
    except ValueError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e)) from e
    _set_session(response, user)
    return {"ok": True}


@router.post("/mfa/recovery-codes")
async def mfa_recovery(body: ReauthIn, request: Request, user: str = Depends(require_user)) -> dict:
    _reauth(user, body, request)
    if not await mfa.verify(body.code):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid authentication code")
    try:
        return {"recovery_codes": await mfa.regenerate_recovery()}
    except ValueError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e)) from e
