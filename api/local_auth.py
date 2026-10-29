"""Local username/password authentication and session management."""
from __future__ import annotations

import os
import time
import json
import sqlite3
import logging
from typing import Optional

import jwt
import bcrypt
from fastapi import APIRouter, Body, HTTPException, Request, Response
from pydantic import BaseModel

logger = logging.getLogger(__name__)


# Password hashing via the bcrypt library directly (passlib's backend-detection
# probe is incompatible with bcrypt>=4). bcrypt only uses the first 72 bytes, so
# truncate explicitly to stay within its limit.
def _hash_password(password: str) -> str:
    pw = password.encode("utf-8")[:72]
    return bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        pw = password.encode("utf-8")[:72]
        return bcrypt.checkpw(pw, stored_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False

router = APIRouter()

_DB_PATH = os.environ.get("AUTH_DB_PATH", os.path.join(os.path.dirname(__file__), "triksha-auth.db"))
_SESSION_COOKIE = "triksha_session"
_SESSION_TTL = int(os.environ.get("SESSION_TTL_SECONDS", str(7 * 24 * 3600)))  # 7 days


def _secret() -> str:
    """Session-signing secret. Persisted so cookies survive restarts."""
    s = os.environ.get("SESSION_SECRET")
    if s:
        return s
    # derive a stable per-install secret stored in app_config
    val = get_config("__session_secret__")
    if not val:
        val = os.urandom(32).hex()
        set_config("__session_secret__", val)
    return val


# ── SQLite store ──────────────────────────────────────────────────────────────
def _conn():
    os.makedirs(os.path.dirname(_DB_PATH) or ".", exist_ok=True)
    c = sqlite3.connect(_DB_PATH, timeout=5.0)
    c.row_factory = sqlite3.Row
    # WAL persists at the DB-file level; busy_timeout is per-connection.
    try:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=5000")
    except sqlite3.OperationalError:
        pass
    return c


def init_store():
    with _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS app_config (
            key TEXT PRIMARY KEY, value TEXT)""")


def get_config(key: str) -> Optional[str]:
    try:
        with _conn() as c:
            row = c.execute("SELECT value FROM app_config WHERE key=?", (key,)).fetchone()
            return row["value"] if row else None
    except sqlite3.OperationalError:
        return None


def set_config(key: str, value: str):
    with _conn() as c:
        c.execute("INSERT INTO app_config(key,value) VALUES(?,?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def _user_count() -> int:
    try:
        with _conn() as c:
            return c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
    except sqlite3.OperationalError:
        return 0


def load_config_into_env():
    """Populate os.environ from app_config so llm_providers + integrations
    pick up user-supplied settings (without overriding explicit env vars)."""
    init_store()
    keys = ["LLM_PROVIDER", "LLM_MODEL", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
            "GEMINI_API_KEY", "JIRA_URL", "JIRA_API_URL", "GUARDRAIL_BASE_URL",
            "GUARDRAIL_TOKEN", "GHE_TOKEN", "GITHUB_TOKEN"]
    for k in keys:
        if not os.environ.get(k):
            v = get_config(k)
            if v:
                os.environ[k] = v


# ── Session helpers ─────────────────────────────────────────────────────────
def _issue_session(username: str, role: str) -> str:
    now = int(time.time())
    return jwt.encode({"sub": username, "role": role, "iat": now,
                       "exp": now + _SESSION_TTL}, _secret(), algorithm="HS256")


def verify_session(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, _secret(), algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


def session_from_request(request: Request) -> Optional[dict]:
    tok = request.cookies.get(_SESSION_COOKIE)
    return verify_session(tok) if tok else None


def _api_key() -> str:
    return os.environ.get("TRIKSHA_API_KEY", "").strip()


def session_from_bearer(authorization: Optional[str]) -> Optional[dict]:
    """Validate Authorization: Bearer — local session JWT or TRIKSHA_API_KEY."""
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    raw = authorization.split(" ", 1)[1].strip().strip('"').strip("'")
    sess = verify_session(raw)
    if sess:
        return sess
    key = _api_key()
    if key and raw == key:
        return {"sub": "api", "role": "admin"}
    return None


def session_from_api_key_header(request: Request) -> Optional[dict]:
    key = _api_key()
    if not key:
        return None
    provided = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
    if provided and provided.strip() == key:
        return {"sub": "api", "role": "admin"}
    return None


def resolve_session(request: Request) -> Optional[dict]:
    """Cookie session, Bearer JWT/API key, or X-API-Key — first match wins."""
    return (
        session_from_request(request)
        or session_from_bearer(request.headers.get("authorization"))
        or session_from_api_key_header(request)
    )


def auth_context_from_bearer(authorization: Optional[str]) -> dict:
    """Shape expected by legacy auth_ctx Depends helpers."""
    sess = session_from_bearer(authorization)
    if not sess:
        return {"token": None, "claims": {}}
    raw = authorization.split(" ", 1)[1].strip().strip('"').strip("'") if authorization else None
    return {"token": raw, "claims": sess}


# ── Endpoints ──────────────────────────────────────────────────────────────────
class SetupBody(BaseModel):
    username: str
    password: str
    llm_provider: str = "gemini"
    llm_api_key: str
    llm_model: Optional[str] = None


class LoginBody(BaseModel):
    username: str
    password: str


@router.get("/setup/status")
def setup_status():
    """Whether first-run setup is still needed (no users yet)."""
    return {"needs_setup": _user_count() == 0}


@router.post("/setup")
def setup(body: SetupBody = Body(...)):
    init_store()
    if _user_count() > 0:
        raise HTTPException(status_code=409, detail="Setup already completed.")
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    provider = body.llm_provider.lower()
    if provider not in ("openai", "anthropic", "gemini"):
        raise HTTPException(status_code=400, detail="Provider must be openai, anthropic, or gemini.")

    with _conn() as c:
        c.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                  (body.username, _hash_password(body.password), "admin"))
    set_config("LLM_PROVIDER", provider)
    key_var = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY",
               "gemini": "GEMINI_API_KEY"}[provider]
    set_config(key_var, body.llm_api_key)
    if body.llm_model:
        set_config("LLM_MODEL", body.llm_model)
    load_config_into_env()
    logger.info("Triksha setup complete — admin '%s', provider '%s'", body.username, provider)
    return {"status": "ok"}


@router.post("/auth/login")
def login(body: LoginBody = Body(...), response: Response = None):
    with _conn() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (body.username,)).fetchone()
    if not row or not _verify_password(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    token = _issue_session(row["username"], row["role"])
    response.set_cookie(_SESSION_COOKIE, token, httponly=True, samesite="lax",
                        max_age=_SESSION_TTL, path="/")
    exp = int(time.time()) + _SESSION_TTL
    return {"status": "ok", "access_token": token, "token_type": "Bearer", "expires_in": _SESSION_TTL,
            "user": {"id": row["username"], "name": row["username"],
            "email": row["username"], "role": row["role"], "token_exp": exp}}


@router.post("/auth/signup")
def signup(body: LoginBody = Body(...), response: Response = None):
    """Self-service registration."""
    init_store()
    if _user_count() == 0:
        raise HTTPException(status_code=409, detail="Run first-time setup before signing up.")
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    if not body.username.strip():
        raise HTTPException(status_code=400, detail="Username is required.")
    with _conn() as c:
        existing = c.execute("SELECT 1 FROM users WHERE username=?", (body.username,)).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="That username is already taken.")
        c.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                  (body.username, _hash_password(body.password), "admin"))
    token = _issue_session(body.username, "admin")
    response.set_cookie(_SESSION_COOKIE, token, httponly=True, samesite="lax",
                        max_age=_SESSION_TTL, path="/")
    logger.info("Triksha signup — new admin user '%s'", body.username)
    return {"status": "ok", "user": {"id": body.username, "name": body.username,
            "email": body.username, "role": "admin"}}


@router.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie(_SESSION_COOKIE, path="/")
    return {"status": "ok"}


@router.get("/auth/me")
def me(request: Request):
    sess = session_from_request(request)
    if not sess:
        raise HTTPException(status_code=401, detail="Not authenticated")
    exp = sess.get("exp")
    return {"user": {"id": sess["sub"], "name": sess["sub"], "email": sess["sub"],
                     "role": sess.get("role", "admin")},
            "token_exp": exp}
