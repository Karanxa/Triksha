"""
Black Hat India Arsenal demo registration: token issue only (the tool has its own login).

/demo/register emails a time-boxed token (proof of address); /demo/session validates it.
Env: DATABASE_URL (else sqlite DEMO_DB_PATH), RESEND_API_KEY, DEMO_FROM_EMAIL,
     DEMO_TOKEN_TTL_SECONDS, DEMO_ADMIN_KEY.
"""
import hashlib
import html
import os
import secrets
import sqlite3
import time
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field

router = APIRouter(prefix="/demo", tags=["Demo"])

TOKEN_TTL = int(os.getenv("DEMO_TOKEN_TTL_SECONDS", "3600"))
RESEND_COOLDOWN = 60

# ── storage (Postgres via DATABASE_URL, else sqlite) ──────────────────────────
_DB_URL = os.getenv("DATABASE_URL", "")
_PG = _DB_URL.startswith(("postgres://", "postgresql://"))
_SQLITE_PATH = os.getenv("DEMO_DB_PATH", "./triksha-demo.db")

_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS demo_visitors (
        email TEXT PRIMARY KEY, name TEXT, company TEXT, job_title TEXT,
        phone TEXT, country TEXT, interest TEXT, marketing_consent INTEGER,
        verify_hash TEXT, verify_expires BIGINT, verified_at BIGINT,
        last_verify_sent BIGINT, ip TEXT, user_agent TEXT, referrer TEXT,
        created_at BIGINT, updated_at BIGINT)""",
    """CREATE TABLE IF NOT EXISTS demo_tokens (
        token_hash TEXT PRIMARY KEY, email TEXT, expires_at BIGINT,
        created_at BIGINT)""",
]
_ready = False


def _conn():
    if _PG:
        import psycopg2
        return psycopg2.connect(_DB_URL)
    return sqlite3.connect(_SQLITE_PATH, timeout=5.0)


def _run(sql: str, params: tuple = (), fetch: str = "") -> Any:
    """Execute one statement; fetch is '', 'one' or 'all' (rows as dicts)."""
    global _ready
    c = _conn()
    try:
        cur = c.cursor()
        if not _ready:
            for ddl in _SCHEMA:
                cur.execute(ddl)
            _ready = True
        cur.execute(sql.replace("?", "%s") if _PG else sql, params)
        out = None
        if fetch:
            cols = [d[0] for d in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
            out = rows[0] if fetch == "one" and rows else (None if fetch == "one" else rows)
        c.commit()
        return out
    finally:
        c.close()


def _hash(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# ── email ─────────────────────────────────────────────────────────────────────
async def _send_email(to: str, subject: str, html: str) -> None:
    key = os.getenv("RESEND_API_KEY", "")
    if not key:
        raise HTTPException(503, "Email delivery is not configured")
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {key}"},
            json={"from": os.getenv("DEMO_FROM_EMAIL", ""), "to": [to],
                  "subject": subject, "html": html},
        )
    if r.status_code >= 300:
        raise HTTPException(502, "Could not send verification email")


# ── models ────────────────────────────────────────────────────────────────────
class RegisterBody(BaseModel):
    email: EmailStr
    name: str = Field(..., min_length=1, max_length=120)
    company: str = Field(..., min_length=1, max_length=160)
    job_title: Optional[str] = Field(None, max_length=120)
    phone: Optional[str] = Field(None, max_length=40)
    country: Optional[str] = Field(None, max_length=80)
    interest: Optional[str] = Field(None, max_length=500)
    marketing_consent: bool = False


# ── auth ──────────────────────────────────────────────────────────────────────
def _session(token: Optional[str]) -> dict:
    if not token:
        raise HTTPException(401, "Demo token required")
    row = _run("SELECT * FROM demo_tokens WHERE token_hash = ?", (_hash(token),), "one")
    if not row or row["expires_at"] < time.time():
        raise HTTPException(401, "Token invalid or expired")
    return row


# ── routes ────────────────────────────────────────────────────────────────────
@router.post("/register")
async def register(body: RegisterBody, request: Request):
    email = body.email.lower()
    now = int(time.time())
    existing = _run("SELECT last_verify_sent FROM demo_visitors WHERE email = ?", (email,), "one")
    if existing and existing["last_verify_sent"] and now - existing["last_verify_sent"] < RESEND_COOLDOWN:
        raise HTTPException(429, "Verification email already sent. Please wait a minute.")

    # The token itself is emailed (never returned here), so receiving it proves ownership of the address.
    token = secrets.token_urlsafe(24)
    ip = (request.headers.get("x-forwarded-for") or (request.client.host if request.client else "")).split(",")[0].strip()
    vals = (body.name, body.company, body.job_title, body.phone, body.country, body.interest,
            int(body.marketing_consent), now, now, ip,
            request.headers.get("user-agent", "")[:300], request.headers.get("referer", "")[:300], now)
    if existing:
        _run("""UPDATE demo_visitors SET name=?, company=?, job_title=?, phone=?, country=?,
                interest=?, marketing_consent=?, verified_at=?, last_verify_sent=?, ip=?,
                user_agent=?, referrer=?, updated_at=? WHERE email=?""",
             vals + (email,))
    else:
        _run("""INSERT INTO demo_visitors (email, name, company, job_title, phone, country,
                interest, marketing_consent, verified_at, last_verify_sent,
                ip, user_agent, referrer, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
             (email,) + vals + (now,))
    _run("INSERT INTO demo_tokens (token_hash, email, expires_at, created_at) VALUES (?,?,?,?)",
         (_hash(token), email, now + TOKEN_TTL, now))

    name = html.escape(body.name)
    await _send_email(email, "Your Triksha access token",
                      f"<div style=\"font-family:system-ui,sans-serif;max-width:480px;margin:auto;padding:24px\">"
                      f"<h2 style=\"margin:0 0 12px\">Hi {name},</h2>"
                      f"<p>Thanks for stopping by Triksha at Black Hat India Arsenal. Here's your access token:</p>"
                      f"<p style=\"margin:20px 0;padding:14px 16px;background:#f3f4f6;border-radius:8px;"
                      f"font-family:ui-monospace,Menlo,monospace;font-size:15px;word-break:break-all\">{token}</p>"
                      f"<p>Paste it on the Triksha page to start. It's valid for {TOKEN_TTL // 60} minutes and includes one scan.</p>"
                      f"<p style=\"color:#666;font-size:13px\">You're also on the open-source contributor waitlist. "
                      f"If you didn't sign up, ignore this email.</p></div>")
    return {"status": "token_sent"}


@router.get("/session")
async def session(x_demo_token: Optional[str] = Header(None)):
    s = _session(x_demo_token)
    return {"email": s["email"], "expires_at": s["expires_at"]}


@router.get("/admin/visitors")
async def export_visitors(x_api_key: Optional[str] = Header(None)):
    key = os.getenv("DEMO_ADMIN_KEY", "").strip()
    if not key or not x_api_key or not secrets.compare_digest(x_api_key.strip(), key):
        raise HTTPException(401, "Unauthorized")
    return _run("""SELECT email, name, company, job_title, phone, country, interest,
                   marketing_consent, verified_at, created_at FROM demo_visitors
                   ORDER BY created_at DESC""", (), "all")
