"""
Demo gateway — email-verified, time-boxed access to a fixed set of Triksha scans.

Flow: /demo/register -> email link -> /demo/verify (issues 1h token)
      -> /demo/targets -> /demo/scan (one scan per token) -> poll /demo/scan/{id}

Visitors never supply targets; they are resolved server-side from demo_targets.json.
Scans are forwarded to this app's own API using TRIKSHA_API_KEY.
Env: DATABASE_URL (else sqlite DEMO_DB_PATH), RESEND_API_KEY, DEMO_FROM_EMAIL,
     DEMO_PUBLIC_URL, TRIKSHA_API_KEY, DEMO_DRY_RUN, DEMO_TOKEN_TTL_SECONDS,
     DEMO_INTERNAL_URL.
"""
import hashlib
import json
import os
import secrets
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field

router = APIRouter(prefix="/demo", tags=["Demo"])

TOKEN_TTL = int(os.getenv("DEMO_TOKEN_TTL_SECONDS", "3600"))
VERIFY_TTL = 24 * 3600
RESEND_COOLDOWN = 60
TARGETS_FILE = Path(os.getenv("DEMO_TARGETS_FILE", Path(__file__).parent / "demo_targets.json"))
SCAN_TYPES = ("llm", "agent", "mcp")

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
    """CREATE TABLE IF NOT EXISTS demo_scans (
        scan_id TEXT PRIMARY KEY, scan_type TEXT, target_id TEXT, email TEXT,
        token_hash TEXT, dry_run INTEGER, created_at BIGINT)""",
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


# ── targets ───────────────────────────────────────────────────────────────────
def _load_targets() -> list:
    return json.loads(TARGETS_FILE.read_text())["targets"]


def _target(scan_type: str, target_id: str) -> Dict[str, Any]:
    for t in _load_targets():
        if t["id"] == target_id and t["scan_type"] == scan_type and t.get("enabled", True):
            return t
    raise HTTPException(404, "Unknown target")


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


class VerifyBody(BaseModel):
    code: str


class ScanBody(BaseModel):
    scan_type: str
    target_id: str


# ── auth ──────────────────────────────────────────────────────────────────────
def _session(token: Optional[str]) -> Dict[str, Any]:
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

    code = secrets.token_urlsafe(32)
    ip = (request.headers.get("x-forwarded-for") or (request.client.host if request.client else "")).split(",")[0].strip()
    vals = (body.name, body.company, body.job_title, body.phone, body.country, body.interest,
            int(body.marketing_consent), _hash(code), now + VERIFY_TTL, now, ip,
            request.headers.get("user-agent", "")[:300], request.headers.get("referer", "")[:300], now)
    if existing:
        _run("""UPDATE demo_visitors SET name=?, company=?, job_title=?, phone=?, country=?,
                interest=?, marketing_consent=?, verify_hash=?, verify_expires=?,
                last_verify_sent=?, ip=?, user_agent=?, referrer=?, updated_at=? WHERE email=?""",
             vals + (email,))
    else:
        _run("""INSERT INTO demo_visitors (email, name, company, job_title, phone, country,
                interest, marketing_consent, verify_hash, verify_expires, last_verify_sent,
                ip, user_agent, referrer, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
             (email,) + vals + (now,))

    base = os.getenv("DEMO_PUBLIC_URL", "").rstrip("/")
    link = f"{base}/verify?code={code}"
    await _send_email(email, "Confirm your email to try Triksha",
                      f"<p>Hi {body.name.replace('<', '')},</p>"
                      f"<p><a href=\"{link}\">Confirm your email</a> to get your demo access token.</p>")
    return {"status": "verification_sent"}


@router.post("/verify")
async def verify(body: VerifyBody):
    row = _run("SELECT email, verify_expires FROM demo_visitors WHERE verify_hash = ?",
               (_hash(body.code),), "one")
    if not row or row["verify_expires"] < time.time():
        raise HTTPException(400, "Invalid or expired confirmation link")
    now = int(time.time())
    token = secrets.token_urlsafe(32)
    _run("UPDATE demo_visitors SET verified_at = ?, verify_hash = NULL, updated_at = ? WHERE email = ?",
         (now, now, row["email"]))
    _run("INSERT INTO demo_tokens (token_hash, email, expires_at, created_at) VALUES (?,?,?,?)",
         (_hash(token), row["email"], now + TOKEN_TTL, now))
    return {"token": token, "email": row["email"], "expires_at": now + TOKEN_TTL}


@router.get("/targets")
async def targets(x_demo_token: Optional[str] = Header(None)):
    _session(x_demo_token)
    return [{k: t[k] for k in ("id", "scan_type", "label", "description")}
            for t in _load_targets() if t.get("enabled", True)]


@router.post("/scan")
async def start_scan(body: ScanBody, x_demo_token: Optional[str] = Header(None)):
    sess = _session(x_demo_token)
    if body.scan_type not in SCAN_TYPES:
        raise HTTPException(400, "Unsupported scan type")
    if _run("SELECT scan_id FROM demo_scans WHERE token_hash = ?", (sess["token_hash"],), "one"):
        raise HTTPException(409, "This token has already been used for a scan")
    t = _target(body.scan_type, body.target_id)

    dry = os.getenv("DEMO_DRY_RUN", "").lower() == "true" or t.get("placeholder", False)
    if dry:
        scan_id = f"dry-{uuid.uuid4().hex[:12]}"
    else:
        scan_id = await _forward_start(body.scan_type, t["config"])
    _run("INSERT INTO demo_scans (scan_id, scan_type, target_id, email, token_hash, dry_run, created_at)"
         " VALUES (?,?,?,?,?,?,?)",
         (scan_id, body.scan_type, body.target_id, sess["email"], sess["token_hash"], int(dry), int(time.time())))
    return {"scan_id": scan_id, "scan_type": body.scan_type, "dry_run": dry}


@router.get("/scan/{scan_id}")
async def scan_status(scan_id: str, x_demo_token: Optional[str] = Header(None)):
    sess = _session(x_demo_token)
    s = _run("SELECT * FROM demo_scans WHERE scan_id = ? AND token_hash = ?",
             (scan_id, sess["token_hash"]), "one")
    if not s:
        raise HTTPException(404, "Scan not found")
    if s["dry_run"]:
        return _dry_status(s)
    return await _forward_status(s["scan_type"], scan_id)


@router.get("/admin/visitors")
async def export_visitors(x_api_key: Optional[str] = Header(None)):
    key = os.getenv("TRIKSHA_API_KEY", "").strip()
    if not key or not x_api_key or not secrets.compare_digest(x_api_key.strip(), key):
        raise HTTPException(401, "Unauthorized")
    return _run("""SELECT email, name, company, job_title, phone, country, interest,
                   marketing_consent, verified_at, created_at FROM demo_visitors
                   ORDER BY created_at DESC""", (), "all")


# ── forwarding to the internal API ────────────────────────────────────────────
def _internal() -> httpx.AsyncClient:
    key = os.getenv("TRIKSHA_API_KEY", "").strip()
    if not key:
        raise HTTPException(503, "Demo scanning is not configured")
    base = os.getenv("DEMO_INTERNAL_URL", f"http://127.0.0.1:{os.getenv('PORT', '8000')}")
    return httpx.AsyncClient(base_url=base, headers={"X-API-Key": key}, timeout=30)


async def _forward_start(scan_type: str, cfg: Dict[str, Any]) -> str:
    path = {"llm": "/scan", "agent": "/agents/scan", "mcp": "/mcp/scan"}[scan_type]
    payload = {"config_file": json.dumps(cfg), "file_name": "demo", "timeout": 60} if scan_type == "mcp" else cfg
    async with _internal() as c:
        r = await c.post(path, json=payload)
    if r.status_code >= 300:
        raise HTTPException(502, "Failed to start scan")
    return r.json()["scan_id"]


async def _forward_status(scan_type: str, scan_id: str) -> Dict[str, Any]:
    async with _internal() as c:
        if scan_type == "llm":
            st = (await c.get(f"/scan/{scan_id}/status")).json()
            out = {"status": st.get("status"), "progress": st, "results": None}
            if st.get("status") == "completed":
                out["results"] = (await c.get(f"/scan/{scan_id}/results")).json()
            return out
        path = f"/agents/scan/{scan_id}" if scan_type == "agent" else f"/mcp/scan/{scan_id}"
        data = (await c.get(path)).json()
        return {"status": data.get("status"), "progress": None, "results": data}


# ── dry run (placeholder targets / DEMO_DRY_RUN) ──────────────────────────────
def _dry_status(s: Dict[str, Any]) -> Dict[str, Any]:
    age = time.time() - s["created_at"]
    if age < 3:
        return {"status": "queued", "dry_run": True, "progress": None, "results": None}
    if age < 20:
        return {"status": "running", "dry_run": True,
                "progress": {"percent": int((age - 3) / 17 * 100)}, "results": None}
    return {"status": "completed", "dry_run": True, "progress": {"percent": 100},
            "results": {"note": "Simulated results — target not connected yet.",
                        "scan_type": s["scan_type"], "target_id": s["target_id"],
                        "findings": [{"title": "Sample finding", "severity": "high"}]}}
