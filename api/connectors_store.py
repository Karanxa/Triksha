"""
Connectors + Sandbox configuration store for Triksha.

Instance-global (single-tenant OSS): every authenticated admin shares the same
set of connectors and the same Sandbox setup. Secrets (API tokens, passwords)
are encrypted at rest with Fernet, keyed off the install's session secret, so the
SQLite file never holds plaintext credentials.

Tables (created in the same SQLite DB as local_auth):
  - connectors(id, type, name, config_json, secrets_enc, enabled,
               copilot_enabled, created_at, updated_at)
  - sandbox_config(id=1, config_json, secrets_enc, updated_at)

The endpoint layer (endpoints/connectors.py) decides which fields of a given
connector type are secret; this module just stores `config` (plaintext JSON) and
`secrets` (Fernet-encrypted JSON) blobs and returns redacted views to callers.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import sqlite3
import time
from typing import Any, Dict, List, Optional

from cryptography.fernet import Fernet, InvalidToken

import local_auth

logger = logging.getLogger(__name__)


# ── Encryption ────────────────────────────────────────────────────────────────
def _fernet() -> Fernet:
    """Fernet keyed off the install's stable session secret (32-byte SHA-256)."""
    secret = local_auth._secret()
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
    return Fernet(key)


def _encrypt(data: Dict[str, Any]) -> str:
    if not data:
        return ""
    return _fernet().encrypt(json.dumps(data).encode("utf-8")).decode("utf-8")


def _decrypt(token: Optional[str]) -> Dict[str, Any]:
    if not token:
        return {}
    try:
        return json.loads(_fernet().decrypt(token.encode("utf-8")).decode("utf-8"))
    except (InvalidToken, ValueError, TypeError):
        logger.warning("Failed to decrypt connector secrets (key rotated?)")
        return {}


# ── Schema ────────────────────────────────────────────────────────────────────
def init_store() -> None:
    local_auth.init_store()
    with local_auth._conn() as c:
        # `owner` is nullable and unused today (instance-global / shared). It is
        # carried now so per-user tenancy can be layered on later without a
        # migration rewrite (NULL == shared).
        c.execute("""CREATE TABLE IF NOT EXISTS connectors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            name TEXT NOT NULL,
            config_json TEXT NOT NULL DEFAULT '{}',
            secrets_enc TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            copilot_enabled INTEGER NOT NULL DEFAULT 0,
            owner TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS sandbox_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            config_json TEXT NOT NULL DEFAULT '{}',
            secrets_enc TEXT NOT NULL DEFAULT '',
            owner TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        # Migrate pre-existing installs that created these tables before `owner`.
        for table in ("connectors", "sandbox_config"):
            cols = {row["name"] for row in c.execute(f"PRAGMA table_info({table})")}
            if "owner" not in cols:
                c.execute(f"ALTER TABLE {table} ADD COLUMN owner TEXT")


# ── Serialization ─────────────────────────────────────────────────────────────
def _redact_secrets(secrets: Dict[str, Any]) -> Dict[str, bool]:
    """Never leak secret values to the UI — report which secret keys are set."""
    return {k: bool(v) for k, v in (secrets or {}).items()}


def _row_to_public(row: sqlite3.Row) -> Dict[str, Any]:
    secrets = _decrypt(row["secrets_enc"])
    return {
        "id": row["id"],
        "type": row["type"],
        "name": row["name"],
        "config": json.loads(row["config_json"] or "{}"),
        "secrets_set": _redact_secrets(secrets),
        "enabled": bool(row["enabled"]),
        "copilot_enabled": bool(row["copilot_enabled"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


# ── Connector CRUD ────────────────────────────────────────────────────────────
def list_connectors() -> List[Dict[str, Any]]:
    init_store()
    with local_auth._conn() as c:
        rows = c.execute("SELECT * FROM connectors ORDER BY type, name").fetchall()
    return [_row_to_public(r) for r in rows]


def get_connector(cid: int, include_secrets: bool = False) -> Optional[Dict[str, Any]]:
    init_store()
    with local_auth._conn() as c:
        row = c.execute("SELECT * FROM connectors WHERE id=?", (cid,)).fetchone()
    if not row:
        return None
    public = _row_to_public(row)
    if include_secrets:
        public["secrets"] = _decrypt(row["secrets_enc"])
    return public


def get_connectors_by_type(ctype: str, enabled_only: bool = True,
                           include_secrets: bool = False) -> List[Dict[str, Any]]:
    init_store()
    q = "SELECT * FROM connectors WHERE type=?"
    args: List[Any] = [ctype]
    if enabled_only:
        q += " AND enabled=1"
    with local_auth._conn() as c:
        rows = c.execute(q, args).fetchall()
    out = []
    for r in rows:
        pub = _row_to_public(r)
        if include_secrets:
            pub["secrets"] = _decrypt(r["secrets_enc"])
        out.append(pub)
    return out


def get_copilot_connectors(include_secrets: bool = True) -> List[Dict[str, Any]]:
    """All enabled connectors flagged for use by the Copilot."""
    init_store()
    with local_auth._conn() as c:
        rows = c.execute(
            "SELECT * FROM connectors WHERE enabled=1 AND copilot_enabled=1 ORDER BY type"
        ).fetchall()
    out = []
    for r in rows:
        pub = _row_to_public(r)
        if include_secrets:
            pub["secrets"] = _decrypt(r["secrets_enc"])
        out.append(pub)
    return out


def create_connector(ctype: str, name: str, config: Dict[str, Any],
                     secrets: Dict[str, Any], enabled: bool = True,
                     copilot_enabled: bool = False) -> Dict[str, Any]:
    init_store()
    with local_auth._conn() as c:
        cur = c.execute(
            "INSERT INTO connectors(type,name,config_json,secrets_enc,enabled,copilot_enabled) "
            "VALUES(?,?,?,?,?,?)",
            (ctype, name, json.dumps(config or {}), _encrypt(secrets or {}),
             1 if enabled else 0, 1 if copilot_enabled else 0),
        )
        cid = cur.lastrowid
    logger.info("Created connector id=%s type=%s name=%s", cid, ctype, name)
    return get_connector(cid)


def update_connector(cid: int, *, name: Optional[str] = None,
                     config: Optional[Dict[str, Any]] = None,
                     secrets: Optional[Dict[str, Any]] = None,
                     enabled: Optional[bool] = None,
                     copilot_enabled: Optional[bool] = None,
                     merge_secrets: bool = True) -> Optional[Dict[str, Any]]:
    """Partial update. By default new secret values are merged over existing ones
    (so the UI can omit unchanged secrets); pass merge_secrets=False to replace."""
    existing = get_connector(cid, include_secrets=True)
    if not existing:
        return None

    sets: List[str] = []
    args: List[Any] = []
    if name is not None:
        sets.append("name=?"); args.append(name)
    if config is not None:
        sets.append("config_json=?"); args.append(json.dumps(config))
    if secrets is not None:
        if merge_secrets:
            merged = dict(existing.get("secrets", {}))
            # Only overwrite keys with truthy new values; "" means "leave as is".
            for k, v in secrets.items():
                if v:
                    merged[k] = v
            final_secrets = merged
        else:
            final_secrets = secrets
        sets.append("secrets_enc=?"); args.append(_encrypt(final_secrets))
    if enabled is not None:
        sets.append("enabled=?"); args.append(1 if enabled else 0)
    if copilot_enabled is not None:
        sets.append("copilot_enabled=?"); args.append(1 if copilot_enabled else 0)

    if not sets:
        return existing
    sets.append("updated_at=?"); args.append(_now())
    args.append(cid)
    with local_auth._conn() as c:
        c.execute(f"UPDATE connectors SET {', '.join(sets)} WHERE id=?", args)
    return get_connector(cid)


def delete_connector(cid: int) -> bool:
    init_store()
    with local_auth._conn() as c:
        cur = c.execute("DELETE FROM connectors WHERE id=?", (cid,))
        return cur.rowcount > 0


# ── Sandbox config ────────────────────────────────────────────────────────────
DEFAULT_SANDBOX_CONFIG: Dict[str, Any] = {
    "guardrail": {"provider": "none"},  # none | generic_http | connector
    "model": {"provider": "", "model": "", "temperature": 0.7, "max_tokens": 1000},
    "agents": [],   # user-defined agents: [{id,name,system_prompt,tools:[...]}]
    "tools": [],    # user-defined tools available to agents
}


def get_sandbox_config(include_secrets: bool = False) -> Dict[str, Any]:
    init_store()
    with local_auth._conn() as c:
        row = c.execute("SELECT * FROM sandbox_config WHERE id=1").fetchone()
    if not row:
        cfg = dict(DEFAULT_SANDBOX_CONFIG)
        return {"config": cfg, "secrets_set": {}}
    out = {
        "config": json.loads(row["config_json"] or "{}") or dict(DEFAULT_SANDBOX_CONFIG),
        "secrets_set": _redact_secrets(_decrypt(row["secrets_enc"])),
        "updated_at": row["updated_at"],
    }
    if include_secrets:
        out["secrets"] = _decrypt(row["secrets_enc"])
    return out


def set_sandbox_config(config: Dict[str, Any],
                       secrets: Optional[Dict[str, Any]] = None,
                       merge_secrets: bool = True) -> Dict[str, Any]:
    init_store()
    current = get_sandbox_config(include_secrets=True)
    if secrets is not None and merge_secrets:
        merged = dict(current.get("secrets", {}))
        for k, v in secrets.items():
            if v:
                merged[k] = v
        final_secrets = merged
    elif secrets is not None:
        final_secrets = secrets
    else:
        final_secrets = current.get("secrets", {})

    with local_auth._conn() as c:
        c.execute(
            "INSERT INTO sandbox_config(id,config_json,secrets_enc,updated_at) "
            "VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET "
            "config_json=excluded.config_json, secrets_enc=excluded.secrets_enc, "
            "updated_at=excluded.updated_at",
            (json.dumps(config or {}), _encrypt(final_secrets), _now()),
        )
    return get_sandbox_config()


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
