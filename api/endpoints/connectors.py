"""
Connectors API for Triksha.

Users connect external tools (Jira, GitHub/GHE, Google Chat, GCP, and
remote MCP servers) here, the same way Claude lets you connect MCP servers.
Connectors are instance-global (single-tenant OSS): every admin shares them.

Secrets are stored encrypted via connectors_store (Fernet). Forms are rendered
from the schema returned by GET /connectors/types so the UI stays generic.

Per-connector test actions verify credentials before they're relied on by the
Copilot or scanners.
"""
from __future__ import annotations

import base64
import json
import logging
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, Body, HTTPException
from pydantic import BaseModel

import connectors_store

logger = logging.getLogger(__name__)
router = APIRouter()

_HTTP_TIMEOUT = 20.0


# ── Connector type schema ─────────────────────────────────────────────────────
# Each field: {key, label, secret, required, placeholder?, help?}
CONNECTOR_TYPES: Dict[str, Dict[str, Any]] = {
    "jira": {
        "label": "Jira",
        "description": "Create and manage security issues in Jira Cloud.",
        "category": "first_party",
        "fields": [
            {"key": "base_url", "label": "Base URL", "secret": False, "required": True,
             "placeholder": "https://your-org.atlassian.net"},
            {"key": "email", "label": "Account Email", "secret": False, "required": True,
             "placeholder": "you@company.com"},
            {"key": "api_token", "label": "API Token", "secret": True, "required": True,
             "help": "Create at id.atlassian.com → Security → API tokens"},
            {"key": "project_key", "label": "Default Project Key", "secret": False,
             "required": False, "placeholder": "SEC"},
        ],
    },
    "github": {
        "label": "GitHub / GHE",
        "description": "Read repositories and code for review (github.com or Enterprise).",
        "category": "first_party",
        "fields": [
            {"key": "base_url", "label": "API Base URL", "secret": False, "required": False,
             "placeholder": "https://api.github.com (or https://ghe.host/api/v3)"},
            {"key": "token", "label": "Personal Access Token", "secret": True, "required": True},
        ],
    },
    "google_chat": {
        "label": "Google Chat",
        "description": "Send security alerts to a Google Chat space via webhook.",
        "category": "first_party",
        "fields": [
            {"key": "webhook_url", "label": "Webhook URL", "secret": True, "required": True,
             "placeholder": "https://chat.googleapis.com/v1/spaces/.../messages?..."},
        ],
    },
    "gcp": {
        "label": "Google Cloud",
        "description": "Service-account credentials for GCP-backed scanners.",
        "category": "first_party",
        "fields": [
            {"key": "project_id", "label": "Project ID", "secret": False, "required": False},
            {"key": "service_account_json", "label": "Service Account JSON", "secret": True,
             "required": True, "help": "Paste the full service-account key JSON"},
        ],
    },
    "mcp": {
        "label": "MCP Server",
        "description": "Connect a remote MCP server and expose its tools to the Copilot.",
        "category": "mcp",
        "fields": [
            {"key": "server_url", "label": "Server URL", "secret": False, "required": True,
             "placeholder": "https://mcp.example.com/sse"},
            {"key": "transport", "label": "Transport", "secret": False, "required": False,
             "placeholder": "sse or http (default: auto)"},
            {"key": "auth_header", "label": "Auth Header Name", "secret": False, "required": False,
             "placeholder": "Authorization"},
            {"key": "auth_token", "label": "Auth Token", "secret": True, "required": False,
             "help": "Sent as the auth header value, e.g. 'Bearer <token>'"},
        ],
    },
}


# ── Request models ────────────────────────────────────────────────────────────
class ConnectorCreate(BaseModel):
    type: str
    name: str
    values: Dict[str, Any] = {}
    enabled: bool = True
    copilot_enabled: bool = False


class ConnectorUpdate(BaseModel):
    name: Optional[str] = None
    values: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None
    copilot_enabled: Optional[bool] = None


class ConnectorTest(BaseModel):
    type: str
    values: Dict[str, Any] = {}


# ── Helpers ───────────────────────────────────────────────────────────────────
def _require_type(ctype: str) -> Dict[str, Any]:
    schema = CONNECTOR_TYPES.get(ctype)
    if not schema:
        raise HTTPException(status_code=400, detail=f"Unknown connector type '{ctype}'")
    return schema


def _invalidate_copilot() -> None:
    """Rebuild the Copilot's cached runner so connector changes (new tools, new
    Jira creds, enable/disable for Copilot) take effect on the next turn."""
    try:
        import copilot
        copilot._reset_runner()
    except Exception:  # pragma: no cover - copilot optional
        pass


def _split_values(ctype: str, values: Dict[str, Any]) -> tuple[Dict[str, Any], Dict[str, Any]]:
    schema = _require_type(ctype)
    config: Dict[str, Any] = {}
    secrets: Dict[str, Any] = {}
    keys = {f["key"]: f for f in schema["fields"]}
    for k, v in (values or {}).items():
        if k not in keys:
            continue
        (secrets if keys[k].get("secret") else config)[k] = v
    return config, secrets


def _validate_required(ctype: str, config: Dict[str, Any], secrets: Dict[str, Any],
                       secrets_already_set: Optional[Dict[str, bool]] = None) -> None:
    schema = _require_type(ctype)
    secrets_already_set = secrets_already_set or {}
    for f in schema["fields"]:
        if not f.get("required"):
            continue
        if f.get("secret"):
            if not secrets.get(f["key"]) and not secrets_already_set.get(f["key"]):
                raise HTTPException(status_code=400, detail=f"'{f['label']}' is required")
        else:
            if not config.get(f["key"]):
                raise HTTPException(status_code=400, detail=f"'{f['label']}' is required")


# ── CRUD endpoints ────────────────────────────────────────────────────────────
@router.get("/connectors/types")
def list_types():
    """Schema for rendering connector forms in the UI (no secret values)."""
    return {"types": [
        {"type": t, **{k: v for k, v in spec.items()}} for t, spec in CONNECTOR_TYPES.items()
    ]}


@router.get("/connectors")
def list_connectors():
    return {"connectors": connectors_store.list_connectors()}


@router.post("/connectors")
async def create_connector(body: ConnectorCreate = Body(...)):
    _require_type(body.type)
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="Name is required")
    config, secrets = _split_values(body.type, body.values)
    _validate_required(body.type, config, secrets)
    created = connectors_store.create_connector(
        body.type, body.name.strip(), config, secrets,
        enabled=body.enabled, copilot_enabled=body.copilot_enabled,
    )
    # per-tool tools without a live network call at runner-build time.
    if body.type == "mcp":
        await _refresh_mcp_tool_cache(created["id"])
        created = connectors_store.get_connector(created["id"])
    _invalidate_copilot()
    return {"status": "ok", "connector": created}


@router.get("/connectors/{cid}")
def get_connector(cid: int):
    c = connectors_store.get_connector(cid)
    if not c:
        raise HTTPException(status_code=404, detail="Connector not found")
    return {"connector": c}


@router.put("/connectors/{cid}")
def update_connector(cid: int, body: ConnectorUpdate = Body(...)):
    existing = connectors_store.get_connector(cid)
    if not existing:
        raise HTTPException(status_code=404, detail="Connector not found")
    config = secrets = None
    if body.values is not None:
        config, secrets = _split_values(existing["type"], body.values)
        _validate_required(existing["type"], config or {}, secrets or {},
                           existing.get("secrets_set"))
    updated = connectors_store.update_connector(
        cid, name=body.name, config=config, secrets=secrets,
        enabled=body.enabled, copilot_enabled=body.copilot_enabled,
    )
    _invalidate_copilot()
    return {"status": "ok", "connector": updated}


@router.post("/connectors/{cid}/toggle-copilot")
def toggle_copilot(cid: int):
    """Flip whether a connector is exposed to the Triksha Copilot."""
    existing = connectors_store.get_connector(cid)
    if not existing:
        raise HTTPException(status_code=404, detail="Connector not found")
    updated = connectors_store.update_connector(
        cid, copilot_enabled=not existing["copilot_enabled"])
    _invalidate_copilot()
    return {"status": "ok", "connector": updated}


@router.delete("/connectors/{cid}")
def delete_connector(cid: int):
    if not connectors_store.delete_connector(cid):
        raise HTTPException(status_code=404, detail="Connector not found")
    _invalidate_copilot()
    return {"status": "ok"}


# ── Test actions ──────────────────────────────────────────────────────────────
@router.post("/connectors/{cid}/test")
async def test_saved_connector(cid: int):
    c = connectors_store.get_connector(cid, include_secrets=True)
    if not c:
        raise HTTPException(status_code=404, detail="Connector not found")
    values = {**c.get("config", {}), **c.get("secrets", {})}
    return await _run_test(c["type"], values)


@router.post("/connectors/test")
async def test_unsaved_connector(body: ConnectorTest = Body(...)):
    _require_type(body.type)
    return await _run_test(body.type, body.values)


async def _refresh_mcp_tool_cache(cid: int) -> List[Dict[str, Any]]:
    """Best-effort: discover an MCP connector's tools and cache them in its
    config (config['mcp_tools']) for the Copilot to build per-tool tools from."""
    c = connectors_store.get_connector(cid, include_secrets=True)
    if not c or c["type"] != "mcp":
        return []
    try:
        import mcp_connector_client
        values = {**c.get("config", {}), **c.get("secrets", {})}
        tools = await mcp_connector_client.list_tools(values)
    except Exception as exc:
        logger.warning("MCP tool discovery failed for connector %s: %s", cid, exc)
        return []
    new_config = dict(c.get("config", {}))
    new_config["mcp_tools"] = tools
    connectors_store.update_connector(cid, config=new_config)
    return tools


@router.get("/connectors/{cid}/mcp/tools")
async def list_mcp_tools(cid: int):
    """Discover the tools exposed by a connected MCP server (and cache them)."""
    c = connectors_store.get_connector(cid, include_secrets=True)
    if not c:
        raise HTTPException(status_code=404, detail="Connector not found")
    if c["type"] != "mcp":
        raise HTTPException(status_code=400, detail="Not an MCP connector")
    try:
        import mcp_connector_client
    except Exception:
        raise HTTPException(status_code=500, detail="MCP client unavailable in this build")
    values = {**c.get("config", {}), **c.get("secrets", {})}
    try:
        tools = await mcp_connector_client.list_tools(values)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not list tools: {exc}")
    try:
        new_config = dict(c.get("config", {}))
        new_config["mcp_tools"] = tools
        connectors_store.update_connector(cid, config=new_config)
        _invalidate_copilot()
    except Exception:
        pass
    return {"tools": tools}


async def _run_test(ctype: str, values: Dict[str, Any]) -> Dict[str, Any]:
    try:
        if ctype == "jira":
            return await _test_jira(values)
        if ctype == "github":
            return await _test_github(values)
        if ctype == "google_chat":
            return await _test_google_chat(values)
        if ctype == "gcp":
            return _test_gcp(values)
        if ctype == "mcp":
            return await _test_mcp(values)
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Connector test failed (%s): %s", ctype, exc)
        return {"success": False, "error": str(exc)}
    return {"success": False, "error": f"No test available for '{ctype}'"}


async def _test_jira(v: Dict[str, Any]) -> Dict[str, Any]:
    base = (v.get("base_url") or "").rstrip("/")
    email, token = v.get("email"), v.get("api_token")
    if not (base and email and token):
        return {"success": False, "error": "base_url, email and api_token are required"}
    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        r = await client.get(f"{base}/rest/api/3/myself",
                             headers={"Authorization": f"Basic {auth}",
                                      "Accept": "application/json"})
    if r.status_code == 200:
        me = r.json()
        return {"success": True, "message": f"Connected as {me.get('displayName') or me.get('emailAddress')}"}
    return {"success": False, "error": f"Jira returned HTTP {r.status_code}"}


@router.post("/jira/ticket")
async def create_jira_ticket(body: dict = Body(...)):
    """Create a security ticket in the user's configured Jira instance."""
    connectors = connectors_store.get_connectors_by_type("jira", enabled_only=True, include_secrets=True)
    if not connectors:
        raise HTTPException(status_code=400, detail="No Jira connector configured. Add one in Settings → Connectors.")

    c = connectors[0]
    cfg = {**c.get("config", {}), **c.get("secrets", {})}
    base = (cfg.get("base_url") or "").rstrip("/")
    email = cfg.get("email", "")
    token = cfg.get("api_token", "")
    project_key = body.get("project_key") or cfg.get("project_key", "")

    if not (base and email and token):
        raise HTTPException(status_code=400, detail="Jira connector is missing base_url, email, or api_token.")
    if not project_key:
        raise HTTPException(status_code=400, detail="No Jira project key — set one in the connector config or pass project_key in the request.")

    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json", "Accept": "application/json"}

    severity = body.get("severity", "Medium")
    priority_map = {"P0": "Highest", "P1": "High", "P2": "Medium", "P3": "Low", "P4": "Lowest",
                    "Critical": "Highest", "High": "High", "Medium": "Medium", "Low": "Low"}
    priority = priority_map.get(severity, "High")

    vuln_type = body.get("vulnerability_type", "Security Vulnerability")
    title = body.get("title") or vuln_type
    description_parts = [f"*Vulnerability Type:* {vuln_type}", f"*Severity:* {severity}"]
    if body.get("scan_name"):
        description_parts.append(f"*Scan:* {body['scan_name']}")
    if body.get("server_name"):
        description_parts.append(f"*Server:* {body['server_name']}")
    if body.get("tool_name"):
        description_parts.append(f"*Tool:* {body['tool_name']}")
    if body.get("payload"):
        description_parts.append(f"\n*Attack Payload:*\n{{code}}{body['payload'][:2000]}{{code}}")
    if body.get("response"):
        description_parts.append(f"\n*Model Response:*\n{{code}}{body['response'][:2000]}{{code}}")
    if body.get("recommendation"):
        description_parts.append(f"\n*Recommendation:*\n{body['recommendation']}")
    if body.get("details"):
        description_parts.append(f"\n*Additional Details:*\n{body['details']}")
    if body.get("remarks"):
        description_parts.append(f"\n*Notes:*\n{body['remarks']}")
    description_parts.append("\n_Reported by Triksha AI Security Platform_")

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": title,
            "description": "\n".join(description_parts),
            "issuetype": {"name": "Bug"},
            "priority": {"name": priority},
        }
    }
    if body.get("assignee"):
        payload["fields"]["assignee"] = {"emailAddress": body["assignee"]}

    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(f"{base}/rest/api/2/issue", headers=headers, json=payload)

    if r.status_code in (200, 201):
        data = r.json()
        key = data.get("key", "")
        url = f"{base}/browse/{key}"
        return {"status": "success", "ticket_key": key, "ticket_url": url}

    # Extract a human-readable error from Jira's response
    try:
        err = r.json()
        messages = err.get("errorMessages") or []
        field_errors = list((err.get("errors") or {}).values())
        parts = messages + field_errors
        detail = " ".join(parts) if parts else f"Jira returned HTTP {r.status_code}"
    except Exception:
        detail = f"Jira returned HTTP {r.status_code}"
    raise HTTPException(status_code=400, detail=detail)


async def _test_github(v: Dict[str, Any]) -> Dict[str, Any]:
    base = (v.get("base_url") or "https://api.github.com").rstrip("/")
    token = v.get("token")
    if not token:
        return {"success": False, "error": "token is required"}
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        r = await client.get(f"{base}/user",
                             headers={"Authorization": f"Bearer {token}",
                                      "Accept": "application/vnd.github+json"})
    if r.status_code == 200:
        return {"success": True, "message": f"Connected as {r.json().get('login')}"}
    return {"success": False, "error": f"GitHub returned HTTP {r.status_code}"}


async def _test_google_chat(v: Dict[str, Any]) -> Dict[str, Any]:
    url = v.get("webhook_url")
    if not url:
        return {"success": False, "error": "webhook_url is required"}
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        r = await client.post(url, json={"text": "Triksha connector test ✅"})
    if r.status_code in (200, 201):
        return {"success": True, "message": "Test message delivered to the space"}
    return {"success": False, "error": f"Webhook returned HTTP {r.status_code}"}


def _test_gcp(v: Dict[str, Any]) -> Dict[str, Any]:
    raw = v.get("service_account_json")
    if not raw:
        return {"success": False, "error": "service_account_json is required"}
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError:
        return {"success": False, "error": "Service account JSON is not valid JSON"}
    if not data.get("client_email") or not data.get("private_key"):
        return {"success": False, "error": "JSON missing client_email / private_key"}
    return {"success": True, "message": f"Valid key for {data['client_email']}"}


async def _test_mcp(v: Dict[str, Any]) -> Dict[str, Any]:
    try:
        import mcp_connector_client
    except Exception:
        return {"success": False, "error": "MCP client unavailable in this build"}
    return await mcp_connector_client.test_connection(v)
