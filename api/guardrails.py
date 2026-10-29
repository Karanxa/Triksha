"""
Guardrail provider abstraction for the Triksha Sandbox.

The Sandbox runs a multi-agent pipeline and scans every message before and after
the LLM call. Which guardrail does the scanning is pluggable:

  - none          : no-op, always "allow" (pure agent demo)
  - generic_http  : POST the messages to any HTTP guardrail/firewall endpoint
  - guardrail     : HTTP guardrail with deferred-polling support
  - connector     : resolve a guardrail connector from the Connectors store

A provider config is a dict, e.g.:
  {"provider": "guardrail", "base_url": "...", "token": "...",
   "protect_path": "/inline/api/v1/inline/protect", "verify_ssl": false}
  {"provider": "generic_http", "url": "https://fw/scan", "token": "..."}
  {"provider": "connector", "connector_id": 3}
  {"provider": "none"}

scan() returns (data, timing) where data has the shape
  {"result": {"decision": "allow|block|sanitize|...", "masked_content": [...], ...}}
so the Sandbox pipeline can treat every provider uniformly.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional, Tuple

import requests as _req
import urllib3 as _urllib3

logger = logging.getLogger(__name__)

_DEFAULT_PROTECT_PATH = "/inline/api/v1/inline/protect"
_POLL_RETRIES = 30
_POLL_INTERVAL = 2.0


def _empty_timing(phase: str) -> Dict[str, Any]:
    return {
        "phase": phase, "deferred_used": False,
        "protect_post_ms": 0, "initial_http_status": 0,
        "poll_http_round_trip_sum_ms": 0, "poll_sleep_sum_ms": 0,
        "poll_attempts": 0, "redirect_follows": 0, "total_round_trip_ms": 0,
    }


# ── Public entrypoint ─────────────────────────────────────────────────────────
def scan(provider_cfg: Optional[Dict[str, Any]], messages: list,
         user_ctx: dict, agent_ctx: dict, phase: str = "protect") -> Tuple[Any, dict]:
    cfg = dict(provider_cfg or {})
    provider = (cfg.get("provider") or "none").lower()

    if provider == "none":
        return {"result": {"decision": "allow"}}, _empty_timing(phase)

    if provider == "connector":
        cfg = _resolve_connector_cfg(cfg)
        provider = (cfg.get("provider") or "none").lower()
        if provider == "none":
            return ({"status": "error", "error": "connector_unresolved",
                     "result": {"decision": "service_not_available"}}, _empty_timing(phase))

    if provider == "generic_http":
        return _scan_generic_http(cfg, messages, user_ctx, agent_ctx, phase)

    if provider == "guardrail":
        return _scan_guardrail(cfg, messages, user_ctx, agent_ctx, phase)

    return ({"status": "error", "error": f"unknown_guardrail_{provider}",
             "result": {"decision": "service_not_available"}}, _empty_timing(phase))


def _resolve_connector_cfg(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Turn a {'provider':'connector','connector_id':N} config into a concrete
    guardrail/generic_http config using the stored connector's credentials."""
    cid = cfg.get("connector_id")
    if not cid:
        return {"provider": "none"}
    try:
        import connectors_store
        conn = connectors_store.get_connector(int(cid), include_secrets=True)
    except Exception as exc:  # pragma: no cover
        logger.warning("guardrail connector lookup failed: %s", exc)
        return {"provider": "none"}
    if not conn or not conn.get("enabled"):
        return {"provider": "none"}
    c, s = conn.get("config", {}), conn.get("secrets", {})
    # Treat any connector with a base_url as a generic HTTP guardrail.
    return {"provider": "generic_http", "url": c.get("base_url", ""), "token": s.get("token", "")}


# ── generic_http ──────────────────────────────────────────────────────────────
def _scan_generic_http(cfg: Dict[str, Any], messages: list, user_ctx: dict,
                       agent_ctx: dict, phase: str) -> Tuple[Any, dict]:
    timing = _empty_timing(phase)
    url = (cfg.get("url") or "").strip()
    if not url:
        return {"status": "error", "error": "no_url",
                "result": {"decision": "service_not_available"}}, timing
    headers = {"Content-Type": "application/json"}
    if cfg.get("token"):
        headers["Authorization"] = f"Bearer {cfg['token']}"
    payload = {"messages": messages, "phase": phase}
    if user_ctx:
        payload["user"] = user_ctx
    if agent_ctx:
        payload["agent"] = agent_ctx

    t0 = time.perf_counter()
    try:
        resp = _req.post(url, json=payload, headers=headers, timeout=30,
                         verify=cfg.get("verify_ssl", True))
        timing["protect_post_ms"] = int((time.perf_counter() - t0) * 1000)
        timing["initial_http_status"] = resp.status_code
        data = resp.json()
    except Exception as exc:
        timing["total_round_trip_ms"] = int((time.perf_counter() - t0) * 1000)
        return {"status": "error", "error": str(exc),
                "result": {"decision": "service_not_available"}}, timing
    timing["total_round_trip_ms"] = int((time.perf_counter() - t0) * 1000)
    return _normalize_generic(data), timing


def _normalize_generic(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {"result": {"decision": "allow"}, "raw": data}
    if isinstance(data.get("result"), dict) and data["result"].get("decision"):
        return data
    if data.get("decision"):
        return {"result": data}
    if "allowed" in data:
        return {"result": {"decision": "allow" if data.get("allowed") else "block"}, "raw": data}
    if "blocked" in data:
        return {"result": {"decision": "block" if data.get("blocked") else "allow"}, "raw": data}
    return {"result": {"decision": "allow"}, "raw": data}


# ── guardrail (HTTP with deferred-polling support) ────────────────────────────
def _scan_guardrail(cfg: Dict[str, Any], messages: list, user_ctx: dict,
                    agent_ctx: dict, phase: str) -> Tuple[Any, dict]:
    base_url = (cfg.get("base_url") or "").rstrip("/")
    token = cfg.get("token") or ""
    protect_path = cfg.get("protect_path") or _DEFAULT_PROTECT_PATH
    verify_ssl = bool(cfg.get("verify_ssl", False))
    if not verify_ssl:
        _urllib3.disable_warnings(_urllib3.exceptions.InsecureRequestWarning)

    timing = _empty_timing(phase)
    if not base_url:
        return {"status": "error", "error": "no_base_url",
                "result": {"decision": "service_not_available"}}, timing

    protect_url = f"{base_url}{protect_path}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload: Dict[str, Any] = {"messages": messages}
    if user_ctx:
        payload["user"] = user_ctx
    if agent_ctx:
        payload["agent"] = agent_ctx

    t0 = time.perf_counter()
    try:
        resp = _req.post(protect_url, json=payload, headers=headers, timeout=30, verify=verify_ssl)
        data = resp.json()
        timing["protect_post_ms"] = int((time.perf_counter() - t0) * 1000)
        timing["initial_http_status"] = resp.status_code
    except Exception as exc:
        timing["total_round_trip_ms"] = int((time.perf_counter() - t0) * 1000)
        return {"status": "error", "error": str(exc),
                "result": {"decision": "service_not_available"}}, timing

    if resp.status_code >= 400:
        timing["total_round_trip_ms"] = int((time.perf_counter() - t0) * 1000)
        return (data if isinstance(data, dict) else {"error": "guardrail_error"}), timing

    if isinstance(data, dict) and data.get("status") == "processing" and data.get("callback_url"):
        timing["deferred_used"] = True
        data = _poll_deferred(base_url, protect_path, verify_ssl,
                              _resolve_cb_url(base_url, protect_path, str(data["callback_url"])), timing)

    timing["total_round_trip_ms"] = int((time.perf_counter() - t0) * 1000)
    return data, timing


def _gateway_prefix(protect_path: str) -> str:
    idx = protect_path.find("/api/v")
    return protect_path[:idx] if idx > 0 else ""


def _resolve_cb_url(base_url: str, protect_path: str, url: str) -> str:
    if url.startswith("http://") or url.startswith("https://"):
        return url
    path = url if url.startswith("/") else "/" + url
    prefix = _gateway_prefix(protect_path)
    if prefix and not path.startswith(prefix):
        path = prefix + path
    return f"{base_url}{path}"


def _still_processing(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    res = data.get("result")
    if isinstance(res, dict) and res.get("decision") not in (None, "processing"):
        return False
    if data.get("status") == "processing":
        return True
    if isinstance(res, dict) and res.get("status") == "processing":
        return True
    return False


def _poll_deferred(base_url: str, protect_path: str, verify_ssl: bool,
                   callback_url: str, timing: dict) -> Any:
    for _ in range(_POLL_RETRIES):
        s0 = time.perf_counter()
        time.sleep(_POLL_INTERVAL)
        timing["poll_sleep_sum_ms"] += int((time.perf_counter() - s0) * 1000)
        try:
            t1 = time.perf_counter()
            pr = _req.get(callback_url, timeout=15, verify=verify_ssl)
            timing["poll_http_round_trip_sum_ms"] += int((time.perf_counter() - t1) * 1000)
            timing["poll_attempts"] += 1
            pdata = pr.json()

            if pr.status_code in (401, 403, 404):
                return {"status": "error", "error": f"callback_http_{pr.status_code}",
                        "result": {"decision": "service_not_available"}}

            if pr.status_code == 410 and isinstance(pdata, dict) and pdata.get("redirect_url"):
                t2 = time.perf_counter()
                rr = _req.get(_resolve_cb_url(base_url, protect_path, str(pdata["redirect_url"])),
                              timeout=15, verify=verify_ssl)
                timing["poll_http_round_trip_sum_ms"] += int((time.perf_counter() - t2) * 1000)
                timing["redirect_follows"] += 1
                rdata = rr.json()
                if rr.status_code in (200, 202) and not _still_processing(rdata):
                    return rdata
                continue

            if pr.status_code in (200, 202) and not _still_processing(pdata):
                return pdata
        except Exception as exc:
            logger.debug("guardrail poll error: %s", exc)

    return {"status": "error", "error": "polling_timeout",
            "result": {"decision": "service_not_available"}}
