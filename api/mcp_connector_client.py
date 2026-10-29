"""
Remote MCP server client for Triksha connectors.

Lets users connect a remote MCP server (the same way Claude connects to MCP
servers) and expose its tools to the Triksha Copilot. Thin wrapper around the
existing MCPScanner transport plumbing (SSE / streamable-HTTP) plus the MCP
ClientSession for list_tools / call_tool.

All functions accept a `values` dict from a stored connector:
  { server_url, transport?, auth_header?, auth_token? }
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 30


def _server_config(values: Dict[str, Any]) -> Dict[str, Any]:
    url = (values.get("server_url") or "").strip()
    if not url:
        raise ValueError("server_url is required")

    transport = (values.get("transport") or "").strip().lower()
    if transport not in ("sse", "http"):
        # Auto-detect: SSE endpoints conventionally end in /sse.
        transport = "sse" if url.rstrip("/").endswith("/sse") else "http"

    headers: Dict[str, str] = {}
    token = values.get("auth_token")
    if token:
        header_name = (values.get("auth_header") or "Authorization").strip()
        headers[header_name] = token

    return {"type": transport, "url": url, "headers": headers}


async def _with_session(values: Dict[str, Any], fn):
    """Open a session to the MCP server and run fn(session)."""
    from mcp_scanner import MCPScanner
    from mcp import ClientSession

    config = _server_config(values)
    scanner = MCPScanner(console=None, enable_llm_analysis=False)
    async with scanner._get_client(config, _DEFAULT_TIMEOUT) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await fn(session)


def _tool_to_dict(t: Any) -> Dict[str, Any]:
    return {
        "name": getattr(t, "name", None),
        "description": getattr(t, "description", "") or "",
        "input_schema": getattr(t, "inputSchema", None) or {},
    }


def _content_to_text(result: Any) -> str:
    content = getattr(result, "content", None)
    if content is None:
        return str(result)
    parts: List[str] = []
    for item in content:
        text = getattr(item, "text", None)
        if text is not None:
            parts.append(text)
        else:
            parts.append(str(item))
    return "\n".join(parts) if parts else ""


async def list_tools(values: Dict[str, Any]) -> List[Dict[str, Any]]:
    async def _fn(session):
        resp = await session.list_tools()
        return [_tool_to_dict(t) for t in (resp.tools or [])]
    return await _with_session(values, _fn)


async def call_tool(values: Dict[str, Any], tool_name: str,
                    arguments: Optional[Dict[str, Any]] = None) -> str:
    async def _fn(session):
        result = await session.call_tool(tool_name, arguments or {})
        return _content_to_text(result)
    return await _with_session(values, _fn)


async def test_connection(values: Dict[str, Any]) -> Dict[str, Any]:
    try:
        tools = await list_tools(values)
    except Exception as exc:  # noqa: BLE001 - surface any connection error to UI
        logger.warning("MCP connector test failed: %s", exc)
        return {"success": False, "error": str(exc)}
    return {
        "success": True,
        "message": f"Connected — {len(tools)} tool(s) available",
        "tools_count": len(tools),
        "tools": [t["name"] for t in tools],
    }
