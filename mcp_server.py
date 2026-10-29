#!/usr/bin/env python3
"""
Triksha MCP Server

Exposes Triksha AI security scanning capabilities as MCP tools so that
Claude Code, VS Code Copilot, or any MCP-compatible agent can run:
  - LLM red-team scans
  - Agent security scans
  - MCP server security scans
  - Dataset poisoning analysis
  - Prompt hardening

Configuration via environment variables:
  TRIKSHA_API_URL   — base URL of the API (default: http://localhost:8001)
  TRIKSHA_USERNAME  — login username
  TRIKSHA_PASSWORD  — login password
"""

import asyncio
import json
import os
import io
import sys
import time
from typing import Any, Optional

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# ── Config ────────────────────────────────────────────────────────────────────

API_URL = os.environ.get("TRIKSHA_API_URL", "http://localhost:8001").rstrip("/")
USERNAME = os.environ.get("TRIKSHA_USERNAME", "admin")
PASSWORD = os.environ.get("TRIKSHA_PASSWORD", "")

# ── Session management ────────────────────────────────────────────────────────

_session_cookie: Optional[str] = None
_session_expires: float = 0.0
SESSION_TTL = 60 * 60  # 1 hour


async def _get_cookie() -> str:
    global _session_cookie, _session_expires
    if _session_cookie and time.time() < _session_expires:
        return _session_cookie
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{API_URL}/auth/login",
            json={"username": USERNAME, "password": PASSWORD},
            timeout=10,
        )
        resp.raise_for_status()
        cookie = resp.cookies.get("triksha_session")
        if not cookie:
            # May be returned in set-cookie header
            for k, v in resp.cookies.items():
                cookie = v
                break
        if not cookie:
            raise RuntimeError(f"Login failed: {resp.text}")
        _session_cookie = cookie
        _session_expires = time.time() + SESSION_TTL
        return _session_cookie


async def _get(path: str, params: dict = None) -> Any:
    cookie = await _get_cookie()
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{API_URL}{path}",
            params=params,
            cookies={"triksha_session": cookie},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()


async def _post(path: str, json_body: Any = None, data: dict = None,
                files: dict = None, timeout: int = 60) -> Any:
    cookie = await _get_cookie()
    headers = {"Cookie": f"triksha_session={cookie}"}
    async with httpx.AsyncClient() as client:
        if files:
            resp = await client.post(
                f"{API_URL}{path}", data=data, files=files,
                headers=headers, timeout=timeout,
            )
        else:
            resp = await client.post(
                f"{API_URL}{path}", json=json_body,
                headers=headers, timeout=timeout,
            )
        resp.raise_for_status()
        return resp.json()


async def _delete(path: str) -> Any:
    cookie = await _get_cookie()
    async with httpx.AsyncClient() as client:
        resp = await client.delete(
            f"{API_URL}{path}",
            cookies={"triksha_session": cookie},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()


# ── Helper ────────────────────────────────────────────────────────────────────

def _j(obj: Any) -> str:
    return json.dumps(obj, indent=2)


def _ok(data: Any) -> list[TextContent]:
    return [TextContent(type="text", text=_j(data))]


def _err(msg: str) -> list[TextContent]:
    return [TextContent(type="text", text=f"Error: {msg}")]


# ── Server ────────────────────────────────────────────────────────────────────

server = Server("triksha")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        # ── LLM Scans ──────────────────────────────────────────────────────
        Tool(
            name="triksha_llm_scan_start",
            description=(
                "Start a Triksha LLM red-team scan against a target model. "
                "Runs a full adversarial attack suite (jailbreaks, prompt injections, data extraction, etc.) "
                "and returns a scan_id you can poll for results."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_name": {"type": "string", "description": "Human-readable name for this scan"},
                    "provider": {
                        "type": "string",
                        "enum": ["gemini", "openai", "anthropic", "custom-api"],
                        "description": "LLM provider",
                    },
                    "model_id": {"type": "string", "description": "Model ID, e.g. gemini-2.5-flash or gpt-4o"},
                    "system_prompt": {"type": "string", "description": "System prompt of the target model (optional)"},
                    "use_case": {"type": "string", "description": "What the model is used for (optional, improves attack relevance)"},
                    "attack_count": {"type": "integer", "default": 20, "description": "Number of attacks to run (default 20)"},
                },
                "required": ["scan_name", "provider", "model_id"],
            },
        ),
        Tool(
            name="triksha_llm_scan_status",
            description="Poll the status and progress of a running LLM scan.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "Scan ID returned by triksha_llm_scan_start"},
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="triksha_llm_scan_results",
            description=(
                "Get full results of a completed LLM scan: attack results, bypass rate, "
                "safety metrics, and per-technique breakdown."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "Scan ID"},
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="triksha_llm_scans_list",
            description="List past LLM scans with their status and summary stats.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 20, "description": "Max results to return"},
                    "scope": {"type": "string", "enum": ["mine", "all"], "default": "all"},
                },
            },
        ),

        # ── Agent Scans ────────────────────────────────────────────────────
        Tool(
            name="triksha_agent_scan_start",
            description=(
                "Start a Triksha agent security scan. Sends adversarial prompts to a live agent "
                "HTTP endpoint and tests for jailbreaks, tool misuse, data exfiltration, etc. "
                "Pass the agent's URL and request format."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_name": {"type": "string", "description": "Name for this agent"},
                    "agent_endpoint": {"type": "string", "description": "Agent HTTP endpoint URL"},
                    "request_body_template": {
                        "type": "string",
                        "description": 'JSON body template with __PROMPT__ placeholder, e.g. \'{"message": "__PROMPT__"}\'',
                    },
                    "headers": {
                        "type": "object",
                        "description": "Optional auth/custom headers",
                        "additionalProperties": {"type": "string"},
                    },
                    "agent_context": {"type": "string", "description": "Description of what this agent does (improves attack targeting)"},
                    "framework": {
                        "type": "string",
                        "description": "Agent framework: adk, autogen, crewai, langgraph, etc. (optional)",
                    },
                },
                "required": ["agent_name", "agent_endpoint", "request_body_template"],
            },
        ),
        Tool(
            name="triksha_agent_scan_get",
            description="Get the current state and results of an agent scan.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="triksha_agent_scans_list",
            description="List all agent security scans.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 20},
                },
            },
        ),
        Tool(
            name="triksha_agent_scan_cancel",
            description="Cancel a running agent scan.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                },
                "required": ["scan_id"],
            },
        ),

        # ── MCP Scans ──────────────────────────────────────────────────────
        Tool(
            name="triksha_mcp_scan_start",
            description=(
                "Scan an MCP server configuration for security issues: "
                "tool poisoning, prompt injection risks, excessive permissions, "
                "rug-pull patterns, and data exfiltration vectors. "
                "Pass the raw MCP config JSON (same format as claude_desktop_config.json mcpServers block)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "config_json": {
                        "type": "string",
                        "description": (
                            "MCP server config JSON. Can be a full MCP config object or just the mcpServers block. "
                            'Example: {"mcpServers": {"my-server": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}}}'
                        ),
                    },
                    "scan_name": {"type": "string", "description": "Human-readable name for this scan"},
                    "timeout": {"type": "integer", "default": 30, "description": "Timeout per server in seconds"},
                },
                "required": ["config_json"],
            },
        ),
        Tool(
            name="triksha_mcp_scan_get",
            description="Get the results of an MCP security scan.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="triksha_mcp_scans_list",
            description="List past MCP security scans.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 20},
                    "scope": {"type": "string", "enum": ["mine", "all"], "default": "all"},
                },
            },
        ),
        Tool(
            name="triksha_mcp_tool_scan",
            description=(
                "Directly scan a specific MCP tool by its server URL. "
                "Faster than triksha_mcp_scan_start — no queue, returns results immediately. "
                "Use when you have a server URL and want a quick security check."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "tool_name": {"type": "string", "description": "Name of the tool or server"},
                    "server_url": {"type": "string", "description": "MCP server URL, e.g. http://myserver/mcp"},
                    "transport": {
                        "type": "string",
                        "enum": ["sse", "http", "streamable_http"],
                        "default": "streamable_http",
                        "description": "MCP transport type",
                    },
                    "timeout": {"type": "integer", "default": 30},
                },
                "required": ["tool_name", "server_url"],
            },
        ),

        # ── Dataset Poisoning ──────────────────────────────────────────────
        Tool(
            name="triksha_dataset_poisoning_analyze",
            description=(
                "Analyze a dataset for poisoning attacks using statistical + LLM-based analysis. "
                "Detects backdoor triggers, adversarial examples, label flipping, and semantic anomalies. "
                "Pass dataset content as a JSON array of objects with a 'text' field, "
                "or as CSV/JSONL text. Requires at least 10 entries."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "dataset": {
                        "type": "string",
                        "description": (
                            "Dataset content. Accepted formats:\n"
                            '  - JSON array: [{"text": "sample 1"}, {"text": "sample 2"}, ...]\n'
                            '  - CSV text with a "text" column\n'
                            '  - JSONL: one JSON object per line\n'
                            "Minimum 10 entries required."
                        ),
                    },
                    "scan_name": {"type": "string", "description": "Name for this analysis"},
                    "file_format": {
                        "type": "string",
                        "enum": ["json", "csv", "jsonl", "txt"],
                        "default": "json",
                        "description": "Format of the dataset content",
                    },
                },
                "required": ["dataset"],
            },
        ),
        Tool(
            name="triksha_dataset_analysis_get",
            description="Get results of a dataset poisoning analysis.",
            inputSchema={
                "type": "object",
                "properties": {
                    "analysis_id": {"type": "string"},
                },
                "required": ["analysis_id"],
            },
        ),
        Tool(
            name="triksha_dataset_analyses_list",
            description="List past dataset poisoning analyses.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 20},
                },
            },
        ),

        # ── Prompt Hardening ───────────────────────────────────────────────
        Tool(
            name="triksha_prompt_harden",
            description=(
                "Harden a system prompt against adversarial attacks. "
                "Triksha analyzes the prompt and generates a security addendum "
                "that reduces prompt injection, jailbreak, and data extraction risks. "
                "Returns a job_id — poll triksha_harden_result to get the hardened prompt."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "system_prompt": {
                        "type": "string",
                        "description": "The system prompt to harden (min 10 characters)",
                    },
                    "prompt_name": {"type": "string", "description": "Human-readable name for this job"},
                    "context": {
                        "type": "string",
                        "description": "Additional context about the model's use case",
                    },
                },
                "required": ["system_prompt"],
            },
        ),
        Tool(
            name="triksha_harden_result",
            description=(
                "Get the result of a prompt hardening job. "
                "Returns status (queued/running/completed/failed) and, when done, "
                "the security_addendum to append to the original system prompt."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "job_id": {"type": "string", "description": "Job ID from triksha_prompt_harden"},
                    "wait": {
                        "type": "boolean",
                        "default": False,
                        "description": "If true, poll until completed (up to 120s)",
                    },
                },
                "required": ["job_id"],
            },
        ),
        Tool(
            name="triksha_harden_list",
            description="List past prompt hardening jobs.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 20},
                },
            },
        ),
    ]


# ── Tool handlers ─────────────────────────────────────────────────────────────

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        return await _dispatch(name, arguments)
    except httpx.HTTPStatusError as e:
        return _err(f"API error {e.response.status_code}: {e.response.text[:400]}")
    except Exception as e:
        return _err(str(e))


async def _dispatch(name: str, args: dict) -> list[TextContent]:
    # ── LLM scans ──────────────────────────────────────────────────────────
    if name == "triksha_llm_scan_start":
        provider = args["provider"]
        model_id = args["model_id"]
        model_config = {
            "provider": provider,
            "model_id": model_id,
            "custom_config": {"model_id": model_id},
        }
        body = {
            "scan_name": args["scan_name"],
            "models": [model_config],
            "attack_count": args.get("attack_count", 20),
        }
        if args.get("system_prompt"):
            body["system_prompt"] = args["system_prompt"]
        if args.get("use_case"):
            body["use_case"] = args["use_case"]
        result = await _post("/scan", body)
        return _ok(result)

    if name == "triksha_llm_scan_status":
        result = await _get(f"/scan/{args['scan_id']}/status")
        return _ok(result)

    if name == "triksha_llm_scan_results":
        result = await _get(f"/scan/{args['scan_id']}/results")
        # Summarise attack_results to keep response readable
        attacks = result.get("attack_results", [])
        summary = result.get("summary", {})
        metrics = result.get("safety_metrics", {})
        return _ok({
            "scan_id": result.get("scan_id"),
            "scan_name": result.get("scan_name"),
            "status": result.get("status"),
            "summary": summary,
            "safety_metrics": metrics,
            "models_tested": result.get("models_tested"),
            "attack_count": len(attacks),
            "attack_results": attacks[:50],  # cap at 50 for readability
        })

    if name == "triksha_llm_scans_list":
        scope = args.get("scope", "all")
        limit = args.get("limit", 20)
        params = {"limit": limit}
        if scope == "mine":
            params["scope"] = "mine"
        result = await _get("/scans", params)
        scans = result.get("scans", result) if isinstance(result, dict) else result
        return _ok(scans)

    # ── Agent scans ─────────────────────────────────────────────────────────
    if name == "triksha_agent_scan_start":
        template = args["request_body_template"]
        if "__PROMPT__" not in template:
            template = '{"message": "__PROMPT__"}'
        curl_config = {
            "endpoint": args["agent_endpoint"],
            "request_body_template": template,
        }
        if args.get("headers"):
            curl_config["headers"] = args["headers"]
        body = {
            "agent_name": args["agent_name"],
            "agent_endpoint": args["agent_endpoint"],
            "curl_config": curl_config,
        }
        if args.get("agent_context"):
            body["agent_context"] = args["agent_context"]
        if args.get("framework"):
            body["framework"] = args["framework"]
        result = await _post("/agents/scan", body, timeout=30)
        return _ok(result)

    if name == "triksha_agent_scan_get":
        result = await _get(f"/agents/scan/{args['scan_id']}")
        # Surface key fields prominently
        res = result.get("results") or {}
        return _ok({
            "scan_id": result.get("scan_id"),
            "agent_name": result.get("agent_name"),
            "status": result.get("status"),
            "progress": result.get("progress"),
            "total_tests": res.get("total_tests", 0),
            "bypassed": res.get("bypassed", 0),
            "blocked": res.get("blocked", 0),
            "bypass_rate": res.get("bypass_rate"),
            "attack_results": (res.get("attack_results") or [])[:30],
        })

    if name == "triksha_agent_scans_list":
        result = await _get("/agents/scans", {"limit": args.get("limit", 20)})
        return _ok(result)

    if name == "triksha_agent_scan_cancel":
        result = await _post(f"/agents/scan/{args['scan_id']}/cancel")
        return _ok(result)

    # ── MCP scans ───────────────────────────────────────────────────────────
    if name == "triksha_mcp_scan_start":
        body = {
            "config_file": args["config_json"],
            "file_name": args.get("scan_name", "MCP Scan"),
            "scan_name": args.get("scan_name", "MCP Scan"),
            "timeout": args.get("timeout", 30),
        }
        result = await _post("/mcp/scan", body, timeout=60)
        return _ok(result)

    if name == "triksha_mcp_scan_get":
        result = await _get(f"/mcp/scan/{args['scan_id']}")
        return _ok(result)

    if name == "triksha_mcp_scans_list":
        scope = args.get("scope", "all")
        params = {"limit": args.get("limit", 20)}
        if scope == "mine":
            params["scope"] = "mine"
        result = await _get("/mcp/scans", params)
        return _ok(result)

    if name == "triksha_mcp_tool_scan":
        tool_name = args["tool_name"]
        server_url = args["server_url"]
        transport = args.get("transport", "streamable_http")
        config = json.dumps({
            "name": tool_name,
            "config": {
                "server_params": {
                    "url": server_url,
                    "type": transport,
                    "optional": {"timeout": args.get("timeout", 30)},
                }
            },
        })
        body = {
            "tool_id": tool_name,
            "tool_name": tool_name,
            "tenant_id": "triksha-mcp",
            "user_id": USERNAME,
            "config": config,
            "timeout": args.get("timeout", 30),
        }
        result = await _post("/mcp/tool-scan/scan", body, timeout=90)
        return _ok(result)

    # ── Dataset poisoning ───────────────────────────────────────────────────
    if name == "triksha_dataset_poisoning_analyze":
        raw = args["dataset"]
        fmt = args.get("file_format", "json")
        scan_name = args.get("scan_name", "Dataset Analysis")

        # Build file-like content
        if fmt == "json":
            filename = "dataset.json"
            content_type = "application/json"
            # Ensure it's valid JSON
            try:
                parsed = json.loads(raw)
                content = json.dumps(parsed).encode()
            except json.JSONDecodeError:
                content = raw.encode()
        elif fmt == "csv":
            filename = "dataset.csv"
            content_type = "text/csv"
            content = raw.encode()
        elif fmt == "jsonl":
            filename = "dataset.jsonl"
            content_type = "application/x-jsonlines"
            content = raw.encode()
        else:
            filename = "dataset.txt"
            content_type = "text/plain"
            content = raw.encode()

        files = {"dataset_file": (filename, io.BytesIO(content), content_type)}
        data = {"scan_name": scan_name}
        result = await _post("/dataset/analyze-poisoning", data=data, files=files, timeout=120)
        return _ok(result)

    if name == "triksha_dataset_analysis_get":
        result = await _get(f"/dataset/analysis/{args['analysis_id']}")
        return _ok(result)

    if name == "triksha_dataset_analyses_list":
        result = await _get("/dataset/analyses", {"limit": args.get("limit", 20)})
        return _ok(result)

    # ── Prompt hardening ────────────────────────────────────────────────────
    if name == "triksha_prompt_harden":
        body = {"system_prompt": args["system_prompt"]}
        if args.get("prompt_name"):
            body["prompt_name"] = args["prompt_name"]
        if args.get("context"):
            body["context"] = args["context"]
        result = await _post("/harden/submit", body)
        return _ok(result)

    if name == "triksha_harden_result":
        job_id = args["job_id"]
        wait = args.get("wait", False)

        async def _fetch_job():
            jobs = await _get("/harden/list")
            for job in (jobs if isinstance(jobs, list) else jobs.get("jobs", [])):
                if job.get("job_id") == job_id:
                    return job
            return None

        if wait:
            deadline = time.time() + 120
            while time.time() < deadline:
                job = await _fetch_job()
                if job is None:
                    return _err(f"Job {job_id} not found")
                if job.get("status") in ("completed", "failed"):
                    return _ok(job)
                await asyncio.sleep(3)
            return _err("Timed out waiting for harden job")
        else:
            job = await _fetch_job()
            if job is None:
                return _err(f"Job {job_id} not found")
            return _ok(job)

    if name == "triksha_harden_list":
        result = await _get("/harden/list")
        jobs = result if isinstance(result, list) else result.get("jobs", result)
        limit = args.get("limit", 20)
        return _ok(jobs[:limit])

    return _err(f"Unknown tool: {name}")


# ── Entrypoint ─────────────────────────────────────────────────────────────────

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
