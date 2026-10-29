"""
Triksha Copilot — the conversational agent on the home page.

An ADK LlmAgent (running on the user's configured provider via PluggableLlm) that
turns natural language into real Triksha actions. Its function tools call the
app's own HTTP endpoints in-process, forwarding the caller's session cookie, so
"run a jailbreak benchmark on gpt-4o" or "scan this MCP server" actually start
the real scans — not a scripted chatbot.

Exposes:
  POST /copilot/chat   — SSE stream of {tool, action, message, done, error} events.
  GET  /copilot/health — whether an LLM provider is configured.
"""
from __future__ import annotations

import os
import re
import json
import uuid
import inspect
import asyncio
import logging
import contextvars
from typing import Dict, Optional

import base64

import requests
from fastapi import APIRouter, Body, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import connectors_store

logger = logging.getLogger(__name__)
router = APIRouter()

_API_BASE = os.getenv("INTERNAL_API_BASE", "http://localhost:8000")
_SESSION_COOKIE = "triksha_session"

# Per-request auth cookie, read by tools (lets us keep one global agent/runner).
_auth_cv: contextvars.ContextVar[str] = contextvars.ContextVar("copilot_auth", default="")

_runner = None  # cached ADK Runner (with a persistent session service)
_session_service = None  # cached session service (independent of the LLM)

_KEY_ENV = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY",
            "gemini": "GEMINI_API_KEY"}
# Same mapping used to check whether a SCAN TARGET provider's key is present.
_TARGET_KEY_ENV = _KEY_ENV


def _reset_runner():
    """Drop the cached runner so the next turn rebuilds with fresh LLM config."""
    global _runner
    _runner = None


def _is_api_key_error(msg: str) -> bool:
    """Heuristic: does this error mean the LLM API key is missing/invalid?"""
    m = (msg or "").lower()
    needles = ["api key not valid", "api_key_invalid", "invalid api key",
               "incorrect api key", "no api key", "not configured",
               "missing credentials", "authentication", "unauthorized",
               "401", "403", "permission_denied"]
    return any(n in m for n in needles)

_APP_NAME = "triksha_copilot"


def _headers() -> dict:
    tok = _auth_cv.get()
    h = {"Content-Type": "application/json"}
    if tok:
        h["Cookie"] = f"{_SESSION_COOKIE}={tok}"
    return h


def _gen_reference_id() -> str:
    return f"OS-{uuid.uuid4().hex[:10].upper()}"


def _post(path: str, body: dict, timeout: int = 60):
    return requests.post(f"{_API_BASE}{path}", json=body, headers=_headers(), timeout=timeout)


def _get(path: str, timeout: int = 30):
    return requests.get(f"{_API_BASE}{path}", headers=_headers(), timeout=timeout)


def _summarize(resp) -> str:
    try:
        data = resp.json()
    except Exception:
        data = {"raw": resp.text[:500]}
    return json.dumps({"http_status": resp.status_code, "response": data}, default=str)[:1500]


# ── Capability catalog (also used to seed the system prompt) ──────────────────
_CAPABILITIES = {
    "benchmark_scan": "Red-team / jailbreak benchmark against an LLM — 50+ attack techniques across jailbreak, prompt-injection, PII, RAG and agentic categories. Page: /scan",
    "mcp_scan": "Security scan of an MCP server config (tool poisoning, injection, excessive permissions). Page: /mcps",
    "agent_discovery": "Discover AI agents in a GitHub repo (framework, tools, LLM, security concerns). Page: /agents",
    "agent_scan": "Active security probe of a live agent endpoint. Page: /agents",
    "prd_review": "Automated security review of a PRD / design doc — surfaces threats & security requirements. Page: /prd",
    "prompt_hardener": "Harden a system prompt against jailbreaks & injection. Page: /harden",
    "dataset_poisoning": "Analyze a dataset for poisoning / adversarial samples. Page: /datasets",
}


def _system_instruction() -> str:
    caps = "\n".join(f"  - {k}: {v}" for k, v in _CAPABILITIES.items())
    return f"""You are **Triksha Copilot**, the AI assistant for the Triksha AI-security platform.
You are the user's first point of contact and you help them operate Triksha through natural language.

Triksha capabilities you can drive with your tools:
{caps}

════════════════════════════════════════
HOW TO COLLECT INPUTS BEFORE A SCAN
════════════════════════════════════════

When a user wants to start a scan, gather the required fields conversationally — one
question at a time, not a long form dump. Use the profiles below:

**BENCHMARK (model jailbreak) SCAN — `start_benchmark_scan`**
Required:
  1. Provider — ask "Which provider? (OpenAI / Anthropic / Google / Self-hosted)"
  2. Model — ask for the model name (e.g. gpt-4o, claude-sonnet-4-6, gemini-2.5-flash).
     For self-hosted also ask for the endpoint URL.
Optional (ask in ONE grouped message after required are confirmed):
  3. System prompt — "What system prompt does the model use? (optional — paste it or skip)"
  4. Use-case flags — "What does the model handle? Pick all that apply:
     RAG / Agentic-AI / PII / Standard-jailbreak / Image-inputs (or say 'standard' if unsure)"
  5. Intensity — "Scan intensity: quick (50 prompts) / standard (200) / deep (1000)? Default: quick"

Defaults when not provided: intensity=quick, use_cases=normal, no system_prompt.

**MCP SERVER SCAN — `start_mcp_scan`**
Required (accept EITHER format):
  Option A — Server URL: ask "What's the MCP server name and URL?"
             Then ask "Server type: HTTP or SSE? (default HTTP)"
             Optionally: "Any auth headers? (e.g. Authorization: Bearer …)"
  Option B — Full JSON config: if the user pastes a JSON block, use it directly as `config_file`.
When using Option A, pass server_name, server_url, server_type, headers_json to the tool.

**AGENT SCAN — `start_agent_scan`**
Required:
  1. Agent name — "What's the agent called?"
  2. cURL command — "Paste the cURL command to call the agent. Put `__PROMPT__` where the
     adversarial message goes in the request body. The tool extracts the endpoint and auth
     headers automatically."
     If the user doesn't have a cURL, explain that it's needed so the scanner knows how to
     call the agent (endpoint, auth headers, request body format). Do NOT accept a bare URL.
Optional:
  3. System prompt / context — "What does this agent do? Paste its system prompt or describe it.
     (optional — helps generate more targeted attacks)"

════════════════════════════════════════
GENERAL RULES
════════════════════════════════════════
- Be concise, friendly and action-oriented. Prefer DOING over explaining.
- When the user asks to run something, collect the above inputs first, THEN call the tool.
- Never batch all questions at once — ask for required fields first, then optionals together.
- After starting ANY scan (benchmark, mcp, agent), immediately call `poll_scan_result`
  with the returned scan_id and kind. While it runs, tell the user the scan is running in
  the background. When `poll_scan_result` returns, report the summary and share the `link`
  as a clickable URL so the user can view full results (e.g. "View results: /mcps?highlight=…").
  Do NOT ask the user to navigate to a page themselves — provide the link directly.
- For general questions about AI security, attack techniques, or how Triksha works, just answer.
- Never invent scan ids or results — only report what tools return.

Connectors: the user can connect external tools on the Connectors page (Jira, remote
MCP servers, etc.). Use `list_connectors` to see what's available, `jira_search` /
`jira_create_issue` to work with their Jira. Tools from connected MCP servers are
exposed directly as their own tools named `mcp_<server>_<tool>` — prefer those when
present; otherwise fall back to `list_mcp_tools` / `call_mcp_tool`. If a connector tool
reports that none is enabled, tell the user to connect one on the Connectors page.

You support these target LLM providers for benchmark scans: openai, anthropic, gemini, self-hosted."""


# ── Tools (async callables; docstrings are the tool descriptions for ADK) ─────
async def list_capabilities() -> str:
    """List everything Triksha can do, with the page each feature lives on.

    Returns: JSON object mapping capability name → description.
    """
    return json.dumps(_CAPABILITIES)


async def navigate(page: str) -> str:
    """Open a Triksha page in the UI for the user.

    Args:
        page: One of home, scan, mcps, agents, prd, datasets, sandbox, harden.

    Returns: confirmation string. The UI listens for this and routes the user there.
    """
    valid = {"home": "/", "scan": "/scan", "mcps": "/mcps", "agents": "/agents",
             "prd": "/prd", "datasets": "/datasets",
             "sandbox": "/sandbox", "harden": "/harden"}
    route = valid.get(page.lower().strip())
    if not route:
        return f"error: unknown page '{page}'. Valid: {', '.join(valid)}"
    return json.dumps({"navigate": route})


async def start_benchmark_scan(scan_name: str, target_provider: str,
                               target_model: str = "",
                               system_prompt: str = "",
                               use_cases: str = "normal",
                               scan_intensity: str = "quick",
                               self_hosted_url: str = "") -> str:
    """Start a red-team / jailbreak benchmark scan against an LLM.

    Args:
        scan_name: A short human name for this scan.
        target_provider: The target LLM provider — openai, anthropic, gemini, or self-hosted.
        target_model: The target model id (e.g. gpt-4o, claude-sonnet-4-6, gemini-2.5-flash).
        system_prompt: The system prompt the target model uses (optional but improves attack quality).
        use_cases: Comma-separated flags describing what the model handles.
                   Options: rag, agentic, pii, normal, image. Default: normal.
        scan_intensity: quick (50 prompts) | standard (200) | deep (1000). Default: quick.
        self_hosted_url: Base URL for self-hosted provider (e.g. http://localhost:11434).

    Returns: JSON with http_status and the API response (includes scan_id when queued).
    """
    provider = target_provider.lower().strip()
    key_var = _TARGET_KEY_ENV.get(provider)
    if key_var and not os.environ.get(key_var):
        label = target_model or f"{target_provider} models"
        return json.dumps({
            "needs_provider_key": target_provider,
            "message": (f"To scan **{label}** I need a **{target_provider.title()} API key** — "
                        f"this is separate from the key used by the copilot itself. "
                        f"Add it below and ask me again to start the scan."),
        })

    # Build model entry
    model_entry: dict = {"provider": provider}
    if target_model:
        model_entry["model_id"] = target_model
    if provider == "self-hosted" and self_hosted_url:
        model_entry["custom_config"] = {"base_url": self_hosted_url}

    # Parse use-case flags
    flags = {f.strip().lower() for f in use_cases.split(",")}
    attack_cfg: dict = {
        "scan_intensity": scan_intensity.lower() if scan_intensity in ("quick", "standard", "deep") else "quick",
        "is_rag_based":  "rag" in flags,
        "is_agentic":    "agentic" in flags,
        "handles_pii":   "pii" in flags,
        "is_normal":     "normal" in flags or not ({"rag", "agentic", "pii", "image"} & flags),
        "is_image_based": "image" in flags,
    }
    if system_prompt:
        attack_cfg["target_model_context"] = {"system_prompt": system_prompt}

    body = {"scan_name": scan_name, "models": [model_entry], "attack_config": attack_cfg}
    return await asyncio.to_thread(lambda: _summarize(_post("/scan", body)))


async def start_mcp_scan(scan_name: str = "MCP scan",
                         config_file: str = "",
                         server_url: str = "",
                         server_type: str = "http",
                         headers_json: str = "{}") -> str:
    """Start a security scan of an MCP server.

    Accepts EITHER a full JSON config string OR a server URL (simpler).

    Args:
        scan_name: A short name for the scan.
        config_file: Full MCP config as a JSON string (pass this if the user pasted a JSON block).
        server_url: The MCP server URL (use this instead of config_file when the user gives a URL).
        server_type: http or sse (default http). Only used when server_url is provided.
        headers_json: JSON object of headers to send (e.g. '{"Authorization":"Bearer xyz"}').
                      Only used when server_url is provided.

    Returns: JSON with http_status and the API response (includes scan_id when queued).
    """
    if not config_file and server_url:
        # Build a minimal MCP config from the URL
        try:
            extra_headers = json.loads(headers_json) if headers_json and headers_json.strip() not in ("{}", "") else {}
        except Exception:
            extra_headers = {}
        server_key = scan_name.lower().replace(" ", "_") or "server"
        config_obj = {
            "mcpServers": {
                server_key: {
                    "url": server_url,
                    "transport": server_type.lower(),
                    **({"headers": extra_headers} if extra_headers else {}),
                }
            }
        }
        config_file = json.dumps(config_obj)

    if not config_file:
        return json.dumps({"error": "Provide either config_file (JSON) or server_url."})

    body = {"config_file": config_file, "scan_name": scan_name,
            "reference_id": _gen_reference_id()}
    return await asyncio.to_thread(lambda: _summarize(_post("/mcp/scan", body)))


async def discover_agents(repo_url: str, branch: str = "main") -> str:
    """Discover AI agents in a GitHub repository (passive — reads code, no probing).

    Args:
        repo_url: The repository URL to scan.
        branch: Branch to scan (default main).

    Returns: JSON with http_status and the discovered agents.
    """
    body = {"repo_url": repo_url, "branch": branch}
    return await asyncio.to_thread(lambda: _summarize(_post("/agents/discover", body, timeout=120)))


def _parse_curl(curl_str: str) -> dict:
    """Extract endpoint URL, headers, and body template from a cURL command string."""
    import re as _re
    result = {"endpoint": "", "headers": {}, "body_template": ""}
    s = curl_str.replace("\\\n", " ").replace("\\\r\n", " ").strip()
    if s.lower().startswith("curl"):
        s = s[4:].strip()
    # Extract URL (quoted or bare)
    m = _re.search(r"['\"]?(https?://[^\s'\"]+)['\"]?", s)
    if m:
        result["endpoint"] = m.group(1).rstrip("'\"")
    # Extract headers (exclude Content-Type, that's implicit)
    header_re = _re.compile(r'(?:-H|--header)\s+[\'"]([^\'"]+)[\'"]', _re.IGNORECASE)
    for hm in header_re.finditer(s):
        colon = hm.group(1).find(":")
        if colon > 0:
            k = hm.group(1)[:colon].strip()
            v = hm.group(1)[colon + 1:].strip()
            if k.lower() != "content-type":
                result["headers"][k] = v
    # Extract -d / --data body template — handle single-quoted (may contain ") and double-quoted (may contain ')
    # Try single-quoted first (match from ' to closing ')
    sq_m = _re.search(r"(?:-d|--data(?:-raw)?)\s+'([^']*)'", s, _re.DOTALL)
    dq_m = _re.search(r'(?:-d|--data(?:-raw)?)\s+"((?:[^"\\]|\\.)*)"', s, _re.DOTALL)
    if sq_m:
        result["body_template"] = sq_m.group(1)
    elif dq_m:
        result["body_template"] = dq_m.group(1).replace('\\"', '"')
    return result


async def start_agent_scan(agent_name: str,
                           curl_command: str,
                           agent_context: str = "") -> str:
    """Start an ACTIVE security scan (autonomous red-team) against a LIVE AI agent.

    The scanner probes the agent with adversarial prompts to find jailbreaks, tool misuse,
    prompt injection and data exfiltration.

    Args:
        agent_name: A short name for the agent under test.
        curl_command: The cURL command used to call the agent. The user MUST include
                      `__PROMPT__` in the request body where the adversarial message goes.
                      The tool extracts the endpoint URL and auth headers automatically.
        agent_context: The agent's system prompt or a description of its purpose/tools.
                       Optional but strongly recommended — it helps generate targeted attacks.

    Returns: JSON with http_status and the API response (includes scan_id when queued).
    """
    if not curl_command or not curl_command.strip():
        return json.dumps({"error": "curl_command is required. Ask the user to provide the cURL command for their agent with __PROMPT__ in the body."})

    parsed = _parse_curl(curl_command)
    endpoint = parsed["endpoint"]
    if not endpoint:
        return json.dumps({"error": "Could not extract endpoint URL from the cURL command. Ask the user to double-check it."})

    body_template = parsed["body_template"] or '{"message": "__PROMPT__"}'
    if "__PROMPT__" not in body_template:
        body_template = '{"message": "__PROMPT__"}'

    curl_config: dict = {
        "endpoint": endpoint,
        "request_body_template": body_template,
    }
    if parsed["headers"]:
        curl_config["headers"] = parsed["headers"]

    body: dict = {
        "agent_name": agent_name,
        "agent_endpoint": endpoint,
        "curl_config": curl_config,
    }
    if agent_context:
        body["agent_context"] = agent_context
    if parsed["headers"]:
        body["auth_headers"] = parsed["headers"]
    return await asyncio.to_thread(lambda: _summarize(_post("/agents/scan", body, timeout=30)))


async def harden_prompt(system_prompt: str, prompt_name: str = "Untitled prompt") -> str:
    """Harden a system prompt against jailbreaks and prompt injection.

    Args:
        system_prompt: The system prompt text to harden.
        prompt_name: A short name for this prompt.

    Returns: JSON with http_status and the API response (includes job id).
    """
    body = {"system_prompt": system_prompt, "prompt_name": prompt_name,
            "reference_id": _gen_reference_id()}
    return await asyncio.to_thread(lambda: _summarize(_post("/harden/submit", body)))


async def analyze_dataset_poisoning(dataset_samples: str, scan_name: str = "Dataset Poisoning Scan") -> str:
    """Analyze a dataset for data poisoning / adversarial sample injection attacks.

    Pass the dataset as a JSON-encoded list of samples. Each sample should be a
    dict with at least a 'text' key (e.g. [{"text": "sample text"}, ...]).
    The analyser checks for prompt-injection strings, backdoor triggers, label
    flipping, and other poisoning indicators.

    Args:
        dataset_samples: JSON array of dataset samples (each has a 'text' field).
        scan_name: A short name for this poisoning analysis run.

    Returns: JSON with analysis results including poisoning score and suspicious samples.
    """
    import io as _io
    import csv as _csv
    try:
        samples = json.loads(dataset_samples)
        if not isinstance(samples, list):
            return json.dumps({"error": "dataset_samples must be a JSON array"})
    except Exception:
        return json.dumps({"error": "dataset_samples must be valid JSON (a list of dicts with 'text' keys)"})

    # Build a CSV in-memory to send as a multipart upload
    buf = _io.StringIO()
    writer = _csv.DictWriter(buf, fieldnames=["text"])
    writer.writeheader()
    for s in samples:
        if isinstance(s, dict):
            writer.writerow({"text": str(s.get("text", ""))})
        else:
            writer.writerow({"text": str(s)})
    csv_bytes = buf.getvalue().encode("utf-8")

    def _upload():
        import requests as _req
        url = f"http://localhost:{os.environ.get('PORT', '8000')}/dataset/analyze-poisoning"
        files = {"dataset_file": (f"{scan_name}.csv", csv_bytes, "text/csv")}
        data = {"scan_name": scan_name}
        # Don't pass Content-Type header — requests sets it automatically for multipart
        tok = _auth_cv.get()
        hdrs = {}
        if tok:
            hdrs["Cookie"] = f"{_SESSION_COOKIE}={tok}"
        resp = _req.post(url, files=files, data=data, headers=hdrs, timeout=60)
        return resp

    resp = await asyncio.to_thread(_upload)
    return _summarize(resp)


async def review_prd(document_text: str, author: str = "copilot") -> str:
    """Start an automated security review of a PRD / design document.

    Args:
        document_text: The full text of the PRD / design doc.
        author: The author's name or email.

    Returns: JSON with http_status and the API response (includes review id).
    """
    body = {"document_text": document_text, "author": author}
    return await asyncio.to_thread(lambda: _summarize(_post("/security-review", body)))


async def list_recent_scans(kind: str = "benchmark") -> str:
    """List recent scans of a given kind so you can report status to the user.

    Args:
        kind: One of benchmark, mcp, agent, prd, harden, dataset.

    Returns: JSON with http_status and the list.
    """
    routes = {"benchmark": "/scans", "mcp": "/mcp/scans", "agent": "/agents/scans",
              "prd": "/security-review/list", "harden": "/harden/list",
              "dataset": "/dataset/analyses"}
    path = routes.get(kind.lower().strip())
    if not path:
        return f"error: unknown kind '{kind}'. Valid: {', '.join(routes)}"
    return await asyncio.to_thread(lambda: _summarize(_get(path)))


async def poll_scan_result(scan_id: str, kind: str, max_wait_seconds: int = 300) -> str:
    """Wait for a scan to complete and return a result summary with a deep link.

    Call this immediately after starting any scan. It polls the scan until it
    finishes (or times out) and returns a human-readable summary plus a URL
    the user can click to view the full results.

    Args:
        scan_id: The scan ID returned by the scan-start tool.
        kind: One of: benchmark, mcp, agent.
        max_wait_seconds: Maximum seconds to wait (default 300 = 5 min).

    Returns: JSON with status, summary text, and a link URL to view the scan.
    """
    import time

    _POLL_INTERVAL = 8
    _TERMINAL = {"completed", "failed", "error", "cancelled", "done"}

    _status_path = {
        "benchmark": f"/scan/{scan_id}/status",
        "mcp":       f"/mcp/scan/{scan_id}",
        "agent":     f"/agents/scan/{scan_id}",
    }
    _link = {
        "benchmark": f"/scan?highlight={scan_id}",
        "mcp":       f"/mcps?highlight={scan_id}",
        "agent":     f"/agents?highlight={scan_id}",
    }

    kind = kind.lower().strip()
    if kind not in _status_path:
        return json.dumps({"error": f"Unknown kind '{kind}'. Use: benchmark, mcp, agent."})

    link = _link[kind]
    deadline = time.time() + max_wait_seconds

    def _get_status(data: dict) -> str:
        if kind == "benchmark":
            return data.get("status", "running")
        if kind == "mcp":
            return (data.get("scan") or {}).get("status", "running")
        if kind == "agent":
            return data.get("status", "running")
        return "running"

    def _build_summary(status: str, data: dict) -> str:
        try:
            if kind == "benchmark":
                # Try summary block first, fall back to statistics
                results = data.get("results") or data
                summ   = results.get("summary") or {}
                stats  = results.get("statistics") or results.get("safety_metrics") or {}
                total    = (summ.get("total_prompts") or stats.get("total_tests") or
                            results.get("total_tests") or 0)
                bypassed = (summ.get("successful_bypasses") or
                            stats.get("successful_responses") or
                            results.get("bypassed") or 0)
                blocked  = (summ.get("failed_bypasses") or
                            stats.get("refusal_responses") or
                            (total - bypassed) or 0)
                rate = f"{100 * bypassed / total:.1f}%" if total else "N/A"

                lines = [f"**Benchmark scan {status}**"]
                lines.append(f"- Prompts run: **{total}**")
                lines.append(f"- Bypassed guardrails: **{bypassed}** ({rate})")
                lines.append(f"- Blocked / refused: **{blocked}**")

                # Top bypassed technique if attack_results available
                attack_results = results.get("attack_results") or []
                if attack_results:
                    technique_counts: dict = {}
                    for r in attack_results:
                        if r.get("bypassed"):
                            t = r.get("technique") or r.get("category") or "Unknown"
                            technique_counts[t] = technique_counts.get(t, 0) + 1
                    if technique_counts:
                        top_t = max(technique_counts, key=technique_counts.__getitem__)
                        lines.append(f"- Most effective technique: **{top_t}** ({technique_counts[top_t]} bypasses)")

                verdict = ("🔴 High risk" if total and bypassed / total > 0.4
                           else "🟡 Moderate risk" if total and bypassed / total > 0.1
                           else "🟢 Low risk")
                lines.append(f"\n{verdict} — [View full results]({link})")
                return "\n".join(lines)

            if kind == "mcp":
                scan = data.get("scan", {})
                results = scan.get("results") or {}
                servers = results.get("servers") or []
                total_findings = 0
                sev: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                finding_names: list = []
                for s in servers:
                    for f in (s.get("security_findings", {}).get("pattern_based") or []):
                        sk = (f.get("severity") or "medium").lower()
                        sev[sk] = sev.get(sk, 0) + 1
                        total_findings += 1
                        if f.get("name") or f.get("title"):
                            finding_names.append(f.get("name") or f.get("title"))
                    ai = (s.get("security_findings", {}).get("ai_analysis") or {})
                    for f in (ai.get("findings") or []):
                        sk = (f.get("severity") or "medium").lower()
                        sev[sk] = sev.get(sk, 0) + 1
                        total_findings += 1
                        if f.get("name") or f.get("title"):
                            finding_names.append(f.get("name") or f.get("title"))

                lines = [f"**MCP scan {status}**"]
                lines.append(f"- Servers scanned: **{len(servers)}**")
                lines.append(f"- Total findings: **{total_findings}**")
                if sev["critical"]:
                    lines.append(f"  - 🔴 Critical: {sev['critical']}")
                if sev["high"]:
                    lines.append(f"  - 🟠 High: {sev['high']}")
                if sev["medium"]:
                    lines.append(f"  - 🟡 Medium: {sev['medium']}")
                if sev["low"] or sev["info"]:
                    lines.append(f"  - 🔵 Low/Info: {sev['low'] + sev['info']}")
                if finding_names:
                    top = finding_names[:3]
                    lines.append(f"- Top findings: {', '.join(top)}")
                verdict = ("🔴 High risk" if sev["critical"] or sev["high"] > 2
                           else "🟡 Moderate risk" if total_findings > 0
                           else "🟢 No findings")
                lines.append(f"\n{verdict} — [View full results]({link})")
                return "\n".join(lines)

            if kind == "agent":
                results = data.get("results") or {}
                total    = results.get("total_tests") or 0
                bypassed = results.get("bypassed") or 0
                blocked  = results.get("blocked") or (total - bypassed)
                rate     = f"{results.get('bypass_rate', 0):.1f}%" if total else "N/A"
                partial  = results.get("partial_bypass_count") or 0
                tools    = results.get("discovered_tools") or []
                cats     = results.get("categories") or []

                lines = [f"**Agent scan {status}**"]
                lines.append(f"- Attack prompts sent: **{total}**")
                lines.append(f"- Bypassed: **{bypassed}** ({rate})")
                if partial:
                    lines.append(f"- Partial bypasses: **{partial}**")
                lines.append(f"- Blocked / refused: **{blocked}**")
                if tools:
                    lines.append(f"- Tools discovered: **{len(tools)}** ({', '.join(t.get('name','?') for t in tools[:4])}{'…' if len(tools) > 4 else ''})")
                # Top vulnerable categories
                vuln_cats = [c for c in cats if c.get("bypassed", 0) > 0]
                vuln_cats_sorted = sorted(vuln_cats, key=lambda c: c.get("bypass_rate", 0), reverse=True)
                if vuln_cats_sorted:
                    top = vuln_cats_sorted[0]
                    lines.append(f"- Most vulnerable category: **{top.get('category', 'Unknown')}** ({top.get('bypass_rate', 0):.0f}% bypass rate)")

                verdict = ("🔴 High risk" if total and bypassed / total > 0.4
                           else "🟡 Moderate risk" if total and bypassed / total > 0.1
                           else "🟢 Low risk" if total else "⚪ No results")
                lines.append(f"\n{verdict} — [View full results]({link})")
                return "\n".join(lines)

        except Exception:
            pass
        return f"Scan {status}. [View results]({link})"

    while time.time() < deadline:
        try:
            path = _status_path[kind]
            resp = await asyncio.to_thread(lambda: _get(path))
            if resp.status_code in (200, 202):
                data = resp.json()
                st = _get_status(data)
                if st in _TERMINAL:
                    # Fetch full results for richer summaries
                    if kind == "benchmark" and st == "completed":
                        try:
                            rr = await asyncio.to_thread(lambda: _get(f"/scan/{scan_id}/results"))
                            if rr.status_code == 200:
                                data = rr.json()
                        except Exception:
                            pass
                    elif kind == "agent" and st == "completed":
                        try:
                            rr = await asyncio.to_thread(lambda: _get(f"/agents/scan/{scan_id}"))
                            if rr.status_code == 200:
                                data = rr.json()
                        except Exception:
                            pass
                    summary = _build_summary(st, data)
                    return json.dumps({"status": st, "summary": summary, "link": link})
        except Exception:
            pass
        await asyncio.sleep(_POLL_INTERVAL)

    return json.dumps({
        "status": "still_running",
        "summary": f"Scan is still running after {max_wait_seconds}s. Check back soon.",
        "link": link,
    })


# ── Connector-backed tools (Jira + remote MCP servers) ───────────────────────
# These read the instance-global connectors store at call time, so adding/removing
# a connector takes effect immediately without rebuilding the cached runner.
def _first_copilot_connector(ctype: str):
    try:
        for c in connectors_store.get_copilot_connectors():
            if c["type"] == ctype:
                return c
    except Exception as exc:  # pragma: no cover
        logger.warning("connector lookup failed: %s", exc)
    return None


def _jira_conn():
    c = _first_copilot_connector("jira")
    if not c:
        return None
    cfg, sec = c.get("config", {}), c.get("secrets", {})
    base = (cfg.get("base_url") or "").rstrip("/")
    email, token = cfg.get("email"), sec.get("api_token")
    if not (base and email and token):
        return None
    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    return base, auth, cfg.get("project_key")


async def list_connectors() -> str:
    """List the external connectors (Jira, MCP servers, …) the user has connected
    and enabled for the Copilot, so you know which connector tools are usable.

    Returns: JSON array of {name, type}.
    """
    try:
        cs = connectors_store.get_copilot_connectors(include_secrets=False)
    except Exception as exc:
        return f"error: {exc}"
    return json.dumps([{"name": c["name"], "type": c["type"]} for c in cs])


async def jira_search(jql: str, max_results: int = 10) -> str:
    """Search Jira issues with a JQL query, via the connected Jira connector.

    Args:
        jql: A Jira JQL query, e.g. 'project = SEC AND status = "To Do"'.
        max_results: Max issues to return (default 10).

    Returns: JSON with the matching issues (key, summary, status) or an error.
    """
    conn = _jira_conn()
    if not conn:
        return "error: no Jira connector is enabled for the Copilot. Connect one on the Connectors page."
    base, auth, _ = conn

    def _do():
        r = requests.get(f"{base}/rest/api/2/search",
                         params={"jql": jql, "maxResults": int(max_results),
                                 "fields": "summary,status"},
                         headers={"Authorization": f"Basic {auth}", "Accept": "application/json"},
                         timeout=30)
        if r.status_code != 200:
            return f"error: Jira returned HTTP {r.status_code}: {r.text[:300]}"
        issues = r.json().get("issues", [])
        out = [{"key": i.get("key"),
                "summary": i.get("fields", {}).get("summary"),
                "status": (i.get("fields", {}).get("status") or {}).get("name")}
               for i in issues]
        return json.dumps({"count": len(out), "issues": out})

    return await asyncio.to_thread(_do)


async def jira_create_issue(summary: str, description: str = "",
                            project_key: str = "", issue_type: str = "Task") -> str:
    """Create a Jira issue via the connected Jira connector.

    Args:
        summary: The issue summary / title.
        description: The issue description (plain text).
        project_key: Project key (defaults to the connector's configured project).
        issue_type: Issue type name (default Task).

    Returns: JSON with the created issue key/url, or an error.
    """
    conn = _jira_conn()
    if not conn:
        return "error: no Jira connector is enabled for the Copilot. Connect one on the Connectors page."
    base, auth, default_pk = conn
    pk = (project_key or default_pk or "").strip()
    if not pk:
        return "error: no project_key — set a default in the Jira connector or pass project_key."

    def _do():
        payload = {"fields": {"project": {"key": pk}, "summary": summary,
                              "description": description or summary,
                              "issuetype": {"name": issue_type}}}
        r = requests.post(f"{base}/rest/api/2/issue", json=payload,
                          headers={"Authorization": f"Basic {auth}",
                                   "Content-Type": "application/json"},
                          timeout=30)
        if r.status_code not in (200, 201):
            return f"error: Jira returned HTTP {r.status_code}: {r.text[:300]}"
        key = r.json().get("key")
        return json.dumps({"key": key, "url": f"{base}/browse/{key}"})

    return await asyncio.to_thread(_do)


async def list_mcp_tools(connector_name: str = "") -> str:
    """List the tools exposed by connected MCP servers (those enabled for the Copilot).

    Args:
        connector_name: Optional — limit to one MCP connector by name. Empty = all.

    Returns: JSON mapping connector name → list of {name, description}.
    """
    try:
        import mcp_connector_client
    except Exception:
        return "error: MCP client unavailable in this build."
    out: Dict[str, object] = {}
    for c in connectors_store.get_copilot_connectors():
        if c["type"] != "mcp":
            continue
        if connector_name and c["name"] != connector_name:
            continue
        values = {**c.get("config", {}), **c.get("secrets", {})}
        try:
            tools = await mcp_connector_client.list_tools(values)
            out[c["name"]] = [{"name": t["name"], "description": t["description"]} for t in tools]
        except Exception as exc:
            out[c["name"]] = f"error: {exc}"
    if not out:
        return "error: no MCP connector is enabled for the Copilot. Connect one on the Connectors page."
    return json.dumps(out)


async def call_mcp_tool(connector_name: str, tool_name: str, arguments_json: str = "{}") -> str:
    """Call a tool on a connected remote MCP server.

    Args:
        connector_name: The name of the MCP connector (see list_mcp_tools / list_connectors).
        tool_name: The MCP tool to invoke.
        arguments_json: JSON object string of the tool arguments (default '{}').

    Returns: The tool's text result, or an error.
    """
    try:
        import mcp_connector_client
    except Exception:
        return "error: MCP client unavailable in this build."
    target = None
    for c in connectors_store.get_copilot_connectors():
        if c["type"] == "mcp" and c["name"] == connector_name:
            target = c
            break
    if not target:
        return f"error: no enabled MCP connector named '{connector_name}'."
    try:
        args = json.loads(arguments_json or "{}")
    except json.JSONDecodeError:
        return "error: arguments_json is not valid JSON."
    values = {**target.get("config", {}), **target.get("secrets", {})}
    try:
        result = await mcp_connector_client.call_tool(values, tool_name, args)
    except Exception as exc:
        return f"error: MCP tool call failed: {exc}"
    return (result or "")[:4000]


_TOOLS = [list_capabilities, navigate, start_benchmark_scan, start_mcp_scan,
          discover_agents, start_agent_scan, harden_prompt, analyze_dataset_poisoning,
          review_prd, list_recent_scans, poll_scan_result,
          list_connectors, jira_search, jira_create_issue, list_mcp_tools, call_mcp_tool]


# ── Dynamic per-tool MCP tools (Claude-style: each remote tool is its own tool) ──
_JSON_PY_TYPE = {"string": str, "integer": int, "number": float,
                 "boolean": bool, "array": list, "object": dict}


def _sanitize_tool_name(s: str) -> str:
    return (re.sub(r"[^a-zA-Z0-9_]", "_", s or "") or "tool")[:50]


def _make_mcp_tool(conn_name: str, values: dict, tool: dict):
    """Generate a callable ADK tool that proxies one remote MCP tool. The
    declared signature/annotations come from the tool's input schema so the LLM
    sees the real parameters; the body forwards them to mcp_connector_client."""
    tname = tool.get("name")
    desc = (tool.get("description") or f"Call '{tname}' on MCP server '{conn_name}'.")[:1000]
    schema = tool.get("input_schema") or {}
    props = schema.get("properties") or {}
    required = set(schema.get("required") or [])

    async def _fn(**kwargs):
        try:
            import mcp_connector_client
            res = await mcp_connector_client.call_tool(values, tname, kwargs)
            return (res or "")[:4000]
        except Exception as exc:  # noqa: BLE001
            return f"error: MCP tool '{tname}' failed: {exc}"

    params = []
    annotations: Dict[str, object] = {}
    for pname, pspec in props.items():
        if not isinstance(pname, str) or not pname.isidentifier():
            continue
        ann = _JSON_PY_TYPE.get((pspec or {}).get("type"), str)
        annotations[pname] = ann
        if pname in required:
            params.append(inspect.Parameter(pname, inspect.Parameter.KEYWORD_ONLY, annotation=ann))
        else:
            params.append(inspect.Parameter(pname, inspect.Parameter.KEYWORD_ONLY,
                                            annotation=ann, default=None))
    annotations["return"] = str
    _fn.__signature__ = inspect.Signature(params)
    _fn.__annotations__ = annotations
    _fn.__name__ = f"mcp_{_sanitize_tool_name(conn_name)}_{_sanitize_tool_name(tname)}"
    _fn.__doc__ = desc
    return _fn


def _build_connector_tools() -> list:
    """One ADK tool per cached MCP tool across enabled-for-Copilot connectors."""
    out: list = []
    try:
        conns = connectors_store.get_copilot_connectors()
    except Exception as exc:  # pragma: no cover
        logger.warning("could not load copilot connectors: %s", exc)
        return out
    for c in conns:
        if c.get("type") != "mcp":
            continue
        cached = (c.get("config") or {}).get("mcp_tools") or []
        values = {**c.get("config", {}), **c.get("secrets", {})}
        for t in cached:
            if not t.get("name"):
                continue
            try:
                out.append(_make_mcp_tool(c["name"], values, t))
            except Exception as exc:  # noqa: BLE001
                logger.warning("could not build MCP tool %s: %s", t.get("name"), exc)
    return out


# ── Agent / runner lifecycle ──────────────────────────────────────────────────
def _adk_db_url() -> Optional[str]:
    """SQLAlchemy URL for ADK's persistent session store (reuse the app DB).
    ADK uses create_async_engine, so map to an async driver dialect."""
    url = os.getenv("DATABASE_URL", "")
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        return "postgresql+asyncpg://" + url[len("postgresql://"):]
    if url.startswith("sqlite:///"):
        return "sqlite+aiosqlite:///" + url[len("sqlite:///"):]
    return None


def _get_session_service():
    """Cached PERSISTENT session service (Postgres/SQLite) — independent of the
    LLM, so conversation history/CRUD works even before a key is configured."""
    global _session_service
    if _session_service is not None:
        return _session_service
    db_url = _adk_db_url()
    if db_url:
        try:
            from google.adk.sessions import DatabaseSessionService
            _session_service = DatabaseSessionService(db_url=db_url)
            logger.info("Triksha Copilot: persistent session store (%s)", db_url.split("@")[-1])
            return _session_service
        except Exception as e:  # pragma: no cover
            logger.warning("ADK DatabaseSessionService unavailable (%s); in-memory sessions", e)
    from google.adk.sessions import InMemorySessionService
    _session_service = InMemorySessionService()
    return _session_service


def _get_runner():
    """Build (once) and cache the ADK agent + runner sharing the persistent
    session service so conversation memory survives reloads and restarts."""
    global _runner
    if _runner is not None:
        return _runner
    from google.adk.agents import Agent
    from google.adk.runners import Runner
    from llm_providers import get_adk_model

    model = get_adk_model()  # raises LLMNotConfigured if no key

    # Append one tool per cached remote MCP tool from enabled connectors. If a
    # dynamically-built tool trips up ADK, fall back to the base toolset so the
    # Copilot still works.
    dynamic_tools = _build_connector_tools()
    try:
        agent = Agent(
            name="triksha_copilot",
            model=model,
            instruction=_system_instruction(),
            description="Conversational assistant that operates Triksha via tools.",
            tools=_TOOLS + dynamic_tools,
        )
    except Exception as exc:
        logger.warning("Copilot: dynamic connector tools rejected (%s); using base tools", exc)
        agent = Agent(
            name="triksha_copilot",
            model=model,
            instruction=_system_instruction(),
            description="Conversational assistant that operates Triksha via tools.",
            tools=_TOOLS,
        )
    _runner = Runner(agent=agent, app_name=_APP_NAME, session_service=_get_session_service())
    return _runner


# ── Conversation titles + history reconstruction ─────────────────────────────
def _title_key(user_id: str, cid: str) -> str:
    return f"convtitle:{user_id}:{cid}"


def _get_title(user_id: str, cid: str) -> Optional[str]:
    try:
        import local_auth
        return local_auth.get_config(_title_key(user_id, cid))
    except Exception:
        return None


def _set_title(user_id: str, cid: str, title: str):
    try:
        import local_auth
        local_auth.set_config(_title_key(user_id, cid), (title or "").strip()[:80] or "New chat")
    except Exception:
        pass


def _del_title(user_id: str, cid: str):
    try:
        import local_auth
        local_auth.set_config(_title_key(user_id, cid), "")
    except Exception:
        pass


def _session_to_messages(session) -> list:
    """Reconstruct a [{role, text}] transcript from a session's ADK events,
    merging consecutive same-role turns."""
    msgs = []
    for ev in (getattr(session, "events", None) or []):
        content = getattr(ev, "content", None)
        if not content or not getattr(content, "parts", None):
            continue
        text = "".join(p.text for p in content.parts if getattr(p, "text", None))
        if not text.strip():
            continue
        role = "user" if getattr(content, "role", "") == "user" else "assistant"
        if msgs and msgs[-1]["role"] == role:
            msgs[-1]["text"] += text
        else:
            msgs.append({"role": role, "text": text})
    return msgs


def _user_id_from_token(token: str) -> str:
    try:
        import local_auth
        sess = local_auth.verify_session(token) if token else None
        if sess and sess.get("sub"):
            return sess["sub"]
    except Exception:
        pass
    return "copilot_user"


async def _ensure_session(runner, conversation_id: str, user_id: str) -> str:
    """Get-or-create a session whose id IS the client's conversation_id, so the
    same conversation resumes (with full history) across reloads/restarts."""
    svc = runner.session_service
    try:
        existing = await svc.get_session(
            app_name=_APP_NAME, user_id=user_id, session_id=conversation_id)
        if existing:
            return conversation_id
    except Exception:
        pass
    await svc.create_session(
        app_name=_APP_NAME, user_id=user_id, session_id=conversation_id)
    return conversation_id


def _sse(event: str, data: dict) -> str:
    # data-only SSE with an embedded "type" (matches the app's existing
    # ReadableStream parser that reads the `data:` line and switches on type).
    payload = {"type": event, **data}
    return f"data: {json.dumps(payload, default=str)}\n\n"


# ── Endpoints ──────────────────────────────────────────────────────────────────
class ChatBody(BaseModel):
    message: str
    conversation_id: Optional[str] = None


@router.get("/copilot/health")
def copilot_health():
    """Report whether an LLM provider/key is configured for the copilot."""
    try:
        from llm_providers import is_configured, get_provider
        return {"ready": bool(is_configured()), "provider": get_provider()}
    except Exception as e:
        return {"ready": False, "error": str(e)}


class ConfigureBody(BaseModel):
    provider: str
    api_key: str
    model: Optional[str] = None


@router.post("/copilot/configure")
def copilot_configure(body: ConfigureBody = Body(...)):
    """Set/update the LLM provider + API key on the fly (no restart needed).
    Persists to the local config store and resets the copilot so the next turn
    uses the new key."""
    from fastapi import HTTPException
    provider = (body.provider or "").lower().strip()
    if provider not in _KEY_ENV:
        raise HTTPException(status_code=400, detail="Provider must be openai, anthropic, or gemini.")
    if not body.api_key.strip():
        raise HTTPException(status_code=400, detail="API key is required.")

    key_var = _KEY_ENV[provider]
    # Persist + apply immediately (override any placeholder already in env).
    try:
        import local_auth
        local_auth.set_config("LLM_PROVIDER", provider)
        local_auth.set_config(key_var, body.api_key.strip())
        if body.model:
            local_auth.set_config("LLM_MODEL", body.model.strip())
    except Exception as e:  # pragma: no cover
        logger.warning("could not persist LLM config: %s", e)
    os.environ["LLM_PROVIDER"] = provider
    os.environ[key_var] = body.api_key.strip()
    if body.model:
        os.environ["LLM_MODEL"] = body.model.strip()
    else:
        os.environ.pop("LLM_MODEL", None)

    _reset_runner()
    logger.info("Triksha Copilot: LLM reconfigured → provider '%s'", provider)
    return {"status": "ok", "provider": provider}


@router.post("/copilot/chat")
async def copilot_chat(request: Request, body: ChatBody = Body(...)):
    """Stream a copilot turn as Server-Sent Events."""
    auth_token = request.cookies.get(_SESSION_COOKIE, "")
    conversation_id = body.conversation_id or uuid.uuid4().hex
    user_message = body.message
    user_id = _user_id_from_token(auth_token)

    async def stream():
        _auth_cv.set(auth_token)
        # Build runner / handle missing key gracefully
        try:
            runner = _get_runner()
        except Exception as e:
            from llm_providers import get_provider
            yield _sse("needs_api_key", {
                "provider": get_provider(),
                "message": "No LLM API key is configured yet. Add one to start chatting.",
            })
            yield _sse("done", {"conversation_id": conversation_id})
            return

        from google.genai import types as genai_types
        try:
            session_id = await _ensure_session(runner, conversation_id, user_id)
            # Title the conversation from its first message.
            if not _get_title(user_id, conversation_id):
                _set_title(user_id, conversation_id, user_message)
            content = genai_types.Content(
                role="user", parts=[genai_types.Part.from_text(text=user_message)])

            final_text = ""
            llm_error = ""
            async for event in runner.run_async(
                user_id=user_id,
                session_id=session_id, new_message=content):
                # surface provider/LLM errors (bad key, rate limit, …)
                err_msg = getattr(event, "error_message", None)
                if err_msg:
                    llm_error = err_msg
                parts = (event.content.parts if event.content and event.content.parts else [])
                for part in parts:
                    # surface tool calls as they happen (agentic feel)
                    fc = getattr(part, "function_call", None)
                    if fc is not None:
                        args = dict(fc.args) if getattr(fc, "args", None) else {}
                        yield _sse("tool", {"name": fc.name, "args": args})
                        # navigate tool → also emit a UI action
                        if fc.name == "navigate" and args.get("page"):
                            pass  # actual route comes back in the tool result below
                    # tool results may carry a navigate instruction or a key requirement
                    fr = getattr(part, "function_response", None)
                    if fr is not None:
                        try:
                            resp = fr.response
                            payload = resp.get("result") if isinstance(resp, dict) else resp
                            if isinstance(payload, str):
                                payload = json.loads(payload)
                            if isinstance(payload, dict) and payload.get("navigate"):
                                yield _sse("action", {"type": "navigate", "route": payload["navigate"]})
                            if isinstance(payload, dict) and payload.get("needs_provider_key"):
                                yield _sse("needs_target_key", {
                                    "provider": payload["needs_provider_key"],
                                    "message": payload.get("message", ""),
                                })
                        except Exception:
                            pass
                if event.is_final_response() and parts:
                    for part in parts:
                        if getattr(part, "text", None):
                            final_text += part.text
            if final_text:
                yield _sse("message", {"text": final_text})
            elif llm_error and _is_api_key_error(llm_error):
                from llm_providers import get_provider
                yield _sse("needs_api_key", {
                    "provider": get_provider(),
                    "message": "Your LLM API key looks invalid or isn't set. Add a valid key to continue.",
                })
            elif llm_error:
                yield _sse("error", {"message": f"LLM call failed: {llm_error}"})
            else:
                yield _sse("message", {"text": "(no response)"})
            yield _sse("done", {"conversation_id": conversation_id})
        except Exception as e:
            logger.exception("copilot chat failed")
            yield _sse("error", {"message": str(e)})
            yield _sse("done", {"conversation_id": conversation_id})

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Conversation management (Claude-style sidebar) ────────────────────────────
class RenameBody(BaseModel):
    title: str


@router.get("/copilot/conversations")
async def list_conversations(request: Request):
    """List the user's conversations (most-recent first) for the sidebar."""
    user_id = _user_id_from_token(request.cookies.get(_SESSION_COOKIE, ""))
    svc = _get_session_service()
    try:
        resp = await svc.list_sessions(app_name=_APP_NAME, user_id=user_id)
        sessions = getattr(resp, "sessions", resp) or []
    except Exception as e:
        logger.warning("list_sessions failed: %s", e)
        sessions = []
    out = []
    for s in sessions:
        title = _get_title(user_id, s.id)
        if title == "":
            continue  # soft-deleted title marker
        out.append({"id": s.id, "title": title or "New chat",
                    "updated": getattr(s, "last_update_time", 0) or 0})
    out.sort(key=lambda x: x["updated"], reverse=True)
    return {"conversations": out}


@router.get("/copilot/conversations/{cid}")
async def get_conversation(cid: str, request: Request):
    """Return a conversation's transcript (reconstructed from durable sessions)."""
    from fastapi import HTTPException
    user_id = _user_id_from_token(request.cookies.get(_SESSION_COOKIE, ""))
    svc = _get_session_service()
    try:
        session = await svc.get_session(app_name=_APP_NAME, user_id=user_id, session_id=cid)
    except Exception:
        session = None
    if not session:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"id": cid, "title": _get_title(user_id, cid) or "New chat",
            "messages": _session_to_messages(session)}


@router.delete("/copilot/conversations/{cid}")
async def delete_conversation(cid: str, request: Request):
    """Delete a conversation and its history."""
    user_id = _user_id_from_token(request.cookies.get(_SESSION_COOKIE, ""))
    svc = _get_session_service()
    try:
        await svc.delete_session(app_name=_APP_NAME, user_id=user_id, session_id=cid)
    except Exception as e:
        logger.warning("delete_session failed: %s", e)
    _del_title(user_id, cid)
    return {"status": "ok"}


@router.patch("/copilot/conversations/{cid}")
async def rename_conversation(cid: str, request: Request, body: RenameBody = Body(...)):
    """Rename a conversation."""
    user_id = _user_id_from_token(request.cookies.get(_SESSION_COOKIE, ""))
    _set_title(user_id, cid, body.title)
    return {"status": "ok", "title": body.title.strip()[:80]}
