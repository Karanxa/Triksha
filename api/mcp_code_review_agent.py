"""
MCP Security Code Review Agent

Fetches MCP server source code from a GitHub repository and uses an LLM
to analyze it for security vulnerabilities.
"""

import os
import json
import base64
import asyncio
import re
from typing import Dict, Any, List, Optional, Tuple

import requests
from rich.console import Console

console = Console()

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_FILES = 15
MAX_CHARS_PER_FILE = 3000
MAX_TOTAL_CHARS = 50_000

# Priority filenames (matched case-insensitively against the basename)
PRIORITY_PATTERNS = [
    "server",
    "index",
    "tools",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "mcp",
]

# Extensions we actually want to read
READABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".mjs", ".cjs", ".json", ".toml",
    ".yaml", ".yml", ".txt", ".sh", ".bash", ".env.example",
    ".cfg", ".ini",
}

VULNERABILITY_TYPES = (
    "PROMPT_INJECTION",
    "TOOL_POISONING",
    "MISSING_AUTH",
    "CMD_INJECTION",
    "PATH_TRAVERSAL",
    "SSRF",
    "SENSITIVE_DATA",
    "OVERPERMISSIVE_TOOLS",
    "INPUT_VALIDATION",
    "TRANSPORT_SECURITY",
    "OTHER",
)

SEVERITY_LEVELS = ("critical", "high", "medium", "low")


# ── LLM helper ────────────────────────────────────────────────────────────────

def _call_llm(prompt: str, model: str = "gemini-2.5-flash") -> str:
    """Synchronous LLM completion via the user-configured provider.

    Triksha: routes through llm_providers (OpenAI / Anthropic / Gemini) using
    the API key set in Settings. Wrap with asyncio.to_thread() when awaiting.
    """
    import llm_providers

    text = llm_providers.complete_sync(
        prompt,
        temperature=0.1,
        max_tokens=8192,
    )
    if not text:
        raise ValueError("No text in LLM response")
    return text.strip()


def _strip_markdown_json(text: str) -> str:
    """Strip ```json ... ``` or ``` ... ``` fences that Gemini sometimes emits."""
    # Try to find a JSON block fenced with ```
    match = re.search(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    # Fall back: strip any leading/trailing fence markers
    text = re.sub(r"^```(?:json)?\s*", "", text.strip())
    text = re.sub(r"\s*```$", "", text.strip())
    return text.strip()


# ── GitHub helpers ─────────────────────────────────────────────────────────────

def _github_api_base(host: str) -> str:
    if host == "github.com":
        return "https://api.github.com"
    return f"https://{host}/api/v3"


def _github_token(host: str) -> str:
    if host == "github.com":
        return os.environ.get("GITHUB_TOKEN", "")
    return os.environ.get("GHE_TOKEN", "")


def _github_headers(host: str) -> Dict[str, str]:
    token = _github_token(host)
    headers: Dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def _fetch_file_tree(api_base: str, owner: str, repo: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Fetch the full recursive git tree for HEAD."""
    url = f"{api_base}/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data.get("tree", [])


def _fetch_file_content(api_base: str, owner: str, repo: str, path: str, headers: Dict[str, str]) -> Optional[str]:
    """Fetch decoded content of a single file via the contents API."""
    url = f"{api_base}/repos/{owner}/{repo}/contents/{path}"
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    data = resp.json()
    encoded = data.get("content", "")
    try:
        return base64.b64decode(encoded).decode("utf-8", errors="replace")
    except Exception:
        return None


def _is_readable(path: str) -> bool:
    """Return True if the file extension is something we want to read."""
    ext = os.path.splitext(path)[1].lower()
    # Also accept files with no extension if they look like dotfiles we care about
    return ext in READABLE_EXTENSIONS or os.path.basename(path) in {
        "Makefile", "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    }


def _priority_score(path: str) -> int:
    """Lower score = higher priority."""
    basename = os.path.basename(path).lower()
    for idx, pattern in enumerate(PRIORITY_PATTERNS):
        if pattern in basename:
            return idx
    return len(PRIORITY_PATTERNS)


def _select_files(tree: List[Dict[str, Any]]) -> List[str]:
    """Select up to MAX_FILES relevant files from the repo tree."""
    blobs = [item["path"] for item in tree if item.get("type") == "blob" and _is_readable(item["path"])]
    blobs.sort(key=_priority_score)
    return blobs[:MAX_FILES]


# ── Security analysis prompt ──────────────────────────────────────────────────

_SECURITY_PROMPT_TEMPLATE = """\
You are a senior security engineer specializing in AI/LLM security, particularly
Model Context Protocol (MCP) servers. Analyze the following MCP server source
code for security vulnerabilities.

## Repository: {repo_full_name}

## Source Files

{file_contents}

## What to Look For

Analyze specifically for these MCP security vulnerability classes:

1. **Tool Poisoning** — Malicious or misleading tool descriptions designed to
   manipulate LLMs into unintended behaviour (e.g., hidden instructions embedded
   in tool `description` or `inputSchema` fields).

2. **Prompt Injection** — Unsanitized user-controlled data flowing into tool
   outputs or descriptions that could hijack the LLM's instructions.

3. **Missing Authentication** — MCP tool endpoints or transport listeners
   (stdio, SSE, HTTP) that require no authentication, allowing any caller to
   invoke tools.

4. **Command Injection** — Shell commands constructed from user-supplied tool
   parameters without sanitization (e.g., `subprocess.run(f"cmd {param}")`,
   `exec`, `eval`, template strings passed to shells).

5. **Path Traversal** — File-path tool parameters passed directly to filesystem
   operations without validation, allowing `../../` escape.

6. **SSRF (Server-Side Request Forgery)** — URL parameters from tool inputs
   passed directly to HTTP clients, allowing internal network access.

7. **Sensitive Data Exposure** — Hardcoded API keys, tokens, passwords, or
   secrets in source files; overly verbose error messages leaking internal info.

8. **Overly Permissive Tools** — Tools granting unrestricted filesystem, shell,
   or network access without scope limiting or allowlisting.

9. **Missing Input Validation** — Tool parameters accepted without type checks,
   length limits, or format validation.

10. **Transport Security** — Missing TLS, plaintext credential transmission,
    or insecure SSE/WebSocket configurations.

## Output Format

Respond with **only** a valid JSON object — no markdown, no prose, no code
fences. The JSON must conform exactly to this schema:

{{
  "vulnerabilities": [
    {{
      "severity": "<critical|high|medium|low>",
      "type": "<PROMPT_INJECTION|TOOL_POISONING|MISSING_AUTH|CMD_INJECTION|PATH_TRAVERSAL|SSRF|SENSITIVE_DATA|OVERPERMISSIVE_TOOLS|INPUT_VALIDATION|TRANSPORT_SECURITY|OTHER>",
      "title": "<short descriptive title>",
      "description": "<detailed explanation of the vulnerability and how it could be exploited>",
      "file": "<relative/path/to/file>",
      "line_start": <integer or null>,
      "line_end": <integer or null>,
      "code_snippet": "<the vulnerable code excerpt or empty string>",
      "recommendation": "<specific, actionable remediation advice>"
    }}
  ],
  "summary": "<overall risk summary — 2-4 sentences>",
  "risk_score": <integer 0-100>
}}

If no vulnerabilities are found, return an empty "vulnerabilities" array with
an appropriate summary and a risk_score of 0.
"""


def _build_prompt(repo_full_name: str, file_map: Dict[str, str]) -> str:
    parts: List[str] = []
    total = 0
    for path, content in file_map.items():
        truncated = content[:MAX_CHARS_PER_FILE]
        if len(content) > MAX_CHARS_PER_FILE:
            truncated += f"\n... [truncated — {len(content) - MAX_CHARS_PER_FILE} chars omitted]"
        section = f"### {path}\n```\n{truncated}\n```\n"
        if total + len(section) > MAX_TOTAL_CHARS:
            break
        parts.append(section)
        total += len(section)

    file_contents = "\n".join(parts) if parts else "(no readable source files found)"
    return _SECURITY_PROMPT_TEMPLATE.format(
        repo_full_name=repo_full_name,
        file_contents=file_contents,
    )


# ── Result parsing ─────────────────────────────────────────────────────────────

def _parse_result(raw: str) -> Dict[str, Any]:
    """Parse Gemini JSON output; normalise and sanitise fields."""
    cleaned = _strip_markdown_json(raw)
    data = json.loads(cleaned)

    vulnerabilities = []
    for vuln in data.get("vulnerabilities", []):
        severity = vuln.get("severity", "low").lower()
        if severity not in SEVERITY_LEVELS:
            severity = "low"
        vuln_type = vuln.get("type", "OTHER").upper()
        if vuln_type not in VULNERABILITY_TYPES:
            vuln_type = "OTHER"
        vulnerabilities.append({
            "severity": severity,
            "type": vuln_type,
            "title": str(vuln.get("title", ""))[:200],
            "description": str(vuln.get("description", "")),
            "file": str(vuln.get("file", "")),
            "line_start": vuln.get("line_start"),
            "line_end": vuln.get("line_end"),
            "code_snippet": str(vuln.get("code_snippet", "")),
            "recommendation": str(vuln.get("recommendation", "")),
        })

    risk_score = int(data.get("risk_score", 0))
    risk_score = max(0, min(100, risk_score))

    return {
        "vulnerabilities": vulnerabilities,
        "summary": str(data.get("summary", "")),
        "risk_score": risk_score,
    }


# ── Main agent class ──────────────────────────────────────────────────────────

class MCPCodeReviewAgent:
    """Analyses an MCP server GitHub repository for security vulnerabilities."""

    async def review_repo(self, repo_full_name: str, host: str = "github.com") -> Dict[str, Any]:
        """
        Fetch source code from *repo_full_name* on *host* and return a
        structured vulnerability report.

        Parameters
        ----------
        repo_full_name : str
            «owner/repo» format, e.g. "org/my-mcp-server".
        host : str
            GitHub host (e.g. "github.com" or your GHE instance).

        Returns
        -------
        dict with keys: vulnerabilities, summary, risk_score
        """
        parts = repo_full_name.split("/", 1)
        if len(parts) != 2:
            return self._error_result(f"Invalid repo_full_name: {repo_full_name!r}")

        owner, repo = parts

        try:
            file_map = await asyncio.to_thread(
                self._fetch_repo_files, host, owner, repo
            )
        except Exception as exc:
            console.print(f"[yellow]MCP review: GitHub fetch failed for {repo_full_name}: {exc}[/]")
            return self._error_result(f"GitHub fetch failed: {exc}")

        if not file_map:
            return {
                "vulnerabilities": [],
                "summary": "No readable source files found in the repository.",
                "risk_score": 0,
            }

        prompt = _build_prompt(repo_full_name, file_map)

        try:
            raw_response = await asyncio.to_thread(_call_llm, prompt)
        except Exception as exc:
            console.print(f"[yellow]MCP review: LLM call failed for {repo_full_name}: {exc}[/]")
            return self._error_result(f"LLM analysis failed: {exc}")

        try:
            result = _parse_result(raw_response)
        except Exception as exc:
            console.print(f"[yellow]MCP review: Failed to parse LLM response for {repo_full_name}: {exc}[/]")
            return self._error_result(f"Failed to parse analysis response: {exc}")

        return result

    # ── private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _fetch_repo_files(host: str, owner: str, repo: str) -> Dict[str, str]:
        """Synchronous: fetch file tree and contents. Call via asyncio.to_thread."""
        api_base = _github_api_base(host)
        headers = _github_headers(host)

        tree = _fetch_file_tree(api_base, owner, repo, headers)
        selected_paths = _select_files(tree)

        file_map: Dict[str, str] = {}
        for path in selected_paths:
            content = _fetch_file_content(api_base, owner, repo, path, headers)
            if content is not None:
                file_map[path] = content

        return file_map

    @staticmethod
    def _error_result(message: str) -> Dict[str, Any]:
        return {
            "vulnerabilities": [],
            "summary": message,
            "risk_score": 0,
        }
