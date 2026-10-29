# Triksha — MCP Integration Guide

Triksha exposes all its AI security scanning capabilities as MCP tools so that
Claude Code, VS Code, or any MCP-compatible agent can run scans and file tickets
without touching the web UI.

---

## How it works

Two MCP servers, one workflow:

```
Claude Code
  ├── triksha        →  run scans, get results, harden prompts
  └── atlassian      →  create Jira tickets from findings
```

Claude handles the full loop autonomously — scan → analyse → file ticket — with
no credential storage inside Triksha and no manual UI steps.

---

## Quick start (Claude Code)

The `.mcp.json` in this repo root is picked up automatically when you open
`/triksha` in Claude Code. Fill in your values and you're ready:

```json
{
  "mcpServers": {
    "triksha": {
      "command": "python3",
      "args": ["/path/to/triksha/mcp_server.py"],
      "env": {
        "TRIKSHA_API_URL": "http://localhost:8001",
        "TRIKSHA_USERNAME": "your-triksha-username",
        "TRIKSHA_PASSWORD": "your-triksha-password"
      }
    },
    "atlassian": {
      "command": "npx",
      "args": ["-y", "@atlassian/mcp-atlassian"],
      "env": {
        "JIRA_URL": "https://your-org.atlassian.net",
        "JIRA_USERNAME": "you@yourorg.com",
        "JIRA_API_TOKEN": "your-api-token"
      }
    }
  }
}
```

> **Jira API token** → generate at `id.atlassian.com → Security → API tokens`

Then approve both servers when Claude Code prompts on first use.

---

## VS Code

Add to your `settings.json` (or workspace `.vscode/settings.json`):

```json
"mcp.servers": {
  "triksha": {
    "command": "python3",
    "args": ["/path/to/triksha/mcp_server.py"],
    "env": {
      "TRIKSHA_API_URL": "http://localhost:8001",
      "TRIKSHA_USERNAME": "your-username",
      "TRIKSHA_PASSWORD": "your-password"
    }
  },
  "atlassian": {
    "command": "npx",
    "args": ["-y", "@atlassian/mcp-atlassian"],
    "env": {
      "JIRA_URL": "https://your-org.atlassian.net",
      "JIRA_USERNAME": "you@yourorg.com",
      "JIRA_API_TOKEN": "your-api-token"
    }
  }
}
```

---

## Example prompts

Once both servers are connected, you can ask Claude things like:

```
Scan FinBot at http://localhost:9100/chat for prompt injection
and file a P1 Jira ticket in project SEC for any bypasses found.
```

```
Run a red-team scan on gemini-2.5-flash, then harden its system prompt
based on whatever gets through.
```

```
Analyze this dataset for poisoning attacks: [paste samples]
```

Claude will call Triksha tools to run the scan, wait for results, and call
Atlassian tools to file the ticket — no UI required.

---

## Web UI users (no Claude Code)

If you're using the Triksha web app directly (not through Claude Code), the
**Raise Ticket** button in scan results uses the Jira connector configured in
**Settings → Connectors**. Add your Jira credentials there once and it works
from any scan result.

---

## Triksha MCP tools reference

### LLM scans
| Tool | Description |
|------|-------------|
| `triksha_llm_scan_start` | Start a red-team scan against any LLM (Gemini, OpenAI, Anthropic, custom API) |
| `triksha_llm_scan_status` | Poll progress (0–100%) |
| `triksha_llm_scan_results` | Full results — bypass rate, per-technique breakdown, example payloads |
| `triksha_llm_scans_list` | List past LLM scans |

### Agent scans
| Tool | Description |
|------|-------------|
| `triksha_agent_scan_start` | Scan a live agent HTTP endpoint for prompt injection, jailbreaks, data exfil |
| `triksha_agent_scan_get` | Get agent scan results |
| `triksha_agent_scans_list` | List agent scans |
| `triksha_agent_scan_cancel` | Cancel a running scan |

### MCP server scans
| Tool | Description |
|------|-------------|
| `triksha_mcp_scan_start` | Security scan an MCP server config (discovers tools, tests for injection) |
| `triksha_mcp_scan_get` | Get MCP scan findings |
| `triksha_mcp_scans_list` | List MCP scans |
| `triksha_mcp_tool_scan` | Quick scan of an MCP server by URL |

### Dataset poisoning
| Tool | Description |
|------|-------------|
| `triksha_dataset_poisoning_analyze` | Analyze a dataset (JSON array of text samples) for poisoning |
| `triksha_dataset_analysis_get` | Get analysis result — risk score, suspicious samples |
| `triksha_dataset_analyses_list` | List past analyses |

### Prompt hardening
| Tool | Description |
|------|-------------|
| `triksha_prompt_harden` | Submit a system prompt for security hardening |
| `triksha_harden_result` | Get hardened prompt + security addendum (pass `wait=true` to block until done) |
| `triksha_harden_list` | List past hardening jobs |

---

## Requirements

```bash
pip install "mcp[cli]" httpx
```

Triksha API must be running:

```bash
cd triksha/api
AUTH_DB_PATH=./auth.db DATABASE_URL=sqlite:///./triksha.db \
uvicorn main:app --host 0.0.0.0 --port 8001
```
