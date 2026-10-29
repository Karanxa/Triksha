# MCP Scanning

Triksha provides two distinct MCP-related capabilities:

1. **Scan MCP servers** — inspect a running MCP server's tool descriptions for prompt injection vectors
2. **Run Triksha as an MCP server** — expose Triksha's scan tools to Claude Code, VS Code, or any MCP-compatible client

---

## Part 1: Scanning an MCP Server

### What It Tests

MCP tool descriptions are strings that an LLM reads to understand what a tool does. A malicious or poorly written tool description can instruct the downstream LLM to:

- Exfiltrate data via URL parameters or encoded payloads
- Ignore safety instructions and override system context
- Shadow legitimate tools by mimicking their names
- Access files, credentials, or configuration outside the tool's declared scope

Triksha runs 8 detectors against every tool, prompt, and resource in the server:

| Detector | Finds |
|---|---|
| **Hidden Instructions** | Concealed directives (`<!-- -->`, zero-width chars, whitespace padding, instruction-like phrases) |
| **Exfiltration Channels** | URLs with data params, webhook patterns, encoded data in descriptions |
| **Tool Shadowing** | Tools with names mimicking system tools (`read_file`, `execute`, `shell`) |
| **Cross-Origin** | Instructions referencing data outside the tool's declared domain |
| **Sensitive Files** | References to `.env`, `id_rsa`, `credentials.json`, `~/.ssh/`, config paths |
| **OWASP-MCP** | OWASP Top 10 for LLM patterns mapped to the MCP attack surface |
| **Capability Analysis** | Privilege escalation language, capability abuse patterns |
| **AI Analysis** | LLM-powered semantic inspection of ambiguous descriptions |

### Running a Scan

**Via UI:**
1. Go to **MCP Scanner** in the left navigation
2. Enter your MCP server URL or paste the server manifest JSON
3. Click **Scan** — results appear in real time

**Via API:**
```bash
curl -b cookies.txt -X POST http://localhost:8000/mcp/scan \
  -H "Content-Type: application/json" \
  -d '{
    "server_url": "http://localhost:3000",
    "scan_name": "Production MCP Server Audit"
  }'
```

**Via MCP tool (from Claude Code):**
```
Scan the MCP server at localhost:3000 for prompt injection vulnerabilities
```

### Understanding Results

Each finding includes:
- **Detector** — which detector flagged it
- **Entity** — tool name, prompt name, or resource URI
- **Content** — the specific text or pattern that triggered the finding
- **Severity** — Critical, High, or Medium
- **Recommendation** — suggested remediation

**Critical / High findings require immediate attention.** A tool description with hidden instructions is an active attack vector against any LLM that reads it.

---

## Part 2: Running Triksha as an MCP Server

Triksha exposes its scan capabilities as MCP tools so you can trigger scans directly from Claude Code, VS Code, or any MCP client — without opening the web UI.

### Available MCP Tools

| Tool | Description |
|---|---|
| `run_llm_scan` | Run a red team scan against an LLM model or API endpoint |
| `run_agent_scan` | Scan an AI agent running as an HTTP service |
| `run_mcp_scan` | Scan an MCP server for prompt injection vulnerabilities |
| `run_dataset_analysis` | Analyze a training dataset for poisoning and backdoor patterns |
| `harden_system_prompt` | Generate a hardened version of a system prompt |
| `get_scan_results` | Retrieve results for a completed scan |
| `list_scans` | List recent scans with status |
| `get_mcp_scan_results` | Retrieve results for a completed MCP scan |
| `run_prd_security_review` | Run a security review against a PRD document |
| `get_active_scans` | List currently running scans |
| `cancel_scan` | Cancel a running scan |
| `get_dashboard_stats` | Get current platform statistics |
| `get_supported_techniques` | List all available attack techniques |

### Setup: Claude Code

Add Triksha to your `.mcp.json` (project-level) or `~/.claude/.mcp.json` (global):

```json
{
  "mcpServers": {
    "triksha": {
      "command": "python",
      "args": ["/path/to/triksha/mcp_server.py"],
      "env": {
        "TRIKSHA_API_URL": "http://localhost:8000",
        "TRIKSHA_SESSION_COOKIE": "your_session_cookie_value"
      }
    }
  }
}
```

To get your session cookie after logging in:
```bash
curl -c /tmp/triksha_cookies.txt -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpassword"}'

grep triksha_session /tmp/triksha_cookies.txt | awk '{print $NF}'
```

### Example Workflows in Claude Code

**Basic scan:**
```
Scan the model at https://api.openai.com/v1/chat/completions using gpt-4o
with system prompt "You are a banking assistant" for all attack techniques
```

**Scan and file tickets:**
```
Scan the agent at localhost:9100 for prompt injection.
For any Critical or High findings, file a P1 Jira ticket in project SEC.
```

**MCP audit:**
```
Audit the MCP server at localhost:3000 and give me a summary of
all findings with severity High or above.
```

**Prompt hardening:**
```
Harden this system prompt: "You are a helpful customer service agent
for Acme Corp. Help users with their orders and returns."
```

### Setup: VS Code (via Copilot MCP extension)

1. Install the MCP extension for VS Code
2. Add Triksha to the MCP servers configuration in VS Code settings
3. Use the same configuration as the Claude Code setup above

---

## Security Notes

- The MCP server authenticates to the Triksha API using your session cookie — keep the cookie value secret
- Session cookies expire after 7 days by default (configurable via `SESSION_TTL_SECONDS`)
- The MCP server only has access to whatever your user account can access in Triksha
- Do not commit `.mcp.json` files containing session cookies to version control — the file is in `.gitignore` by default

---

## See Also

- [Attack Techniques](attack-techniques.md)
- [Interpreting Results](interpreting-results.md)
- [Configuration](configuration.md)
