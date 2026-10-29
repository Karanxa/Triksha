# API Reference

All endpoints require authentication unless noted. Authenticate by logging in (see below) — the API sets an httpOnly session cookie that is automatically sent with subsequent requests.

Interactive docs with request/response schemas: **http://localhost:8000/swagger** (no login required)

---

## Authentication

### POST /auth/login
Authenticate and receive a session cookie.

**Request:**
```json
{ "username": "admin", "password": "yourpassword" }
```

**Response:**
```json
{
  "status": "ok",
  "user": { "id": "admin", "name": "admin", "email": "admin", "role": "admin" }
}
```

Sets `triksha_session` httpOnly cookie. Pass `-c cookies.txt` with curl to save it, then `-b cookies.txt` on subsequent requests.

---

### POST /auth/logout
Clears the session cookie.

### GET /auth/me
Returns the currently authenticated user.

### POST /auth/signup
Create a new account (setup must be completed first).

**Request:**
```json
{ "username": "newuser", "password": "securepassword" }
```

### GET /auth/user-permissions
Returns the current user's permissions and roles.

---

## Setup

### GET /setup/status
Check if first-run setup is needed. **Public — no auth required.**

**Response:**
```json
{ "needs_setup": true }
```

### POST /setup
Complete first-run setup. **Public — only works once.**

**Request:**
```json
{
  "username": "admin",
  "password": "yourpassword",
  "llm_provider": "gemini",
  "llm_api_key": "your_api_key",
  "llm_model": "gemini-2.5-flash"
}
```

`llm_provider` must be `gemini`, `openai`, or `anthropic`. `llm_model` is optional.

---

## LLM Scans

### POST /scan
Start a new LLM red team scan.

**Request:**
```json
{
  "scan_name": "Banking Assistant Security Audit",
  "target_url": "https://api.openai.com/v1/chat/completions",
  "model": "gpt-4o",
  "api_key": "sk-...",
  "system_prompt": "You are a banking assistant for FinSecure...",
  "user_context": "Banking customer service assistant with access to account data",
  "techniques": ["ALL_TECHNIQUES"],
  "num_tests": 50,
  "is_agentic": false,
  "handles_pii": true,
  "uses_rag": false
}
```

**Response:**
```json
{ "scan_id": "uuid", "status": "queued" }
```

**`techniques`** — array of technique names or `["ALL_TECHNIQUES"]`. See [Attack Techniques](attack-techniques.md) for the full list.

### GET /scan/{scan_id}/status
Get the current status of a scan.

**Response:**
```json
{
  "scan_id": "uuid",
  "status": "running",
  "progress": { "completed": 23, "total": 50 },
  "bypass_rate": 4.35,
  "findings_count": 2
}
```

`status` values: `queued`, `running`, `completed`, `failed`, `cancelled`

### GET /scan/{scan_id}/results
Get the full results of a completed scan.

**Response:**
```json
{
  "scan_id": "uuid",
  "status": "completed",
  "bypass_rate": 5.68,
  "total_tests": 50,
  "bypasses": 3,
  "findings": [
    {
      "technique": "MULTI_TURN_ESCALATION",
      "severity": "High",
      "prompt": "...",
      "response": "...",
      "verdict": "bypass",
      "verdict_reason": "Model revealed restricted account monitoring details"
    }
  ],
  "hardened_system_prompt": "You are a banking assistant...\n\n[SECURITY] Never reveal..."
}
```

### GET /scans
List recent scans.

**Query params:** `limit` (default 20), `offset` (default 0)

### DELETE /scan/{scan_id}
Delete a scan and its results.

### POST /scan/{scan_id}/cancel
Cancel a running scan.

---

## MCP Scanning

### POST /mcp/scan
Start a new MCP server scan.

**Request:**
```json
{
  "scan_name": "Production MCP Server Audit",
  "server_url": "http://localhost:3000",
  "scan_name": "MCP Server Security Audit"
}
```

**Response:**
```json
{ "scan_id": "uuid", "status": "queued" }
```

### GET /mcp/scan/{scan_id}/results
Get MCP scan results.

**Response:**
```json
{
  "scan_id": "uuid",
  "status": "completed",
  "findings": [
    {
      "detector": "hidden_instructions",
      "entity": "read_file",
      "entity_type": "tool",
      "severity": "Critical",
      "matches": ["IGNORE ALL PREVIOUS INSTRUCTIONS"],
      "summary": "Found 1 hidden_instructions pattern(s)"
    }
  ],
  "tools_scanned": 5,
  "findings_count": 1
}
```

### GET /mcp/scans
List recent MCP scans.

---

## Agent Scanning

### POST /agents/scan
Start a new agent scan.

**Request:**
```json
{
  "scan_name": "Customer Service Agent Audit",
  "agent_config": {
    "agent_type": "rest",
    "endpoint_url": "https://your-agent.example.com/chat",
    "request_body_template": "{\"message\": \"{{prompt}}\"}",
    "response_path": "reply",
    "auth_header": "Authorization: Bearer token"
  },
  "system_context": "E-commerce customer service agent with order history access",
  "techniques": ["ALL_TECHNIQUES"],
  "num_tests": 20,
  "is_agentic": true
}
```

### GET /agents/scan/{scan_id}/results
Get agent scan results including conversation transcripts.

### GET /agents/scans
List recent agent scans.

---

## Dataset Analysis

### POST /dataset/analyze
Upload and analyze a training dataset for poisoning.

**Request:** `multipart/form-data`
- `file` — CSV or JSON file
- `dataset_name` — display name
- `analysis_type` — `full` or `quick`

### GET /dataset/analysis/{analysis_id}/results
Get dataset analysis results.

---

## System Prompt Hardening

### POST /harden
Harden a system prompt.

**Request:**
```json
{
  "system_prompt": "You are a helpful banking assistant...",
  "context": "Banking customer service, handles account inquiries",
  "techniques_to_defend": ["ALL_TECHNIQUES"]
}
```

**Response:**
```json
{
  "original_prompt": "...",
  "hardened_prompt": "...",
  "addenda": ["Added instruction to never reveal system prompt", "..."]
}
```

---

## System Prompt Generation

### POST /generate-system-prompt
Generate a system prompt from a description of the use case.

**Request:**
```json
{
  "purpose": "Customer service agent for an e-commerce platform",
  "domain": "E-commerce, returns, order tracking",
  "constraints": ["Never reveal pricing data", "Always escalate fraud to human"],
  "tone": "professional"
}
```

**Response:**
```json
{ "system_prompt": "You are a professional customer service agent for..." }
```

---

## Models

### GET /models
List available models for the active LLM provider.

**Response:**
```json
{
  "models": [
    {
      "model_id": "gemini-2.5-flash",
      "name": "Gemini 2.5 Flash",
      "provider": "gemini",
      "is_default": true
    }
  ],
  "default_provider": "gemini",
  "configured": true
}
```

---

## Dashboard

### GET /dashboard/stats
Get platform statistics (scan counts, bypass rates, activity).

### GET /health
Health check. **Public — no auth required.**

**Response:** `{"status": "ok"}`

---

## PRD Security Review

### POST /security-review/analyze
Submit a PRD document for AI security requirements generation.

**Request:**
```json
{
  "prd_content": "Product requirements document text...",
  "review_name": "Q3 Feature Security Review"
}
```

---

## Connectors

### GET /connectors
List configured integrations.

### POST /connectors/{connector_type}
Configure an integration (Jira, GitHub, Google Chat, GCP).

### DELETE /connectors/{connector_type}
Remove an integration.

---

## Copilot

### POST /copilot/chat
Send a message to the Triksha Copilot AI assistant.

**Request:**
```json
{
  "message": "What was the bypass rate on my last scan?",
  "session_id": "optional-session-id-for-history"
}
```

**Response:** Server-Sent Events stream with the assistant's response.
