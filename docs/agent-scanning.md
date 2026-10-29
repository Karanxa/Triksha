# Agent Scanning

Triksha's agent scanner tests AI agents running as HTTP services across multiple turns, the way a real attacker would interact with them. Single-shot prompts miss the most impactful agent vulnerabilities — Triksha's scanner builds conversation context to find them.

---

## What Is an AI Agent (for Triksha's purposes)

Triksha's agent scanner targets any system that:

- Accepts conversational input via HTTP (REST or WebSocket)
- Has access to tools, external APIs, databases, or file systems
- Makes decisions autonomously based on user input
- Maintains conversation state across turns

This includes: LangChain agents, AutoGen agents, Google ADK agents, custom-built agents over any LLM, and any chatbot with tool-use capabilities.

---

## What It Tests

The agent scanner uses Google ADK to drive multi-turn conversations that probe for:

| Attack Category | What It Finds |
|---|---|
| **Instruction Hijacking** | Whether injected instructions in user input override the agent's goals |
| **Tool Manipulation** | Whether crafted inputs cause the agent to call tools with malicious parameters |
| **Data Exfiltration** | Whether the agent can be tricked into leaking data it has access to |
| **Goal Redirection** | Whether the agent can be redirected from its intended task to an attacker objective |
| **Boundary Erosion** | Whether gradual conversation pressure erodes behavioral constraints |
| **Memory Poisoning** | Whether false information injected early in the conversation affects later behavior |
| **Reasoning Chain Breaking** | Whether injected confusion disrupts multi-step reasoning |
| **Secret Extraction** | Whether the agent reveals API keys, system prompts, or configuration details it has access to |

---

## Agent Types Supported

### REST Agent (JSON API)
For agents that accept and return JSON over HTTP.

**Configuration:**
```json
{
  "agent_type": "rest",
  "endpoint_url": "https://your-agent.example.com/chat",
  "request_body_template": "{\"message\": \"{{prompt}}\", \"session_id\": \"{{session_id}}\"}",
  "response_path": "response.text",
  "auth_header": "Authorization: Bearer your_token"
}
```

`{{prompt}}` is replaced with the attack prompt. `{{session_id}}` is replaced with a unique session identifier for each scan run.

### Conversational Agent (OpenAI-compatible)
For agents that implement the OpenAI chat completions API format.

**Configuration:**
```json
{
  "agent_type": "openai_compatible",
  "endpoint_url": "https://your-agent.example.com/v1/chat/completions",
  "model": "your-model-id",
  "auth_header": "Authorization: Bearer your_token"
}
```

### Google ADK Agent
For agents built with Google's Agent Development Kit.

**Configuration:**
```json
{
  "agent_type": "adk",
  "agent_module": "your_agent.agent",
  "agent_class": "YourAgent"
}
```

### cURL Agent (custom)
For any agent accessible via cURL. Use the template to construct any HTTP request.

**Configuration:**
```json
{
  "agent_type": "curl",
  "curl_template": "curl -X POST https://your-agent.example.com/api -H 'Authorization: Bearer token' -d '{\"input\": \"{{prompt}}\"}'"
}
```

---

## Running a Scan

**Via UI:**
1. Go to **Agents** in the left navigation
2. Click **New Agent Scan**
3. Select your agent type and fill in the connection details
4. Describe what your agent is supposed to do (used to generate context-specific attacks)
5. Select techniques — check "Include agentic techniques" for agent-specific attacks
6. Click **Start Scan**

**Via API:**
```bash
curl -b cookies.txt -X POST http://localhost:8000/agents/scan \
  -H "Content-Type: application/json" \
  -d '{
    "scan_name": "Production Agent Security Audit",
    "agent_config": {
      "agent_type": "rest",
      "endpoint_url": "https://your-agent.example.com/chat",
      "request_body_template": "{\"message\": \"{{prompt}}\"}",
      "response_path": "reply"
    },
    "system_context": "Customer service agent for an e-commerce platform with access to order history, user PII, and return processing",
    "techniques": ["ALL_TECHNIQUES"],
    "num_tests": 30,
    "is_agentic": true
  }'
```

---

## Understanding Agent Scan Results

### Conversation Transcripts
Unlike LLM scans, agent scan results include the full conversation transcript for each attack attempt. You can see exactly which message triggered the behavioral change and trace the attack path.

### Multi-Turn vs Single-Turn Findings
Agent scan results distinguish between:

- **Single-turn findings** — the first message caused the violation (usually direct injection or jailbreak)
- **Multi-turn findings** — the violation occurred after context-building (more sophisticated, higher real-world risk)

Multi-turn findings are generally more significant because they require an attacker to maintain a conversation, which is exactly what automated attack tools and motivated human attackers do.

### Tool Call Logging
If the agent exposes tool call information in its responses, Triksha logs which tools were called and with what parameters during attack attempts. Unexpected tool calls (especially with user-supplied parameters that were passed through without sanitization) are flagged as findings.

---

## Improving Scan Coverage

**Increase `num_tests`** — more tests means more technique coverage and higher statistical confidence.

**Provide a detailed system context** — the more accurately you describe what the agent does and what data it has access to, the more targeted and effective the attack generation will be.

**Enable all agentic techniques** — make sure `is_agentic: true` is set so the scanner includes tool manipulation, memory poisoning, and goal redirection techniques.

**Scan specific techniques** — if you know your agent uses a retrieval system, include `RAG_POISONING` and `RETRIEVAL_ATTACKS` explicitly.

---

## Common Findings and Fixes

| Finding | Typical Cause | Fix |
|---|---|---|
| Instruction hijacking | Agent passes user input directly to LLM context without sanitization | Separate user input from system context; validate input before processing |
| Tool parameter injection | Agent uses user-supplied text in tool call parameters | Validate and sanitize all tool inputs; use structured parameter extraction |
| Secret extraction | Agent has access to env vars, config files, or API keys in its context | Restrict what information is available in the agent's execution context |
| Goal redirection | System prompt does not explicitly constrain the agent's scope | Add explicit scope boundaries to the system prompt; use Triksha's prompt hardener |
| Multi-turn boundary erosion | Agent treats each turn independently without tracking cumulative context | Implement conversation-level safety checks; monitor for pattern escalation |

---

## See Also

- [Attack Techniques](attack-techniques.md) — agent-specific techniques explained
- [Interpreting Results](interpreting-results.md)
- [MCP Scanning](mcp-scanning.md)
