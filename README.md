<div align="center">

# Triksha — AI Security Platform

<img src="docs/images/triksha-logo.png" alt="Triksha" width="320" style="margin-bottom: 40px;" />

[![Black Hat India 2026 Arsenal](docs/images/blackhat-india-logo.png)](https://www.blackhat-india.com/arsenal-overview)

<br/>

**Selected for Black Hat India 2026 Arsenal** · Bengaluru, October 29–30, 2026

<br/>

**Context-aware red teaming for AI models, agents, and MCP servers.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Node 18+](https://img.shields.io/badge/node-18+-green.svg)](https://nodejs.org/)
[![Docker](https://img.shields.io/badge/docker-required-blue.svg)](https://docs.docker.com/get-docker/)
[![Black Hat Tool Arsenal](https://img.shields.io/badge/Black%20Hat-Tool%20Arsenal-black.svg)](https://www.blackhat.com/us-25/arsenal.html)

</div>

---

Triksha red-teams your AI system the way an actual attacker would — by understanding what it is supposed to do, then finding ways to make it do something it should not. You describe your use case, Triksha generates context-specific attacks, and surfaces the vulnerabilities that matter.

## Why Triksha

AI systems are being deployed faster than they are being secured. Most organizations treat LLM safety as a model-level property — something the foundation model vendor handles — and deploy AI assistants, autonomous agents, and tool-calling systems with little understanding of how they behave under adversarial pressure specific to their use case.

<img src="docs/images/co-pilot-hero.png" alt="Triksha Copilot" width="1000" />

Existing red-teaming tools reflect this gap. They throw generic harmful content at a model and check if it refuses, measuring baseline safety training, not deployment security. In a benchmark across five tools — Triksha, Garak, Promptfoo, Giskard, and PyRIT — against the same hardened banking chatbot (Gemini 2.5 Flash), Triksha achieved the highest confirmed bypass rate, approximately 90% higher than the next closest tool (PyRIT, Promptfoo), with every finding mapping to a real, exploitable business-logic vulnerability verified by an LLM judge. Triksha was the only tool whose attack suite was contextually generated from the target's declared use case rather than pulled from generic datasets. Triksha surfaced vulnerabilities the others missed: internal fraud detection algorithm disclosure, MFA monitoring system enumeration, multi-turn boundary erosion, and HTML comment injection attack patterns that an adversary targeting a financial AI assistant would actually exploit.

Triksha is an open-source AI security platform that red-teams AI systems the way a real attacker would: by understanding what the system is supposed to do, then generating attacks specific to that context.

---

## What You Can Test

### LLM Models
Point Triksha at any model (Gemini, OpenAI, Anthropic, or a custom REST endpoint). Describe what the model is for — Triksha generates targeted attacks across **69 technique categories** spanning:

- Classic jailbreaks (DAN, roleplay, encoding, token manipulation)
- Multi-turn escalation and boundary erosion
- Context injection, prompt leakage, and system prompt extraction
- PII extraction and data exfiltration
- Behavioral profiling and authority manipulation
- RAG poisoning and retrieval manipulation
- Research-driven techniques (Skeleton Key, Best-of-N, Cipher attacks, ASCII art encoding)

You get a bypass rate per technique, the exact payloads that succeeded, and a hardened system prompt to close the gaps.

### AI Agents
For agents running as HTTP services, Triksha's autonomous scanner (built on Google ADK) drives multi-turn conversations — probing the way a real attacker would, not with single-shot prompts. Eight agent-specific attack techniques are applied automatically:

| Technique | What It Finds |
|---|---|
| Tool Manipulation | Crafted inputs that trigger tools with malicious parameters or unintended call sequences |
| Agent Hijacking | Injected instructions that override goals and redirect the agent to an attacker objective |
| Tool Injection | Malicious tool-call instructions embedded in external content the agent processes |
| Chain Breaking | Confusion injected at intermediate reasoning steps to disrupt multi-step plans |
| Memory Poisoning | False context injected early that influences behavior in later turns |
| Agentic Info Leakage | Extraction of API keys, system prompts, and configuration the agent can access |
| Agentic Script Gen | Tricks the agent into generating malicious Python, Bash, or SQL under a legitimate pretext |
| Agentic Encoding | Base64, hex, homoglyph, and leetspeak payloads adapted to bypass agent safety filters |

Supports REST, OpenAI-compatible, Google ADK, and custom cURL agent endpoints. See [docs/agent-scanning.md](docs/agent-scanning.md).

### MCP Servers
Triksha inspects your MCP server's tool descriptions and schemas for prompt injection vectors using 8 purpose-built detectors:

| Detector | What It Finds |
|---|---|
| Hidden Instructions | Concealed directives embedded in tool descriptions |
| Exfiltration Channels | Data leak paths via URL params, headers, encoded payloads |
| Tool Shadowing | Tools impersonating legitimate system tools |
| Cross-Origin Attacks | Instructions targeting data outside the tool's declared scope |
| Sensitive File Access | Attempts to read credentials, keys, config files |
| OWASP-MCP Coverage | OWASP Top 10 for LLM mapped to MCP attack surface |
| Capability Analysis | Privilege escalation and capability abuse patterns |
| AI-Assisted Inspection | Deep semantic analysis of ambiguous tool descriptions |

### Training Datasets
Upload a sample of your training data. Triksha's ML detector identifies poisoned samples and backdoor patterns using statistical analysis, clustering, and ensemble methods.

### System Prompt Hardening
Paste any system prompt and Triksha returns a hardened version with security addenda that close jailbreak, injection, and leakage vectors its scan engine would otherwise exploit. Submit jobs from the **Prompt Hardener** UI (`/harden`) or the API; track progress live and download the hardened prompt when complete.

### Agent Skill Hardening — Coming Soon (30th August)
Harden agent skill definitions (`SKILL.md` and related files) before they ship to coding agents. Upload a skill file or point at a GitHub repo — Triksha appends a tailored **Security Guidelines** section grounded in OWASP and LLM/agent security guidance, specific to that skill's tools, inputs, and external systems. Optional PR flow for repo-based jobs. Available at `/skills-harden`.

---

## Quickstart

### Docker (recommended)

```bash
git clone https://github.com/flipkart-incubator/Triksha.git
cd Triksha
docker compose -f docker-compose.os.yml up -d --build
```

First build takes a few minutes (image pulls + dependency install). Ports `8000`, `8080`, `9092`, and `5432` must be free — stop any existing Triksha stack first (`docker compose -f docker-compose.os.yml down`) if you hit a `port is already allocated` error.

Open **http://localhost:8080** → complete the setup wizard (2 minutes: pick LLM provider, paste API key, create admin account) → start scanning.

### Local Development

**Requirements:** Python 3.11+, Node 18+

```bash
# Clone
git clone https://github.com/flipkart-incubator/Triksha.git
cd Triksha

# Backend (Terminal 1)
cd api
python3.11 -m venv venv
venv/bin/pip install -r requirements.txt
AUTH_DB_PATH=./triksha-auth.db venv/bin/python -m uvicorn main:app --port 8000 --reload

# Frontend (Terminal 2)
cd frontend
npm install
npm start
```

Open **http://localhost:8080** → setup wizard → done.

- API: **http://localhost:8000**
- Swagger UI: **http://localhost:8000/swagger**
- Frontend: **http://localhost:8080**

---

## How to Use It

### Web UI
Run the stack, open localhost:8080, complete setup, and start scanning. Results stream live. Findings link directly to "Raise Ticket" for Jira filing.

### REST API
Every scan type is available via API. Integrate Triksha into your CI pipeline to catch regressions before deployment.

```bash
# Login
curl -c cookies.txt -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpassword"}'

# Run a scan
curl -b cookies.txt -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://api.openai.com/v1/chat/completions",
    "model": "gpt-4o",
    "system_prompt": "You are a banking assistant...",
    "techniques": ["ALL_TECHNIQUES"],
    "num_tests": 50
  }'
```

Full API docs at **http://localhost:8000/swagger**

### MCP (Claude Code / VS Code)
Triksha exposes all scan tools as MCP tools. Once configured, tell Claude:

> "Scan the agent at localhost:9100 for prompt injection and file a P1 Jira ticket in project SEC for any bypasses found."

Claude runs the scan, waits for results, and files the ticket — no UI required. See [docs/mcp-scanning.md](docs/mcp-scanning.md) for setup.

---

## LLM Providers

| Provider | Environment Variable |
|---|---|
| Gemini | `GEMINI_API_KEY` |
| OpenAI | `OPENAI_API_KEY` |
| Anthropic | `ANTHROPIC_API_KEY` |
| Custom REST | Configure endpoint + auth headers in the scan config |

Set during the setup wizard or via environment variable. The same provider drives attack generation and agent scanning.

---

## Integrations

Configure in **Settings → Connectors** after setup:

- **Jira** — file tickets from any scan result with one click
- **GitHub / GHE** — repository context for agent and MCP scanning
- **Google Chat** — scan result notifications
- **GCP** — cloud resource context

---

## Documentation

| Doc | Description |
|---|---|
| [Getting Started](docs/getting-started.md) | Detailed setup for Docker and local dev |
| [Attack Techniques](docs/attack-techniques.md) | All 69 techniques explained with examples |
| [Interpreting Results](docs/interpreting-results.md) | Bypass rate, severity, what to do with findings |
| [MCP Scanning](docs/mcp-scanning.md) | MCP server scanning + MCP tool configuration |
| [Agent Scanning](docs/agent-scanning.md) | AI agent scanning guide |
| [Configuration](docs/configuration.md) | All environment variables and settings |
| [API Reference](docs/api-reference.md) | Complete REST API reference |
| [FAQ](docs/faq.md) | Common setup issues and fixes |

---

## Contributing

1. Fork → feature branch → PR
2. Include tests for new scan techniques or API endpoints
3. Keep attack technique descriptions use-case-neutral in code; specificity comes from user-supplied context at scan time

---

## License

Apache License 2.0 — free to use, modify, self-host, and offer as a service, with an express patent grant. See [LICENSE](LICENSE).
