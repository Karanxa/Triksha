# Architecture

This document describes how Triksha works under the hood — the component model, data flow, scan lifecycle, and key design decisions.

---

## Component Overview

```
┌──────────────────────────────────────────────────────────┐
│                      Client Layer                         │
│                                                           │
│   React Frontend (:8080)    MCP Clients    REST Clients   │
│   (Tailwind CSS, SSE)       (Claude Code)  (curl, CI/CD) │
└─────────────────────┬────────────────────────────────────┘
                      │ HTTP / SSE / MCP
┌─────────────────────▼────────────────────────────────────┐
│                   FastAPI Backend (:8000)                  │
│                                                           │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │ Auth / RBAC │  │  API Routes  │  │ Copilot Agent   │  │
│  │ (JWT cookie)│  │  (endpoints/)│  │ (POST /copilot) │  │
│  └─────────────┘  └──────┬───────┘  └─────────────────┘  │
│                          │                                 │
│  ┌───────────────────────▼───────────────────────────┐   │
│  │                  Scan Queue Layer                   │   │
│  │                                                     │   │
│  │  LLM Queue   MCP Queue   Agent Queue   Dataset Q   │   │
│  │  (2 workers) (2 workers) (2 workers)  (2 workers)  │   │
│  └───────────────────────┬───────────────────────────┘   │
└──────────────────────────┼───────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────┐
│                    Execution Layer                         │
│                                                           │
│  ┌──────────────┐  ┌─────────────┐  ┌────────────────┐  │
│  │ LLM Providers│  │ Google ADK  │  │ MCP Detectors  │  │
│  │ (attack gen) │  │(agent scans)│  │ (8 detectors)  │  │
│  └──────────────┘  └─────────────┘  └────────────────┘  │
│                                                           │
│  ┌──────────────┐  ┌─────────────┐                       │
│  │ Bypass Verdict│  │ ML Detectors│                      │
│  │ (LLM judge)  │  │ (dataset)   │                       │
│  └──────────────┘  └─────────────┘                       │
└──────────────────────────┬───────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────┐
│                     Storage Layer                          │
│                                                           │
│   SQLite (default)          PostgreSQL + pgvector          │
│   (zero-config local dev)   (production / Docker)         │
└──────────────────────────────────────────────────────────┘
```

---

## Request Lifecycle: LLM Scan

1. **Client** submits a scan request to `POST /scan` with target URL, model, system prompt, and technique selection
2. **Auth middleware** validates the JWT session cookie and injects RBAC headers
3. **Route handler** validates the request, creates a scan record in the database with status `running`, and enqueues the job
4. **Client** immediately receives the `scan_id` and begins polling `GET /scan/{id}/status` or listening on the SSE stream
5. **Scan worker** (asyncio queue, thread pool) dequeues the job and starts execution:
   - Calls `templates.py` to generate attack prompts for each selected technique
   - Sends each prompt to the target model via HTTP
   - Sends each (prompt, response) pair to the LLM judge (`bypass_verdict.py`) for verdict
   - Writes results to the database in real time
6. On completion, the worker updates the scan status to `completed` and generates the hardened system prompt
7. **Client** receives the final results via the SSE stream or the next status poll

---

## Attack Generation

Attack prompts are not static templates — they are parameterized with context the user provides:

- **Purpose** — what the target model is for (e.g., "banking customer service assistant")
- **Domain** — the vertical or context (e.g., "financial services, fraud detection, account management")
- **Sensitivity flags** — whether it handles PII, uses RAG, is agent-based

The template engine in `templates.py` takes this context and generates domain-specific payloads. A MULTI_TURN_ESCALATION attack against a banking assistant looks different from one against a coding assistant — the escalation path uses banking-specific terminology and the attacker's stated goals are banking-relevant.

---

## Verdict System

Every (prompt, response) pair is evaluated by an LLM judge, not a pattern matcher.

The judge receives:
- The original system prompt (what the model is supposed to do)
- The attack prompt
- The model's response
- The technique category

The judge returns a verdict: `bypass`, `refusal`, or `partial`, with reasoning.

This eliminates false positives from refusal text that happens to contain keywords from the harmful topic. It also catches partial bypasses — where the model refused the surface request but revealed adjacent sensitive information.

---

## Scan Queue Architecture

Each scan type runs in its own asyncio queue with dedicated workers:

| Queue | Workers | Max Size | Scan Type |
|---|---|---|---|
| Production scan | 2 | 100 | LLM model red teaming |
| MCP scan | 2 | 50 | MCP server inspection |
| Agent scan | 2 | 50 | AI agent scanning |
| Dataset | 2 | 50 | Training data analysis |
| PRD review | 2 | 50 | Security requirements review |

Workers run blocking I/O (HTTP calls to target models, LLM API calls) in a thread pool via `asyncio.to_thread` to avoid blocking the event loop. The asyncio queue coordinates work distribution without requiring an external message broker.

For high-throughput deployments, Kafka can replace the asyncio queue: set `TRIKSHA_USE_KAFKA=true`.

---

## Authentication

Triksha uses local, single-tenant authentication backed by SQLite:

- **Setup wizard** creates the first admin account and stores the LLM API key
- **Login** validates credentials against bcrypt-hashed passwords and issues a signed JWT
- **JWT** is stored as an httpOnly session cookie (`triksha_session`), not localStorage
- **Middleware** on every request validates the cookie and injects RBAC headers (`x-proxy-user`, `x-user-permissions`, `x-user-roles`)
- **RBAC** (`rbac.py`) checks the injected headers on protected endpoints

No external IdP, OAuth, or client secrets required. Everything runs on the box.

---

## Database

**SQLite** (default) — zero configuration, file-based, suitable for local development and single-user deployments. Database file is created at `AUTH_DB_PATH` (default: `./triksha-auth.db` for auth, `./triksha.db` for scan data).

**PostgreSQL + pgvector** (production) — enables vector similarity search for dataset poisoning detection. Used automatically when `DATABASE_URL` is set. The Docker stack provisions this automatically.

The database abstraction layer (`db_factory.py`) selects the appropriate backend at startup.

---

## MCP Server

`mcp_server.py` at the repo root runs Triksha's scan capabilities as MCP tools. It communicates with the Triksha API via authenticated HTTP calls using a session cookie. Each MCP tool maps to a Triksha API endpoint.

The MCP server is a thin client — it does not contain scan logic. All execution happens in the Triksha API backend.

---

## Key Design Decisions

**LLM-as-judge over lexical matching** — eliminates the false positive problem that makes tools like Garak unreliable in practice. The judge understands context; a keyword matcher does not.

**Context-aware attack generation** — generic harmful content tests miss business-logic vulnerabilities. Triksha's attack generation is parameterized by the target's purpose, producing domain-specific attacks that reflect real attacker goals.

**Asyncio queue over task scheduler** — Celery and similar tools add operational complexity (Redis/RabbitMQ dependency) that conflicts with the self-hosted, zero-config goal. The asyncio queue handles concurrent scans with no external dependencies.

**Local auth over OAuth/SAML** — external IdP integration creates a dependency that prevents "clone and run" deployment. Local JWT auth works immediately with no external configuration.

**SQLite default over requiring Postgres** — the most common friction point in self-hosted tools is database setup. SQLite gets you running in seconds; Postgres is opt-in for production needs.

---

## File Map

```
triksha/
├── api/
│   ├── main.py                  # FastAPI app, middleware, all routes
│   ├── local_auth.py            # Auth store, session management
│   ├── llm_providers.py         # Multi-provider LLM abstraction
│   ├── llm_client.py            # LLM HTTP client
│   ├── templates.py             # Attack technique templates
│   ├── bypass_verdict.py        # LLM-as-judge verdict system
│   ├── benchmark_runner.py      # Scan execution engine
│   ├── mcp_scanner.py           # MCP server scanner
│   ├── agent_scanner.py         # Agent scanner (Google ADK)
│   ├── poisoning_analyzer.py    # Dataset poisoning ML detector
│   ├── guardrails.py            # System prompt hardening
│   ├── copilot.py               # Triksha Copilot chat agent
│   ├── rbac.py                  # Role-based access control
│   ├── db_factory.py            # DB backend selector
│   ├── pg_database.py           # PostgreSQL + pgvector
│   ├── connectors_store.py      # Integrations (Jira, GitHub, GChat)
│   ├── endpoints/               # Modular route handlers
│   ├── detectors/               # ML detectors (statistical, clustering)
│   ├── mcp_detectors/           # MCP-specific detectors (8 detectors)
│   └── feature_extractors/      # Embedding, TF-IDF, statistical extractors
├── frontend/                    # React 18 + Tailwind CSS
├── mcp_server.py                # MCP server (exposes Triksha tools)
├── docker-compose.os.yml        # Docker stack
└── docs/                        # This documentation
```
