# Configuration

All configuration can be set via environment variables before starting the API, or via the setup wizard and Settings UI after first run. Environment variables take priority over database-stored values.

---

## LLM Provider

| Variable | Description | Default |
|---|---|---|
| `LLM_PROVIDER` | Active provider: `gemini`, `openai`, `anthropic` | Set during setup wizard |
| `GEMINI_API_KEY` | Google Gemini API key | — |
| `OPENAI_API_KEY` | OpenAI API key | — |
| `ANTHROPIC_API_KEY` | Anthropic API key | — |
| `LLM_MODEL` | Override the default model for the active provider | Provider default |

**Default models per provider:**

| Provider | Default Model |
|---|---|
| Gemini | `gemini-2.5-flash` |
| OpenAI | `gpt-4o-mini` |
| Anthropic | `claude-sonnet-4-6` |

---

## Database

| Variable | Description | Default |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | None (uses SQLite) |
| `AUTH_DB_PATH` | Path to the SQLite auth database | `./triksha-auth.db` (beside `main.py`) |

When `DATABASE_URL` is set, Triksha uses PostgreSQL with pgvector. When unset, it uses SQLite — no setup required.

**SQLite paths (local dev):**
- Auth DB: `api/triksha-auth.db`
- Scan data DB: `api/triksha.db`

---

## Authentication

| Variable | Description | Default |
|---|---|---|
| `SESSION_SECRET` | JWT signing secret | Auto-generated and persisted in DB on first run |
| `SESSION_TTL_SECONDS` | Session cookie lifetime in seconds | `604800` (7 days) |
| `TRIKSHA_API_KEY` | Optional static API key for programmatic access (`Authorization: Bearer …` or `X-API-Key`) | — |

If `SESSION_SECRET` is set as an environment variable, it takes priority over the database-stored secret. Set this explicitly in production to ensure sessions survive database resets.

---

## Queue

| Variable | Description | Default |
|---|---|---|
| `TRIKSHA_USE_KAFKA` | Use Kafka instead of asyncio queue | `false` |
| `KAFKA_BOOTSTRAP_SERVERS` | Kafka broker address | `localhost:9092` |

The asyncio queue (default) requires no external dependencies and works for single-node deployments. Use Kafka for multi-node or high-throughput deployments.

---

## Integrations

Set these in **Settings → Connectors** in the UI, or via environment variables:

| Variable | Description |
|---|---|
| `JIRA_URL` | Jira instance URL (e.g., `https://your-org.atlassian.net`) |
| `JIRA_API_URL` | Jira REST API base URL |
| `GHE_TOKEN` | GitHub Enterprise personal access token |
| `GITHUB_TOKEN` | GitHub.com personal access token |
| `GUARDRAIL_BASE_URL` | Guardrail service base URL |
| `GUARDRAIL_TOKEN` | Guardrail service authentication token |

---

## Ports

| Service | Default Port | Override |
|---|---|---|
| API (FastAPI) | `8000` | Set `PORT` env var |
| Frontend (React) | `8080` | Set `PORT` env var in frontend env |

---

## Frontend

The frontend reads environment variables at build time. Set these in `frontend/.env`:

| Variable | Description | Default |
|---|---|---|
| `REACT_APP_API_URL` | Backend API URL for the dev proxy | `http://localhost:8000` |
| `PORT` | Frontend dev server port | `3000` (overridden to `8080`) |
| `DISABLE_ESLINT_PLUGIN` | Disable ESLint at build time | `true` (required on Node 24+) |

---

## Internal API (Copilot)

| Variable | Description | Default |
|---|---|---|
| `INTERNAL_API_BASE` | Base URL the Copilot agent uses to call the Triksha API | `http://localhost:8000` |

Set this if running the API on a non-default port or on a remote host.

---

## Example: Local Dev `.env`

Create `api/.env` (gitignored):

```env
# LLM Provider
LLM_PROVIDER=gemini
GEMINI_API_KEY=your_gemini_api_key_here

# Auth
AUTH_DB_PATH=./triksha-auth.db
SESSION_TTL_SECONDS=604800

# Optional: integrations
# JIRA_URL=https://your-org.atlassian.net
# GITHUB_TOKEN=ghp_...
```

---

## Example: Production Docker `.env`

```env
# LLM
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...

# Auth
SESSION_SECRET=a-long-random-string-generated-with-openssl-rand-hex-32

# Database
DATABASE_URL=postgresql://triksha:password@db:5432/triksha

# Session
SESSION_TTL_SECONDS=86400
```

Pass to Docker Compose:
```bash
docker compose -f docker-compose.os.yml --env-file .env up -d
```

---

## Checking Active Configuration

```bash
curl -b cookies.txt http://localhost:8000/config
```

Returns the active LLM provider and which integrations are configured (API keys are never returned).
