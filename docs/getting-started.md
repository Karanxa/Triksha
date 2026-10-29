# Getting Started

This guide covers every way to run Triksha: Docker (recommended for most users), local development (for contributors and customization), and first-run setup.

---

## Requirements

| Dependency | Minimum Version | Notes |
|---|---|---|
| Python | 3.11+ | 3.11.x recommended |
| Node.js | 18+ | 20.x or 22.x work fine |
| Docker | 24+ | Only needed for Docker install |
| Docker Compose | v2 | `docker compose` (not `docker-compose`) |
| LLM API Key | — | Gemini, OpenAI, or Anthropic |

---

## Option 1: Docker (Recommended)

The fastest path. Starts the API, frontend, and a PostgreSQL + pgvector database.

```bash
git clone https://github.com/your-org/triksha.git
cd triksha
docker compose -f docker-compose.os.yml up -d --build
```

Wait ~60 seconds for services to initialize, then open **http://localhost:8080**.

Services started:
- `frontend` → http://localhost:8080
- `api` → http://localhost:8000
- `db` → PostgreSQL on port 5432 (internal)

To stop:
```bash
docker compose -f docker-compose.os.yml down
```

To view logs:
```bash
docker compose -f docker-compose.os.yml logs -f api
```

---

## Option 2: Local Development

Use this if you want to modify the code, run without Docker, or contribute.

### Backend

```bash
cd triksha/api

# Create and activate virtualenv
python3.11 -m venv venv
source venv/bin/activate       # macOS / Linux
# venv\Scripts\activate        # Windows

# Install dependencies
pip install -r requirements.txt

# Start the API
AUTH_DB_PATH=./triksha-auth.db uvicorn main:app --port 8000 --reload
```

The `--reload` flag restarts the server automatically when you save a file.

**Environment variables** (optional — can also be set via the setup wizard):

```bash
export GEMINI_API_KEY=your_key_here
# or
export OPENAI_API_KEY=your_key_here
# or
export ANTHROPIC_API_KEY=your_key_here
```

### Frontend

Open a second terminal:

```bash
cd triksha/frontend
npm install
npm start
```

The frontend starts on **http://localhost:8080** and proxies API calls to `http://localhost:8000`.

If you see an ESLint compile error on Node 24+, the `frontend/.env` file already has the fix:
```
DISABLE_ESLINT_PLUGIN=true
```

---

## First-Run Setup

The first time you open Triksha, a setup wizard guides you through:

1. **Create admin account** — username and password (minimum 8 characters)
2. **Choose LLM provider** — Gemini, OpenAI, or Anthropic
3. **Paste your API key** — stored encrypted in the local database

After setup, you are logged in and ready to scan. The setup wizard is only shown once. If you need to change the LLM provider or API key later, go to **Settings → App Configuration**.

### Checking setup status (API)

```bash
curl http://localhost:8000/setup/status
# {"needs_setup": true}   ← setup needed
# {"needs_setup": false}  ← already configured
```

---

## Adding Users

After initial setup, additional users can sign up at **http://localhost:8080/signup** or via API:

```bash
curl -X POST http://localhost:8000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst","password":"securepassword"}'
```

All accounts are admin-level in the current release.

---

## Verifying the Installation

```bash
# Health check
curl http://localhost:8000/health
# {"status": "ok"}

# Setup status
curl http://localhost:8000/setup/status

# Swagger UI
open http://localhost:8000/swagger
```

---

## Using PostgreSQL (Production)

By default Triksha uses SQLite — no setup needed for local dev. For production or team deployments, use PostgreSQL:

Set these environment variables before starting the API:

```bash
export DATABASE_URL=postgresql://user:password@host:5432/triksha
export PGVECTOR_ENABLED=true
```

The Docker stack (`docker-compose.os.yml`) already configures PostgreSQL + pgvector automatically.

---

## Next Steps

- [Run your first scan](interpreting-results.md)
- [Understand the attack techniques](attack-techniques.md)
- [Configure integrations](configuration.md)
- [Set up MCP tools for Claude Code](mcp-scanning.md)
