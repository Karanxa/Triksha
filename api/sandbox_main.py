"""Sandbox service — standalone FastAPI app.

Runs as a separate process/container (port 8000 internally, 7000 on the host locally).
Exposes guardrail + LLM proxy multi-agent demo endpoints at /sandbox/*.

This file is NOT imported by the main Triksha API (main.py).
Start locally: uvicorn sandbox_main:app --port 7000 --reload
"""

import logging
import os

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from db_factory import init_database
from endpoints.sandbox import router as sandbox_router, set_database

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(name)s  %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Triksha Sandbox API",
    description="Guardrail + LLM proxy multi-agent demo",
    version="1.0.0",
    docs_url="/sandbox/docs",
    redoc_url=None,
)

cors_origins = os.environ.get("CORS_ORIGINS", "http://localhost:8000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in cors_origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Database — shared with main API via volume-mounted SQLite or PostgreSQL URL
# ---------------------------------------------------------------------------
db = init_database()
set_database(db)
logger.info("Sandbox DB initialised (%s)", type(db).__name__)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(sandbox_router)


@app.get("/sandbox/health")
async def health():
    return {"status": "ok", "service": "sandbox-api"}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("sandbox_main:app", host="0.0.0.0", port=port, reload=False)
