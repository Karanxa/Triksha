# Triksha: Black Hat India 2026 Arsenal site

Registration and launch page for Triksha at Black Hat India 2026 Arsenal. The Triksha platform itself lives in the open-source project: https://github.com/Karanxa/Triksha

- `frontend/`: React (CRA) site. Register, paste your emailed token, land on the launch page.
- `api/index.py`: FastAPI. `POST /demo/register` emails a 1-hour token, `GET /demo/session` validates it.

## Run locally

```
cd api && python3 -m venv venv && venv/bin/pip install -r requirements.txt
RESEND_API_KEY=... DEMO_FROM_EMAIL="Triksha <noreply@yourdomain.com>" venv/bin/uvicorn index:app --port 8001

cd frontend && npm install && REACT_APP_API_URL=http://localhost:8001 PORT=8080 npm start
```

## Environment (API)

`RESEND_API_KEY`, `DEMO_FROM_EMAIL`, `DATABASE_URL` (Postgres; SQLite fallback is local only), `DEMO_TOKEN_TTL_SECONDS` (default 3600), `DEMO_ADMIN_KEY` (guards `/demo/admin/visitors`), `CORS_ORIGINS`.

## License

Apache 2.0, see `LICENSE`.
