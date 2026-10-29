# FAQ

Common setup issues, questions, and fixes.

---

## Setup and Installation

### The setup wizard doesn't appear — I just see a login page.

Setup was already completed. If you need to reset:
1. Delete `api/triksha-auth.db`
2. Restart the API
3. The setup wizard will appear again

**Warning:** This deletes all users. Scan data is stored separately in `api/triksha.db` and is not affected.

---

### I get "Read-only file system" on startup.

The default auth database path (`/data/triksha-auth.db`) is a Docker path that doesn't exist on bare metal. Fix by setting `AUTH_DB_PATH` to a writable location:

```bash
AUTH_DB_PATH=./triksha-auth.db uvicorn main:app --port 8000
```

Or permanently: the `api/local_auth.py` default is already set to write beside the module file.

---

### Frontend won't start — ESLint error about `jest/globals`.

This is a Node 24 + react-scripts 5 incompatibility. The `frontend/.env` file already contains the fix:

```
DISABLE_ESLINT_PLUGIN=true
```

If the file doesn't exist, create it:
```bash
echo "DISABLE_ESLINT_PLUGIN=true" >> frontend/.env
echo "REACT_APP_API_URL=http://localhost:8000" >> frontend/.env
echo "PORT=8080" >> frontend/.env
```

---

### Port 8000 is already in use.

Find and kill the process:
```bash
lsof -ti:8000 | xargs kill -9
```

Or run on a different port:
```bash
PORT=8001 uvicorn main:app --port 8001
```

If you change the API port, update `frontend/.env`:
```
REACT_APP_API_URL=http://localhost:8001
```

---

### `python-dotenv could not parse statement starting at line 46`

There is a malformed line in `api/.env`. Open the file and remove or fix line 46. This is a warning, not an error — the API will still start correctly.

---

## Authentication

### I forgot my admin password.

There is no password reset in the UI yet. Reset via the database:

```bash
cd api
python3 -c "
import bcrypt, sqlite3
pw = b'newpassword'
h = bcrypt.hashpw(pw, bcrypt.gensalt()).decode()
c = sqlite3.connect('triksha-auth.db')
c.execute('UPDATE users SET password_hash=? WHERE username=?', (h, 'admin'))
c.commit()
print('done')
"
```

---

### Session cookie isn't being sent.

If you're using curl, make sure you're passing the cookie file correctly:

```bash
# Save cookie on login
curl -c cookies.txt -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpassword"}'

# Use cookie on subsequent requests
curl -b cookies.txt http://localhost:8000/auth/me
```

Note: `#HttpOnly_` prefixed entries in Netscape cookie files may not be sent by some curl versions. Extract the token manually if needed:

```bash
TOKEN=$(grep triksha_session cookies.txt | awk '{print $NF}')
curl -H "Cookie: triksha_session=$TOKEN" http://localhost:8000/auth/me
```

---

## Scanning

### Scans are completing instantly with 0 results.

Usually means the target URL is unreachable. Check:
1. The target URL is correct and the service is running
2. Any required API keys or auth headers are set in the scan config
3. The API can reach the target (network/firewall)

Run a quick connectivity test:
```bash
curl -v POST your_target_url -H "Authorization: Bearer your_key" \
  -d '{"messages": [{"role": "user", "content": "hello"}]}'
```

---

### I'm getting "Gemini error 404: model not found".

The model name is incorrect or the model is not available in your region. Check available models:
```bash
curl -b cookies.txt http://localhost:8000/models
```

Use the `model_id` values returned, not display names.

---

### Bypass rate is 0% but I know the model is vulnerable.

Try:
1. Increase `num_tests` — more tests improve coverage (recommend 50+ for a reliable baseline)
2. Run `ALL_TECHNIQUES` if you haven't — individual techniques may miss what `ALL_TECHNIQUES` catches
3. Provide more detailed context in `user_context` / `system_context` — context-aware attacks are significantly more effective

---

### MCP scan returns no findings.

This may be expected — the tool descriptions are clean. To verify the scanner is working:
1. Check the scan completed successfully (status: `completed`)
2. Verify the server was reachable (check `tools_scanned` in results — should be > 0)
3. Check the scan logs for any connection errors

If `tools_scanned` is 0, the scanner could not reach or parse the MCP server.

---

## Performance

### Scans are slow.

Scan speed depends on:
- The target model's response latency
- The LLM provider's rate limits (attack generation + verdict both consume API quota)
- The number of tests (`num_tests`)

To speed up:
- Reduce `num_tests` for a quick check
- Use a faster model (e.g., `gemini-2.5-flash` over larger models)
- Run targeted technique scans instead of `ALL_TECHNIQUES`

---

### The API is unresponsive during a scan.

The scan workers run in a thread pool and should not block the event loop. If the API becomes unresponsive, check:
1. Memory usage — large scans with many tests can consume significant memory
2. Database lock contention — common with SQLite under heavy write load; consider PostgreSQL for production

---

## Docker

### Docker containers start but the frontend can't reach the API.

Check that the API service is healthy:
```bash
docker compose -f docker-compose.os.yml ps
docker compose -f docker-compose.os.yml logs api
```

The frontend proxies to the API via the Docker network. If the API container is restarting, the frontend will show connection errors.

---

### Database migrations fail on startup.

The database schema is created automatically on first run. If you see migration errors:
1. Check that the `db` service (PostgreSQL) is healthy before the `api` service starts
2. Verify `DATABASE_URL` is correct
3. Check PostgreSQL logs: `docker compose logs db`

---

## MCP Tools

### Claude Code isn't finding the Triksha MCP tools.

1. Verify `.mcp.json` is in the project root or `~/.claude/`
2. Check the `python` command in the config points to the correct Python installation
3. Verify the `TRIKSHA_API_URL` and `TRIKSHA_SESSION_COOKIE` values are correct
4. Restart Claude Code after modifying `.mcp.json`

Test the MCP server directly:
```bash
python mcp_server.py
```

It should start without errors.

---

### Session cookie in `.mcp.json` expired.

Session cookies expire after 7 days (default). Re-login and update the cookie:

```bash
curl -c /tmp/new_cookies.txt -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpassword"}'

grep triksha_session /tmp/new_cookies.txt | awk '{print $NF}'
```

Update the `TRIKSHA_SESSION_COOKIE` value in `.mcp.json`.

To avoid frequent rotation, increase `SESSION_TTL_SECONDS` in your environment:
```bash
SESSION_TTL_SECONDS=2592000  # 30 days
```

---

## Still stuck?

Open an issue at the project GitHub repository with:
- Your OS and Python version
- The error message (just the relevant line, not the full log)
- The command you ran
