"""
Skill Hardening — self-serve upload + optional repo-based async jobs.

Endpoints:
  POST /skills/harden/upload/submit   Upload a skill file for hardening
  POST /skills/harden/submit          Repo-based hardening (+ optional PR)
  GET  /skills/harden/list            List jobs
  GET  /skills/harden/{job_id}        Poll job status
  GET  /skills/harden/{job_id}/events SSE progress stream
  GET  /skills/harden/{job_id}/download  Download hardened .md
  DELETE /skills/harden/{job_id}      Delete a job
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from rich.console import Console

logger = logging.getLogger("skill_harden")
console = Console()

router = APIRouter(tags=["Skills Hardening"])

# ---------------------------------------------------------------------------
# Lazy references — set by init_skill_harden() from main.py
# ---------------------------------------------------------------------------
_db = None
_harden_skill = None
_harden_uploaded_skill = None
_parse_repo_url = None
_raise_hardening_pr = None
_resolve_token = None
_SkillHardeningError: type = RuntimeError


def set_dependencies(
    db,
    harden_skill,
    harden_uploaded_skill,
    parse_repo_url,
    raise_hardening_pr,
    resolve_token,
    skill_hardening_error,
) -> None:
    """Called once from main.py to inject lazy references."""
    global _db, _harden_skill, _harden_uploaded_skill, _parse_repo_url
    global _raise_hardening_pr, _resolve_token, _SkillHardeningError
    _db = db
    _harden_skill = harden_skill
    _harden_uploaded_skill = harden_uploaded_skill
    _parse_repo_url = parse_repo_url
    _raise_hardening_pr = raise_hardening_pr
    _resolve_token = resolve_token
    _SkillHardeningError = skill_hardening_error or RuntimeError


# ---------------------------------------------------------------------------
# Queue infrastructure
# ---------------------------------------------------------------------------
_MAX_CONCURRENT = int(os.environ.get("TRIKSHA_MAX_CONCURRENT_SKILL_HARDENS", "2"))
_QUEUE_MAX_SIZE = int(os.environ.get("TRIKSHA_SKILL_HARDEN_QUEUE_MAX_SIZE", "50"))

skill_harden_queue: Optional[asyncio.Queue] = None
skill_harden_event_queues: Dict[str, asyncio.Queue] = {}
running_skill_hardens: Dict[str, Dict[str, Any]] = {}

_OUTPUT_DIR = Path(os.environ.get("TRIKSHA_DATA_DIR", "data")) / "skill_hardening"
_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

_ALLOWED_EXTENSIONS = (".md", ".markdown", ".yaml", ".yml", ".json", ".txt")
_MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB


# ---------------------------------------------------------------------------
# DB helpers (best-effort, mirrors security_review.py)
# ---------------------------------------------------------------------------

def _save_job(record: Dict[str, Any]) -> None:
    if _db:
        try:
            _db.save_skill_harden_job(record)
        except Exception:
            pass


def _update_job(job_id: str, update: Dict[str, Any]) -> None:
    if _db:
        try:
            _db.update_skill_harden_job(job_id, update)
        except Exception as e:
            console.print(f"[red]skill_harden DB update failed for {job_id}: {e}[/]")


# ---------------------------------------------------------------------------
# SSE emit
# ---------------------------------------------------------------------------

async def _emit(job_id: str, event: Dict[str, Any]) -> None:
    q = skill_harden_event_queues.get(job_id)
    if q:
        await q.put(event)


# ---------------------------------------------------------------------------
# Worker task
# ---------------------------------------------------------------------------

async def _run_skill_harden_task(job_id: str) -> None:
    record = running_skill_hardens.get(job_id)
    if not record:
        return

    record["status"] = "running"
    record["progress"] = 10
    _update_job(job_id, {"status": "running", "progress": 10})
    await _emit(job_id, {
        "job_id": job_id, "status": "running", "progress": 10,
        "event": f"Locating skill '{record.get('skill_name', '?')}'…",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    try:
        if _harden_skill is None:
            raise RuntimeError(
                "skill_hardening_service failed to import at startup — see server logs."
            )

        pr_url = None
        pr_number = None
        full_content_preview = None
        original_content = None

        if record.get("mode") == "upload":
            # ── Self-serve upload path ──
            record["progress"] = 40
            await _emit(job_id, {
                "job_id": job_id, "status": "running", "progress": 40,
                "event": "Generating Security Guidelines…",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            hardened = await _harden_uploaded_skill(
                skill_name=record["skill_name"],
                skill_content=record["skill_content"],
            )
            security_guidelines = hardened.security_recommendations
            full_content_preview = hardened.full_content_preview
            original_content = hardened.original_content
        else:
            # ── Repo-based path ──
            owner, repo_name, host = _parse_repo_url(record["repo_url"])
            token = _resolve_token(host, record.get("github_token"))

            record["progress"] = 40
            await _emit(job_id, {
                "job_id": job_id, "status": "running", "progress": 40,
                "event": "Generating Security Guidelines…",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            if record.get("raise_pr"):
                result = await _raise_hardening_pr(
                    owner, repo_name, host, token, record["skill_name"],
                    record.get("branch"), record.get("security_guidelines"),
                )
                security_guidelines = result.security_guidelines
                pr_url = result.pr_url
                pr_number = result.pr_number
            else:
                hardened, _branch_used = await _harden_skill(
                    owner, repo_name, host, token,
                    record["skill_name"], record.get("branch"),
                )
                security_guidelines = hardened.security_recommendations
                full_content_preview = hardened.full_content_preview
                original_content = hardened.original_content

        completed_at = datetime.now(timezone.utc).isoformat()
        record.update({
            "status": "completed", "progress": 100,
            "security_guidelines": security_guidelines,
            "full_content_preview": full_content_preview,
            "original_content": original_content,
            "pr_url": pr_url, "pr_number": pr_number,
            "completed_at": completed_at,
        })

        _update_job(job_id, {
            "status": "completed", "progress": 100,
            "completed_at": completed_at,
            "security_guidelines": security_guidelines,
            "full_content_preview": full_content_preview,
            "pr_url": pr_url, "pr_number": pr_number,
        })

        # Free large blobs from in-memory record after DB persistence
        record.pop("skill_content", None)

        await _emit(job_id, {
            "job_id": job_id, "status": "completed", "progress": 100,
            "event": "Completed",
            "security_guidelines": security_guidelines,
            "full_content_preview": full_content_preview,
            "pr_url": pr_url, "pr_number": pr_number,
            "timestamp": completed_at,
        })

    except _SkillHardeningError as e:
        _fail_job(job_id, record, str(e))
        await _emit(job_id, {
            "job_id": job_id, "status": "failed", "progress": 0,
            "event": "Failed", "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as e:
        _fail_job(job_id, record, str(e))
        await _emit(job_id, {
            "job_id": job_id, "status": "failed", "progress": 0,
            "event": "Failed", "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    finally:
        q = skill_harden_event_queues.get(job_id)
        if q:
            await q.put(None)  # SSE sentinel

        # Evict from memory after delay so SSE clients can read final event
        async def _evict():
            await asyncio.sleep(60)
            running_skill_hardens.pop(job_id, None)
            skill_harden_event_queues.pop(job_id, None)

        asyncio.create_task(_evict())


def _fail_job(job_id: str, record: Dict[str, Any], error: str) -> None:
    record["status"] = "failed"
    record["progress"] = 0
    record["error"] = error
    _update_job(job_id, {
        "status": "failed", "progress": 0, "error": error,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    })


# ---------------------------------------------------------------------------
# Worker + queue init
# ---------------------------------------------------------------------------

async def _worker(worker_id: int) -> None:
    console.print(f"[dim]Skill harden worker {worker_id} started[/]")
    while True:
        try:
            item = await skill_harden_queue.get()
            if item is None:
                skill_harden_queue.task_done()
                break
            await _run_skill_harden_task(item)
        except Exception as e:
            console.print(f"[yellow]Skill harden worker {worker_id} error: {e}[/]")
        finally:
            try:
                skill_harden_queue.task_done()
            except Exception:
                pass


def init_skill_harden_queue() -> None:
    global skill_harden_queue
    skill_harden_queue = asyncio.Queue(maxsize=_QUEUE_MAX_SIZE)
    for i in range(_MAX_CONCURRENT):
        asyncio.create_task(_worker(i + 1))
    console.print(
        f"[cyan]Initialized skill harden queue "
        f"(maxsize={_QUEUE_MAX_SIZE}) with {_MAX_CONCURRENT} workers[/]"
    )


async def _enqueue(job_id: str) -> None:
    if skill_harden_queue is None or skill_harden_queue.full():
        raise HTTPException(
            status_code=429,
            detail="Skill-harden queue is full. Please try again later.",
        )
    await skill_harden_queue.put(job_id)


def _require_user(x_proxy_user: Optional[str]) -> str:
    if not x_proxy_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return x_proxy_user


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class SkillHardenSubmitRequest(BaseModel):
    repo_url: str = Field(..., max_length=500)
    skill_name: str = Field(...)
    branch: Optional[str] = Field(None)
    github_token: Optional[str] = Field(None, exclude=True)
    raise_pr: bool = Field(True)
    security_guidelines: Optional[str] = Field(None)


# Fields stripped from API responses (secrets + large blobs)
_STRIP_FIELDS = {"github_token", "skill_content"}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/skills/harden/upload/submit", summary="Upload a skill file for hardening")
async def upload_submit(
    skill_name: str = Form(...),
    file: UploadFile = File(...),
    x_proxy_user: str = Header(None, alias="x-proxy-user"),
):
    caller = _require_user(x_proxy_user)

    # Validate file type
    filename = (file.filename or "").lower()
    if not filename or not filename.endswith(_ALLOWED_EXTENSIONS):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type. Allowed: {', '.join(_ALLOWED_EXTENSIONS)}",
        )

    raw = await file.read()
    if len(raw) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 10 MB).")
    try:
        skill_content = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 text.")
    if not skill_content.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    q: asyncio.Queue = asyncio.Queue()
    skill_harden_event_queues[job_id] = q
    running_skill_hardens[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "progress": 0,
        "mode": "upload",
        "repo_url": None,
        "skill_name": skill_name.strip(),
        "skill_content": skill_content,
        "skill_filename": file.filename,
        "branch": None,
        "raise_pr": False,
        "created_by": caller,
        "created_at": now,
    }

    _save_job({
        "job_id": job_id,
        "repo_url": "(uploaded)",
        "skill_name": skill_name.strip(),
        "skill_content": skill_content,
        "branch": None,
        "status": "queued",
        "progress": 0,
        "created_by": caller,
        "created_at": now,
    })

    await _emit(job_id, {
        "job_id": job_id, "status": "queued", "progress": 0,
        "event": "Queued", "timestamp": now,
    })
    await _enqueue(job_id)

    return {
        "job_id": job_id,
        "status": "queued",
        "events_url": f"/skills/harden/{job_id}/events",
        "status_url": f"/skills/harden/{job_id}",
    }


@router.post("/skills/harden/submit", summary="Submit repo-based skill hardening")
async def repo_submit(
    request: SkillHardenSubmitRequest,
    x_proxy_user: str = Header(None, alias="x-proxy-user"),
):
    caller = _require_user(x_proxy_user)

    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    q: asyncio.Queue = asyncio.Queue()
    skill_harden_event_queues[job_id] = q
    running_skill_hardens[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "progress": 0,
        "mode": "repo",
        "repo_url": request.repo_url,
        "skill_name": request.skill_name,
        "branch": request.branch,
        "github_token": request.github_token,
        "raise_pr": request.raise_pr,
        "security_guidelines": request.security_guidelines,
        "created_by": caller,
        "created_at": now,
    }

    _save_job({
        "job_id": job_id,
        "repo_url": request.repo_url,
        "skill_name": request.skill_name,
        "branch": request.branch,
        "status": "queued",
        "progress": 0,
        "created_by": caller,
        "created_at": now,
    })

    await _emit(job_id, {
        "job_id": job_id, "status": "queued", "progress": 0,
        "event": "Queued", "timestamp": now,
    })
    await _enqueue(job_id)

    return {"job_id": job_id, "status": "queued"}


@router.get("/skills/harden/list", summary="List skill-harden jobs")
async def list_jobs(
    request: Request,
    scope: Optional[str] = None,
    mine: bool = False,
    x_proxy_user: Optional[str] = Header(None, alias="x-proxy-user"),
):
    """Return jobs visible to the caller.
    scope: 'mine' | 'others' (or mine=true for backwards compat)."""
    effective_scope = scope or ("mine" if mine else "all")
    caller = x_proxy_user or request.headers.get("x-proxy-user") or "anonymous"

    # DB records
    merged: Dict[str, Dict] = {}
    if _db:
        try:
            created_by_filter = caller if effective_scope == "mine" else None
            db_jobs = await asyncio.to_thread(
                lambda: _db.list_skill_harden_jobs(created_by=created_by_filter)
            )
            for j in db_jobs:
                merged[j["job_id"]] = j
        except Exception as e:
            console.print(f"[red]skill_harden list DB error: {e}[/]")

    # Overlay in-memory (running/queued have live progress)
    for jid, job in running_skill_hardens.items():
        merged[jid] = {k: v for k, v in job.items() if k not in _STRIP_FIELDS}

    jobs = sorted(
        merged.values(), key=lambda j: j.get("created_at", ""), reverse=True
    )

    # Ownership filter
    if effective_scope in ("mine", "others") and caller:
        def _username(val: str) -> str:
            s = str(val or "").strip()
            return (s.split("@", 1)[0]).lower() if s else ""

        me = _username(caller)

        def _is_mine(rec):
            return bool(me) and _username(rec.get("created_by")) == me

        if effective_scope == "mine":
            jobs = [j for j in jobs if _is_mine(j)]
        else:
            jobs = [j for j in jobs if not _is_mine(j)]

    # Strip sensitive fields
    jobs = [{k: v for k, v in j.items() if k not in _STRIP_FIELDS} for j in jobs]

    return {"jobs": jobs, "scope": effective_scope}


@router.get("/skills/harden/{job_id}", summary="Get job status")
async def get_job(
    job_id: str,
    x_proxy_user: str = Header(None, alias="x-proxy-user"),
):
    _require_user(x_proxy_user)

    record = running_skill_hardens.get(job_id)
    if not record and _db:
        record = await asyncio.to_thread(lambda: _db.get_skill_harden_job(job_id))
    if not record:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    return {k: v for k, v in record.items() if k not in _STRIP_FIELDS}


@router.get("/skills/harden/{job_id}/events", summary="SSE progress stream")
async def stream_events(
    request: Request,
    job_id: str,
    x_proxy_user: str = Header(None, alias="x-proxy-user"),
):
    _require_user(x_proxy_user)

    record = running_skill_hardens.get(job_id)
    known = record or (
        await asyncio.to_thread(lambda: _db.get_skill_harden_job(job_id))
        if _db else None
    )
    if not known:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    # Live SSE if this pod owns the job
    if record:
        q = skill_harden_event_queues.get(job_id)
        if q is None:
            q = asyncio.Queue()
            skill_harden_event_queues[job_id] = q

        async def live_generator():
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    event = await q.get()
                    if event is None:
                        yield 'event: end\ndata: {"status": "done"}\n\n'
                        break
                    yield f"data: {json.dumps(event)}\n\n"
            except asyncio.CancelledError:
                return

        return StreamingResponse(
            live_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    # Cross-pod fallback: poll DB
    async def db_poll_generator():
        last_status = None
        try:
            while True:
                if await request.is_disconnected():
                    return
                current = (
                    await asyncio.to_thread(lambda: _db.get_skill_harden_job(job_id))
                    if _db else None
                )
                if not current:
                    yield 'event: end\ndata: {"status": "done"}\n\n'
                    return
                if current.get("status") != last_status:
                    last_status = current.get("status")
                    yield f"data: {json.dumps({**current, 'event': last_status})}\n\n"
                if last_status in ("completed", "failed"):
                    yield 'event: end\ndata: {"status": "done"}\n\n'
                    return
                await asyncio.sleep(3)
        except asyncio.CancelledError:
            return

    return StreamingResponse(
        db_poll_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get(
    "/skills/harden/{job_id}/download",
    summary="Download the hardened skill as .md",
)
async def download(
    job_id: str,
    x_proxy_user: str = Header(None, alias="x-proxy-user"),
):
    _require_user(x_proxy_user)

    record = running_skill_hardens.get(job_id)
    if not record and _db:
        record = await asyncio.to_thread(lambda: _db.get_skill_harden_job(job_id))
    if not record:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    if record.get("status") != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Job is {record.get('status')}, not completed",
        )

    content = (
        record.get("full_content_preview")
        or record.get("security_guidelines")
    )
    if not content:
        raise HTTPException(status_code=500, detail="No hardened content available.")

    safe_name = re.sub(r"[^\w-]", "_", record.get("skill_name") or "skill")
    filename = f"{safe_name}_hardened_{job_id[:8]}.md"
    filepath = _OUTPUT_DIR / filename
    filepath.write_text(content, encoding="utf-8")
    return FileResponse(
        path=str(filepath), filename=filename, media_type="text/markdown"
    )


@router.delete("/skills/harden/{job_id}", summary="Delete a skill-harden job")
async def delete_job(
    job_id: str,
    x_proxy_user: str = Header(None, alias="x-proxy-user"),
):
    _require_user(x_proxy_user)

    record = running_skill_hardens.get(job_id)
    if not record and _db:
        record = await asyncio.to_thread(lambda: _db.get_skill_harden_job(job_id))
    if not record:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    running_skill_hardens.pop(job_id, None)
    skill_harden_event_queues.pop(job_id, None)
    if _db:
        await asyncio.to_thread(lambda: _db.delete_skill_harden_job(job_id))

    return {"deleted": job_id}
