"""
MCP Security Code Review — REST endpoints

POST /triksha/mcp-security-review/review          Trigger a single repo review
GET  /triksha/mcp-security-review/results          List all reviews
GET  /triksha/mcp-security-review/results/{path}   Latest review for a repo
POST /triksha/mcp-security-review/review-org       Trigger reviews for all MCP repos in org scan
"""

import asyncio
import json
from typing import Any, Dict, List, Optional

import requests
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field
from rich.console import Console

from db_factory import get_database
from mcp_code_review_agent import MCPCodeReviewAgent

router = APIRouter(tags=["MCP Security Code Review"])
console = Console()

# ── Request / Response models ──────────────────────────────────────────────────

class ReviewRequest(BaseModel):
    repo_full_name: str = Field(..., description="«owner/repo» format, e.g. org/my-mcp-server")
    host: str = Field("github.com", description="GitHub host (e.g. github.com or your GHE instance)")
    repo_url: str = Field("", description="Human-readable URL for the repo (stored for reference)")


class OrgReviewRequest(BaseModel):
    host: str = Field("github.com", description="GitHub host to use when fetching source code")
    repo_limit: int = Field(500, ge=1, le=2000, description="Max repos to pull from the repo source")


# ── Background task ────────────────────────────────────────────────────────────

async def _run_review(review_id: int, repo_full_name: str, host: str) -> None:
    """Background coroutine: run the MCP code review and persist results."""
    db = get_database()
    try:
        agent = MCPCodeReviewAgent()
        result = await agent.review_repo(repo_full_name, host)
        vulns: List[Dict[str, Any]] = result.get("vulnerabilities", [])
        db.update_mcp_security_review(
            review_id,
            {
                "status": "completed",
                "critical_count": sum(1 for v in vulns if v.get("severity") == "critical"),
                "high_count": sum(1 for v in vulns if v.get("severity") == "high"),
                "medium_count": sum(1 for v in vulns if v.get("severity") == "medium"),
                "low_count": sum(1 for v in vulns if v.get("severity") == "low"),
                "vulnerabilities": json.dumps(vulns),
                "summary": result.get("summary", ""),
                "risk_score": result.get("risk_score", 0),
            },
        )
        console.print(
            f"[green]MCP review completed for {repo_full_name} "
            f"(id={review_id}, score={result.get('risk_score', 0)}, "
            f"vulns={len(vulns)})[/]"
        )
    except Exception as exc:
        console.print(f"[red]MCP review failed for {repo_full_name} (id={review_id}): {exc}[/]")
        db.update_mcp_security_review(review_id, {"status": "failed", "error": str(exc)})


def _schedule_review(review_id: int, repo_full_name: str, host: str) -> None:
    """FastAPI BackgroundTasks callable: schedules the async review coroutine."""
    asyncio.ensure_future(_run_review(review_id, repo_full_name, host))


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post(
    "/mcp-security-review/review",
    summary="Trigger a security code review for an MCP server repo",
)
async def trigger_review(body: ReviewRequest, background_tasks: BackgroundTasks):
    """
    Enqueues a background security analysis for the given GitHub repo.
    Returns immediately with the review_id and initial status='pending'.
    """
    db = get_database()
    if not hasattr(db, "create_mcp_security_review"):
        raise HTTPException(
            status_code=501,
            detail="MCP Security Reviews are not supported by the current DB backend.",
        )

    review_id = db.create_mcp_security_review(
        repo_full_name=body.repo_full_name,
        repo_url=body.repo_url,
        triggered_by="api",
    )
    if review_id is None:
        raise HTTPException(status_code=500, detail="Failed to create review record in database.")

    background_tasks.add_task(_schedule_review, review_id, body.repo_full_name, body.host)

    return {
        "review_id": review_id,
        "repo_full_name": body.repo_full_name,
        "status": "pending",
        "message": "Review queued. Poll /mcp-security-review/results/{repo_full_name} for updates.",
    }


@router.get(
    "/mcp-security-review/results",
    summary="List all MCP security reviews",
)
async def list_reviews(limit: int = 200):
    """Return all reviews ordered by creation time (newest first)."""
    db = get_database()
    if not hasattr(db, "list_mcp_security_reviews"):
        raise HTTPException(
            status_code=501,
            detail="MCP Security Reviews are not supported by the current DB backend.",
        )
    reviews = db.list_mcp_security_reviews(limit=limit)
    # Deserialise vulnerabilities JSON field for each review
    for r in reviews:
        raw = r.get("vulnerabilities")
        if isinstance(raw, str) and raw:
            try:
                r["vulnerabilities"] = json.loads(raw)
            except Exception:
                r["vulnerabilities"] = []
        elif not raw:
            r["vulnerabilities"] = []
    return {"reviews": reviews, "count": len(reviews)}


@router.get(
    "/mcp-security-review/results/{repo_full_name:path}",
    summary="Get the latest security review for a specific repo",
)
async def get_review(repo_full_name: str):
    """Return the most recent review for the given «owner/repo»."""
    db = get_database()
    if not hasattr(db, "get_mcp_security_review"):
        raise HTTPException(
            status_code=501,
            detail="MCP Security Reviews are not supported by the current DB backend.",
        )
    review = db.get_mcp_security_review(repo_full_name)
    if review is None:
        raise HTTPException(
            status_code=404,
            detail=f"No review found for repo: {repo_full_name}",
        )
    raw = review.get("vulnerabilities")
    if isinstance(raw, str) and raw:
        try:
            review["vulnerabilities"] = json.loads(raw)
        except Exception:
            review["vulnerabilities"] = []
    elif not raw:
        review["vulnerabilities"] = []
    return review


@router.post(
    "/mcp-security-review/review-org",
    summary="Trigger security reviews for all MCP repos discovered in org scan",
)
async def trigger_org_review(body: OrgReviewRequest, background_tasks: BackgroundTasks):
    """
    Fetches all repos with has_mcp=1 and enqueues a review for
    each one that has not already been reviewed.
    """
    db = get_database()
    if not hasattr(db, "create_mcp_security_review"):
        raise HTTPException(
            status_code=501,
            detail="MCP Security Reviews are not supported by the current DB backend.",
        )

    repos_data = {"items": [], "total": 0}

    # Response may be {repos: [...]} or a plain list
    if isinstance(repos_data, dict):
        repos = repos_data.get("repos", repos_data.get("data", []))
    elif isinstance(repos_data, list):
        repos = repos_data
    else:
        repos = []

    if not repos:
        return {"queued": 0, "message": "No MCP repos found in org scan."}

    queued: List[str] = []
    skipped: List[str] = []

    for repo in repos:
        full_name = repo.get("full_name") or repo.get("repo_full_name") or ""
        if not full_name:
            continue
        repo_url = repo.get("html_url") or repo.get("repo_url") or ""

        # Skip if a completed review already exists
        existing = db.get_mcp_security_review(full_name)
        if existing and existing.get("status") in ("completed", "pending"):
            skipped.append(full_name)
            continue

        review_id = db.create_mcp_security_review(
            repo_full_name=full_name,
            repo_url=repo_url,
            triggered_by="org-scan",
        )
        if review_id is not None:
            background_tasks.add_task(_schedule_review, review_id, full_name, body.host)
            queued.append(full_name)

    return {
        "queued": len(queued),
        "skipped": len(skipped),
        "queued_repos": queued,
        "skipped_repos": skipped,
        "message": f"Queued {len(queued)} reviews, skipped {len(skipped)} already-reviewed repos.",
    }
