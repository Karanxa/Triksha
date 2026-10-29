"""Generate additive ## Security Guidelines sections for agent SKILL.md files."""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger("triksha")

GitHubClient = None
_KB_DIR = Path(__file__).resolve().parent / "data" / "security-skills-kb"
_MAX_KB_FILE_CHARS = 150
_MAX_SKILL_CHARS = 2200

_HOST_RE = re.compile(r"^(?:https?://)?([\w.-]+\.[\w.-]+)/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")
_SKILL_MD_FILENAME_RE = re.compile(r"(?:^|/)skill\.md$", re.IGNORECASE)
_VERSION_DIR_RE = re.compile(r"^v?\d+(?:\.\d+)*$", re.IGNORECASE)

_PROMPT = """\
You are an application security reviewer. You are given:
1. SECURITY KNOWLEDGE BASE — secure development and LLM/agent security guidance.
2. A SKILL DEFINITION — an agent skill (SKILL.md) that an AI coding agent executes.

Task: write a "## Security Guidelines" markdown section to append to this skill,
matching the tone and density of any existing "## General Guidelines" section —
a short flat bullet list, NOT a table.

Requirements:
- 5-8 bullets. Each: "- **Short label**: one or two sentences." No sub-bullets or tables.
- Include exactly ONE bullet on AI/LLM security (prompt injection, insecure output
  handling, excessive agency, or tool-delegation risk) grounded in what THIS skill does.
  Omit only if the skill has no LLM or agent surface.
- Be specific to this skill's inputs, outputs, tools, and external systems.
- Ground bullets in the knowledge base when relevant; use OWASP categories where apt.
- Cover only plausible risks; skip categories that do not apply.
- Output ONLY the "## Security Guidelines" heading and bullet list. No preamble or fences.

--- SECURITY KNOWLEDGE BASE ---
{knowledge_base}

--- SKILL DEFINITION: {skill_name} ---
{skill_content}
"""


def _get_github_client(token=None):
    global GitHubClient
    if GitHubClient is None:
        from repo_scanner.scanner.github_client import GitHubClient as _Cls
        GitHubClient = _Cls
    return GitHubClient(token)


def parse_repo_url(repo_url: str) -> tuple[str, str, str]:
    repo_url = repo_url.strip().rstrip("/")
    m = _HOST_RE.match(repo_url)
    if m:
        return m.group(2), m.group(3), m.group(1)
    if "/" in repo_url and repo_url.count("/") == 1 and not repo_url.startswith("http"):
        owner, repo = repo_url.split("/")
        return owner, repo, "github.com"
    raise SkillHardeningError(f"Could not parse owner/repo from: {repo_url!r}")


def resolve_token(host: str, explicit_token: Optional[str]) -> Optional[str]:
    if explicit_token:
        return explicit_token
    if host == "github.com":
        return os.environ.get("GITHUB_TOKEN") or None
    return os.environ.get("GHE_TOKEN") or os.environ.get("GITHUB_TOKEN") or None


def _normalize_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _parse_skill_path(path: str) -> Optional[tuple[str, str]]:
    if not _SKILL_MD_FILENAME_RE.search(path):
        return None
    parts = path.split("/")
    if len(parts) < 2:
        return None
    parent = parts[-2]
    if _VERSION_DIR_RE.match(parent):
        if len(parts) < 3:
            return None
        return parts[-3], parent
    version = ""
    for p in reversed(parts[:-2]):
        if _VERSION_DIR_RE.match(p):
            version = p
            break
    return parent, version


def _version_sort_key(version: str) -> tuple:
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts) or (0,)


@dataclass
class HardenedSkill:
    skill_name: str
    skill_path: str
    original_content: str
    security_recommendations: str
    full_content_preview: str = field(init=False)

    def __post_init__(self) -> None:
        self.full_content_preview = (
            self.original_content.rstrip() + "\n\n" + self.security_recommendations.strip() + "\n"
        )


@dataclass
class HardenPRResult:
    skill_name: str
    skill_path: str
    branch: str
    base_branch: str
    pr_url: str
    pr_number: int
    security_guidelines: str


class SkillHardeningError(RuntimeError):
    pass


def _load_bundled_kb() -> str:
    if not _KB_DIR.is_dir():
        return ""
    chunks = []
    for path in sorted(_KB_DIR.glob("*.md")):
        try:
            text = path.read_text(encoding="utf-8")
            chunks.append(f"### {path.name}\n{text[:_MAX_KB_FILE_CHARS]}")
        except OSError as exc:
            logger.warning("Could not read KB file %s: %s", path, exc)
    return "\n\n".join(chunks)


def _load_kb_from_repo(client, owner: str, repo_name: str, tree: list[dict]) -> str:
    security_dirs = []
    for item in tree:
        if item.get("type") != "blob":
            continue
        path = item.get("path", "")
        parsed = _parse_skill_path(path)
        if parsed and _normalize_name(parsed[0]) in ("security-skills", "security_skills"):
            security_dirs.append((parsed[1], path.rsplit("/", 1)[0]))
    if not security_dirs:
        return ""
    bundle_dir = max(security_dirs, key=lambda vd: _version_sort_key(vd[0]))[1]
    chunks = []
    for item in tree:
        path = item.get("path", "")
        if item.get("type") != "blob" or not path.startswith(bundle_dir + "/"):
            continue
        if not path.lower().endswith(".md"):
            continue
        content = client.get_file_content(owner, repo_name, path)
        if content:
            chunks.append(f"### {path.rsplit('/', 1)[-1]}\n{content[:_MAX_KB_FILE_CHARS]}")
    return "\n\n".join(chunks)


async def _call_llm(prompt: str) -> str:
    import llm_providers
    text = await llm_providers.complete(prompt, temperature=0.3, max_tokens=1200)
    if not text or not text.strip():
        raise SkillHardeningError("Empty response from LLM.")
    return text.strip()


def _resolve_branch(client, owner: str, repo_name: str, branch: Optional[str]) -> str:
    branch = (branch or "").strip()
    if branch:
        return branch
    metadata = client.get_repo_metadata(owner, repo_name)
    return metadata.default_branch or "main"


def _locate_skill(
    client, owner: str, repo_name: str, tree: list[dict],
    skill_name: str, resolved_branch: str,
) -> tuple[str, str]:
    target = _normalize_name(skill_name)
    matches: list[tuple[str, str]] = []
    for item in tree:
        if item.get("type") != "blob":
            continue
        path = item.get("path", "")
        parsed = _parse_skill_path(path)
        if parsed and _normalize_name(parsed[0]) == target:
            matches.append((parsed[1], path))
    if not matches:
        raise SkillHardeningError(
            f"No SKILL.md found for '{skill_name}' in {owner}/{repo_name}@{resolved_branch}."
        )
    skill_path = max(matches, key=lambda vp: _version_sort_key(vp[0]))[1]
    skill_content = client.get_file_content(owner, repo_name, skill_path)
    if not skill_content:
        raise SkillHardeningError(f"Could not fetch {skill_path} from {owner}/{repo_name}.")
    return skill_path, skill_content


async def harden_skill(
    owner: str, repo_name: str, host: str, token: Optional[str],
    skill_name: str, branch: Optional[str] = None,
) -> tuple[HardenedSkill, str]:
    client = _get_github_client(token)
    if host and host != "github.com":
        client.BASE_URL = f"https://{host}/api/v3"
    resolved_branch = _resolve_branch(client, owner, repo_name, branch)
    tree = client.get_repo_tree(owner, repo_name, resolved_branch)
    skill_path, skill_content = _locate_skill(client, owner, repo_name, tree, skill_name, resolved_branch)
    knowledge_base = _load_kb_from_repo(client, owner, repo_name, tree) or _load_bundled_kb()
    prompt = _PROMPT.format(
        knowledge_base=knowledge_base or "(no security knowledge base available)",
        skill_name=skill_name,
        skill_content=skill_content[:_MAX_SKILL_CHARS],
    )
    section = await _call_llm(prompt)
    result = HardenedSkill(
        skill_name=skill_name,
        skill_path=skill_path,
        original_content=skill_content,
        security_recommendations=section,
    )
    return result, resolved_branch


async def harden_uploaded_skill(
    skill_name: str, skill_content: str,
    kb_owner: Optional[str] = None, kb_repo: Optional[str] = None,
    kb_host: str = "github.com", kb_token: Optional[str] = None,
) -> HardenedSkill:
    knowledge_base = _load_bundled_kb()
    kb_spec = os.environ.get("SKILL_HARDEN_KB_REPO", "").strip()
    if kb_spec and not (kb_owner and kb_repo):
        try:
            kb_owner, kb_repo, kb_host = parse_repo_url(kb_spec)
        except SkillHardeningError:
            kb_owner = kb_repo = None
    if kb_owner and kb_repo:
        try:
            client = _get_github_client(kb_token or resolve_token(kb_host, None))
            if kb_host and kb_host != "github.com":
                client.BASE_URL = f"https://{kb_host}/api/v3"
            branch = _resolve_branch(client, kb_owner, kb_repo, None)
            tree = client.get_repo_tree(kb_owner, kb_repo, branch)
            repo_kb = _load_kb_from_repo(client, kb_owner, kb_repo, tree)
            if repo_kb:
                knowledge_base = repo_kb
        except Exception as exc:
            logger.warning("Could not fetch remote KB (using bundled): %s", exc)

    prompt = _PROMPT.format(
        knowledge_base=knowledge_base or "(no security knowledge base available)",
        skill_name=skill_name,
        skill_content=skill_content[:_MAX_SKILL_CHARS],
    )
    section = await _call_llm(prompt)
    return HardenedSkill(
        skill_name=skill_name,
        skill_path="(uploaded)",
        original_content=skill_content,
        security_recommendations=section,
    )


def _assert_not_security_bundle(skill_path: str) -> None:
    segments = {s.lower() for s in skill_path.split("/")}
    if "security" in segments or "security_skills" in segments:
        raise SkillHardeningError(
            f"Refusing to raise a PR under the security folder ({skill_path})."
        )


async def raise_hardening_pr(
    owner: str, repo_name: str, host: str, token: Optional[str],
    skill_name: str, branch: Optional[str] = None,
    security_guidelines: Optional[str] = None,
) -> HardenPRResult:
    if not token:
        raise SkillHardeningError("A GitHub token with write access is required to raise a PR.")

    client = _get_github_client(token)
    if host and host != "github.com":
        client.BASE_URL = f"https://{host}/api/v3"

    if security_guidelines is not None:
        base_branch = _resolve_branch(client, owner, repo_name, branch)
        tree = client.get_repo_tree(owner, repo_name, base_branch)
        skill_path, skill_content = _locate_skill(client, owner, repo_name, tree, skill_name, base_branch)
        result = HardenedSkill(
            skill_name=skill_name,
            skill_path=skill_path,
            original_content=skill_content,
            security_recommendations=security_guidelines,
        )
    else:
        result, base_branch = await harden_skill(owner, repo_name, host, token, skill_name, branch)
    _assert_not_security_bundle(result.skill_path)

    base_sha = client.get_default_branch_head_sha(owner, repo_name, base_branch)
    if not base_sha:
        raise SkillHardeningError(f"Could not resolve HEAD sha for {owner}/{repo_name}@{base_branch}.")

    file_sha = client.get_file_sha(owner, repo_name, result.skill_path, base_branch)
    if not file_sha:
        raise SkillHardeningError(f"Could not resolve blob sha for {result.skill_path}.")

    new_branch = f"harden/{skill_name}-security-guidelines"
    try:
        client.create_branch(owner, repo_name, new_branch, base_sha)
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 422:
            raise SkillHardeningError(
                f"Branch '{new_branch}' already exists — delete it first or pick another skill."
            ) from exc
        raise

    client.update_file_content(
        owner, repo_name, result.skill_path,
        content=result.full_content_preview,
        message=f"Add Security Guidelines to {skill_name}",
        branch=new_branch,
        sha=file_sha,
    )
    pr = client.create_pull_request(
        owner, repo_name,
        title=f"Add Security Guidelines to {skill_name}",
        body=(
            f"Adds a `## Security Guidelines` section to `{result.skill_path}`. "
            f"Additive only — no existing content changed.\n\n"
            f"_Generated by Triksha skill hardening._"
        ),
        head=new_branch,
        base=base_branch,
    )
    return HardenPRResult(
        skill_name=skill_name,
        skill_path=result.skill_path,
        branch=new_branch,
        base_branch=base_branch,
        pr_url=pr.get("html_url", ""),
        pr_number=pr.get("number", 0),
        security_guidelines=result.security_recommendations,
    )
