import base64
import logging
import os
import requests
import time
from typing import List, Generator, Optional, Tuple, Union
from urllib.parse import quote
from .result import RepoMetadata

logger = logging.getLogger("repo_scanner")


class GitHubClient:
    BASE_URL = "https://api.github.com"

    def __init__(self, token: str = None):
        self.token = token
        self._code_search_owner_qualifier: Optional[str] = None
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Triksha-MCP-Scanner/1.0",
        })
        if token:
            auth_kind = (os.getenv("GITHUB_AUTHORIZATION_KIND") or "token").strip().lower()
            if auth_kind in ("bearer", "jwt"):
                self.session.headers.update({"Authorization": f"Bearer {token}"})
            else:
                self.session.headers.update({"Authorization": f"token {token}"})
        connect = float(os.getenv("GITHUB_HTTP_CONNECT_TIMEOUT", "30"))
        read = float(os.getenv("GITHUB_HTTP_READ_TIMEOUT", "120"))
        self._http_timeout: Union[float, Tuple[float, float]] = (connect, read)

    def _request(self, method: str, endpoint: str, params: dict = None, json_body: dict = None) -> requests.Response:
        url = f"{self.BASE_URL}{endpoint}"
        while True:
            response = self.session.request(
                method, url, params=params, json=json_body, timeout=self._http_timeout
            )

            if response.status_code == 403 and "x-ratelimit-remaining" in response.headers:
                remaining = int(response.headers["x-ratelimit-remaining"])
                if remaining == 0:
                    reset_time = int(response.headers["x-ratelimit-reset"])
                    sleep_time = max(reset_time - int(time.time()) + 1, 1)
                    logger.warning("Rate limit hit. Sleeping %ds.", sleep_time)
                    time.sleep(sleep_time)
                    continue

            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 60))
                logger.warning("Secondary rate limit hit. Sleeping %ds.", retry_after)
                time.sleep(retry_after)
                continue

            response.raise_for_status()
            return response

    def get_rate_limit(self) -> dict:
        try:
            data = self._request("GET", "/rate_limit").json()
            core = data.get("resources", {}).get("core", {})
            search = data.get("resources", {}).get("search", {})
            return {
                "core": {"limit": core.get("limit"), "remaining": core.get("remaining"), "reset": core.get("reset")},
                "search": {"limit": search.get("limit"), "remaining": search.get("remaining"), "reset": search.get("reset")},
            }
        except Exception as exc:
            logger.warning("Rate limit check failed: %s", exc)
            return {}

    def get_repo_metadata(self, owner: str, repo: str) -> RepoMetadata:
        endpoint = f"/repos/{owner}/{repo}"
        data = self._request("GET", endpoint).json()
        return RepoMetadata(
            name=data["name"],
            owner=data["owner"]["login"],
            full_name=data["full_name"],
            html_url=data["html_url"],
            description=data.get("description"),
            language=data.get("language"),
            stars=data["stargazers_count"],
            default_branch=data["default_branch"],
            updated_at=data["updated_at"],
            size_kb=data.get("size", 0),
        )

    def get_org_or_user_repos(self, login: str) -> Generator[RepoMetadata, None, None]:
        org_endpoint = f"/orgs/{login}/repos"
        user_endpoint = f"/users/{login}/repos"
        self._code_search_owner_qualifier = f"org:{login}"
        it = self._paginate_repos(org_endpoint, extra_params={"type": "all"})
        try:
            saw_repo = False
            for repo in it:
                saw_repo = True
                yield repo
        except requests.HTTPError as exc:
            if (
                not saw_repo
                and exc.response is not None
                and exc.response.status_code == 404
            ):
                self._code_search_owner_qualifier = f"user:{login}"
                logger.info("'%s' is not a GitHub org (404); listing as user account.", login)
                yield from self._paginate_repos(user_endpoint, extra_params={"type": "all"})
            else:
                raise

    def _paginate_repos(self, endpoint: str, extra_params: dict = None) -> Generator[RepoMetadata, None, None]:
        params = {"per_page": 100, "page": 1}
        if extra_params:
            params.update(extra_params)
        while True:
            data = self._request("GET", endpoint, params=params).json()
            if not data:
                break
            for repo_data in data:
                yield RepoMetadata(
                    name=repo_data["name"],
                    owner=repo_data["owner"]["login"],
                    full_name=repo_data["full_name"],
                    html_url=repo_data["html_url"],
                    description=repo_data.get("description"),
                    language=repo_data.get("language"),
                    stars=repo_data.get("stargazers_count", 0),
                    default_branch=repo_data.get("default_branch", "main"),
                    updated_at=repo_data.get("updated_at", ""),
                    is_archived=repo_data.get("archived", False),
                    is_fork=repo_data.get("fork", False),
                    pushed_at=repo_data.get("pushed_at"),
                )
            params["page"] += 1

    def get_file_content(self, owner: str, repo: str, path: str) -> Optional[str]:
        try:
            data = self._request("GET", f"/repos/{owner}/{repo}/contents/{path}").json()
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code in (404, 403):
                return None
            raise
        if not isinstance(data, dict):
            return None
        encoding = data.get("encoding", "")
        raw = data.get("content", "")
        if encoding == "base64":
            return base64.b64decode(raw.replace("\n", "")).decode("utf-8", errors="ignore")
        return raw or None

    def code_search(self, query: str, page: int = 1, per_page: int = 100) -> dict:
        prev_accept = self.session.headers.get("Accept", "")
        self.session.headers["Accept"] = "application/vnd.github.text-match+json"
        try:
            return self._request(
                "GET",
                "/search/code",
                params={"q": query, "per_page": per_page, "page": page},
            ).json()
        finally:
            self.session.headers["Accept"] = prev_accept or "application/vnd.github.v3+json"

    def get_repo_tree(self, owner: str, repo: str, branch: str = "main") -> list:
        try:
            data = self._request(
                "GET",
                f"/repos/{owner}/{repo}/git/trees/{branch}",
                params={"recursive": "1"},
            ).json()
        except Exception as exc:
            logger.warning("Tree fetch failed for %s/%s: %s", owner, repo, exc)
            return []

        if data.get("truncated"):
            logger.info("Tree truncated for %s/%s (very large repo).", owner, repo)
        return data.get("tree", [])

    def get_archive_url(self, owner: str, repo: str, ref: str = None) -> str:
        if ref:
            return f"{self.BASE_URL}/repos/{owner}/{repo}/zipball/{ref}"
        return f"{self.BASE_URL}/repos/{owner}/{repo}/zipball"

    def get_default_branch_head_sha(self, owner: str, repo: str, branch: str) -> Optional[str]:
        if not branch:
            return None
        try:
            enc = quote(branch, safe="")
            data = self._request("GET", f"/repos/{owner}/{repo}/branches/{enc}").json()
            commit = data.get("commit") or {}
            sha = commit.get("sha")
            return sha if isinstance(sha, str) and len(sha) >= 7 else None
        except Exception as exc:
            logger.debug("Branch head fetch failed for %s/%s@%s: %s", owner, repo, branch, exc)
            return None

    def get_file_sha(self, owner: str, repo: str, path: str, ref: str) -> Optional[str]:
        try:
            data = self._request(
                "GET", f"/repos/{owner}/{repo}/contents/{path}", params={"ref": ref},
            ).json()
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                return None
            raise
        return data.get("sha") if isinstance(data, dict) else None

    def create_branch(self, owner: str, repo: str, new_branch: str, base_sha: str) -> None:
        self._request(
            "POST", f"/repos/{owner}/{repo}/git/refs",
            json_body={"ref": f"refs/heads/{new_branch}", "sha": base_sha},
        )

    def update_file_content(
        self, owner: str, repo: str, path: str, content: str, message: str,
        branch: str, sha: str,
    ) -> dict:
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        return self._request(
            "PUT", f"/repos/{owner}/{repo}/contents/{path}",
            json_body={"message": message, "content": encoded, "branch": branch, "sha": sha},
        ).json()

    def create_pull_request(
        self, owner: str, repo: str, title: str, body: str, head: str, base: str,
    ) -> dict:
        return self._request(
            "POST", f"/repos/{owner}/{repo}/pulls",
            json_body={"title": title, "body": body, "head": head, "base": base},
        ).json()
