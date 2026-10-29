"""Read repo files via GitHub Tree + Contents API — zero disk I/O."""

import logging
from pathlib import Path
from typing import Generator

from .file_filter import FileFilter
from .github_client import GitHubClient
from .result import FileData

logger = logging.getLogger("repo_scanner")

_SKIP_DIRS = frozenset({
    "node_modules", "venv", ".venv", "__pycache__", ".git",
    "dist", "build", "vendor", ".tox", ".mypy_cache",
})

MAX_FILES_PER_SCAN = 300


class GitHubContentReader:
    def __init__(self, client: GitHubClient, file_filter: FileFilter, max_files: int = MAX_FILES_PER_SCAN):
        self._client = client
        self._filter = file_filter
        self._max_files = max_files

    def iter_files(self, owner: str, repo: str, branch: str) -> Generator[FileData, None, None]:
        tree = self._client.get_repo_tree(owner, repo, branch)
        if not tree:
            logger.warning("Empty tree for %s/%s@%s", owner, repo, branch)
            return

        fetched = 0
        for entry in tree:
            if fetched >= self._max_files:
                logger.info("File cap (%d) reached for %s/%s", self._max_files, owner, repo)
                break

            if entry.get("type") != "blob":
                continue

            path: str = entry["path"]
            size: int = entry.get("size", 0)

            parts = Path(path).parts
            if any(part.startswith(".") or part in _SKIP_DIRS for part in parts[:-1]):
                continue

            if not self._filter.should_include(path, size):
                continue

            content = self._client.get_file_content(owner, repo, path)
            if not content:
                continue

            fetched += 1
            yield FileData(path=path, content=content, extension=Path(path).suffix)

        logger.info("Read %d files from %s/%s@%s via Contents API.", fetched, owner, repo, branch)
