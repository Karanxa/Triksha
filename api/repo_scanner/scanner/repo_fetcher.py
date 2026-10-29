import requests
import zipfile
import io
import tempfile
import os
import logging
from contextlib import contextmanager
from typing import Generator, Tuple, Union

logger = logging.getLogger("repo_scanner")


class RepoFetcher:
    def __init__(self, token: str = None):
        self.token = token
        connect = float(os.getenv("GITHUB_HTTP_CONNECT_TIMEOUT", "30"))
        read = float(os.getenv("GITHUB_ZIP_READ_TIMEOUT", "600"))
        self._http_timeout: Union[float, Tuple[float, float]] = (connect, read)

    def _get_headers(self):
        headers = {
            "User-Agent": "Triksha-MCP-Scanner/1.0",
            "Accept": "application/vnd.github.v3+json",
        }
        if self.token:
            headers["Authorization"] = f"token {self.token}"
        return headers

    @contextmanager
    def fetch_repo_zip(self, url: str) -> Generator[str, None, None]:
        """Download a repo ZIP from GitHub and extract to a temp directory. Yields the path."""
        logger.info("Downloading repository from %s", url)
        try:
            response = requests.get(
                url,
                headers=self._get_headers(),
                stream=True,
                timeout=self._http_timeout,
            )
            response.raise_for_status()

            with tempfile.TemporaryDirectory() as temp_dir:
                try:
                    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                        z.extractall(temp_dir)

                        contents = os.listdir(temp_dir)
                        if len(contents) == 1 and os.path.isdir(os.path.join(temp_dir, contents[0])):
                            yield os.path.join(temp_dir, contents[0])
                        else:
                            yield temp_dir
                except zipfile.BadZipFile:
                    logger.error("Failed to unzip repository.")
                    raise ValueError("Invalid ZIP file")
        except requests.RequestException as e:
            logger.error("Network error downloading repo: %s", e)
            raise
