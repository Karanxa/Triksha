import os
import re
from typing import List
from repo_scanner.scanner.result import Indicator
from .base import BaseScanner

_MCP_PACKAGES: frozenset = frozenset({
    "mcp",
    "fastmcp",
    "mcp-server",
    "mcp_server",
    "mcp-client",
    "mcp_client",
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/inspector",
    "@modelcontextprotocol/client",
    "mcp-sdk",
    "mcpserver",
    "mcp-cli",
})


class DependencyScanner(BaseScanner):
    def __init__(self) -> None:
        self._parsers = {
            "requirements.txt": re.compile(r"^([a-zA-Z0-9_\-]+)", re.MULTILINE),
            "pyproject.toml":   re.compile(r'["\']([a-zA-Z0-9_\-]+)["\']', re.MULTILINE),
            "package.json":     re.compile(r'"(@?[a-zA-Z0-9_\-\/]+)"\s*:', re.MULTILINE),
            "go.mod":           re.compile(r'^\s*([a-zA-Z0-9_.\-\/]+)\s+v', re.MULTILINE),
            "Cargo.toml":       re.compile(r'^([a-zA-Z0-9_\-]+)\s*=', re.MULTILINE),
        }

    def scan(self, file_path: str, content: str) -> List[Indicator]:
        filename = os.path.basename(file_path)
        parser = self._parsers.get(filename)
        if not parser:
            return []

        indicators = []
        seen: set = set()

        for match in parser.findall(content):
            name = match.strip().lower()
            if name in _MCP_PACKAGES and name not in seen:
                seen.add(name)
                indicators.append(
                    Indicator(
                        type="dependency",
                        value=match.strip(),
                        file=file_path,
                        score=5.0,
                        classification="SERVER",
                    )
                )

        return indicators
