import re
from typing import List, Dict
from repo_scanner.scanner.result import Indicator
from .base import BaseScanner

class KeywordScanner(BaseScanner):
    def __init__(self, config: Dict):
        self.keywords = config.get("keywords", {})
        self.server_keywords = set(self.keywords.get("server_indicators", []))
        self.client_keywords = set(self.keywords.get("client_indicators", []))

        self.compiled_patterns = []
        patterns = config.get("patterns", [])
        for p in patterns:
            try:
                self.compiled_patterns.append({
                    "regex": re.compile(p["regex"]),
                    "score": p.get("score", 1.0),
                    "classification": p.get("classification", "UNKNOWN"),
                    "name": p.get("name", "unknown")
                })
            except re.error:
                pass

    def scan(self, file_path: str, content: str) -> List[Indicator]:
        indicators = []

        for p in self.compiled_patterns:
            matches = p["regex"].findall(content)
            if matches:
                unique_matches = set(matches) if isinstance(matches[0], str) else set([m[0] for m in matches])
                for m in unique_matches:
                    indicators.append(Indicator(
                        type="pattern_match",
                        value=f"{p['name']}: {m[:50]}",
                        file=file_path,
                        score=p["score"],
                        classification=p["classification"]
                    ))

        if self.server_keywords or self.client_keywords:
            lines = content.splitlines()
            for i, line in enumerate(lines):
                line_lower = line.lower()
                for kw in self.server_keywords:
                    if kw in line_lower:
                        indicators.append(Indicator(type="keyword", value=kw, file=file_path, line=i+1, context=line.strip()[:100], classification="SERVER", score=0.1))
                for kw in self.client_keywords:
                    if kw in line_lower:
                        indicators.append(Indicator(type="keyword", value=kw, file=file_path, line=i+1, context=line.strip()[:100], classification="CLIENT", score=0.1))

        return indicators
