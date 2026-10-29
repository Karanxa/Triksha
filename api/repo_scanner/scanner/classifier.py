from typing import List, Dict
from .scorer import Scorer
from repo_scanner.scanner.result import Indicator, ScanResult


class Classifier:
    def __init__(self, config: Dict):
        self.scorer = Scorer(config)
        self.thresholds = config.get("thresholds", {}).get("classification", {})
        self.server_threshold = self.thresholds.get("SERVER", 0.6)
        self.client_threshold = self.thresholds.get("CLIENT", 0.6)

    def classify(self, indicators: List[Indicator]) -> str:
        scores = self.scorer.calculate_score(indicators)
        server_score = scores.get("SERVER", 0.0)
        client_score = scores.get("CLIENT", 0.0)

        high_thresh = self.thresholds.get("high", 8.0)
        med_thresh = self.thresholds.get("medium", 5.0)

        if server_score >= high_thresh:
            return "SERVER"
        elif server_score >= med_thresh:
            return "PROTOCOL_RELATED"

        if client_score >= high_thresh:
            return "CLIENT"

        if server_score > 0 or client_score > 0:
            return "UNKNOWN"

        return "UNKNOWN"

    def get_confidence(self, indicators: List[Indicator]) -> float:
        scores = self.scorer.calculate_score(indicators)
        raw_conf = max(scores.values()) if scores.values() else 0.0
        return min(100.0, max(0.0, raw_conf))
