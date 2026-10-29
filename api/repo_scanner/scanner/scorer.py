import logging
from typing import List, Dict
from repo_scanner.scanner.result import Indicator

logger = logging.getLogger("repo_scanner")


class Scorer:
    def __init__(self, config: Dict):
        self.weights = config.get("weights", {})
        self.thresholds = config.get("thresholds", {})

        self.weight_keyword = self.weights.get("keyword_match", 0.1)
        self.weight_dependency = self.weights.get("dependency_match", 0.5)
        self.weight_ast = self.weights.get("ast_match", 0.8)

    def calculate_score(self, indicators: List[Indicator]) -> Dict[str, float]:
        scores = {"SERVER": 0.0, "CLIENT": 0.0}

        for ind in indicators:
            weight = ind.score
            if weight == 0.0:
                if ind.type == "keyword":
                    weight = self.weight_keyword
                elif ind.type == "dependency":
                    weight = self.weight_dependency
                elif ind.type.startswith("ast"):
                    weight = self.weight_ast

            category = ind.classification
            if not category:
                val_lower = ind.value.lower()
                if "server" in val_lower or "listen" in val_lower or "bind" in val_lower:
                    category = "SERVER"
                elif "client" in val_lower or "connect" in val_lower:
                    category = "CLIENT"

            if category in scores:
                scores[category] += weight
            elif category:
                scores[category] = scores.get(category, 0.0) + weight

        return scores
