"""
Ensemble Detector

Combines multiple detectors using voting and weighted ensemble methods.
"""

import numpy as np
from typing import List, Dict, Any, Tuple
from .base_detector import BaseDetector


class EnsembleDetector:
    """
    Ensemble of multiple detectors with voting mechanism
    
    Combines predictions from multiple detectors to make final decision.
    Uses configurable voting thresholds and weighted scoring.
    """
    
    def __init__(
        self,
        detectors: List[BaseDetector],
        voting_threshold: int = None,
        weights: List[float] = None
    ):
        """
        Initialize ensemble detector
        
        Args:
            detectors: List of fitted BaseDetector instances
            voting_threshold: Minimum number of detectors that must agree.
                            If None, uses majority voting (>50%)
            weights: Optional weights for each detector. If None, uses equal weights.
        """
        self.detectors = detectors
        self.n_detectors = len(detectors)
        
        # Set voting threshold (default: majority)
        if voting_threshold is None:
            self.voting_threshold = max(1, (self.n_detectors + 1) // 2)
        else:
            self.voting_threshold = voting_threshold
        
        # Set weights (default: equal weights)
        if weights is None:
            self.weights = np.ones(self.n_detectors) / self.n_detectors
        else:
            if len(weights) != self.n_detectors:
                raise ValueError(f"Number of weights ({len(weights)}) must match number of detectors ({self.n_detectors})")
            self.weights = np.array(weights) / np.sum(weights)  # Normalize
    
    def predict(self, features: np.ndarray) -> np.ndarray:
        """
        Ensemble prediction using voting
        
        Args:
            features: numpy array of shape (n_samples, n_features)
            
        Returns:
            Array of -1 (outlier) and 1 (inlier) based on voting
        """
        # Collect predictions from all detectors
        all_predictions = []
        for detector in self.detectors:
            predictions = detector.predict(features)
            all_predictions.append(predictions)
        
        all_predictions = np.array(all_predictions)  # Shape: (n_detectors, n_samples)
        
        # Count votes for outliers (-1)
        outlier_votes = np.sum(all_predictions == -1, axis=0)
        
        # Make final prediction based on voting threshold
        ensemble_predictions = np.where(
            outlier_votes >= self.voting_threshold,
            -1,  # Outlier if enough detectors agree
            1    # Inlier otherwise
        )
        
        return ensemble_predictions
    
    def score(self, features: np.ndarray) -> np.ndarray:
        """
        Weighted ensemble anomaly scores
        
        Args:
            features: numpy array of shape (n_samples, n_features)
            
        Returns:
            Array of weighted anomaly scores [0, 1]
        """
        # Collect scores from all detectors
        all_scores = []
        for detector in self.detectors:
            scores = detector.score(features)
            all_scores.append(scores)
        
        all_scores = np.array(all_scores)  # Shape: (n_detectors, n_samples)
        
        # Compute weighted average
        weighted_scores = np.average(all_scores, axis=0, weights=self.weights)
        
        return weighted_scores
    
    def get_suspicious_indices(
        self,
        features: np.ndarray,
        return_details: bool = True
    ) -> Tuple[np.ndarray, np.ndarray, Dict[str, Any]]:
        """
        Get suspicious indices with detailed breakdown
        
        Args:
            features: numpy array of shape (n_samples, n_features)
            return_details: If True, return detailed breakdown by detector
            
        Returns:
            Tuple of:
            - suspicious_indices: Array of suspicious sample indices
            - weighted_scores: Array of ensemble anomaly scores
            - details: Dictionary with per-detector results (if return_details=True)
        """
        # Get ensemble predictions and scores
        predictions = self.predict(features)
        scores = self.score(features)
        
        # Get suspicious indices
        suspicious_indices = np.where(predictions == -1)[0]
        
        if not return_details:
            return suspicious_indices, scores, {}
        
        # Collect detailed results from each detector
        details = {
            "detectors": [],
            "vote_counts": None,
            "agreement_matrix": None
        }
        
        all_predictions = []
        all_scores = []
        
        for detector in self.detectors:
            det_predictions = detector.predict(features)
            det_scores = detector.score(features)
            det_suspicious = np.where(det_predictions == -1)[0]
            
            all_predictions.append(det_predictions)
            all_scores.append(det_scores)
            
            details["detectors"].append({
                "name": detector.name,
                "n_suspicious": len(det_suspicious),
                "suspicious_indices": det_suspicious.tolist(),
                "metadata": detector.get_metadata()
            })
        
        # Compute vote counts for each sample
        all_predictions = np.array(all_predictions)
        vote_counts = np.sum(all_predictions == -1, axis=0)
        details["vote_counts"] = vote_counts.tolist()
        
        # Compute agreement matrix (how often detectors agree)
        agreement_matrix = np.zeros((self.n_detectors, self.n_detectors))
        for i in range(self.n_detectors):
            for j in range(i, self.n_detectors):
                agreement = np.mean(all_predictions[i] == all_predictions[j])
                agreement_matrix[i, j] = agreement
                agreement_matrix[j, i] = agreement
        
        details["agreement_matrix"] = agreement_matrix.tolist()
        details["detector_names"] = [d.name for d in self.detectors]
        
        return suspicious_indices, scores, details
    
    def get_ensemble_summary(self, features: np.ndarray) -> Dict[str, Any]:
        """
        Get comprehensive ensemble analysis summary
        
        Args:
            features: numpy array of shape (n_samples, n_features)
            
        Returns:
            Dictionary with ensemble analysis summary
        """
        suspicious_indices, scores, details = self.get_suspicious_indices(
            features,
            return_details=True
        )
        
        # Calculate ensemble metrics
        vote_counts = np.array(details["vote_counts"])
        
        summary = {
            "n_samples": len(features),
            "n_detectors": self.n_detectors,
            "voting_threshold": self.voting_threshold,
            "n_suspicious": len(suspicious_indices),
            "suspicious_ratio": len(suspicious_indices) / len(features),
            "per_detector_results": details["detectors"],
            "ensemble_metrics": {
                "avg_agreement": float(np.mean(details["agreement_matrix"])),
                "unanimous_outliers": int(np.sum(vote_counts == self.n_detectors)),
                "majority_outliers": int(np.sum(vote_counts >= self.voting_threshold)),
                "split_decisions": int(np.sum((vote_counts > 0) & (vote_counts < self.voting_threshold))),
                "vote_distribution": {
                    str(i): int(np.sum(vote_counts == i))
                    for i in range(self.n_detectors + 1)
                }
            },
            "top_suspicious_samples": [
                {
                    "index": int(idx),
                    "score": float(scores[idx]),
                    "votes": int(vote_counts[idx])
                }
                for idx in suspicious_indices[np.argsort(-scores[suspicious_indices])[:20]]
            ]
        }
        
        return summary

