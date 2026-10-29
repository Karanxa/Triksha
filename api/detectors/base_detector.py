"""
Base Detector Abstract Class

Defines the interface that all detectors must implement.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple
import numpy as np


class BaseDetector(ABC):
    """Base class for all poisoning detectors"""
    
    def __init__(self, name: str):
        self.name = name
        self.is_fitted = False
    
    @abstractmethod
    def fit(self, features: np.ndarray) -> None:
        """
        Fit the detector on the features
        
        Args:
            features: numpy array of shape (n_samples, n_features)
        """
        pass
    
    @abstractmethod
    def predict(self, features: np.ndarray) -> np.ndarray:
        """
        Predict anomalies
        
        Args:
            features: numpy array of shape (n_samples, n_features)
            
        Returns:
            Array of 1 (inlier) and -1 (outlier)
        """
        pass
    
    @abstractmethod
    def score(self, features: np.ndarray) -> np.ndarray:
        """
        Return anomaly scores
        
        Args:
            features: numpy array of shape (n_samples, n_features)
            
        Returns:
            Array of anomaly scores (higher = more anomalous)
            Normalized to [0, 1] range where 1 is most anomalous
        """
        pass
    
    def get_suspicious_indices(self, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Get indices of suspicious samples with their scores
        
        Args:
            features: numpy array of shape (n_samples, n_features)
            
        Returns:
            Tuple of (suspicious_indices, anomaly_scores)
        """
        predictions = self.predict(features)
        scores = self.score(features)
        suspicious_indices = np.where(predictions == -1)[0]
        return suspicious_indices, scores
    
    def get_metadata(self) -> Dict[str, Any]:
        """
        Return detector metadata and parameters
        
        Returns:
            Dictionary containing detector information
        """
        return {
            "name": self.name,
            "is_fitted": self.is_fitted
        }

