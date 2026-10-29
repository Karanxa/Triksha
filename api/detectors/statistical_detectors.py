"""
Statistical Anomaly Detectors

Implements various statistical methods for detecting poisoned data:
- Isolation Forest
- Local Outlier Factor (LOF)
- One-Class SVM
- Mahalanobis Distance
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.covariance import EmpiricalCovariance
from scipy.spatial.distance import mahalanobis
from typing import Dict, Any
from .base_detector import BaseDetector


class IsolationForestDetector(BaseDetector):
    """
    Isolation Forest Anomaly Detector
    
    Isolates observations by randomly selecting a feature and then randomly 
    selecting a split value between maximum and minimum values of the selected feature.
    """
    
    def __init__(
        self,
        contamination: float = 0.1,
        n_estimators: int = 100,
        random_state: int = 42
    ):
        super().__init__("IsolationForest")
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model = None
    
    def fit(self, features: np.ndarray) -> None:
        """Fit Isolation Forest model"""
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.model.fit(features)
        self.is_fitted = True
    
    def predict(self, features: np.ndarray) -> np.ndarray:
        """Predict anomalies (-1 for outliers, 1 for inliers)"""
        if not self.is_fitted:
            raise RuntimeError("Detector must be fitted before prediction")
        return self.model.predict(features)
    
    def score(self, features: np.ndarray) -> np.ndarray:
        """
        Return normalized anomaly scores [0, 1]
        Higher score = more anomalous
        """
        if not self.is_fitted:
            raise RuntimeError("Detector must be fitted before scoring")
        
        # decision_function returns negative scores for outliers
        raw_scores = -self.model.decision_function(features)
        
        # Normalize to [0, 1]
        min_score = np.min(raw_scores)
        max_score = np.max(raw_scores)
        if max_score - min_score > 0:
            normalized = (raw_scores - min_score) / (max_score - min_score)
        else:
            normalized = np.zeros_like(raw_scores)
        
        return normalized
    
    def get_metadata(self) -> Dict[str, Any]:
        """Return detector metadata"""
        meta = super().get_metadata()
        meta.update({
            "contamination": self.contamination,
            "n_estimators": self.n_estimators
        })
        return meta


class LOFDetector(BaseDetector):
    """
    Local Outlier Factor (LOF) Detector
    
    Computes local density deviation of a given sample with respect to its neighbors.
    Samples that have substantially lower density than their neighbors are considered outliers.
    """
    
    def __init__(
        self,
        n_neighbors: int = 20,
        contamination: float = 0.1
    ):
        super().__init__("LocalOutlierFactor")
        self.n_neighbors = n_neighbors
        self.contamination = contamination
        self.model = None
    
    def fit(self, features: np.ndarray) -> None:
        """Fit LOF model"""
        self.model = LocalOutlierFactor(
            n_neighbors=self.n_neighbors,
            contamination=self.contamination,
            novelty=True,  # Enable predict method
            n_jobs=-1
        )
        self.model.fit(features)
        self.is_fitted = True
    
    def predict(self, features: np.ndarray) -> np.ndarray:
        """Predict anomalies (-1 for outliers, 1 for inliers)"""
        if not self.is_fitted:
            raise RuntimeError("Detector must be fitted before prediction")
        return self.model.predict(features)
    
    def score(self, features: np.ndarray) -> np.ndarray:
        """
        Return normalized anomaly scores [0, 1]
        Higher score = more anomalous
        """
        if not self.is_fitted:
            raise RuntimeError("Detector must be fitted before scoring")
        
        # decision_function returns negative scores for outliers
        raw_scores = -self.model.decision_function(features)
        
        # Normalize to [0, 1]
        min_score = np.min(raw_scores)
        max_score = np.max(raw_scores)
        if max_score - min_score > 0:
            normalized = (raw_scores - min_score) / (max_score - min_score)
        else:
            normalized = np.zeros_like(raw_scores)
        
        return normalized
    
    def get_metadata(self) -> Dict[str, Any]:
        """Return detector metadata"""
        meta = super().get_metadata()
        meta.update({
            "n_neighbors": self.n_neighbors,
            "contamination": self.contamination
        })
        return meta


class OneClassSVMDetector(BaseDetector):
    """
    One-Class SVM Detector
    
    Learns a decision function for outlier detection: classifying new data 
    as similar or different to the training set.
    """
    
    def __init__(
        self,
        kernel: str = 'rbf',
        gamma: str = 'auto',
        nu: float = 0.1
    ):
        super().__init__("OneClassSVM")
        self.kernel = kernel
        self.gamma = gamma
        self.nu = nu  # Upper bound on fraction of outliers
        self.model = None
    
    def fit(self, features: np.ndarray) -> None:
        """Fit One-Class SVM model"""
        self.model = OneClassSVM(
            kernel=self.kernel,
            gamma=self.gamma,
            nu=self.nu
        )
        self.model.fit(features)
        self.is_fitted = True
    
    def predict(self, features: np.ndarray) -> np.ndarray:
        """Predict anomalies (-1 for outliers, 1 for inliers)"""
        if not self.is_fitted:
            raise RuntimeError("Detector must be fitted before prediction")
        return self.model.predict(features)
    
    def score(self, features: np.ndarray) -> np.ndarray:
        """
        Return normalized anomaly scores [0, 1]
        Higher score = more anomalous
        """
        if not self.is_fitted:
            raise RuntimeError("Detector must be fitted before scoring")
        
        # decision_function returns negative scores for outliers
        raw_scores = -self.model.decision_function(features)
        
        # Normalize to [0, 1]
        min_score = np.min(raw_scores)
        max_score = np.max(raw_scores)
        if max_score - min_score > 0:
            normalized = (raw_scores - min_score) / (max_score - min_score)
        else:
            normalized = np.zeros_like(raw_scores)
        
        return normalized
    
    def get_metadata(self) -> Dict[str, Any]:
        """Return detector metadata"""
        meta = super().get_metadata()
        meta.update({
            "kernel": self.kernel,
            "gamma": self.gamma,
            "nu": self.nu
        })
        return meta


class MahalanobisDetector(BaseDetector):
    """
    Mahalanobis Distance Detector
    
    Uses Mahalanobis distance to measure how far each sample is from the 
    distribution center, accounting for covariance structure.
    """
    
    def __init__(self, contamination: float = 0.1):
        super().__init__("MahalanobisDistance")
        self.contamination = contamination
        self.mean = None
        self.cov_inv = None
        self.threshold = None
    
    def fit(self, features: np.ndarray) -> None:
        """Fit Mahalanobis detector by computing mean and covariance"""
        # Compute mean and covariance
        self.mean = np.mean(features, axis=0)
        
        # Use robust covariance estimator
        cov_estimator = EmpiricalCovariance()
        cov_estimator.fit(features)
        
        try:
            self.cov_inv = np.linalg.inv(cov_estimator.covariance_)
        except np.linalg.LinAlgError:
            # If covariance is singular, use pseudo-inverse
            self.cov_inv = np.linalg.pinv(cov_estimator.covariance_)
        
        # Compute distances for all samples
        distances = self._compute_distances(features)
        
        # Set threshold based on contamination rate
        self.threshold = np.percentile(distances, 100 * (1 - self.contamination))
        
        self.is_fitted = True
    
    def _compute_distances(self, features: np.ndarray) -> np.ndarray:
        """Compute Mahalanobis distances for all samples"""
        distances = np.zeros(len(features))
        for i, sample in enumerate(features):
            diff = sample - self.mean
            distances[i] = np.sqrt(diff @ self.cov_inv @ diff.T)
        return distances
    
    def predict(self, features: np.ndarray) -> np.ndarray:
        """Predict anomalies (-1 for outliers, 1 for inliers)"""
        if not self.is_fitted:
            raise RuntimeError("Detector must be fitted before prediction")
        
        distances = self._compute_distances(features)
        predictions = np.where(distances > self.threshold, -1, 1)
        return predictions
    
    def score(self, features: np.ndarray) -> np.ndarray:
        """
        Return normalized anomaly scores [0, 1]
        Higher score = more anomalous
        """
        if not self.is_fitted:
            raise RuntimeError("Detector must be fitted before scoring")
        
        distances = self._compute_distances(features)
        
        # Normalize to [0, 1]
        min_dist = np.min(distances)
        max_dist = np.max(distances)
        if max_dist - min_dist > 0:
            normalized = (distances - min_dist) / (max_dist - min_dist)
        else:
            normalized = np.zeros_like(distances)
        
        return normalized
    
    def get_metadata(self) -> Dict[str, Any]:
        """Return detector metadata"""
        meta = super().get_metadata()
        meta.update({
            "contamination": self.contamination,
            "threshold": float(self.threshold) if self.threshold is not None else None
        })
        return meta

