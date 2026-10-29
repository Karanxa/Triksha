"""
Clustering-Based Anomaly Detectors

Implements clustering methods for detecting poisoned data:
- DBSCAN (noise points are outliers)
- Gaussian Mixture Models (GMM)
"""

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.mixture import GaussianMixture
from sklearn.metrics import silhouette_samples
from typing import Dict, Any
from .base_detector import BaseDetector


class DBSCANDetector(BaseDetector):
    """
    DBSCAN Clustering Detector
    
    Uses DBSCAN clustering to identify noise points (samples that don't belong 
    to any cluster) as potential poisoned data.
    """
    
    def __init__(
        self,
        eps: float = 0.5,
        min_samples: int = 5,
        metric: str = 'euclidean'
    ):
        super().__init__("DBSCAN")
        self.eps = eps
        self.min_samples = min_samples
        self.metric = metric
        self.labels = None
        self.silhouette_scores = None
    
    def fit(self, features: np.ndarray) -> None:
        """Fit DBSCAN clustering"""
        # Auto-tune eps if not specified
        if self.eps == 'auto':
            from sklearn.neighbors import NearestNeighbors
            k = self.min_samples
            nbrs = NearestNeighbors(n_neighbors=k).fit(features)
            distances, _ = nbrs.kneighbors(features)
            self.eps = np.percentile(distances[:, -1], 90)
        
        model = DBSCAN(
            eps=self.eps,
            min_samples=self.min_samples,
            metric=self.metric,
            n_jobs=-1
        )
        self.labels = model.fit_predict(features)
        
        # Compute silhouette scores for non-noise points
        non_noise_mask = self.labels != -1
        if np.sum(non_noise_mask) > 1 and len(np.unique(self.labels[non_noise_mask])) > 1:
            silhouette = np.zeros(len(features))
            silhouette[non_noise_mask] = silhouette_samples(
                features[non_noise_mask],
                self.labels[non_noise_mask]
            )
            # Noise points get very low silhouette scores
            silhouette[~non_noise_mask] = -1.0
            self.silhouette_scores = silhouette
        else:
            # Not enough clusters for silhouette
            self.silhouette_scores = np.ones(len(features))
            self.silhouette_scores[~non_noise_mask] = -1.0
        
        self.is_fitted = True
    
    def predict(self, features: np.ndarray) -> np.ndarray:
        """Predict anomalies (-1 for outliers, 1 for inliers)"""
        if not self.is_fitted:
            raise RuntimeError("Detector must be fitted before prediction")
        
        # Noise points (label = -1) are outliers
        # Also include points with very low silhouette scores
        predictions = np.ones(len(features))
        noise_mask = self.labels == -1
        low_silhouette_mask = self.silhouette_scores < 0.2
        
        predictions[noise_mask | low_silhouette_mask] = -1
        return predictions
    
    def score(self, features: np.ndarray) -> np.ndarray:
        """
        Return normalized anomaly scores [0, 1]
        Higher score = more anomalous
        """
        if not self.is_fitted:
            raise RuntimeError("Detector must be fitted before scoring")
        
        # Use inverted silhouette scores as anomaly scores
        # Noise points get highest score (1.0)
        scores = np.zeros(len(features))
        
        noise_mask = self.labels == -1
        scores[noise_mask] = 1.0
        
        # For clustered points, use inverted normalized silhouette
        non_noise_mask = ~noise_mask
        if np.sum(non_noise_mask) > 0:
            # Silhouette ranges from -1 to 1
            # Convert to anomaly score: low silhouette = high anomaly
            silhouette_normalized = (1 - self.silhouette_scores[non_noise_mask]) / 2
            scores[non_noise_mask] = silhouette_normalized
        
        return scores
    
    def get_metadata(self) -> Dict[str, Any]:
        """Return detector metadata"""
        meta = super().get_metadata()
        n_clusters = len(set(self.labels)) - (1 if -1 in self.labels else 0)
        n_noise = np.sum(self.labels == -1)
        meta.update({
            "eps": self.eps,
            "min_samples": self.min_samples,
            "n_clusters": n_clusters,
            "n_noise_points": int(n_noise)
        })
        return meta


class GMMDetector(BaseDetector):
    """
    Gaussian Mixture Model (GMM) Detector
    
    Uses GMM to model the data distribution and identifies samples with 
    low likelihood as potential outliers.
    """
    
    def __init__(
        self,
        n_components: int = 3,
        contamination: float = 0.1,
        covariance_type: str = 'full'
    ):
        super().__init__("GaussianMixtureModel")
        self.n_components = n_components
        self.contamination = contamination
        self.covariance_type = covariance_type
        self.model = None
        self.threshold = None
    
    def fit(self, features: np.ndarray) -> None:
        """Fit GMM model"""
        # Auto-select number of components if not specified
        if self.n_components == 'auto':
            from sklearn.metrics import silhouette_score
            best_n = 2
            best_score = -1
            for n in range(2, min(10, len(features) // 10)):
                gmm = GaussianMixture(n_components=n, covariance_type=self.covariance_type, random_state=42)
                labels = gmm.fit_predict(features)
                if len(np.unique(labels)) > 1:
                    score = silhouette_score(features, labels)
                    if score > best_score:
                        best_score = score
                        best_n = n
            self.n_components = best_n
        
        self.model = GaussianMixture(
            n_components=self.n_components,
            covariance_type=self.covariance_type,
            random_state=42
        )
        self.model.fit(features)
        
        # Compute log-likelihoods
        log_likelihoods = self.model.score_samples(features)
        
        # Set threshold based on contamination rate
        self.threshold = np.percentile(log_likelihoods, 100 * self.contamination)
        
        self.is_fitted = True
    
    def predict(self, features: np.ndarray) -> np.ndarray:
        """Predict anomalies (-1 for outliers, 1 for inliers)"""
        if not self.is_fitted:
            raise RuntimeError("Detector must be fitted before prediction")
        
        log_likelihoods = self.model.score_samples(features)
        predictions = np.where(log_likelihoods < self.threshold, -1, 1)
        return predictions
    
    def score(self, features: np.ndarray) -> np.ndarray:
        """
        Return normalized anomaly scores [0, 1]
        Higher score = more anomalous
        """
        if not self.is_fitted:
            raise RuntimeError("Detector must be fitted before scoring")
        
        log_likelihoods = self.model.score_samples(features)
        
        # Convert log-likelihood to anomaly score
        # Lower likelihood = higher anomaly
        anomaly_scores = -log_likelihoods
        
        # Normalize to [0, 1]
        min_score = np.min(anomaly_scores)
        max_score = np.max(anomaly_scores)
        if max_score - min_score > 0:
            normalized = (anomaly_scores - min_score) / (max_score - min_score)
        else:
            normalized = np.zeros_like(anomaly_scores)
        
        return normalized
    
    def get_metadata(self) -> Dict[str, Any]:
        """Return detector metadata"""
        meta = super().get_metadata()
        meta.update({
            "n_components": self.n_components,
            "contamination": self.contamination,
            "covariance_type": self.covariance_type,
            "threshold": float(self.threshold) if self.threshold is not None else None
        })
        return meta

