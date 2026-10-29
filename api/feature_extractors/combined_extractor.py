"""
Combined Feature Extractor

Combines multiple feature extraction methods into a single interface.
"""

import numpy as np
from typing import List, Dict, Any
from .tfidf_extractor import TFIDFExtractor
from .embedding_extractor import EmbeddingExtractor
from .statistical_extractor import StatisticalFeatureExtractor


class CombinedFeatureExtractor:
    """
    Combined feature extractor that merges:
    - TF-IDF features
    - Deep embeddings
    - Statistical features
    """
    
    def __init__(
        self,
        use_tfidf: bool = True,
        use_embeddings: bool = True,
        use_statistical: bool = True,
        use_perplexity: bool = False,
        tfidf_max_features: int = 500,
        embedding_model: str = 'all-MiniLM-L6-v2'
    ):
        """
        Initialize combined feature extractor
        
        Args:
            use_tfidf: Whether to include TF-IDF features
            use_embeddings: Whether to include deep embeddings
            use_statistical: Whether to include statistical features
            use_perplexity: Whether to compute perplexity scores
            tfidf_max_features: Maximum TF-IDF features
            embedding_model: Name of embedding model
        """
        self.use_tfidf = use_tfidf
        self.use_embeddings = use_embeddings
        self.use_statistical = use_statistical
        self.use_perplexity = use_perplexity
        
        # Initialize extractors
        self.tfidf_extractor = TFIDFExtractor(max_features=tfidf_max_features) if use_tfidf else None
        self.embedding_extractor = EmbeddingExtractor(model_name=embedding_model) if use_embeddings else None
        self.statistical_extractor = StatisticalFeatureExtractor(use_perplexity=use_perplexity) if use_statistical else None
    
    def extract(self, texts: List[str]) -> np.ndarray:
        """
        Extract combined features from texts
        
        Args:
            texts: List of text strings
            
        Returns:
            Combined feature matrix of shape (n_samples, total_features)
        """
        feature_arrays = []
        
        # Extract TF-IDF features
        if self.use_tfidf and self.tfidf_extractor:
            try:
                tfidf_features = self.tfidf_extractor.fit_transform(texts)
                feature_arrays.append(tfidf_features)
                print(f"Extracted TF-IDF features: {tfidf_features.shape}")
            except Exception as e:
                print(f"TF-IDF extraction failed: {e}")
        
        # Extract embedding features
        if self.use_embeddings and self.embedding_extractor:
            try:
                embedding_features = self.embedding_extractor.extract(texts)
                feature_arrays.append(embedding_features)
                print(f"Extracted embedding features: {embedding_features.shape}")
            except Exception as e:
                print(f"Embedding extraction failed: {e}")
        
        # Extract statistical features
        if self.use_statistical and self.statistical_extractor:
            try:
                statistical_features = self.statistical_extractor.extract(texts)
                feature_arrays.append(statistical_features)
                print(f"Extracted statistical features: {statistical_features.shape}")
            except Exception as e:
                print(f"Statistical extraction failed: {e}")
        
        # Combine all features
        if not feature_arrays:
            raise RuntimeError("No features could be extracted")
        
        combined_features = np.hstack(feature_arrays)
        print(f"Combined feature shape: {combined_features.shape}")
        
        return combined_features
    
    def get_feature_breakdown(self) -> Dict[str, Any]:
        """
        Get breakdown of feature dimensions
        
        Returns:
            Dictionary with feature type dimensions and names
        """
        breakdown = {
            'total_features': 0,
            'feature_types': {}
        }
        
        if self.use_tfidf and self.tfidf_extractor:
            feature_names = self.tfidf_extractor.get_feature_names()
            n_features = len(feature_names) if feature_names else 0
            breakdown['feature_types']['tfidf'] = {
                'count': n_features,
                'names': feature_names[:10] if feature_names else []  # Sample
            }
            breakdown['total_features'] += n_features
        
        if self.use_embeddings and self.embedding_extractor:
            n_features = self.embedding_extractor.get_embedding_dim()
            breakdown['feature_types']['embeddings'] = {
                'count': n_features,
                'model': self.embedding_extractor.model_name
            }
            breakdown['total_features'] += n_features
        
        if self.use_statistical and self.statistical_extractor:
            feature_names = self.statistical_extractor.get_feature_names()
            breakdown['feature_types']['statistical'] = {
                'count': len(feature_names),
                'names': feature_names
            }
            breakdown['total_features'] += len(feature_names)
        
        return breakdown

