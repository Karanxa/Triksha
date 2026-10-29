"""
TF-IDF Feature Extractor

Traditional text feature extraction using TF-IDF vectorization.
"""

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from typing import Optional


class TFIDFExtractor:
    """TF-IDF feature extractor for text data"""
    
    def __init__(
        self,
        max_features: int = 1000,
        min_df: int = 1,
        max_df: float = 0.95,
        ngram_range: tuple = (1, 2),
        use_idf: bool = True
    ):
        """
        Initialize TF-IDF extractor
        
        Args:
            max_features: Maximum number of features
            min_df: Minimum document frequency
            max_df: Maximum document frequency
            ngram_range: Range of n-grams to extract
            use_idf: Whether to use inverse document frequency
        """
        self.max_features = max_features
        self.min_df = min_df
        self.max_df = max_df
        self.ngram_range = ngram_range
        self.use_idf = use_idf
        
        self.vectorizer = None
    
    def fit_transform(self, texts: list) -> np.ndarray:
        """
        Fit vectorizer and transform texts
        
        Args:
            texts: List of text strings
            
        Returns:
            Feature matrix of shape (n_samples, n_features)
        """
        self.vectorizer = TfidfVectorizer(
            max_features=self.max_features,
            min_df=self.min_df,
            max_df=self.max_df,
            stop_words='english',
            ngram_range=self.ngram_range,
            use_idf=self.use_idf
        )
        
        try:
            tfidf_matrix = self.vectorizer.fit_transform(texts)
            return tfidf_matrix.toarray()
        except Exception as e:
            # Fallback to simple character-level features
            print(f"TF-IDF failed: {e}, using fallback features")
            return self._fallback_features(texts)
    
    def transform(self, texts: list) -> np.ndarray:
        """
        Transform texts using fitted vectorizer
        
        Args:
            texts: List of text strings
            
        Returns:
            Feature matrix of shape (n_samples, n_features)
        """
        if self.vectorizer is None:
            raise RuntimeError("Vectorizer must be fitted first")
        
        tfidf_matrix = self.vectorizer.transform(texts)
        return tfidf_matrix.toarray()
    
    def _fallback_features(self, texts: list) -> np.ndarray:
        """
        Fallback to simple character-level features if TF-IDF fails
        
        Args:
            texts: List of text strings
            
        Returns:
            Feature matrix of shape (n_samples, 9)
        """
        features = []
        for text in texts:
            feature_vector = [
                len(text),  # Length
                len(text.split()),  # Word count
                len(set(text.lower())),  # Unique character count
                text.count('!'),  # Exclamation marks
                text.count('?'),  # Question marks
                text.count('@'),  # At symbols
                text.count('#'),  # Hash symbols
                sum(1 for c in text if c.isupper()),  # Uppercase count
                sum(1 for c in text if c.isdigit()),  # Digit count
            ]
            features.append(feature_vector)
        return np.array(features)
    
    def get_feature_names(self) -> Optional[list]:
        """Get feature names from vectorizer"""
        if self.vectorizer is None:
            return None
        
        try:
            return self.vectorizer.get_feature_names_out().tolist()
        except AttributeError:
            return self.vectorizer.get_feature_names()

