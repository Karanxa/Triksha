"""
Deep Embedding Feature Extractor

Uses pre-trained models (BERT, Sentence Transformers) to extract 
semantic embeddings from text.
"""

import numpy as np
from typing import Optional, List


class EmbeddingExtractor:
    """Deep embedding extractor using Sentence Transformers"""
    
    def __init__(
        self,
        model_name: str = 'all-MiniLM-L6-v2',
        batch_size: int = 32,
        normalize: bool = True
    ):
        """
        Initialize embedding extractor
        
        Args:
            model_name: Name of sentence-transformers model
                       'all-MiniLM-L6-v2' - Fast, 384 dimensions
                       'all-mpnet-base-v2' - Best quality, 768 dimensions
            batch_size: Batch size for encoding
            normalize: Whether to normalize embeddings
        """
        self.model_name = model_name
        self.batch_size = batch_size
        self.normalize = normalize
        self.model = None
        
        self._load_model()
    
    def _load_model(self):
        """Load sentence transformer model"""
        try:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(self.model_name)
        except ImportError:
            print("Warning: sentence-transformers not installed. "
                  "Run: pip install sentence-transformers")
            self.model = None
        except Exception as e:
            print(f"Warning: Failed to load embedding model: {e}")
            self.model = None
    
    def extract(self, texts: List[str]) -> np.ndarray:
        """
        Extract embeddings from texts
        
        Args:
            texts: List of text strings
            
        Returns:
            Embedding matrix of shape (n_samples, embedding_dim)
        """
        if self.model is None:
            # Fallback to simple features if model not available
            print("Embedding model not available, using fallback")
            return self._fallback_features(texts)
        
        try:
            embeddings = self.model.encode(
                texts,
                batch_size=self.batch_size,
                normalize_embeddings=self.normalize,
                show_progress_bar=False
            )
            return np.array(embeddings)
        except Exception as e:
            print(f"Embedding extraction failed: {e}, using fallback")
            return self._fallback_features(texts)
    
    def _fallback_features(self, texts: List[str]) -> np.ndarray:
        """
        Fallback features when embeddings are not available
        
        Returns simple statistical features with consistent dimensionality
        """
        features = []
        for text in texts:
            words = text.split()
            # Create a 50-dimensional feature vector (to maintain reasonable dimensionality)
            feature_vector = [
                len(text),  # Total length
                len(words),  # Word count
                len(set(words)),  # Unique word count
                np.mean([len(w) for w in words]) if words else 0,  # Avg word length
                np.std([len(w) for w in words]) if len(words) > 1 else 0,  # Std word length
                sum(1 for c in text if c.isupper()) / max(len(text), 1),  # Uppercase ratio
                sum(1 for c in text if c.islower()) / max(len(text), 1),  # Lowercase ratio
                sum(1 for c in text if c.isdigit()) / max(len(text), 1),  # Digit ratio
                sum(1 for c in text if c.isspace()) / max(len(text), 1),  # Whitespace ratio
                sum(1 for c in text if c in '!?.,;:') / max(len(text), 1),  # Punctuation ratio
            ]
            # Pad to 50 dimensions with zeros
            feature_vector.extend([0] * (50 - len(feature_vector)))
            features.append(feature_vector)
        
        return np.array(features)
    
    def get_embedding_dim(self) -> int:
        """Get embedding dimensionality"""
        if self.model is None:
            return 50  # Fallback feature dim
        
        # Test with a dummy text
        test_embedding = self.model.encode(["test"], show_progress_bar=False)
        return test_embedding.shape[1]

