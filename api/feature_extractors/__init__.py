"""
Feature Extraction Framework for Dataset Poisoning Detection

Provides various feature extraction methods:
- TF-IDF (traditional text features)
- Deep embeddings (BERT, Sentence Transformers)
- Perplexity scores (language model based)
- Statistical text features
"""

from .tfidf_extractor import TFIDFExtractor
from .embedding_extractor import EmbeddingExtractor
from .statistical_extractor import StatisticalFeatureExtractor
from .combined_extractor import CombinedFeatureExtractor

__all__ = [
    'TFIDFExtractor',
    'EmbeddingExtractor',
    'StatisticalFeatureExtractor',
    'CombinedFeatureExtractor'
]

