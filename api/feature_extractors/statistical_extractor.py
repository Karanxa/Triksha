"""
Statistical Feature Extractor

Extracts various statistical and linguistic features from text:
- Lexical diversity (Type-Token Ratio)
- Entropy measures
- Readability scores
- Syntactic complexity
- Perplexity (if language model available)
"""

import numpy as np
from typing import List, Dict, Any
from collections import Counter
import re


class StatisticalFeatureExtractor:
    """Extract statistical and linguistic features from text"""
    
    def __init__(self, use_perplexity: bool = False):
        """
        Initialize statistical feature extractor
        
        Args:
            use_perplexity: Whether to compute perplexity scores (requires transformers)
        """
        self.use_perplexity = use_perplexity
        self.perplexity_model = None
        
        if use_perplexity:
            self._load_perplexity_model()
    
    def _load_perplexity_model(self):
        """Load small language model for perplexity calculation"""
        try:
            from transformers import AutoTokenizer, AutoModelForCausalLM
            import torch
            
            model_name = "gpt2"  # Small and fast
            self.perplexity_tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.perplexity_model = AutoModelForCausalLM.from_pretrained(model_name)
            self.perplexity_model.eval()
            
            # Set padding token
            if self.perplexity_tokenizer.pad_token is None:
                self.perplexity_tokenizer.pad_token = self.perplexity_tokenizer.eos_token
            
            print("Perplexity model loaded successfully")
        except Exception as e:
            print(f"Warning: Could not load perplexity model: {e}")
            self.perplexity_model = None
    
    def extract(self, texts: List[str]) -> np.ndarray:
        """
        Extract statistical features from texts
        
        Args:
            texts: List of text strings
            
        Returns:
            Feature matrix of shape (n_samples, n_features)
        """
        features = []
        
        for text in texts:
            feature_dict = {}
            
            # Basic statistics
            feature_dict.update(self._extract_basic_stats(text))
            
            # Lexical diversity
            feature_dict.update(self._extract_lexical_diversity(text))
            
            # Entropy measures
            feature_dict.update(self._extract_entropy(text))
            
            # Syntactic features
            feature_dict.update(self._extract_syntactic_features(text))
            
            # Readability scores
            feature_dict.update(self._extract_readability(text))
            
            # Perplexity (if enabled)
            if self.use_perplexity and self.perplexity_model:
                feature_dict['perplexity'] = self._compute_perplexity(text)
            else:
                feature_dict['perplexity'] = 0.0
            
            # Convert to array
            feature_vector = list(feature_dict.values())
            features.append(feature_vector)
        
        return np.array(features)
    
    def _extract_basic_stats(self, text: str) -> Dict[str, float]:
        """Extract basic text statistics"""
        words = text.split()
        
        return {
            'char_count': len(text),
            'word_count': len(words),
            'unique_word_count': len(set(words)),
            'avg_word_length': np.mean([len(w) for w in words]) if words else 0,
            'std_word_length': np.std([len(w) for w in words]) if len(words) > 1 else 0,
        }
    
    def _extract_lexical_diversity(self, text: str) -> Dict[str, float]:
        """Extract lexical diversity metrics"""
        words = text.lower().split()
        
        if not words:
            return {
                'type_token_ratio': 0.0,
                'hapax_ratio': 0.0,
                'yules_k': 0.0
            }
        
        # Type-Token Ratio
        ttr = len(set(words)) / len(words)
        
        # Hapax Legomena Ratio (words appearing once)
        word_freq = Counter(words)
        hapax = sum(1 for freq in word_freq.values() if freq == 1)
        hapax_ratio = hapax / len(words)
        
        # Yule's K (measure of vocabulary richness)
        N = len(words)
        freq_counts = Counter(word_freq.values())
        yules_k = 10000 * (sum(i**2 * freq_counts[i] for i in freq_counts) - N) / (N**2)
        
        return {
            'type_token_ratio': ttr,
            'hapax_ratio': hapax_ratio,
            'yules_k': yules_k
        }
    
    def _extract_entropy(self, text: str) -> Dict[str, float]:
        """Extract entropy measures"""
        # Character entropy
        char_freq = Counter(text.lower())
        char_probs = np.array([count / len(text) for count in char_freq.values()])
        char_entropy = -np.sum(char_probs * np.log2(char_probs + 1e-10))
        
        # Word entropy
        words = text.lower().split()
        if words:
            word_freq = Counter(words)
            word_probs = np.array([count / len(words) for count in word_freq.values()])
            word_entropy = -np.sum(word_probs * np.log2(word_probs + 1e-10))
        else:
            word_entropy = 0.0
        
        return {
            'char_entropy': char_entropy,
            'word_entropy': word_entropy
        }
    
    def _extract_syntactic_features(self, text: str) -> Dict[str, float]:
        """Extract syntactic complexity features"""
        # Count punctuation
        punct_count = sum(1 for c in text if c in '!?.,;:')
        punct_ratio = punct_count / max(len(text), 1)
        
        # Count special characters
        special_count = sum(1 for c in text if not c.isalnum() and not c.isspace())
        special_ratio = special_count / max(len(text), 1)
        
        # Uppercase ratio
        upper_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        
        # Digit ratio
        digit_ratio = sum(1 for c in text if c.isdigit()) / max(len(text), 1)
        
        # Sentence count (approximate)
        sentences = re.split(r'[.!?]+', text)
        sentence_count = len([s for s in sentences if s.strip()])
        
        # Average sentence length
        words = text.split()
        avg_sentence_length = len(words) / max(sentence_count, 1)
        
        return {
            'punct_ratio': punct_ratio,
            'special_char_ratio': special_ratio,
            'uppercase_ratio': upper_ratio,
            'digit_ratio': digit_ratio,
            'sentence_count': sentence_count,
            'avg_sentence_length': avg_sentence_length
        }
    
    def _extract_readability(self, text: str) -> Dict[str, float]:
        """Extract readability scores"""
        words = text.split()
        sentences = re.split(r'[.!?]+', text)
        sentences = [s for s in sentences if s.strip()]
        
        if not words or not sentences:
            return {
                'flesch_reading_ease': 0.0,
                'flesch_kincaid_grade': 0.0
            }
        
        # Count syllables (approximate)
        def count_syllables(word):
            word = word.lower()
            vowels = 'aeiou'
            syllable_count = 0
            previous_was_vowel = False
            
            for char in word:
                is_vowel = char in vowels
                if is_vowel and not previous_was_vowel:
                    syllable_count += 1
                previous_was_vowel = is_vowel
            
            # Adjust for silent e
            if word.endswith('e'):
                syllable_count -= 1
            
            # Each word has at least one syllable
            if syllable_count == 0:
                syllable_count = 1
            
            return syllable_count
        
        total_syllables = sum(count_syllables(word) for word in words)
        
        # Flesch Reading Ease
        avg_sentence_length = len(words) / len(sentences)
        avg_syllables_per_word = total_syllables / len(words)
        
        flesch_reading_ease = 206.835 - 1.015 * avg_sentence_length - 84.6 * avg_syllables_per_word
        
        # Flesch-Kincaid Grade Level
        flesch_kincaid_grade = 0.39 * avg_sentence_length + 11.8 * avg_syllables_per_word - 15.59
        
        return {
            'flesch_reading_ease': flesch_reading_ease,
            'flesch_kincaid_grade': max(0, flesch_kincaid_grade)  # Clip to 0
        }
    
    def _compute_perplexity(self, text: str) -> float:
        """Compute perplexity using language model"""
        if self.perplexity_model is None:
            return 0.0
        
        try:
            import torch
            
            # Tokenize
            inputs = self.perplexity_tokenizer(
                text,
                return_tensors='pt',
                truncation=True,
                max_length=512
            )
            
            # Compute loss
            with torch.no_grad():
                outputs = self.perplexity_model(**inputs, labels=inputs['input_ids'])
                loss = outputs.loss
            
            # Perplexity = exp(loss)
            perplexity = torch.exp(loss).item()
            
            return perplexity
        except Exception as e:
            print(f"Perplexity computation failed: {e}")
            return 0.0
    
    def get_feature_names(self) -> List[str]:
        """Get names of all extracted features"""
        feature_names = [
            # Basic stats
            'char_count', 'word_count', 'unique_word_count', 
            'avg_word_length', 'std_word_length',
            # Lexical diversity
            'type_token_ratio', 'hapax_ratio', 'yules_k',
            # Entropy
            'char_entropy', 'word_entropy',
            # Syntactic
            'punct_ratio', 'special_char_ratio', 'uppercase_ratio',
            'digit_ratio', 'sentence_count', 'avg_sentence_length',
            # Readability
            'flesch_reading_ease', 'flesch_kincaid_grade',
            # Perplexity
            'perplexity'
        ]
        return feature_names

