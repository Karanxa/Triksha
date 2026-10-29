"""
Attack-Specific Poisoning Detectors

Implements detectors for specific types of data poisoning attacks:
- Label Flipping
- Backdoor Triggers
- Data Corruption
"""

import numpy as np
from typing import List, Dict, Any, Tuple
from collections import Counter
import re


class LabelFlippingDetector:
    """
    Detects label flipping attacks by analyzing:
    - Inconsistent labels for similar text
    - Sudden label distribution changes
    - Semantically contradictory label assignments
    """
    
    def __init__(self, similarity_threshold: float = 0.85):
        self.similarity_threshold = similarity_threshold
        self.name = "LabelFlipping"
    
    def detect(self, texts: List[str], embeddings: np.ndarray) -> Dict[str, Any]:
        """
        Detect potential label flipping by finding similar texts
        
        Args:
            texts: List of text strings
            embeddings: Embedding vectors for texts
            
        Returns:
            Dictionary with detection results
        """
        from sklearn.metrics.pairwise import cosine_similarity
        
        # Compute pairwise similarities
        similarities = cosine_similarity(embeddings)
        
        suspicious_pairs = []
        duplicate_groups = []
        
        # Find highly similar texts (potential label flipping targets)
        for i in range(len(texts)):
            similar_indices = np.where(similarities[i] > self.similarity_threshold)[0]
            similar_indices = similar_indices[similar_indices != i]  # Exclude self
            
            if len(similar_indices) > 0:
                suspicious_pairs.append({
                    "index": int(i),
                    "text_preview": texts[i][:100],
                    "similar_count": len(similar_indices),
                    "similar_indices": similar_indices.tolist()[:5],  # Top 5
                    "max_similarity": float(np.max(similarities[i, similar_indices]))
                })
        
        # Find exact or near-duplicate groups
        seen = set()
        for i in range(len(texts)):
            if i in seen:
                continue
            
            duplicates = [i]
            for j in range(i+1, len(texts)):
                if j in seen:
                    continue
                if similarities[i, j] > 0.95:  # Very high similarity
                    duplicates.append(j)
                    seen.add(j)
            
            if len(duplicates) > 1:
                duplicate_groups.append({
                    "group_size": len(duplicates),
                    "indices": duplicates,
                    "text_preview": texts[i][:100]
                })
        
        # Calculate risk score
        risk_score = 0.0
        if len(texts) > 0:
            # More suspicious pairs = higher risk
            pair_ratio = len(suspicious_pairs) / len(texts)
            duplicate_ratio = sum(g["group_size"] for g in duplicate_groups) / len(texts)
            risk_score = min(1.0, (pair_ratio * 0.6 + duplicate_ratio * 0.4))
        
        return {
            "detector": self.name,
            "suspicious_pairs_count": len(suspicious_pairs),
            "duplicate_groups_count": len(duplicate_groups),
            "suspicious_pairs": suspicious_pairs[:20],  # Top 20
            "duplicate_groups": duplicate_groups[:10],  # Top 10
            "risk_score": risk_score,
            "risk_level": self._get_risk_level(risk_score),
            "summary": self._generate_summary(suspicious_pairs, duplicate_groups)
        }
    
    def _get_risk_level(self, score: float) -> str:
        if score < 0.3:
            return "LOW"
        elif score < 0.6:
            return "MEDIUM"
        else:
            return "HIGH"
    
    def _generate_summary(self, pairs, groups) -> str:
        if len(pairs) == 0 and len(groups) == 0:
            return "No label flipping indicators detected."
        
        summary = f"Found {len(pairs)} potentially mislabeled samples and {len(groups)} duplicate groups. "
        
        if len(groups) > 0:
            summary += f"Duplicate groups may indicate label manipulation attempts. "
        
        if len(pairs) > len(groups) * 2:
            summary += "High number of similar samples detected - review for label consistency."
        
        return summary


class BackdoorTriggerDetector:
    """
    Detects backdoor triggers by analyzing:
    - Rare words/phrases that appear consistently
    - Unusual character patterns
    - Consistent insertion of specific tokens
    """
    
    def __init__(self, min_frequency: float = 0.01, max_frequency: float = 0.05):
        self.min_frequency = min_frequency
        self.max_frequency = max_frequency
        self.name = "BackdoorTrigger"
    
    def detect(self, texts: List[str]) -> Dict[str, Any]:
        """
        Detect potential backdoor triggers
        
        Args:
            texts: List of text strings
            
        Returns:
            Dictionary with detection results
        """
        total_texts = len(texts)
        
        # 1. Detect rare consistent n-grams
        ngram_triggers = self._detect_ngram_triggers(texts, total_texts)
        
        # 2. Detect special character patterns
        special_triggers = self._detect_special_patterns(texts, total_texts)
        
        # 3. Detect URL/email patterns (common backdoor vectors)
        url_email_triggers = self._detect_url_email_patterns(texts, total_texts)
        
        # 4. Detect position-based triggers (always at start/end)
        positional_triggers = self._detect_positional_patterns(texts)
        
        # Calculate overall risk
        all_triggers = ngram_triggers + special_triggers + url_email_triggers + positional_triggers
        risk_score = min(1.0, len(all_triggers) * 0.15)
        
        return {
            "detector": self.name,
            "total_triggers_found": len(all_triggers),
            "ngram_triggers": ngram_triggers[:10],
            "special_pattern_triggers": special_triggers[:10],
            "url_email_triggers": url_email_triggers[:10],
            "positional_triggers": positional_triggers[:10],
            "risk_score": risk_score,
            "risk_level": self._get_risk_level(risk_score),
            "summary": self._generate_summary(all_triggers)
        }
    
    def _detect_ngram_triggers(self, texts: List[str], total: int) -> List[Dict]:
        triggers = []
        all_ngrams = []
        
        for text in texts:
            tokens = text.split()
            # Get 2-grams and 3-grams
            for n in [2, 3]:
                for i in range(len(tokens) - n + 1):
                    ngram = ' '.join(tokens[i:i+n])
                    all_ngrams.append(ngram)
        
        ngram_counts = Counter(all_ngrams)
        
        for ngram, count in ngram_counts.items():
            frequency = count / total
            # Suspicious: appears in 1-5% but consistently
            if self.min_frequency < frequency < self.max_frequency:
                # Check if it's unusual (contains special chars or rare words)
                if self._is_unusual_ngram(ngram):
                    triggers.append({
                        "trigger": ngram,
                        "frequency": round(frequency, 4),
                        "count": count,
                        "type": "ngram"
                    })
        
        return triggers
    
    def _detect_special_patterns(self, texts: List[str], total: int) -> List[Dict]:
        triggers = []
        
        # Patterns to look for
        patterns = {
            "repeated_special": r'([!@#$%^&*])\1{2,}',  # !!! or ### etc
            "unicode_special": r'[\u2600-\u26FF\u2700-\u27BF]',  # Emojis/symbols
            "base64_like": r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64 encoding
            "hex_pattern": r'0x[0-9a-fA-F]{6,}',  # Hex codes
        }
        
        for pattern_name, pattern in patterns.items():
            matches = []
            for text in texts:
                found = re.findall(pattern, text)
                matches.extend(found)
            
            if matches:
                unique_matches = set(matches)
                for match in unique_matches:
                    count = matches.count(match)
                    frequency = count / total
                    
                    if self.min_frequency < frequency < self.max_frequency:
                        triggers.append({
                            "trigger": str(match)[:50],  # Truncate long matches
                            "frequency": round(frequency, 4),
                            "count": count,
                            "type": f"special_pattern_{pattern_name}"
                        })
        
        return triggers
    
    def _detect_url_email_patterns(self, texts: List[str], total: int) -> List[Dict]:
        triggers = []
        
        url_pattern = r'https?://[^\s]+'
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        
        for pattern_name, pattern in [("url", url_pattern), ("email", email_pattern)]:
            matches = []
            for text in texts:
                found = re.findall(pattern, text)
                matches.extend(found)
            
            if matches:
                match_counts = Counter(matches)
                for match, count in match_counts.items():
                    frequency = count / total
                    
                    if self.min_frequency < frequency < self.max_frequency:
                        triggers.append({
                            "trigger": match[:100],
                            "frequency": round(frequency, 4),
                            "count": count,
                            "type": pattern_name
                        })
        
        return triggers
    
    def _detect_positional_patterns(self, texts: List[str]) -> List[Dict]:
        """Detect tokens that always appear at start or end"""
        triggers = []
        
        # Get first and last tokens
        first_tokens = Counter()
        last_tokens = Counter()
        
        for text in texts:
            tokens = text.split()
            if tokens:
                first_tokens[tokens[0]] += 1
                last_tokens[tokens[-1]] += 1
        
        total = len(texts)
        
        # Check for tokens that appear very frequently at specific positions
        for token, count in first_tokens.items():
            frequency = count / total
            if 0.05 < frequency < 0.2 and len(token) > 3:  # Suspicious consistency
                triggers.append({
                    "trigger": token,
                    "position": "start",
                    "frequency": round(frequency, 4),
                    "count": count,
                    "type": "positional"
                })
        
        for token, count in last_tokens.items():
            frequency = count / total
            if 0.05 < frequency < 0.2 and len(token) > 3:
                triggers.append({
                    "trigger": token,
                    "position": "end",
                    "frequency": round(frequency, 4),
                    "count": count,
                    "type": "positional"
                })
        
        return triggers
    
    def _is_unusual_ngram(self, ngram: str) -> bool:
        """Check if ngram contains unusual patterns"""
        # Contains special characters
        if re.search(r'[!@#$%^&*(){}\[\]<>]', ngram):
            return True
        # All caps
        if ngram.isupper() and len(ngram) > 3:
            return True
        # Contains numbers
        if re.search(r'\d{3,}', ngram):
            return True
        return False
    
    def _get_risk_level(self, score: float) -> str:
        if score < 0.3:
            return "LOW"
        elif score < 0.6:
            return "MEDIUM"
        else:
            return "HIGH"
    
    def _generate_summary(self, triggers: List[Dict]) -> str:
        if len(triggers) == 0:
            return "No backdoor trigger indicators detected."
        
        types = Counter(t["type"] for t in triggers)
        summary = f"Detected {len(triggers)} potential trigger patterns: "
        
        type_descriptions = []
        for trigger_type, count in types.most_common(3):
            type_descriptions.append(f"{count} {trigger_type}")
        
        summary += ", ".join(type_descriptions) + ". "
        summary += "Review these patterns for potential backdoor insertion."
        
        return summary


class DataCorruptionDetector:
    """
    Detects corrupted/malformed data:
    - Encoding issues
    - Truncated text
    - Garbage characters
    - Format inconsistencies
    """
    
    def __init__(self):
        self.name = "DataCorruption"
    
    def detect(self, texts: List[str]) -> Dict[str, Any]:
        """
        Detect data corruption issues
        
        Args:
            texts: List of text strings
            
        Returns:
            Dictionary with detection results
        """
        corrupted_samples = []
        issue_counts = Counter()
        
        for idx, text in enumerate(texts):
            issues = self._analyze_text(text)
            
            if issues:
                issue_counts.update([i["type"] for i in issues])
                corrupted_samples.append({
                    "index": idx,
                    "issues": issues,
                    "issue_count": len(issues),
                    "text_preview": text[:100]
                })
        
        # Calculate risk score
        corruption_ratio = len(corrupted_samples) / max(len(texts), 1)
        avg_issues_per_sample = (
            sum(s["issue_count"] for s in corrupted_samples) / max(len(corrupted_samples), 1)
            if corrupted_samples else 0
        )
        risk_score = min(1.0, corruption_ratio * 0.7 + (avg_issues_per_sample / 10) * 0.3)
        
        return {
            "detector": self.name,
            "corrupted_samples_count": len(corrupted_samples),
            "corruption_ratio": round(corruption_ratio, 4),
            "issue_types": dict(issue_counts),
            "corrupted_samples": corrupted_samples[:20],  # Top 20
            "risk_score": risk_score,
            "risk_level": self._get_risk_level(risk_score),
            "summary": self._generate_summary(corrupted_samples, issue_counts)
        }
    
    def _analyze_text(self, text: str) -> List[Dict[str, str]]:
        """Analyze a single text for corruption issues"""
        issues = []
        
        # 1. Check encoding issues
        if self._has_encoding_issues(text):
            issues.append({"type": "encoding_error", "description": "Possible encoding/mojibake"})
        
        # 2. Excessive special characters
        special_ratio = sum(1 for c in text if not c.isalnum() and not c.isspace()) / max(len(text), 1)
        if special_ratio > 0.3:
            issues.append({"type": "excessive_special_chars", "description": f"{special_ratio:.1%} special characters"})
        
        # 3. Repeated patterns
        if self._has_repeated_patterns(text):
            issues.append({"type": "repeated_patterns", "description": "Suspicious repetition detected"})
        
        # 4. Truncation
        if len(text) < 5:
            issues.append({"type": "too_short", "description": "Extremely short text"})
        elif len(text) > 50 and not any(text.endswith(p) for p in ['.', '!', '?', '"', "'", ')', ']']):
            issues.append({"type": "possible_truncation", "description": "May be truncated"})
        
        # 5. Mixed scripts (English + Chinese/Arabic etc)
        if self._has_mixed_scripts(text):
            issues.append({"type": "mixed_scripts", "description": "Multiple writing systems detected"})
        
        # 6. Control characters
        if any(ord(c) < 32 and c not in '\n\r\t' for c in text):
            issues.append({"type": "control_characters", "description": "Contains control characters"})
        
        # 7. Null bytes or unusual whitespace
        if '\x00' in text or '\\x00' in text:
            issues.append({"type": "null_bytes", "description": "Contains null bytes"})
        
        return issues
    
    def _has_encoding_issues(self, text: str) -> bool:
        """Detect common encoding issues"""
        # Check for mojibake patterns
        mojibake_patterns = ['Ã', 'â€', 'Â', '�']
        return any(pattern in text for pattern in mojibake_patterns)
    
    def _has_repeated_patterns(self, text: str) -> bool:
        """Detect suspicious repetition"""
        words = text.split()
        if len(words) < 5:
            return False
        
        # Check for repeated consecutive words
        for i in range(len(words) - 2):
            if words[i] == words[i+1] == words[i+2]:
                return True
        
        # Check for repeated character sequences
        if re.search(r'(.{3,})\1{3,}', text):
            return True
        
        return False
    
    def _has_mixed_scripts(self, text: str) -> bool:
        """Detect mixed writing systems"""
        has_latin = bool(re.search(r'[a-zA-Z]', text))
        has_cyrillic = bool(re.search(r'[а-яА-Я]', text))
        has_arabic = bool(re.search(r'[\u0600-\u06FF]', text))
        has_cjk = bool(re.search(r'[\u4E00-\u9FFF\u3040-\u309F\u30A0-\u30FF]', text))
        
        script_count = sum([has_latin, has_cyrillic, has_arabic, has_cjk])
        return script_count > 1
    
    def _get_risk_level(self, score: float) -> str:
        if score < 0.2:
            return "LOW"
        elif score < 0.5:
            return "MEDIUM"
        else:
            return "HIGH"
    
    def _generate_summary(self, samples: List[Dict], issue_counts: Counter) -> str:
        if len(samples) == 0:
            return "No data corruption detected."
        
        summary = f"Found {len(samples)} corrupted samples. "
        
        if issue_counts:
            top_issue = issue_counts.most_common(1)[0]
            summary += f"Most common issue: {top_issue[0]} ({top_issue[1]} occurrences). "
        
        if len(samples) > len(issue_counts) * 5:
            summary += "Multiple issues per sample detected - data quality is poor."
        
        return summary

