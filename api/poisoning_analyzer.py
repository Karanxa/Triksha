"""
Enhanced Dataset Poisoning Analyzer

Comprehensive poisoning detection using:
- Multiple statistical detectors (ensemble)
- Attack-specific detectors
- Hybrid feature extraction (TF-IDF + Embeddings + Statistical)
- AI-powered semantic validation
"""

import numpy as np
from typing import List, Dict, Any, Tuple
from datetime import datetime
from sklearn.preprocessing import StandardScaler

# Import feature extractors
from feature_extractors.combined_extractor import CombinedFeatureExtractor

# Import detectors
from detectors.statistical_detectors import (
    IsolationForestDetector,
    LOFDetector,
    OneClassSVMDetector,
    MahalanobisDetector
)
from detectors.clustering_detectors import DBSCANDetector
from detectors.ensemble_detector import EnsembleDetector

# Import attack-specific detectors
from detectors.attack_specific_detectors import (
    LabelFlippingDetector,
    BackdoorTriggerDetector,
    DataCorruptionDetector
)


class EnhancedPoisoningAnalyzer:
    """
    Enhanced analyzer that combines multiple detection methods
    """
    
    def __init__(
        self,
        contamination: float = 0.1,
        use_embeddings: bool = True,
        voting_threshold: int = 2
    ):
        """
        Initialize enhanced analyzer
        
        Args:
            contamination: Expected contamination rate (0.05-0.2)
            use_embeddings: Whether to use deep embeddings
            voting_threshold: Minimum detectors that must agree (2-3 recommended)
        """
        self.contamination = contamination
        self.use_embeddings = use_embeddings
        self.voting_threshold = voting_threshold
        
        # Initialize feature extractor
        self.feature_extractor = CombinedFeatureExtractor(
            use_tfidf=True,
            use_embeddings=use_embeddings,
            use_statistical=True,
            tfidf_max_features=500,
            embedding_model='all-MiniLM-L6-v2'
        )
        
        # Initialize attack-specific detectors
        self.label_flipping_detector = LabelFlippingDetector()
        self.backdoor_detector = BackdoorTriggerDetector()
        self.corruption_detector = DataCorruptionDetector()
    
    def analyze(self, texts: List[str]) -> Dict[str, Any]:
        """
        Comprehensive poisoning analysis
        
        Args:
            texts: List of text strings to analyze
            
        Returns:
            Complete analysis results with all detections
        """
        if len(texts) < 10:
            raise ValueError("Dataset must contain at least 10 entries for meaningful analysis")
        
        print(f"\n{'='*60}")
        print(f"ENHANCED POISONING ANALYSIS")
        print(f"{'='*60}")
        print(f"Analyzing {len(texts)} samples...")
        
        # Step 1: Extract hybrid features
        print(f"\n[1/5] Extracting features...")
        features_normalized, embeddings = self._extract_features(texts)
        
        # Step 2: Run ensemble statistical detection
        print(f"\n[2/5] Running ensemble anomaly detection...")
        ensemble_results = self._run_ensemble_detection(features_normalized)
        
        # Step 3: Run attack-specific detectors
        print(f"\n[3/5] Running attack-specific detectors...")
        attack_results = self._run_attack_detection(texts, (features_normalized, embeddings))
        
        # Step 4: Combine results and calculate risk
        print(f"\n[4/5] Combining results...")
        combined_results = self._combine_results(
            texts, (features_normalized, embeddings), ensemble_results, attack_results
        )
        
        # Step 5: Generate final analysis
        print(f"\n[5/5] Generating final analysis...")
        final_analysis = self._generate_final_analysis(
            texts, ensemble_results, attack_results, combined_results
        )
        
        print(f"\n{'='*60}")
        print(f"ANALYSIS COMPLETE")
        print(f"{'='*60}\n")
        
        return final_analysis
    
    def _extract_features(self, texts: List[str]) -> Tuple[np.ndarray, np.ndarray]:
        """Extract hybrid features"""
        try:
            # Extract combined features
            features = self.feature_extractor.extract(texts)
            
            # Ensure features is a 2D numpy array
            if not isinstance(features, np.ndarray):
                features = np.array(features)
            
            if len(features.shape) != 2:
                raise ValueError(f"Features must be 2D array, got shape {features.shape}")
            
            # Normalize features
            scaler = StandardScaler()
            features_normalized = scaler.fit_transform(features)
            
            # Also extract embeddings separately for label flipping detector
            from feature_extractors.embedding_extractor import EmbeddingExtractor
            embedding_extractor = EmbeddingExtractor(model_name='all-MiniLM-L6-v2')
            embeddings = embedding_extractor.extract(texts)
            
            # Ensure embeddings is also a 2D array
            if not isinstance(embeddings, np.ndarray):
                embeddings = np.array(embeddings)
            
            if len(embeddings.shape) != 2:
                raise ValueError(f"Embeddings must be 2D array, got shape {embeddings.shape}")
            
            print(f"✓ Feature extraction complete: {features_normalized.shape}")
            
            return features_normalized, embeddings
        
        except Exception as e:
            print(f"✗ Feature extraction error: {e}")
            import traceback
            traceback.print_exc()
            # Fallback to simple features
            return self._fallback_features(texts), np.zeros((len(texts), 50))
    
    def _fallback_features(self, texts: List[str]) -> np.ndarray:
        """Fallback feature extraction"""
        features = []
        for text in texts:
            feature_vector = [
                len(text),
                len(text.split()),
                len(set(text.lower())),
                text.count('!'),
                text.count('?'),
                text.count('@'),
                text.count('#'),
                sum(1 for c in text if c.isupper()),
                sum(1 for c in text if c.isdigit()),
            ]
            features.append(feature_vector)
        
        scaler = StandardScaler()
        return scaler.fit_transform(np.array(features))
    
    def _run_ensemble_detection(self, features: np.ndarray) -> Dict[str, Any]:
        """Run ensemble statistical detection"""
        try:
            # Initialize detectors
            detectors = [
                IsolationForestDetector(
                    contamination=self.contamination,
                    n_estimators=100
                ),
                LOFDetector(
                    n_neighbors=min(20, len(features) // 5),
                    contamination=self.contamination
                ),
                DBSCANDetector(
                    eps='auto',
                    min_samples=max(3, len(features) // 50)
                ),
                OneClassSVMDetector(
                    nu=self.contamination,
                    kernel='rbf'
                )
            ]
            
            # Fit all detectors
            print(f"  Fitting {len(detectors)} detectors...")
            for detector in detectors:
                detector.fit(features)
            
            # Create ensemble
            ensemble = EnsembleDetector(
                detectors=detectors,
                voting_threshold=self.voting_threshold,
                weights=[0.3, 0.25, 0.25, 0.2]  # IsolationForest has highest weight
            )
            
            # Get detailed results
            suspicious_indices, scores, details = ensemble.get_suspicious_indices(
                features,
                return_details=True
            )
            
            # Get summary
            summary = ensemble.get_ensemble_summary(features)
            
            print(f"✓ Ensemble detection complete: {len(suspicious_indices)} suspicious samples")
            
            return {
                "suspicious_indices": suspicious_indices,
                "anomaly_scores": scores,
                "per_detector_results": details["detectors"],
                "vote_counts": details["vote_counts"],
                "agreement_matrix": details["agreement_matrix"],
                "summary": summary,
                "detector_names": [d.name for d in detectors]
            }
        
        except Exception as e:
            print(f"✗ Ensemble detection error: {e}")
            import traceback
            traceback.print_exc()
            # Fallback to single detector
            return self._fallback_detection(features)
    
    def _fallback_detection(self, features: np.ndarray) -> Dict[str, Any]:
        """Fallback to single Isolation Forest if ensemble fails"""
        from sklearn.ensemble import IsolationForest
        
        model = IsolationForest(contamination=self.contamination, random_state=42)
        predictions = model.fit_predict(features)
        scores = -model.decision_function(features)
        
        suspicious_indices = np.where(predictions == -1)[0]
        
        return {
            "suspicious_indices": suspicious_indices,
            "anomaly_scores": scores,
            "per_detector_results": [{"name": "IsolationForest (fallback)", "n_suspicious": len(suspicious_indices)}],
            "vote_counts": [1 if p == -1 else 0 for p in predictions],
            "summary": {"n_suspicious": len(suspicious_indices)},
            "detector_names": ["IsolationForest"]
        }
    
    def _run_attack_detection(self, texts: List[str], features: Tuple[np.ndarray, np.ndarray]) -> Dict[str, Any]:
        """Run attack-specific detectors"""
        features_normalized, embeddings = features
        
        results = {}
        
        # 1. Label Flipping Detection
        try:
            print(f"  Running Label Flipping detector...")
            results["label_flipping"] = self.label_flipping_detector.detect(texts, embeddings)
            print(f"  ✓ Found {results['label_flipping']['suspicious_pairs_count']} suspicious pairs")
        except Exception as e:
            print(f"  ✗ Label Flipping detection failed: {e}")
            results["label_flipping"] = {"error": str(e), "risk_score": 0}
        
        # 2. Backdoor Trigger Detection
        try:
            print(f"  Running Backdoor Trigger detector...")
            results["backdoor_triggers"] = self.backdoor_detector.detect(texts)
            print(f"  ✓ Found {results['backdoor_triggers']['total_triggers_found']} potential triggers")
        except Exception as e:
            print(f"  ✗ Backdoor detection failed: {e}")
            results["backdoor_triggers"] = {"error": str(e), "risk_score": 0}
        
        # 3. Data Corruption Detection
        try:
            print(f"  Running Data Corruption detector...")
            results["data_corruption"] = self.corruption_detector.detect(texts)
            print(f"  ✓ Found {results['data_corruption']['corrupted_samples_count']} corrupted samples")
        except Exception as e:
            print(f"  ✗ Corruption detection failed: {e}")
            results["data_corruption"] = {"error": str(e), "risk_score": 0}
        
        return results
    
    def _combine_results(
        self,
        texts: List[str],
        features: Tuple[np.ndarray, np.ndarray],
        ensemble_results: Dict,
        attack_results: Dict
    ) -> Dict[str, Any]:
        """Combine all detection results"""
        features_normalized, embeddings = features
        
        # Get all suspicious indices from ensemble
        ensemble_suspicious = set(ensemble_results["suspicious_indices"].tolist())
        
        # Get suspicious from attack detectors
        label_flipping_suspicious = set()
        if "label_flipping" in attack_results and "suspicious_pairs" in attack_results["label_flipping"]:
            for pair in attack_results["label_flipping"]["suspicious_pairs"]:
                label_flipping_suspicious.add(pair["index"])
        
        backdoor_suspicious = set()
        if "backdoor_triggers" in attack_results and "ngram_triggers" in attack_results["backdoor_triggers"]:
            # Find texts containing triggers
            triggers = [t["trigger"] for t in attack_results["backdoor_triggers"]["ngram_triggers"][:5]]
            for idx, text in enumerate(texts):
                if any(trigger in text for trigger in triggers):
                    backdoor_suspicious.add(idx)
        
        corruption_suspicious = set()
        if "data_corruption" in attack_results and "corrupted_samples" in attack_results["data_corruption"]:
            corruption_suspicious = set(
                s["index"] for s in attack_results["data_corruption"]["corrupted_samples"]
            )
        
        # Combine all suspicious indices
        all_suspicious = ensemble_suspicious | label_flipping_suspicious | backdoor_suspicious | corruption_suspicious
        
        # Calculate consensus scores
        suspicious_details = []
        for idx in all_suspicious:
            detection_sources = []
            if idx in ensemble_suspicious:
                detection_sources.append("ensemble")
            if idx in label_flipping_suspicious:
                detection_sources.append("label_flipping")
            if idx in backdoor_suspicious:
                detection_sources.append("backdoor")
            if idx in corruption_suspicious:
                detection_sources.append("corruption")
            
            anomaly_score = ensemble_results["anomaly_scores"][idx]
            confidence = len(detection_sources) / 4  # 0-1 based on how many detectors flagged it
            
            suspicious_details.append({
                "index": int(idx),
                "text_preview": texts[idx][:200],
                "anomaly_score": float(anomaly_score),
                "confidence": round(confidence, 2),
                "detection_sources": detection_sources,
                "risk_level": self._calculate_risk_level(anomaly_score, confidence)
            })
        
        # Sort by confidence and anomaly score
        suspicious_details.sort(key=lambda x: (x["confidence"], x["anomaly_score"]), reverse=True)
        
        return {
            "total_suspicious": len(all_suspicious),
            "ensemble_only": len(ensemble_suspicious - label_flipping_suspicious - backdoor_suspicious - corruption_suspicious),
            "multi_source": len([s for s in suspicious_details if len(s["detection_sources"]) > 1]),
            "suspicious_details": suspicious_details
        }
    
    def _calculate_risk_level(self, anomaly_score: float, confidence: float) -> str:
        """Calculate risk level based on anomaly score and confidence"""
        combined_score = (anomaly_score * 0.6 + confidence * 0.4)
        
        if combined_score > 0.7:
            return "HIGH"
        elif combined_score > 0.4:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_final_analysis(
        self,
        texts: List[str],
        ensemble_results: Dict,
        attack_results: Dict,
        combined_results: Dict
    ) -> Dict[str, Any]:
        """Generate final comprehensive analysis"""
        
        # Calculate overall security score
        total_samples = len(texts)
        suspicious_ratio = combined_results["total_suspicious"] / total_samples
        
        # Weight different factors
        ensemble_score = (1 - suspicious_ratio) * 100
        label_flip_score = (1 - attack_results.get("label_flipping", {}).get("risk_score", 0)) * 100
        backdoor_score = (1 - attack_results.get("backdoor_triggers", {}).get("risk_score", 0)) * 100
        corruption_score = (1 - attack_results.get("data_corruption", {}).get("risk_score", 0)) * 100
        
        # Weighted average (ensemble has highest weight)
        final_security_score = int(
            ensemble_score * 0.4 +
            label_flip_score * 0.2 +
            backdoor_score * 0.2 +
            corruption_score * 0.2
        )
        
        # Determine if poisoned
        is_poisoned = (
            suspicious_ratio > 0.15 or
            final_security_score < 70 or
            attack_results.get("backdoor_triggers", {}).get("risk_score", 0) > 0.6
        )
        
        # Generate summary
        summary = self._generate_summary(
            ensemble_results,
            attack_results,
            combined_results,
            final_security_score,
            is_poisoned
        )
        
        return {
            "is_poisoned": is_poisoned,
            "security_score": final_security_score,
            "confidence_level": "high" if combined_results["multi_source"] > 5 else "medium",
            "total_samples": total_samples,
            "suspicious_count": combined_results["total_suspicious"],
            "suspicious_ratio": round(suspicious_ratio, 4),
            
            # Detection breakdown
            "detection_breakdown": {
                "ensemble": {
                    "suspicious_count": len(ensemble_results["suspicious_indices"]),
                    "detectors_used": ensemble_results["detector_names"],
                    "per_detector": ensemble_results["per_detector_results"]
                },
                "label_flipping": attack_results.get("label_flipping", {}),
                "backdoor_triggers": attack_results.get("backdoor_triggers", {}),
                "data_corruption": attack_results.get("data_corruption", {})
            },
            
            # Suspicious samples with full details
            "suspicious_entries": combined_results["suspicious_details"][:50],  # Top 50
            
            # Metadata
            "analysis_metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "contamination_rate": self.contamination,
                "voting_threshold": self.voting_threshold,
                "features_used": "TF-IDF + Embeddings + Statistical" if self.use_embeddings else "TF-IDF + Statistical",
                "detectors_count": len(ensemble_results["detector_names"]) + 3,  # + 3 attack detectors
            },
            
            # Summary
            "summary": summary
        }
    
    def _generate_summary(
        self,
        ensemble_results: Dict,
        attack_results: Dict,
        combined_results: Dict,
        security_score: int,
        is_poisoned: bool
    ) -> str:
        """Generate human-readable summary"""
        lines = []
        
        # Overall assessment
        if is_poisoned:
            lines.append(f"⚠️  DATASET IS POTENTIALLY POISONED (Security Score: {security_score}/100)")
        else:
            lines.append(f"✓ Dataset appears clean (Security Score: {security_score}/100)")
        
        lines.append(f"\nFound {combined_results['total_suspicious']} suspicious samples total:")
        
        # Ensemble results
        ensemble_count = len(ensemble_results["suspicious_indices"])
        lines.append(f"  • Ensemble detectors: {ensemble_count} samples")
        
        # Attack-specific results
        if "label_flipping" in attack_results:
            lf = attack_results["label_flipping"]
            if lf.get("risk_level") != "LOW":
                lines.append(f"  • Label flipping risk: {lf.get('risk_level', 'UNKNOWN')} ({lf.get('suspicious_pairs_count', 0)} pairs)")
        
        if "backdoor_triggers" in attack_results:
            bt = attack_results["backdoor_triggers"]
            if bt.get("total_triggers_found", 0) > 0:
                lines.append(f"  • Backdoor triggers: {bt['total_triggers_found']} potential triggers found")
        
        if "data_corruption" in attack_results:
            dc = attack_results["data_corruption"]
            if dc.get("corrupted_samples_count", 0) > 0:
                lines.append(f"  • Data corruption: {dc['corrupted_samples_count']} corrupted samples")
        
        # Confidence assessment
        if combined_results["multi_source"] > 0:
            lines.append(f"\n{combined_results['multi_source']} samples flagged by multiple detectors (high confidence)")
        
        return "\n".join(lines)


# Convenience function for API endpoint
def analyze_dataset_poisoning_enhanced(texts: List[str], contamination: float = 0.1) -> Dict[str, Any]:
    """
    Analyze dataset for poisoning using enhanced multi-detector approach
    
    Args:
        texts: List of text samples
        contamination: Expected contamination rate (0.05-0.2)
        
    Returns:
        Complete analysis results
    """
    analyzer = EnhancedPoisoningAnalyzer(
        contamination=contamination,
        use_embeddings=True,
        voting_threshold=2
    )
    
    return analyzer.analyze(texts)

