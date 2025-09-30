"""
Production Injection Detection System
Provides both binary detection and attack type classification
"""

import torch
import torch.nn as nn
from typing import Dict, List, Optional, Any
import numpy as np
from models import InjectionDetectionModel, MultiClassInjectionModel
from rule_filter import RuleBasedInjectionFilter

class InjectionDetector:
    """
    Production-ready injection detection system
    
    Usage:
        detector = InjectionDetector(
            binary_model_path='models/binary_model.pth',
            multiclass_model_path='models/multiclass_model.pth'
        )
        
        result = detector.detect('SELECT * FROM users')
    """
    
    def __init__(self,
                 binary_model_path: str,
                 multiclass_model_path: str,
                 device: str = None,
                 max_length: int = 2048):
        """
        Initialize detector with trained models
        
        Args:
            binary_model_path: Path to binary classification model (.pth)
            multiclass_model_path: Path to multi-class model (.pth)
            device: 'cuda' or 'cpu'. Auto-detects if None
            max_length: Maximum input length (default: 2048)
        """
        
        if device is None:
            self.device = 'cpu'
        else:
            self.device = device
            
        self.max_length = max_length
        
        # Initialize rule-based filter
        self.rule_filter = RuleBasedInjectionFilter()
        
        # Load binary model
        print(f"Loading binary model from {binary_model_path}...")
        self.binary_model = InjectionDetectionModel()
        self.binary_model.load_state_dict(torch.load(binary_model_path, map_location=self.device))
        self.binary_model.to(self.device)
        self.binary_model.eval()
        
        # Load multi-class model
        print(f"Loading multi-class model from {multiclass_model_path}...")
        base_model = InjectionDetectionModel()
        self.multiclass_model = MultiClassInjectionModel(base_model, num_classes=4)
        self.multiclass_model.load_state_dict(torch.load(multiclass_model_path, map_location=self.device))
        self.multiclass_model.to(self.device)
        self.multiclass_model.eval()
        
        self.attack_types = ['sqli', 'commandi', 'xss', 'traversal']
        
        print(f"Models loaded successfully on {self.device}")
    
    def _preprocess(self, text: str) -> Dict[str, torch.Tensor]:
        """Convert text to model input format"""
        
        # Convert to bytes
        byte_sequence = list(text.encode('utf-8'))
        
        if len(byte_sequence) > self.max_length:
            byte_sequence = byte_sequence[:self.max_length]
            
        attention_mask = [False] * len(byte_sequence)
        
        while len(byte_sequence) < self.max_length:
            byte_sequence.append(0)
            attention_mask.append(True)
            
        return {
            'input_ids': torch.tensor([byte_sequence], dtype=torch.long).to(self.device),
            'attention_mask': torch.tensor([attention_mask], dtype=torch.bool).to(self.device)
        }
    
    def detect(self, text: str, threshold: float = 0.5, use_rule_filter: bool = True) -> Dict:
        """
        Detect if input contains injection attack
        
        Args:
            text: Input text to analyze
            threshold: Detection threshold (default: 0.5)
            use_rule_filter: Whether to use rule-based pre-filtering
            
        Returns:
            Dict with detection results:
            {
                'is_malicious': bool,
                'confidence': float,
                'attack_type': str or None,
                'attack_confidence': float or None,
                'rule_result': int (0=benign, 1=malicious, 2=ambiguous)
            }
        """
        
        if not text or not text.strip():
            return {
                'is_malicious': False,
                'confidence': 1.0,
                'attack_type': None,
                'attack_confidence': None,
                'rule_result': 0
            }
        
        # Rule-based pre-filtering
        rule_result = 0
        if use_rule_filter:
            rule_result = self.rule_filter.classify_text(text)
            
            # If rule filter gives definitive result
            if rule_result == 0:  # Obviously benign
                return {
                    'is_malicious': False,
                    'confidence': 1.0,
                    'attack_type': None,
                    'attack_confidence': None,
                    'rule_result': rule_result
                }
            elif rule_result == 1:  # Obviously malicious
                return {
                    'is_malicious': True,
                    'confidence': 1.0,
                    'attack_type': 'rule_detected',
                    'attack_confidence': 1.0,
                    'rule_result': rule_result
                }
        
        # Preprocess for model
        inputs = self._preprocess(text)
        
        with torch.no_grad():
            # Binary classification
            binary_output = self.binary_model(inputs['input_ids'], inputs['attention_mask'])
            malicious_prob = binary_output['probabilities'].item()
            is_malicious = malicious_prob > threshold
            
            # If malicious, classify attack type
            attack_type = None
            attack_confidence = None
            
            if is_malicious:
                multiclass_output = self.multiclass_model(inputs['input_ids'], inputs['attention_mask'])
                probs = multiclass_output['probabilities'][0].cpu().numpy()
                attack_idx = probs.argmax()
                attack_type = self.attack_types[attack_idx]
                attack_confidence = float(probs[attack_idx])
        
        return {
            'is_malicious': is_malicious,
            'confidence': float(malicious_prob),
            'attack_type': attack_type,
            'attack_confidence': attack_confidence,
            'rule_result': rule_result
        }
    
    def batch_detect(self, texts: List[str], threshold: float = 0.5, use_rule_filter: bool = True) -> List[Dict]:
        """
        Batch detection for multiple texts
        
        Args:
            texts: List of texts to analyze
            threshold: Detection threshold
            use_rule_filter: Whether to use rule-based pre-filtering
            
        Returns:
            List of detection results
        """
        return [self.detect(text, threshold, use_rule_filter) for text in texts]


# Simple function-based API for backward compatibility
def has_injection_signature(text: str, threshold: float = 0.5) -> bool:
    """
    Simple function to check if text contains injection signatures
    
    Args:
        text: Input text to analyze
        threshold: Confidence threshold (default: 0.5)
        
    Returns:
        True if injection detected, False otherwise
    """
    try:
        # Use rule-based detection for simple API
        from utils.regex_patterns import INJECTION_PATTERNS, WHITELIST_PATTERNS
        
        # Check whitelist first
        for pattern in WHITELIST_PATTERNS:
            if pattern.match(text.strip()):
                return False
        
        # Check all injection patterns
        for category, patterns in INJECTION_PATTERNS.items():
            for pattern, confidence in patterns:
                if pattern.search(text):
                    if confidence >= threshold:
                        return True
        
        return False
        
    except Exception as e:
        print(f"Error in has_injection_signature: {e}")
        return False


def analyze_injection_signature(text: str) -> Dict[str, Any]:
    """
    Analyze text for injection signatures and return detailed results
    
    Args:
        text: Input text to analyze
        
    Returns:
        Dictionary with detection results
    """
    try:
        from utils.regex_patterns import INJECTION_PATTERNS, WHITELIST_PATTERNS
        
        result = {
            "is_injection": False,
            "confidence": 0.0,
            "attack_type": None,
            "patterns_matched": [],
            "severity": "low"
        }
        
        # Check whitelist first
        for pattern in WHITELIST_PATTERNS:
            if pattern.match(text.strip()):
                return result
        
        max_confidence = 0.0
        matched_patterns = []
        
        # Check all injection patterns
        for category, patterns in INJECTION_PATTERNS.items():
            for pattern, confidence in patterns:
                if pattern.search(text):
                    matched_patterns.append({
                        "pattern": pattern.pattern,
                        "confidence": confidence,
                        "category": category
                    })
                    
                    if confidence > max_confidence:
                        max_confidence = confidence
                        result["attack_type"] = category.split('_')[0]  # Extract attack type
        
        if max_confidence > 0:
            result["is_injection"] = True
            result["confidence"] = max_confidence
            result["patterns_matched"] = matched_patterns
            
            # Determine severity
            if max_confidence >= 0.8:
                result["severity"] = "critical"
            elif max_confidence >= 0.6:
                result["severity"] = "high"
            elif max_confidence >= 0.4:
                result["severity"] = "medium"
            else:
                result["severity"] = "low"
        
        return result
        
    except Exception as e:
        print(f"Error in analyze_injection_signature: {e}")
        return {
            "is_injection": False,
            "confidence": 0.0,
            "attack_type": None,
            "patterns_matched": [],
            "severity": "low",
            "error": str(e)
        }


def get_injection_statistics() -> Dict[str, Any]:
    """
    Get statistics about injection detection
    
    Returns:
        Dictionary with injection detection statistics
    """
    try:
        # This is a placeholder implementation
        # In a real application, you would query your database or storage
        # to get actual statistics about detected injections
        
        stats = {
            "total_detections": 0,
            "detections_by_type": {
                "sql": 0,
                "xss": 0,
                "nosql": 0,
                "ldap": 0,
                "cmd": 0,
                "path": 0
            },
            "detections_by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "recent_detections": [],
            "top_patterns": [],
            "detection_rate": 0.0,
            "false_positive_rate": 0.0
        }
        
        # You could integrate with your storage system here
        # For example:
        # from storage import injection_alert_store
        # stats["total_detections"] = len(injection_alert_store)
        
        return stats
        
    except Exception as e:
        print(f"Error in get_injection_statistics: {e}")
        return {
            "total_detections": 0,
            "detections_by_type": {},
            "detections_by_severity": {},
            "recent_detections": [],
            "top_patterns": [],
            "detection_rate": 0.0,
            "false_positive_rate": 0.0,
            "error": str(e)
        }