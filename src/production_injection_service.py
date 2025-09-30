"""
Production Injection Detection Service
Provides a unified interface for injection detection using rule-based patterns
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.injection import has_injection_signature, analyze_injection_signature
from typing import Dict, Any, List
import time
from datetime import datetime

class ProductionInjectionDetector:
    """
    Production-ready injection detector using rule-based patterns
    """
    
    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold
        self.detection_count = 0
        self.start_time = time.time()
    
    def detect(self, text: str, threshold: float = None) -> Dict[str, Any]:
        """
        Detect if input contains injection attack
        
        Args:
            text: Input text to analyze
            threshold: Detection threshold (uses instance default if None)
            
        Returns:
            Dict with detection results
        """
        if threshold is None:
            threshold = self.threshold
            
        if not text or not text.strip():
            return {
                'is_malicious': False,
                'confidence': 1.0,
                'attack_type': None,
                'attack_confidence': None,
                'rule_result': 0
            }
        
        # Use the existing rule-based detection
        analysis = analyze_injection_signature(text)
        
        is_malicious = analysis.get('is_injection', False)
        confidence = analysis.get('confidence', 0.0)
        attack_type = analysis.get('attack_type', None)
        
        # Apply threshold
        if confidence >= threshold:
            self.detection_count += 1
            return {
                'is_malicious': True,
                'confidence': confidence,
                'attack_type': attack_type,
                'attack_confidence': confidence,
                'rule_result': 1,
                'severity': analysis.get('severity', 'medium'),
                'patterns_matched': analysis.get('patterns_matched', [])
            }
        else:
            return {
                'is_malicious': False,
                'confidence': confidence,
                'attack_type': attack_type,
                'attack_confidence': confidence,
                'rule_result': 0
            }
    
    def batch_detect(self, texts: List[str], threshold: float = None) -> List[Dict[str, Any]]:
        """
        Batch detection for multiple texts
        """
        return [self.detect(text, threshold) for text in texts]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics"""
        uptime = time.time() - self.start_time
        return {
            'detection_count': self.detection_count,
            'uptime_seconds': uptime,
            'threshold': self.threshold,
            'detection_rate': self.detection_count / max(uptime, 1)
        }

# Global detector instance
_detector_instance = None

def get_detector_instance(threshold: float = 0.5) -> ProductionInjectionDetector:
    """
    Get or create the global detector instance
    """
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = ProductionInjectionDetector(threshold)
    return _detector_instance

def reset_detector():
    """Reset the global detector instance"""
    global _detector_instance
    _detector_instance = None
