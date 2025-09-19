from utils.regex_patterns import (
    INJECTION_PATTERNS, 
    WHITELIST_PATTERNS, 
    CONFIDENCE_THRESHOLDS
)
from typing import Dict, List, Tuple, Optional


def has_injection_signature(text: str, min_confidence: float = 0.4) -> bool:
    """
    Check if text contains injection signatures with confidence scoring.
    
    Args:
        text: Text to analyze
        min_confidence: Minimum confidence threshold (0.0-1.0)
    
    Returns:
        bool: True if injection signature detected above threshold
    """
    if not text:
        return False
    
    # Check whitelist first to avoid false positives
    if _is_whitelisted(text):
        return False
    
    confidence, attack_type = _calculate_injection_confidence(text)
    return confidence >= min_confidence


def analyze_injection_signature(text: str) -> Dict[str, any]:
    """
    Comprehensive injection analysis with detailed results.
    
    Args:
        text: Text to analyze
    
    Returns:
        Dict containing analysis results
    """
    if not text:
        return {
            "has_injection": False,
            "confidence": 0.0,
            "attack_types": [],
            "severity": "none",
            "details": []
        }
    
    # Check whitelist first
    if _is_whitelisted(text):
        return {
            "has_injection": False,
            "confidence": 0.0,
            "attack_types": [],
            "severity": "none",
            "details": ["Whitelisted pattern detected"]
        }
    
    confidence, attack_types, details = _detailed_injection_analysis(text)
    severity = _determine_severity(confidence)
    
    return {
        "has_injection": confidence >= CONFIDENCE_THRESHOLDS["medium"],
        "confidence": confidence,
        "attack_types": attack_types,
        "severity": severity,
        "details": details
    }


def _is_whitelisted(text: str) -> bool:
    """Check if text matches whitelist patterns."""
    for pattern in WHITELIST_PATTERNS:
        if pattern.match(text.strip()):
            return True
    return False


def _calculate_injection_confidence(text: str) -> Tuple[float, str]:
    """
    Calculate confidence score and identify attack type.
    
    Returns:
        Tuple of (confidence_score, attack_type)
    """
    max_confidence = 0.0
    detected_types = []
    
    for category, patterns in INJECTION_PATTERNS.items():
        for pattern, confidence in patterns:
            if pattern.search(text):
                max_confidence = max(max_confidence, confidence)
                attack_type = category.split('_')[0]  # Extract base type (sql, xss, etc.)
                if attack_type not in detected_types:
                    detected_types.append(attack_type)
    
    return max_confidence, ", ".join(detected_types) if detected_types else "unknown"


def _detailed_injection_analysis(text: str) -> Tuple[float, List[str], List[str]]:
    """
    Perform detailed injection analysis.
    
    Returns:
        Tuple of (max_confidence, attack_types, details)
    """
    max_confidence = 0.0
    detected_types = []
    details = []
    
    for category, patterns in INJECTION_PATTERNS.items():
        category_confidence = 0.0
        category_matches = []
        
        for pattern, confidence in patterns:
            if pattern.search(text):
                category_confidence = max(category_confidence, confidence)
                category_matches.append(f"{pattern.pattern[:50]}...")
        
        if category_confidence > 0:
            attack_type = category.split('_')[0]
            if attack_type not in detected_types:
                detected_types.append(attack_type)
            
            max_confidence = max(max_confidence, category_confidence)
            details.append(f"{attack_type.upper()} injection detected (confidence: {category_confidence:.2f})")
            if category_matches:
                details.extend([f"  - {match}" for match in category_matches[:3]])  # Limit details
    
    return max_confidence, detected_types, details


def _determine_severity(confidence: float) -> str:
    """Determine severity level based on confidence score."""
    if confidence >= CONFIDENCE_THRESHOLDS["critical"]:
        return "critical"
    elif confidence >= CONFIDENCE_THRESHOLDS["high"]:
        return "high"
    elif confidence >= CONFIDENCE_THRESHOLDS["medium"]:
        return "medium"
    elif confidence >= CONFIDENCE_THRESHOLDS["low"]:
        return "low"
    else:
        return "none"


def get_injection_statistics() -> Dict[str, int]:
    """Get statistics about available injection patterns."""
    stats = {}
    for category, patterns in INJECTION_PATTERNS.items():
        attack_type = category.split('_')[0]
        if attack_type not in stats:
            stats[attack_type] = 0
        stats[attack_type] += len(patterns)
    
    stats["total_patterns"] = sum(len(patterns) for patterns in INJECTION_PATTERNS.values())
    stats["total_categories"] = len(INJECTION_PATTERNS)
    stats["whitelist_patterns"] = len(WHITELIST_PATTERNS)
    
    return stats


