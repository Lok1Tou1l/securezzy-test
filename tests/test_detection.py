#!/usr/bin/env python3
"""
Test script for injection detection
"""

import sys
import os
sys.path.append('src')

from production_injection_service import get_detector_instance

def test_detection():
    detector = get_detector_instance()
    
    test_cases = [
        "1' OR '1'='1",
        "1' OR 1=1--",
        "<script>alert('XSS')</script>",
        "admin'--",
        "1' UNION SELECT 1,2,3--",
        "normal text",
        "test@example.com",
        "https://example.com"
    ]
    
    print("Testing injection detection:")
    print("=" * 50)
    
    for test_input in test_cases:
        result = detector.detect(test_input)
        status = "🚨 DETECTED" if result['is_malicious'] else "✅ CLEAN"
        print(f"{status} | {test_input[:30]}{'...' if len(test_input) > 30 else ''}")
        if result['is_malicious']:
            print(f"   Attack Type: {result.get('attack_type', 'unknown')}")
            print(f"   Confidence: {result.get('confidence', 0):.3f}")
        print()

if __name__ == "__main__":
    test_detection()
