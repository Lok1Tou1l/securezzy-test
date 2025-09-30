#!/usr/bin/env python3
"""
Simple Rule-Based Injection Detection Test
"""

def test_rule_based_detection():
    """Test the rule-based detection system"""
    print("🔍 Testing Rule-Based Detection System")
    print("=" * 50)
    
    try:
        from detection.injection import has_injection_signature, analyze_injection_signature
        
        # Test cases: (input, should_detect, expected_type)
        test_cases = [
            ("SELECT * FROM users", True, "sql"),
            ("admin", False, "normal"),
            ("1 OR 1=1", True, "sql"),
            ("DROP TABLE users", True, "sql"),
            ("<script>alert('xss')</script>", True, "xss"),
            ("javascript:alert(1)", True, "xss"),
            ("; ls -la", True, "cmd"),
            ("../../../etc/passwd", True, "path"),
            ("normal text", False, "normal"),
            ("user@example.com", False, "normal"),
        ]
        
        correct = 0
        total = len(test_cases)
        
        for text, should_detect, expected_type in test_cases:
            # Test simple detection
            is_injection = has_injection_signature(text)
            
            # Test detailed analysis
            analysis = analyze_injection_signature(text)
            
            # Check if detection was correct
            detection_correct = (is_injection == should_detect)
            if detection_correct:
                correct += 1
            
            # Print result
            status = "✅" if detection_correct else "❌"
            print(f"{status} {text[:25]:<25} | Expected: {should_detect} | Got: {is_injection} | Type: {analysis.get('attack_type', 'None')} | Confidence: {analysis.get('confidence', 0.0):.2f}")
        
        accuracy = (correct / total) * 100
        print(f"\n📊 Results: {correct}/{total} correct ({accuracy:.1f}% accuracy)")
        
        return accuracy > 80  # Consider successful if >80% accuracy
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    success = test_rule_based_detection()
    if success:
        print("✅ Rule-based detection test passed!")
    else:
        print("❌ Rule-based detection test failed!")
