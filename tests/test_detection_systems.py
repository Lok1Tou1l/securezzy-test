#!/usr/bin/env python3
"""
Test both rule-based and ML detection systems
"""

import sys
import os

# Add current directory to path so we can import detection modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_rule_based_detection():
    """Test rule-based detection system"""
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
        print(f"\n📊 Rule-Based Results: {correct}/{total} correct ({accuracy:.1f}% accuracy)")
        
        return accuracy > 80  # Consider successful if >80% accuracy
        
    except Exception as e:
        print(f"❌ Error in rule-based detection: {e}")
        return False

def test_ml_detection():
    """Test ML-based detection system"""
    print("\n🤖 Testing ML-Based Detection System")
    print("=" * 50)
    
    try:
        from detection.injection import InjectionDetector
        
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
        
        # Initialize ML detector
        detector = InjectionDetector(
            binary_model_path='models/best_binary_injection_model.pth',
            multiclass_model_path='models/best_multiclass_model.pth',
            device='cpu'  # Use CPU for testing
        )
        
        correct = 0
        total = len(test_cases)
        
        for text, should_detect, expected_type in test_cases:
            # Test ML detection
            result = detector.detect(text, threshold=0.5)
            
            # Extract results
            is_injection = result.get("is_injection", False)
            confidence = result.get("confidence", 0.0)
            attack_type = result.get("attack_type", "None")
            
            # Check if detection was correct
            detection_correct = (is_injection == should_detect)
            if detection_correct:
                correct += 1
            
            # Print result
            status = "✅" if detection_correct else "❌"
            print(f"{status} {text[:25]:<25} | Expected: {should_detect} | Got: {is_injection} | Type: {attack_type} | Confidence: {confidence:.2f}")
        
        accuracy = (correct / total) * 100
        print(f"\n📊 ML-Based Results: {correct}/{total} correct ({accuracy:.1f}% accuracy)")
        
        return accuracy > 70  # ML might be less accurate without training
        
    except Exception as e:
        print(f"❌ Error in ML detection: {e}")
        print("Note: ML models may not be available or trained yet")
        return False

def test_combined_detection():
    """Test combined rule-based + ML detection"""
    print("\n🔄 Testing Combined Detection System")
    print("=" * 50)
    
    try:
        from detection.injection import has_injection_signature, InjectionDetector
        
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
        
        # Initialize ML detector
        detector = InjectionDetector(
            binary_model_path='models/best_binary_injection_model.pth',
            multiclass_model_path='models/best_multiclass_model.pth',
            device='cpu'
        )
        
        correct = 0
        total = len(test_cases)
        
        for text, should_detect, expected_type in test_cases:
            # Rule-based detection
            rule_result = has_injection_signature(text)
            
            # ML detection
            ml_result = detector.detect(text, threshold=0.5)
            ml_detected = ml_result.get("is_injection", False)
            
            # Combined logic: if either detects, consider it detected
            combined_detected = rule_result or ml_detected
            
            # Check if detection was correct
            detection_correct = (combined_detected == should_detect)
            if detection_correct:
                correct += 1
            
            # Print result
            status = "✅" if detection_correct else "❌"
            print(f"{status} {text[:25]:<25} | Expected: {should_detect} | Rule: {rule_result} | ML: {ml_detected} | Combined: {combined_detected}")
        
        accuracy = (correct / total) * 100
        print(f"\n📊 Combined Results: {correct}/{total} correct ({accuracy:.1f}% accuracy)")
        
        return accuracy > 80  # Combined should be more accurate
        
    except Exception as e:
        print(f"❌ Error in combined detection: {e}")
        return False

def main():
    """Main test function"""
    print("🚀 Starting Detection Systems Test")
    print("=" * 60)
    
    # Test rule-based detection
    rule_success = test_rule_based_detection()
    
    # Test ML detection
    ml_success = test_ml_detection()
    
    # Test combined detection
    combined_success = test_combined_detection()
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 FINAL SUMMARY")
    print("=" * 60)
    print(f"Rule-Based Detection: {'✅ PASSED' if rule_success else '❌ FAILED'}")
    print(f"ML-Based Detection: {'✅ PASSED' if ml_success else '❌ FAILED'}")
    print(f"Combined Detection: {'✅ PASSED' if combined_success else '❌ FAILED'}")
    
    if rule_success and ml_success and combined_success:
        print("\n🎉 All detection systems are working!")
    else:
        print("\n⚠️  Some detection systems need attention")
    
    return rule_success and ml_success and combined_success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
