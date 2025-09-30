#!/usr/bin/env python3
"""
Comprehensive Injection Detection Test
Tests both rule-based and ML-based detection systems
"""

import time
import json
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import sys

# Test cases for injection detection
TEST_CASES = [
    # SQL Injection
    ("SELECT * FROM users", "sql", True),
    ("1 OR 1=1", "sql", True),
    ("DROP TABLE users", "sql", True),
    ("UNION SELECT password FROM users", "sql", True),
    ("' OR '1'='1", "sql", True),
    ("admin'--", "sql", True),
    ("'; DROP TABLE users; --", "sql", True),
    
    # XSS
    ("<script>alert('xss')</script>", "xss", True),
    ("javascript:alert(1)", "xss", True),
    ("<img src=x onerror=alert(1)>", "xss", True),
    ("<iframe src=javascript:alert(1)></iframe>", "xss", True),
    
    # Command Injection
    ("; ls -la", "cmd", True),
    ("| cat /etc/passwd", "cmd", True),
    ("&& whoami", "cmd", True),
    ("; rm -rf /", "cmd", True),
    
    # Path Traversal
    ("../../../etc/passwd", "path", True),
    ("..\\..\\windows\\system32", "path", True),
    ("%2e%2e%2f%2e%2e%2f", "path", True),
    
    # NoSQL Injection
    ("{'$ne': null}", "nosql", True),
    ("{'$where': 'this.password'}", "nosql", True),
    
    # LDAP Injection
    ("(cn=*)", "ldap", True),
    ("(|(cn=*)(uid=*))", "ldap", True),
    
    # Normal/Non-malicious inputs
    ("admin", "normal", False),
    ("password123", "normal", False),
    ("user@example.com", "normal", False),
    ("https://example.com", "normal", False),
    ("Hello World", "normal", False),
    ("SELECT name FROM products WHERE price > 100", "normal", False),  # Legitimate SQL
]

class ComprehensiveInjectionTester:
    """Comprehensive tester for both rule-based and ML detection"""
    
    def __init__(self):
        self.results = {
            "rule_based": {"correct": 0, "incorrect": 0, "total": 0, "details": []},
            "ml_based": {"correct": 0, "incorrect": 0, "total": 0, "details": []},
            "combined": {"correct": 0, "incorrect": 0, "total": 0, "details": []}
        }
        
    def test_rule_based_detection(self):
        """Test rule-based detection system"""
        print("🔍 Testing Rule-Based Detection System")
        print("=" * 50)
        
        try:
            from detection.injection import has_injection_signature, analyze_injection_signature
            
            for input_text, expected_type, should_detect in TEST_CASES:
                start_time = time.time()
                
                # Test simple boolean detection
                is_injection = has_injection_signature(input_text)
                detection_time = time.time() - start_time
                
                # Test detailed analysis
                analysis = analyze_injection_signature(input_text)
                
                # Determine if detection was correct
                correct = (is_injection == should_detect)
                
                if correct:
                    self.results["rule_based"]["correct"] += 1
                else:
                    self.results["rule_based"]["incorrect"] += 1
                
                self.results["rule_based"]["total"] += 1
                
                # Store detailed results
                detail = {
                    "input": input_text,
                    "expected_type": expected_type,
                    "should_detect": should_detect,
                    "detected": is_injection,
                    "confidence": analysis.get("confidence", 0.0),
                    "attack_type": analysis.get("attack_type", "None"),
                    "severity": analysis.get("severity", "low"),
                    "correct": correct,
                    "detection_time": detection_time
                }
                self.results["rule_based"]["details"].append(detail)
                
                # Print result
                status = "✅" if correct else "❌"
                print(f"{status} {input_text[:30]:<30} | Expected: {should_detect} | Got: {is_injection} | Type: {analysis.get('attack_type', 'None')} | Time: {detection_time:.4f}s")
                
        except Exception as e:
            print(f"❌ Error testing rule-based detection: {e}")
            return False
            
        return True
    
    def test_ml_detection(self):
        """Test ML-based detection system"""
        print("\n🤖 Testing ML-Based Detection System")
        print("=" * 50)
        
        try:
            from detection.injection import InjectionDetector
            
            # Initialize ML detector (this will use the class-based approach)
            detector = InjectionDetector(
                binary_model_path='models/best_binary_injection_model.pth',
                multiclass_model_path='models/best_multiclass_model.pth',
                device='cpu'  # Use CPU for testing
            )
            
            for input_text, expected_type, should_detect in TEST_CASES:
                start_time = time.time()
                
                # Test ML detection
                result = detector.detect(input_text, threshold=0.5)
                detection_time = time.time() - start_time
                
                # Extract results
                is_injection = result.get("is_injection", False)
                confidence = result.get("confidence", 0.0)
                attack_type = result.get("attack_type", "None")
                
                # Determine if detection was correct
                correct = (is_injection == should_detect)
                
                if correct:
                    self.results["ml_based"]["correct"] += 1
                else:
                    self.results["ml_based"]["incorrect"] += 1
                
                self.results["ml_based"]["total"] += 1
                
                # Store detailed results
                detail = {
                    "input": input_text,
                    "expected_type": expected_type,
                    "should_detect": should_detect,
                    "detected": is_injection,
                    "confidence": confidence,
                    "attack_type": attack_type,
                    "correct": correct,
                    "detection_time": detection_time
                }
                self.results["ml_based"]["details"].append(detail)
                
                # Print result
                status = "✅" if correct else "❌"
                print(f"{status} {input_text[:30]:<30} | Expected: {should_detect} | Got: {is_injection} | Type: {attack_type} | Time: {detection_time:.4f}s")
                
        except Exception as e:
            print(f"❌ Error testing ML detection: {e}")
            print("Note: ML models may not be available or trained yet")
            return False
            
        return True
    
    def test_combined_detection(self):
        """Test combined rule-based + ML detection"""
        print("\n🔄 Testing Combined Detection System")
        print("=" * 50)
        
        try:
            from detection.injection import has_injection_signature, InjectionDetector
            
            # Initialize ML detector
            detector = InjectionDetector(
                binary_model_path='models/best_binary_injection_model.pth',
                multiclass_model_path='models/best_multiclass_model.pth',
                device='cpu'
            )
            
            for input_text, expected_type, should_detect in TEST_CASES:
                start_time = time.time()
                
                # Rule-based detection
                rule_result = has_injection_signature(input_text)
                
                # ML detection
                ml_result = detector.detect(input_text, threshold=0.5)
                ml_detected = ml_result.get("is_injection", False)
                
                # Combined logic: if either detects, consider it detected
                combined_detected = rule_result or ml_detected
                detection_time = time.time() - start_time
                
                # Determine if detection was correct
                correct = (combined_detected == should_detect)
                
                if correct:
                    self.results["combined"]["correct"] += 1
                else:
                    self.results["combined"]["incorrect"] += 1
                
                self.results["combined"]["total"] += 1
                
                # Store detailed results
                detail = {
                    "input": input_text,
                    "expected_type": expected_type,
                    "should_detect": should_detect,
                    "rule_detected": rule_result,
                    "ml_detected": ml_detected,
                    "combined_detected": combined_detected,
                    "ml_confidence": ml_result.get("confidence", 0.0),
                    "correct": correct,
                    "detection_time": detection_time
                }
                self.results["combined"]["details"].append(detail)
                
                # Print result
                status = "✅" if correct else "❌"
                print(f"{status} {input_text[:30]:<30} | Expected: {should_detect} | Rule: {rule_result} | ML: {ml_detected} | Combined: {combined_detected} | Time: {detection_time:.4f}s")
                
        except Exception as e:
            print(f"❌ Error testing combined detection: {e}")
            return False
            
        return True
    
    def print_summary(self):
        """Print comprehensive test summary"""
        print("\n" + "=" * 80)
        print("📊 COMPREHENSIVE DETECTION TEST SUMMARY")
        print("=" * 80)
        
        for system_name, results in self.results.items():
            if results["total"] > 0:
                accuracy = (results["correct"] / results["total"]) * 100
                print(f"\n🔍 {system_name.upper().replace('_', '-')} SYSTEM:")
                print(f"   Accuracy: {accuracy:.2f}% ({results['correct']}/{results['total']})")
                print(f"   Correct: {results['correct']}")
                print(f"   Incorrect: {results['incorrect']}")
                
                # Calculate average detection time
                total_time = sum(detail["detection_time"] for detail in results["details"])
                avg_time = total_time / len(results["details"]) if results["details"] else 0
                print(f"   Average Detection Time: {avg_time:.4f}s")
        
        # Save detailed results to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"detection_test_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"\n💾 Detailed results saved to: {filename}")
        
        # Performance comparison
        print(f"\n⚡ PERFORMANCE COMPARISON:")
        for system_name, results in self.results.items():
            if results["total"] > 0:
                accuracy = (results["correct"] / results["total"]) * 100
                total_time = sum(detail["detection_time"] for detail in results["details"])
                avg_time = total_time / len(results["details"]) if results["details"] else 0
                print(f"   {system_name.replace('_', ' ').title()}: {accuracy:.1f}% accuracy, {avg_time:.4f}s avg time")

def main():
    """Main test function"""
    print("🚀 Starting Comprehensive Injection Detection Test")
    print("=" * 80)
    print(f"📅 Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🧪 Total test cases: {len(TEST_CASES)}")
    print("=" * 80)
    
    tester = ComprehensiveInjectionTester()
    
    # Test rule-based detection
    rule_success = tester.test_rule_based_detection()
    
    # Test ML detection
    ml_success = tester.test_ml_detection()
    
    # Test combined detection
    combined_success = tester.test_combined_detection()
    
    # Print summary
    tester.print_summary()
    
    # Final status
    print(f"\n🏁 Test completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if rule_success and ml_success and combined_success:
        print("✅ All detection systems tested successfully!")
    else:
        print("⚠️  Some detection systems had issues - check the output above")
    
    return rule_success and ml_success and combined_success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
