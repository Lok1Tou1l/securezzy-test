#!/usr/bin/env python3
"""
Complete Pipeline Test for Injection Detection
Tests the full workflow: Rule-based Filter → ML Model
Matches your production InjectionDetector implementation
"""

import torch
import time
import json
import numpy as np
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import os
import sys

# Import your modules
try:
    from models import InjectionDetectionModel, MultiClassInjectionModel
    from rule_filter import RuleBasedInjectionFilter
    MODELS_AVAILABLE = True
except ImportError as e:
    print(f"❌ Error importing modules: {e}")
    print("Make sure models.py and rule_filter.py are in the same directory")
    MODELS_AVAILABLE = False
    sys.exit(1)

class CompletePipelineTester:
    """Test the complete injection detection pipeline"""

    def __init__(self, 
                 binary_model_path: str = 'models/best_binary_injection_model.pth',
                 multiclass_model_path: str = 'models/best_multiclass_model.pth',
                 device: str = None,
                 max_length: int = 2048):

        self.device = device if device else ('cuda' if torch.cuda.is_available() else 'cpu')
        self.max_length = max_length
        self.attack_types = ['sqli', 'commandi', 'xss', 'traversal']

        print("🔧 Initializing Complete Pipeline Tester")
        print("=" * 60)

        # Initialize rule-based filter
        print("📋 Initializing rule-based filter...")
        self.rule_filter = RuleBasedInjectionFilter()
        print("✅ Rule-based filter ready")

        # Load ML models
        try:
            print(f"🤖 Loading ML models on device: {self.device}")

            # Binary model
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

            # Multiclass model
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

            self.ml_available = True
            print("🚀 Complete pipeline ready!")

        except Exception as e:
            print(f"❌ Failed to load ML models: {e}")
            print("⚠️  Will test rule-based filter only")
            self.ml_available = False

        print()

    def _preprocess(self, text: str) -> Dict[str, torch.Tensor]:
        """Convert text to model input format (matches your detector implementation)"""

        if not text:
            text = ""

        # Convert to bytes (GBST tokenization)
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
            byte_sequence.append(0)
            attention_mask.append(True)

        return {
            'input_ids': torch.tensor([byte_sequence], dtype=torch.long).to(self.device),
            'attention_mask': torch.tensor([attention_mask], dtype=torch.bool).to(self.device)
        }

    def detect_complete_pipeline(self, text: str, threshold: float = 0.5, use_rule_filter: bool = True) -> Dict:
        """
        Complete pipeline detection (matches your InjectionDetector.detect method)

        Returns detailed results including pipeline decisions
        """

        pipeline_steps = []
        start_time = time.time()

        # Step 1: Input validation
        if not text or not text.strip():
            return {
                'is_malicious': False,
                'confidence': 1.0,
                'attack_type': None,
                'attack_confidence': None,
                'rule_result': 0,
                'pipeline_steps': ['input_validation'],
                'decision_point': 'empty_input',
                'total_time_ms': (time.time() - start_time) * 1000
            }

        pipeline_steps.append('input_validation')

        # Step 2: Rule-based pre-filtering
        rule_result = 0
        rule_time = 0

        if use_rule_filter:
            rule_start = time.time()
            rule_result = self.rule_filter.classify_text(text)
            rule_time = (time.time() - rule_start) * 1000
            pipeline_steps.append('rule_filter')

            # If rule filter gives definitive result
            if rule_result == 0:  # Obviously benign
                return {
                    'is_malicious': False,
                    'confidence': 1.0,
                    'attack_type': None,
                    'attack_confidence': None,
                    'rule_result': rule_result,
                    'pipeline_steps': pipeline_steps,
                    'decision_point': 'rule_benign',
                    'rule_time_ms': rule_time,
                    'ml_time_ms': 0,
                    'total_time_ms': (time.time() - start_time) * 1000
                }
            elif rule_result == 1:  # Obviously malicious
                return {
                    'is_malicious': True,
                    'confidence': 1.0,
                    'attack_type': 'rule_detected',
                    'attack_confidence': 1.0,
                    'rule_result': rule_result,
                    'pipeline_steps': pipeline_steps,
                    'decision_point': 'rule_malicious',
                    'rule_time_ms': rule_time,
                    'ml_time_ms': 0,
                    'total_time_ms': (time.time() - start_time) * 1000
                }

        # Step 3: ML Model Evaluation (for ambiguous cases)
        if not self.ml_available:
            # Fallback if ML not available
            return {
                'is_malicious': rule_result == 1,
                'confidence': 0.5,  # Unknown confidence
                'attack_type': 'unknown',
                'attack_confidence': None,
                'rule_result': rule_result,
                'pipeline_steps': pipeline_steps + ['ml_fallback'],
                'decision_point': 'ml_unavailable',
                'rule_time_ms': rule_time,
                'ml_time_ms': 0,
                'total_time_ms': (time.time() - start_time) * 1000,
                'error': 'ML models not available'
            }

        # Preprocess for ML models
        ml_start = time.time()
        inputs = self._preprocess(text)
        pipeline_steps.append('ml_preprocessing')

        try:
            with torch.no_grad():
                # Binary classification
                binary_output = self.binary_model(inputs['input_ids'], inputs['attention_mask'])
                malicious_prob = binary_output['probabilities'].item()
                is_malicious = malicious_prob > threshold
                pipeline_steps.append('ml_binary')

                # If malicious, classify attack type
                attack_type = None
                attack_confidence = None

                if is_malicious:
                    multiclass_output = self.multiclass_model(inputs['input_ids'], inputs['attention_mask'])
                    probs = multiclass_output['probabilities'][0].cpu().numpy()
                    attack_idx = probs.argmax()
                    attack_type = self.attack_types[attack_idx]
                    attack_confidence = float(probs[attack_idx])
                    pipeline_steps.append('ml_multiclass')

                ml_time = (time.time() - ml_start) * 1000

                return {
                    'is_malicious': is_malicious,
                    'confidence': float(malicious_prob),
                    'attack_type': attack_type,
                    'attack_confidence': attack_confidence,
                    'rule_result': rule_result,
                    'pipeline_steps': pipeline_steps,
                    'decision_point': 'ml_prediction',
                    'rule_time_ms': rule_time,
                    'ml_time_ms': ml_time,
                    'total_time_ms': (time.time() - start_time) * 1000
                }

        except Exception as e:
            ml_time = (time.time() - ml_start) * 1000
            return {
                'is_malicious': rule_result == 1,
                'confidence': 0.5,
                'attack_type': None,
                'attack_confidence': None,
                'rule_result': rule_result,
                'pipeline_steps': pipeline_steps + ['ml_error'],
                'decision_point': 'ml_error',
                'rule_time_ms': rule_time,
                'ml_time_ms': ml_time,
                'total_time_ms': (time.time() - start_time) * 1000,
                'error': str(e)
            }

    def get_comprehensive_test_cases(self) -> Dict[str, List[Tuple[str, bool, str, str]]]:
        """
        Get test cases designed to test the complete pipeline
        Format: (text, expected_malicious, expected_type, expected_decision_point)
        """

        return {
            "rule_benign_cases": [
                # Cases that should be caught by rule filter as benign
                ("hello world", False, "none", "rule_benign"),
                ("user@example.com", False, "none", "rule_benign"),
                ("search query", False, "none", "rule_benign"),
                ("12345", False, "none", "rule_benign"),
                ("2023-12-25", False, "none", "rule_benign"),
                ("normal user input", False, "none", "rule_benign"),
                ("product-name-123", False, "none", "rule_benign"),
                ("simple text", False, "none", "rule_benign"),
            ],

            "rule_malicious_cases": [
                # Cases that should be caught by rule filter as malicious
                ("'; DROP TABLE users; --", True, "sqli", "rule_malicious"),
                ("<script>alert('XSS')</script>", True, "xss", "rule_malicious"),
                ("javascript:alert('xss')", True, "xss", "rule_malicious"),
                ("; ls -la", True, "commandi", "rule_malicious"),
                ("../../../etc/passwd", True, "traversal", "rule_malicious"),
                ("<iframe src=javascript:alert(1)></iframe>", True, "xss", "rule_malicious"),
                ("'; EXEC xp_cmdshell('dir'); --", True, "sqli", "rule_malicious"),
                ("| whoami", True, "commandi", "rule_malicious"),
            ],

            "rule_ambiguous_ml_cases": [
                # Cases that should go to ML for evaluation
                ("SELECT name FROM products", None, "sqli", "ml_prediction"),
                ("ORDER BY created_date", None, "ambiguous", "ml_prediction"),
                ("<p>Hello world</p>", None, "xss", "ml_prediction"),
                ("UPDATE profile SET name='John'", None, "sqli", "ml_prediction"),
                ("function test() { return true; }", None, "ambiguous", "ml_prediction"),
                ("%20%21%40%23", None, "ambiguous", "ml_prediction"),
                ("search with 'quotes'", None, "ambiguous", "ml_prediction"),
                ("data.json", None, "ambiguous", "ml_prediction"),
            ],

            "mixed_attack_cases": [
                # Complex cases that test both systems
                ("admin' OR '1'='1", True, "sqli", "rule_malicious"),  # Should be caught by rules
                ("1' UNION SELECT password", True, "sqli", "rule_malicious"),  # Should be caught by rules
                ("<img src=x onerror=alert(1)>", True, "xss", "rule_malicious"),  # Should be caught by rules
                ("SELECT * WHERE id=1", None, "sqli", "ml_prediction"),  # Should go to ML
            ],

            "edge_cases": [
                # Edge cases to test robustness
                ("", False, "none", "empty_input"),
                ("   ", False, "none", "rule_benign"),
                ("a" * 100, False, "none", "rule_benign"),
                ("'" * 50, None, "sqli", "ml_prediction"),  # Suspicious, needs ML
                ("<" * 20 + ">" * 20, None, "xss", "ml_prediction"),  # Suspicious, needs ML
                ("🚀💻🔒", False, "none", "rule_benign"),  # Unicode
            ],

            "performance_cases": [
                # Cases to test performance at different lengths
                ("short", False, "none", "rule_benign"),
                ("medium length text " * 10, False, "none", "rule_benign"),
                ("long text " * 100, None, "ambiguous", "ml_prediction"),  # Long texts go to ML
                ("very long text " * 200, None, "ambiguous", "ml_prediction"),
            ]
        }

    def run_pipeline_tests(self, test_cases: Dict = None, threshold: float = 0.5) -> Dict:
        """Run comprehensive pipeline tests"""

        if test_cases is None:
            test_cases = self.get_comprehensive_test_cases()

        print("🧪 COMPLETE PIPELINE TESTING")
        print("=" * 70)
        print(f"Device: {self.device}")
        print(f"Binary Threshold: {threshold}")
        print(f"ML Models Available: {self.ml_available}")
        print()

        all_results = {}
        overall_stats = {
            'total_tests': 0,
            'rule_benign_decisions': 0,
            'rule_malicious_decisions': 0,
            'ml_decisions': 0,
            'correct_predictions': 0,
            'total_rule_time': 0,
            'total_ml_time': 0,
            'pipeline_efficiency': {}
        }

        for category, cases in test_cases.items():
            print(f"📂 Testing {category.upper().replace('_', ' ')} ({len(cases)} cases)")
            print("-" * 60)

            category_results = []
            category_correct = 0

            for i, (test_input, expected_malicious, expected_type, expected_decision) in enumerate(cases):
                overall_stats['total_tests'] += 1

                try:
                    # Run complete pipeline
                    result = self.detect_complete_pipeline(test_input, threshold)

                    # Analyze results
                    predicted_malicious = result['is_malicious']
                    decision_point = result['decision_point']

                    # Track pipeline decisions
                    if decision_point in ['rule_benign', 'rule_malicious']:
                        if decision_point == 'rule_benign':
                            overall_stats['rule_benign_decisions'] += 1
                        else:
                            overall_stats['rule_malicious_decisions'] += 1
                    elif decision_point == 'ml_prediction':
                        overall_stats['ml_decisions'] += 1

                    # Track timing
                    overall_stats['total_rule_time'] += result.get('rule_time_ms', 0)
                    overall_stats['total_ml_time'] += result.get('ml_time_ms', 0)

                    # Check correctness (if expected result is provided)
                    correct = True
                    if expected_malicious is not None:
                        correct = predicted_malicious == expected_malicious
                        if correct:
                            category_correct += 1
                            overall_stats['correct_predictions'] += 1

                    # Check decision point correctness
                    decision_correct = decision_point == expected_decision

                    # Format output
                    input_display = test_input[:35] + "..." if len(test_input) > 35 else test_input

                    # Status indicators
                    pred_status = "✅" if correct else "❌"
                    decision_status = "✅" if decision_correct else "⚠️"

                    pred_text = "MALICIOUS" if predicted_malicious else "BENIGN"
                    conf_text = f"[{result['confidence']:.3f}]"

                    if predicted_malicious and result['attack_type']:
                        type_text = f"({result['attack_type']})"
                    else:
                        type_text = ""

                    decision_text = f"via_{decision_point}"
                    time_text = f"{result['total_time_ms']:.1f}ms"

                    print(f"{pred_status}{decision_status} {pred_text:<10} {conf_text} {type_text:<12} {decision_text:<15} {time_text:<8} | {input_display}")

                    # Store detailed results
                    test_result = {
                        'input': test_input,
                        'expected_malicious': expected_malicious,
                        'expected_decision': expected_decision,
                        'predicted_malicious': predicted_malicious,
                        'decision_point': decision_point,
                        'correct_prediction': correct,
                        'correct_decision': decision_correct,
                        'pipeline_result': result
                    }

                    category_results.append(test_result)

                except Exception as e:
                    print(f"❌ ERROR testing '{test_input[:40]}': {e}")
                    category_results.append({
                        'input': test_input,
                        'error': str(e),
                        'correct_prediction': False,
                        'correct_decision': False
                    })

            # Category summary
            if cases:
                category_accuracy = (category_correct / len(cases)) * 100 if expected_malicious is not None else 0
                print(f"\n📊 {category.upper()}: {category_accuracy:.1f}% accuracy ({category_correct}/{len(cases)})")
            print()

            all_results[category] = {
                'results': category_results,
                'accuracy': category_accuracy if cases else 0,
                'correct': category_correct,
                'total': len(cases)
            }

        # Calculate pipeline efficiency
        total_tests = overall_stats['total_tests']
        if total_tests > 0:
            overall_stats['pipeline_efficiency'] = {
                'rule_decisions_pct': ((overall_stats['rule_benign_decisions'] + overall_stats['rule_malicious_decisions']) / total_tests) * 100,
                'ml_decisions_pct': (overall_stats['ml_decisions'] / total_tests) * 100,
                'avg_rule_time_ms': overall_stats['total_rule_time'] / total_tests,
                'avg_ml_time_ms': overall_stats['total_ml_time'] / overall_stats['ml_decisions'] if overall_stats['ml_decisions'] > 0 else 0,
                'overall_accuracy_pct': (overall_stats['correct_predictions'] / total_tests) * 100
            }

        # Overall summary
        print("=" * 70)
        print("🎯 COMPLETE PIPELINE PERFORMANCE SUMMARY")
        print("=" * 70)
        print(f"Total Tests: {total_tests}")
        print(f"Correct Predictions: {overall_stats['correct_predictions']}")
        print(f"Overall Accuracy: {overall_stats['pipeline_efficiency'].get('overall_accuracy_pct', 0):.1f}%")
        print()
        print("📊 PIPELINE EFFICIENCY:")
        eff = overall_stats['pipeline_efficiency']
        print(f"  Rule Decisions: {eff.get('rule_decisions_pct', 0):.1f}% ({overall_stats['rule_benign_decisions'] + overall_stats['rule_malicious_decisions']} cases)")
        print(f"  ML Decisions: {eff.get('ml_decisions_pct', 0):.1f}% ({overall_stats['ml_decisions']} cases)")
        print(f"  Avg Rule Time: {eff.get('avg_rule_time_ms', 0):.2f}ms")
        print(f"  Avg ML Time: {eff.get('avg_ml_time_ms', 0):.2f}ms")
        print(f"  Rule Benign: {overall_stats['rule_benign_decisions']} cases")
        print(f"  Rule Malicious: {overall_stats['rule_malicious_decisions']} cases")

        return {
            'category_results': all_results,
            'overall_stats': overall_stats,
            'summary': {
                'total_tests': total_tests,
                'correct_predictions': overall_stats['correct_predictions'],
                'overall_accuracy': overall_stats['pipeline_efficiency'].get('overall_accuracy_pct', 0),
                'pipeline_efficiency': overall_stats['pipeline_efficiency']
            }
        }

    def benchmark_pipeline_performance(self, num_iterations: int = 50) -> Dict:
        """Benchmark complete pipeline performance"""

        print("\n" + "=" * 70)
        print("⚡ COMPLETE PIPELINE PERFORMANCE BENCHMARK")
        print("=" * 70)

        benchmark_cases = [
            # Rule benign (should be fast)
            ("hello world", "rule_benign"),
            ("user@example.com", "rule_benign"),

            # Rule malicious (should be fast)
            ("'; DROP TABLE users; --", "rule_malicious"),
            ("<script>alert('xss')</script>", "rule_malicious"),

            # ML cases (should be slower)
            ("SELECT name FROM products", "ml_required"),
            ("UPDATE profile SET name='test'", "ml_required"),
        ]

        results = {}

        for text, expected_path in benchmark_cases:
            print(f"\n🎯 Benchmarking: '{text[:40]}...' ({expected_path})")

            times = []
            rule_times = []
            ml_times = []
            decision_points = []

            for _ in range(num_iterations):
                result = self.detect_complete_pipeline(text)
                times.append(result['total_time_ms'])
                rule_times.append(result.get('rule_time_ms', 0))
                ml_times.append(result.get('ml_time_ms', 0))
                decision_points.append(result['decision_point'])

            # Calculate statistics
            avg_total = np.mean(times)
            avg_rule = np.mean(rule_times)
            avg_ml = np.mean(ml_times)
            std_total = np.std(times)

            # Check consistency
            unique_decisions = set(decision_points)
            consistency = (decision_points.count(decision_points[0]) / len(decision_points)) * 100

            results[text] = {
                'expected_path': expected_path,
                'avg_total_ms': avg_total,
                'avg_rule_ms': avg_rule,
                'avg_ml_ms': avg_ml,
                'std_total_ms': std_total,
                'min_total_ms': min(times),
                'max_total_ms': max(times),
                'decision_consistency_pct': consistency,
                'decision_points': unique_decisions
            }

            print(f"  Total Time: {avg_total:.2f}ms ± {std_total:.2f}ms")
            print(f"  Rule Time: {avg_rule:.2f}ms")
            print(f"  ML Time: {avg_ml:.2f}ms")
            print(f"  Decision Consistency: {consistency:.1f}%")
            print(f"  Decision Points: {unique_decisions}")

        return results


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description='Test complete injection detection pipeline')
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
    parser.add_argument('--no-rule-filter', action='store_true',
                       help='Skip rule-based filtering (ML only)')

    args = parser.parse_args()

    # Initialize tester
    device = args.device if args.device != 'auto' else None

    try:
        tester = CompletePipelineTester(
            binary_model_path=args.binary_model,
            multiclass_model_path=args.multiclass_model,
            device=device
        )
    except Exception as e:
        print(f"❌ Failed to initialize pipeline tester: {e}")
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

        results = tester.run_pipeline_tests(test_cases, args.threshold)

        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f'pipeline_test_results_{timestamp}.json'

        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        print(f"\n💾 Results saved to: {results_file}")

        # Run benchmark if requested
        if args.benchmark:
            benchmark_results = tester.benchmark_pipeline_performance(args.iterations)

            benchmark_file = f'pipeline_benchmark_{timestamp}.json'
            with open(benchmark_file, 'w') as f:
                json.dump(benchmark_results, f, indent=2, default=str)

            print(f"💾 Benchmark results saved to: {benchmark_file}")

        return 0

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    if not MODELS_AVAILABLE:
        print("❌ Cannot run tests without required modules")
        sys.exit(1)

    sys.exit(main())
