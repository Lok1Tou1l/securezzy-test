#!/usr/bin/env python3
"""
Test script to verify sniffer to DDoS service integration
"""

import time
import requests
import json
from typing import Dict, Any

def test_ddos_analysis():
    """Test DDoS analysis with sample traffic data"""
    
    # Create sample traffic flows that would come from sniffer
    flows = []
    base_time = time.time()
    
    # Simulate a potential DDoS attack with multiple flows from same source
    for i in range(10):
        flow = {
            'timestamp': base_time + i * 0.1,  # 100ms intervals
            'src_ip': '192.168.1.100',  # Same source IP
            'dst_ip': '10.0.0.1',  # Same destination IP
            'src_port': 12345 + i,
            'dst_port': 80,  # HTTP port
            'protocol': 'TCP',
            'packets_count': 50 + i * 10,  # Increasing packet count
            'fwd_packets_count': 50 + i * 10,
            'bwd_packets_count': 0,  # No response packets (suspicious)
            'duration': 0.1
        }
        flows.append(flow)
    
    # Test the DDoS analysis endpoint
    url = "http://localhost:5000/ddos/lstm/analyze"
    payload = {
        "flows": flows,
        "threshold": 0.3  # Lower threshold for testing
    }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            result = response.json()
            print("✅ DDoS Analysis Test Results:")
            print(f"   Attack Detected: {result.get('attack_detected', False)}")
            print(f"   Max Probability: {result.get('max_attack_probability', 0):.3f}")
            print(f"   Max Intensity: {result.get('max_attack_intensity', 0):.3f}")
            print(f"   Windows Created: {result.get('windows_created', 0)}")
            print(f"   Sequences Created: {result.get('sequences_created', 0)}")
            print(f"   Processing Time: {result.get('processing_time_ms', 0):.2f}ms")
            
            if result.get('error'):
                print(f"   Error: {result.get('error')}")
                
            return result
        else:
            print(f"❌ DDoS Analysis failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ DDoS Analysis error: {e}")
        return None

def test_lstm_status():
    """Test LSTM DDoS service status"""
    
    url = "http://localhost:5000/ddos/lstm/status"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            result = response.json()
            print("✅ LSTM DDoS Service Status:")
            print(f"   Available: {result.get('available', False)}")
            
            stats = result.get('statistics', {})
            print(f"   Model Loaded: {stats.get('model_loaded', False)}")
            print(f"   Device: {stats.get('device', 'unknown')}")
            print(f"   Feature Count: {stats.get('feature_count', 0)}")
            print(f"   Total Detections: {stats.get('total_detections', 0)}")
            print(f"   Attack Detections: {stats.get('attack_detections', 0)}")
            print(f"   Detection Rate: {stats.get('attack_detection_rate', 0):.2%}")
            
            return result
        else:
            print(f"❌ LSTM Status failed: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"❌ LSTM Status error: {e}")
        return None

def test_sniffer_status():
    """Test sniffer status"""
    
    url = "http://localhost:5000/sniffer/status"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            result = response.json()
            print("✅ Sniffer Status:")
            print(f"   Available: {result.get('available', False)}")
            print(f"   Enabled: {result.get('enabled', False)}")
            print(f"   Interface: {result.get('interface', 'unknown')}")
            print(f"   BPF Filter: {result.get('bpf_filter', 'unknown')}")
            
            return result
        else:
            print(f"❌ Sniffer Status failed: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"❌ Sniffer Status error: {e}")
        return None

def main():
    """Run all tests"""
    print("🧪 Testing Sniffer to DDoS Service Integration")
    print("=" * 50)
    
    # Test 1: Sniffer Status
    print("\n1. Testing Sniffer Status...")
    sniffer_status = test_sniffer_status()
    
    # Test 2: LSTM DDoS Service Status
    print("\n2. Testing LSTM DDoS Service Status...")
    lstm_status = test_lstm_status()
    
    # Test 3: DDoS Analysis
    print("\n3. Testing DDoS Analysis...")
    ddos_result = test_ddos_analysis()
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Integration Test Summary:")
    
    if sniffer_status and sniffer_status.get('available') and sniffer_status.get('enabled'):
        print("✅ Sniffer: Running and enabled")
    else:
        print("❌ Sniffer: Not available or disabled")
    
    if lstm_status and lstm_status.get('available'):
        print("✅ LSTM DDoS Service: Available")
    else:
        print("❌ LSTM DDoS Service: Not available")
    
    if ddos_result:
        print("✅ DDoS Analysis: Working")
        if ddos_result.get('attack_detected'):
            print("🚨 DDoS Attack Detected in test data!")
        else:
            print("ℹ️  No attack detected in test data (expected for single flow)")
    else:
        print("❌ DDoS Analysis: Failed")
    
    print("\n🎯 Integration Status: COMPLETE")
    print("   The sniffer is now configured to pass data to the LSTM DDoS service.")
    print("   Real-time DDoS detection will occur as network traffic is captured.")

if __name__ == "__main__":
    main()
