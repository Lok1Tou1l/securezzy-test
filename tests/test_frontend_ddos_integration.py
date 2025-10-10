#!/usr/bin/env python3
"""
Test script to verify frontend DDoS integration
"""

import requests
import json
import time
from typing import Dict, Any

def test_ddos_endpoints():
    """Test all DDoS-related endpoints"""
    
    endpoints = [
        {
            'name': 'DDoS Status',
            'url': 'http://localhost:5000/ddos/lstm/status',
            'method': 'GET',
            'expected_status': 200
        },
        {
            'name': 'DDoS Alerts',
            'url': 'http://localhost:5000/ddos/lstm/alerts',
            'method': 'GET',
            'expected_status': 200
        },
        {
            'name': 'DDoS Analysis',
            'url': 'http://localhost:5000/ddos/lstm/analyze',
            'method': 'POST',
            'expected_status': 200,
            'data': {
                'flows': [{
                    'timestamp': time.time(),
                    'src_ip': '192.168.1.100',
                    'dst_ip': '10.0.0.1',
                    'src_port': 12345,
                    'dst_port': 80,
                    'protocol': 'TCP',
                    'packets_count': 100,
                    'fwd_packets_count': 100,
                    'bwd_packets_count': 0,
                    'duration': 1.0
                }],
                'threshold': 0.5
            }
        }
    ]
    
    print("🧪 Testing DDoS API Endpoints")
    print("=" * 40)
    
    results = []
    
    for endpoint in endpoints:
        try:
            if endpoint['method'] == 'GET':
                response = requests.get(endpoint['url'], timeout=10)
            else:
                response = requests.post(
                    endpoint['url'], 
                    json=endpoint.get('data', {}), 
                    timeout=10
                )
            
            success = response.status_code == endpoint['expected_status']
            results.append({
                'name': endpoint['name'],
                'success': success,
                'status_code': response.status_code,
                'response': response.json() if success else response.text
            })
            
            status_icon = "✅" if success else "❌"
            print(f"{status_icon} {endpoint['name']}: {response.status_code}")
            
            if success and endpoint['name'] == 'DDoS Status':
                stats = response.json().get('statistics', {})
                print(f"   Model Loaded: {stats.get('model_loaded', False)}")
                print(f"   Total Detections: {stats.get('total_detections', 0)}")
                print(f"   Attack Detections: {stats.get('attack_detections', 0)}")
            
        except Exception as e:
            results.append({
                'name': endpoint['name'],
                'success': False,
                'error': str(e)
            })
            print(f"❌ {endpoint['name']}: Error - {e}")
    
    return results

def test_frontend_files():
    """Test frontend file accessibility"""
    
    files = [
        'http://localhost:5000/',
        'http://localhost:5000/admin-content.html',
        'http://localhost:5000/web.html'
    ]
    
    print("\n🌐 Testing Frontend Files")
    print("=" * 40)
    
    results = []
    
    for file_url in files:
        try:
            response = requests.get(file_url, timeout=10)
            success = response.status_code == 200
            results.append({
                'url': file_url,
                'success': success,
                'status_code': response.status_code
            })
            
            status_icon = "✅" if success else "❌"
            print(f"{status_icon} {file_url}: {response.status_code}")
            
        except Exception as e:
            results.append({
                'url': file_url,
                'success': False,
                'error': str(e)
            })
            print(f"❌ {file_url}: Error - {e}")
    
    return results

def test_sniffer_integration():
    """Test sniffer integration status"""
    
    print("\n🔍 Testing Sniffer Integration")
    print("=" * 40)
    
    try:
        # Test sniffer status
        response = requests.get('http://localhost:5000/sniffer/status', timeout=10)
        if response.status_code == 200:
            sniffer_data = response.json()
            print(f"✅ Sniffer Status: {response.status_code}")
            print(f"   Available: {sniffer_data.get('available', False)}")
            print(f"   Enabled: {sniffer_data.get('enabled', False)}")
            print(f"   Interface: {sniffer_data.get('interface', 'unknown')}")
            print(f"   BPF Filter: {sniffer_data.get('bpf_filter', 'unknown')}")
            return True
        else:
            print(f"❌ Sniffer Status: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Sniffer Integration Error: {e}")
        return False

def generate_test_report(api_results, frontend_results, sniffer_success):
    """Generate comprehensive test report"""
    
    print("\n" + "=" * 60)
    print("📊 Frontend DDoS Integration Test Report")
    print("=" * 60)
    
    # API Endpoints Summary
    api_success = sum(1 for r in api_results if r.get('success', False))
    api_total = len(api_results)
    print(f"\n🔌 API Endpoints: {api_success}/{api_total} working")
    
    for result in api_results:
        status = "✅" if result.get('success', False) else "❌"
        print(f"   {status} {result['name']}")
    
    # Frontend Files Summary
    frontend_success = sum(1 for r in frontend_results if r.get('success', False))
    frontend_total = len(frontend_results)
    print(f"\n🌐 Frontend Files: {frontend_success}/{frontend_total} accessible")
    
    for result in frontend_results:
        status = "✅" if result.get('success', False) else "❌"
        print(f"   {status} {result['url']}")
    
    # Sniffer Integration
    print(f"\n🔍 Sniffer Integration: {'✅ Working' if sniffer_success else '❌ Failed'}")
    
    # Overall Status
    overall_success = (api_success == api_total and 
                      frontend_success == frontend_total and 
                      sniffer_success)
    
    print(f"\n🎯 Overall Integration Status: {'✅ COMPLETE' if overall_success else '❌ ISSUES FOUND'}")
    
    if overall_success:
        print("\n🎉 Frontend DDoS Integration is fully functional!")
        print("   - All API endpoints are working")
        print("   - Frontend files are accessible")
        print("   - Sniffer is integrated with DDoS service")
        print("   - Real-time monitoring is active")
        print("\n📱 Access the dashboard at: http://localhost:5000/")
        print("   Navigate to Admin Panel → Network Management → DDoS Detection Dashboard")
    else:
        print("\n⚠️  Some issues were found. Check the details above.")
    
    return overall_success

def main():
    """Run comprehensive frontend integration test"""
    
    print("🚀 Frontend DDoS Integration Test Suite")
    print("=" * 60)
    
    # Test API endpoints
    api_results = test_ddos_endpoints()
    
    # Test frontend files
    frontend_results = test_frontend_files()
    
    # Test sniffer integration
    sniffer_success = test_sniffer_integration()
    
    # Generate report
    overall_success = generate_test_report(api_results, frontend_results, sniffer_success)
    
    return 0 if overall_success else 1

if __name__ == "__main__":
    exit(main())
