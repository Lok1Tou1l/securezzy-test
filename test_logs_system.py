#!/usr/bin/env python3
"""
Test script for the logging system
"""

import requests
import json
import time
import os

# Ensure the Flask app is running on http://localhost:5000
BASE_URL = "http://localhost:5000"

def test_logs_endpoints():
    """Test all logging endpoints"""
    print("🧪 Testing Logging System")
    print("=" * 50)
    
    # Test 1: Get log statistics
    print("1. Testing log statistics endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/logs/statistics")
        if response.status_code == 200:
            stats = response.json()
            print(f"   ✅ Log statistics retrieved: {stats.get('total_logs', 0)} total logs")
        else:
            print(f"   ❌ Failed to get log statistics: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error getting log statistics: {e}")
    
    # Test 2: Get logs
    print("2. Testing logs retrieval endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/logs?limit=10")
        if response.status_code == 200:
            data = response.json()
            logs = data.get('logs', [])
            print(f"   ✅ Retrieved {len(logs)} logs")
            if logs:
                print(f"   📝 Latest log: {logs[-1].get('message', 'N/A')}")
        else:
            print(f"   ❌ Failed to get logs: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error getting logs: {e}")
    
    # Test 3: Generate some test logs by making API calls
    print("3. Generating test logs...")
    try:
        # Make some API calls to generate logs
        test_payloads = [
            {
                "source_ip": "192.168.1.100",
                "path": "/api/test",
                "method": "POST",
                "body": "SELECT * FROM users WHERE id = 1 OR 1=1",
                "user_agent": "Test Agent",
                "country": "US"
            },
            {
                "source_ip": "192.168.1.101",
                "path": "/api/search",
                "method": "GET",
                "body": "<script>alert('XSS')</script>",
                "user_agent": "Test Agent 2",
                "country": "CA"
            },
            {
                "source_ip": "192.168.1.102",
                "path": "/api/normal",
                "method": "GET",
                "body": "normal request",
                "user_agent": "Test Agent 3",
                "country": "UK"
            }
        ]
        
        for i, payload in enumerate(test_payloads):
            response = requests.post(f"{BASE_URL}/analyze", json=payload)
            if response.status_code == 200:
                print(f"   ✅ Test request {i+1} processed successfully")
            else:
                print(f"   ❌ Test request {i+1} failed: {response.status_code}")
            time.sleep(0.5)  # Small delay between requests
        
    except Exception as e:
        print(f"   ❌ Error generating test logs: {e}")
    
    # Test 4: Check logs after generating test data
    print("4. Checking logs after test data generation...")
    try:
        response = requests.get(f"{BASE_URL}/logs?limit=20")
        if response.status_code == 200:
            data = response.json()
            logs = data.get('logs', [])
            print(f"   ✅ Total logs now: {len(logs)}")
            
            # Show recent logs
            print("   📋 Recent log entries:")
            for log in logs[-5:]:  # Show last 5 logs
                timestamp = time.strftime('%H:%M:%S', time.localtime(log.get('timestamp', 0)))
                level = log.get('level', 'UNKNOWN')
                log_type = log.get('log_type', 'unknown')
                message = log.get('message', 'No message')[:50] + "..." if len(log.get('message', '')) > 50 else log.get('message', 'No message')
                print(f"      {timestamp} [{level}] {log_type}: {message}")
        else:
            print(f"   ❌ Failed to get updated logs: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error checking updated logs: {e}")
    
    # Test 5: Test log filtering
    print("5. Testing log filtering...")
    try:
        # Test filtering by type
        response = requests.get(f"{BASE_URL}/logs?type=api&limit=5")
        if response.status_code == 200:
            data = response.json()
            api_logs = data.get('logs', [])
            print(f"   ✅ API logs: {len(api_logs)} entries")
        
        # Test filtering by level
        response = requests.get(f"{BASE_URL}/logs?level=WARNING&limit=5")
        if response.status_code == 200:
            data = response.json()
            warning_logs = data.get('logs', [])
            print(f"   ✅ Warning logs: {len(warning_logs)} entries")
        
        # Test filtering by source
        response = requests.get(f"{BASE_URL}/logs?source=analyze&limit=5")
        if response.status_code == 200:
            data = response.json()
            analyze_logs = data.get('logs', [])
            print(f"   ✅ Analyze source logs: {len(analyze_logs)} entries")
            
    except Exception as e:
        print(f"   ❌ Error testing log filtering: {e}")
    
    # Test 6: Test log export
    print("6. Testing log export...")
    try:
        response = requests.get(f"{BASE_URL}/logs/export?limit=10")
        if response.status_code == 200:
            # Check if it's a JSON response
            content_type = response.headers.get('content-type', '')
            if 'application/json' in content_type:
                logs_data = response.json()
                print(f"   ✅ Log export successful: {len(logs_data)} entries")
            else:
                print(f"   ✅ Log export successful: {len(response.content)} bytes")
        else:
            print(f"   ❌ Failed to export logs: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error testing log export: {e}")
    
    # Test 7: Test log statistics again
    print("7. Testing updated log statistics...")
    try:
        response = requests.get(f"{BASE_URL}/logs/statistics")
        if response.status_code == 200:
            stats = response.json()
            print(f"   ✅ Updated statistics:")
            print(f"      Total logs: {stats.get('total_logs', 0)}")
            print(f"      By level: {stats.get('by_level', {})}")
            print(f"      By type: {stats.get('by_type', {})}")
            print(f"      By source: {stats.get('by_source', {})}")
        else:
            print(f"   ❌ Failed to get updated statistics: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error getting updated statistics: {e}")
    
    print("\n🎉 Logging system test completed!")
    print("=" * 50)

def test_dashboard_accessibility():
    """Test if the dashboard is accessible"""
    print("\n🌐 Testing Dashboard Accessibility")
    print("=" * 50)
    
    try:
        response = requests.get(f"{BASE_URL}/dashboard-content.html")
        if response.status_code == 200:
            print("   ✅ Dashboard content is accessible")
            
            # Check if logs section is present
            content = response.text
            if "System Logs" in content:
                print("   ✅ Logs section found in dashboard")
            else:
                print("   ❌ Logs section not found in dashboard")
                
            if "loadLogStatistics" in content:
                print("   ✅ Logs JavaScript functions found")
            else:
                print("   ❌ Logs JavaScript functions not found")
                
        else:
            print(f"   ❌ Dashboard not accessible: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error accessing dashboard: {e}")

if __name__ == "__main__":
    print("🚀 Starting Logging System Tests")
    print("=" * 60)
    
    # Check if server is running
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            print("✅ Server is running and accessible")
        else:
            print("❌ Server responded with error")
            exit(1)
    except requests.exceptions.RequestException as e:
        print(f"❌ Server is not accessible: {e}")
        print("Please make sure the Flask app is running on http://localhost:5000")
        exit(1)
    
    # Run tests
    test_logs_endpoints()
    test_dashboard_accessibility()
    
    print("\n✨ All tests completed!")
    print("You can now access the dashboard at http://localhost:5000")
    print("and check the 'System Logs' section to see the logging functionality.")
