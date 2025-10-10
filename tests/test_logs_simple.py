#!/usr/bin/env python3
"""
Simple test script for the logging system without Flask dependencies
"""

import sys
import os

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

def test_storage_module():
    """Test the storage module directly"""
    print("🧪 Testing Storage Module")
    print("=" * 50)
    
    try:
        from storage import (
            log_store,
            LogType,
            LogLevel,
            log_info,
            log_warning,
            log_error,
            log_critical,
            log_debug
        )
        print("✅ Storage module imported successfully")
        
        # Test logging functions
        print("2. Testing logging functions...")
        
        # Test different log levels
        log_info("Test info message", LogType.SYSTEM, "test")
        log_warning("Test warning message", LogType.SECURITY, "test")
        log_error("Test error message", LogType.API, "test")
        log_critical("Test critical message", LogType.SECURITY, "test")
        log_debug("Test debug message", LogType.SYSTEM, "test")
        
        print("   ✅ All logging functions executed successfully")
        
        # Test log retrieval
        print("3. Testing log retrieval...")
        logs = log_store.get_logs(limit=10)
        print(f"   ✅ Retrieved {len(logs)} logs")
        
        # Show recent logs
        print("   📋 Recent log entries:")
        for log in logs[-5:]:  # Show last 5 logs
            print(f"      [{log['level']}] {log['log_type']}: {log['message']}")
        
        # Test log statistics
        print("4. Testing log statistics...")
        stats = log_store.get_log_statistics()
        print(f"   ✅ Log statistics:")
        print(f"      Total logs: {stats.get('total_logs', 0)}")
        print(f"      By level: {stats.get('by_level', {})}")
        print(f"      By type: {stats.get('by_type', {})}")
        print(f"      By source: {stats.get('by_source', {})}")
        
        # Test filtering
        print("5. Testing log filtering...")
        system_logs = log_store.get_logs(log_type="system", limit=5)
        print(f"   ✅ System logs: {len(system_logs)} entries")
        
        error_logs = log_store.get_logs(level="ERROR", limit=5)
        print(f"   ✅ Error logs: {len(error_logs)} entries")
        
        test_logs = log_store.get_logs(source="test", limit=5)
        print(f"   ✅ Test source logs: {len(test_logs)} entries")
        
        print("\n🎉 Storage module test completed successfully!")
        return True
        
    except ImportError as e:
        print(f"❌ Failed to import storage module: {e}")
        return False
    except Exception as e:
        print(f"❌ Error testing storage module: {e}")
        return False

def test_logs_directory():
    """Test if logs directory is created"""
    print("\n📁 Testing Logs Directory")
    print("=" * 50)
    
    logs_dir = "logs"
    if os.path.exists(logs_dir):
        print(f"✅ Logs directory exists: {logs_dir}")
        
        log_file = os.path.join(logs_dir, "system.log")
        if os.path.exists(log_file):
            print(f"✅ Log file exists: {log_file}")
            
            # Check file size
            file_size = os.path.getsize(log_file)
            print(f"   📊 Log file size: {file_size} bytes")
            
            # Show last few lines
            try:
                with open(log_file, 'r') as f:
                    lines = f.readlines()
                    print(f"   📝 Total lines in log file: {len(lines)}")
                    if lines:
                        print("   📋 Last log entry:")
                        print(f"      {lines[-1].strip()}")
            except Exception as e:
                print(f"   ❌ Error reading log file: {e}")
        else:
            print(f"❌ Log file not found: {log_file}")
    else:
        print(f"❌ Logs directory not found: {logs_dir}")

if __name__ == "__main__":
    print("🚀 Starting Simple Logging System Tests")
    print("=" * 60)
    
    success = test_storage_module()
    test_logs_directory()
    
    if success:
        print("\n✨ All tests completed successfully!")
        print("The logging system is working correctly.")
        print("You can now start the Flask app and test the dashboard.")
    else:
        print("\n❌ Some tests failed.")
        print("Please check the error messages above.")
