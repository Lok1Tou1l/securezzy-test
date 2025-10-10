#!/usr/bin/env python3
"""
Comprehensive Injection Attack Test Suite for SecurEZZY
Tests various injection attack patterns against the application endpoints
"""

import requests
import json
import time
import urllib.parse
from typing import List, Dict, Any
import sys

# Base URL for the SecurEZZY application
BASE_URL = "http://127.0.0.1:5000"

class InjectionAttackTester:
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.session = requests.Session()
        self.results = []
        
    def log_result(self, test_name: str, payload: str, response: requests.Response, detected: bool = None):
        """Log test results"""
        result = {
            'test_name': test_name,
            'payload': payload,
            'status_code': response.status_code,
            'response_time': response.elapsed.total_seconds(),
            'detected': detected,
            'headers': dict(response.headers),
            'response_size': len(response.content)
        }
        
        # Check for detection headers
        if 'X-Injection-Detected' in response.headers:
            result['detected'] = response.headers['X-Injection-Detected'] == 'true'
            result['injection_count'] = response.headers.get('X-Injection-Count', '0')
        
        self.results.append(result)
        
        # Print result
        status = "🚨 DETECTED" if result.get('detected') else "✅ PASSED"
        print(f"{status} | {test_name}")
        print(f"   Payload: {payload[:80]}{'...' if len(payload) > 80 else ''}")
        print(f"   Status: {response.status_code} | Time: {response.elapsed.total_seconds():.3f}s")
        if result.get('detected'):
            print(f"   Injection Count: {result.get('injection_count', 'N/A')}")
        print()

    def test_sql_injection_attacks(self):
        """Test SQL injection attacks on /api/users endpoint"""
        print("🔍 Testing SQL Injection Attacks on /api/users")
        print("=" * 60)
        
        sql_payloads = [
            # Basic SQL injection
            "1' OR '1'='1",
            "1' OR 1=1--",
            "1' OR 1=1#",
            "1' OR 1=1/*",
            
            # UNION-based attacks
            "1' UNION SELECT 1,2,3--",
            "1' UNION ALL SELECT NULL,NULL,NULL--",
            "1' UNION SELECT user(),database(),version()--",
            
            # Boolean-based blind SQL injection
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            
            # Time-based blind SQL injection
            "1'; WAITFOR DELAY '00:00:05'--",
            "1'; SELECT SLEEP(5)--",
            "1'; SELECT BENCHMARK(5000000,ENCODE('msg','by 5 seconds'))--",
            
            # Error-based SQL injection
            "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            
            # Stacked queries
            "1'; DROP TABLE users--",
            "1'; INSERT INTO users VALUES ('hacker','password')--",
            "1'; UPDATE users SET password='hacked' WHERE id=1--",
            
            # Advanced techniques
            "1' OR 'x'='x",
            "admin'--",
            "admin'/*",
            "1' OR '1'='1' LIMIT 1--",
            "1' OR '1'='1' ORDER BY 1--",
        ]
        
        for payload in sql_payloads:
            try:
                # Test with id parameter
                params = {'id': payload, 'name': 'test'}
                response = self.session.get(f"{self.base_url}/api/users", params=params, timeout=10)
                self.log_result("SQL Injection (id param)", payload, response)
                
                # Test with name parameter
                params = {'id': '1', 'name': payload}
                response = self.session.get(f"{self.base_url}/api/users", params=params, timeout=10)
                self.log_result("SQL Injection (name param)", payload, response)
                
                time.sleep(0.1)  # Small delay between requests
                
            except requests.exceptions.RequestException as e:
                print(f"❌ ERROR | SQL Injection test failed: {e}")
                print()

    def test_xss_attacks(self):
        """Test XSS attacks on /api/search endpoint"""
        print("🔍 Testing XSS Attacks on /api/search")
        print("=" * 60)
        
        xss_payloads = [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>alert(document.cookie)</script>",
            
            # Event handler XSS
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            
            # JavaScript protocol
            "javascript:alert('XSS')",
            "javascript:alert(1)",
            "javascript:alert(document.domain)",
            
            # Data URI
            "data:text/html,<script>alert('XSS')</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
            
            # Iframe XSS
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<iframe src=data:text/html,<script>alert('XSS')</script>></iframe>",
            
            # Object/Embed XSS
            "<object data=javascript:alert('XSS')></object>",
            "<embed src=javascript:alert('XSS')>",
            
            # Form XSS
            "<form><button formaction=javascript:alert('XSS')>CLICK</button></form>",
            "<form><input formaction=javascript:alert('XSS') type=submit value=CLICK></form>",
            
            # Advanced XSS
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
            "<script>setTimeout('alert(\\'XSS\\')',0)</script>",
            "<script>setInterval('alert(\\'XSS\\')',1000)</script>",
            
            # CSS-based XSS
            "<style>@import'javascript:alert(\"XSS\")';</style>",
            "<link rel=stylesheet href=javascript:alert('XSS')>",
            
            # Meta refresh XSS
            "<meta http-equiv=refresh content=0;url=javascript:alert('XSS')>",
            
            # Polyglot XSS
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>",
        ]
        
        for payload in xss_payloads:
            try:
                # Test with query parameter
                params = {'q': payload, 'category': 'test'}
                response = self.session.get(f"{self.base_url}/api/search", params=params, timeout=10)
                self.log_result("XSS Attack (query param)", payload, response)
                
                # Test with category parameter
                params = {'q': 'test', 'category': payload}
                response = self.session.get(f"{self.base_url}/api/search", params=params, timeout=10)
                self.log_result("XSS Attack (category param)", payload, response)
                
                time.sleep(0.1)
                
            except requests.exceptions.RequestException as e:
                print(f"❌ ERROR | XSS test failed: {e}")
                print()

    def test_nosql_injection_attacks(self):
        """Test NoSQL injection attacks on /admin/config endpoint"""
        print("🔍 Testing NoSQL Injection Attacks on /admin/config")
        print("=" * 60)
        
        nosql_payloads = [
            # MongoDB injection
            '{"$where": "this.username == this.password"}',
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$exists": true}',
            '{"$in": ["admin", "user"]}',
            '{"$nin": ["guest"]}',
            '{"$or": [{"username": "admin"}, {"username": "user"}]}',
            '{"$and": [{"username": {"$ne": null}}, {"password": {"$ne": null}}]}',
            '{"$not": {"username": "guest"}}',
            '{"$nor": [{"username": "guest"}, {"password": "guest"}]}',
            
            # JavaScript injection
            '{"$where": "function() { return true; }"}',
            '{"$where": "this.username.match(/.*/)"}',
            '{"$where": "this.username.length > 0"}',
            
            # Array injection
            '{"username": {"$in": ["admin", "administrator", "root"]}}',
            '{"roles": {"$all": ["admin", "user"]}}',
            '{"tags": {"$elemMatch": {"$regex": ".*"}}}',
            
            # Comparison operators
            '{"age": {"$gte": 0}}',
            '{"age": {"$lte": 999}}',
            '{"age": {"$lt": 1000}}',
            '{"age": {"$gt": -1}}',
            
            # Type confusion
            '{"username": {"$type": "string"}}',
            '{"password": {"$type": 2}}',  # 2 = string type in MongoDB
        ]
        
        for payload in nosql_payloads:
            try:
                # Test as JSON in request body
                headers = {'Content-Type': 'application/json'}
                data = json.loads(payload)
                response = self.session.post(f"{self.base_url}/admin/config", 
                                           json=data, headers=headers, timeout=10)
                self.log_result("NoSQL Injection (JSON body)", payload, response)
                
                time.sleep(0.1)
                
            except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                print(f"❌ ERROR | NoSQL test failed: {e}")
                print()

    def test_command_injection_attacks(self):
        """Test command injection attacks"""
        print("🔍 Testing Command Injection Attacks")
        print("=" * 60)
        
        cmd_payloads = [
            # Basic command injection
            "test; ls -la",
            "test && whoami",
            "test | cat /etc/passwd",
            "test; id",
            "test && pwd",
            
            # Windows command injection
            "test; dir",
            "test && type C:\\windows\\system32\\drivers\\etc\\hosts",
            "test | tasklist",
            "test; systeminfo",
            "test && whoami",
            
            # Network commands
            "test; ping -c 1 127.0.0.1",
            "test && curl http://127.0.0.1",
            "test; wget http://127.0.0.1",
            "test | nc -l 8080",
            
            # File operations
            "test; cat /etc/passwd",
            "test && rm -rf /tmp/test",
            "test; mkdir /tmp/hacked",
            "test | find / -name '*.txt'",
            
            # Process operations
            "test; ps aux",
            "test && kill -9 1",
            "test; top -n 1",
            
            # Advanced techniques
            "test; $(whoami)",
            "test && `id`",
            "test; ${IFS}cat${IFS}/etc/passwd",
            "test && {cat,/etc/passwd}",
        ]
        
        for payload in cmd_payloads:
            try:
                # Test on search endpoint
                params = {'q': payload}
                response = self.session.get(f"{self.base_url}/api/search", params=params, timeout=10)
                self.log_result("Command Injection (search)", payload, response)
                
                time.sleep(0.1)
                
            except requests.exceptions.RequestException as e:
                print(f"❌ ERROR | Command injection test failed: {e}")
                print()

    def test_path_traversal_attacks(self):
        """Test path traversal attacks"""
        print("🔍 Testing Path Traversal Attacks")
        print("=" * 60)
        
        path_payloads = [
            # Basic path traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
            
            # Double encoding
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%255c..%255c..%255cwindows%255csystem32",
            
            # Unicode encoding
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..%c1%9c..%c1%9c..%c1%9cwindows%c1%9csystem32",
            
            # Null byte injection
            "../../../etc/passwd%00",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%00",
            
            # Specific files
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/group",
            "/proc/version",
            "/proc/cpuinfo",
            "/proc/meminfo",
            "/boot/grub/grub.conf",
            "/var/log/messages",
            "/var/log/auth.log",
            
            # Windows files
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\windows\\system32\\config\\sam",
            "C:\\windows\\system32\\config\\system",
            "C:\\boot.ini",
            "C:\\win.ini",
            "C:\\windows\\win.ini",
            
            # Configuration files
            "../../../var/www/html/config.php",
            "..\\..\\..\\inetpub\\wwwroot\\web.config",
            "../../../app/config/database.yml",
        ]
        
        for payload in path_payloads:
            try:
                # Test on search endpoint
                params = {'q': payload}
                response = self.session.get(f"{self.base_url}/api/search", params=params, timeout=10)
                self.log_result("Path Traversal (search)", payload, response)
                
                time.sleep(0.1)
                
            except requests.exceptions.RequestException as e:
                print(f"❌ ERROR | Path traversal test failed: {e}")
                print()

    def test_ldap_injection_attacks(self):
        """Test LDAP injection attacks"""
        print("🔍 Testing LDAP Injection Attacks")
        print("=" * 60)
        
        ldap_payloads = [
            # Basic LDAP injection
            "*",
            "*)(uid=*",
            "*)(|(uid=*",
            "*)(|(objectClass=*",
            "*)(|(cn=*",
            "*)(|(mail=*",
            "*)(|(sn=*",
            
            # Boolean-based LDAP injection
            "*)(|(objectClass=user)(objectClass=computer)",
            "*)(|(cn=admin)(cn=administrator)",
            "*)(|(uid=admin)(uid=root)",
            "*)(|(mail=admin@*)(mail=root@*)",
            
            # Time-based LDAP injection
            "*)(|(objectClass=*)(objectClass=ldap))",
            "*)(|(cn=*)(cn=ldap))",
            
            # Union-based LDAP injection
            "*)(|(objectClass=user)(objectClass=group)",
            "*)(|(cn=admin)(cn=user))",
            
            # Error-based LDAP injection
            "*)(|(objectClass=invalid)(objectClass=*",
            "*)(|(cn=invalid)(cn=*",
            
            # Advanced techniques
            "*)(|(objectClass=*)(objectClass=ldap))",
            "*)(|(cn=*)(cn=ldap))",
            "*)(|(uid=*)(uid=ldap))",
            "*)(|(mail=*)(mail=ldap))",
        ]
        
        for payload in ldap_payloads:
            try:
                # Test on users endpoint
                params = {'id': payload, 'name': 'test'}
                response = self.session.get(f"{self.base_url}/api/users", params=params, timeout=10)
                self.log_result("LDAP Injection (users)", payload, response)
                
                time.sleep(0.1)
                
            except requests.exceptions.RequestException as e:
                print(f"❌ ERROR | LDAP injection test failed: {e}")
                print()

    def get_monitoring_stats(self):
        """Get monitoring statistics"""
        try:
            response = self.session.get(f"{self.base_url}/_monitor/stats", timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"❌ Failed to get monitoring stats: {response.status_code}")
                return None
        except requests.exceptions.RequestException as e:
            print(f"❌ Error getting monitoring stats: {e}")
            return None

    def get_recent_alerts(self):
        """Get recent injection alerts"""
        try:
            response = self.session.get(f"{self.base_url}/_monitor/alerts", timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"❌ Failed to get alerts: {response.status_code}")
                return None
        except requests.exceptions.RequestException as e:
            print(f"❌ Error getting alerts: {e}")
            return None

    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 80)
        print("🎯 INJECTION ATTACK TEST SUMMARY")
        print("=" * 80)
        
        total_tests = len(self.results)
        detected_attacks = sum(1 for r in self.results if r.get('detected'))
        blocked_attacks = sum(1 for r in self.results if r.get('status_code') == 403)
        
        print(f"Total Tests Run: {total_tests}")
        print(f"Attacks Detected: {detected_attacks}")
        print(f"Attacks Blocked: {blocked_attacks}")
        print(f"Detection Rate: {(detected_attacks/total_tests)*100:.1f}%")
        print(f"Block Rate: {(blocked_attacks/total_tests)*100:.1f}%")
        
        # Get monitoring stats
        stats = self.get_monitoring_stats()
        if stats:
            print(f"\n📊 MONITORING STATISTICS:")
            print(f"Total Requests Monitored: {stats.get('total_requests_monitored', 'N/A')}")
            print(f"Total Parameters Analyzed: {stats.get('total_parameters_analyzed', 'N/A')}")
            print(f"Injection Attempts Detected: {stats.get('injection_attempts_detected', 'N/A')}")
            print(f"Recent Alerts Count: {stats.get('recent_alerts_count', 'N/A')}")
            print(f"Detector Available: {stats.get('detector_available', 'N/A')}")
        
        # Show recent alerts
        alerts = self.get_recent_alerts()
        if alerts and len(alerts) > 0:
            print(f"\n🚨 RECENT ALERTS ({len(alerts)}):")
            for i, alert in enumerate(alerts[-5:], 1):  # Show last 5 alerts
                print(f"  {i}. {alert.get('attack_type', 'Unknown')} - {alert.get('parameter', 'N/A')}")
                print(f"     Confidence: {alert.get('confidence', 'N/A')}")
                print(f"     Timestamp: {alert.get('timestamp', 'N/A')}")
        
        print("\n" + "=" * 80)

    def run_all_tests(self):
        """Run all injection attack tests"""
        print("🚀 Starting Comprehensive Injection Attack Tests")
        print("Target: SecurEZZY Application")
        print(f"Base URL: {self.base_url}")
        print("=" * 80)
        
        # Check if application is running
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=5)
            if response.status_code != 200:
                print(f"❌ Application not responding properly. Status: {response.status_code}")
                return
        except requests.exceptions.RequestException as e:
            print(f"❌ Cannot connect to application: {e}")
            print("Make sure the SecurEZZY application is running on http://127.0.0.1:5000")
            return
        
        print("✅ Application is running, starting tests...\n")
        
        # Run all test categories
        self.test_sql_injection_attacks()
        self.test_xss_attacks()
        self.test_nosql_injection_attacks()
        self.test_command_injection_attacks()
        self.test_path_traversal_attacks()
        self.test_ldap_injection_attacks()
        
        # Print summary
        self.print_summary()

def main():
    """Main function"""
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = BASE_URL
    
    tester = InjectionAttackTester(base_url)
    tester.run_all_tests()

if __name__ == "__main__":
    main()
