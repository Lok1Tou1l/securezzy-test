# Generate the enhanced detection engine
detection_engine_content = '''"""
Enhanced Detection Engine
Replaces the basic regex-based detection with advanced algorithms
"""

import re
import time
import redis
from collections import defaultdict
from datetime import datetime, timedelta
import logging
import ipaddress
from typing import Dict, List, Any

class DetectionEngine:
    def __init__(self):
        self.redis_client = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
        self.logger = logging.getLogger(__name__)
        
        # Enhanced DDoS detection parameters
        self.ddos_window = 60  # 60 seconds window
        self.ddos_threshold = 50  # requests per window
        self.burst_threshold = 20  # requests in 10 seconds
        
        # IP reputation and whitelist
        self.ip_whitelist = {'127.0.0.1', '::1'}
        self.suspicious_ips = set()
        
        # Enhanced injection patterns
        self.injection_patterns = self._load_injection_patterns()
        
    def _load_injection_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Load comprehensive injection detection patterns"""
        patterns = {
            'sql_injection': [
                re.compile(r"(?i)(union|select|insert|update|delete|drop|create|alter)\\s", re.IGNORECASE),
                re.compile(r"(?i)('|(\\x27)|(\\x2D)){2,}", re.IGNORECASE),
                re.compile(r"(?i)(\\||\\|\\||&&)", re.IGNORECASE),
                re.compile(r"(?i)(exec|execute|sp_|xp_)", re.IGNORECASE),
                re.compile(r"(?i)(information_schema|sysobjects|syscolumns)", re.IGNORECASE),
                re.compile(r"(?i)(\\bor\\b.*\\b=\\b|\\band\\b.*\\b=\\b)", re.IGNORECASE),
                re.compile(r"(?i)(0x[0-9a-f]+|unhex|hex|ascii|char\\()", re.IGNORECASE)
            ],
            'xss': [
                re.compile(r"(?i)<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
                re.compile(r"(?i)javascript:", re.IGNORECASE),
                re.compile(r"(?i)on(load|click|error|mouseover)\\s*=", re.IGNORECASE),
                re.compile(r"(?i)<iframe[^>]*>", re.IGNORECASE),
                re.compile(r"(?i)eval\\s*\\(|expression\\s*\\(", re.IGNORECASE),
                re.compile(r"(?i)<img[^>]*src\\s*=\\s*[\"']?javascript:", re.IGNORECASE),
                re.compile(r"(?i)document\\.(cookie|write|location)", re.IGNORECASE)
            ],
            'command_injection': [
                re.compile(r"(?i)(;|\\||&|\\$\\(|`)", re.IGNORECASE),
                re.compile(r"(?i)(cat|ls|ps|whoami|id|uname|pwd)\\s", re.IGNORECASE),
                re.compile(r"(?i)(wget|curl|nc|netcat|telnet)\\s", re.IGNORECASE),
                re.compile(r"(?i)(\\.\\./|\\.\\\\\\.\\.\\\\|%2e%2e%2f|%252e%252e%252f)", re.IGNORECASE),
                re.compile(r"(?i)(rm\\s+-rf|del\\s+/|format\\s+c:)", re.IGNORECASE)
            ],
            'ldap_injection': [
                re.compile(r"(?i)(\\*|\\(|\\)|\\\\|\\0|/)", re.IGNORECASE),
                re.compile(r"(?i)(objectclass=|cn=|uid=)", re.IGNORECASE)
            ],
            'xml_injection': [
                re.compile(r"(?i)<!\\[CDATA\\[", re.IGNORECASE),
                re.compile(r"(?i)<!DOCTYPE|<!ENTITY", re.IGNORECASE),
                re.compile(r"(?i)(&lt;|&gt;|&amp;|&quot;|&#)", re.IGNORECASE)
            ]
        }
        return patterns
    
    def detect_ddos(self, event: Dict[str, Any]) -> bool:
        """Enhanced DDoS detection using multiple algorithms"""
        source_ip = event.get('source_ip')
        if not source_ip or source_ip in self.ip_whitelist:
            return False
            
        current_time = time.time()
        
        try:
            # Algorithm 1: Sliding window rate limiting
            window_key = f"rate_limit:{source_ip}:{int(current_time // self.ddos_window)}"
            request_count = self.redis_client.incr(window_key)
            self.redis_client.expire(window_key, self.ddos_window)
            
            if request_count > self.ddos_threshold:
                self._flag_suspicious_ip(source_ip, 'ddos_rate_limit')
                return True
            
            # Algorithm 2: Burst detection (short-term spikes)
            burst_key = f"burst:{source_ip}:{int(current_time // 10)}"
            burst_count = self.redis_client.incr(burst_key)
            self.redis_client.expire(burst_key, 10)
            
            if burst_count > self.burst_threshold:
                self._flag_suspicious_ip(source_ip, 'ddos_burst')
                return True
            
            # Algorithm 3: Pattern-based detection
            if self._detect_ddos_patterns(event):
                self._flag_suspicious_ip(source_ip, 'ddos_pattern')
                return True
                
            # Algorithm 4: Geographic anomaly detection
            if self._detect_geographic_anomaly(source_ip):
                return True
                
        except Exception as e:
            self.logger.error(f"DDoS detection error: {e}")
            
        return False
    
    def _detect_ddos_patterns(self, event: Dict[str, Any]) -> bool:
        """Detect DDoS based on request patterns"""
        source_ip = event.get('source_ip')
        path = event.get('path', '')
        method = event.get('method', 'GET')
        user_agent = event.get('user_agent', '')
        
        # Pattern 1: Same path repeatedly
        path_key = f"path_pattern:{source_ip}:{path}"
        path_count = self.redis_client.incr(path_key)
        self.redis_client.expire(path_key, 300)  # 5 minutes
        
        if path_count > 30:  # Same path > 30 times in 5 minutes
            return True
            
        # Pattern 2: Missing or suspicious User-Agent
        if not user_agent or len(user_agent) < 10:
            ua_key = f"suspicious_ua:{source_ip}"
            ua_count = self.redis_client.incr(ua_key)
            self.redis_client.expire(ua_key, 60)
            if ua_count > 10:
                return True
        
        # Pattern 3: Only HEAD/OPTIONS requests (reconnaissance)
        if method in ['HEAD', 'OPTIONS']:
            method_key = f"recon:{source_ip}:{method}"
            method_count = self.redis_client.incr(method_key)
            self.redis_client.expire(method_key, 60)
            if method_count > 15:
                return True
                
        return False
    
    def _detect_geographic_anomaly(self, source_ip: str) -> bool:
        """Detect requests from unusual geographic locations"""
        try:
            # In production, integrate with GeoIP database
            # For now, check for private/localhost IPs making too many requests
            ip_obj = ipaddress.ip_address(source_ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return False
                
            # Check if IP is from a known bot/crawler network
            # This would typically involve checking against threat intelligence feeds
            if source_ip in self.suspicious_ips:
                return True
                
        except Exception as e:
            self.logger.error(f"Geographic anomaly detection error: {e}")
            
        return False
    
    def detect_injection(self, event: Dict[str, Any]) -> Dict[str, bool]:
        """Enhanced injection detection with multiple attack types"""
        detection_results = {
            'sql_injection': False,
            'xss': False,
            'command_injection': False,
            'ldap_injection': False,
            'xml_injection': False
        }
        
        # Combine all input sources for analysis
        inputs_to_check = []
        inputs_to_check.append(event.get('path', ''))
        inputs_to_check.append(event.get('body', ''))
        
        # Check headers for injection attempts
        headers = event.get('headers', {})
        for header_value in headers.values():
            if isinstance(header_value, str):
                inputs_to_check.append(header_value)
        
        # URL decode inputs before analysis
        decoded_inputs = []
        for input_str in inputs_to_check:
            if input_str:
                decoded_inputs.append(self._url_decode(input_str))
        
        # Run pattern matching for each injection type
        for injection_type, patterns in self.injection_patterns.items():
            for input_str in decoded_inputs:
                for pattern in patterns:
                    if pattern.search(input_str):
                        detection_results[injection_type] = True
                        self._log_injection_attempt(event['source_ip'], injection_type, input_str)
                        break
                if detection_results[injection_type]:
                    break
        
        # Return True if any injection type detected
        return any(detection_results.values())
    
    def _url_decode(self, input_str: str) -> str:
        """URL decode input string for better pattern matching"""
        import urllib.parse
        try:
            # Multiple rounds of decoding to catch double-encoded attacks
            decoded = input_str
            for _ in range(3):
                new_decoded = urllib.parse.unquote(decoded)
                if new_decoded == decoded:
                    break
                decoded = new_decoded
            return decoded.lower()
        except Exception:
            return input_str.lower()
    
    def _flag_suspicious_ip(self, ip: str, reason: str):
        """Flag IP as suspicious and store in Redis"""
        try:
            flag_key = f"suspicious_ip:{ip}"
            flag_data = {
                'reason': reason,
                'timestamp': datetime.utcnow().isoformat(),
                'count': self.redis_client.incr(f"suspicious_count:{ip}")
            }
            self.redis_client.hset(flag_key, mapping=flag_data)
            self.redis_client.expire(flag_key, 3600)  # 1 hour
            
            self.suspicious_ips.add(ip)
            self.logger.warning(f"Flagged suspicious IP {ip}: {reason}")
            
        except Exception as e:
            self.logger.error(f"Error flagging suspicious IP: {e}")
    
    def _log_injection_attempt(self, source_ip: str, injection_type: str, payload: str):
        """Log injection attempt details"""
        try:
            log_key = f"injection_log:{source_ip}:{int(time.time())}"
            log_data = {
                'injection_type': injection_type,
                'payload_preview': payload[:200],  # First 200 chars
                'timestamp': datetime.utcnow().isoformat()
            }
            self.redis_client.hset(log_key, mapping=log_data)
            self.redis_client.expire(log_key, 86400)  # 24 hours
            
            self.logger.warning(f"Injection attempt from {source_ip}: {injection_type}")
            
        except Exception as e:
            self.logger.error(f"Error logging injection attempt: {e}")
    
    def get_suspicious_ips(self) -> List[Dict[str, Any]]:
        """Get list of currently flagged suspicious IPs"""
        try:
            suspicious_data = []
            pattern = "suspicious_ip:*"
            for key in self.redis_client.scan_iter(match=pattern):
                ip = key.split(':')[1]
                data = self.redis_client.hgetall(key)
                data['ip'] = ip
                suspicious_data.append(data)
            return suspicious_data
        except Exception as e:
            self.logger.error(f"Error retrieving suspicious IPs: {e}")
            return []
'''

with open('app/security/detection_engine.py', 'w') as f:
    f.write(detection_engine_content)

print("Generated enhanced detection_engine.py")