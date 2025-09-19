import re
from typing import Dict, List, Tuple


# Comprehensive injection patterns with confidence scoring
INJECTION_PATTERNS = {
    # SQL Injection patterns (High confidence)
    "sql_high": [
        (re.compile(r"\bOR\b\s+'1'='1", re.IGNORECASE), 0.9),
        (re.compile(r"\bUNION\b\s+SELECT", re.IGNORECASE), 0.9),
        (re.compile(r"\bUNION\b\s+ALL\s+SELECT", re.IGNORECASE), 0.9),
        (re.compile(r"'\s*OR\s*'.*?'\s*=\s*'.*?'", re.IGNORECASE), 0.8),
        (re.compile(r"\bAND\b\s+'.*?'\s*=\s*'.*?'", re.IGNORECASE), 0.8),
        (re.compile(r"\bDROP\b\s+TABLE", re.IGNORECASE), 0.9),
        (re.compile(r"\bDELETE\b\s+FROM", re.IGNORECASE), 0.8),
        (re.compile(r"\bINSERT\b\s+INTO", re.IGNORECASE), 0.8),
        (re.compile(r"\bUPDATE\b\s+.*?\bSET\b", re.IGNORECASE), 0.8),
        (re.compile(r"\bEXEC\b\s*\(", re.IGNORECASE), 0.9),
        (re.compile(r"\bEXECUTE\b\s*\(", re.IGNORECASE), 0.9),
        (re.compile(r"\bWAITFOR\b\s+DELAY", re.IGNORECASE), 0.9),
        (re.compile(r"\bSLEEP\b\s*\(", re.IGNORECASE), 0.8),
        (re.compile(r"\bBENCHMARK\b\s*\(", re.IGNORECASE), 0.8),
    ],
    
    # SQL Injection patterns (Medium confidence)
    "sql_medium": [
        (re.compile(r"'\s*;\s*--", re.IGNORECASE), 0.6),
        (re.compile(r"'\s*;\s*/\*", re.IGNORECASE), 0.6),
        (re.compile(r"\bSELECT\b\s+.*?\bFROM\b", re.IGNORECASE), 0.5),
        (re.compile(r"\bWHERE\b\s+.*?\s*=", re.IGNORECASE), 0.4),
        (re.compile(r"'\s*OR\s*1\s*=\s*1", re.IGNORECASE), 0.7),
        (re.compile(r"'\s*AND\s*1\s*=\s*1", re.IGNORECASE), 0.6),
    ],
    
    # XSS patterns (High confidence)
    "xss_high": [
        (re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL), 0.9),
        (re.compile(r"<script[^>]*>", re.IGNORECASE), 0.8),
        (re.compile(r"javascript\s*:", re.IGNORECASE), 0.8),
        (re.compile(r"on\w+\s*=\s*['\"].*?['\"]", re.IGNORECASE), 0.7),
        (re.compile(r"<iframe[^>]*>", re.IGNORECASE), 0.8),
        (re.compile(r"<object[^>]*>", re.IGNORECASE), 0.7),
        (re.compile(r"<embed[^>]*>", re.IGNORECASE), 0.7),
        (re.compile(r"<link[^>]*>", re.IGNORECASE), 0.6),
        (re.compile(r"<meta[^>]*>", re.IGNORECASE), 0.6),
        (re.compile(r"<style[^>]*>.*?</style>", re.IGNORECASE | re.DOTALL), 0.7),
    ],
    
    # XSS patterns (Medium confidence)
    "xss_medium": [
        (re.compile(r"<img[^>]*onerror\s*=", re.IGNORECASE), 0.6),
        (re.compile(r"<svg[^>]*onload\s*=", re.IGNORECASE), 0.6),
        (re.compile(r"<body[^>]*onload\s*=", re.IGNORECASE), 0.6),
        (re.compile(r"<form[^>]*onsubmit\s*=", re.IGNORECASE), 0.6),
        (re.compile(r"<input[^>]*onfocus\s*=", re.IGNORECASE), 0.6),
        (re.compile(r"<a[^>]*onclick\s*=", re.IGNORECASE), 0.5),
    ],
    
    # NoSQL Injection patterns
    "nosql_high": [
        (re.compile(r"\$where\s*:", re.IGNORECASE), 0.9),
        (re.compile(r"\$ne\s*:", re.IGNORECASE), 0.8),
        (re.compile(r"\$gt\s*:", re.IGNORECASE), 0.8),
        (re.compile(r"\$lt\s*:", re.IGNORECASE), 0.8),
        (re.compile(r"\$regex\s*:", re.IGNORECASE), 0.8),
        (re.compile(r"\$exists\s*:", re.IGNORECASE), 0.7),
        (re.compile(r"\$in\s*:", re.IGNORECASE), 0.7),
        (re.compile(r"\$nin\s*:", re.IGNORECASE), 0.7),
        (re.compile(r"\$or\s*:", re.IGNORECASE), 0.8),
        (re.compile(r"\$and\s*:", re.IGNORECASE), 0.7),
        (re.compile(r"\$not\s*:", re.IGNORECASE), 0.7),
        (re.compile(r"\$nor\s*:", re.IGNORECASE), 0.7),
    ],
    
    # LDAP Injection patterns
    "ldap_high": [
        (re.compile(r"\(\s*\|\s*\(.*?\)\s*\)", re.IGNORECASE), 0.8),
        (re.compile(r"\(\s*&\s*\(.*?\)\s*\)", re.IGNORECASE), 0.8),
        (re.compile(r"\(\s*!\s*\(.*?\)\s*\)", re.IGNORECASE), 0.8),
        (re.compile(r"\(\s*cn\s*=\s*\*\)", re.IGNORECASE), 0.9),
        (re.compile(r"\(\s*uid\s*=\s*\*\)", re.IGNORECASE), 0.9),
        (re.compile(r"\(\s*mail\s*=\s*\*\)", re.IGNORECASE), 0.9),
        (re.compile(r"\(\s*sn\s*=\s*\*\)", re.IGNORECASE), 0.9),
        (re.compile(r"\(\s*objectClass\s*=\s*\*\)", re.IGNORECASE), 0.9),
        (re.compile(r"\(\s*userPassword\s*=\s*\*\)", re.IGNORECASE), 0.9),
        (re.compile(r"\(\s*memberOf\s*=\s*\*\)", re.IGNORECASE), 0.9),
    ],
    
    # LDAP Injection patterns (Medium confidence)
    "ldap_medium": [
        (re.compile(r"\(\s*cn\s*=\s*.*?\*.*?\)", re.IGNORECASE), 0.6),
        (re.compile(r"\(\s*uid\s*=\s*.*?\*.*?\)", re.IGNORECASE), 0.6),
        (re.compile(r"\(\s*mail\s*=\s*.*?\*.*?\)", re.IGNORECASE), 0.6),
        (re.compile(r"\(\s*sn\s*=\s*.*?\*.*?\)", re.IGNORECASE), 0.6),
    ],
    
    # Command Injection patterns
    "cmd_high": [
        (re.compile(r"[\|;&]\s*(ls|dir|cat|type|more|less)", re.IGNORECASE), 0.8),
        (re.compile(r"[\|;&]\s*(rm|del|rmdir|rd)", re.IGNORECASE), 0.9),
        (re.compile(r"[\|;&]\s*(wget|curl|nc|netcat)", re.IGNORECASE), 0.8),
        (re.compile(r"[\|;&]\s*(ps|tasklist|top|htop)", re.IGNORECASE), 0.7),
        (re.compile(r"[\|;&]\s*(id|whoami|who)", re.IGNORECASE), 0.7),
        (re.compile(r"[\|;&]\s*(uname|systeminfo|ver)", re.IGNORECASE), 0.7),
        (re.compile(r"[\|;&]\s*(ping|traceroute|tracert)", re.IGNORECASE), 0.6),
        (re.compile(r"[\|;&]\s*(chmod|chown|attrib)", re.IGNORECASE), 0.8),
        (re.compile(r"[\|;&]\s*(find|grep|findstr)", re.IGNORECASE), 0.7),
        (re.compile(r"[\|;&]\s*(tar|zip|unzip|gzip)", re.IGNORECASE), 0.6),
    ],
    
    # Path Traversal patterns
    "path_high": [
        (re.compile(r"\.\./", re.IGNORECASE), 0.8),
        (re.compile(r"\.\.\\", re.IGNORECASE), 0.8),
        (re.compile(r"\.\.%2f", re.IGNORECASE), 0.8),
        (re.compile(r"\.\.%5c", re.IGNORECASE), 0.8),
        (re.compile(r"\.\.%252f", re.IGNORECASE), 0.8),
        (re.compile(r"\.\.%255c", re.IGNORECASE), 0.8),
        (re.compile(r"\.\.%c0%af", re.IGNORECASE), 0.8),
        (re.compile(r"\.\.%c1%9c", re.IGNORECASE), 0.8),
        (re.compile(r"/etc/passwd", re.IGNORECASE), 0.9),
        (re.compile(r"/etc/shadow", re.IGNORECASE), 0.9),
        (re.compile(r"/windows/system32", re.IGNORECASE), 0.9),
        (re.compile(r"/boot\.ini", re.IGNORECASE), 0.9),
        (re.compile(r"/win\.ini", re.IGNORECASE), 0.9),
    ],
}

# Whitelist patterns for common false positives
WHITELIST_PATTERNS = [
    re.compile(r"^https?://", re.IGNORECASE),  # URLs
    re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),  # Email addresses
    re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),  # IP addresses
    re.compile(r"^[a-fA-F0-9]{32}$"),  # MD5 hashes
    re.compile(r"^[a-fA-F0-9]{40}$"),  # SHA1 hashes
    re.compile(r"^[a-fA-F0-9]{64}$"),  # SHA256 hashes
    re.compile(r"^[A-Za-z0-9+/]{4}*[A-Za-z0-9+/]{2}==?$"),  # Base64
    re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),  # UUIDs
]

# Confidence thresholds for different severity levels
CONFIDENCE_THRESHOLDS = {
    "critical": 0.8,
    "high": 0.6,
    "medium": 0.4,
    "low": 0.2
}


