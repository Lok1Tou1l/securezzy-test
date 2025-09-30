"""
Rule-based injection detection filter using libinjection and custom patterns
Returns: 0 (benign), 1 (attack), 2 (ambiguous - needs model)
Fast pre-filtering to reduce ML model workload
"""

import re
import string
from typing import Union

# Install required library: pip install libinjection-python
try:
    import libinjection
    LIBINJECTION_AVAILABLE = True
    print("libinjection-python installed")
except ImportError:
    print("Warning: libinjection-python not installed. Install with: pip install libinjection-python")
    LIBINJECTION_AVAILABLE = False

class RuleBasedInjectionFilter:
    """
    Fast rule-based filter for web injection detection
    Uses libinjection for definitive attack detection and custom patterns for benign detection

    Classification Results:
    - 0: Obviously benign (safe to pass without ML evaluation)
    - 1: Obviously malicious (definitive attack detected)  
    - 2: Ambiguous (requires ML model evaluation)
    """

    def __init__(self):
        # Compile regex patterns for performance
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile all regex patterns for better performance"""

        # Obviously benign patterns (return 0)
        self.benign_patterns = [
            # Pure alphanumeric with basic punctuation
            re.compile(r'^[a-zA-Z0-9_\-\.@\s]*$'),

            # Common email patterns
            re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_\-\.]{1,63}@[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$'),

            # Simple numeric values (integers and decimals)
            re.compile(r'^\d+(\.\d+)?$'),

            # Common search terms (letters, numbers, spaces, basic punctuation)
            re.compile(r'^[a-zA-Z0-9\s\'\"\.\!\?\-]+$'),

            # URL-safe strings (RFC 3986 unreserved characters)
            re.compile(r'^[a-zA-Z0-9\-\._~:/?#[\]@!$&\'()*+,;=]*$'),

            # Common date formats
            re.compile(r'^\d{4}-\d{2}-\d{2}(\s\d{2}:\d{2}(:\d{2})?)?$'),

            # Simple word boundaries
            re.compile(r'^\b[a-zA-Z]+\b$'),
        ]

        # Obviously malicious patterns (return 1) - High confidence
        self.malicious_patterns = [
            # SQL injection keywords (high confidence combinations)
            re.compile(r'\b(union\s+select|drop\s+table|delete\s+from|insert\s+into)\b', re.IGNORECASE),
            re.compile(r'\b(alter\s+table|create\s+table|truncate\s+table)\b', re.IGNORECASE),
            re.compile(r'\b(exec\s*\(|execute\s*\(|sp_executesql)\b', re.IGNORECASE),

            # XSS script injection
            re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            re.compile(r'<iframe[^>]*>.*?</iframe>', re.IGNORECASE | re.DOTALL),
            re.compile(r'<object[^>]*>.*?</object>', re.IGNORECASE | re.DOTALL),
            re.compile(r'<embed[^>]*>.*?</embed>', re.IGNORECASE | re.DOTALL),

            # JavaScript execution patterns
            re.compile(r'javascript\s*:', re.IGNORECASE),
            re.compile(r'on(load|error|click|mouseover|mouseout|focus|blur)\s*=', re.IGNORECASE),
            re.compile(r'eval\s*\(|setTimeout\s*\(|setInterval\s*\(', re.IGNORECASE),

            # Command injection patterns
            re.compile(r'\b(cmd|system|exec|eval|passthru|shell_exec)\s*\(', re.IGNORECASE),
            re.compile(r'\b(\|\s*|(;\s*|&&\s*|\|\|\s*)(ls|cat|pwd|whoami|id)\b)', re.IGNORECASE),
            re.compile(r'\b(wget|curl|nc|netcat)\s+', re.IGNORECASE),

            # Path traversal patterns
            re.compile(r'\.\.[\\/]\.\.[\\/]'),
            re.compile(r'\.\.[\\/]{3,}'),
            re.compile(r'[\\/]etc[\\/]passwd'),
            re.compile(r'[\\/]windows[\\/]system32'),

            # SQL comment patterns (definitive attack context)
            re.compile(r'--\s*$', re.MULTILINE),
            re.compile(r'/\*.*?\*/', re.DOTALL),
            re.compile(r'#.*$', re.MULTILINE),

            # LDAP injection
            re.compile(r'\*\)|\(\|', re.IGNORECASE),

            # NoSQL injection patterns
            re.compile(r'\$where|\$ne|\$gt|\$lt|\$regex', re.IGNORECASE),
        ]

        # Suspicious patterns that need model evaluation (return 2)
        self.suspicious_patterns = [
            # SQL-like patterns (lower confidence)
            re.compile(r'\b(select|from|where|order\s+by|group\s+by|having|limit)\b', re.IGNORECASE),
            re.compile(r'\b(update|insert|delete|create|drop|alter)\b', re.IGNORECASE),

            # HTML-like patterns that might be benign
            re.compile(r'<[^>]+>'),
            re.compile(r'&[a-zA-Z0-9]+;'),

            # URL encoding patterns
            re.compile(r'%[0-9a-f]{2}', re.IGNORECASE),
            re.compile(r'\\x[0-9a-f]{2}', re.IGNORECASE),

            # Function call patterns
            re.compile(r'\w+\s*\([^)]*\)'),

            # Base64-like patterns (might hide payloads)
            re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),

            # Suspicious characters clustering
            re.compile(r'[<>\"\'\(\);=%&\|]{3,}'),
            re.compile(r'[{}\[\]]{2,}'),

            # Potential concatenation attacks
            re.compile(r'\+\s*[\'\"]+|[\'\"]+\s*\+'),

            # UNION patterns (might be legitimate in some contexts)
            re.compile(r'\bunion\b', re.IGNORECASE),
        ]

    def is_obviously_benign(self, text: str) -> bool:
        """Check if text matches obviously benign patterns"""

        # Empty or very short strings are usually benign
        if not text or len(text.strip()) <= 2:
            return True

        # Check basic characteristics first (fast)
        if self._is_simple_alphanumeric(text):
            return True

        # Check against benign patterns
        for pattern in self.benign_patterns:
            if pattern.match(text.strip()):
                return True

        return False

    def _is_simple_alphanumeric(self, text: str) -> bool:
        """Check if text is simple alphanumeric with minimal special chars"""

        # Count character types
        alpha_count = sum(1 for c in text if c.isalpha())
        digit_count = sum(1 for c in text if c.isdigit())
        space_count = sum(1 for c in text if c.isspace())
        safe_special = sum(1 for c in text if c in '_-.@')
        other_count = len(text) - alpha_count - digit_count - space_count - safe_special

        # If mostly alphanumeric with minimal special characters
        total_safe = alpha_count + digit_count + space_count + safe_special
        return len(text) > 0 and (total_safe / len(text)) >= 0.95

    def has_definitive_attack(self, text: str) -> bool:
        """Check for definitive attack patterns using libinjection and high-confidence patterns"""

        # Use libinjection for SQL injection and XSS detection
        if LIBINJECTION_AVAILABLE:
            try:
                # Check SQL injection with libinjection
                if libinjection.is_sql_injection(text):
                    return True

                # Check XSS with libinjection  
                if libinjection.is_xss(text):
                    return True
            except Exception:
                # Fall back to pattern matching if libinjection fails
                pass

        # Check high-confidence malicious patterns
        for pattern in self.malicious_patterns:
            if pattern.search(text):
                return True

        return False

    def has_suspicious_patterns(self, text: str) -> bool:
        """Check for suspicious patterns that need model evaluation"""

        for pattern in self.suspicious_patterns:
            if pattern.search(text):
                return True

        return False

    def classify_text(self, text: str) -> int:
        """
        Main classification function

        Returns:
            0: Obviously benign (safe to pass)
            1: Obviously malicious (block immediately) 
            2: Ambiguous (needs model evaluation)
        """

        if not isinstance(text, str):
            return 2  # Non-string input needs evaluation

        # Basic preprocessing
        text = text.strip()

        # Empty strings are benign
        if not text:
            return 0

        # Check for obvious attacks first (highest priority)
        if self.has_definitive_attack(text):
            return 1

        # Check for obviously benign patterns
        if self.is_obviously_benign(text):
            return 0

        # Check for suspicious patterns
        if self.has_suspicious_patterns(text):
            return 2

        # If no patterns match but not obviously benign, check characteristics
        if self._needs_model_evaluation(text):
            return 2

        # Default to benign for simple text that doesn't match any patterns
        return 0

    def _needs_model_evaluation(self, text: str) -> bool:
        """Determine if text characteristics suggest model evaluation is needed"""

        # Very long strings might hide attacks
        if len(text) > 1000:
            return True

        # High ratio of special characters
        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        if len(text) > 0 and (special_chars / len(text)) > 0.3:
            return True

        # Contains multiple encoding types (suspicious)
        has_url_encoding = '%' in text
        has_html_encoding = '&' in text and ';' in text  
        has_unicode = any(ord(c) > 127 for c in text)

        encoding_count = sum([has_url_encoding, has_html_encoding, has_unicode])
        if encoding_count >= 2:
            return True

        # Contains mixed quotes and brackets (potential injection)
        quote_bracket_chars = sum(1 for c in text if c in '\'"()[]{}')
        if quote_bracket_chars >= 4:
            return True

        # High entropy (might be encoded payload)
        if self._calculate_entropy(text) > 4.5:
            return True

        return False

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        import math

        if not text:
            return 0

        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculate entropy
        entropy = 0
        text_len = len(text)
        for count in char_counts.values():
            p = count / text_len
            entropy -= p * math.log2(p)

        return entropy

    def get_classification_details(self, text: str) -> dict:
        """Get detailed classification information for debugging"""
        result = self.classify_text(text)

        details = {
            'result': result,
            'result_meaning': {0: 'benign', 1: 'malicious', 2: 'ambiguous'}[result],
            'text_length': len(text),
            'has_definitive_attack': self.has_definitive_attack(text),
            'is_obviously_benign': self.is_obviously_benign(text),
            'has_suspicious_patterns': self.has_suspicious_patterns(text),
            'needs_model_evaluation': self._needs_model_evaluation(text),
            'entropy': self._calculate_entropy(text),
            'libinjection_available': LIBINJECTION_AVAILABLE
        }

        return details


# Convenience function for direct use
def quick_injection_check(text: str) -> int:
    """
    Quick injection detection function

    Args:
        text: Input text to check

    Returns:
        0: Obviously benign (safe to pass)
        1: Obviously malicious (block immediately)
        2: Ambiguous (needs model evaluation)
    """
    filter_instance = RuleBasedInjectionFilter()
    return filter_instance.classify_text(text)


# Test function for validation
def test_filter():
    """Test function to validate the filter works correctly"""
    filter_obj = RuleBasedInjectionFilter()

    test_cases = [
        ("hello world", 0),  # benign
        ("user@example.com", 0),  # benign  
        ("'; DROP TABLE users; --", 1),  # malicious
        ("<script>alert('xss')</script>", 1),  # malicious
        ("SELECT * FROM products", 2),  # suspicious
        ("search term with spaces", 0),  # benign
        ("../../../etc/passwd", 1),  # malicious
        ("ORDER BY username", 2),  # suspicious
    ]

    print("Testing RuleBasedInjectionFilter:")
    for text, expected in test_cases:
        result = filter_obj.classify_text(text)
        status = "✓" if result == expected else "✗"
        print(f"{status} '{text}' -> {result} (expected {expected})")


if __name__ == "__main__":
    test_filter()
