import re


# Very lightweight patterns for demo purposes only
INJECTION_PATTERNS = [
    re.compile(r"\bOR\b\s+'1'='1", re.IGNORECASE),
    re.compile(r"\bUNION\b\s+SELECT", re.IGNORECASE),
    re.compile(r"<script[^>]*>", re.IGNORECASE),
]


