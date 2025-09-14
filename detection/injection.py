from utils.regex_patterns import INJECTION_PATTERNS


def has_injection_signature(text: str) -> bool:
    if not text:
        return False
    for pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            return True
    return False


