from detection.injection import has_injection_signature, analyze_injection_signature


def test_injection_detection():
    assert has_injection_signature("username=admin' OR '1'='1") is True
    assert has_injection_signature("normal text only") is False


def test_enhanced_injection_detection():
    # Test SQL injection
    result = analyze_injection_signature("username=admin' OR '1'='1")
    assert result["has_injection"] is True
    assert result["confidence"] > 0.5
    assert "sql" in result["attack_types"]
    
    # Test XSS
    result = analyze_injection_signature("<script>alert('xss')</script>")
    assert result["has_injection"] is True
    assert result["confidence"] > 0.5
    assert "xss" in result["attack_types"]
    
    # Test NoSQL injection
    result = analyze_injection_signature('{"$where": "this.username == this.password"}')
    assert result["has_injection"] is True
    assert result["confidence"] > 0.5
    assert "nosql" in result["attack_types"]
    
    # Test normal text
    result = analyze_injection_signature("normal text only")
    assert result["has_injection"] is False
    assert result["confidence"] == 0.0


def test_whitelist_patterns():
    # Test whitelisted patterns
    result = analyze_injection_signature("https://example.com")
    assert result["has_injection"] is False
    
    result = analyze_injection_signature("user@example.com")
    assert result["has_injection"] is False
    
    result = analyze_injection_signature("192.168.1.1")
    assert result["has_injection"] is False


