from detection.ddos import record_request, is_ddos, analyze_ddos_threat, REQUEST_THRESHOLD


def test_ddos_threshold():
    ip = "9.9.9.9"
    for _ in range(REQUEST_THRESHOLD):
        record_request(ip)
        assert is_ddos(ip) is False
    # One more crosses the threshold
    record_request(ip)
    assert is_ddos(ip) is True


def test_enhanced_ddos_detection():
    ip = "8.8.8.8"
    
    # Test volume-based detection
    for _ in range(25):  # Exceed 1-second threshold
        record_request(ip, "/test", "GET", "Mozilla/5.0", "US")
    
    analysis = analyze_ddos_threat(ip)
    assert analysis["confidence"] > 0.0
    assert len(analysis["threats"]) > 0
    
    # Test behavioral detection
    ip2 = "7.7.7.7"
    for _ in range(20):
        record_request(ip2, "/same/path", "GET", "SameUserAgent", "US")
    
    analysis2 = analyze_ddos_threat(ip2)
    assert analysis2["confidence"] > 0.0


def test_whitelist_integration():
    from detection.whitelist import add_ip_whitelist, is_whitelisted
    
    # Add IP to whitelist
    ip = "6.6.6.6"
    add_ip_whitelist(ip, "Test whitelist")
    
    # Check if whitelisted
    is_whitelisted_flag, confidence, reason = is_whitelisted(ip)
    assert is_whitelisted_flag is True
    assert confidence > 0.0
    assert "Test whitelist" in reason


