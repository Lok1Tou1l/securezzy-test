from detection.injection import has_injection_signature


def test_injection_detection():
    assert has_injection_signature("username=admin' OR '1'='1") is True
    assert has_injection_signature("normal text only") is False


