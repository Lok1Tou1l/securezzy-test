from detection.ddos import record_request, is_ddos, REQUEST_THRESHOLD


def test_ddos_threshold():
    ip = "9.9.9.9"
    for _ in range(REQUEST_THRESHOLD):
        record_request(ip)
        assert is_ddos(ip) is False
    # One more crosses the threshold
    record_request(ip)
    assert is_ddos(ip) is True


