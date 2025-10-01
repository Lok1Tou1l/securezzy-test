import json
import pytest

from app import create_app


@pytest.fixture()
def client():
    app = create_app()
    app.config.update({"TESTING": True})
    with app.test_client() as c:
        yield c


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_events_flow(client):
    # Initially empty
    resp = client.get("/events")
    assert resp.status_code == 200
    assert isinstance(resp.get_json(), list)

    # Add one
    payload = {
        "source_ip": "1.2.3.4",
        "path": "/",
        "method": "GET",
        "body": "",
    }
    resp = client.post("/events", data=json.dumps(payload), content_type="application/json")
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["stored"] is True

    # List again
    resp = client.get("/events")
    events = resp.get_json()
    assert len(events) >= 1


def test_analyze_endpoint(client):
    """Test the /analyze endpoint for request analysis"""
    payload = {
        "source_ip": "192.168.1.100",
        "path": "/api/test",
        "method": "POST",
        "body": '{"username": "admin", "password": "test123"}',
        "user_agent": "Test-Agent/1.0",
        "country": "US"
    }
    
    resp = client.post("/analyze", data=json.dumps(payload), content_type="application/json")
    assert resp.status_code == 200
    
    data = resp.get_json()
    
    # Check required fields are present
    assert "whitelisted" in data
    assert "ddos_analysis" in data
    assert "injection_analysis" in data
    assert "anomaly_score" in data
    
    # Check injection analysis structure
    assert "path" in data["injection_analysis"]
    assert "body" in data["injection_analysis"]
    
    # Check data types
    assert isinstance(data["whitelisted"], bool)
    assert isinstance(data["ddos_analysis"], dict)
    assert isinstance(data["injection_analysis"], dict)
    assert data["anomaly_score"] is None or isinstance(data["anomaly_score"], (int, float))


def test_analyze_endpoint_minimal_data(client):
    """Test the /analyze endpoint with minimal data"""
    payload = {
        "source_ip": "127.0.0.1",
        "path": "/",
        "method": "GET"
    }
    
    resp = client.post("/analyze", data=json.dumps(payload), content_type="application/json")
    assert resp.status_code == 200
    
    data = resp.get_json()
    assert "whitelisted" in data
    assert "ddos_analysis" in data
    assert "injection_analysis" in data


