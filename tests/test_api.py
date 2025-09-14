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


