import os

from fastapi.testclient import TestClient

os.environ["PHISHGUARD_API_KEY"] = "test-secret-key-that-is-long-enough-123"
from phishguard import api

client = TestClient(api.app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_predict_requires_api_key():
    response = client.post("/predict", json={"url": "https://example.com"})
    assert response.status_code == 401

def test_invalid_url_rejected_with_auth():
    response = client.post(
        "/predict",
        headers={"X-API-Key": "test-secret-key-that-is-long-enough-123"},
        json={"url": "javascript:alert(1)"},
    )
    assert response.status_code == 422
