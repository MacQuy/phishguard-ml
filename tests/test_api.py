import os

from fastapi.testclient import TestClient

_TEST_KEY = os.environ.setdefault(
    "PHISHGUARD_TEST_API_KEY",
    "ci-test-key-not-a-real-secret-xyzzy",
)
os.environ["PHISHGUARD_API_KEY"] = _TEST_KEY
os.environ["PHISHGUARD_ALLOW_INSECURE_DEV_KEY"] = "1"

from phishguard import api  # noqa: E402

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
        headers={"X-API-Key": _TEST_KEY},
        json={"url": "javascript:alert(1)"},
    )
    assert response.status_code == 422