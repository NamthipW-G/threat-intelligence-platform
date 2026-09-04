from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_check():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_create_ioc_validation_rejects_invalid_confidence():
    response = client.post(
        "/iocs",
        json={
            "type": "domain",
            "value": "invalid-confidence-example.com",
            "severity": "high",
            "confidence": 150,
            "source": "pytest",
        },
    )

    assert response.status_code == 422