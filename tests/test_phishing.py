import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

def test_phishing_url_detection():
    payload = {"url": "http://192.168.1.1/secure-login.bank-update.xyz/auth"}
    res = client.post("/api/v1/phishing/scan", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["is_phishing"] is True
    assert data["threat_score"] >= 0.50
    assert len(data["detected_suspicious_patterns"]) >= 2

def test_legitimate_url_scan():
    payload = {"url": "https://docs.python.org/3/library/math.html"}
    res = client.post("/api/v1/phishing/scan", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["is_phishing"] is False
    assert data["threat_score"] < 0.50
