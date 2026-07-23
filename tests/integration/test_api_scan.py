from starlette.testclient import TestClient

from app.presentation.api.main import api

client = TestClient(api)


def test_api_scan_endpoint() -> None:
    payload = {"rootfs_path": "sample_data/rootfs"}

    response = client.post("/scan", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert "components" in body
    assert "vulnerabilities" in body
    assert "risk_score" in body
