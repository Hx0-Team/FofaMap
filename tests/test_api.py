from fastapi.testclient import TestClient

from service.api import app


def test_openapi_and_fields_endpoint():
    with TestClient(app) as client:
        openapi = client.get("/openapi.json")
        assert openapi.status_code == 200
        assert openapi.json()["info"]["version"] == "2.0.1"
        response = client.get("/v1/fields")
        assert response.status_code == 200
        assert "host" in response.json()["base"]
        assert "longitude" in response.json()["base"]
        assert "status_code" in response.json()["compat"]
        assert "fid" in response.json()["tiers"]["enterprise"]
        assert response.json()["membership_source"] == "https://fofa.info/api"
        education = next(item for item in response.json()["memberships"] if item["vip_level"] == 22)
        assert education["field_tier"] == "personal"
        assert education["stats_api"] is False
