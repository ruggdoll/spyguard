"""Tests for /api/ioc routes."""

import pytest


class TestIocAuth:
    def test_get_types_without_token_returns_401(self, client):
        r = client.get("/api/ioc/get/types")
        assert r.status_code == 401

    def test_get_types_with_invalid_token_returns_403(self, client):
        r = client.get("/api/ioc/get/types", headers={"X-Token": "not-a-jwt"})
        assert r.status_code == 403


class TestIocReadOnlyRoutes:
    def test_get_types_returns_known_types(self, client, auth_headers):
        r = client.get("/api/ioc/get/types", headers=auth_headers)
        assert r.status_code == 200
        types = [t["type"] for t in r.get_json()["types"]]
        assert "ip4addr" in types
        assert "domain" in types
        assert "sha1cert" in types

    def test_get_tags_returns_list(self, client, auth_headers):
        r = client.get("/api/ioc/get/tags", headers=auth_headers)
        assert r.status_code == 200
        tags = r.get_json()["tags"]
        assert isinstance(tags, list)
        assert "malicious" in tags
        assert "stalkerware" in tags

    def test_search_wildcard_on_empty_db_returns_empty(self, client, auth_headers):
        r = client.get("/api/ioc/search/*", headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["results"] == []

    def test_search_specific_term_on_empty_db_returns_empty(self, client, auth_headers):
        r = client.get("/api/ioc/search/evil.example.com", headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["results"] == []


class TestIocAddViaExistingPostRoute:
    """POST /add_post already uses the correct verb — should pass right now."""

    def test_add_valid_domain_ioc(self, client, auth_headers):
        payload = {"data": {"ioc": {
            "ioc_type": "domain",
            "ioc_tag": "malicious",
            "ioc_tlp": "white",
            "ioc_value": "evil.example.com",
            "ioc_source": "pytest",
        }}}
        r = client.post("/api/ioc/add_post", json=payload, headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        assert body["status"] is True
        assert body["message"] == "IOC added"

    def test_add_invalid_tlp_is_rejected(self, client, auth_headers):
        payload = {"data": {"ioc": {
            "ioc_type": "domain",
            "ioc_tag": "malicious",
            "ioc_tlp": "invalid_tlp",
            "ioc_value": "evil.example.com",
            "ioc_source": "pytest",
        }}}
        r = client.post("/api/ioc/add_post", json=payload, headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["status"] is False

    def test_add_duplicate_ioc_is_rejected(self, client, auth_headers):
        payload = {"data": {"ioc": {
            "ioc_type": "domain",
            "ioc_tag": "malicious",
            "ioc_tlp": "white",
            "ioc_value": "duplicate.example.com",
            "ioc_source": "pytest",
        }}}
        client.post("/api/ioc/add_post", json=payload, headers=auth_headers)
        r = client.post("/api/ioc/add_post", json=payload, headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["status"] is False
        assert "already exists" in r.get_json()["message"]

    def test_search_finds_added_ioc(self, client, auth_headers):
        payload = {"data": {"ioc": {
            "ioc_type": "ip4addr",
            "ioc_tag": "apt",
            "ioc_tlp": "green",
            "ioc_value": "1.2.3.4",
            "ioc_source": "pytest",
        }}}
        client.post("/api/ioc/add_post", json=payload, headers=auth_headers)
        r = client.get("/api/ioc/search/1.2.3.4", headers=auth_headers)
        assert r.status_code == 200
        results = r.get_json()["results"]
        assert len(results) == 1
        assert results[0]["value"] == "1.2.3.4"
        assert results[0]["type"] == "ip4addr"


class TestIocDeleteWithCorrectVerb:
    """DELETE /api/ioc/delete/<id> is the correct REST verb."""

    def test_delete_existing_ioc_via_delete(self, client, auth_headers):
        payload = {"data": {"ioc": {
            "ioc_type": "domain",
            "ioc_tag": "malicious",
            "ioc_tlp": "white",
            "ioc_value": "to-delete.example.com",
            "ioc_source": "pytest",
        }}}
        add_r = client.post("/api/ioc/add_post", json=payload, headers=auth_headers)
        assert add_r.get_json()["status"] is True

        search_r = client.get("/api/ioc/search/to-delete.example.com", headers=auth_headers)
        results = search_r.get_json()["results"]
        assert len(results) == 1
        ioc_id = results[0]["id"]

        r = client.delete(f"/api/ioc/delete/{ioc_id}", headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["status"] is True

    def test_get_on_delete_route_returns_405(self, client, auth_headers):
        """GET /api/ioc/delete/<id> should be 405 Method Not Allowed."""
        r = client.get("/api/ioc/delete/999", headers=auth_headers)
        assert r.status_code == 405
