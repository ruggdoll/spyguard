"""Tests for /api/whitelist routes."""

import pytest


class TestWhitelistAuth:
    def test_get_types_without_token_returns_401(self, client):
        r = client.get("/api/whitelist/get/types")
        assert r.status_code == 401


class TestWhitelistReadOnlyRoutes:
    def test_get_types_returns_known_types(self, client, auth_headers):
        r = client.get("/api/whitelist/get/types", headers=auth_headers)
        assert r.status_code == 200
        types = [t["type"] for t in r.get_json()["types"]]
        assert "ip4addr" in types
        assert "domain" in types

    def test_search_on_empty_db_returns_empty(self, client, auth_headers):
        r = client.get("/api/whitelist/search/*", headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["results"] == []


class TestWhitelistAddWithCorrectVerb:

    def test_add_domain_via_post(self, client, auth_headers):
        payload = {"data": {"element": {
            "elem_type": "domain",
            "elem_value": "safe.example.com",
            "elem_source": "pytest",
        }}}
        r = client.post("/api/whitelist/add_post", json=payload, headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["status"] is True


class TestWhitelistDeleteWithCorrectVerb:

    def test_delete_via_get_returns_405(self, client, auth_headers):
        """GET /delete/<id> should be 405 Method Not Allowed."""
        r = client.get("/api/whitelist/delete/999", headers=auth_headers)
        assert r.status_code == 405

    def test_delete_nonexistent_via_delete_returns_404_or_status_false(self, client, auth_headers):
        r = client.delete("/api/whitelist/delete/9999", headers=auth_headers)
        assert r.status_code in (200, 404)
        if r.status_code == 200:
            assert r.get_json()["status"] is False
