#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from unittest.mock import MagicMock, patch

import pytest


_PAYLOAD = {
    "data": {
        "instance": {
            "url": "https://misp.example.com",
            "name": "Test MISP",
            "key": "testapikey123",
            "ssl": False,
        }
    }
}


class TestMISPAuth:
    def test_get_all_without_token_returns_401(self, client):
        r = client.get("/api/misp/get_all")
        assert r.status_code == 401

    def test_add_without_token_returns_401(self, client):
        r = client.post("/api/misp/add", json=_PAYLOAD)
        assert r.status_code == 401

    def test_delete_without_token_returns_401(self, client):
        r = client.delete("/api/misp/delete/1")
        assert r.status_code == 401


class TestMISPGetAll:
    def test_get_all_returns_empty_list_on_clean_db(self, client, auth_headers):
        r = client.get("/api/misp/get_all", headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["results"] == []


class TestMISPAdd:
    def test_add_succeeds_when_connection_ok(self, client, auth_headers):
        with patch("app.classes.misp.PyMISP", return_value=MagicMock()):
            r = client.post("/api/misp/add", json=_PAYLOAD, headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["status"] is True

    def test_add_fails_when_connection_refused(self, client, auth_headers):
        with patch("app.classes.misp.PyMISP", side_effect=Exception("conn refused")):
            r = client.post("/api/misp/add", json=_PAYLOAD, headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["status"] is False

    def test_add_without_name_returns_status_false(self, client, auth_headers):
        payload = {
            "data": {
                "instance": {
                    "url": "https://misp.example.com",
                    "name": "",
                    "key": "testapikey123",
                    "ssl": False,
                }
            }
        }
        with patch("app.classes.misp.PyMISP", return_value=MagicMock()):
            r = client.post("/api/misp/add", json=payload, headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["status"] is False

    def test_add_duplicate_is_rejected(self, client, auth_headers):
        with patch("app.classes.misp.PyMISP", return_value=MagicMock()):
            client.post("/api/misp/add", json=_PAYLOAD, headers=auth_headers)
            r = client.post("/api/misp/add", json=_PAYLOAD, headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["status"] is False


class TestMISPDelete:
    def test_delete_nonexistent_returns_status_false(self, client, auth_headers):
        r = client.delete("/api/misp/delete/9999", headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["status"] is False

    def test_delete_existing_succeeds(self, client, auth_headers):
        # Add first.
        with patch("app.classes.misp.PyMISP", return_value=MagicMock()):
            add_r = client.post("/api/misp/add", json=_PAYLOAD, headers=auth_headers)
        assert add_r.get_json()["status"] is True

        # Get its ID from the list.
        with patch("app.classes.misp.PyMISP", return_value=MagicMock()):
            list_r = client.get("/api/misp/get_all", headers=auth_headers)
        results = list_r.get_json()["results"]
        assert len(results) == 1
        misp_id = results[0]["id"]

        # Delete it.
        r = client.delete(f"/api/misp/delete/{misp_id}", headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["status"] is True
