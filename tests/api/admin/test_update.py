#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from unittest.mock import MagicMock, patch

import pytest


class TestUpdatePublicRoute:
    def test_get_version_returns_current_version(self, client):
        r = client.get("/api/update/get-version")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] is True
        assert data["current_version"] == "2.0"


class TestUpdateAuth:
    def test_check_without_token_returns_401(self, client):
        r = client.get("/api/update/check")
        assert r.status_code == 401

    def test_process_without_token_returns_401(self, client):
        r = client.post("/api/update/process")
        assert r.status_code == 401


class TestUpdateCheck:
    def test_check_detects_new_version(self, client, auth_headers):
        mock_resp = MagicMock()
        mock_resp.content = b'[{"name": "3.0"}]'
        with patch("app.classes.update.requests.get", return_value=mock_resp):
            r = client.get("/api/update/check", headers=auth_headers)
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] is True
        assert data["next_version"] == "3.0"

    def test_check_reports_up_to_date(self, client, auth_headers):
        mock_resp = MagicMock()
        mock_resp.content = b'[{"name": "2.0"}]'
        with patch("app.classes.update.requests.get", return_value=mock_resp):
            r = client.get("/api/update/check", headers=auth_headers)
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] is True
        assert "next_version" not in data

    def test_check_returns_status_false_on_network_error(self, client, auth_headers):
        with patch("app.classes.update.requests.get", side_effect=Exception("network error")):
            r = client.get("/api/update/check", headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["status"] is False


class TestUpdateProcess:
    def test_process_launches_update_script(self, client, auth_headers):
        with patch("app.classes.update.sp.Popen") as mock_popen:
            mock_popen.return_value = MagicMock()
            r = client.post("/api/update/process", headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["status"] is True
        mock_popen.assert_called_once()
