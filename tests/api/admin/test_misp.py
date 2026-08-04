#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from unittest.mock import MagicMock, patch

import pytest

from app.classes.misp import MISP


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


class TestMISPGetIOCs:
    """Unit tests for MISP.get_iocs attribute type mapping."""

    def _make_attr(self, attr_type, value, tags=None):
        attr = {"type": attr_type, "value": value}
        if tags:
            attr["Tag"] = [{"name": t} for t in tags]
        return attr

    def _run_get_iocs(self, attributes, misp_id=1):
        """Call MISP.get_iocs with a mocked PyMISP returning the given attributes."""
        mock_misp_inst = MagicMock()
        mock_misp_inst.url = "https://misp.test"
        mock_misp_inst.apikey = "key"
        mock_misp_inst.verifycert = False
        mock_misp_inst.last_sync = 0

        mock_pymisp = MagicMock()
        mock_pymisp.search.return_value = {"Attribute": attributes}

        with patch("app.classes.misp.MISPInst") as MockModel, \
             patch("app.classes.misp.PyMISP", return_value=mock_pymisp):
            MockModel.query.get.return_value = mock_misp_inst
            return list(MISP.get_iocs(misp_id))

    def test_ja3_fingerprint_md5_yields_ja3_ioc(self):
        h = "72a589da586844d7f0818ce684948eea"
        iocs = self._run_get_iocs([self._make_attr("ja3-fingerprint-md5", h)])
        assert len(iocs) == 1
        assert iocs[0]["type"] == "ja3"
        assert iocs[0]["value"] == h

    def test_domain_attr_yields_domain_ioc(self):
        iocs = self._run_get_iocs([self._make_attr("domain", "evil.example.com")])
        assert len(iocs) == 1
        assert iocs[0]["type"] == "domain"

    def test_ip_dst_attr_yields_ip4addr_ioc(self):
        iocs = self._run_get_iocs([self._make_attr("ip-dst", "1.2.3.4")])
        assert len(iocs) == 1
        assert iocs[0]["type"] == "ip4addr"

    def test_tlp_tag_is_extracted(self):
        iocs = self._run_get_iocs([
            self._make_attr("domain", "evil.example.com", tags=["tlp:red"])
        ])
        assert iocs[0]["tlp"] == "red"

    def test_unknown_attr_type_is_skipped(self):
        iocs = self._run_get_iocs([self._make_attr("url", "http://evil.example.com")])
        assert iocs == []


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
