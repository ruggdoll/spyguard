#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import pytest


class TestCTIQuarantineAuth:
    def test_get_quarantine_without_token_returns_401(self, client):
        r = client.get("/api/cti/quarantine")
        assert r.status_code == 401

    def test_add_quarantine_without_token_returns_401(self, client):
        r = client.post("/api/cti/quarantine/add", json={"name": "test"})
        assert r.status_code == 401

    def test_delete_quarantine_without_token_returns_401(self, client):
        r = client.delete("/api/cti/quarantine/delete/1")
        assert r.status_code == 401


class TestCTIQuarantineList:
    def test_empty_list_on_clean_db(self, client, auth_headers):
        r = client.get("/api/cti/quarantine", headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        assert body["status"] is True
        assert body["results"] == []


class TestCTIQuarantineAdd:
    def test_add_requires_name(self, client, auth_headers):
        r = client.post("/api/cti/quarantine/add", json={}, headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["status"] is False

    def test_add_with_name_succeeds(self, client, auth_headers):
        r = client.post("/api/cti/quarantine/add",
                        json={"name": "Pegasus cluster 2024-07", "duration_days": 42},
                        headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        assert body["status"] is True
        assert body["duration_days"] == 42

    def test_add_defaults_duration_to_42(self, client, auth_headers):
        r = client.post("/api/cti/quarantine/add",
                        json={"name": "Predator cluster"},
                        headers=auth_headers)
        assert r.get_json()["duration_days"] == 42

    def test_add_custom_duration(self, client, auth_headers):
        r = client.post("/api/cti/quarantine/add",
                        json={"name": "Short quarantine", "duration_days": 14},
                        headers=auth_headers)
        assert r.get_json()["duration_days"] == 14

    def test_added_event_appears_in_list(self, client, auth_headers):
        client.post("/api/cti/quarantine/add",
                    json={"name": "Paragon exposure", "reason": "Citizen Lab report"},
                    headers=auth_headers)
        r = client.get("/api/cti/quarantine", headers=auth_headers)
        results = r.get_json()["results"]
        assert any(q["name"] == "Paragon exposure" for q in results)

    def test_active_flag_true_for_fresh_event(self, client, auth_headers):
        client.post("/api/cti/quarantine/add",
                    json={"name": "NSO cluster", "duration_days": 30},
                    headers=auth_headers)
        r = client.get("/api/cti/quarantine", headers=auth_headers)
        results = r.get_json()["results"]
        event = next(q for q in results if q["name"] == "NSO cluster")
        assert event["active"] is True

    def test_reason_stored(self, client, auth_headers):
        client.post("/api/cti/quarantine/add",
                    json={"name": "Tagged event", "reason": "Sekoia blog post 2024"},
                    headers=auth_headers)
        r = client.get("/api/cti/quarantine", headers=auth_headers)
        event = next(q for q in r.get_json()["results"] if q["name"] == "Tagged event")
        assert event["reason"] == "Sekoia blog post 2024"


class TestCTIQuarantineDelete:
    def test_delete_nonexistent_returns_false(self, client, auth_headers):
        r = client.delete("/api/cti/quarantine/delete/9999", headers=auth_headers)
        assert r.get_json()["status"] is False

    def test_delete_existing_succeeds(self, client, auth_headers):
        client.post("/api/cti/quarantine/add",
                    json={"name": "To delete"},
                    headers=auth_headers)
        list_r = client.get("/api/cti/quarantine", headers=auth_headers)
        event_id = list_r.get_json()["results"][0]["id"]

        del_r = client.delete(f"/api/cti/quarantine/delete/{event_id}",
                              headers=auth_headers)
        assert del_r.get_json()["status"] is True

        list_r2 = client.get("/api/cti/quarantine", headers=auth_headers)
        assert not any(q["id"] == event_id for q in list_r2.get_json()["results"])
