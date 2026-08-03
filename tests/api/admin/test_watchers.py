#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

import pytest
import yaml


_PAYLOAD = {
    "data": {
        "instance": {
            "name": "SpyGuard IOCs",
            "url": "https://raw.githubusercontent.com/example/iocs.json",
            "type": "iocs",
        }
    }
}


@pytest.fixture(autouse=True)
def clean_watchers():
    """Reset watcher in-memory state and YAML file between tests."""
    from app.blueprints.watchers import watcher as _watcher

    yield

    _watcher.watchers = []
    wpath = os.environ.get("SPYGUARD_WATCHERS_PATH")
    if wpath:
        with open(wpath, "w") as f:
            yaml.dump({"watchers": []}, f)


class TestWatchersAuth:
    def test_get_all_without_token_returns_401(self, client):
        r = client.get("/api/watchers/get_all")
        assert r.status_code == 401

    def test_add_without_token_returns_401(self, client):
        r = client.post("/api/watchers/add", json=_PAYLOAD)
        assert r.status_code == 401

    def test_delete_without_token_returns_401(self, client):
        r = client.delete("/api/watchers/delete/0")
        assert r.status_code == 401


class TestWatchersGetAll:
    def test_get_all_returns_empty_list_initially(self, client, auth_headers):
        r = client.get("/api/watchers/get_all", headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["results"] == []


class TestWatchersAdd:
    def test_add_watcher_succeeds(self, client, auth_headers):
        r = client.post("/api/watchers/add", json=_PAYLOAD, headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["status"] is True

    def test_add_duplicate_is_rejected(self, client, auth_headers):
        client.post("/api/watchers/add", json=_PAYLOAD, headers=auth_headers)
        r = client.post("/api/watchers/add", json=_PAYLOAD, headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["status"] is False


class TestWatchersDelete:
    def test_delete_existing_watcher(self, client, auth_headers):
        # Add a watcher first.
        add_r = client.post("/api/watchers/add", json=_PAYLOAD, headers=auth_headers)
        assert add_r.get_json()["status"] is True

        # Delete by index 0 (only one in list).
        r = client.delete("/api/watchers/delete/0", headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["status"] is True
