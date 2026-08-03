"""Tests for /api/config routes.

Green  (pass now)   : GET /list (public, no auth required).
Red    (xfail now)  : mutation routes should use PATCH not GET.
                        GET /switch/<cat>/<key>         → PATCH /switch/<cat>/<key>
                        GET /edit/<cat>/<key>/<value>   → PATCH /edit/<cat>/<key>
                        GET /ioc-type/add/<tag>         → POST  /ioc-type/<tag>
                        GET /ioc-type/delete/<tag>      → DELETE /ioc-type/<tag>
"""

import pytest


class TestConfigPublicRoutes:
    def test_list_returns_config_without_password(self, client):
        r = client.get("/api/config/list")
        assert r.status_code == 200
        body = r.get_json()
        assert "analysis" in body
        assert "frontend" in body
        assert "network" in body
        # Password value must be sanitised to empty string, never the real hash
        assert body["backend"]["password"] == ""

    def test_list_contains_expected_analysis_keys(self, client):
        r = client.get("/api/config/list")
        analysis = r.get_json()["analysis"]
        assert "active" in analysis
        assert "heuristics" in analysis
        assert "iocs" in analysis
        assert "whitelist" in analysis


class TestConfigSwitchWithCorrectVerb:
    """
    PATCH /api/config/switch/<cat>/<key> is the correct verb for toggling.
    Currently xfail because the route only accepts GET.
    Will pass after task 9.
    """

    @pytest.mark.xfail(strict=False, reason="route uses GET; fix to PATCH in task 9")
    def test_switch_via_get_returns_405(self, client, auth_headers):
        """After task 9, GET /config/switch/... should be 405."""
        r = client.get("/api/config/switch/analysis/heuristics", headers=auth_headers)
        assert r.status_code == 405

    @pytest.mark.xfail(strict=False, reason="route uses GET; fix to PATCH in task 9")
    def test_switch_via_patch_toggles_value(self, client, auth_headers):
        before = client.get("/api/config/list").get_json()["analysis"]["heuristics"]
        r = client.patch("/api/config/switch/analysis/heuristics", headers=auth_headers)
        assert r.status_code == 200
        assert r.get_json()["status"] is True
        after = client.get("/api/config/list").get_json()["analysis"]["heuristics"]
        assert after != before


class TestConfigEditWithCorrectVerb:
    """
    PATCH /api/config/edit/<cat>/<key> is the correct verb for editing a value.
    Currently xfail because the route only accepts GET.
    Will pass after task 9.
    """

    @pytest.mark.xfail(strict=False, reason="route uses GET; fix to PATCH in task 9")
    def test_edit_via_get_returns_405(self, client, auth_headers):
        r = client.get("/api/config/edit/frontend/ui_zoom/120", headers=auth_headers)
        assert r.status_code == 405

    @pytest.mark.xfail(strict=False, reason="route uses GET; fix to PATCH in task 9")
    def test_edit_via_patch_updates_value(self, client, auth_headers):
        r = client.patch(
            "/api/config/edit/frontend/ui_zoom",
            json={"value": 120},
            headers=auth_headers,
        )
        assert r.status_code == 200
        assert r.get_json()["status"] is True
