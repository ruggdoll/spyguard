#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for EngineInfraMixin (T5 — infrastructure layer separation detection)."""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "analysis", "classes"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "analysis"))

from engine_infra import EngineInfraMixin
from engine_scoring import DEFAULT_WEIGHTS


# ---------------------------------------------------------------------------
# Minimal stub that gives EngineInfraMixin the _add_signal() helper.
# ---------------------------------------------------------------------------

class _StubEngine(EngineInfraMixin):
    def __init__(self):
        self.alerts = []
        self._scoring_weights = dict(DEFAULT_WEIGHTS)

    def _add_signal(self, record, name, label=""):
        w = self._scoring_weights.get(name, 1.0)
        record.setdefault("_signals", []).append({"name": name, "weight": w, "label": label})
        record["_score"] = record.get("_score", 0.0) + w


def _record(ip="1.2.3.4", certs=None, snis=None, dns_domains=None, whitelisted=False):
    r = {
        "ip_dst": ip,
        "whitelisted": whitelisted,
        "suspicious": False,
        "domains": list(dns_domains or []),
        "_dns_domains": list(dns_domains or []),
        "_cert_snis_seen": set(snis or []),
        "certificates": certs if certs is not None else [{"version": "TLS 1.3", "port": 443}],
    }
    return r


# ---------------------------------------------------------------------------
# INFRA-01 — TLS without SNI
# ---------------------------------------------------------------------------

class TestTlsNoSni:
    def test_no_sni_emits_signal(self):
        eng = _StubEngine()
        rec = _record(snis=None)
        eng.check_infra_layers(rec)
        names = [s["name"] for s in rec.get("_signals", [])]
        assert "tls_no_sni" in names

    def test_no_sni_sets_suspicious(self):
        eng = _StubEngine()
        rec = _record(snis=None)
        eng.check_infra_layers(rec)
        assert rec["suspicious"] is True

    def test_no_sni_adds_alert_infra01(self):
        eng = _StubEngine()
        rec = _record(snis=None)
        eng.check_infra_layers(rec)
        ids = [a["id"] for a in eng.alerts]
        assert "INFRA-01" in ids

    def test_infra01_alert_level_low(self):
        eng = _StubEngine()
        rec = _record(snis=None)
        eng.check_infra_layers(rec)
        alert = next(a for a in eng.alerts if a["id"] == "INFRA-01")
        assert alert["level"] == "Low"

    def test_sni_present_no_signal(self):
        eng = _StubEngine()
        rec = _record(snis=["example.com"])
        eng.check_infra_layers(rec)
        names = [s["name"] for s in rec.get("_signals", [])]
        assert "tls_no_sni" not in names

    def test_sni_present_no_suspicious(self):
        eng = _StubEngine()
        rec = _record(snis=["example.com"], dns_domains=["example.com"])
        eng.check_infra_layers(rec)
        assert rec["suspicious"] is False

    def test_no_tls_no_signal(self):
        """Without TLS certificates, neither signal should fire."""
        eng = _StubEngine()
        rec = _record(certs=[], snis=None)
        eng.check_infra_layers(rec)
        assert rec.get("_signals") is None

    def test_whitelisted_skipped(self):
        eng = _StubEngine()
        rec = _record(whitelisted=True)
        eng.check_infra_layers(rec)
        assert rec.get("_signals") is None

    def test_tls_no_sni_weight(self):
        assert DEFAULT_WEIGHTS["tls_no_sni"] == 3.0

    def test_signal_score_added(self):
        eng = _StubEngine()
        rec = _record(snis=None, dns_domains=["example.com"])
        eng.check_infra_layers(rec)
        assert rec.get("_score", 0.0) == pytest.approx(DEFAULT_WEIGHTS["tls_no_sni"])


# ---------------------------------------------------------------------------
# INFRA-02 — Direct IP TLS without DNS
# ---------------------------------------------------------------------------

class TestDirectIpNoDns:
    def test_no_dns_emits_signal(self):
        eng = _StubEngine()
        rec = _record(snis=["example.com"], dns_domains=[])
        eng.check_infra_layers(rec)
        names = [s["name"] for s in rec.get("_signals", [])]
        assert "direct_ip_no_dns" in names

    def test_no_dns_sets_suspicious(self):
        eng = _StubEngine()
        rec = _record(snis=["example.com"], dns_domains=[])
        eng.check_infra_layers(rec)
        assert rec["suspicious"] is True

    def test_no_dns_adds_alert_infra02(self):
        eng = _StubEngine()
        rec = _record(snis=["example.com"], dns_domains=[])
        eng.check_infra_layers(rec)
        ids = [a["id"] for a in eng.alerts]
        assert "INFRA-02" in ids

    def test_infra02_alert_level_low(self):
        eng = _StubEngine()
        rec = _record(snis=["example.com"], dns_domains=[])
        eng.check_infra_layers(rec)
        alert = next(a for a in eng.alerts if a["id"] == "INFRA-02")
        assert alert["level"] == "Low"

    def test_dns_present_no_signal(self):
        eng = _StubEngine()
        rec = _record(snis=["example.com"], dns_domains=["example.com"])
        eng.check_infra_layers(rec)
        names = [s["name"] for s in rec.get("_signals", [])]
        assert "direct_ip_no_dns" not in names

    def test_direct_ip_no_dns_weight(self):
        assert DEFAULT_WEIGHTS["direct_ip_no_dns"] == 2.5

    def test_placeholder_ip_skipped(self):
        """Records with ip_dst='--' (unresolved DNS queries) are skipped."""
        eng = _StubEngine()
        rec = _record(ip="--", snis=None, dns_domains=[])
        eng.check_infra_layers(rec)
        assert rec.get("_signals") is None


# ---------------------------------------------------------------------------
# Combined signals (Pegasus C2 pattern: no SNI + no DNS + TLS)
# ---------------------------------------------------------------------------

class TestBothSignals:
    def test_both_signals_emitted(self):
        """Record with TLS but no SNI and no DNS should emit both signals."""
        eng = _StubEngine()
        rec = _record(snis=None, dns_domains=[])
        eng.check_infra_layers(rec)
        names = [s["name"] for s in rec.get("_signals", [])]
        assert "tls_no_sni" in names
        assert "direct_ip_no_dns" in names

    def test_combined_score_exceeds_moderate_threshold(self):
        """tls_no_sni (3.0) + direct_ip_no_dns (2.5) = 5.5 > 4.0 moderate threshold."""
        eng = _StubEngine()
        rec = _record(snis=None, dns_domains=[])
        eng.check_infra_layers(rec)
        score = rec.get("_score", 0.0)
        assert score == pytest.approx(3.0 + 2.5)

    def test_two_alerts_generated(self):
        eng = _StubEngine()
        rec = _record(snis=None, dns_domains=[])
        eng.check_infra_layers(rec)
        ids = {a["id"] for a in eng.alerts}
        assert "INFRA-01" in ids
        assert "INFRA-02" in ids
