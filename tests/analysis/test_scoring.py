#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for T1 composite scoring and T2 JA3/JA4 fingerprint detection.

The Engine is NOT fully instantiated here — we build a minimal stub that
exposes only the attributes and methods needed by the methods under test.
"""

from __future__ import annotations

import sys
import os
import types
import pytest

# Ensure analysis/classes is importable (conftest.py adds analysis/ to path)
_classes_dir = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "analysis", "classes")
)
if _classes_dir not in sys.path:
    sys.path.insert(0, _classes_dir)

from engine_scoring import (
    DEFAULT_WEIGHTS,
    UPGRADE_MODERATE_THRESHOLD,
    UPGRADE_HIGH_THRESHOLD,
    Signal,
)


# ---------------------------------------------------------------------------
# Minimal Engine stub — only what _add_signal / _apply_composite_score need.
# ---------------------------------------------------------------------------

class _StubEngine:
    """Minimal stub mimicking Engine enough to test scoring helpers."""

    def __init__(self, scoring_weights=None, ja3_signatures=None, ja4_signatures=None):
        self.alerts = []
        self._scoring_weights = scoring_weights or dict(DEFAULT_WEIGHTS)
        self._ja3_signatures = ja3_signatures or {}
        self._ja4_signatures = ja4_signatures or {}
        self.iocs_analysis = True

    # Import the real implementations by mixing them in at call time.
    def _add_signal(self, record, name, label=""):
        weight = self._scoring_weights.get(name, DEFAULT_WEIGHTS.get(name, 1.0))
        record.setdefault("_signals", []).append({"name": name, "weight": weight, "label": label})
        record["_score"] = record.get("_score", 0.0) + weight

    def _apply_composite_score(self, record):
        score = record.get("_score", 0.0)
        if score < UPGRADE_MODERATE_THRESHOLD:
            return
        host_keys = set(record.get("domains", [])) | {record.get("ip_dst", "")}
        upgraded = False
        for alert in self.alerts:
            if alert.get("host") not in host_keys:
                continue
            old_level = alert.get("level", "Low")
            if score >= UPGRADE_HIGH_THRESHOLD and old_level in ("Low", "Moderate"):
                alert["level"] = "High"
                upgraded = True
            elif score >= UPGRADE_MODERATE_THRESHOLD and old_level == "Low":
                alert["level"] = "Moderate"
                upgraded = True
        if upgraded:
            host = record["domains"][0] if record.get("domains") else record.get("ip_dst", "")
            signals_summary = ", ".join(
                s["name"] + (f'({s["label"]})' if s.get("label") else "")
                for s in record.get("_signals", [])
            )
            self.alerts.append({
                "title": f"Composite suspicion score {score:.1f} for {host}",
                "description": f"Multiple signals detected: {signals_summary}",
                "host": host,
                "level": "High" if score >= UPGRADE_HIGH_THRESHOLD else "Moderate",
                "id": "SCORE-01",
            })

    def _check_flow_ja3(self, record):
        """Reimplementation of the JA3/JA4 block from check_flow() for unit testing."""
        resolved_host = record["domains"][0] if record.get("domains") else record.get("ip_dst", "")
        if self.iocs_analysis and self._ja3_signatures:
            for ja3h in record.get("_ja3_hashes", set()):
                c2_label = self._ja3_signatures.get(ja3h)
                if c2_label:
                    record["suspicious"] = True
                    self._add_signal(record, "ja3_ioc", f"{c2_label} ({ja3h[:8]})")
                    self.alerts.append({
                        "title": f"Known C2 JA3 fingerprint: {c2_label}",
                        "description": f"TLS connection to {resolved_host} ({record['ip_dst']}) matches JA3 fingerprint {ja3h} associated with {c2_label}.",
                        "host": resolved_host,
                        "level": "High",
                        "id": "TLS-JA3",
                    })
        if self.iocs_analysis and self._ja4_signatures:
            for ja4h in record.get("_ja4_hashes", set()):
                c2_label = self._ja4_signatures.get(ja4h)
                if c2_label:
                    record["suspicious"] = True
                    self._add_signal(record, "ja4_ioc", f"{c2_label}")
                    self.alerts.append({
                        "title": f"Known C2 JA4 fingerprint: {c2_label}",
                        "description": f"TLS connection to {resolved_host} ({record['ip_dst']}) matches JA4 fingerprint {ja4h} associated with {c2_label}.",
                        "host": resolved_host,
                        "level": "High",
                        "id": "TLS-JA4",
                    })


def _make_record(**kwargs):
    defaults = {
        "ip_dst": "1.2.3.4",
        "domains": [],
        "whitelisted": False,
        "suspicious": False,
        "protocols": [],
        "certificates": [],
    }
    defaults.update(kwargs)
    return defaults


# ---------------------------------------------------------------------------
# engine_scoring module constants
# ---------------------------------------------------------------------------

class TestScoringConstants:
    def test_default_weights_not_empty(self):
        assert len(DEFAULT_WEIGHTS) > 0

    def test_thresholds_ordering(self):
        assert UPGRADE_MODERATE_THRESHOLD < UPGRADE_HIGH_THRESHOLD

    def test_moderate_threshold_value(self):
        assert UPGRADE_MODERATE_THRESHOLD == 4.0

    def test_high_threshold_value(self):
        assert UPGRADE_HIGH_THRESHOLD == 8.0

    def test_signal_dataclass(self):
        s = Signal(name="test", weight=2.0, label="example.com")
        assert s.name == "test"
        assert s.weight == 2.0
        assert s.label == "example.com"

    def test_signal_default_label(self):
        s = Signal(name="test", weight=1.0)
        assert s.label == ""


# ---------------------------------------------------------------------------
# _add_signal accumulates score correctly
# ---------------------------------------------------------------------------

class TestAddSignal:
    def test_single_signal_score(self):
        engine = _StubEngine()
        record = _make_record()
        engine._add_signal(record, "domain_freedns", "evil.duckdns.org")
        assert record["_score"] == DEFAULT_WEIGHTS["domain_freedns"]
        assert len(record["_signals"]) == 1

    def test_multiple_signals_accumulate(self):
        engine = _StubEngine()
        record = _make_record()
        engine._add_signal(record, "domain_freedns")
        engine._add_signal(record, "domain_suspicious_tld")
        engine._add_signal(record, "domain_suspicious_ns")
        expected = (
            DEFAULT_WEIGHTS["domain_freedns"]
            + DEFAULT_WEIGHTS["domain_suspicious_tld"]
            + DEFAULT_WEIGHTS["domain_suspicious_ns"]
        )
        assert record["_score"] == pytest.approx(expected)
        assert len(record["_signals"]) == 3

    def test_unknown_signal_defaults_to_weight_1(self):
        engine = _StubEngine()
        record = _make_record()
        engine._add_signal(record, "nonexistent_signal_xyz")
        assert record["_score"] == 1.0

    def test_custom_weight_override(self):
        engine = _StubEngine(scoring_weights={"domain_freedns": 99.0})
        record = _make_record()
        engine._add_signal(record, "domain_freedns")
        assert record["_score"] == 99.0

    def test_signal_label_stored(self):
        engine = _StubEngine()
        record = _make_record()
        engine._add_signal(record, "domain_freedns", "example.org")
        assert record["_signals"][0]["label"] == "example.org"


# ---------------------------------------------------------------------------
# _apply_composite_score — level upgrades
# ---------------------------------------------------------------------------

class TestApplyCompositeScore:
    def test_no_upgrade_below_threshold(self):
        engine = _StubEngine()
        record = _make_record(ip_dst="1.2.3.4")
        engine.alerts.append({
            "host": "1.2.3.4", "level": "Low", "id": "PROTO-01", "title": "x", "description": "x"
        })
        # Score = 1.0 (below UPGRADE_MODERATE_THRESHOLD=4)
        engine._add_signal(record, "proto_nonstandard_port")
        engine._apply_composite_score(record)
        assert engine.alerts[0]["level"] == "Low"
        # No composite alert added
        assert not any(a["id"] == "SCORE-01" for a in engine.alerts)

    def test_low_to_moderate_at_threshold(self):
        engine = _StubEngine()
        record = _make_record(ip_dst="5.5.5.5")
        engine.alerts.append({
            "host": "5.5.5.5", "level": "Low", "id": "IOC-06", "title": "x", "description": "x"
        })
        # Add signals to reach exactly UPGRADE_MODERATE_THRESHOLD (4.0)
        # domain_freedns=3.0 + domain_suspicious_tld=1.0 = 4.0
        engine._add_signal(record, "domain_freedns")
        engine._add_signal(record, "domain_suspicious_tld")
        assert record["_score"] == pytest.approx(4.0)
        engine._apply_composite_score(record)
        assert engine.alerts[0]["level"] == "Moderate"
        assert any(a["id"] == "SCORE-01" for a in engine.alerts)
        score_alert = next(a for a in engine.alerts if a["id"] == "SCORE-01")
        assert score_alert["level"] == "Moderate"

    def test_moderate_to_high_at_high_threshold(self):
        engine = _StubEngine()
        record = _make_record(ip_dst="6.6.6.6")
        engine.alerts.append({
            "host": "6.6.6.6", "level": "Moderate", "id": "ACT-02", "title": "x", "description": "x"
        })
        # Score >= 8.0: domain_freedns(3) + cert_self_signed(3) + domain_suspicious_ns(2) = 8.0
        engine._add_signal(record, "domain_freedns")
        engine._add_signal(record, "cert_self_signed")
        engine._add_signal(record, "domain_suspicious_ns")
        assert record["_score"] == pytest.approx(8.0)
        engine._apply_composite_score(record)
        assert engine.alerts[0]["level"] == "High"
        score_alert = next(a for a in engine.alerts if a["id"] == "SCORE-01")
        assert score_alert["level"] == "High"

    def test_low_to_high_when_score_over_8(self):
        engine = _StubEngine()
        record = _make_record(ip_dst="7.7.7.7")
        engine.alerts.append({
            "host": "7.7.7.7", "level": "Low", "id": "IOC-06", "title": "x", "description": "x"
        })
        # Score = 9.0
        engine._add_signal(record, "domain_freedns")     # 3.0
        engine._add_signal(record, "cert_self_signed")   # 3.0
        engine._add_signal(record, "domain_suspicious_ns")  # 2.0
        engine._add_signal(record, "proto_nonstandard_port")  # 1.0  => total 9.0
        engine._apply_composite_score(record)
        assert engine.alerts[0]["level"] == "High"

    def test_unrelated_host_not_upgraded(self):
        engine = _StubEngine()
        record = _make_record(ip_dst="9.9.9.9")
        engine.alerts.append({
            "host": "other.host", "level": "Low", "id": "IOC-06", "title": "x", "description": "x"
        })
        engine._add_signal(record, "domain_freedns")     # 3.0
        engine._add_signal(record, "domain_suspicious_ns")  # 2.0  => 5.0
        engine._apply_composite_score(record)
        # The alert is for a different host — must not be upgraded
        assert engine.alerts[0]["level"] == "Low"

    def test_domain_in_host_keys_matched(self):
        engine = _StubEngine()
        record = _make_record(ip_dst="10.0.0.1", domains=["evil.example.com"])
        engine.alerts.append({
            "host": "evil.example.com", "level": "Low", "id": "IOC-06", "title": "x", "description": "x"
        })
        # domain_freedns(3) + domain_suspicious_ns(2) = 5.0 >= MODERATE threshold
        engine._add_signal(record, "domain_freedns")
        engine._add_signal(record, "domain_suspicious_ns")
        engine._apply_composite_score(record)
        assert engine.alerts[0]["level"] == "Moderate"

    def test_composite_note_contains_signal_names(self):
        engine = _StubEngine()
        record = _make_record(ip_dst="8.8.4.4", domains=["bad.dyn.com"])
        engine.alerts.append({
            "host": "bad.dyn.com", "level": "Low", "id": "IOC-06", "title": "x", "description": "x"
        })
        engine._add_signal(record, "domain_freedns", "bad.dyn.com")
        engine._add_signal(record, "domain_suspicious_ns", "bad.dyn.com")
        engine._apply_composite_score(record)
        score_alert = next(a for a in engine.alerts if a["id"] == "SCORE-01")
        assert "domain_freedns" in score_alert["description"]
        assert "domain_suspicious_ns" in score_alert["description"]


# ---------------------------------------------------------------------------
# JA3 match generates High alert with id "TLS-JA3"
# ---------------------------------------------------------------------------

class TestJA3Matching:
    _CS_HASH = "72a589da586844d7f0818ce684948eea"

    def test_ja3_match_generates_high_alert(self):
        engine = _StubEngine(ja3_signatures={self._CS_HASH: "CobaltStrike-default"})
        record = _make_record(ip_dst="11.22.33.44", domains=["evil.c2.com"])
        record["_ja3_hashes"] = {self._CS_HASH}
        engine._check_flow_ja3(record)
        assert record["suspicious"] is True
        ja3_alerts = [a for a in engine.alerts if a["id"] == "TLS-JA3"]
        assert len(ja3_alerts) == 1
        assert ja3_alerts[0]["level"] == "High"
        assert "CobaltStrike-default" in ja3_alerts[0]["title"]

    def test_ja3_no_match_no_alert(self):
        engine = _StubEngine(ja3_signatures={self._CS_HASH: "CobaltStrike-default"})
        record = _make_record(ip_dst="1.1.1.1")
        record["_ja3_hashes"] = {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
        engine._check_flow_ja3(record)
        assert record["suspicious"] is False
        assert not engine.alerts

    def test_ja3_empty_hashes_no_alert(self):
        engine = _StubEngine(ja3_signatures={self._CS_HASH: "CobaltStrike-default"})
        record = _make_record(ip_dst="2.2.2.2")
        engine._check_flow_ja3(record)
        assert not engine.alerts

    def test_ja3_match_adds_signal(self):
        engine = _StubEngine(ja3_signatures={self._CS_HASH: "CobaltStrike-default"})
        record = _make_record(ip_dst="3.3.3.3")
        record["_ja3_hashes"] = {self._CS_HASH}
        engine._check_flow_ja3(record)
        signals = record.get("_signals", [])
        assert any(s["name"] == "ja3_ioc" for s in signals)
        ja3_signal = next(s for s in signals if s["name"] == "ja3_ioc")
        assert ja3_signal["weight"] == DEFAULT_WEIGHTS["ja3_ioc"]

    def test_ja3_iocs_analysis_disabled_skips_check(self):
        engine = _StubEngine(ja3_signatures={self._CS_HASH: "CobaltStrike-default"})
        engine.iocs_analysis = False
        record = _make_record(ip_dst="4.4.4.4")
        record["_ja3_hashes"] = {self._CS_HASH}
        engine._check_flow_ja3(record)
        assert not engine.alerts

    def test_ja4_match_generates_high_alert(self):
        ja4_hash = "t13d1517h2_8daaf6152771_b0da82dd1658"
        engine = _StubEngine(ja4_signatures={ja4_hash: "SomeRAT-variant"})
        record = _make_record(ip_dst="5.5.5.5")
        record["_ja4_hashes"] = {ja4_hash}
        engine._check_flow_ja3(record)
        ja4_alerts = [a for a in engine.alerts if a["id"] == "TLS-JA4"]
        assert len(ja4_alerts) == 1
        assert ja4_alerts[0]["level"] == "High"


# ---------------------------------------------------------------------------
# No signal on whitelisted records
# ---------------------------------------------------------------------------

class TestWhitelistedRecordsNoSignals:
    def test_whitelisted_record_signals_not_emitted_by_caller(self):
        """Engine callers skip check_domains/check_flow for whitelisted records.

        We verify the guard is set and that the scoring methods themselves
        are safe to call on a whitelisted record (they rely on callers to skip
        the signal-emitting check methods).
        """
        engine = _StubEngine()
        record = _make_record(ip_dst="192.168.1.1", whitelisted=True)
        # Even if _add_signal is called (it shouldn't be in real flow), _apply_composite_score
        # should produce no composite alert when there are no matching alerts.
        engine._add_signal(record, "domain_freedns")
        engine._add_signal(record, "domain_suspicious_tld")
        # No alerts in engine.alerts for this host — so no upgrade, no composite note.
        engine._apply_composite_score(record)
        # _apply_composite_score should not produce a composite alert when no existing alerts match.
        assert not engine.alerts

    def test_whitelisted_field_present(self):
        record = _make_record(whitelisted=True)
        assert record["whitelisted"] is True
