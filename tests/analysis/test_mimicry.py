#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for T6 — domain mimicry heuristic."""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "analysis", "classes"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "analysis"))

from engine_dns import _mimicry_match, _MEDIA_KEYWORDS, _GEO_TERMS
from engine_scoring import DEFAULT_WEIGHTS


# ---------------------------------------------------------------------------
# _mimicry_match — unit tests
# ---------------------------------------------------------------------------

class TestMimicryMatch:

    # --- Should match (real Predator/Pegasus-style patterns) ---

    def test_kazakh_times(self):
        matched, media, geo = _mimicry_match("kazakhtimes.com")
        assert matched is True
        assert media == "times"
        assert geo == "kazakh"

    def test_africa_news(self):
        matched, media, geo = _mimicry_match("africanews.net")
        assert matched is True
        assert media == "news"
        assert geo in ("african", "africa")

    def test_press_saudi(self):
        matched, media, geo = _mimicry_match("presssaudi.io")
        assert matched is True
        assert media == "press"
        assert geo == "saudi"

    def test_malagasy_herald(self):
        matched, media, geo = _mimicry_match("malagasyherald.org")
        assert matched is True
        assert geo == "malagasy"
        assert media == "herald"

    def test_iran_daily(self):
        matched, media, geo = _mimicry_match("irandaily.com")
        assert matched is True

    def test_gulf_media(self):
        matched, media, geo = _mimicry_match("gulfmedia.net")
        assert matched is True
        assert geo == "gulf"
        assert media == "media"

    def test_subdomain_stripped(self):
        """www. prefix should not prevent matching."""
        matched, _, _ = _mimicry_match("www.kazakhtimes.com")
        assert matched is True

    def test_subdomain_not_sld(self):
        """Mimicry on sub.kazakhtimes.com should still match (SLD is kazakhtimes.com)."""
        matched, _, _ = _mimicry_match("updates.kazakhtimes.com")
        assert matched is True

    def test_uae_news(self):
        matched, media, geo = _mimicry_match("uaenews.info")
        assert matched is True
        assert geo == "uae"

    def test_actualite_africaine(self):
        matched, _, _ = _mimicry_match("actualiteafricaine.com")
        assert matched is True

    # --- Should NOT match ---

    def test_google_does_not_match(self):
        matched, _, _ = _mimicry_match("google.com")
        assert matched is False

    def test_bbc_does_not_match(self):
        """'bbc' has no explicit geo term."""
        matched, _, _ = _mimicry_match("bbc.co.uk")
        assert matched is False

    def test_media_only_no_geo(self):
        """Only a media keyword, no geo term."""
        matched, _, _ = _mimicry_match("dailynews.com")
        assert matched is False

    def test_geo_only_no_media(self):
        """Only a geo term, no media keyword."""
        matched, _, _ = _mimicry_match("kazakh.org")
        assert matched is False

    def test_empty_domain(self):
        matched, _, _ = _mimicry_match("")
        assert matched is False

    def test_legitimate_al_jazeera_style(self):
        """aljazeera.com — 'arab' not in label 'aljazeera'."""
        matched, _, _ = _mimicry_match("aljazeera.com")
        assert matched is False


# ---------------------------------------------------------------------------
# Weight constant
# ---------------------------------------------------------------------------

class TestMimicryWeight:
    def test_weight_defined(self):
        assert "domain_mimicry" in DEFAULT_WEIGHTS

    def test_weight_value(self):
        assert DEFAULT_WEIGHTS["domain_mimicry"] == 3.0

    def test_combined_with_recent_6mo_exceeds_moderate(self):
        """domain_mimicry (3.0) + domain_recent_6mo (2.0) = 5.0 > 4.0."""
        combined = DEFAULT_WEIGHTS["domain_mimicry"] + DEFAULT_WEIGHTS["domain_recent_6mo"]
        assert combined > 4.0

    def test_alone_below_moderate(self):
        """domain_mimicry alone (3.0) should not trigger moderate threshold (4.0)."""
        assert DEFAULT_WEIGHTS["domain_mimicry"] < 4.0


# ---------------------------------------------------------------------------
# Keyword list completeness sanity checks
# ---------------------------------------------------------------------------

class TestKeywordLists:
    def test_common_media_keywords_present(self):
        for kw in ("news", "press", "times", "daily", "herald", "media", "tribune"):
            assert kw in _MEDIA_KEYWORDS, f"Missing media keyword: {kw}"

    def test_common_geo_terms_present(self):
        for geo in ("kazakh", "iranian", "egyptian", "african", "malagasy", "uae"):
            assert geo in _GEO_TERMS, f"Missing geo term: {geo}"
