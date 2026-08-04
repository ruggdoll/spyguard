#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for the MVT/Amnesty STIX2 bundle parser."""

from app.classes.mvt import stix2_find_urls, extract_stix2_iocs


class TestStix2FindUrls:
    def test_flat_dict(self):
        data = {"stix2_url": "https://example.com/bundle.stix2"}
        assert stix2_find_urls(data) == ["https://example.com/bundle.stix2"]

    def test_nested_list(self):
        data = [{"stix2_url": "https://a.com/a.stix2"},
                {"stix2_url": "https://b.com/b.stix2"}]
        urls = stix2_find_urls(data)
        assert len(urls) == 2

    def test_non_http_ignored(self):
        data = {"stix2_url": "ftp://bad.com/file.stix2"}
        assert stix2_find_urls(data) == []

    def test_missing_key_returns_empty(self):
        data = {"other_key": "value"}
        assert stix2_find_urls(data) == []

    def test_deeply_nested(self):
        data = {"level1": {"level2": [{"stix2_url": "https://deep.com/x.stix2"}]}}
        assert stix2_find_urls(data) == ["https://deep.com/x.stix2"]


class TestExtractStix2IOCs:
    def _bundle(self, objects):
        return {"type": "bundle", "objects": objects}

    def test_domain_name_object(self):
        b = self._bundle([{"type": "domain-name", "value": "Evil.Example.Com"}])
        iocs = list(extract_stix2_iocs(b, "test"))
        assert ("domain", "evil.example.com") in iocs

    def test_ipv4_addr_object(self):
        b = self._bundle([{"type": "ipv4-addr", "value": "1.2.3.4"}])
        iocs = list(extract_stix2_iocs(b, "test"))
        assert ("ip4addr", "1.2.3.4") in iocs

    def test_ipv6_addr_object(self):
        b = self._bundle([{"type": "ipv6-addr", "value": "2001:db8::1"}])
        iocs = list(extract_stix2_iocs(b, "test"))
        assert ("ip6addr", "2001:db8::1") in iocs

    def test_url_object_yields_hostname(self):
        b = self._bundle([{"type": "url", "value": "https://c2.example.com/path?q=1"}])
        iocs = list(extract_stix2_iocs(b, "test"))
        assert ("domain", "c2.example.com") in iocs

    def test_indicator_domain_pattern(self):
        b = self._bundle([{
            "type": "indicator",
            "pattern": "[domain-name:value = 'pegasus.evil.com']",
        }])
        iocs = list(extract_stix2_iocs(b, "test"))
        assert ("domain", "pegasus.evil.com") in iocs

    def test_indicator_ip_pattern(self):
        b = self._bundle([{
            "type": "indicator",
            "pattern": "[ipv4-addr:value = '5.6.7.8']",
        }])
        iocs = list(extract_stix2_iocs(b, "test"))
        assert ("ip4addr", "5.6.7.8") in iocs

    def test_non_network_types_skipped(self):
        b = self._bundle([
            {"type": "process", "name": "evil_proc"},
            {"type": "file", "hashes": {"SHA-256": "abc"}},
            {"type": "email-addr", "value": "x@evil.com"},
            {"type": "domain-name", "value": "keep.me"},
        ])
        iocs = list(extract_stix2_iocs(b, "test"))
        assert len(iocs) == 1
        assert iocs[0] == ("domain", "keep.me")

    def test_empty_bundle(self):
        b = {"type": "bundle", "objects": []}
        assert list(extract_stix2_iocs(b, "test")) == []

    def test_missing_value_skipped(self):
        b = self._bundle([{"type": "domain-name", "value": ""}])
        assert list(extract_stix2_iocs(b, "test")) == []

    def test_trailing_dot_stripped(self):
        b = self._bundle([{"type": "domain-name", "value": "trail.dot.com."}])
        iocs = list(extract_stix2_iocs(b, "test"))
        assert ("domain", "trail.dot.com") in iocs
