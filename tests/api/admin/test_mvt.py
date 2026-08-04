#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for the MVT/Amnesty STIX2 bundle parser."""

from app.classes.mvt import stix2_find_urls, stix2_find_bundles, extract_stix2_iocs


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


class TestStix2FindBundles:
    """Tests for stix2_find_bundles() — current github format + legacy fallback."""

    _RAW = "https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"

    def _gh(self, owner="mvt-project", repo="mvt-indicators",
            branch="main", path="indicators/pegasus.stix2", name="Pegasus"):
        return {"name": name, "github": {"owner": owner, "repo": repo,
                                          "branch": branch, "path": path}}

    def test_github_format_returns_url_and_label(self):
        index = {"indicators": [self._gh()]}
        bundles = stix2_find_bundles(index)
        assert len(bundles) == 1
        url, label = bundles[0]
        expected_url = self._RAW.format(
            owner="mvt-project", repo="mvt-indicators",
            branch="main", path="indicators/pegasus.stix2")
        assert url == expected_url

    def test_label_derived_from_name(self):
        index = {"indicators": [self._gh(name="Pegasus iOS")]}
        _, label = stix2_find_bundles(index)[0]
        assert label == "mvt-pegasus_ios"

    def test_label_derived_from_path_when_no_name(self):
        entry = {"github": {"owner": "o", "repo": "r", "branch": "main",
                             "path": "indicators/candiru.stix2"}}
        index = {"indicators": [entry]}
        _, label = stix2_find_bundles(index)[0]
        assert label == "mvt-candiru"

    def test_multiple_github_entries(self):
        index = {"indicators": [
            self._gh(path="indicators/pegasus.stix2", name="Pegasus"),
            self._gh(path="indicators/predator.stix2", name="Predator"),
        ]}
        bundles = stix2_find_bundles(index)
        assert len(bundles) == 2

    def test_missing_owner_skipped(self):
        entry = {"github": {"repo": "r", "branch": "main", "path": "x.stix2"}}
        assert stix2_find_bundles({"indicators": [entry]}) == []

    def test_missing_path_skipped(self):
        entry = {"github": {"owner": "o", "repo": "r", "branch": "main"}}
        assert stix2_find_bundles({"indicators": [entry]}) == []

    def test_legacy_stix2_url_fallback(self):
        index = {"stix2_url": "https://legacy.example.com/bundle.stix2"}
        bundles = stix2_find_bundles(index)
        assert len(bundles) == 1
        url, label = bundles[0]
        assert url == "https://legacy.example.com/bundle.stix2"
        assert label == "mvt-bundle"

    def test_deduplication_github_and_legacy_same_url(self):
        raw_url = self._RAW.format(
            owner="mvt-project", repo="mvt-indicators",
            branch="main", path="indicators/pegasus.stix2")
        index = {
            "indicators": [self._gh()],
            "stix2_url": raw_url,
        }
        bundles = stix2_find_bundles(index)
        urls = [u for u, _ in bundles]
        assert urls.count(raw_url) == 1

    def test_empty_index_returns_empty(self):
        assert stix2_find_bundles({}) == []

    def test_empty_indicators_list(self):
        assert stix2_find_bundles({"indicators": []}) == []

    def test_non_dict_indicator_skipped(self):
        index = {"indicators": ["not-a-dict", 42, None]}
        assert stix2_find_bundles(index) == []

    def test_branch_defaults_to_main(self):
        entry = {"name": "X", "github": {"owner": "o", "repo": "r", "path": "x.stix2"}}
        bundles = stix2_find_bundles({"indicators": [entry]})
        url, _ = bundles[0]
        assert "/main/" in url


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
