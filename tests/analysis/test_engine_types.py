#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ipaddress import IPv6Network

import pytest
from netaddr import IPNetwork

from classes.engine_types import (
    IOCIndex,
    WhitelistIndex,
    _iter_domain_suffixes,
    _normalize_dn,
    _whitelist_asn_elements_to_int_set,
)


# ---------------------------------------------------------------------------
# _iter_domain_suffixes
# ---------------------------------------------------------------------------


class TestIterDomainSuffixes:
    def test_empty_string_yields_nothing(self):
        assert list(_iter_domain_suffixes("")) == []

    def test_only_dots_yields_nothing(self):
        assert list(_iter_domain_suffixes("...")) == []

    def test_single_label(self):
        assert list(_iter_domain_suffixes("com")) == ["com"]

    def test_fqdn_yields_all_suffixes(self):
        result = list(_iter_domain_suffixes("sub.example.com"))
        assert result == ["sub.example.com", "example.com", "com"]

    def test_trailing_dot_stripped(self):
        result = list(_iter_domain_suffixes("example.com."))
        assert result == ["example.com", "com"]

    def test_uppercase_normalized_to_lower(self):
        result = list(_iter_domain_suffixes("EVIL.COM"))
        assert result == ["evil.com", "com"]

    def test_deep_subdomain(self):
        result = list(_iter_domain_suffixes("a.b.c.d"))
        assert result == ["a.b.c.d", "b.c.d", "c.d", "d"]


# ---------------------------------------------------------------------------
# _normalize_dn
# ---------------------------------------------------------------------------


class TestNormalizeDN:
    def test_empty_returns_empty(self):
        assert _normalize_dn("") == ""

    def test_only_whitespace_returns_empty(self):
        assert _normalize_dn("   ") == ""

    def test_key_value_normalized(self):
        result = _normalize_dn("CN=Example, O=Org")
        assert result == "cn=example,o=org"

    def test_parts_sorted(self):
        a = _normalize_dn("O=Org, CN=Example")
        b = _normalize_dn("CN=Example, O=Org")
        assert a == b

    def test_case_insensitive(self):
        a = _normalize_dn("CN=EXAMPLE")
        b = _normalize_dn("cn=example")
        assert a == b


# ---------------------------------------------------------------------------
# _whitelist_asn_elements_to_int_set
# ---------------------------------------------------------------------------


class TestWhitelistAsnElements:
    def test_empty_list_returns_empty_set(self):
        assert _whitelist_asn_elements_to_int_set([]) == set()

    def test_digit_strings_converted_to_ints(self):
        assert _whitelist_asn_elements_to_int_set(["1234", "5678"]) == {1234, 5678}

    def test_non_digit_strings_ignored(self):
        assert _whitelist_asn_elements_to_int_set(["AS1234", "abc"]) == set()

    def test_zero_included(self):
        assert 0 in _whitelist_asn_elements_to_int_set(["0"])

    def test_mixed_values(self):
        result = _whitelist_asn_elements_to_int_set(["42", "bad", "100"])
        assert result == {42, 100}


# ---------------------------------------------------------------------------
# WhitelistIndex
# ---------------------------------------------------------------------------


class TestWhitelistIndex:
    _ipv6_ula = IPv6Network("fc00::/7")

    def _wl(self, cidrs=None, hosts=None, domains=None):
        return WhitelistIndex(
            [IPNetwork(c) for c in (cidrs or [])],
            hosts or [],
            domains or [],
        )

    def test_ip_in_cidr_is_whitelisted(self):
        wl = self._wl(cidrs=["192.168.0.0/16"])
        rec = {"ip_dst": "192.168.1.50", "domains": [], "whitelisted": False}
        assert wl.mark_record_if_whitelisted(rec, ipv6_ula=self._ipv6_ula) is True
        assert rec["whitelisted"] is True

    def test_ip_not_in_cidr_not_whitelisted(self):
        wl = self._wl(cidrs=["10.0.0.0/8"])
        rec = {"ip_dst": "8.8.8.8", "domains": [], "whitelisted": False}
        assert wl.mark_record_if_whitelisted(rec, ipv6_ula=self._ipv6_ula) is False
        assert rec["whitelisted"] is False

    def test_exact_host_is_whitelisted(self):
        wl = self._wl(hosts=["1.2.3.4"])
        rec = {"ip_dst": "1.2.3.4", "domains": [], "whitelisted": False}
        assert wl.mark_record_if_whitelisted(rec, ipv6_ula=self._ipv6_ula) is True

    def test_multicast_ip_is_whitelisted(self):
        wl = self._wl()
        rec = {"ip_dst": "224.0.0.1", "domains": [], "whitelisted": False}
        assert wl.mark_record_if_whitelisted(rec, ipv6_ula=self._ipv6_ula) is True

    def test_domain_suffix_is_whitelisted(self):
        wl = self._wl(domains=["example.com"])
        rec = {"ip_dst": "8.8.8.8", "domains": ["sub.example.com"], "whitelisted": False}
        assert wl.mark_record_if_whitelisted(rec, ipv6_ula=self._ipv6_ula) is True

    def test_unrelated_domain_not_whitelisted(self):
        wl = self._wl(domains=["safe.com"])
        rec = {"ip_dst": "8.8.8.8", "domains": ["evil.com"], "whitelisted": False}
        assert wl.mark_record_if_whitelisted(rec, ipv6_ula=self._ipv6_ula) is False

    def test_is_domain_whitelisted_suffix_match(self):
        wl = self._wl(domains=["example.com"])
        assert wl.is_domain_whitelisted("deep.sub.example.com") is True

    def test_is_domain_whitelisted_no_match(self):
        wl = self._wl(domains=["example.com"])
        assert wl.is_domain_whitelisted("evil.com") is False

    def test_ipv6_link_local_is_whitelisted(self):
        wl = self._wl()
        rec = {"ip_dst": "fe80::1", "domains": [], "whitelisted": False}
        assert wl.mark_record_if_whitelisted(rec, ipv6_ula=self._ipv6_ula) is True


# ---------------------------------------------------------------------------
# IOCIndex
# ---------------------------------------------------------------------------


def _empty_ioc_index(**overrides):
    defaults = dict(
        bl_cidrs=[],
        bl_hosts=[],
        bl_asns=[],
        tor_nodes=[],
        bl_domains=[],
        bl_freedns=[],
        bl_certs=[],
        bl_jarms=[],
        bl_nameservers=[],
        bl_tlds=[],
        bl_issuers=[],
        enabled_indicator_types=set(),
    )
    defaults.update(overrides)
    return IOCIndex(**defaults)


class TestIOCIndex:
    def test_indicator_type_enabled_with_all(self):
        idx = _empty_ioc_index(enabled_indicator_types={"all"})
        assert idx.indicator_type_enabled("stalkerware") is True
        assert idx.indicator_type_enabled("anything") is True

    def test_indicator_type_enabled_with_specific_tag(self):
        idx = _empty_ioc_index(enabled_indicator_types={"stalkerware"})
        assert idx.indicator_type_enabled("stalkerware") is True
        assert idx.indicator_type_enabled("other") is False

    def test_indicator_type_disabled_when_set_empty(self):
        idx = _empty_ioc_index(enabled_indicator_types=set())
        assert idx.indicator_type_enabled("stalkerware") is False

    def test_domains_map_indexed_by_suffix(self):
        idx = _empty_ioc_index(bl_domains=[["evil.com", "stalkerware"]])
        assert "evil.com" in idx.bl_domains_map
        assert "stalkerware" in idx.bl_domains_map["evil.com"]

    def test_hosts_map_indexed(self):
        idx = _empty_ioc_index(bl_hosts=[["1.2.3.4", "stalkerware"]])
        assert idx.bl_hosts_map.get("1.2.3.4") == "stalkerware"

    def test_asns_map_parses_numeric(self):
        idx = _empty_ioc_index(bl_asns=[["AS1234", "stalkerware"]])
        assert idx.bl_asns_map.get(1234) == "stalkerware"

    def test_asns_map_ignores_invalid(self):
        idx = _empty_ioc_index(bl_asns=[["notanasn", "tag"]])
        assert len(idx.bl_asns_map) == 0

    def test_tlds_map_indexed(self):
        idx = _empty_ioc_index(bl_tlds=[["onion", "tor"]])
        assert "onion" in idx.bl_tlds_map

    def test_tor_nodes_set_populated(self):
        idx = _empty_ioc_index(tor_nodes=["5.5.5.5", "6.6.6.6"])
        assert "5.5.5.5" in idx.tor_nodes_set
        assert "6.6.6.6" in idx.tor_nodes_set

    def test_issuers_map_normalizes_dn(self):
        idx = _empty_ioc_index(bl_issuers=[["CN=Evil CA, O=BadOrg", "stalkerware"]])
        # The key in bl_issuers_map is the normalized DN.
        assert len(idx.bl_issuers_map) == 1
