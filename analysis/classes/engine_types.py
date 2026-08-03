#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, IPv6Network
from typing import Any, Callable, Iterator

from netaddr import IPAddress, IPNetwork


def _whitelist_asn_elements_to_int_set(elements: list[str]) -> set[int]:
    """ASN whitelist entries are stored as digit strings (see WhiteList.add)."""
    out: set[int] = set()
    for x in elements or []:
        s = str(x).strip()
        if not s.isdigit():
            continue
        try:
            n = int(s)
        except ValueError:
            continue
        if n >= 0:
            out.add(n)
    return out


def _iter_domain_suffixes(name: str) -> Iterator[str]:
    """Yield name and its parent suffixes, normalized.

    Example: a.b.example.com -> a.b.example.com, b.example.com, example.com, com
    """
    if not name:
        return
    n = name.strip().strip(".").lower()
    if not n:
        return
    parts = [p for p in n.split(".") if p]
    for i in range(len(parts)):
        yield ".".join(parts[i:])


def _normalize_dn(dn: str) -> str:
    """Normalize a DN string for stable matching."""
    if not dn:
        return ""
    dn = dn.strip().strip(".")
    if not dn:
        return ""
    parts: list[str] = []
    for raw in dn.split(","):
        raw = raw.strip()
        if not raw:
            continue
        if "=" in raw:
            k, v = raw.split("=", 1)
            k = k.strip().lower()
            v = v.strip().lower()
            parts.append(f"{k}={v}")
        else:
            parts.append(raw.strip().lower())
    parts.sort()
    return ",".join(parts)


@dataclass(frozen=True)
class EngineConfig:
    heuristics_analysis: bool
    iocs_analysis: bool
    whitelist_analysis: bool
    active_analysis: bool
    userlang: str
    max_ports: int
    http_default_ports: list[int]
    tls_default_ports: list[int]
    indicators_types: list[str]

    @classmethod
    def load(cls, get_cfg: Callable[[tuple[str, str]], Any]) -> "EngineConfig":
        def _as_int_list(value: Any) -> list[int]:
            if value is None:
                return []
            if isinstance(value, list):
                out: list[int] = []
                for v in value:
                    try:
                        out.append(int(v))
                    except (TypeError, ValueError):
                        continue
                return out
            return []

        heuristics = bool(get_cfg(("analysis", "heuristics")))
        iocs = bool(get_cfg(("analysis", "iocs")))
        whitelist = bool(get_cfg(("analysis", "whitelist")))
        active = bool(get_cfg(("analysis", "active")))
        userlang = str(get_cfg(("frontend", "user_lang")) or "en")
        max_ports_raw = get_cfg(("analysis", "max_ports"))
        try:
            max_ports = int(max_ports_raw)
        except (TypeError, ValueError):
            max_ports = 1024

        http_default_ports = _as_int_list(get_cfg(("analysis", "http_default_ports")))
        tls_default_ports = _as_int_list(get_cfg(("analysis", "tls_default_ports")))
        indicators_types_raw = get_cfg(("analysis", "indicators_types")) or []
        indicators_types = [str(x) for x in indicators_types_raw] if isinstance(indicators_types_raw, list) else []

        return cls(
            heuristics_analysis=heuristics,
            iocs_analysis=iocs,
            whitelist_analysis=whitelist,
            active_analysis=active,
            userlang=userlang,
            max_ports=max_ports,
            http_default_ports=http_default_ports,
            tls_default_ports=tls_default_ports,
            indicators_types=indicators_types,
        )


class WhitelistIndex:
    def __init__(self, cidrs: list[IPNetwork], hosts: list[str], domains: list[str]) -> None:
        self.cidrs = cidrs
        self.hosts = hosts
        self.domains = domains
        self._hosts_set = set(hosts or [])
        self._domains_set = set(d.strip(".").lower() for d in (domains or []) if d)

    def is_domain_whitelisted(self, dnsname: str) -> bool:
        if not dnsname or not self._domains_set:
            return False
        for suffix in _iter_domain_suffixes(dnsname):
            if suffix in self._domains_set:
                return True
        return False

    def mark_record_if_whitelisted(self, record: dict[str, Any], *, ipv6_ula: IPv6Network) -> bool:
        """Mutates record['whitelisted'] exactly like the legacy code."""
        ip_dst = record.get("ip_dst")
        if not isinstance(ip_dst, str) or not ip_dst:
            return False

        # IPv4 checks
        try:
            IPv4Address(ip_dst)
            if IPv4Address("224.0.0.0") <= IPv4Address(ip_dst) <= IPv4Address("239.255.255.255"):
                record["whitelisted"] = True
                return True

            for cidr in self.cidrs:
                if IPAddress(ip_dst) in cidr:
                    record["whitelisted"] = True
                    return True

            if ip_dst in self._hosts_set:
                record["whitelisted"] = True
                return True
        except Exception:
            pass

        # IPv6 checks
        try:
            ip6 = IPv6Address(ip_dst)
            if ip6.is_link_local or ip6.is_multicast or ip6 in ipv6_ula:
                record["whitelisted"] = True
                return True

            for cidr in self.cidrs:
                if IPAddress(ip_dst) in cidr:
                    record["whitelisted"] = True
                    return True

            if ip_dst in self._hosts_set:
                record["whitelisted"] = True
                return True
        except Exception:
            pass

        # Domain suffix checks
        domains = record.get("domains") or []
        if isinstance(domains, list):
            for domain in domains:
                if isinstance(domain, str) and self.is_domain_whitelisted(domain):
                    record["whitelisted"] = True
                    return True
        return False


class IOCIndex:
    """Pre-index IOCs for fast lookups.

    Engine keeps legacy attributes (self.bl_* and self._bl_*_map) sourced from this object.
    """

    def __init__(
        self,
        *,
        bl_cidrs: list[list[Any]],
        bl_hosts: list[list[Any]],
        bl_asns: list[list[Any]],
        tor_nodes: list[str],
        bl_domains: list[list[Any]],
        bl_freedns: list[list[Any]],
        bl_certs: list[list[Any]],
        bl_jarms: list[list[Any]],
        bl_nameservers: list[list[Any]],
        bl_tlds: list[list[Any]],
        bl_issuers: list[list[Any]],
        enabled_indicator_types: set[str],
    ) -> None:
        self.bl_cidrs = bl_cidrs
        self.bl_hosts = bl_hosts
        self.bl_asns = bl_asns
        self.tor_nodes = tor_nodes
        self.bl_domains = bl_domains
        self.bl_freedns = bl_freedns
        self.bl_certs = bl_certs
        self.bl_jarms = bl_jarms
        self.bl_nameservers = bl_nameservers
        self.bl_tlds = bl_tlds
        self.bl_issuers = bl_issuers
        self.enabled_indicator_types = enabled_indicator_types

        self.tor_nodes_set = set(self.tor_nodes or [])

        self.bl_hosts_map: dict[str, str] = {}
        for value, tag in (self.bl_hosts or []):
            self.bl_hosts_map[value] = tag

        self.bl_asns_map: dict[int, str] = {}
        for value, tag in (self.bl_asns or []):
            if value is None:
                continue
            s = str(value).strip()
            if not s:
                continue
            m = re.match(r"^(?:AS|as)?\s*(\d+)$", s)
            if not m:
                continue
            try:
                n = int(m.group(1))
            except Exception:
                continue
            if n > 0:
                self.bl_asns_map[n] = str(tag or "asn")

        def _index_iocs_as_tagmap(items: list[list[Any]] | None) -> dict[str, set[str]]:
            m: dict[str, set[str]] = {}
            for value, tag in (items or []):
                if not value:
                    continue
                key = str(value).strip(".").lower()
                m.setdefault(key, set()).add(str(tag))
            return m

        self.bl_domains_map = _index_iocs_as_tagmap(self.bl_domains)
        self.bl_freedns_map = _index_iocs_as_tagmap(self.bl_freedns)
        self.bl_tlds_map = _index_iocs_as_tagmap(self.bl_tlds)
        self.bl_nameservers_map = _index_iocs_as_tagmap(self.bl_nameservers)

        self.bl_certs_map = {value: tag for value, tag in (self.bl_certs or []) if value}
        self.bl_jarms_map = {value: tag for value, tag in (self.bl_jarms or []) if value}

        self.bl_issuers_map: dict[str, set[str]] = {}
        for value, tag in (self.bl_issuers or []):
            if not value:
                continue
            key = _normalize_dn(str(value))
            self.bl_issuers_map.setdefault(key, set()).add(str(tag))

    def indicator_type_enabled(self, tag: str) -> bool:
        return (tag in self.enabled_indicator_types) or ("all" in self.enabled_indicator_types)
