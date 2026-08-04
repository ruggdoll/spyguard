#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from ipaddress import ip_address
from typing import Optional

import pydig
import requests
import whois
from publicsuffix2 import get_sld

UMBRELLA_JSON_PATH = "/usr/share/spyguard/assets/umbrella-top-1m.json"
UMBRELLA_TOP500K = 500_000
IPTHC_LOOKUP_URL = "https://ip.thc.org/api/v1/lookup"
WHOIS_RECENT_REGISTRATION_MAX_DAYS = 548

# ---------------------------------------------------------------------------
# T6 — Domain mimicry heuristic
# Detects fake news/media domains with geo branding, a recurring Predator/
# Intellexa pattern (e.g. domains imitating Kazakh/Malagasy local press).
# ---------------------------------------------------------------------------

_MEDIA_KEYWORDS: frozenset = frozenset({
    "news", "press", "times", "daily", "weekly", "post",
    "herald", "gazette", "tribune", "journal", "monitor",
    "media", "radio", "channel", "broadcast", "wire",
    "report", "update", "actualite", "actualites",
})

# Geo identifiers commonly used in mercenary spyware C2/infection domain names
# (based on public Amnesty / Citizen Lab / Sekoia campaign reporting).
_GEO_TERMS: frozenset = frozenset({
    # Regions
    "africa", "african", "asia", "asian", "europe", "european",
    "mideast", "mena", "gulf", "maghreb", "caucasus", "latam",
    # Countries / adjectives seen in documented campaigns
    "kazakh", "afghan", "arab", "arabic", "iraqi", "saudi",
    "yemeni", "sudanese", "libyan", "moroccan", "algerian",
    "tunisian", "egyptian", "emirati", "bahraini", "jordanian",
    "lebanese", "syrian", "iran", "iranian", "turkish", "india", "indian",
    "pakistan", "ugandan", "kenyan", "ethiopian", "ghana", "nigerian",
    "cambodian", "thai", "myanmar", "uzbek", "georgian", "ukrainian",
    "russian", "spanish", "greek", "serbian", "indonesia", "malagasy",
    "madagascar", "ivory", "senegal", "rwanda",
    # Common abbreviated forms
    "uae", "gcc", "ksa",
})


def _mimicry_match(dnsname: str) -> tuple:
    """Return (matched: bool, media_kw: str, geo_term: str) for a domain name.

    Checks whether the SLD label (everything before the TLD, lowercased) contains
    both a media/news keyword and a geographic identifier.

    Example matches: kazakhtimes.com, pressafrica.net, africannews.io
    """
    try:
        from publicsuffix2 import get_sld as _get_sld
        sld = str(_get_sld(dnsname) or dnsname)
    except Exception:
        sld = str(dnsname)

    # Work on the label before the TLD (e.g. "kazakhtimes" from "kazakhtimes.com").
    parts = sld.lower().rstrip(".").rsplit(".", 1)
    label = parts[0] if len(parts) > 1 else sld.lower().rstrip(".")
    # Strip common subdomains that may have leaked through (www, m).
    label = re.sub(r"^(www\d?|m|mobile)\.", "", label)

    # Prefer longer matches to avoid "africa" masking "african".
    found_media = next((kw for kw in sorted(_MEDIA_KEYWORDS, key=len, reverse=True) if kw in label), None)
    found_geo = next((geo for geo in sorted(_GEO_TERMS, key=len, reverse=True) if geo in label), None)
    matched = bool(found_media and found_geo)
    return (matched, found_media or "", found_geo or "")


class EngineDNSMixin:

    def _iter_record_hostnames(self, record: dict):
        """DNS names, TLS SNI, and HTTP hostnames seen for this destination."""
        for d in record.get("domains") or []:
            if isinstance(d, str) and d.strip():
                yield d
        for c in record.get("certificates") or []:
            sni = c.get("sni")
            if isinstance(sni, str) and sni.strip():
                yield sni
        for h in record.get("http") or []:
            if isinstance(h, dict):
                hn = h.get("hostname")
                if isinstance(hn, str) and hn.strip():
                    yield hn

    def _merge_observed_hostnames_into_domains(self, record: dict) -> None:
        """Copy TLS SNI and HTTP hostnames into record['domains'] for reporting.

        Suricata stores these separately; the UI only lists record['domains']. Whitelisted
        flows skip check_tls/check_http, so without this merge the Domain column stays empty
        even when SNI/Host was observed in the capture.

        If _dns_domains is non-empty (names from captured DNS A/AAAA answers), those take
        precedence: we do not add SNI/Host so certificate placeholders (e.g. invalid2.invalid)
        do not mask real resolver data.
        """
        doms = record.get("domains")
        if not isinstance(doms, list):
            return
        dns_only = record.get("_dns_domains")
        if isinstance(dns_only, list) and len(dns_only) > 0:
            return

        seen = {d.strip().lower().rstrip(".") for d in doms if isinstance(d, str) and d.strip()}

        def _append(name: str) -> None:
            raw = name.strip()
            if not raw:
                return
            try:
                ip_address(raw)
                return
            except ValueError:
                pass
            if self._normalize_cert_hostname_candidate(raw) is None:
                return
            k = raw.lower().rstrip(".")
            if not k or k in seen:
                return
            doms.append(raw)
            seen.add(k)

        for c in record.get("certificates") or []:
            if not isinstance(c, dict):
                continue
            sni = c.get("sni")
            if isinstance(sni, str):
                _append(sni)

        for h in record.get("http") or []:
            if not isinstance(h, dict):
                continue
            hn = h.get("hostname")
            if isinstance(hn, str):
                _append(hn)

    def _iter_domains_for_enrichment(self) -> set[str]:
        """Unique apex domains to enrich (NS + WHOIS), from DNS/SNI/HTTP hostnames."""
        out: set[str] = set()
        for record in (self.records or []):
            if record.get("whitelisted"):
                continue
            for h in self._iter_record_hostnames(record):
                if not isinstance(h, str) or not h.strip():
                    continue
                hn = h.strip().lower().rstrip(".")
                if not hn or hn == "--":
                    continue
                # Skip IP literals.
                try:
                    ip_address(hn)
                    continue
                except ValueError:
                    pass
                try:
                    d = get_sld(hn) or hn
                except Exception:
                    d = hn
                d = str(d).strip().lower().rstrip(".")
                if d:
                    out.add(d)
        return out

    def _prefetch_domain_enrichments(self) -> None:
        """Run DNS NS + WHOIS for all unique domains, in parallel with bounded workers."""
        domains = sorted(self._iter_domains_for_enrichment())
        if not domains:
            return

        def do_ns(domain: str) -> None:
            with self._domain_enrich_lock:
                if domain in self._domain_ns_cache or domain in self._domain_ns_err:
                    return
            try:
                ok_ns, name_servers, err_ns = self._call_with_timeout(
                    lambda: pydig.query(domain, "NS"), 5
                )
                if not ok_ns:
                    raise RuntimeError(err_ns or "timeout")
                ns = [str(x).strip().strip(".") for x in (name_servers or []) if str(x).strip()]
                with self._domain_enrich_lock:
                    self._domain_ns_cache[domain] = ns
                self._health_event("dns_ns", True, "" if ns else "empty")
            except Exception as e:
                with self._domain_enrich_lock:
                    self._domain_ns_err[domain] = str(e)
                self._health_event("dns_ns", False, str(e))

        def do_whois(domain: str) -> None:
            with self._domain_enrich_lock:
                if domain in self._domain_whois_creation_cache or domain in self._domain_whois_err:
                    return
            try:
                ok_w, whois_record, err_w = self._call_with_timeout(lambda: whois.whois(domain), 14)
                if not ok_w:
                    raise RuntimeError(err_w or "timeout")
                cd = None
                try:
                    cd = whois_record.creation_date
                    cd = cd if type(cd) is not list else cd[0]
                except Exception:
                    cd = None
                with self._domain_enrich_lock:
                    self._domain_whois_creation_cache[domain] = cd
                # Consider the WHOIS request successful even if creation date is missing/redacted.
                self._health_event("whois", True, "" if cd is not None else "no_creation_date")
            except Exception as e:
                with self._domain_enrich_lock:
                    self._domain_whois_err[domain] = str(e)
                self._health_event("whois", False, str(e))

        workers = min(self._enrich_workers, max(1, len(domains)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            # Launch both enrichments per domain; still bounded by pool size.
            futs = []
            for d in domains:
                futs.append(pool.submit(do_ns, d))
                futs.append(pool.submit(do_whois, d))
            # Ensure completion (best-effort); we don't want to hang forever.
            for fut in as_completed(futs, timeout=max(20, 2 * len(domains))):
                try:
                    fut.result()
                except Exception:
                    pass

    def _prefetch_asn_lookups(self) -> None:
        """Resolve each unique destination IP once into _asn_ip_cache (local ip2asn table)."""
        if not self._ip2asn_table:
            return
        seen: set[str] = set()
        for record in self.records or []:
            if record.get("whitelisted"):
                continue
            ip = record.get("ip_dst")
            if not isinstance(ip, str) or not ip.strip():
                continue
            ip = ip.strip()
            if ip in seen:
                continue
            seen.add(ip)
            self._resolve_asn_for_ip(ip)

    def _resolve_asn_for_ip(self, ip: str) -> tuple[Optional[int], str]:
        """IPv4 ASN from local ip2asn TSV (iptoasn.com). IPv6: (None, '')."""
        if not ip or not isinstance(ip, str):
            return (None, "")
        ip = ip.strip()
        if not ip or ip == "--":
            return (None, "")
        if ip in self._asn_ip_cache:
            return self._asn_ip_cache[ip]
        if not self._ip2asn_table:
            self._asn_ip_cache[ip] = (None, "")
            return (None, "")
        r = self._ip2asn_table.lookup_ip_string(ip)
        self._asn_ip_cache[ip] = r
        return r

    def _ensure_umbrella_top500k_loaded(self) -> None:
        """Single read of Umbrella JSON; fills both set and rank map (or empty on failure)."""
        if self._umbrella_top500k_set is not None:
            return
        self._umbrella_top500k_set = set()
        self._umbrella_top500k_rank_map = {}
        try:
            with open(UMBRELLA_JSON_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            domains = (data.get("domains") or [])[:UMBRELLA_TOP500K]
            for i, d in enumerate(domains, start=1):
                if not d:
                    continue
                key = str(d).strip().lower().rstrip(".")
                if not key:
                    continue
                self._umbrella_top500k_set.add(key)
                if key not in self._umbrella_top500k_rank_map:
                    self._umbrella_top500k_rank_map[key] = i
            self._health_event("umbrella", True, "")
        except FileNotFoundError:
            self._health_event("umbrella", False, "file_missing")
            self.errors.append(
                "Cisco Umbrella popularity list missing at {}; run watchers.py to download it.".format(
                    UMBRELLA_JSON_PATH
                )
            )
        except Exception as e:
            self._health_event("umbrella", False, str(e))
            self.errors.append("Could not load Umbrella popularity list: {}".format(str(e)))

    def _load_umbrella_top500k_set(self) -> set[str]:
        """Load first 500K FQDNs from Cisco Umbrella JSON (written by watchers.py)."""
        from typing import cast
        self._ensure_umbrella_top500k_loaded()
        return cast(set[str], self._umbrella_top500k_set)

    def _load_umbrella_top500k_rank_map(self) -> dict[str, int]:
        """Load first 500K FQDNs and map each to its 1-based rank."""
        from typing import cast
        self._ensure_umbrella_top500k_loaded()
        return cast(dict[str, int], self._umbrella_top500k_rank_map)

    def _attach_umbrella_ranks_to_records(self) -> None:
        """Attach Umbrella Top 500K rank per domain for display purposes."""
        ranks = self._load_umbrella_top500k_rank_map()
        if not ranks:
            return
        for record in self.records:
            doms = record.get("domains") or []
            if not isinstance(doms, list) or not doms:
                continue
            out = {}
            for d in doms:
                if not isinstance(d, str):
                    continue
                k = d.strip().lower().rstrip(".")
                if not k:
                    continue
                r = ranks.get(k)
                if r:
                    out[d] = int(r)
            if out:
                record["domains_umbrella_rank"] = out

    def _check_umbrella_popularity(self):
        """Alert (moderate) if a non-whitelisted flow's domain is absent from Umbrella top 500K."""
        umbrella = self._load_umbrella_top500k_set()
        if not umbrella:
            return
        if "UMBRELLA-01" not in self.template:
            return
        seen = set()
        for record in self.records:
            if record.get("whitelisted"):
                continue
            for domain in self._iter_record_hostnames(record):
                if not domain or not isinstance(domain, str):
                    continue
                d = domain.strip().lower().rstrip(".")
                if not d or d == "--":
                    continue
                try:
                    ip_address(d)
                    continue
                except ValueError:
                    pass
                if self._is_domain_whitelisted(domain):
                    continue
                candidates = {d}
                try:
                    sld = get_sld(d)
                    if sld:
                        candidates.add(str(sld).strip().lower().rstrip("."))
                except Exception:
                    pass
                try:
                    canon = get_sld(d) or d
                    canon = str(canon).strip().lower().rstrip(".")
                except Exception:
                    canon = d
                if canon in seen:
                    continue
                if candidates & umbrella:
                    continue
                seen.add(canon)
                self.alerts.append(
                    {
                        "title": self.template["UMBRELLA-01"]["title"].format(domain),
                        "description": self.template["UMBRELLA-01"]["description"].format(domain),
                        "host": domain,
                        "level": "Moderate",
                        "id": "UMBRELLA-01",
                    }
                )

    def _ipthc_first_domain(self, ip: str) -> tuple[Optional[str], int]:
        """Best-effort passive DNS lookup for an IP address using ip.thc.org.

        Returns (first_domain, matching_records_count). Both are cached per IP for the analysis run.
        """
        if not ip or not isinstance(ip, str):
            return (None, 0)
        if ip in self._ipthc_cache:
            return self._ipthc_cache[ip]

        # Only try for IP literals (skip "--" and hostnames).
        try:
            ip_address(ip)
        except ValueError:
            self._ipthc_cache[ip] = (None, 0)
            return (None, 0)

        payload = {
            "ip_address": ip,
            "tld": [],
            "apex_domain": "",
            "page_state": "",
            "limit": 10,
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        try:
            r = requests.post(IPTHC_LOOKUP_URL, headers=headers, json=payload, timeout=5)
            if r.status_code != 200:
                self._health_event("ipthc", False, f"http_{r.status_code}")
                self._ipthc_cache[ip] = (None, 0)
                return (None, 0)
            data = r.json()
            self._health_event("ipthc", True, "")
            domains = data.get("domains") or []
            first = None
            if isinstance(domains, list) and domains:
                d0 = domains[0]
                if isinstance(d0, dict):
                    first = d0.get("domain") or d0.get("apex_domain")
            matching = int(data.get("matching_records") or (len(domains) if isinstance(domains, list) else 0))
            if isinstance(first, str):
                first = first.strip().strip(".").lower()
            if not first:
                first = None
            res = (first, matching)
            self._ipthc_cache[ip] = res
            return res
        except Exception:
            self._health_event("ipthc", False, "exception")
            self._ipthc_cache[ip] = (None, 0)
            return (None, 0)

    def check_domains(self, record):
        """Check the domains associated to each record.
           First this method checks if the record is whitelisted. If not:
              1. Leverage a low alert if the record don't have any associated DNSName
              2. Check each domain associated to the record by calling check_dnsname.
        Args:
            record (dict): record to be processed.
        """
        # Populate record['domains'] for the report (SNI, HTTP Host), including whitelisted flows.
        self._merge_observed_hostnames_into_domains(record)

        # TLS 1.3 / no cleartext cert in EVE: hostname from cache — only if no DNS names for this IP.
        dns_only = record.get("_dns_domains")
        has_dns = isinstance(dns_only, list) and len(dns_only) > 0
        if (
            not has_dns
            and self.heuristics_analysis
            and record["domains"] == []
            and self.active_analysis
            and self.connected
            and self._record_observed_dest_port(record, 443)
        ):
            ip_dst = (record.get("ip_dst") or "").strip()
            if ip_dst and not self._should_skip_active_tls_probe_to_ip(ip_dst):
                cert_name = self._get_tls_cert_hostname_for_ip(ip_dst, 443)
                if (
                    cert_name
                    and cert_name not in record["domains"]
                    and self._normalize_cert_hostname_candidate(cert_name) is not None
                ):
                    record["domains"].append(cert_name)

        if record["whitelisted"]:
            return

        if self.heuristics_analysis:
            # Otherwise, we alert the user that an IP haven't been resolved by
            # a DNS answer during the session...
            if record["domains"] == []:
                record["suspicious"] = True
                ip_dst = record.get("ip_dst", "")
                title = self.template["PROTO-05"]["title"].format(ip_dst)
                description = self.template["PROTO-05"]["description"].format(ip_dst)
                # Best-effort: attach observed service (port/proto) from flows.
                # This is derived from Suricata EVE flow metadata, not DNS.
                alert_proto = None
                alert_port = None
                try:
                    protocols = record.get("protocols") or []
                    for p in protocols:
                        if not isinstance(p, dict):
                            continue
                        name = p.get("name")
                        port = p.get("port")
                        if not name:
                            continue
                        try:
                            port_i = int(port)
                        except Exception:
                            continue
                        if port_i > 0:
                            alert_proto = str(name).strip().upper()
                            alert_port = port_i
                            break
                except Exception:
                    pass

                # Optional enrichment only (do not add to record["domains"]): passive DNS can
                # list many unrelated names for shared IPs (e.g. CDNs) and must not look like
                # a DNS query observed during capture.
                if self.active_analysis and self.connected:
                    domain, matching_records = self._ipthc_first_domain(ip_dst)
                    if domain:
                        title_t = self.template["PROTO-05"].get("title_pdns")
                        desc_t = self.template["PROTO-05"].get("description_pdns")
                        desc_single_t = self.template["PROTO-05"].get("description_pdns_single")
                        other = max(int(matching_records) - 1, 0)

                        if isinstance(title_t, str) and title_t:
                            title = title_t.format(ip_dst, domain)
                        else:
                            title = f"{title} ({domain})"

                        if other == 0 and isinstance(desc_single_t, str) and desc_single_t:
                            description = desc_single_t.format(ip_dst, domain)
                        elif isinstance(desc_t, str) and desc_t:
                            description = desc_t.format(ip_dst, domain, other)

                        umbrella_note = self.template["PROTO-05"].get("umbrella_top500k_note")
                        if isinstance(umbrella_note, str) and umbrella_note:
                            umbrella = self._load_umbrella_top500k_set()
                            d_norm = str(domain).strip().lower().rstrip(".")
                            present = False
                            if umbrella and d_norm:
                                if d_norm in umbrella:
                                    present = True
                                else:
                                    try:
                                        sld = get_sld(d_norm)
                                        if sld and str(sld).strip().lower().rstrip(".") in umbrella:
                                            present = True
                                    except Exception:
                                        pass
                            if present:
                                description = f"{description} {umbrella_note}"
                    else:
                        no_pdns_note = self.template["PROTO-05"].get("description_pdns_none")
                        if isinstance(no_pdns_note, str) and no_pdns_note:
                            description = f"{description} {no_pdns_note}".strip()
                        else:
                            description = (
                                f"{description} Passive DNS (ip.thc.org) did not return any associated domain for this IP address.".strip()
                            )

                self.alerts.append(
                    {
                        "title": title,
                        "description": description,
                        "host": ip_dst,
                        "proto": alert_proto,
                        "port": alert_port,
                        "level": "Low",
                        "id": "PROTO-05",
                    }
                )

        # Check each associated domain.
        for domain in record["domains"]:
            if self.check_dnsname(domain, record=record):
                record["suspicious"] = True

    def check_dnsname(self, dnsname, record=None):
        """Check a domain name against a set of IOCs / heuristics.
              1. Check if the parent domain is blacklisted.
              2. Check if the parent domain is a Free DNS.
              3. Check if the domain extension is a suspicious TLD.
              4. Check if the name servers associated to the domain are suspicious.
              5. Check if the domain have been registered recently - less than one year.
        Args:
            dnsname (str): domain name to check.
            record (dict, optional): flow record to emit signals onto.
        Returns:
            suspicious (bool) : if an alert has been leveraged.
        """
        suspicious = False

        if self.iocs_analysis:
            # Domain & FreeDNS IOCs: match by walking suffixes once.
            for suffix in self._iter_domain_suffixes(dnsname):
                tags = self._bl_domains_map.get(suffix)
                if tags:
                    for tag in tags:
                        if not self._indicator_type_enabled(tag):
                            continue
                        if tag == "dual":
                            suspicious = True
                            self.alerts.append(
                                {
                                    "title": self.template["IOC-12"]["title"],
                                    "description": self.template["IOC-12"]["description"].format(suffix),
                                    "host": suffix,
                                    "level": "Low",
                                    "id": "IOC-12",
                                }
                            )
                        elif tag == "tracker":
                            suspicious = True
                            self.alerts.append(
                                {
                                    "title": self.template["IOC-04"]["title"].format(suffix, "tracker"),
                                    "description": self.template["IOC-04"]["description"].format(suffix, "tracker"),
                                    "host": suffix,
                                    "level": "Low",
                                    "id": "IOC-04",
                                }
                            )
                        elif tag == "doh":
                            suspicious = True
                            self.alerts.append(
                                {
                                    "title": self.template["IOC-13"]["title"].format(f"{dnsname}"),
                                    "description": self.template["IOC-13"]["description"].format(f"{dnsname}"),
                                    "host": dnsname,
                                    "level": "Low",
                                    "id": "IOC-13",
                                }
                            )
                        else:
                            suspicious = True
                            self.alerts.append(
                                {
                                    "title": self.template["IOC-03"]["title"].format(dnsname, tag.upper()),
                                    "description": self.template["IOC-03"]["description"].format(dnsname),
                                    "host": dnsname,
                                    "level": "High",
                                    "id": "IOC-03",
                                }
                            )

                freedns_tags = self._bl_freedns_map.get(suffix)
                if freedns_tags:
                    for tag in freedns_tags:
                        if not self._indicator_type_enabled(tag):
                            continue
                        suspicious = True
                        if record is not None:
                            self._add_signal(record, "domain_freedns", dnsname)
                        self.alerts.append(
                            {
                                "title": self.template["IOC-05"]["title"].format(dnsname),
                                "description": self.template["IOC-05"]["description"].format(dnsname),
                                "host": dnsname,
                                "level": "Moderate",
                                "id": "IOC-05",
                            }
                        )
                        break

        if self.heuristics_analysis:
            # TLD IOCs: check the last label.
            tld = dnsname.strip().strip(".").lower().split(".")[-1] if dnsname else ""
            if tld:
                tags = self._bl_tlds_map.get(tld)
                if tags:
                    for tag in tags:
                        if not self._indicator_type_enabled(tag):
                            continue
                        suspicious = True
                        if record is not None:
                            self._add_signal(record, "domain_suspicious_tld", dnsname)
                        self.alerts.append(
                            {
                                "title": self.template["IOC-06"]["title"].format(dnsname),
                                "description": self.template["IOC-06"]["description"].format(dnsname, tld),
                                "host": dnsname,
                                "level": "Low",
                                "id": "IOC-06",
                            }
                        )
                        break

        if self.heuristics_analysis:
            # T6: domain mimicry — fake news/press domain with geo branding.
            # Deduplicates at SLD level; works offline (pure text, no WHOIS/NS).
            try:
                from publicsuffix2 import get_sld as _get_sld2
                _sld_t6 = str(_get_sld2(dnsname) or dnsname)
            except Exception:
                _sld_t6 = dnsname
            if _sld_t6 not in self._mimicry_seen:
                self._mimicry_seen.add(_sld_t6)
                _matched, _media_kw, _geo_term = _mimicry_match(dnsname)
                if _matched:
                    suspicious = True
                    if record is not None:
                        self._add_signal(record, "domain_mimicry",
                                         f"{_media_kw}+{_geo_term} in {_sld_t6}")
                    self.alerts.append({
                        "title": f"Suspected fake news/media domain: {dnsname}",
                        "description": (
                            f"The domain '{dnsname}' contains a media/press keyword "
                            f"('{_media_kw}') combined with a geographic identifier "
                            f"('{_geo_term}'). This naming pattern is characteristic of "
                            "infection domains used by Predator/Intellexa and similar "
                            "operators, who impersonate local news outlets to deliver "
                            "exploit links. This is a heuristic signal — combine with "
                            "domain age and other indicators before concluding."
                        ),
                        "host": dnsname,
                        "level": "Low",
                        "id": "MIMICRY-01",
                    })

        if self.active_analysis and self.connected:
            domain = get_sld(dnsname)
            if domain not in self.dns_checked:
                self.dns_checked.add(domain)

                # DNS NS results (prefer prefetch cache).
                name_servers = None
                ns_err = ""
                with self._domain_enrich_lock:
                    if domain in self._domain_ns_cache:
                        name_servers = self._domain_ns_cache.get(domain) or []
                    elif domain in self._domain_ns_err:
                        ns_err = self._domain_ns_err.get(domain) or ""
                if name_servers is None:
                    # Fallback: should be rare (prefetch best-effort).
                    try:
                        ok_ns, ns_res, err_ns = self._call_with_timeout(
                            lambda: pydig.query(domain, "NS"), 5
                        )
                        if not ok_ns:
                            raise RuntimeError(err_ns or "timeout")
                        name_servers = ns_res or []
                    except Exception as e:
                        name_servers = []
                        ns_err = str(e)

                if name_servers:
                    ns0 = str(name_servers[0]).strip().strip(".").lower()
                    for suffix in self._iter_domain_suffixes(ns0):
                        tags = self._bl_nameservers_map.get(suffix)
                        if not tags:
                            continue
                        if any(self._indicator_type_enabled(tag) for tag in tags):
                            suspicious = True
                            if record is not None:
                                self._add_signal(record, "domain_suspicious_ns", dnsname)
                            self.alerts.append(
                                {
                                    "title": self.template["ACT-01"]["title"].format(dnsname, name_servers[0]),
                                    "description": self.template["ACT-01"]["description"].format(dnsname),
                                    "host": dnsname,
                                    "level": "Moderate",
                                    "id": "ACT-01",
                                }
                            )
                            break
                elif ns_err:
                    self.errors.append(f"Issue when doing a dig NS query to {domain}: {ns_err}")

                # WHOIS creation_date (prefer prefetch cache).
                creation_date = None
                whois_err = ""
                with self._domain_enrich_lock:
                    if domain in self._domain_whois_creation_cache:
                        creation_date = self._domain_whois_creation_cache.get(domain)
                    elif domain in self._domain_whois_err:
                        whois_err = self._domain_whois_err.get(domain) or ""
                if creation_date is None and not whois_err:
                    # Fallback: should be rare (prefetch best-effort).
                    try:
                        ok_w, whois_record, err_w = self._call_with_timeout(lambda: whois.whois(domain), 14)
                        if not ok_w:
                            raise RuntimeError(err_w or "timeout")
                        cd = whois_record.creation_date
                        creation_date = cd if type(cd) is not list else cd[0]
                    except Exception as e:
                        whois_err = str(e)

                if creation_date is None:
                    if whois_err:
                        if "timeout" in whois_err.lower():
                            self.errors.append(
                                f"WHOIS for {domain} timed out after 14s (registry slow, rate-limited, or unreachable). {whois_err}"
                            )
                        else:
                            self.errors.append(f"WHOIS query for {domain} failed: {whois_err}")
                    else:
                        self.errors.append(
                            f"WHOIS for {domain} returned no creation date (redacted or unparsed response)."
                        )
                else:
                    try:
                        creation_days = abs((datetime.now() - creation_date).days)
                        if creation_days < WHOIS_RECENT_REGISTRATION_MAX_DAYS:
                            suspicious = True
                            if record is not None:
                                if creation_days < 180:
                                    self._add_signal(record, "domain_recent_6mo", dnsname)
                                else:
                                    self._add_signal(record, "domain_recent_1yr", dnsname)
                            self.alerts.append(
                                {"title": self.template["ACT-02"]["title"].format(dnsname, creation_days),
                                 "description": self.template["ACT-02"]["description"].format(dnsname),
                                 "host": dnsname,
                                 "level": "Moderate",
                                 "id": "ACT-02"}
                            )
                    except Exception:
                        # Don't fail the whole check on weird creation_date types.
                        self.errors.append(
                            f"WHOIS for {domain} returned an unparseable creation date."
                        )

        return suspicious

    def check_http(self, record):
        """Check the HTTP hostname against a set of IOCs / heuristics.
        Args:
            record (dict): record to be processed.
        Returns:
            supicious (bool) : if an alert has been leveraged.
        """
        if record["whitelisted"]: return

        if "http" in record:
            for http in record["http"]:
                if http["hostname"] not in record["domains"]:
                    if re.match(r"^[a-z\.0-9\-]+\.[a-z\-]{2,}$", http["hostname"]):
                        if http["hostname"]:
                            if self.check_dnsname(http["hostname"], record=record):
                                record["suspicious"] = True
