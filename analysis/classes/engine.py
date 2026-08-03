#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, IPv6Network, ip_address
from typing import Any, Callable, Optional

import ipaddress
import requests
from netaddr import IPAddress, IPNetwork

from classes.engine_types import (
    EngineConfig,
    WhitelistIndex,
    IOCIndex,
    _whitelist_asn_elements_to_int_set,
    _iter_domain_suffixes,
    _normalize_dn,
)
from classes.engine_tls import EngineTLSMixin
from classes.engine_dns import EngineDNSMixin
from classes.ip2asn_table import load_ip2asn_v4_table
from utils import get_config, get_iocs, get_whitelist


class Engine(EngineTLSMixin, EngineDNSMixin):

    def __init__(self, capture_directory):

        # Set some vars.
        self.analysis_start = datetime.now()
        self.connected = self.check_internet()
        self.working_dir = capture_directory
        self.assets_dir = f"{capture_directory}/assets/"
        self.rules_file = "/tmp/rules.rules"
        self.pcap_path = os.path.join(self.working_dir, "capture.pcap")
        self.records = []
        self.alerts = []
        self.dns = []
        self.files = []
        self.whitelist = []
        self.uncategorized = []
        self.analysed = []
        self.dns_failed = []
        self.dns_checked = set()
        self.cert_checked = set()
        self.errors = []
        self.analysis_end = None
        self._enabled_indicator_types = None
        self._active_ssl_cache = {}
        self._active_ssl_lock = threading.Lock()
        self._active_ssl_workers = 4
        # Hostname extracted from peer TLS certificate (CN/SAN), keyed by (host_or_ip, port).
        self._tls_cert_hostname_cache: dict[tuple[str, int], Optional[str]] = {}
        # Unique local IPv6 (fc00::/7); used instead of a broken list-comprehension test.
        self._ipv6_ula = IPv6Network("fc00::/7")
        self._umbrella_top500k_set: Optional[set[str]] = None
        self._umbrella_top500k_rank_map: Optional[dict[str, int]] = None
        self._ipthc_cache: dict[str, tuple[Optional[str], int]] = {}
        # Domain enrichment caches (filled via prefetch to avoid sequential network latency).
        self._domain_ns_cache: dict[str, list[str]] = {}
        self._domain_ns_err: dict[str, str] = {}
        self._domain_whois_creation_cache: dict[str, Optional[datetime]] = {}
        self._domain_whois_err: dict[str, str] = {}
        self._domain_enrich_lock = threading.Lock()
        self._enrich_workers = 4

        # Get configuration (centralized/typed)
        self.config = EngineConfig.load(get_config)
        self.heuristics_analysis = self.config.heuristics_analysis
        self.iocs_analysis = self.config.iocs_analysis
        self.whitelist_analysis = self.config.whitelist_analysis
        self.active_analysis = self.config.active_analysis
        self.userlang = self.config.userlang
        self.max_ports = self.config.max_ports
        self.http_default_ports = self.config.http_default_ports
        self.tls_default_ports = self.config.tls_default_ports
        self.indicators_types = self.config.indicators_types

        # Save detection methods used.
        self.detection_methods = {
            "iocs": self.iocs_analysis,
            "heuristics": self.heuristics_analysis,
            "active": self.active_analysis,
        }

        # Pre-index indicator types for fast lookups.
        self._enabled_indicator_types = set(self.indicators_types or [])

        # Retrieve and index IOCs.
        if self.iocs_analysis:
            bl_cidrs = [[IPNetwork(cidr[0]), cidr[1]] for cidr in get_iocs("cidr")]
            bl_hosts = get_iocs("ip4addr") + get_iocs("ip6addr")
            bl_asns = get_iocs("asn")
            tor_nodes = self.get_tor_nodes()
            bl_domains = get_iocs("domain")
            bl_freedns = get_iocs("freedns")
            bl_certs = get_iocs("sha1cert")
            bl_jarms = get_iocs("jarm")
            bl_nameservers = get_iocs("ns")
            bl_tlds = get_iocs("tld")
            bl_issuers = get_iocs("issuerdn")
        else:
            bl_cidrs = []
            bl_hosts = []
            bl_asns = []
            tor_nodes = []
            bl_domains = []
            bl_freedns = []
            bl_certs = []
            bl_jarms = []
            bl_nameservers = []
            bl_tlds = []
            bl_issuers = []

        self.ioc_index = IOCIndex(
            bl_cidrs=bl_cidrs,
            bl_hosts=bl_hosts,
            bl_asns=bl_asns,
            tor_nodes=tor_nodes,
            bl_domains=bl_domains,
            bl_freedns=bl_freedns,
            bl_certs=bl_certs,
            bl_jarms=bl_jarms,
            bl_nameservers=bl_nameservers,
            bl_tlds=bl_tlds,
            bl_issuers=bl_issuers,
            enabled_indicator_types=self._enabled_indicator_types,
        )

        # Keep legacy attributes (minimize churn across the rest of the class).
        self.bl_cidrs = self.ioc_index.bl_cidrs
        self.bl_hosts = self.ioc_index.bl_hosts
        self.bl_asns = self.ioc_index.bl_asns
        self.tor_nodes = self.ioc_index.tor_nodes
        self.bl_domains = self.ioc_index.bl_domains
        self.bl_freedns = self.ioc_index.bl_freedns
        self.bl_certs = self.ioc_index.bl_certs
        self.bl_jarms = self.ioc_index.bl_jarms
        self.bl_nameservers = self.ioc_index.bl_nameservers
        self.bl_tlds = self.ioc_index.bl_tlds
        self.bl_issuers = self.ioc_index.bl_issuers

        self._tor_nodes_set = self.ioc_index.tor_nodes_set
        self._bl_hosts_map = self.ioc_index.bl_hosts_map
        self._bl_asns_map = self.ioc_index.bl_asns_map
        self._bl_domains_map = self.ioc_index.bl_domains_map
        self._bl_freedns_map = self.ioc_index.bl_freedns_map
        self._bl_tlds_map = self.ioc_index.bl_tlds_map
        self._bl_certs_map = self.ioc_index.bl_certs_map
        self._bl_jarms_map = self.ioc_index.bl_jarms_map
        self._bl_nameservers_map = self.ioc_index.bl_nameservers_map
        self._bl_issuers_map = self.ioc_index.bl_issuers_map

        # Retrieve and index whitelist.
        if self.whitelist_analysis:
            wl_cidrs = [IPNetwork(cidr) for cidr in get_whitelist("cidr")]
            wl_hosts = get_whitelist("ip4addr") + get_whitelist("ip6addr") + self.get_public_ip()
            wl_domains = get_whitelist("domain")
            wl_asn_elems = get_whitelist("asn")
        else:
            wl_cidrs = []
            wl_hosts = []
            wl_domains = []
            wl_asn_elems = []

        self.whitelist_index = WhitelistIndex(wl_cidrs, wl_hosts, wl_domains)

        # Keep legacy attributes.
        self.wl_cidrs = self.whitelist_index.cidrs
        self.wl_hosts = self.whitelist_index.hosts
        self.wl_domains = self.whitelist_index.domains
        self._wl_hosts_set = set(self.wl_hosts)
        self._wl_domains_set = set(d.strip(".").lower() for d in (self.wl_domains or []) if d)
        # AS whitelist: checked last in check_whitelist (local ip2asn DB) when IP/CIDR/domain do not match.
        self._wl_asns_int = _whitelist_asn_elements_to_int_set(wl_asn_elems)

        # Load template language
        if not re.match("^[a-z]{2,3}$", self.userlang):
            self.userlang = "en"
        with open(os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "locales/{}.json".format(self.userlang))) as f:
            self.template = json.load(f)["alerts"]

        # Health report for external services (shown in UI).
        self.analysis_health = {
            "internet": bool(self.connected),
            "checks": {},  # name -> {attempted:int, ok:int, fail:int, last_error:str}
        }

        self._asn_ip_cache: dict[str, tuple[Optional[int], str]] = {}
        self._ip2asn_table = load_ip2asn_v4_table()
        if self._ip2asn_table:
            self._health_event("ip2asn", True, "")
        else:
            self._health_event("ip2asn", False, "missing_or_unreadable")

    def _health_event(self, name: str, ok: bool, detail: str = "") -> None:
        """Record the health of an external dependency / enrichment step."""
        try:
            c = self.analysis_health.setdefault("checks", {}).setdefault(
                name, {"attempted": 0, "ok": 0, "fail": 0, "last_error": ""}
            )
            c["attempted"] += 1
            if ok:
                c["ok"] += 1
            else:
                c["fail"] += 1
                if detail:
                    c["last_error"] = str(detail)[:500]
        except Exception:
            pass

    def _call_with_timeout(self, fn: Callable[[], Any], timeout_s: float) -> tuple[bool, Any, str]:
        """Run fn() with a wall-clock timeout. Returns (ok, result, error_str)."""
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(fn)
                return (True, fut.result(timeout=timeout_s), "")
        except Exception as exc:
            return (False, None, str(exc))

    def get_analysis_health(self) -> dict:
        """Return a structured health report + a rough effectiveness estimate."""
        checks = (self.analysis_health or {}).get("checks") or {}
        internet = bool((self.analysis_health or {}).get("internet"))

        # Weighted, best-effort estimate of how much analysis capability was lost.
        # These weights are heuristic and intended only for user-facing guidance.
        weights = {
            "ipthc": 10,
            "umbrella": 10,
            "ip2asn": 10,
            "dns_ns": 10,
            "whois": 10,
            "tor_nodes": 5,
            "active_ssl": 20,
        }
        enabled = {k: True for k in weights.keys()}
        need_asn = bool(self._bl_asns_map) or bool(self._wl_asns_int)
        enabled["ip2asn"] = need_asn
        if not self.active_analysis:
            enabled["active_ssl"] = False
            enabled["ipthc"] = False
            enabled["dns_ns"] = False
            enabled["whois"] = False

        total = sum(w for k, w in weights.items() if enabled.get(k))
        lost = 0

        # Offline = hard loss for internet-dependent checks (local ip2asn is unaffected).
        if not internet:
            for k in ("ipthc", "dns_ns", "whois", "tor_nodes"):
                if enabled.get(k):
                    lost += weights[k]

        # Umbrella list is local, but if missing, it's a loss.
        umb = checks.get("umbrella") or {}
        if enabled.get("umbrella") and umb.get("fail", 0) > 0 and umb.get("ok", 0) == 0:
            lost += weights["umbrella"]

        # ip2asn TSV is local; loss only if load failed when ASN rules are enabled.
        ip2 = checks.get("ip2asn") or {}
        if enabled.get("ip2asn") and ip2.get("fail", 0) > 0 and ip2.get("ok", 0) == 0:
            lost += weights["ip2asn"]

        # Active SSL failures: consider it degraded if most attempts fail.
        if enabled.get("active_ssl"):
            a = checks.get("active_ssl") or {}
            att = int(a.get("attempted", 0) or 0)
            fail = int(a.get("fail", 0) or 0)
            if att > 0 and fail / max(att, 1) >= 0.5:
                lost += weights["active_ssl"]

        # Generic service failures when online (ipthc/whois/ns/tor)
        for k in ("ipthc", "dns_ns", "whois", "tor_nodes"):
            if not enabled.get(k) or not internet:
                continue
            a = checks.get(k) or {}
            att = int(a.get("attempted", 0) or 0)
            fail = int(a.get("fail", 0) or 0)
            if att > 0 and fail / max(att, 1) >= 0.5:
                lost += weights[k]

        if total <= 0:
            effectiveness = 100
            lost_pct = 0
        else:
            lost = min(lost, total)
            lost_pct = int(round(100 * (lost / total)))
            effectiveness = max(0, 100 - lost_pct)

        degraded = (not internet) or any((v or {}).get("fail", 0) for v in checks.values())
        return {
            "internet": internet,
            "degraded": bool(degraded),
            "effectiveness_pct": int(effectiveness),
            "lost_pct": int(lost_pct),
            "checks": checks,
        }

    def _indicator_type_enabled(self, tag: str) -> bool:
        # Keep the semantics: IOC tag itself, or "all".
        return self.ioc_index.indicator_type_enabled(tag)

    def _iter_domain_suffixes(self, name: str):
        # Backward-compatible wrapper.
        yield from _iter_domain_suffixes(name)

    def _is_domain_whitelisted(self, dnsname: str) -> bool:
        """True if dnsname matches a whitelisted domain suffix (same rules as check_whitelist)."""
        return self.whitelist_index.is_domain_whitelisted(dnsname)

    def check_internet(self) -> bool:
        """Check the internet link just with a small http request
        to an URL present in the configuration. If the link is down,
        retry 3 times.

        Returns:
            bool: True if everything works.
        """
        attempts = 3

        while True:
            try:
                url = get_config(("network", "internet_check"))
                requests.get(url, timeout=3)
                return True
            except:
                if attempts == 0:
                    return False
                else:
                    time.sleep(5)
                    attempts -= 1

    def get_public_ip(self) -> list:
        """Get the public IP address

        Returns:
            list: list containing the public IP address.
        """
        if self.connected:
            try:
                return [requests.get("https://api.ipify.org", timeout=3).text]
            except:
                return []
        else:
            return []

    def start_engine(self):
        """ This method starts suricata and then launch the
            parsers to analyse the output logs.
        """

        # Parse the eve.json file.
        self.parse_eve_file()

        # Whitelist before any other work so parallel SSL probes skip allowlisted flows.
        if self.whitelist_analysis:
            for record in self.records:
                self.check_whitelist(record)

        # Cheap: merge SNI / HTTP Host into domains once so later steps skip useless work.
        for record in self.records:
            self._merge_observed_hostnames_into_domains(record)

        # Prefetch internet enrichments in parallel to avoid per-domain sequential waits.
        if self.active_analysis and self.connected:
            try:
                self._prefetch_domain_enrichments()
            except Exception:
                # Best-effort; never break the analysis.
                pass

        # Warm local ASN cache (O(log n) each; dedupe by IP for repeated destinations).
        if self._ip2asn_table and (self._bl_asns_map or self._wl_asns_int):
            try:
                self._prefetch_asn_lookups()
            except Exception:
                pass

        # Pre-run active SSL checks in parallel (TLS 1.3+ certificates are not in EVE).
        # This is the most expensive part of the analysis and is independent per host.
        # Active SSL probing requires network reachability; when offline it can hang on DNS/connect.
        if self.active_analysis and self.connected:
            self._precheck_active_ssl()

        # Parallel cert CN/SAN fetch for empty-domain + :443 flows (replaces sequential probes in check_domains).
        if self.active_analysis and self.connected:
            self._precheck_tls_cert_hostnames_for_report()

        # For each type of records, check it against heuristics.
        for record in self.records:
            self.check_domains(record)
            self.check_flow(record)
            self.check_tls(record)
            self.check_http(record)

        # Check for failed DNS answers (if spyguard not connected)
        for dnsname in list(set(self.dns_failed)):
            if self._is_domain_whitelisted(dnsname):
                continue
            self.check_dnsname(dnsname)

        self._check_umbrella_popularity()
        self._attach_umbrella_ranks_to_records()
        self._strip_parse_eve_internal_state()

    def _strip_parse_eve_internal_state(self) -> None:
        """Remove non-JSON-serializable parse helpers before records.json export."""
        for rec in self.records or []:
            rec.pop("_proto_keys", None)
            rec.pop("_cert_snis_seen", None)

    def parse_eve_file(self):
        """This method parses the eve.json file produced by suricata.
           For each record, it look at the record type and then append the self.record
           dictionnary which contains valuable data to look at suspicious stuff.
        """
        eve_path = f"{self.assets_dir}eve.json"

        # Build records efficiently: one pass, plus an index for O(1) lookups.
        records_by_ip = {}

        def get_or_create_record(ip_dst: str):
            rec = records_by_ip.get(ip_dst)
            if rec is None:
                rec = {
                    "ip_dst": ip_dst,
                    "whitelisted": False,
                    "suspicious": False,
                    "protocols": [],
                    "_proto_keys": set(),
                    "domains": [],
                    "_dns_domains": [],
                    "certificates": [],
                    "_cert_snis_seen": set(),
                }
                self.records.append(rec)
                records_by_ip[ip_dst] = rec
            return rec

        dns_queries = set()
        resolved_domains = set()
        # IP -> names from DNS answers (filled before flow rows may exist; merged after the file pass).
        dns_ip_to_domains = {}

        with open(eve_path, "r") as f:
            for line in f:
                try:
                    record = json.loads(line)
                except Exception:
                    # Ignore malformed JSON lines but keep the behavior robust.
                    continue

                # FLOW: create/update per-destination records and protocols.
                if "flow" in record:
                    try:
                        app_proto = record.get("app_proto", "failed")
                        proto = {
                            "name": (app_proto.upper() if app_proto != "failed" else record["proto"].upper()),
                            "port": record.get("dest_port", -1),
                        }
                        rec = get_or_create_record(record["dest_ip"])
                        pkey = (proto["name"], proto["port"])
                        pk = rec.setdefault("_proto_keys", set())
                        if pkey not in pk:
                            pk.add(pkey)
                            rec["protocols"].append(proto)
                    except Exception:
                        self.errors.append(
                            f"Issue when processing the following eve record (flow): {json.dumps(record)}"
                        )
                    continue

                # TLS: attach TLS metadata to the right destination record.
                if "tls" in record:
                    try:
                        dest_ip = record.get("dest_ip")
                        if not dest_ip:
                            continue
                        rec = records_by_ip.get(dest_ip)
                        if rec is None:
                            # Some Suricata configurations don't emit flow records.
                            # Create a destination record so TLS metadata isn't lost.
                            rec = get_or_create_record(dest_ip)

                        tls = record["tls"]
                        if "issuer" in tls and "issuerdn" not in tls:
                            tls["issuerdn"] = tls["issuer"]
                        if "version" in tls:
                            tls_ver = self._tls_version_number(tls.get("version"))
                            snis = rec.setdefault("_cert_snis_seen", set())
                            if tls_ver is not None and tls_ver < 1.3 and "session_resumed" not in tls:
                                if tls not in rec["certificates"]:
                                    tls["port"] = record.get("dest_port")
                                    rec["certificates"].append(tls)
                                    sni0 = tls.get("sni")
                                    if isinstance(sni0, str) and sni0:
                                        snis.add(sni0)
                            else:
                                sni = tls.get("sni")
                                if isinstance(sni, str) and sni and sni not in snis:
                                    rec["certificates"].append(
                                        {"sni": sni, "version": tls["version"], "port": record.get("dest_port")}
                                    )
                                    snis.add(sni)
                                else:
                                    rec["certificates"].append({"version": tls["version"], "port": record.get("dest_port")})
                    except Exception:
                        self.errors.append(
                            f"Issue when processing the following eve record (tls): {json.dumps(record)}"
                        )
                    continue

                # HTTP: attach HTTP host / UA to the right destination record.
                if "http" in record:
                    try:
                        dest_ip = record.get("dest_ip")
                        if not dest_ip:
                            continue
                        rec = records_by_ip.get(dest_ip)
                        if rec is None:
                            # Some Suricata configurations don't emit flow records.
                            rec = get_or_create_record(dest_ip)

                        http = record["http"]
                        d = {"hostname": http["hostname"]}
                        if "http_user_agent" in http:
                            d["user-agent"] = http["http_user_agent"]
                        if "http" in rec:
                            if d not in rec["http"]:
                                rec["http"].append(d)
                        else:
                            rec["http"] = [d]
                    except Exception:
                        self.errors.append(
                            f"Issue when processing the following eve record (http): {json.dumps(record)}"
                        )
                    continue

                # DNS: link rrname to destination IPs when possible; keep queries for later.
                if "dns" in record:
                    try:
                        dns = record["dns"]
                        if dns.get("type") == "answer":
                            rrname = (
                                dns.get("rrname")
                                or dns.get("qry_name")
                                or dns.get("query", {}).get("rrname")
                                or dns.get("query", {}).get("qry_name")
                            )

                            if dns.get("rcode") == "NOERROR":
                                resolved_ips = []

                                # Legacy Suricata EVE format.
                                grouped = dns.get("grouped")
                                if isinstance(grouped, dict):
                                    resolved_ips.extend(grouped.get("A", []) or [])
                                    resolved_ips.extend(grouped.get("AAAA", []) or [])

                                # Modern Suricata EVE format: answers array.
                                answers = dns.get("answers")
                                if isinstance(answers, list):
                                    for ans in answers:
                                        if not isinstance(ans, dict):
                                            continue
                                        rrtype = ans.get("rrtype")
                                        rdata = ans.get("rdata")
                                        if self._dns_rr_is_a_or_aaaa(rrtype) and rdata:
                                            resolved_ips.append(rdata)

                                # Some formats still expose rrtype/rdata at top level.
                                rrtype = dns.get("rrtype")
                                rdata = dns.get("rdata")
                                if self._dns_rr_is_a_or_aaaa(rrtype) and rdata:
                                    resolved_ips.append(rdata)

                                if resolved_ips and rrname:
                                    resolved_domains.add(rrname)
                                for ip in set(resolved_ips):
                                    if rrname:
                                        dns_ip_to_domains.setdefault(ip, set()).add(rrname)

                            elif dns.get("rcode") == "SERVFAIL":
                                if rrname:
                                    self.dns_failed.append(rrname)
                        elif dns.get("type") == "query":
                            qname = (
                                dns.get("rrname")
                                or dns.get("qry_name")
                                or dns.get("query", {}).get("rrname")
                                or dns.get("query", {}).get("qry_name")
                            )
                            if qname:
                                dns_queries.add(qname)
                    except Exception:
                        self.errors.append(
                            f"Issue when processing the following eve record (dns answer): {json.dumps(record)}"
                        )
                    continue

                # ALERT: mark record suspicious and add corresponding alert.
                if "alert" in record and record.get("event_type") == "alert":
                    try:
                        dest_ip = record.get("dest_ip")
                        if not dest_ip:
                            continue
                        rec = records_by_ip.get(dest_ip)
                        if rec is None:
                            rec = get_or_create_record(dest_ip)
                        rec["suspicious"] = True
                        self.alerts.append(
                            {
                                "title": self.template["SNORT-01"]["title"].format(record["alert"]["signature"]),
                                "description": self.template["SNORT-01"]["description"].format(rec["ip_dst"]),
                                "host": rec["ip_dst"],
                                "level": "High",
                                "id": "SNORT-01",
                            }
                        )
                    except Exception:
                        self.errors.append(
                            f"Issue when processing the following eve record (dns answer): {json.dumps(record)}"
                        )

        # Attach DNS names to flows seen to any IP, regardless of eve.json line order.
        for ip, names in dns_ip_to_domains.items():
            rec = records_by_ip.get(ip)
            if rec is None:
                continue
            dd = rec.setdefault("_dns_domains", [])
            for name in sorted(names):
                if name not in rec["domains"]:
                    rec["domains"].append(name)
                if name not in dd:
                    dd.append(name)

        # This pass is if SpyGuard is not connected to Internet.
        # We still analyze the unanswered DNS queries.
        for rrname in dns_queries:
            if rrname not in resolved_domains:
                self.records.append(
                    {
                        "ip_dst": "--",
                        "whitelisted": False,
                        "suspicious": False,
                        "protocols": [{"name": "DNS", "port": "53"}],
                        "domains": [rrname],
                        "_dns_domains": [rrname],
                        "certificates": [],
                    }
                )


    def check_whitelist(self, record):
        """ This method is asked on each record. It:

            1. Check if the associated IP(v4/6) Address can be whitelisted
            2. Check if one of the associated domain names can be whitelisted
            3. Last: if still not whitelisted and ASN whitelist entries exist, resolve ASN
               via local ip2asn-v4.tsv.gz — deferred to avoid lookups when (1–2) already match.

            If its the case, the "whitelisted" key of the record is set to True.
            Therefore, the record will be ignored for the rest of the analysis.
        Args:
            record (dict): record to be processed.
        """

        self.whitelist_index.mark_record_if_whitelisted(record, ipv6_ula=self._ipv6_ula)
        if record.get("whitelisted"):
            return
        self._try_whitelist_by_asn(record)

    def _try_whitelist_by_asn(self, record: dict) -> None:
        """Mark record whitelisted when destination IP's ASN is in the ASN whitelist."""
        if not self._wl_asns_int:
            return
        ip = record.get("ip_dst")
        if not isinstance(ip, str) or not ip.strip() or ip.strip() == "--":
            return
        ip = ip.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return
        asn, _org = self._resolve_asn_for_ip(ip)
        if asn is not None and asn in self._wl_asns_int:
            record["whitelisted"] = True

    def check_flow(self, record):
        """Check a network flow against a set of IOCs / heuristics.
              1. Check if the IP Address is blacklisted
              2. Check if the IP Address is inside a blacklisted CIDR
              3. Check if the UDP or ICMP protocol is going outside of the local network.
              4. Check if the HTTP protocol is not using default HTTP ports.
              5. Check if the network flow is using a port > 1024.
        Args:
            record (dict): record to be processed.
        Returns:
            supicious (bool) : if an alert has been leveraged.
        """
        if record["whitelisted"]: return

        resolved_host = record["domains"][0] if len(record["domains"]) else record["ip_dst"]

        if self.iocs_analysis:
            host_tag = self._bl_hosts_map.get(record["ip_dst"])
            if host_tag and self._indicator_type_enabled(host_tag):
                if host_tag == "dual":
                    record["suspicious"] = True
                    self.alerts.append({"title": self.template["IOC-12"]["title"],
                                        "description": self.template["IOC-12"]["description"].format(resolved_host),
                                        "host": resolved_host,
                                        "level": "Low",
                                        "id": "IOC-12"})
                if host_tag == "tracker":
                    record["suspicious"] = True
                    self.alerts.append({"title": self.template["IOC-04"]["title"].format(resolved_host, "tracker"),
                                        "description": self.template["IOC-04"]["description"].format(resolved_host, "tracker"),
                                        "host": resolved_host,
                                        "level": "Low",
                                        "id": "IOC-04"})
                elif host_tag == "doh":
                    if 443 in [p["port"] for p in record["protocols"]]:
                        record["suspicious"] = True
                        self.alerts.append({"title": self.template["IOC-13"]["title"].format(f"{resolved_host}"),
                                            "description": self.template["IOC-13"]["description"].format(f"{resolved_host}"),
                                            "host": resolved_host,
                                            "level": "Low",
                                            "id": "IOC-13"})
                else:
                    record["suspicious"] = True
                    self.alerts.append({"title": self.template["IOC-01"]["title"].format(resolved_host, record["ip_dst"], host_tag.upper()),
                                        "description": self.template["IOC-01"]["description"].format(f"{resolved_host} ({record['ip_dst']})"),
                                        "host": resolved_host,
                                        "level": "High",
                                        "id": "IOC-01"})

            # ASN IOC: lookup ASN via local ip2asn table and match against IOC list.
            try:
                if self._bl_asns_map and record.get("ip_dst"):
                    asn_num, asn_org = self._resolve_asn_for_ip(record["ip_dst"])
                    if asn_num:
                        asn_tag = self._bl_asns_map.get(asn_num)
                        if asn_tag and self._indicator_type_enabled(asn_tag):
                            record["suspicious"] = True
                            # Best-effort proto/port for display
                            a_proto = None
                            a_port = None
                            try:
                                if record.get("protocols") and isinstance(record["protocols"], list) and record["protocols"]:
                                    p0 = record["protocols"][0]
                                    a_proto = p0.get("name")
                                    a_port = p0.get("port")
                            except Exception:
                                pass
                            self.alerts.append(
                                {
                                    "title": self.template["IOC-14"]["title"].format(asn_num, asn_org or ""),
                                    "description": self.template["IOC-14"]["description"].format(
                                        resolved_host, record["ip_dst"], asn_num, asn_org or ""
                                    ),
                                    "host": resolved_host,
                                    "proto": a_proto,
                                    "port": a_port,
                                    "level": "Moderate",
                                    "id": "IOC-14",
                                }
                            )
            except Exception:
                pass

            if record["ip_dst"] in self._tor_nodes_set:
                record["suspicious"] = True
                self.alerts.append({"title": self.template["IOC-11"]["title"].format(resolved_host, record["ip_dst"]),
                                    "description": self.template["IOC-11"]["description"].format(f"{resolved_host} ({record['ip_dst']})"),
                                    "host": resolved_host,
                                    "level": "High",
                                    "id": "IOC-11"})

            for cidr in self.bl_cidrs:
                try:
                    if IPAddress(record["ip_dst"]) in cidr[0] and self._indicator_type_enabled(cidr[1]):
                        record["suspicious"] = True
                        self.alerts.append({"title": self.template["IOC-02"]["title"].format(resolved_host, cidr[0], cidr[1].upper()),
                                            "description": self.template["IOC-02"]["description"].format(record["ip_dst"]),
                                            "host": resolved_host,
                                            "level": "Moderate",
                                            "id": "IOC-02"})
                except:
                    continue

        if self.heuristics_analysis:
            for protocol in record["protocols"]:
                if protocol["name"] in ["UDP", "ICMP", "IPV6-ICMP"]:
                    record["suspicious"] = True
                    self.alerts.append({"title": self.template["PROTO-01"]["title"].format(protocol["name"], resolved_host),
                                        "description": self.template["PROTO-01"]["description"].format(protocol["name"], resolved_host),
                                        "host": resolved_host,
                                        "proto": protocol.get("name"),
                                        "port": protocol.get("port"),
                                        "level": "Low",
                                        "id": "PROTO-01"})
                try:
                    if protocol["port"] >= int(self.max_ports):
                        record["suspicious"] = True
                        self.alerts.append({"title": self.template["PROTO-02"]["title"].format("", resolved_host,  self.max_ports),
                                            "description": self.template["PROTO-02"]["description"].format("", resolved_host, protocol["port"]),
                                            "host": resolved_host,
                                            "proto": protocol.get("name"),
                                            "port": protocol.get("port"),
                                            "level": "Low",
                                            "id": "PROTO-02"})
                except:
                    pass

                if protocol["name"] == "HTTP":
                    record["suspicious"] = True
                    self.alerts.append({"title": self.template["PROTO-03"]["title"].format(resolved_host),
                                        "description": self.template["PROTO-03"]["description"].format(resolved_host),
                                        "host":  resolved_host,
                                        "proto": protocol.get("name"),
                                        "port": protocol.get("port"),
                                        "level": "Low",
                                        "id": "PROTO-03"})

                if protocol["name"] == "HTTP" and protocol["port"] not in self.http_default_ports:
                    record["suspicious"] = True
                    self.alerts.append({"title": self.template["PROTO-04"]["title"].format(resolved_host, protocol["port"]),
                                        "description": self.template["PROTO-04"]["description"].format(resolved_host, protocol["port"]),
                                        "host":  resolved_host,
                                        "proto": protocol.get("name"),
                                        "port": protocol.get("port"),
                                        "level": "Moderate",
                                        "id": "PROTO-04"})

    def get_tor_nodes(self) -> list:
        """Get a list of TOR nodes from dan.me.uk.

        Returns:
            list: list of TOR nodes
        """

        nodes = []
        if os.path.exists("/tmp/tor_nodes.lst"):
            with open("/tmp/tor_nodes.lst", "r") as f:
                for l in f.readlines():
                    nodes.append(l.strip())
        else:
            if self.connected:
                try:
                    nodes_list = requests.get("https://www.dan.me.uk/torlist/", timeout=10).text
                    with open("/tmp/tor_nodes.lst", "w+") as f:
                        f.write(nodes_list)
                    for l in nodes_list.splitlines():
                        nodes.append(l.strip())
                    self._health_event("tor_nodes", True, "")
                except:
                    self._health_event("tor_nodes", False, "exception")
                    self.errors.append(f"Issue when trying to get TOR nodes from dan.me.uk")
        return nodes

    def get_alerts(self):
        """Retrieves the alerts triggered during the analysis

        Returns:
            list: list of the alerts.
        """
        self.analysis_end = datetime.now()
        return [dict(t) for t in {tuple(d.items()) for d in self.alerts}]

    def _record_observed_dest_port(self, record: dict, port: int) -> bool:
        """True if any flow protocol row matches destination port (e.g. 443 for HTTPS)."""
        try:
            want = int(port)
        except Exception:
            return False
        for p in record.get("protocols") or []:
            if not isinstance(p, dict):
                continue
            try:
                if int(p.get("port", -1)) == want:
                    return True
            except Exception:
                continue
        return False
