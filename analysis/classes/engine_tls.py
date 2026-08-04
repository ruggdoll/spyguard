#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional

import OpenSSL

from classes.engine_types import _normalize_dn
from classes.jarm import get_jarm


class EngineTLSMixin:

    def _dns_rr_is_a_or_aaaa(self, rrtype) -> bool:
        """Suricata EVE may use rrtype as name (A/AAAA) or numeric RFC code (1 / 28)."""
        if rrtype in ("A", "AAAA"):
            return True
        if isinstance(rrtype, int):
            return rrtype in (1, 28)
        if isinstance(rrtype, str):
            s = rrtype.strip().upper()
            if s in ("A", "AAAA"):
                return True
            if s.isdigit():
                return int(s) in (1, 28)
        return False

    def _format_x509_name(self, components: dict) -> str:
        """Format an X509Name components dict to a stable DN string."""
        if not components:
            return ""
        preferred = ["C", "ST", "L", "O", "OU", "CN"]
        ordered_keys = [k for k in preferred if k.encode() in components] + sorted(
            [k.decode("utf8") for k in components.keys() if k.decode("utf8") not in preferred]
        )
        parts = []
        for k in ordered_keys:
            kb = k.encode("utf8")
            if kb not in components:
                continue
            vb = components[kb]
            parts.append(f"{k}={vb.decode('utf8')}")
        return ", ".join(parts)

    def _normalize_dn(self, dn: str) -> str:
        # Backward-compatible wrapper.
        return _normalize_dn(dn)

    def _tls_version_number(self, version: str):
        """Extract numeric TLS version from strings like 'TLS 1.3'."""
        if not version:
            return None
        m = re.search(r"([0-9]+(?:\.[0-9]+)?)", str(version))
        if not m:
            return None
        try:
            return float(m.group(1))
        except Exception:
            return None

    def _coerce_tls_port(self, certificate: dict) -> int:
        """Suricata sometimes omits dest_port on tls events; default to 443."""
        p = certificate.get("port")
        if p is None or p == "":
            return 443
        try:
            n = int(p)
        except (TypeError, ValueError):
            return 443
        if n < 1 or n > 65535:
            return 443
        return n

    def _cert_issuerdn_str(self, certificate: dict) -> str:
        for key in ("issuerdn", "issuer"):
            v = certificate.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return ""

    def _get_host_for_ssl(self, record: dict, certificate: dict) -> str:
        """Pick best hostname for an active TLS connection."""
        if certificate.get("sni"):
            return certificate["sni"]
        if record.get("domains"):
            return record["domains"][0]
        if record.get("http") and isinstance(record["http"], list) and record["http"]:
            return record["http"][0].get("hostname") or ""
        return record.get("ip_dst", "")

    def _should_skip_active_tls_probe_to_ip(self, ip: str) -> bool:
        """Avoid TLS handshakes to addresses that will not yield useful cert hostnames."""
        if not ip or not isinstance(ip, str):
            return True
        try:
            a = ipaddress.ip_address(ip.strip())
        except ValueError:
            return True
        if a.is_multicast or a.is_link_local or a.is_loopback or a.is_unspecified:
            return True
        return False

    def _normalize_cert_hostname_candidate(self, raw: str) -> Optional[str]:
        """Turn a CN/SAN value into a usable DNS name, or None if not suitable."""
        if not raw or not isinstance(raw, str):
            return None
        s = raw.strip().lower().rstrip(".")
        if not s:
            return None
        if s.startswith("*."):
            s = s[2:]
        if not s:
            return None
        try:
            ipaddress.ip_address(s)
            return None
        except ValueError:
            pass
        if ".." in s or s.startswith(".") or s.endswith("."):
            return None
        # RFC 6761 + common QUIC/TLS placeholders (e.g. invalid2.invalid); never prefer over real DNS.
        if s == "invalid" or s.endswith(".invalid"):
            return None
        if not re.match(r"^[a-z0-9._-]+$", s):
            return None
        if "." not in s:
            return s if re.match(r"^[a-z][a-z0-9-]*$", s) else None
        return s

    def _hostname_from_x509(self, x509: Any) -> Optional[str]:
        """Prefer subject CN, then subjectAltName dNSName entries."""
        if x509 is None:
            return None
        candidates: list[str] = []
        try:
            for k, v in x509.get_subject().get_components():
                if k == b"CN":
                    candidates.append(v.decode("utf-8", errors="replace"))
                    break
        except Exception:
            pass
        try:
            for i in range(x509.get_extension_count()):
                ext = x509.get_extension(i)
                if ext.get_short_name() != b"subjectAltName":
                    continue
                for piece in str(ext).split(","):
                    piece = piece.strip()
                    if piece.upper().startswith("DNS:"):
                        candidates.append(piece[4:].strip())
        except Exception:
            pass
        for raw in candidates:
            norm = self._normalize_cert_hostname_candidate(raw)
            if norm:
                return norm
        return None

    def _tls_handshake_get_peer_x509(self, host: str, port: int) -> Any:
        """Perform TLS handshake and return peer cert as OpenSSL X509 (or raise)."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        conn = socket.create_connection((host, port), timeout=5)
        sock = context.wrap_socket(conn, server_hostname=host)
        sock.settimeout(5)
        try:
            der_cert = sock.getpeercert(True)
        finally:
            sock.close()
        if not der_cert:
            raise ValueError("no peer certificate")
        pem = ssl.DER_cert_to_PEM_cert(der_cert)
        return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)

    def _cache_tls_hostname(self, host: str, port: int, x509: Any) -> None:
        hn = self._hostname_from_x509(x509)
        key = (str(host).strip(), int(port))
        with self._active_ssl_lock:
            self._tls_cert_hostname_cache[key] = hn

    def _get_tls_cert_hostname_for_ip(self, ip: str, port: int = 443) -> Optional[str]:
        """Active probe: certificate CN/SAN for TLS on ip:port (cached). Used before passive DNS."""
        if not ip or not isinstance(ip, str):
            return None
        ip = ip.strip()
        if not ip or ip == "--":
            return None
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None
        key = (ip, int(port))
        with self._active_ssl_lock:
            if key in self._tls_cert_hostname_cache:
                return self._tls_cert_hostname_cache[key]
        try:
            x509 = self._tls_handshake_get_peer_x509(ip, port)
        except Exception:
            with self._active_ssl_lock:
                self._tls_cert_hostname_cache[key] = None
            return None
        hn = self._hostname_from_x509(x509)
        with self._active_ssl_lock:
            self._tls_cert_hostname_cache[key] = hn
        return hn

    def _precheck_tls_cert_hostnames_for_report(self) -> None:
        """Parallel TLS cert probes for (ip, 443) when domains are still empty.

        check_domains used to call _get_tls_cert_hostname_for_ip sequentially per record;
        this batches unique targets and reuses _tls_cert_hostname_cache.
        """
        if not (self.active_analysis and self.connected and self.heuristics_analysis):
            return

        targets: list[tuple[str, int]] = []
        seen: set[tuple[str, int]] = set()
        for record in self.records:
            dns_only = record.get("_dns_domains")
            if isinstance(dns_only, list) and len(dns_only) > 0:
                continue
            if record.get("domains"):
                continue
            if not self._record_observed_dest_port(record, 443):
                continue
            ip = (record.get("ip_dst") or "").strip()
            if not ip or ip == "--" or self._should_skip_active_tls_probe_to_ip(ip):
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            key = (ip, 443)
            if key in seen:
                continue
            seen.add(key)
            with self._active_ssl_lock:
                if key in self._tls_cert_hostname_cache:
                    continue
            targets.append(key)

        if not targets:
            return

        workers = min(self._active_ssl_workers, len(targets))

        def probe_one(key: tuple[str, int]) -> None:
            ip, port = key
            try:
                x509 = self._tls_handshake_get_peer_x509(ip, port)
                hn = self._hostname_from_x509(x509)
            except Exception:
                hn = None
            with self._active_ssl_lock:
                self._tls_cert_hostname_cache[key] = hn

        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_by_key = {pool.submit(probe_one, k): k for k in targets}
            total_timeout_s = max(25, 5 * len(future_by_key))
            try:
                for fut in as_completed(future_by_key, timeout=total_timeout_s):
                    try:
                        fut.result()
                    except Exception:
                        k = future_by_key[fut]
                        with self._active_ssl_lock:
                            self._tls_cert_hostname_cache.setdefault(k, None)
            except Exception:
                with self._active_ssl_lock:
                    for k in targets:
                        self._tls_cert_hostname_cache.setdefault(k, None)

    def _precheck_active_ssl(self):
        """Run active SSL checks concurrently and cache results."""
        targets = []
        seen = set()
        # Build (host, port) -> record mapping so signals can be attributed.
        key_to_record: dict[tuple[str, int], dict] = {}
        for record in self.records:
            if record.get("whitelisted"):
                continue
            for cert in record.get("certificates", []):
                port = self._coerce_tls_port(cert)
                host = self._get_host_for_ssl(record, cert)
                if not host:
                    continue
                key = (host, port)
                if key not in key_to_record:
                    key_to_record[key] = record
                if key in seen:
                    continue
                seen.add(key)
                with self._active_ssl_lock:
                    if key in self._active_ssl_cache:
                        continue
                targets.append(key)

        if not targets:
            return

        workers = min(self._active_ssl_workers, len(targets))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_by_key = {
                pool.submit(self.active_check_ssl, host, port, key_to_record.get((host, port))): (host, port)
                for host, port in targets
            }
            # Hard cap to avoid rare hangs (DNS resolver / socket edge cases).
            total_timeout_s = max(30, 8 * len(future_by_key))
            try:
                it = as_completed(future_by_key, timeout=total_timeout_s)
                for fut in it:
                    host, port = future_by_key[fut]
                    try:
                        res = bool(fut.result())
                    except Exception:
                        res = False
                    with self._active_ssl_lock:
                        self._active_ssl_cache[(host, port)] = res
            except Exception as exc:
                self._health_event("active_ssl", False, f"timeout_or_error:{exc}")
                # Best-effort: mark remaining tasks as failed in cache so callers don't block.
                with self._active_ssl_lock:
                    for host, port in targets:
                        self._active_ssl_cache.setdefault((host, port), False)

    def active_check_ssl(self, host, port, record=None):
        """This method:

        1. Check the issuer and subject of a certificate directly by connecting
        to the remote server in order to bypass TLS 1.3+ restrictions.
        Most of this method was been taken from: https://tinyurl.com/3vsvhu79

        2. Get the JARM of the remote server by using the standard poc library
        from sales force.

        Args:
            host (str): Host to connect to
            port (int): Port to connect to
            record (dict, optional): Flow record to emit signals onto.
        """
        try:
            suspect = False
            try:
                x509 = self._tls_handshake_get_peer_x509(host, port)
            except Exception as conn_err:
                self._health_event("active_ssl", False, str(conn_err))
                with self._active_ssl_lock:
                    self.errors.append(
                        f"Issue when trying to grab the SSL certificate located at {host}:{port} ({str(conn_err)})"
                    )
                return False

            self._cache_tls_hostname(host, port, x509)

            issuer = dict(x509.get_issuer().get_components())
            subject = dict(x509.get_subject().get_components())
            certhash = x509.digest("sha1").decode("utf8").replace(":", "").lower()
            issuer = self._format_x509_name(issuer)
            subject = self._format_x509_name(subject)

            issuer_tags = self._bl_issuers_map.get(self._normalize_dn(issuer))
            if issuer_tags and any(self._indicator_type_enabled(t) for t in issuer_tags):
                with self._active_ssl_lock:
                    if record is not None:
                        self._add_signal(record, "cert_issuer_ioc", host)
                    self.alerts.append(
                        {
                            "title": self.template["SSL-02"]["title"].format(host),
                            "description": self.template["SSL-02"]["description"],
                            "host": host,
                            "proto": "TLS",
                            "port": port,
                            "level": "Moderate",
                            "id": "SSL-02",
                        }
                    )
                suspect = True

            if issuer == subject:
                with self._active_ssl_lock:
                    if record is not None:
                        self._add_signal(record, "cert_self_signed", host)
                    self.alerts.append({"title": self.template["SSL-03"]["title"].format(host),
                                        "description": self.template["SSL-03"]["description"].format(host),
                                        "host": host,
                                        "proto": "TLS",
                                        "port": port,
                                        "level": "Moderate",
                                        "id": "SSL-03"})
                suspect = True

            if self.iocs_analysis:
                cert_tag = self._bl_certs_map.get(certhash)
                if cert_tag and self._indicator_type_enabled(cert_tag):
                    with self._active_ssl_lock:
                        if record is not None:
                            self._add_signal(record, "cert_hash_ioc", host)
                        self.alerts.append({"title": self.template["SSL-04"]["title"].format(host, cert_tag.upper()),
                                            "description": self.template["SSL-04"]["description"].format(host),
                                            "host": host,
                                            "level": "High",
                                            "id": "SSL-04"})
                    suspect = True

                if self._bl_jarms_map:
                    host_jarm = get_jarm(host, port)
                    jarm_tag = self._bl_jarms_map.get(host_jarm)
                    if jarm_tag and self._indicator_type_enabled(jarm_tag):
                        with self._active_ssl_lock:
                            if record is not None:
                                self._add_signal(record, "jarm_ioc", host)
                            self.alerts.append({"title": self.template["SSL-05"]["title"].format(host, jarm_tag.upper()),
                                                "description": self.template["SSL-05"]["description"].format(host),
                                                "host": host,
                                                "level": "High",
                                                "id": "SSL-05"})
                        suspect = True

            self._health_event("active_ssl", True, "")
            return suspect
        except Exception as e:
            self._health_event("active_ssl", False, str(e))
            with self._active_ssl_lock:
                self.errors.append(f"Issue when trying to grab the SSL certificate located at {host}:{port} ({str(e)})")
            return False

    def check_tls(self, record):
        """Check a TLS protocol and certificates against a set of IOCs / heuristics.
        Note since TLS 1.3, the certificate is not exchanged in clear text, therefore
        we need to check it "actively" via the method active_check_ssl.

              1. Check if the TLS record is not using default TLS ports.
              2. Check if one of the certificates is a free one, like Let's Encrypt.
              3. Check if the certificate is auto-signed.
              4. If the certificate has an SNI, check the domain by calling check_dnsname.
        Args:
            record (dict): record to be processed.
        Returns:
            supicious (bool) : if an alert has been leveraged.
        """
        if record["whitelisted"]: return

        resolved_host = record["domains"][0] if len(record["domains"]) else record["ip_dst"]

        for certificate in record["certificates"]:

            try:
                tls_port = self._coerce_tls_port(certificate)
                certificate["port"] = tls_port

                if "sni" in certificate and certificate["sni"] not in record["domains"]:
                    if certificate["sni"]:
                        if self.check_dnsname(certificate["sni"], record=record):
                            record["suspicious"] = True

                default_ports = [int(p) for p in self.tls_default_ports]
                if tls_port not in default_ports:
                    record["suspicious"] = True
                    self._add_signal(record, "tls_nonstandard_port", str(tls_port))
                    self.alerts.append({"title": self.template["SSL-01"]["title"].format(tls_port, resolved_host),
                                        "description": self.template["SSL-01"]["description"].format(resolved_host),
                                        "host": resolved_host,
                                        "proto": "TLS",
                                        "port": tls_port,
                                        "level": "Moderate",
                                        "id": "SSL-01"})

                cert_tls_ver = self._tls_version_number(certificate.get("version"))
                issuerdn = self._cert_issuerdn_str(certificate)
                subject = (certificate.get("subject") or "").strip() if isinstance(certificate.get("subject"), str) else ""

                if cert_tls_ver is not None and cert_tls_ver < 1.3 and issuerdn:

                    tags = self._bl_issuers_map.get(self._normalize_dn(issuerdn))
                    if tags and any(self._indicator_type_enabled(t) for t in tags):
                        record["suspicious"] = True
                        self._add_signal(record, "cert_free_ca", resolved_host)
                        self.alerts.append({"title": self.template["SSL-02"]["title"].format(resolved_host),
                                            "description": self.template["SSL-02"]["description"],
                                            "host": resolved_host,
                                            "proto": "TLS",
                                            "port": tls_port,
                                            "level": "Moderate",
                                            "id": "SSL-02"})

                    elif subject and self._normalize_dn(issuerdn) == self._normalize_dn(subject):
                        record["suspicious"] = True
                        self._add_signal(record, "cert_self_signed", resolved_host)
                        self.alerts.append({"title": self.template["SSL-03"]["title"].format(resolved_host),
                                            "description": self.template["SSL-03"]["description"].format(resolved_host),
                                            "host": resolved_host,
                                            "proto": "TLS",
                                            "port": tls_port,
                                            "level": "Moderate",
                                            "id": "SSL-03"})
                else:
                    # Even if the generic internet check fails, the target host
                    # may still be reachable. Try the active SSL check anyway.
                    # When offline, active checks can block on name resolution/connect; skip.
                    if self.active_analysis and self.connected:
                        host_for_ssl = self._get_host_for_ssl(record, certificate) or resolved_host
                        port = tls_port
                        cache_key = (host_for_ssl, port)

                        if host_for_ssl not in self.cert_checked:
                            self.cert_checked.add(host_for_ssl)

                            with self._active_ssl_lock:
                                cached = self._active_ssl_cache.get(cache_key)

                            if cached is None:
                                cached = self.active_check_ssl(host_for_ssl, port)
                                with self._active_ssl_lock:
                                    self._active_ssl_cache[cache_key] = bool(cached)

                            if cached:
                                record["suspicious"] = True
                                break
            except Exception as e:
                self.errors.append(f"Issue when processing the following certificate (check_tls): {json.dumps(certificate)}")
