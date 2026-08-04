#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Infrastructure layer separation detection mixin (T5).

Detects two structural patterns used by mercenary spyware (Pegasus v4+, Predator)
to evade domain/SNI-based detection:

  INFRA-01 — TLS without SNI: client initiates TLS but omits the SNI extension,
             preventing hostname-based interception.

  INFRA-02 — Direct IP TLS without DNS: TLS connection to an IP for which no DNS
             answer was observed in the capture, consistent with hardcoded C2 IPs
             that bypass DNS entirely.

Both signals feed the composite scorer (engine_scoring.py) rather than triggering
high-severity standalone alerts, so they escalate only when combined with other
suspicious signals. A false-positive note is included in every alert because DNS
caching before capture start legitimately hides DNS resolutions.
"""


class EngineInfraMixin:

    def check_infra_layers(self, record: dict) -> None:
        """Emit INFRA-01 / INFRA-02 signals for this flow record if applicable."""
        if record.get("whitelisted"):
            return

        # Only meaningful for records with observed TLS.
        certificates = record.get("certificates", [])
        if not certificates:
            return

        ip_dst = record.get("ip_dst", "")
        if not ip_dst or ip_dst == "--":
            return

        self._check_tls_no_sni(record, ip_dst)
        self._check_direct_ip_no_dns(record, ip_dst)

    # ------------------------------------------------------------------
    # INFRA-01: TLS without SNI
    # ------------------------------------------------------------------

    def _check_tls_no_sni(self, record: dict, ip_dst: str) -> None:
        """Emit tls_no_sni signal when TLS was observed but no SNI extension was sent.

        _cert_snis_seen is a set built during EVE parsing that collects every SNI
        value seen in ClientHello messages destined to this IP.  An empty set means
        the client opened at least one TLS session without announcing a hostname.
        """
        snis_seen = record.get("_cert_snis_seen", set())
        if snis_seen:
            return  # SNI was present — normal behaviour

        self._add_signal(record, "tls_no_sni", ip_dst)
        record["suspicious"] = True
        self.alerts.append({
            "title": f"TLS without SNI to {ip_dst}",
            "description": (
                f"A TLS connection to {ip_dst} was established without the SNI extension "
                "in the ClientHello. Mercenary spyware (Pegasus C2, Predator) deliberately "
                "omits SNI to prevent hostname-based filtering and traffic interception. "
                "This is a structural signal independent of any IOC list. "
                "Note: session resumptions are excluded; false positives are possible if "
                "the SNI is encrypted (TLS ECH) or if the connection predates the capture."
            ),
            "host": ip_dst,
            "level": "Low",
            "id": "INFRA-01",
        })

    # ------------------------------------------------------------------
    # INFRA-02: TLS to IP without prior DNS resolution
    # ------------------------------------------------------------------

    def _check_direct_ip_no_dns(self, record: dict, ip_dst: str) -> None:
        """Emit direct_ip_no_dns signal when TLS is made to an IP with no DNS match.

        _dns_domains is populated from EVE DNS answer events that resolved any
        domain name to this IP during the capture.  An empty list means the device
        connected directly to the IP without (visible) DNS resolution.

        Pegasus v4+ separates install servers, DNS-based install servers, and C2
        servers.  C2 contacts are made directly to hardcoded IPs with no DNS lookup,
        making them invisible to domain-level blocking and IOC matching.
        """
        dns_domains = record.get("_dns_domains", [])
        if dns_domains:
            return  # DNS resolution was observed — expected path

        self._add_signal(record, "direct_ip_no_dns", ip_dst)
        record["suspicious"] = True
        self.alerts.append({
            "title": f"Direct TLS to {ip_dst} — no DNS resolution observed",
            "description": (
                f"TLS was established to {ip_dst} with no DNS answer for this IP seen in "
                "the capture. This matches the Pegasus v4+ C2 pattern: C2 servers are "
                "contacted by hardcoded IP, bypassing DNS and domain-based detection. "
                "False positives are common when DNS was resolved before the capture "
                "started (cached responses); combine with other signals before concluding."
            ),
            "host": ip_dst,
            "level": "Low",
            "id": "INFRA-02",
        })
