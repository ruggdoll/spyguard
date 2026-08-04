#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class Signal:
    name: str
    weight: float
    label: str = ""   # human-readable context (e.g. domain name)


DEFAULT_WEIGHTS: Dict[str, float] = {
    # TLS signals
    "cert_free_ca":          2.0,   # Let's Encrypt / ZeroSSL
    "cert_self_signed":      3.0,
    "cert_issuer_ioc":       4.0,
    "cert_hash_ioc":         4.0,
    "tls_nonstandard_port":  1.5,
    "jarm_ioc":              4.0,
    "ja3_ioc":               5.0,   # T2
    "ja4_ioc":               5.0,   # T2
    # DNS / domain signals
    "domain_freedns":        3.0,
    "domain_recent_6mo":     2.0,   # registered < 6 months ago
    "domain_recent_1yr":     1.0,   # registered < 1 year ago
    "domain_suspicious_ns":  2.0,
    "domain_suspicious_tld": 1.0,
    "domain_mimicry":        3.0,   # T6: media keyword + geo term in domain name
    # Protocol / flow signals
    "proto_nonstandard_port": 1.0,
    "proto_http_plain":       1.0,
    # Infrastructure layer signals (T5) — structural, IOC-list-independent
    "tls_no_sni":             3.0,   # TLS ClientHello without SNI extension
    "direct_ip_no_dns":       2.5,   # TLS to IP with no DNS answer seen in capture
}

# Score thresholds for level upgrade (normal mode)
UPGRADE_MODERATE_THRESHOLD = 4.0   # Low  -> Moderate when record score >= 4
UPGRADE_HIGH_THRESHOLD     = 8.0   # Moderate -> High when record score >= 8

# Hardened thresholds applied during an active post-exposure quarantine window.
# Lowered so that fewer signals are needed to escalate — infrastructure rebuilt
# after a major CTI publication tends to reuse recognizable registration patterns.
QUARANTINE_MODERATE_THRESHOLD = 2.5
QUARANTINE_HIGH_THRESHOLD     = 6.0
