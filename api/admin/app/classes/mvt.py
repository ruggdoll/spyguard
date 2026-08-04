#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Helpers for fetching and parsing MVT/Amnesty STIX2 IOC bundles."""

import json
import re
from urllib.parse import urlparse


_GITHUB_RAW = "https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"


def stix2_find_bundles(index: dict) -> list:
    """Return a list of (url, label) from an MVT indicators.yaml dict.

    Handles two formats:
    - Legacy:  {"stix2_url": "https://..."}  anywhere in the tree
    - Current: {"type": "github", "name": "...", "github": {owner, repo, branch, path}}
               at the top-level indicators list
    """
    results = []
    seen_urls = set()

    def _add(url: str, label: str) -> None:
        if url and url not in seen_urls:
            seen_urls.add(url)
            results.append((url, label))

    # Current format: top-level indicators list with github dicts
    for entry in index.get("indicators", []):
        if not isinstance(entry, dict):
            continue
        gh = entry.get("github")
        name = entry.get("name", "")
        if isinstance(gh, dict):
            owner = gh.get("owner", "")
            repo = gh.get("repo", "")
            branch = gh.get("branch", "main")
            path = gh.get("path", "")
            if owner and repo and path:
                url = _GITHUB_RAW.format(owner=owner, repo=repo,
                                         branch=branch, path=path)
                # Derive a short label from the name or filename
                label = "mvt-" + (
                    path.rsplit("/", 1)[-1].rsplit(".", 1)[0].lower()
                    if not name else
                    name.lower()[:40].replace(" ", "_").replace("/", "_")
                )
                _add(url, label)

    # Legacy format: stix2_url key anywhere in the tree
    def _walk_legacy(obj: object) -> None:
        if isinstance(obj, dict):
            v = obj.get("stix2_url")
            if isinstance(v, str) and v.startswith("http"):
                fname = v.rstrip("/").split("/")[-1].rsplit(".", 1)[0].lower()
                _add(v, "mvt-" + fname)
            for val in obj.values():
                _walk_legacy(val)
        elif isinstance(obj, list):
            for item in obj:
                _walk_legacy(item)

    _walk_legacy(index)
    return results


def stix2_find_urls(obj, found=None):
    """Legacy helper — collect every stix2_url string value recursively.

    Kept for backward compatibility with existing tests.
    Use stix2_find_bundles() for the current MVT indicators.yaml format.
    """
    if found is None:
        found = []
    if isinstance(obj, dict):
        v = obj.get("stix2_url")
        if isinstance(v, str) and v.startswith("http"):
            found.append(v)
        for val in obj.values():
            stix2_find_urls(val, found)
    elif isinstance(obj, list):
        for item in obj:
            stix2_find_urls(item, found)
    return found


def extract_stix2_iocs(bundle_json: dict, source_label: str):
    """Yield (ioc_type, value) pairs from a STIX2 bundle dict.

    Accepted STIX object types (network-observable only):
        domain-name  → domain
        ipv4-addr    → ip4addr
        ipv6-addr    → ip6addr
        url          → extract hostname → domain
        indicator    → regex extraction of domain/IP from STIX2 pattern field

    Non-network types (process, file, email-addr, android-property,
    configuration-profile, etc.) are counted per type and reported via print
    so callers know what was silently skipped.
    """
    skipped_types = {}
    for obj in bundle_json.get("objects", []):
        otype = obj.get("type", "")
        if otype == "domain-name":
            v = (obj.get("value") or "").strip().lower().rstrip(".")
            if v:
                yield ("domain", v)
        elif otype == "ipv4-addr":
            v = (obj.get("value") or "").strip()
            if v:
                yield ("ip4addr", v)
        elif otype == "ipv6-addr":
            v = (obj.get("value") or "").strip()
            if v:
                yield ("ip6addr", v)
        elif otype == "url":
            raw = (obj.get("value") or "").strip()
            try:
                host = urlparse(raw).hostname or ""
                host = host.lower().rstrip(".")
                if host:
                    yield ("domain", host)
            except Exception:
                pass
        elif otype == "indicator":
            pattern = obj.get("pattern") or ""
            for dom in re.findall(r"domain-name:value\s*=\s*'([^']+)'", pattern):
                yield ("domain", dom.strip().lower().rstrip("."))
            for ip in re.findall(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern):
                yield ("ip4addr", ip.strip())
            for ip in re.findall(r"ipv6-addr:value\s*=\s*'([^']+)'", pattern):
                yield ("ip6addr", ip.strip())
        else:
            skipped_types[otype] = skipped_types.get(otype, 0) + 1

    if skipped_types:
        summary = ", ".join("{}×{}".format(c, t) for t, c in skipped_types.items())
        print("[watch_mvt] {}: skipped non-network STIX types: {}".format(
            source_label, summary))
