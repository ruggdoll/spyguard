#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Parse watchers from config and pull IOCs / whitelist / MISP; refresh Umbrella top-1M."""

from app.utils import get_watchers
from app.classes.iocs import IOCs
from app.classes.whitelist import WhiteList
from app.classes.misp import MISP

import io
import json
import os
import requests
import urllib3
import zipfile
import time
from datetime import datetime, timezone
from multiprocessing import Process


UMBRELLA_TOP1M_ZIP_URL = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
UMBRELLA_JSON_PATH = "/usr/share/spyguard/assets/umbrella-top-1m.json"

import csv
import datetime
import gzip as _gzip

# iptoasn.com is behind Cloudflare and blocks automated downloads.
# db-ip.com provides the same data (ip_start,ip_end,asn,org) under CC-BY 4.0.
_DBIP_ASN_TEMPLATE = "https://download.db-ip.com/free/dbip-asn-lite-{year}-{month:02d}.csv.gz"
IP2ASN_V4_TSV_GZ_PATH = "/usr/share/spyguard/assets/ip2asn-v4.tsv.gz"


def _dbip_asn_url() -> str:
    """Return the URL for this month's db-ip ASN lite file."""
    now = datetime.date.today()
    return _DBIP_ASN_TEMPLATE.format(year=now.year, month=now.month)


def download_umbrella_top1m_json():
    """Fetch Cisco Umbrella Top 1M (CSV in zip), write domains as JSON for analysis."""
    r = requests.get(UMBRELLA_TOP1M_ZIP_URL, timeout=180)
    r.raise_for_status()
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    csv_names = [n for n in zf.namelist() if n.lower().endswith(".csv")]
    if not csv_names:
        raise ValueError("No CSV found in Umbrella zip")
    domains = []
    with zf.open(csv_names[0]) as raw:
        for i, line in enumerate(raw):
            if i >= 1_000_000:
                break
            try:
                s = line.decode("utf-8", errors="replace").strip()
            except Exception:
                continue
            if not s or "," not in s:
                continue
            _, dom = s.split(",", 1)
            dom = dom.strip().lower().rstrip(".")
            if dom:
                domains.append(dom)
    payload = {
        "source": UMBRELLA_TOP1M_ZIP_URL,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "format": "rank,domain",
        "count": len(domains),
        "domains": domains,
    }
    os.makedirs(os.path.dirname(UMBRELLA_JSON_PATH), exist_ok=True)
    with open(UMBRELLA_JSON_PATH, "w", encoding="utf-8") as out:
        json.dump(payload, out, ensure_ascii=False)


def download_ip2asn_v4_tsv_gz():
    """Fetch db-ip.com ASN lite (CSV) and convert to iptoasn-compatible TSV.gz.

    db-ip.com format: ip_start,ip_end,asn,"org"
    Output TSV format: ip_start\tip_end\tasn\t\torg  (5 columns, country left blank)
    """
    url = _dbip_asn_url()
    r = requests.get(url, timeout=600, stream=True,
                     headers={"User-Agent": "SpyGuard/2.0 (https://github.com/SpyGuard)"})
    r.raise_for_status()
    raw_gz = io.BytesIO()
    for chunk in r.iter_content(chunk_size=1024 * 1024):
        if chunk:
            raw_gz.write(chunk)
    raw_gz.seek(0)

    os.makedirs(os.path.dirname(IP2ASN_V4_TSV_GZ_PATH), exist_ok=True)
    tmp = IP2ASN_V4_TSV_GZ_PATH + ".part"
    with _gzip.open(raw_gz, "rt", encoding="utf-8", errors="replace") as src, \
         _gzip.open(tmp, "wt", encoding="utf-8") as dst:
        reader = csv.reader(src)
        for row in reader:
            if len(row) < 3:
                continue
            ip_start, ip_end, asn = row[0].strip(), row[1].strip(), row[2].strip()
            org = row[3].strip() if len(row) >= 4 else ""
            dst.write("{}\t{}\t{}\t\t{}\n".format(ip_start, ip_end, asn, org))
    os.replace(tmp, IP2ASN_V4_TSV_GZ_PATH)


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def watch_iocs():
    """
        Retrieve IOCs from the remote URLs defined in config/watchers.
        For each IOC, add it to the DB.
    """

    watchers = [{"url": w["url"], "status": False} for w in get_watchers("iocs")]

    while True:
        for w in watchers:
            if w["status"] == False:
                iocs = IOCs()
                iocs_list = []
                to_delete = []
                try:
                    res = requests.get(w["url"], verify=False)
                    if res.status_code == 200:
                        content = json.loads(res.content)
                        iocs_list = content["iocs"] if "iocs" in content else []
                        to_delete = content["to_delete"] if "to_delete" in content else []
                    else:
                        w["status"] = False
                except:
                    w["status"] = False

                for ioc in iocs_list:
                    try:
                        iocs.add(ioc["type"], ioc["tag"],
                                 ioc["tlp"], ioc["value"], "watcher")
                        w["status"] = True
                    except:
                        continue

                for ioc in to_delete:
                    try:
                        iocs.delete_by_value(ioc["value"])
                        w["status"] = True
                    except:
                        continue

        # If at least one URL haven't be parsed, let's retry in 1min.
        if False in [w["status"] for w in watchers]:
            time.sleep(60)
        else:
            break


def watch_whitelists():
    """
        Retrieve whitelist elements from the remote URLs
        defined in config/watchers. For each (new ?) element,
        add it to the DB.
    """

    watchers = [{"url": w["url"], "status": False} for w in get_watchers("whitelist")]

    while True:
        for w in watchers:
            if w["status"] == False:
                whitelist = WhiteList()
                elements = []
                to_delete = []
                try:
                    res = requests.get(w["url"], verify=False)
                    if res.status_code == 200:
                        content = json.loads(res.content)
                        elements = content["elements"] if "elements" in content else []
                        to_delete = content["to_delete"] if "to_delete" in content else []
                    else:
                        w["status"] = False
                except:
                    w["status"] = False

                for elem in elements:
                    try:
                        whitelist.add(elem["type"], elem["element"], "watcher")
                        w["status"] = True
                    except:
                        continue

                for elem in to_delete:
                    try:
                        whitelist.delete_by_value(elem["element"])
                        w["status"] = True
                    except:
                        continue

        if False in [w["status"] for w in watchers]:
            time.sleep(60)
        else:
            break


def _misp_db_path() -> str:
    """Resolve the SQLite database path used by the admin API."""
    import sys as _sys
    db_url = os.environ.get("SPYGUARD_DB_URL", "")
    if db_url.startswith("sqlite:////"):
        return db_url[len("sqlite:////"):]
    parent = "/".join(_sys.path[0].split("/")[:-2])
    return os.path.join(parent, "database.sqlite3")


def _ensure_sync_log_table(db_path: str) -> None:
    """Create misp_sync_log if it does not yet exist (upgrade-safe)."""
    import sqlite3 as _sqlite3
    with _sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS misp_sync_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                misp_id    INTEGER NOT NULL,
                synced_at  NUMERIC NOT NULL,
                iocs_added INTEGER NOT NULL DEFAULT 0,
                status     TEXT NOT NULL,
                message    TEXT
            )
        """)
        conn.commit()


def _log_misp_sync(db_path: str, misp_id: int, iocs_added: int,
                   status: str, message: str = "") -> None:
    import sqlite3 as _sqlite3
    try:
        with _sqlite3.connect(db_path) as conn:
            conn.execute(
                "INSERT INTO misp_sync_log (misp_id, synced_at, iocs_added, status, message) "
                "VALUES (?, ?, ?, ?, ?)",
                (misp_id, int(time.time()), iocs_added, status, message),
            )
            conn.commit()
    except Exception as exc:
        print("[watch_misp] audit log write failed: {}".format(exc))


def watch_misp():
    """
    Retrieve IOCs from MISP instances on a configurable schedule.

    Runs indefinitely: syncs all configured instances, then sleeps for
    backend.misp_sync_interval_hours (default 6) before repeating.
    Each sync attempt is recorded in misp_sync_log for audit purposes.
    """
    from app.utils import read_config as _read_config
    db_path = _misp_db_path()
    _ensure_sync_log_table(db_path)

    sync_interval_hours = _read_config(("backend", "misp_sync_interval_hours")) or 6
    sync_interval_seconds = int(sync_interval_hours) * 3600

    while True:
        iocs, misp = IOCs(), MISP()
        pending = list(misp.get_instances())

        # Retry loop: keep trying unreachable instances until all succeed or we give up.
        max_retries = 5
        retry = 0
        while pending and retry < max_retries:
            still_pending = []
            for ist in pending:
                reachable = misp.test_instance(ist["url"], ist["apikey"], ist["verifycert"])
                if reachable:
                    added = 0
                    try:
                        for ioc in misp.get_iocs(ist["id"]):
                            iocs.add(ioc["type"], ioc["tag"], ioc["tlp"],
                                     ioc["value"], "misp-{}".format(ist["id"]))
                            added += 1
                        misp.update_sync(ist["id"])
                        _log_misp_sync(db_path, ist["id"], added, "ok",
                                       "Synced {} IOC(s)".format(added))
                        print("[watch_misp] instance {} synced: {} IOC(s) added".format(
                            ist["id"], added))
                    except Exception as exc:
                        _log_misp_sync(db_path, ist["id"], added, "error", str(exc))
                        print("[watch_misp] instance {} error: {}".format(ist["id"], exc))
                else:
                    still_pending.append(ist)

            pending = still_pending
            if pending:
                retry += 1
                time.sleep(60)

        for ist in pending:
            _log_misp_sync(db_path, ist["id"], 0, "unreachable",
                           "Instance unreachable after {} retries".format(max_retries))
            print("[watch_misp] instance {} unreachable, skipped".format(ist["id"]))

        print("[watch_misp] next sync in {} hour(s)".format(sync_interval_hours))
        time.sleep(sync_interval_seconds)


from app.classes.mvt import stix2_find_bundles as _stix2_find_bundles
from app.classes.mvt import extract_stix2_iocs as _extract_stix2_iocs


def watch_mvt_indicators():
    """Periodically fetch STIX2 IOC bundles from the MVT/Amnesty indicators index.

    Downloads mvt-project/mvt-indicators/main/indicators.yaml, resolves every
    stix2_url entry, parses domain-name / ipv4-addr / url / indicator objects,
    and stores results in the IOC database tagged as 'spyware' with source
    label 'mvt-<bundle_name>'.

    Interval: backend.mvt_sync_interval_hours (default 24h).
    """
    import yaml as _yaml
    from app.utils import read_config as _read_config
    from app.classes.iocs import IOCs as _IOCs

    MVT_INDEX_URL = (
        "https://raw.githubusercontent.com/mvt-project/"
        "mvt-indicators/main/indicators.yaml"
    )

    sync_interval_hours = _read_config(("backend", "mvt_sync_interval_hours")) or 24
    sync_interval_seconds = int(sync_interval_hours) * 3600

    while True:
        print("[watch_mvt] starting sync")
        total_added = 0
        try:
            r = requests.get(MVT_INDEX_URL, timeout=30,
                             headers={"User-Agent": "SpyGuard/2.0"})
            r.raise_for_status()
            index = _yaml.safe_load(r.text)
            bundles = _stix2_find_bundles(index)
            print("[watch_mvt] found {} STIX2 bundle(s) in index".format(len(bundles)))
        except Exception as exc:
            print("[watch_mvt] failed to fetch/parse indicators index: {}".format(exc))
            time.sleep(sync_interval_seconds)
            continue

        iocs = _IOCs()
        for url, label in bundles:
            try:
                br = requests.get(url, timeout=60,
                                  headers={"User-Agent": "SpyGuard/2.0"})
                br.raise_for_status()
                bundle = json.loads(br.text)
            except Exception as exc:
                print("[watch_mvt] failed to fetch bundle {}: {}".format(url, exc))
                continue

            added_this_bundle = 0
            for ioc_type, value in _extract_stix2_iocs(bundle, label):
                try:
                    iocs.add(ioc_type, "spyware", "white", value, label)
                    added_this_bundle += 1
                except Exception:
                    pass
            total_added += added_this_bundle
            print("[watch_mvt] {}: {} IOC(s) added".format(label, added_this_bundle))

        print("[watch_mvt] sync complete: {} total IOC(s) — next in {}h".format(
            total_added, sync_interval_hours))
        time.sleep(sync_interval_seconds)


try:
    download_umbrella_top1m_json()
except Exception as exc:
    print("[watchers] Cisco Umbrella top-1m download failed: {}".format(exc))

try:
    download_ip2asn_v4_tsv_gz()
except Exception as exc:
    print("[watchers] ip2asn-v4.tsv.gz download failed: {}".format(exc))

p1 = Process(target=watch_iocs)
p2 = Process(target=watch_whitelists)
p3 = Process(target=watch_misp)
p4 = Process(target=watch_mvt_indicators)

p1.start()
p2.start()
p3.start()
p4.start()
