#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import sys
import threading

from app.spyguard_logging import get_logger

# Add analysis/ to sys.path so `import analysis` resolves to analysis/analysis.py.
_ANALYSIS_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "analysis")
)
if _ANALYSIS_DIR not in sys.path:
    sys.path.insert(0, _ANALYSIS_DIR)

import analysis as _analysis_module  # noqa: E402  (import after sys.path mutation)


class Analysis(object):

    def __init__(self, token):
        self.token = token if re.match(r"[A-F0-9]{8}", token) else None
        self.log = get_logger()

    def start(self) -> dict:
        """Start the analysis of the captured communication by calling
        analysis.analyze() in a background thread.

        Returns:
            dict: operation status
        """
        if self.token is None:
            self.log.warning("analysis start with bad token")
            return {"status": False, "message": "Bad token provided", "token": "null"}

        capture_folder = "/tmp/{}".format(self.token)
        token = self.token
        log = self.log

        def _run() -> None:
            try:
                _analysis_module.analyze(capture_folder)
            except Exception:
                log.exception("analysis failed token=%s", token)

        t = threading.Thread(target=_run, daemon=True, name="analysis-{}".format(token))
        t.start()
        self.log.info("analysis started token=%s folder=%s", token, capture_folder)
        return {"status": True, "message": "Analysis started", "token": token}

    def get_report(self) -> dict:
        """Generate a small json report of the analysis
        containing the alerts and the device properties.

        Returns:
            dict: alerts, pcap and device info.
        """

        device, alerts, pcap = {}, {}, {}
        methods = {}
        records = []

        # Getting device configuration.
        if os.path.isfile("/tmp/{}/assets/device.json".format(self.token)):
            with open("/tmp/{}/assets/device.json".format(self.token), "r") as f:
                device = json.load(f)

        # Getting pcap infos.
        if os.path.isfile("/tmp/{}/assets/capinfos.json".format(self.token)):
            with open("/tmp/{}/assets/capinfos.json".format(self.token), "r") as f:
                pcap = json.load(f)

        # Getting alerts configuration.
        if os.path.isfile("/tmp/{}/assets/alerts.json".format(self.token)):
            with open("/tmp/{}/assets/alerts.json".format(self.token), "r") as f:
                alerts = json.load(f)

        # Getting detection methods.
        if os.path.isfile("/tmp/{}/assets/detection_methods.json".format(self.token)):
            with open("/tmp/{}/assets/detection_methods.json".format(self.token), "r") as f:
                methods = json.load(f)

        # Getting records.
        if os.path.isfile("/tmp/{}/assets/records.json".format(self.token)):
            with open("/tmp/{}/assets/records.json".format(self.token), "r") as f:
                records = json.load(f)

        analysis_meta = {}
        if os.path.isfile("/tmp/{}/assets/analysis_meta.json".format(self.token)):
            with open("/tmp/{}/assets/analysis_meta.json".format(self.token), "r") as f:
                analysis_meta = json.load(f)

        if device != {} and alerts != {}:
            self.log.info(
                "analysis report ready token=%s alerts=%s records=%s",
                self.token,
                {k: len(v) for k, v in (alerts or {}).items() if isinstance(v, list)},
                len(records or []),
            )
            return {
                "alerts": alerts,
                "device": device,
                "methods": methods,
                "pcap": pcap,
                "records": records,
                "analysis_meta": analysis_meta,
            }
        else:
            return {"message": "No report yet"}
