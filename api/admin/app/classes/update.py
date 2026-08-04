#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from app.utils import read_config
import subprocess as sp
import requests
import json
import os


class Update(object):

    def __init__(self):
        self.project_url = read_config(("project", "tags_url"))
        self.app_path = read_config(("project", "path"))
        return None

    def check_version(self) -> dict:
        """ Check if a new version of SpyGuard is available 
            by quering the Github api and comparing the last
            tag inside the VERSION file.

        Returns:
            dict: dict containing the available versions.
        """
        try:
            
            res = requests.get(self.project_url)
            res = json.loads(res.content.decode("utf8"))

            with open(os.path.join(self.app_path, "VERSION")) as f:
                cv = f.read().strip()
                latest = res[0]["name"].strip()
                # VERSION may be a `git describe` string like "v2.1-6-gabcd123".
                # Extract the base tag (everything before the first "-N-g" suffix).
                base = cv.split("-")[0]
                if base == latest or cv == latest:
                    return {"status": True,
                            "message": "This is the latest version",
                            "current_version": cv}
                else:
                    return {"status": True,
                            "message": "A new version is available",
                            "current_version": cv,
                            "next_version": latest}
        except:
            return {"status": False,
                    "message": "Something went wrong (no API access nor version file)"}

    def get_current_version(self) -> dict:
        """ Get the current version of the Spyguard instance

        Returns:
            dict: current version or error.
        """
        try:
            with open(os.path.join(self.app_path, "VERSION")) as f:
                return {"status": True,
                        "current_version": f.read()}
        except:
            return {"status": False,
                    "message": "Something went wrong - no version file ?"}

    def update_instance(self) -> dict:
        """Launching update.sh to update SpyGuard

        Returns:
            dict: result of the operation
        """
        try:
            os.chdir(self.app_path)
            sp.Popen(["bash", os.path.join(self.app_path, "update.sh")])
            return {"status": True,
                    "message": "Update successfully launched"}
        except:
            return {"status": False,
                    "message": "Issue during the update"}
