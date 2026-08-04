#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sqlite3
import datetime
import yaml
import sys
import json
import os
from functools import reduce

# I'm not going to use an ORM for that.
parent = os.path.split(os.path.dirname(os.path.abspath(__file__)))[0]
_db_path = os.path.join(parent, "database.sqlite3")


def get_iocs(ioc_type):
    """
        Get a list of IOCs specified by their type.
        :return: list of IOCs
    """
    with sqlite3.connect(_db_path) as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT value, tag FROM iocs WHERE type = ? ORDER BY value", (ioc_type,))
        res = cur.fetchall()
    return [[r[0], r[1]] for r in res] if res is not None else []


def get_whitelist(elem_type):
    """
        Get a list of whitelisted elements specified by their type.
        :return: list of elements
    """
    with sqlite3.connect(_db_path) as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT element FROM whitelist WHERE type = ? ORDER BY element", (elem_type,))
        res = cur.fetchall()
    return [r[0] for r in res] if res is not None else []


def get_config(path):
    """
        Read a value from the configuration
        :return: value (it can be any type)
    """
    config = yaml.load(open(os.path.join(parent, "config.yaml"),
                            "r"), Loader=yaml.SafeLoader)
    return reduce(dict.get, path, config)


def get_device(token):
    """
        Read the device configuration from device.json file.
        :return: dict - the device configuration
    """
    try:
        with open("/tmp/{}/device.json".format(token), "r") as f:
            return json.load(f)
    except:
        pass


def get_apname():
    """
        Read the current name of the Access Point from
        the hostapd configuration file
        :return: str - the AP name
    """
    try:
        with open("/tmp/hostapd.conf", "r") as f:
            for l in f.readlines():
                if "ssid=" in l:
                    return l.replace("ssid=", "").strip()
    except:
        pass
