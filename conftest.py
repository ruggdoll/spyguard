"""Root conftest.py — executed before any test file or import.

Sets environment variables and creates temporary fixtures (SQLite DB, YAML
config) BEFORE the Flask app modules are imported, so that module-level
SQLAlchemy engine creation and config path resolution use the test values.
"""

import hashlib
import os
import pathlib
import sqlite3
import sys
import tempfile

import yaml

# ---------------------------------------------------------------------------
# 1. Create temp files and set env vars — MUST happen before app imports.
# ---------------------------------------------------------------------------

_tmp_dir = tempfile.mkdtemp(prefix="spyguard_test_")
_db_path = os.path.join(_tmp_dir, "database.sqlite3")
_config_path = os.path.join(_tmp_dir, "config.yaml")
_watchers_path = os.path.join(_tmp_dir, "watchers.yaml")

os.environ.setdefault("SPYGUARD_DB_URL", f"sqlite:///{_db_path}")
os.environ.setdefault("SPYGUARD_CONFIG_PATH", _config_path)
os.environ.setdefault("SPYGUARD_WATCHERS_PATH", _watchers_path)

# ---------------------------------------------------------------------------
# 2. Initialise SQLite schema before models.py autoloads the tables.
# ---------------------------------------------------------------------------

_schema_sql = (pathlib.Path(__file__).parent / "assets" / "scheme.sql").read_text()
_conn = sqlite3.connect(_db_path)
_conn.executescript(_schema_sql)
_conn.close()

# ---------------------------------------------------------------------------
# 3. Write minimal test config and empty watchers file.
# ---------------------------------------------------------------------------

TEST_LOGIN = "testadmin"
TEST_PASSWORD = "testpassword"
_password_hash = hashlib.sha256(TEST_PASSWORD.encode()).hexdigest()

_test_config = {
    "analysis": {
        "active": True,
        "heuristics": True,
        "http_default_ports": [80],
        "indicators_types": ["all"],
        "iocs": True,
        "max_ports": 1024,
        "remote": False,
        "tls_default_ports": [443],
        "whitelist": True,
    },
    "backend": {
        "login": TEST_LOGIN,
        "password": _password_hash,
        "remote_access": False,
    },
    "frontend": {
        "backend_option": True,
        "capture_export": "server",
        "download_links": False,
        "http_port": 8000,
        "remote_access": False,
        "shutdown_option": False,
        "slideshow": False,
        "sparklines": False,
        "spyguard_server": "https://spyguard.net",
        "ui_zoom": 100,
        "update": False,
        "user_lang": "en",
        "virtual_keyboard": False,
    },
    "network": {
        "in": "wlan0",
        "internet_check": "https://example.net",
        "out": "eth0",
        "ssids": ["TestNet"],
        "tokenized_ssids": True,
    },
    "project": {
        "path": _tmp_dir,
        "tags_url": "https://api.github.com/repos/SpyGuard/spyguard/tags",
    },
}

with open(_config_path, "w") as _f:
    yaml.dump(_test_config, _f)

with open(_watchers_path, "w") as _f:
    yaml.dump({"watchers": []}, _f)

# ---------------------------------------------------------------------------
# 4. Add api/admin to sys.path so Flask module imports ("from app import ...")
#    resolve correctly, mirroring how the service runs in production.
# ---------------------------------------------------------------------------

_admin_api_dir = str(pathlib.Path(__file__).parent / "api" / "admin")
if _admin_api_dir not in sys.path:
    sys.path.insert(1, _admin_api_dir)

# ---------------------------------------------------------------------------
# 5. Import Flask app and configure for testing.
# ---------------------------------------------------------------------------

import datetime

import jwt
import pytest

from main import app as _flask_app

TEST_SECRET = b"spyguard-pytest-secret"
_flask_app.config["TESTING"] = True
_flask_app.config["SECRET_KEY"] = TEST_SECRET


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _make_token() -> str:
    payload = {"exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
    token = jwt.encode(payload, TEST_SECRET)
    return token.decode("utf-8") if isinstance(token, bytes) else token


@pytest.fixture
def client():
    with _flask_app.test_client() as c:
        yield c


@pytest.fixture
def auth_headers():
    return {"X-Token": _make_token()}


@pytest.fixture(autouse=True)
def clean_db():
    """Truncate all DB tables before each test for full isolation."""
    from app import db
    from app.db.models import Ioc, MISPInst, Whitelist

    yield

    db.session.rollback()
    db.session.query(Ioc).delete()
    db.session.query(Whitelist).delete()
    db.session.query(MISPInst).delete()
    db.session.commit()
