# Changelog

All notable changes to SpyGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `CLAUDE.md` — developer guide documenting architecture, setup, conventions, and detection flow
- `CHANGELOG.md` — this file, tracking structural improvements

### Changed
- Renamed `app/backend/` → `ui/admin/`, `app/frontend/` → `ui/capture/` — clarifies these are Vue UIs, not Flask backends
- Renamed `server/backend/` → `api/admin/`, `server/frontend/` → `api/capture/` — unambiguous pairing with the UIs they serve
- Updated all path references in `install.sh`, `update.sh`, `api/admin/main.py`, `api/capture/main.py`, `analysis/analysis.py`

### Added
- `conftest.py` — pytest root setup: creates temp SQLite DB + YAML config before any Flask import, adds `api/admin/` to sys.path, provides `client`, `auth_headers`, and `clean_db` fixtures
- `tests/api/admin/test_ioc.py` — 10 tests: auth, read-only routes (pass), mutation routes with correct verbs (xfail until task 9)
- `tests/api/admin/test_whitelist.py` — 5 tests: auth, read-only routes (pass), mutation routes with correct verbs (xfail until task 9)
- `tests/api/admin/test_config.py` — 6 tests: public config list (pass), PATCH switch/edit (xfail until task 9)
- `pytest.ini` and `requirements-dev.txt`

### Changed
- `api/admin/app/db/__init__.py`, `api/admin/app/__init__.py` — support `SPYGUARD_DB_URL` env var for test isolation
- `api/admin/app/utils.py` — `CONFIG_PATH` and `WATCHERS_PATH` read from `SPYGUARD_CONFIG_PATH` / `SPYGUARD_WATCHERS_PATH` env vars
- `api/admin/app/classes/config.py` — `_config_path()` now delegates to `CONFIG_PATH` from utils (env-var-aware)
- `api/admin/app/classes/watchers.py` — `get_watchers()` and `update_watchers()` now use `WATCHERS_PATH` from utils instead of computing from `sys.path[0]`
- `.venv/` created at project root (not committed)

### Test results baseline
```
15 passed, 9 xfailed (specification for task 9 — HTTP verb fixes)
```

### Planned
- Fix HTTP verbs: GET → PATCH/PUT for all state-mutating routes
- Update and harmonize Python/JS dependencies (PyJWT 2.x, SQLAlchemy 2.0, axios unified version)
- Split `analysis/classes/engine.py` (2361 lines) into focused sub-modules
- Replace subprocess call to `analysis/analysis.py` with a direct Python import
- Add test suite (pytest for Python, vitest for Vue)
- Add Docker Compose for development without hardware dependencies

## [2.0] — 2024

### Changed
- Major rewrite focused on stability and Suricata updates
- TLSv1.3 and JARM fingerprinting support
- Stalkerware monitoring managed by ECHAP

## [1.0] — 2022-11-06

- Initial fork of TinyCheck (Kaspersky Lab)
