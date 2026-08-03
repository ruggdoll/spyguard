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

### Task 9 — Fix HTTP verbs (GET → correct REST verbs for mutations)

#### Flask blueprints changed
- `api/admin/app/blueprints/ioc.py` — removed legacy `GET /add/<...>` route; `GET /delete/<id>` → `DELETE /delete/<id>`
- `api/admin/app/blueprints/whitelist.py` — removed `GET /add/<...>` route; added `POST /add_post`; `GET /delete/<id>` → `DELETE /delete/<id>`
- `api/admin/app/blueprints/config.py` — `GET /switch/<cat>/<key>` → `PATCH`; `GET /ioc-type/add/<tag>` → `POST /ioc-type/<tag>`; `GET /ioc-type/delete/<tag>` → `DELETE /ioc-type/<tag>`; `GET /edit/<cat>/<key>/<value>` → `PATCH /edit/<cat>/<key>` with JSON body `{"value": ...}`
- `api/admin/app/blueprints/misp.py` — `GET /delete/<id>` → `DELETE /delete/<id>`
- `api/admin/app/blueprints/watchers.py` — `GET /delete/<id>` → `DELETE /delete/<id>`
- `api/admin/app/blueprints/update.py` — `GET /process` → `POST /process`

#### Vue views updated
- `ui/admin/src/views/iocs-manage.vue` — `axios.get /add/...` → `axios.post /add_post` with JSON body
- `ui/admin/src/views/iocs-search.vue` — `axios.get /delete/<id>` → `axios.delete`
- `ui/admin/src/views/whitelist-manage.vue` — `axios.get /add/...` → `axios.post /add_post` with JSON body
- `ui/admin/src/views/whitelist-search.vue` — `axios.get /delete/<id>` → `axios.delete`
- `ui/admin/src/views/edit-configuration.vue` — all 6 `axios.get /config/switch` and `/config/edit` calls → `axios.patch` with JSON body
- `ui/admin/src/views/analysis-engine.vue` — `axios.get /config/switch` → `axios.patch`; `axios.get /ioc-type/add` → `axios.post`; `axios.get /ioc-type/delete` → `axios.delete`
- `ui/admin/src/views/instance-misp.vue` — `axios.get /misp/delete/<id>` → `axios.delete`
- `ui/admin/src/views/instance-watchers.vue` — `axios.get /watchers/delete/<id>` → `axios.delete`
- `ui/admin/src/views/update.vue` — `axios.get /update/process` → `axios.post`

#### Tests after task 9
```
20 passed, 4 xfailed
```
Remaining 4 xfail: "GET on mutation route should return 405" — masked by the `GET /<p>/<path:path>`
catch-all in `api/admin/main.py` which intercepts before Flask can return 405.

### Planned
- Fix HTTP verbs: GET → PATCH/PUT for all state-mutating routes (DONE — task 9)
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
