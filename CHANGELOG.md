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
