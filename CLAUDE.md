# SpyGuard — Developer Guide

## What is SpyGuard?

SpyGuard is a network-based device compromise detection appliance. It intercepts WiFi traffic from a target device (smartphone, laptop, IoT) and analyzes it for IOC matches, Suricata alerts, and behavioral heuristics to detect spyware and stalkerware.

It is **not** a forensic tool — it only detects malware that communicates during the analysis window (recommended minimum: 30 minutes of active device use).

Fork of [TinyCheck](https://github.com/KasperskyLab/TinyCheck) (Kaspersky Lab). Current version: 2.0.

## Architecture Overview

The project has two independent Flask services and two Vue 3 UIs:

```
spyguard/
├── app/
│   ├── backend/      # Vue 3 UI — admin/management panel (port 4201 in dev)
│   └── frontend/     # Vue 3 UI — capture & analysis workflow (port 4202 in dev)
├── server/
│   ├── backend/      # Flask API — admin endpoints, JWT auth (port 8443, HTTPS)
│   └── frontend/     # Flask API — capture/analysis endpoints (port 8000, HTTP)
├── analysis/         # Detection engine (Suricata, IOC matching, heuristics, JARM)
└── assets/           # Static data: iocs.json, whitelist.json, scheme.sql, requirements.txt
```

> **Naming note:** The `app/backend` / `server/backend` pair manages SpyGuard's own
> configuration (admin UI + admin API). The `app/frontend` / `server/frontend` pair is
> what the end-user sees during a capture session (user UI + capture API). The naming
> is confusing and will be corrected — see CHANGELOG.md.

### Ports

| Service             | Port  | Auth         |
|---------------------|-------|--------------|
| Admin API (Flask)   | 8443  | Basic + JWT  |
| Capture API (Flask) | 8000  | None         |

### Installed path

Production install copies everything to `/usr/share/spyguard/`. Three systemd services
are created: `spyguard-backend`, `spyguard-frontend`, `spyguard-watchers`.

## Key Files

| File | Purpose |
|------|---------|
| `config.yaml` | Main runtime config (network interfaces, credentials hash, ports, flags) |
| `watchers.yaml` | External IOC/whitelist sources (GitHub raw URLs, polled by the watchers daemon) |
| `assets/requirements.txt` | Pinned Python dependencies — **do not unpin without testing** |
| `assets/scheme.sql` | SQLite schema (3 tables: iocs, whitelist, misp) |
| `analysis/classes/engine.py` | Core detection logic (Suricata, IOC matching, heuristics, DNS, JARM) |
| `analysis/classes/report.py` | PDF report generation via weasyprint |
| `server/backend/app/db/models.py` | SQLAlchemy ORM models |
| `server/backend/app/decorators.py` | Flask auth decorators (Basic + JWT) |
| `install.sh` | Full install script (Debian only, requires root) |

## Development Setup

### Prerequisites

- Debian-based Linux (Ubuntu, Kali, etc.)
- Python 3.10+, Node 18+
- For the capture/analysis parts: `suricata`, `tshark`, `NetworkManager`

### Python backend (dev mode)

```bash
cd /usr/share/spyguard   # or the repo root after install
python3 -m venv spyguard-venv
source spyguard-venv/bin/activate
pip install -r assets/requirements.txt

# Admin API
python server/backend/main.py

# Capture API
python server/frontend/main.py
```

### Vue frontends (dev mode)

```bash
# Admin UI (proxies to https://localhost:5000 by default in dev)
cd app/backend && npm install && npm run dev

# Capture UI (proxies to http://localhost:8040 by default in dev)
cd app/frontend && npm install && npm run dev
```

### Linting

```bash
# Python — no linter configured yet (TODO)

# Vue
cd app/backend && npm run lint
cd app/frontend && npm run lint
```

## Dependency Constraints

- `weasyprint==57.1` is **not** compatible with `pydyf>=0.11` — keep `pydyf==0.10.0`
- `PyJWT==1.7.1` uses the old API (`jwt.encode()` returns bytes) — upgrading to 2.x requires code changes in `server/backend/app/decorators.py`
- `SQLAlchemy==1.4.44` uses the 1.x ORM API — upgrading to 2.0 requires `Session` and `Query` API changes

## Code Conventions

- Flask blueprints live in `server/<service>/app/blueprints/`, business logic in `server/<service>/app/classes/`
- Config is read/written atomically via `server/backend/app/utils.py` (YAML, no schema validation)
- Database sessions are thread-local (SQLAlchemy `scoped_session`)
- Auth on the admin API: `@auth.login_required` (Basic) for login endpoint, `@require_header_token` (JWT) for all other routes
- The capture API has **no authentication** — assumes it runs on a local/isolated network

## Detection Flow

```
1. /api/capture/start    → dumpcap captures packets to a .pcap file
2. /api/capture/stop     → stops dumpcap
3. /api/analysis/run     → subprocess call to analysis/analysis.py <pcap_path>
4. analysis.py           → Engine.start_engine() → writes alerts.json, records.json
5. analysis.py           → Report.generate_pdf() → writes report.pdf
6. /api/analysis/results → frontend reads JSON outputs from capture folder
```

## IOC Data Sources

Managed by the watchers daemon (`server/backend/watchers.py`), configured in `watchers.yaml`:
1. SpyGuard IOCs — community IOC database
2. ECHAP — French stalkerware indicators (cyberviolence NGO)
3. SpyGuard whitelist — benign traffic whitelist

## Running Tests

*No tests exist yet — adding them is a planned improvement.*

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the history of structural improvements.
