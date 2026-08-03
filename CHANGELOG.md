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

### Task 5 — Découper engine.py (2361 lignes) en modules

#### Objectif
`analysis/classes/engine.py` faisait 2361 lignes et mêlait initialisation, logique TLS,
enrichissement DNS/WHOIS, et orchestration. Divisé en 3 modules par rôle, sans changer
aucun comportement observable.

#### Fichiers créés
- `analysis/classes/engine_types.py` (275 lignes) — Types partagés : 3 fonctions module-level
  (`_whitelist_asn_elements_to_int_set`, `_iter_domain_suffixes`, `_normalize_dn`) et les
  dataclasses/classes `EngineConfig`, `WhitelistIndex`, `IOCIndex`.
- `analysis/classes/engine_tls.py` (511 lignes) — `EngineTLSMixin` : 17 méthodes TLS/SSL
  (`active_check_ssl`, `check_tls`, `_precheck_active_ssl`, helpers cert/SNI, etc.).
- `analysis/classes/engine_dns.py` (731 lignes) — `EngineDNSMixin` : 15 méthodes DNS/domaine
  (`check_domains`, `check_dnsname`, `check_http`, `_prefetch_domain_enrichments`,
  `_check_umbrella_popularity`, `_ipthc_first_domain`, etc.).

#### Fichier modifié
- `analysis/classes/engine.py` (900 lignes) — Réduit à `class Engine(EngineTLSMixin, EngineDNSMixin):`
  avec uniquement les méthodes non déléguées : `__init__`, `start_engine`, `parse_eve_file`,
  `check_flow`, `check_whitelist`, `get_alerts`, `get_tor_nodes`, et les helpers d'orchestration.
  Imports nettoyés (suppression de `subprocess`, `ssl`, `socket`, `OpenSSL`, `pydig`, `whois`,
  `publicsuffix2`, `get_jarm` qui sont dans les mixins).

#### Vérification
```
MRO: ['Engine', 'EngineTLSMixin', 'EngineDNSMixin', 'object']
20 passed, 4 xfailed
```

### Task 6 — Migrer l'appel analysis de subprocess vers import Python direct

#### Problème
`api/capture/app/classes/analysis.py` lançait `sp.Popen([sys.executable, ".../analysis.py", token])`
— un processus fils séparé, sans retour d'erreur structuré, avec un calcul de chemin fragile
basé sur `sys.path[0]`.

#### Correctifs prérequis (chemin basé sur `__file__`)
- `analysis/utils.py` : `sys.argv[0]` → `__file__` pour trouver la racine du projet
  (chemin vers `database.sqlite3` et `config.yaml`)
- `analysis/classes/engine.py` : `sys.argv[0]` → `__file__` pour trouver `locales/`
- `analysis/analysis.py` : chemin hardcodé `/usr/share/spyguard/api/capture` remplacé
  par un chemin relatif à `__file__`, avec fallback sur `logging.getLogger` si le module
  de log n'est pas importable

#### Migration
- `api/capture/app/classes/analysis.py` :
  - Calcul dynamique de `analysis/` via `__file__` → injection dans `sys.path`
  - `import analysis as _analysis_module`
  - `Analysis.start()` : `sp.Popen(cmd)` → `threading.Thread(target=_analysis_module.analyze, daemon=True).start()`
  - Les exceptions du thread sont capturées et loggées, sans planter le processus Flask
- `api/capture/app/blueprints/analysis.py` : suppression de l'import `subprocess` inutilisé
- `api/capture/app/__init__.py` : même migration SQLAlchemy 2.0 que l'admin API
  (`MetaData(bind=)` supprimé, `convert_unicode` supprimé, `mapper` supprimé)

#### Tests après tâche 6
```
20 passed, 4 xfailed, 0 warnings
```

### Task 4 — Mise à jour et harmonisation des dépendances

#### Python
- `PyJWT 1.7.1 → 2.13.0` — `jwt.encode()` retourne désormais `str` (plus `bytes`). Nettoyage du
  code `.decode("utf8") if type(token) == bytes else token` dans `main.py` et `conftest.py`.
  `datetime.datetime.utcnow()` remplacé par `datetime.datetime.now(datetime.timezone.utc)`.
- `SQLAlchemy 1.4.44 → 2.0.51` — Migration des APIs supprimées en 2.0 :
  - `mapper()` → `registry().map_imperatively()` dans `app/db/models.py`
  - `MetaData(bind=engine)` → `MetaData()` dans `app/__init__.py` et `app/db/__init__.py`
  - `Table(..., autoload=True)` → `Table(..., autoload_with=engine)`
  - `create_engine(url, convert_unicode=True)` → `create_engine(url)`
  - `sessionmaker(bind=engine, autocommit=False, autoflush=False)` → `sessionmaker(engine, autoflush=False)`
  - Le style de requête "legacy" (`session.query()`) reste utilisé ; il fonctionne en 2.0.

#### JavaScript
- `ui/admin/package.json` : `axios ^0.21.1 → ^1.15.0`, aligné sur `ui/capture/package.json`

#### Tests après tâche 4
```
20 passed, 4 xfailed, 0 warnings
```

### Fix catch-all route masking 405 responses

#### Problem
`api/admin/main.py` registered `GET /<p>/<path:path>` (static asset serving) before the API
blueprints. Any GET request to an API path whose blueprint only accepts DELETE/PATCH was
intercepted by the catch-all and returned 401 (auth gate) instead of 405 Method Not Allowed.
This masked the 4 xfailed tests from task 9.

#### Fix
Replaced the bare `<p>` segment with a custom Werkzeug converter `_AssetFolderConverter`
whose regex only matches the known asset folders (`assets|css|fonts|js|img`). The pattern
`/<asset_folder:p>/<path:path>` never fires for `/api/…` URLs, so Flask's URL map now
correctly returns 405 for GET requests on DELETE/PATCH-only blueprint routes.

Removed the `@pytest.mark.xfail` markers from the 4 tests that now pass cleanly.

#### Test results
```
84 passed, 0 xfailed
```

### Task 7 — Compléter la suite de tests (vitest + couverture engine)

#### Python — nouveaux fichiers de tests

- `tests/api/admin/test_misp.py` (8 tests) — Auth, get-all, add (mock PyMISP), add failure,
  add duplicate, delete nonexistent, delete existing.
- `tests/api/admin/test_watchers.py` (7 tests) — Auth, get-all, add, duplicate rejection,
  delete. Fixture `clean_watchers` (autouse) resets le singleton `watcher.watchers` et le
  fichier YAML après chaque test.
- `tests/api/admin/test_update.py` (7 tests) — Version publique, auth, check (mock
  `requests.get` avec réponse GitHub-like), update-to-date, erreur réseau, process (mock
  `subprocess.Popen`).
- `tests/analysis/__init__.py` + `tests/analysis/conftest.py` — Injecte `analysis/` dans
  `sys.path` pour les imports directs sans chemin d'installation.
- `tests/analysis/test_engine_types.py` (36 tests) — Couvre `_iter_domain_suffixes`,
  `_normalize_dn`, `_whitelist_asn_elements_to_int_set`, `WhitelistIndex`, `IOCIndex`.

#### JavaScript — vitest pour le panneau admin

- `ui/admin/package.json` — ajout `vitest`, `@vue/test-utils`, `happy-dom` en devDependencies ;
  scripts `test` et `test:watch`.
- `ui/admin/vite.config.js` — bloc `test: { environment: 'happy-dom', globals: true }`.
- `ui/admin/src/tests/iocs-manage.test.js` (5 tests) — Monte le composant, vérifie l'état
  initial des onglets, `switch_tab`, validation `type_tag_error`, appel `axios.post`.
- `ui/admin/src/tests/edit-configuration.test.js` (2 tests) — Teste les méthodes
  `switch_config` et `change_spyguard_server` directement sans monter le template
  (le template nécessite un objet `config` complet) via `Component.methods.fn.call({…})`.

#### CI/CD

- `.github/workflows/ci.yml` — deux jobs : `python-tests` (pytest sur Python 3.12) et
  `vue-admin-tests` (vitest sur Node 20), déclenchés sur push/PR vers `main`/`master`.

#### Test results
```
84 passed, 0 xfailed  (pytest)
2 test files, 7 tests  (vitest)
```

### Task 8 — Environnement Docker pour le développement

#### Fichiers créés

- `docker-compose.dev.yml` — 4 services :
  - `admin-api` (toujours actif) : Flask admin sur le port 8443 en HTTP (pas de TLS en dev).
  - `admin-ui` (toujours actif) : Vite dev server sur le port 4201 avec hot-reload.
  - `capture-api` (profil `capture`) : Flask capture sur le port 8000. Nécessite
    `--network host` + `CAP_NET_RAW` pour le vrai WiFi ; l'API démarre sans eux.
  - `capture-ui` (profil `capture`) : Vite dev server sur le port 4202.
- `docker/dev-config.yaml` — Config de développement : `remote_access: false` (HTTP),
  identifiants `admin` / `spyguard`.
- `docker/admin-api/Dockerfile` + `entrypoint.sh` — Python 3.12-slim, installe
  `requirements.txt`, initialise le schéma SQLite au premier démarrage.
- `docker/capture-api/Dockerfile` + `entrypoint.sh` — Idem + `libudev-dev` pour `pyudev`.
- `docker/admin-ui/Dockerfile` — Node 20-slim, `npm ci` ; source montée en volume pour le
  hot-reload (node_modules reste dans l'image).
- `docker/capture-ui/Dockerfile` — Idem pour le Capture UI.
- `.dockerignore` — Exclut `.venv/`, `node_modules/`, `dist/`, `*.sqlite3`, `.git/`.

#### Fichiers modifiés

- `ui/admin/vite.config.js` — cible du proxy lisible via `SPYGUARD_ADMIN_API_URL`
  (défaut : `https://localhost:5000` pour le dev local hors Docker).
- `ui/capture/vite.config.js` — idem avec `SPYGUARD_CAPTURE_API_URL`
  (défaut : `http://localhost:8040`).

#### Usage
```bash
# Admin seulement (cas le plus courant)
docker compose -f docker-compose.dev.yml up --build

# Tout inclus (capture nécessite host network + privilèges)
docker compose -f docker-compose.dev.yml --profile capture up --build
```
Accès : `http://localhost:4201` — login `admin` / `spyguard`.

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
