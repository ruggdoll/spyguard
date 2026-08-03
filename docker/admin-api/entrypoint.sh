#!/bin/sh
set -e

DB_FILE="${SPYGUARD_DB_FILE:-/app/database.sqlite3}"

if [ ! -f "$DB_FILE" ]; then
    echo "Initializing database at $DB_FILE ..."
    python3 - <<'PYEOF'
import os, sqlite3
db = os.environ.get("SPYGUARD_DB_FILE", "/app/database.sqlite3")
schema = open("/app/assets/scheme.sql").read()
os.makedirs(os.path.dirname(os.path.abspath(db)), exist_ok=True)
with sqlite3.connect(db) as con:
    con.executescript(schema)
print("Database initialized.")
PYEOF
fi

cd /app/api/admin
exec python3 main.py
