#!/bin/sh
set -e

DB_FILE="/usr/share/spyguard/database.sqlite3"

if [ ! -f "$DB_FILE" ]; then
    echo "Initializing database at $DB_FILE ..."
    python3 - <<'PYEOF'
import sqlite3
schema = open("/usr/share/spyguard/assets/scheme.sql").read()
with sqlite3.connect("/usr/share/spyguard/database.sqlite3") as con:
    con.executescript(schema)
print("Database initialized.")
PYEOF
fi

cd /usr/share/spyguard/api/capture
exec python3 main.py
