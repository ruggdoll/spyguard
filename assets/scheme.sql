CREATE TABLE "iocs" (
	"id"	INTEGER UNIQUE,
	"value"	TEXT NOT NULL,
	"type"	TEXT NOT NULL,
	"tlp"	TEXT NOT NULL,
	"tag"	TEXT NOT NULL,
	"source"	TEXT NOT NULL,
	"added_on"	NUMERIC NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
);

CREATE TABLE "whitelist" (
	"id"	INTEGER UNIQUE,
	"element"	TEXT NOT NULL UNIQUE,
	"type"	TEXT NOT NULL,
	"source"	TEXT NOT NULL,
	"added_on"	INTEGER NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
);

CREATE TABLE "misp" (
	"id" 	INTEGER UNIQUE,
	"name" 	TEXT,
	"url"	TEXT NOT NULL,
	"apikey"	TEXT NOT NULL,
	"verifycert" INTEGER NOT NULL DEFAULT 0,
	"added_on" NUMERIC NOT NULL,
	"last_sync" NUMERIC NOT NULL DEFAULT 0,
	PRIMARY KEY("id" AUTOINCREMENT)
);

CREATE TABLE "cti_quarantine" (
	"id"           INTEGER UNIQUE,
	"name"         TEXT NOT NULL,
	"reason"       TEXT,
	"started_at"   NUMERIC NOT NULL,
	"duration_days" INTEGER NOT NULL DEFAULT 42,
	PRIMARY KEY("id" AUTOINCREMENT)
);

CREATE TABLE "misp_sync_log" (
	"id"         INTEGER UNIQUE,
	"misp_id"    INTEGER NOT NULL,
	"synced_at"  NUMERIC NOT NULL,
	"iocs_added" INTEGER NOT NULL DEFAULT 0,
	"status"     TEXT NOT NULL,
	"message"    TEXT,
	PRIMARY KEY("id" AUTOINCREMENT)
);
