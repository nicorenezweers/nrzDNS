-- nrzDNS: Benutzer, Sitzungen, Einstellungen, Zonen mit Einträgen, Sperrlisten, eigene
-- Sperren und Ausnahmen, Abfrageprotokoll. Zeitpunkte sind Unix-Sekunden (UTC), nur das
-- Abfrageprotokoll zählt in Millisekunden.

CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    display_name  TEXT    NOT NULL DEFAULT '',
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
    disabled      INTEGER NOT NULL DEFAULT 0,
    -- JSON (nrzdns_types::Preferences)
    preferences   TEXT    NOT NULL DEFAULT '{}',
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER
);

CREATE TABLE sessions (
    -- SHA-256 (hex) des Tokens im Cookie; das Token selbst steht nirgends
    token_hash   TEXT    PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    user_agent   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user ON sessions (user_id);

-- Instanzweite Werte als JSON: `instance` (InstanceSettings), `dns` (DnsSettings),
-- `cookie_secret`, `blocking_paused_until`
CREATE TABLE app_settings (
    key        TEXT    PRIMARY KEY,
    value      TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Eigene Zonen (primär) und bedingte Weiterleitungen
CREATE TABLE zones (
    id                INTEGER PRIMARY KEY,
    -- klein, ohne Punkt am Ende
    name              TEXT    NOT NULL UNIQUE,
    kind              TEXT    NOT NULL DEFAULT 'primary' CHECK (kind IN ('primary', 'forwarder')),
    disabled          INTEGER NOT NULL DEFAULT 0,
    soa_primary_ns    TEXT    NOT NULL DEFAULT '',
    soa_responsible   TEXT    NOT NULL DEFAULT '',
    soa_serial        INTEGER NOT NULL DEFAULT 1,
    soa_refresh       INTEGER NOT NULL DEFAULT 900,
    soa_retry         INTEGER NOT NULL DEFAULT 300,
    soa_expire        INTEGER NOT NULL DEFAULT 604800,
    soa_minimum       INTEGER NOT NULL DEFAULT 900,
    -- JSON (Vec<nrzdns_types::Upstream>), nur für Weiterleitungszonen
    forwarders        TEXT    NOT NULL DEFAULT '[]',
    comment           TEXT    NOT NULL DEFAULT '',
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);

CREATE TABLE zone_records (
    id         INTEGER PRIMARY KEY,
    zone_id    INTEGER NOT NULL REFERENCES zones (id) ON DELETE CASCADE,
    -- relativ zur Zone: '@', 'www', '*', '*.dev'
    name       TEXT    NOT NULL,
    -- 'A', 'AAAA', 'CNAME', … (doppelt zu data.type, zum Filtern)
    type       TEXT    NOT NULL,
    -- JSON (nrzdns_types::RecordData)
    data       TEXT    NOT NULL,
    ttl        INTEGER NOT NULL,
    disabled   INTEGER NOT NULL DEFAULT 0,
    comment    TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (zone_id, name, data)
);
CREATE INDEX zone_records_zone_name ON zone_records (zone_id, name);

CREATE TABLE block_lists (
    id              INTEGER PRIMARY KEY,
    name            TEXT    NOT NULL,
    url             TEXT    NOT NULL UNIQUE,
    enabled         INTEGER NOT NULL DEFAULT 1,
    domain_count    INTEGER NOT NULL DEFAULT 0,
    -- letztes erfolgreiches Laden (Datei liegt dann unter blocklists/<id>.txt)
    last_updated_at INTEGER,
    -- letzter Versuch, erfolgreich oder nicht
    last_checked_at INTEGER,
    last_error      TEXT,
    created_at      INTEGER NOT NULL
);

-- Eigene Sperren und Ausnahmen; gelten auch für alle Subdomains
CREATE TABLE custom_domains (
    id         INTEGER PRIMARY KEY,
    kind       TEXT    NOT NULL CHECK (kind IN ('blocked', 'allowed')),
    domain     TEXT    NOT NULL,
    comment    TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    UNIQUE (kind, domain)
);

-- Jede beantwortete Anfrage (nrzdns_types::QueryLogEntry); wird nach
-- DnsSettings::log_retention_days gelöscht
CREATE TABLE query_log (
    id          INTEGER PRIMARY KEY,
    -- Unix-Millisekunden
    at_ms       INTEGER NOT NULL,
    client      TEXT    NOT NULL,
    protocol    TEXT    NOT NULL,
    qname       TEXT    NOT NULL,
    qtype       TEXT    NOT NULL,
    rcode       TEXT    NOT NULL,
    kind        TEXT    NOT NULL,
    answer      TEXT    NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    upstream    TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX query_log_at ON query_log (at_ms);
CREATE INDEX query_log_qname ON query_log (qname, at_ms);
CREATE INDEX query_log_client ON query_log (client, at_ms);
CREATE INDEX query_log_kind ON query_log (kind, at_ms);
