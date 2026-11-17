//! Schema der Datenbank als sqlx-Migrationen – laufen beim Start ([`super::migrate`]), sqlx
//! merkt sich in `_sqlx_migrations`, was schon gelaufen ist.
//!
//! Ausgelieferte Migrationen nie ändern: sqlx vergleicht die Prüfsumme (SHA-384 des SQL-Texts)
//! und bricht sonst mit „VersionMismatch“ ab. Schemaänderungen immer als neue Migration hinten
//! anhängen; der Test unten hält die Prüfsummen der ausgelieferten fest.

use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::SqlStr;

/// Version, Beschreibung und SQL jeder Migration, aufsteigend.
const MIGRATIONS: &[(i64, &str, &str)] = &[
    (
        1,
        "init",
        r#"-- nrzDNS: Benutzer, Sitzungen, Einstellungen, Zonen mit Einträgen, Sperrlisten, eigene
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
"#,
    ),
    (
        2,
        "proxy",
        r#"-- Reverse Proxy: Name → HTTP-Ziel (z. B. music.nrz.ch → http://100.78.107.162:8350)
CREATE TABLE proxy_hosts (
    id         INTEGER PRIMARY KEY,
    -- klein, ohne Punkt am Ende
    host       TEXT    NOT NULL UNIQUE,
    -- http://adresse:port[/pfad], ohne / am Ende
    target     TEXT    NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    comment    TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
"#,
    ),
    (
        3,
        "unlocks",
        r#"-- Sperrseite: auf Zeit freigeschaltete Domains und Anträge auf dauerhafte Ausnahmen
CREATE TABLE temp_unlocks (
    -- klein, ohne Punkt am Ende; gilt für die Domain und alle Subdomains
    domain     TEXT    PRIMARY KEY,
    until      INTEGER NOT NULL,
    client     TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE TABLE allow_requests (
    id         INTEGER PRIMARY KEY,
    domain     TEXT    NOT NULL,
    client     TEXT    NOT NULL DEFAULT '',
    reason     TEXT    NOT NULL DEFAULT '',
    status     TEXT    NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at INTEGER NOT NULL,
    decided_at INTEGER,
    decided_by TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX allow_requests_status ON allow_requests (status, created_at);
"#,
    ),
    (
        4,
        "devices",
        r#"-- Eigene Namen für Geräte im Netzwerk (nach IP-Adresse)
CREATE TABLE device_names (
    ip         TEXT    PRIMARY KEY,
    name       TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
);
"#,
    ),
    (
        5,
        "block page",
        r#"-- nrzNetwork: die Sperrseite wird der Standard-Sperrmodus. Wer noch den alten Standard
-- (0.0.0.0) hatte, bekommt die Sperrseite; eine bewusst andere Wahl bleibt.
UPDATE app_settings
SET value = json_set(value, '$.blockMode', 'blockPage')
WHERE key = 'dns' AND json_extract(value, '$.blockMode') = 'nullAddress';
"#,
    ),
    (
        6,
        "access",
        r#"-- Zugriffe auf die Websites hinter dem Reverse Proxy (Monitor)
CREATE TABLE access_log (
    id          INTEGER PRIMARY KEY,
    at_ms       INTEGER NOT NULL,
    host        TEXT    NOT NULL,
    method      TEXT    NOT NULL,
    path        TEXT    NOT NULL,
    status      INTEGER NOT NULL,
    bytes       INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    client      TEXT    NOT NULL,
    source      TEXT    NOT NULL,
    country     TEXT    NOT NULL DEFAULT '',
    user_agent  TEXT    NOT NULL DEFAULT '',
    referer     TEXT    NOT NULL DEFAULT '',
    kind        TEXT    NOT NULL
);
CREATE INDEX access_log_at ON access_log (at_ms);
CREATE INDEX access_log_host ON access_log (host, at_ms);
CREATE INDEX access_log_client ON access_log (client, at_ms);

-- Einträge, die über den Cloudflare Tunnel öffentlich erreichbar sind
ALTER TABLE proxy_hosts ADD COLUMN public INTEGER NOT NULL DEFAULT 0;
"#,
    ),
    (
        7,
        "spy reports",
        r#"-- Spy: Verlauf aller Berichte (je Domain die letzten 60)
CREATE TABLE spy_reports (
    id         INTEGER PRIMARY KEY,
    domain     TEXT    NOT NULL,
    scanned_at INTEGER NOT NULL,
    score      INTEGER NOT NULL,
    report     TEXT    NOT NULL
);
CREATE INDEX spy_reports_domain ON spy_reports (domain, scanned_at);
"#,
    ),
    (
        8,
        "dieter",
        r#"-- Dieter: Gespräche, Nachrichten (Rohformat für den Anbieter + Anzeige) und Vorfälle
CREATE TABLE dieter_conversations (
    id         INTEGER PRIMARY KEY,
    title      TEXT    NOT NULL,
    automatic  INTEGER NOT NULL DEFAULT 0,
    -- Claude CLI: Sitzung zum Fortsetzen
    session    TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE dieter_messages (
    id              INTEGER PRIMARY KEY,
    conversation_id INTEGER NOT NULL REFERENCES dieter_conversations (id) ON DELETE CASCADE,
    -- user, assistant, action, error
    role            TEXT    NOT NULL,
    text            TEXT    NOT NULL DEFAULT '',
    tool            TEXT    NOT NULL DEFAULT '',
    detail          TEXT    NOT NULL DEFAULT '',
    -- Nachricht im Format des Anbieters (OpenAI-kompatibel), leer = nur Anzeige
    raw             TEXT    NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL
);
CREATE INDEX dieter_messages_conv ON dieter_messages (conversation_id, id);

CREATE TABLE dieter_incidents (
    key             TEXT    PRIMARY KEY,
    text            TEXT    NOT NULL,
    first_seen      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL,
    active          INTEGER NOT NULL DEFAULT 1,
    conversation_id INTEGER NOT NULL DEFAULT 0,
    -- Letzter automatischer Einsatz (nicht öfter als alle 6 Stunden je Problem)
    handled_at      INTEGER NOT NULL DEFAULT 0
);
"#,
    ),
    (
        9,
        "two factor",
        r#"-- Zwei-Faktor-Anmeldung (TOTP) und Wiederherstellungscodes (SHA-256 als JSON-Liste)
ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_pending TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN recovery_codes TEXT NOT NULL DEFAULT '[]';
"#,
    ),
];

/// Alle Migrationen für [`Migrator::run`].
pub fn migrator() -> Migrator {
    Migrator::with_migrations(
        MIGRATIONS
            .iter()
            .map(|&(version, description, sql)| {
                Migration::new(
                    version,
                    description.into(),
                    MigrationType::Simple,
                    SqlStr::from_static(sql),
                    sql.starts_with("-- no-transaction"),
                )
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    /// SHA-384 der ausgelieferten Migrationen (so stehen sie in `_sqlx_migrations` jeder
    /// bestehenden Datenbank). Neue Migrationen hier anhängen, alte nie ändern.
    const SHIPPED: &[&str] = &[
        "93e5ef3e45abe0683883ea91a0ee1f2d94624220bc264245800990126b717086663358c07f9c2296b08ad6498a54fe02",
        "62e3f030f9a4f0fe2c6d6e4260d9552ec9a4b0d0253b73a8e5ddde78ca3231b397a1005c909de5c0e7695b7ce5bc7391",
        "8e2f5177b2a5c36242e49d824ea000f98464f37aa89e7e270bb61325d90ec6340cc02f94358cc81b4c3dcd41d96d9de7",
        "d7beda8695413e5286b5d089608672b3e2107bf06a87f8255748dbe9b116909afccbeeb51d97897d2efb76faed094db7",
        "4a78af2c6a4460f245e0b163ce6d1c4d1118b79f91162f1dc9df3199b7598fed5188846fe0df8ecf07b2bb617d94eba8",
        "ebf835db4c67ac7d86264ad77b1436bb17db161f5cb275d55d6dd63b3474290b94c8362d3208b08b3e82e34f2332fd7a",
        "c0e84c0dc80364d30078d10ce03e6072d5a3dc2686add6a65ede0ad27cc095b26c64745644ee6655f1052825d9d99990",
        "73f50c9027dd95095762c222cea18c15920c816ed366cd70fe772ee081c0107c61b9e90c68ebd66d3730d9ed961288c4",
        "24c3d2bbc966b2da6951df0eaa02431019faf467a92be9fbdd93d8876155530e78b52577c74683aeb2754a94c53de22e",
    ];

    #[test]
    fn shipped_migrations_never_change() {
        let migrator = super::migrator();
        let migrations: Vec<_> = migrator.iter().collect();
        assert!(migrations.len() >= SHIPPED.len());
        for (i, m) in migrations.iter().enumerate() {
            assert_eq!(m.version, i as i64 + 1, "Versionen lückenlos ab 1");
        }
        for (m, sum) in migrations.iter().zip(SHIPPED) {
            assert_eq!(
                hex::encode(&m.checksum),
                *sum,
                "Migration {} ({}) wurde geändert",
                m.version,
                m.description
            );
        }
    }
}
