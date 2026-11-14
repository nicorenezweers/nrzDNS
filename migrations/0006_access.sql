-- Zugriffe auf die Websites hinter dem Reverse Proxy (Monitor)
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
