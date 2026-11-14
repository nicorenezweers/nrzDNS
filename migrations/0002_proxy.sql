-- Reverse Proxy: Name → HTTP-Ziel (z. B. music.nrz.ch → http://100.78.107.162:8350)
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
