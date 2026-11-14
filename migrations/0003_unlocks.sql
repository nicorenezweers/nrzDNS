-- Sperrseite: auf Zeit freigeschaltete Domains und Anträge auf dauerhafte Ausnahmen
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
