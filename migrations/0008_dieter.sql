-- Dieter: Gespräche, Nachrichten (Rohformat für den Anbieter + Anzeige) und Vorfälle
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
