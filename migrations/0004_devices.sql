-- Eigene Namen für Geräte im Netzwerk (nach IP-Adresse)
CREATE TABLE device_names (
    ip         TEXT    PRIMARY KEY,
    name       TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
);
