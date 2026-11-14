-- Spy: Verlauf aller Berichte (je Domain die letzten 60)
CREATE TABLE spy_reports (
    id         INTEGER PRIMARY KEY,
    domain     TEXT    NOT NULL,
    scanned_at INTEGER NOT NULL,
    score      INTEGER NOT NULL,
    report     TEXT    NOT NULL
);
CREATE INDEX spy_reports_domain ON spy_reports (domain, scanned_at);
