-- Zwei-Faktor-Anmeldung (TOTP) und Wiederherstellungscodes (SHA-256 als JSON-Liste)
ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_pending TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN recovery_codes TEXT NOT NULL DEFAULT '[]';
