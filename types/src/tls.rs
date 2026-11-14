//! HTTPS für eigene Domains: Zertifikat von Let's Encrypt, Nachweis über einen TXT-Eintrag bei
//! Cloudflare (DNS-01). So klappt auch `*.zweers.ch` im lokalen Netz, ohne dass etwas von
//! aussen erreichbar sein muss.

use serde::{Deserialize, Serialize};

/// Einstellungen (ohne Cloudflare-Token – der wird nie ausgeliefert).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TlsSettings {
    /// HTTPS anbieten und das Zertifikat automatisch erneuern.
    pub enabled: bool,
    /// Namen im Zertifikat, z. B. `zweers.ch`, `*.zweers.ch` (höchstens 10).
    pub domains: Vec<String>,
    /// Kontakt für Let's Encrypt (Hinweise vor Ablauf), leer = keiner.
    pub email: String,
    /// Testzertifikat von Let's Encrypt (Staging, nicht vertrauenswürdig – zum Ausprobieren).
    pub staging: bool,
    /// `http://` für Namen mit Zertifikat auf `https://` umleiten.
    pub redirect_http: bool,
}

impl Default for TlsSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            domains: Vec::new(),
            email: String::new(),
            staging: false,
            redirect_http: true,
        }
    }
}

/// `PUT /tls`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct TlsSettingsInput {
    #[serde(flatten)]
    pub settings: TlsSettings,
    /// Cloudflare-API-Token (Rechte: Zone → DNS → Bearbeiten). Leer = bisheriges behalten.
    pub cloudflare_token: String,
    /// Gespeichertes Token löschen.
    pub clear_token: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct CertificateInfo {
    /// Namen im Zertifikat.
    pub names: Vec<String>,
    pub issuer: String,
    /// Gültig ab / bis (Unix-Sekunden).
    pub not_before: i64,
    pub not_after: i64,
}

/// `GET /tls`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct TlsStatus {
    pub settings: TlsSettings,
    /// Ein Cloudflare-Token ist gespeichert.
    pub token_set: bool,
    pub certificate: Option<CertificateInfo>,
    /// Gerade wird ein Zertifikat geholt.
    pub issuing: bool,
    /// Schritte des letzten bzw. laufenden Versuchs.
    pub progress: Vec<String>,
    /// Fehler des letzten Versuchs (leer = keiner).
    pub last_error: String,
    /// Letzter Versuch (Unix-Sekunden, 0 = noch keiner).
    pub last_attempt: i64,
    /// Adressen des HTTPS-Eingangs.
    pub listen: Vec<String>,
    pub listen_errors: Vec<String>,
}

// ------------------------------------------------------------------ Verbindungen

/// `PUT /integrations` – leere Tokens = bisherige behalten.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct IntegrationsInput {
    /// Cloudflare-API-Token (Rechte: Zone → Zone → Lesen und Zone → DNS → Bearbeiten).
    pub cloudflare_token: String,
    pub clear_cloudflare: bool,
    /// Adresse der NetBird-Verwaltung, leer = NetBird Cloud (`https://api.netbird.io`).
    pub netbird_url: String,
    /// Persönliches Zugangstoken (NetBird → Einstellungen → Persönliche Zugangstoken).
    pub netbird_token: String,
    pub clear_netbird: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct IntegrationStatus {
    /// Token gespeichert.
    pub configured: bool,
    /// Letzte Prüfung erfolgreich (nur bei `GET /integrations?test=true`).
    pub ok: bool,
    /// „Verbunden als …“ oder die Fehlermeldung.
    pub detail: String,
}

/// `GET /integrations[?test=true]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct IntegrationsStatus {
    pub cloudflare: IntegrationStatus,
    pub netbird: IntegrationStatus,
    /// Eingetragene NetBird-Adresse (leer = NetBird Cloud).
    pub netbird_url: String,
}
