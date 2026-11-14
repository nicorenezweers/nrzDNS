//! Spy: was andere über eine Domain wissen können – aus öffentlichen Quellen
//! (Certificate Transparency, DNS von aussen, RDAP), für eigene Domains auch aktiv
//! (Webserver, offene Ports).

use serde::{Deserialize, Serialize};

/// `POST /spy/scan`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SpyScanInput {
    pub domain: String,
    /// Auch Webserver und Ports der gefundenen Adressen prüfen (nur eigene Domains).
    pub active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
}

/// Eine Erkenntnis mit Empfehlung.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SpyFinding {
    pub severity: Severity,
    /// Kurz: „12 Namen in Zertifikaten öffentlich“.
    pub title: String,
    /// Was ein Angreifer damit anfangen kann.
    pub detail: String,
    /// Was du tun kannst (leer = nichts nötig).
    pub advice: String,
    /// Betroffene Namen, Adressen …
    pub items: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SpyRegistration {
    pub registrar: String,
    /// Unix-Sekunden, 0 = unbekannt.
    pub created: i64,
    pub updated: i64,
    pub expires: i64,
    pub status: Vec<String>,
    pub dnssec: bool,
    /// Öffentliche Kontakte („Registrant: Max Muster, max@…“), meist geschwärzt.
    pub contacts: Vec<String>,
    /// Quelle (RDAP-Server).
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SpyRecord {
    pub name: String,
    pub qtype: String,
    pub data: String,
}

/// Ein Name in Zertifikaten (Certificate Transparency).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SpyCertName {
    pub name: String,
    pub certificates: u32,
    /// Erstes/letztes Ausstellungsdatum (Unix-Sekunden).
    pub first_seen: i64,
    pub last_seen: i64,
    pub issuers: Vec<String>,
}

/// Eine öffentliche Adresse und wem das Netz gehört.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SpyAddress {
    pub ip: String,
    /// Netzbetreiber/Hoster laut RDAP, z. B. „Cloudflare, Inc.“ oder „Hetzner Online GmbH“.
    pub provider: String,
    pub network: String,
    pub country: String,
    /// CDN/Proxy (Cloudflare …): der eigentliche Server bleibt verborgen.
    pub cdn: bool,
    /// Private Adresse (192.168…, 10…, 100.64/10) im öffentlichen DNS.
    pub private: bool,
    /// Gleich der öffentlichen Adresse dieses Anschlusses (zu Hause).
    pub home: bool,
    /// Offene Ports (nur aktive Prüfung, von innen geprüft).
    pub open_ports: Vec<u16>,
}

/// Ein Name mit seinen öffentlichen Adressen und (aktiv) dem Webserver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SpyHost {
    pub name: String,
    pub addresses: Vec<String>,
    pub cname: String,
    /// Woher bekannt: `dns`, `ct` (Zertifikat), `mx`, `ns`.
    pub sources: Vec<String>,
    /// Aktiv: HTTP-Status (0 = nicht geprüft/keine Antwort).
    pub http_status: u16,
    pub server: String,
    pub powered_by: String,
    pub title: String,
    pub hsts: bool,
    pub https: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SpyMail {
    pub mx: Vec<String>,
    /// Erkannter Anbieter, z. B. „Google Workspace“.
    pub provider: String,
    pub spf: String,
    pub dmarc: String,
    /// Gefundene DKIM-Selektoren.
    pub dkim: Vec<String>,
}

/// Ergebnis eines Scans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SpyReport {
    pub domain: String,
    /// Unix-Sekunden.
    pub scanned_at: i64,
    pub active: bool,
    /// 0–100, höher = weniger verraten.
    pub score: u8,
    pub findings: Vec<SpyFinding>,
    pub registration: SpyRegistration,
    pub name_servers: Vec<String>,
    /// Erkannter DNS-Anbieter, z. B. „Cloudflare“.
    pub dns_provider: String,
    pub records: Vec<SpyRecord>,
    pub mail: SpyMail,
    pub cert_names: Vec<SpyCertName>,
    pub cert_count: u32,
    /// E-Mail-Adressen aus Zertifikaten.
    pub cert_emails: Vec<String>,
    pub hosts: Vec<SpyHost>,
    pub addresses: Vec<SpyAddress>,
    /// Dienste, die TXT-Einträge verraten („Google Workspace“, „Atlassian“ …).
    pub services: Vec<String>,
    /// Quellen, die nicht geantwortet haben.
    pub errors: Vec<String>,
}

/// `GET /spy`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SpyStatus {
    pub running: bool,
    pub progress: Vec<String>,
    /// Eigene Domains (Cloudflare-Zonen, HTTPS-Namen) – nur dafür gibt es aktive Prüfungen.
    pub own_domains: Vec<String>,
    /// Letzte Berichte, neuester zuerst.
    pub reports: Vec<SpyReport>,
}
