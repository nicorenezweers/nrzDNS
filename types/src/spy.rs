//! Spy: was andere über eine Domain wissen können – aus öffentlichen Quellen
//! (Certificate Transparency, DNS von aussen, RDAP), für eigene Domains auch aktiv
//! (Webserver, offene Ports).

use serde::{Deserialize, Serialize};

/// `POST /spy/scan` – nur eigene Domains (Cloudflare-Zonen, HTTPS-Namen).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SpyScanInput {
    pub domain: String,
    /// Auch Webserver und Ports prüfen.
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
    /// Anleitung Schritt für Schritt.
    pub steps: Vec<String>,
    /// Stelle in nrzNetwork, wo man es beheben kann (`dns`, `proxy`, `https`,
    /// `integrations`, `components`, `netbird`), leer = keine.
    pub link: String,
    /// Fester Schlüssel (für den Vergleich zwischen zwei Scans), z. B. `ct-names`.
    pub id: String,
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
    /// Fehlende Sicherheits-Kopfzeilen (nur bei Antworten < 400).
    pub missing_headers: Vec<String>,
    /// Ziel des CNAME löst nicht auf (Übernahme der Subdomain möglich).
    pub dangling: bool,
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
    /// Änderungen seit dem vorigen Scan.
    pub changes: Vec<String>,
    /// So viele Ports je Adresse geprüft (0 = keine Portprüfung).
    pub ports_scanned: u32,
    /// Öffentliche Adresse dieses Anschlusses.
    pub home_ip: String,
    /// Automatisch (Zeitplan) oder von Hand gestartet.
    pub scheduled: bool,
}

/// Ein Eintrag im Verlauf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SpyHistoryEntry {
    pub domain: String,
    pub scanned_at: i64,
    pub score: u8,
    pub problems: u32,
    pub changes: Vec<String>,
    pub scheduled: bool,
}

/// `PUT /spy/settings`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SpySettings {
    /// Täglich alle eigenen Domains prüfen.
    pub auto: bool,
    /// Stunde (Ortszeit) für den täglichen Scan.
    pub hour: u8,
    /// Alle 65 535 Ports prüfen (sonst nur die wichtigsten).
    pub all_ports: bool,
    /// Auch die öffentliche Adresse dieses Anschlusses prüfen.
    pub scan_home: bool,
}

impl Default for SpySettings {
    fn default() -> Self {
        Self {
            auto: true,
            hour: 4,
            all_ports: true,
            scan_home: true,
        }
    }
}

/// `GET /spy`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SpyStatus {
    pub running: bool,
    pub progress: Vec<String>,
    /// Eigene Domains (Cloudflare-Zonen, HTTPS-Namen) – nur dafür gibt es aktive Prüfungen.
    pub own_domains: Vec<String>,
    /// Letzter Bericht je Domain, neuester zuerst.
    pub reports: Vec<SpyReport>,
    /// Verlauf aller Scans, neuester zuerst.
    pub history: Vec<SpyHistoryEntry>,
    pub settings: SpySettings,
    /// Fortschritt der Portprüfung (0–100, nur während eines Scans).
    pub port_progress: u8,
}

/// Bekannte Dienste hinter Ports (für Anzeige und Bewertung).
pub fn port_service(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        111 => "RPC",
        139 | 445 => "SMB (Windows-Freigabe)",
        143 => "IMAP",
        443 => "HTTPS",
        465 | 587 => "SMTP (Mail-Versand)",
        993 => "IMAPS",
        995 => "POP3S",
        1080 => "SOCKS-Proxy",
        1194 => "OpenVPN",
        1433 => "MS SQL",
        1883 | 8883 => "MQTT",
        2049 => "NFS",
        2375 | 2376 => "Docker-API",
        3000 => "Web-App (z. B. Grafana)",
        3306 => "MySQL/MariaDB",
        3389 => "Remotedesktop (RDP)",
        5000 | 5001 => "Synology/Web-App",
        5432 => "PostgreSQL",
        5900..=5910 => "VNC (Bildschirmfreigabe)",
        6379 => "Redis",
        8000 | 8008 | 8080 | 8888 => "Web (alternativ)",
        8096 => "Jellyfin",
        8123 => "Home Assistant",
        8443 => "HTTPS (alternativ)",
        9000 => "Portainer/Web-App",
        9090 => "Prometheus/Cockpit",
        9100 => "Drucker/Exporter",
        9200 | 9300 => "Elasticsearch",
        11211 => "Memcached",
        27017 => "MongoDB",
        32400 => "Plex",
        51820 => "WireGuard",
        _ => "",
    }
}
