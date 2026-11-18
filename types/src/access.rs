//! Zugriffe auf die Websites hinter dem Reverse Proxy (Monitor) und die Komponenten, die
//! nrzNetwork selbst betreibt (Cloudflare Tunnel, NetBird) samt automatischer Updates.

use serde::{Deserialize, Serialize};

/// Ein Zugriff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct AccessEntry {
    /// Unix-Millisekunden.
    pub at_ms: i64,
    pub host: String,
    pub method: String,
    /// Pfad ohne Query.
    pub path: String,
    pub status: u16,
    pub bytes: u64,
    pub duration_ms: u32,
    /// Echte Adresse des Besuchers (bei Cloudflare aus `CF-Connecting-IP`).
    pub client: String,
    /// `cloudflare`, `netbird`, `lan`, `device` (über das Gerät, z. B. umbrelOS-NetBird),
    /// `local`, `internet`.
    pub source: String,
    /// Land (nur über Cloudflare bekannt), z. B. `CH`.
    pub country: String,
    pub user_agent: String,
    /// Host der verweisenden Seite.
    pub referer: String,
    /// `entry` (Eintrag), `redirect` (http → https), `blocked` (Sperrseite).
    pub kind: String,
    /// Bekannter Name (Geräte-Seite oder NetBird), leer = unbekannt.
    pub client_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct AccessCount {
    pub key: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct AccessBucket {
    /// Beginn (Unix-Sekunden).
    pub start: i64,
    pub requests: u64,
    pub visitors: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct AccessHost {
    pub host: String,
    pub requests: u64,
    pub visitors: u64,
    pub bytes: u64,
    pub errors: u64,
    pub last_at_ms: i64,
    /// Über Cloudflare öffentlich freigegeben.
    pub public: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct AccessClient {
    pub client: String,
    pub name: String,
    pub source: String,
    pub country: String,
    pub requests: u64,
    pub last_at_ms: i64,
}

/// `GET /access/stats?period=24h|7d|30d&host=`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct AccessStats {
    pub period: String,
    pub requests: u64,
    pub visitors: u64,
    pub bytes: u64,
    /// Antworten mit 5xx.
    pub errors: u64,
    /// Aufrufe der Sperrseite.
    pub blocked: u64,
    pub timeline: Vec<AccessBucket>,
    pub hosts: Vec<AccessHost>,
    pub sources: Vec<AccessCount>,
    pub paths: Vec<AccessCount>,
    pub clients: Vec<AccessClient>,
    pub countries: Vec<AccessCount>,
    pub statuses: Vec<AccessCount>,
    /// Browser/Bots (aus dem User-Agent).
    pub agents: Vec<AccessCount>,
}

// ------------------------------------------------------------------ Komponenten

/// `PUT /components`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ComponentsSettings {
    /// Täglich zu dieser Stunde (Ortszeit) nach Updates suchen und einspielen.
    pub update_hour: u8,
    pub auto_update: bool,
    pub cloudflared_enabled: bool,
    pub netbird_enabled: bool,
    /// Name des Geräts im NetBird-Netz.
    pub netbird_hostname: String,
}

impl Default for ComponentsSettings {
    fn default() -> Self {
        Self {
            update_hour: 3,
            auto_update: true,
            cloudflared_enabled: false,
            netbird_enabled: false,
            netbird_hostname: "nrznetwork".into(),
        }
    }
}

/// `PUT /components` – Geheimnisse leer = behalten.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ComponentsInput {
    #[serde(flatten)]
    pub settings: ComponentsSettings,
    /// Tunnel-Token (Cloudflare → Zero Trust → Netzwerke → Tunnel → Token).
    pub tunnel_token: String,
    /// Setup-Key für NetBird (leer = behalten; mit NetBird-Verbindung auch automatisch).
    pub netbird_setup_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ComponentStatus {
    /// `cloudflared` oder `netbird`.
    pub name: String,
    pub enabled: bool,
    pub installed_version: String,
    pub latest_version: String,
    /// Läuft gerade.
    pub running: bool,
    /// Verbunden (Tunnel: Verbindungen zu Cloudflare, NetBird: angemeldet).
    pub connected: bool,
    /// Kurzer Zustand, z. B. „4 Verbindungen zu Cloudflare“ oder „100.78.1.2“.
    pub detail: String,
    pub started_at: i64,
    pub restarts: u32,
    pub last_error: String,
    /// Letzte Zeilen der Ausgabe.
    pub log: Vec<String>,
}

/// `GET /components`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ComponentsStatus {
    pub settings: ComponentsSettings,
    pub tunnel_token_set: bool,
    /// Tunnel-ID aus dem Token.
    pub tunnel_id: String,
    pub netbird_key_set: bool,
    pub components: Vec<ComponentStatus>,
    /// Letzte Update-Prüfung (Unix-Sekunden).
    pub last_check: i64,
    pub last_check_result: String,
    pub checking: bool,
    /// Zeitzone für die Update-Stunde.
    pub time_zone: String,
}

/// `PUT /proxy/hosts/<id>/public`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PublicInput {
    pub public: bool,
}
