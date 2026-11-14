//! Netzwerk-Tools (Ping, Ports, HTTP-Check) und Geräte im Netzwerk.

use serde::{Deserialize, Serialize};

/// `POST /tools/ping`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PingInput {
    pub host: String,
    /// 1–10, Vorgabe 4.
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PingResult {
    pub host: String,
    pub ip: String,
    /// `icmp` oder `tcp` (Verbindungsaufbau, wenn ICMP nicht erlaubt ist).
    pub method: String,
    /// Je Versuch die Zeit in ms, `None` = keine Antwort.
    pub probes: Vec<Option<f64>>,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub loss_percent: f64,
}

/// `POST /tools/ports`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PortsInput {
    pub host: String,
    /// z. B. `22,80,443,8000-8010` (höchstens 200 Ports).
    pub ports: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    #[default]
    Closed,
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PortProbe {
    pub port: u16,
    pub state: PortState,
    pub ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PortsResult {
    pub host: String,
    pub ip: String,
    pub ports: Vec<PortProbe>,
}

/// `POST /tools/http`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct HttpCheckInput {
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct HttpCheckResult {
    pub url: String,
    pub final_url: String,
    pub status: u16,
    pub reason: String,
    pub ms: f64,
    pub remote: String,
    pub tls: bool,
    pub headers: Vec<(String, String)>,
}

/// Ein Gerät, das nrzNetwork in den letzten Tagen gefragt hat (`GET /devices?days=`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Device {
    pub ip: String,
    /// Selbst vergebener Name (leer = keiner).
    pub name: String,
    pub queries: u64,
    pub blocked: u64,
    /// Zuletzt gesehen (Unix-Sekunden).
    pub last_seen: i64,
}

/// `PUT /devices/<ip>` – leerer Name löscht ihn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DeviceNameInput {
    pub name: String,
}
