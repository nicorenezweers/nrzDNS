//! Netzwerkkarte: alle Verbindungen auf einen Blick (Internet, Tunnel, NetBird,
//! Reverse Proxy, Docker, LAN).

use serde::{Deserialize, Serialize};

/// Ein Punkt auf der Karte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct TopoNode {
    /// Eindeutig, z. B. `dom:music.zweers.ch`, `ct:nrz-dns_app_1`, `nb:100.78.1.2`.
    pub id: String,
    /// `internet`, `gateway`, `nrz`, `docker`, `lan`, `netbird`.
    pub area: String,
    /// `domain`, `tunnel`, `netbird`, `router`, `lan`, `hub`, `proxy`, `container`,
    /// `device`, `peer`, `host`, `external`.
    pub kind: String,
    pub label: String,
    /// Zweite Zeile (IP, Ziel …).
    pub sub: String,
    /// `ok`, `warn`, `off` oder leer.
    pub status: String,
    /// Untergruppe innerhalb des Bereichs (z. B. Docker-Netz).
    pub group: String,
    /// Weitere Angaben für die Detailansicht.
    pub info: Vec<String>,
}

/// Eine Verbindung (Fluss von `from` nach `to`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct TopoLink {
    pub from: String,
    pub to: String,
    /// `tunnel`, `netbird`, `router`, `lan`, `proxy`, `docker`, `dns`, `mesh`.
    pub kind: String,
    pub label: String,
    /// Weg funktioniert gerade (z. B. Tunnel verbunden).
    pub active: bool,
    /// Zugriffe in den letzten 24 Stunden.
    pub hits: u64,
    /// Name des Weges (z. B. die Domain) – alle Verbindungen eines Weges leuchten zusammen auf.
    pub flow: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Topology {
    pub nodes: Vec<TopoNode>,
    pub links: Vec<TopoLink>,
    /// Hinweise, was fehlt (z. B. „NetBird-Token fehlt“).
    pub notes: Vec<String>,
    pub generated_at: i64,
}
