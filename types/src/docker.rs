//! Docker auf dem Gerät (nur lesend): Container, Netze, Logs – wie `docker ps`,
//! `docker network ls` und `docker logs`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DockerAddress {
    pub network: String,
    pub ip: String,
    pub gateway: String,
    pub mac: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DockerContainer {
    pub id: String,
    pub name: String,
    pub image: String,
    /// `running`, `exited`, `restarting` …
    pub state: String,
    /// z. B. „Up 3 hours (healthy)“.
    pub status: String,
    pub created: i64,
    /// Compose-Projekt (auf Umbrel die App-ID, z. B. `nrz-dns`).
    pub app: String,
    pub service: String,
    /// `host`, `bridge`, Name eines Netzes …
    pub network_mode: String,
    pub addresses: Vec<DockerAddress>,
    /// Veröffentlichte Ports, z. B. `0.0.0.0:8400→80/tcp`.
    pub ports: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DockerNetwork {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub subnet: String,
    pub gateway: String,
    pub internal: bool,
    /// (Container, IP)
    pub containers: Vec<(String, String)>,
}

/// `GET /docker`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DockerOverview {
    /// Docker erreichbar (Socket eingebunden).
    pub available: bool,
    pub error: String,
    pub version: String,
    pub containers: Vec<DockerContainer>,
    pub networks: Vec<DockerNetwork>,
}
