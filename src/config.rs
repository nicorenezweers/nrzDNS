//! Einstellungen. Quelle ist Rockets Figment: `Rocket.toml` und Umgebungsvariablen mit
//! dem Präfix `NRZDNS_` (z. B. `NRZDNS_DATA_DIR`, `NRZDNS_DNS_LISTEN`).
//!
//! Rockets eigene Schlüssel (`port`, `address`, `ip_header`, `limits` …) gelten wie gewohnt;
//! hier stehen nur die von nrzNetwork. Alles, was sich zur Laufzeit ändern lässt (Weiterleitungen,
//! Cache, Sperren …), liegt dagegen als [`nrzdns_types::DnsSettings`] in der Datenbank.

use rocket::figment::providers::{Env, Format, Toml};
use rocket::figment::Figment;
use serde::{Deserialize, Deserializer};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Datenordner: hier liegen `nrzdns.db` und der Zwischenspeicher der Sperrlisten
    /// (`blocklists/<id>.txt`).
    pub data_dir: PathBuf,
    /// Adressen für DNS über UDP und TCP. In der Umgebung als Liste
    /// (`NRZDNS_DNS_LISTEN=0.0.0.0:53,[::]:53` oder `["0.0.0.0:53"]`); ohne Port gilt 53.
    /// Leer = kein DNS-Server (nur DoH und Oberfläche).
    #[serde(deserialize_with = "listen_addrs")]
    pub dns_listen: Vec<SocketAddr>,
    /// Adressen für den Reverse Proxy (HTTP), z. B. `NRZDNS_PROXY_LISTEN=0.0.0.0:80`; ohne
    /// Port gilt 80. Leer = kein Proxy.
    #[serde(deserialize_with = "proxy_addrs")]
    pub proxy_listen: Vec<SocketAddr>,
    /// Name, unter dem der Container das Gerät selbst erreicht (`NRZDNS_HOST_GATEWAY`, auf
    /// Umbrel `host.docker.internal`). Ziele auf einer Adresse dieses Geräts verbindet der
    /// Proxy darüber – aus dem Container ist z. B. die VPN-Adresse oft nicht erreichbar.
    pub host_gateway: Option<String>,
    /// Ziel für Namen ohne Eintrag, IP-Adressen und `.local`-Namen (`NRZDNS_PROXY_FALLBACK`,
    /// auf Umbrel `http://host.docker.internal:80` = umbrelOS), wenn der Proxy Port 80 hat.
    pub proxy_fallback: Option<String>,
    /// HTTPS-Eingang (`NRZDNS_PROXY_TLS_LISTEN`, Vorgabe `0.0.0.0:443`, leer = keiner). Nur
    /// Namen mit eigenem Zertifikat beantwortet nrzNetwork selbst, der Rest geht an
    /// `tls_fallback`.
    #[serde(deserialize_with = "tls_addrs")]
    pub proxy_tls_listen: Vec<SocketAddr>,
    /// HTTPS für fremde Namen unverändert hierhin (`NRZDNS_TLS_FALLBACK`, z. B.
    /// `host.docker.internal:443` = umbrelOS).
    pub tls_fallback: Option<String>,
    /// ACME-Server statt Let's Encrypt (`NRZDNS_ACME_DIRECTORY`, für Tests).
    pub acme_directory: Option<String>,
    /// Eigene Stammzertifizierungsstelle für den ACME-Server (PEM-Datei, für Tests).
    pub acme_root: Option<PathBuf>,
    /// Adresse der Cloudflare-API (`NRZDNS_CLOUDFLARE_API`).
    pub cloudflare_api: String,
    /// Vor der Prüfung warten, bis Cloudflares Nameserver den TXT-Eintrag ausliefern.
    pub acme_dns_check: bool,
    /// Neue Benutzer dürfen sich selbst registrieren, solange der Admin nichts anderes
    /// einstellt (das erste Konto immer).
    pub registration_open: bool,
    /// Cookies nur über HTTPS senden – einschalten, sobald nrzNetwork hinter HTTPS läuft.
    pub cookie_secure: bool,
    /// Hintergrundarbeiten (DNS-Ports öffnen, Sperrlisten laden, Aufräumen) starten.
    /// Tests schalten sie aus.
    pub background: bool,
    /// Fester Zugang zum MCP-Server (`/mcp`, `NRZDNS_MCP_TOKEN`, mindestens 16 Zeichen).
    /// Gesetzt, gilt nur dieses Token; ein in der Oberfläche erzeugtes wird ignoriert.
    pub mcp_token: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            dns_listen: vec![SocketAddr::from(([0, 0, 0, 0], 53))],
            proxy_listen: vec![SocketAddr::from(([0, 0, 0, 0], 80))],
            host_gateway: None,
            proxy_fallback: None,
            proxy_tls_listen: vec![SocketAddr::from(([0, 0, 0, 0], 443))],
            tls_fallback: None,
            acme_directory: None,
            acme_root: None,
            cloudflare_api: "https://api.cloudflare.com/client/v4".into(),
            acme_dns_check: true,
            registration_open: false,
            cookie_secure: false,
            background: true,
            mcp_token: None,
        }
    }
}

impl Config {
    pub fn database_path(&self) -> PathBuf {
        self.data_dir.join("nrzdns.db")
    }

    /// MCP-Token aus der Umgebung (leer = keins).
    pub fn mcp_env_token(&self) -> Option<&str> {
        self.mcp_token
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
    }

    /// Ordner für die zuletzt geladenen Fassungen der Sperrlisten.
    pub fn blocklist_dir(&self) -> PathBuf {
        self.data_dir.join("blocklists")
    }
}

/// Eine Adresse wie `0.0.0.0:53`, `[::]:53` oder nur `127.0.0.1` (Port 53).
pub fn parse_listen(s: &str) -> Option<SocketAddr> {
    parse_listen_port(s, 53)
}

/// Wie [`parse_listen`], ohne Port gilt `port`.
pub fn parse_listen_port(s: &str, port: u16) -> Option<SocketAddr> {
    let s = s.trim();
    s.parse::<SocketAddr>().ok().or_else(|| {
        let ip = s.trim_start_matches('[').trim_end_matches(']');
        ip.parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, port))
    })
}

fn listen_addrs<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<SocketAddr>, D::Error> {
    addrs(d, "dns_listen", 53)
}

fn proxy_addrs<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<SocketAddr>, D::Error> {
    addrs(d, "proxy_listen", 80)
}

fn tls_addrs<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<SocketAddr>, D::Error> {
    addrs(d, "proxy_tls_listen", 443)
}

/// Adressen als Liste oder als Zeichenkette mit Kommas (so kommen sie aus der Umgebung).
fn addrs<'de, D: Deserializer<'de>>(
    d: D,
    key: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        One(String),
        Many(Vec<String>),
    }
    let items = match Raw::deserialize(d)? {
        Raw::One(s) => s.split(',').map(str::to_string).collect(),
        Raw::Many(v) => v,
    };
    items
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            parse_listen_port(s, port)
                .ok_or_else(|| serde::de::Error::custom(format!("{key}: ungültige Adresse „{s}“")))
        })
        .collect()
}

/// Rocket-Konfiguration plus `NRZDNS_*`-Umgebung (statt `ROCKET_*`).
pub fn figment() -> Figment {
    Figment::from(rocket::Config::default())
        // Vorgaben aus Rocket.toml sind eingebettet: Auf Umbrel liegt nur das Programm im
        // Container, ohne Datei daneben. Eine Rocket.toml (NRZDNS_CONFIG) ergänzt sie.
        .merge(Toml::string(include_str!("../Rocket.toml")).nested())
        .merge(Toml::file(Env::var_or("NRZDNS_CONFIG", "Rocket.toml")).nested())
        // NRZDNS_LOG ist der tracing-Filter (main.rs), keine Rocket-Einstellung
        .merge(
            Env::prefixed("NRZDNS_")
                .ignore(&["PROFILE", "LOG"])
                .global(),
        )
        .select(rocket::figment::Profile::from_env_or(
            "NRZDNS_PROFILE",
            rocket::Config::DEFAULT_PROFILE,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listen(figment: Figment) -> Vec<String> {
        figment
            .extract::<Config>()
            .unwrap()
            .dns_listen
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn dns_listen_as_list_or_string() {
        let base = Figment::new;
        assert_eq!(listen(base()), ["0.0.0.0:53"]);
        assert_eq!(
            listen(base().merge(("dns_listen", "127.0.0.1:1053, [::1]:1053"))),
            ["127.0.0.1:1053", "[::1]:1053"]
        );
        assert_eq!(
            listen(base().merge(("dns_listen", vec!["10.0.0.1", "[::]:5353"]))),
            ["10.0.0.1:53", "[::]:5353"]
        );
        assert!(listen(base().merge(("dns_listen", ""))).is_empty());
        assert!(listen(base().merge(("dns_listen", Vec::<String>::new()))).is_empty());
        let proxy = |f: Figment| -> Vec<String> {
            let c: Config = f.extract().unwrap();
            c.proxy_listen.iter().map(ToString::to_string).collect()
        };
        assert_eq!(proxy(base()), ["0.0.0.0:80"]);
        assert_eq!(
            proxy(base().merge(("proxy_listen", "0.0.0.0:8480,[::]"))),
            ["0.0.0.0:8480", "[::]:80"]
        );
        assert!(proxy(base().merge(("proxy_listen", ""))).is_empty());
        let tls = |f: Figment| -> Vec<String> {
            let c: Config = f.extract().unwrap();
            c.proxy_tls_listen.iter().map(ToString::to_string).collect()
        };
        assert_eq!(tls(base()), ["0.0.0.0:443"]);
        assert_eq!(
            tls(base().merge(("proxy_tls_listen", "0.0.0.0:444"))),
            ["0.0.0.0:444"]
        );
        assert!(base()
            .merge(("dns_listen", "kein-host:53"))
            .extract::<Config>()
            .is_err());
    }
}
