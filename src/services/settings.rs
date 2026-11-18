//! Instanzweite Einstellungen in `app_settings` (JSON-Werte): Instanz, DNS-Server, Pause der
//! Sperren und der Cookie-Schlüssel.

use crate::db::now;
use crate::error::{AppError, AppResult};
use base64::Engine as _;
use nrzdns_types::{
    normalize_domain, BlockMode, DnsSettings, InstanceSettings, Upstream, UpstreamProtocol,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sqlx::SqlitePool;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// [`InstanceSettings`] (Registrierung)
pub const INSTANCE: &str = "instance";
/// [`DnsSettings`]
pub const DNS: &str = "dns";
/// Sperren pausiert bis (Unix-Sekunden) oder `null`
pub const PAUSE: &str = "blocking_paused_until";
const COOKIE_SECRET: &str = "cookie_secret";

/// Höchstens so viele Weiterleitungen je Liste.
pub const MAX_UPSTREAMS: usize = 20;

pub async fn get<T: DeserializeOwned>(pool: &SqlitePool, key: &str) -> AppResult<Option<T>> {
    let raw: Option<String> = sqlx::query_scalar("SELECT value FROM app_settings WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(raw.and_then(|v| serde_json::from_str(&v).ok()))
}

pub async fn set<T: Serialize>(pool: &SqlitePool, key: &str, value: &T) -> AppResult<()> {
    let json = serde_json::to_string(value)
        .map_err(|e| AppError::Config(format!("Einstellung „{key}“: {e}")))?;
    sqlx::query(
        "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
    )
    .bind(key)
    .bind(json)
    .bind(now())
    .execute(pool)
    .await?;
    Ok(())
}

/// Einstellungen der Instanz; ohne gespeicherten Wert gelten die Vorgaben
/// (Registrierung laut `NRZDNS_REGISTRATION_OPEN`).
pub async fn instance(
    pool: &SqlitePool,
    config: &crate::config::Config,
) -> AppResult<InstanceSettings> {
    Ok(get::<InstanceSettings>(pool, INSTANCE)
        .await?
        .unwrap_or(InstanceSettings {
            registration_open: config.registration_open,
        }))
}

/// Einstellungen des DNS-Servers; ohne gespeicherten Wert die Vorgaben. Fehlende Felder
/// (ältere Fassung) bekommen ihre Vorgabe.
pub async fn dns(pool: &SqlitePool) -> AppResult<DnsSettings> {
    Ok(get::<DnsSettings>(pool, DNS).await?.unwrap_or_default())
}

/// Prüfen, vereinheitlichen und speichern. Zahlen ausserhalb ihres Bereichs werden auf die
/// Grenze gesetzt, ungültige Namen und Adressen abgewiesen. Liefert, was gespeichert wurde.
pub async fn save_dns(pool: &SqlitePool, input: &DnsSettings) -> AppResult<DnsSettings> {
    let settings = validate_dns(input)?;
    set(pool, DNS, &settings).await?;
    Ok(settings)
}

pub fn validate_dns(input: &DnsSettings) -> AppResult<DnsSettings> {
    let mut s = input.clone();
    s.server_domain = normalize_domain(&s.server_domain).ok_or_else(|| {
        AppError::bad(
            "Servername: bitte einen gültigen Domainnamen angeben, z. B. ns.nrzdns.local.",
        )
    })?;
    s.default_ttl = s.default_ttl.clamp(1, 604_800);
    s.rate_limit_qps = s.rate_limit_qps.min(100_000);
    s.forwarders = validate_upstreams(&s.forwarders)?;
    s.upstream_timeout_ms = s.upstream_timeout_ms.clamp(200, 15_000);
    s.cache_max_entries = s.cache_max_entries.clamp(100, 1_000_000);
    s.cache_max_ttl = s.cache_max_ttl.clamp(1, 604_800);
    s.cache_min_ttl = s.cache_min_ttl.min(s.cache_max_ttl).min(86_400);
    s.cache_negative_ttl = s.cache_negative_ttl.min(86_400);
    s.serve_stale_secs = s.serve_stale_secs.min(604_800);
    s.block_ttl = s.block_ttl.min(86_400);
    s.blocklist_update_hours = s.blocklist_update_hours.clamp(1, 168);
    s.log_retention_days = s.log_retention_days.clamp(1, 365);

    s.block_ipv4 = s.block_ipv4.trim().to_string();
    s.block_ipv6 = s.block_ipv6.trim().to_string();
    if !s.block_ipv4.is_empty() {
        s.block_ipv4 = s
            .block_ipv4
            .parse::<Ipv4Addr>()
            .map_err(|_| AppError::bad("Sperradresse IPv4: ungültige Adresse."))?
            .to_string();
    }
    if !s.block_ipv6.is_empty() {
        s.block_ipv6 = s
            .block_ipv6
            .parse::<Ipv6Addr>()
            .map_err(|_| AppError::bad("Sperradresse IPv6: ungültige Adresse."))?
            .to_string();
    }
    if s.block_mode == BlockMode::CustomAddress
        && s.block_ipv4.is_empty()
        && s.block_ipv6.is_empty()
    {
        return Err(AppError::bad(
            "Eigene Sperradresse: bitte mindestens eine IPv4- oder IPv6-Adresse angeben.",
        ));
    }
    Ok(s)
}

/// Liste vorgelagerter Server prüfen (Einstellungen und Weiterleitungszonen).
pub fn validate_upstreams(list: &[Upstream]) -> AppResult<Vec<Upstream>> {
    if list.len() > MAX_UPSTREAMS {
        return Err(AppError::bad(format!(
            "Höchstens {MAX_UPSTREAMS} Weiterleitungen."
        )));
    }
    list.iter().map(validate_upstream).collect()
}

/// Einen vorgelagerten Server prüfen: UDP/TCP/TLS nur mit IP-Adresse (Port optional), DoH
/// mit ganzer `https://`-Adresse, TLS-Name als Domain.
pub fn validate_upstream(u: &Upstream) -> AppResult<Upstream> {
    let address = u.address.trim().to_string();
    let tls_name = u.tls_name.trim().trim_end_matches('.').to_ascii_lowercase();
    let name: String = u.name.trim().chars().take(80).collect();
    match u.protocol {
        UpstreamProtocol::Https => {
            let rest = address.strip_prefix("https://").unwrap_or_default();
            let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
            if host.is_empty() || address.chars().any(char::is_whitespace) {
                return Err(AppError::bad(
                    "Weiterleitung über HTTPS: bitte die ganze Adresse angeben, z. B. https://1.1.1.1/dns-query.",
                ));
            }
        }
        _ => {
            if !is_ip_with_optional_port(&address) {
                return Err(AppError::bad(
                    "Weiterleitung: bitte eine IP-Adresse angeben, z. B. 1.1.1.1 oder 1.1.1.1:53.",
                ));
            }
        }
    }
    if !tls_name.is_empty() && normalize_domain(&tls_name).is_none() {
        return Err(AppError::bad(
            "Weiterleitung über TLS: ungültiger Name im Zertifikat.",
        ));
    }
    Ok(Upstream {
        protocol: u.protocol,
        address,
        tls_name,
        name,
    })
}

/// `1.1.1.1`, `1.1.1.1:53`, `2606:4700::1111`, `[2606:4700::1111]:53`
fn is_ip_with_optional_port(s: &str) -> bool {
    s.parse::<SocketAddr>().is_ok()
        || s.parse::<IpAddr>().is_ok()
        || s.strip_prefix('[')
            .and_then(|r| r.strip_suffix(']'))
            .is_some_and(|ip| ip.parse::<Ipv6Addr>().is_ok())
}

/// Bis wann die Sperren pausiert sind; `None`, wenn nicht (oder schon abgelaufen).
pub async fn paused_until(pool: &SqlitePool) -> AppResult<Option<i64>> {
    Ok(get::<Option<i64>>(pool, PAUSE)
        .await?
        .flatten()
        .filter(|t| *t > now()))
}

pub async fn set_paused_until(pool: &SqlitePool, until: Option<i64>) -> AppResult<()> {
    set(pool, PAUSE, &until).await
}

/// Schlüssel für Rockets private Cookies. Liegt in der Datenbank, damit Sitzungen einen
/// Neustart überstehen, ohne dass ein weiteres Geheimnis konfiguriert werden muss.
pub async fn cookie_secret(pool: &SqlitePool) -> AppResult<String> {
    if let Some(secret) = get::<String>(pool, COOKIE_SECRET).await? {
        return Ok(secret);
    }
    let secret = base64::engine::general_purpose::STANDARD.encode(rand::random::<[u8; 32]>());
    set(pool, COOKIE_SECRET, &secret).await?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstreams() {
        let ok = |p, a: &str| validate_upstream(&Upstream::new(p, a, "", "")).is_ok();
        use UpstreamProtocol::*;
        assert!(ok(Udp, "1.1.1.1"));
        assert!(ok(Udp, "1.1.1.1:5353"));
        assert!(ok(Tcp, "[2606:4700:4700::1111]:53"));
        assert!(ok(Tls, "2606:4700:4700::1111"));
        assert!(ok(Https, "https://dns.quad9.net/dns-query"));
        assert!(!ok(Udp, "dns.google"));
        assert!(!ok(Udp, ""));
        assert!(!ok(Https, "http://1.1.1.1/dns-query"));
        assert!(!ok(Https, "https:///dns-query"));
        assert!(validate_upstream(&Upstream::new(Tls, "1.1.1.1", "kein name", "")).is_err());
    }

    #[test]
    fn dns_settings_are_clamped() {
        let input = DnsSettings {
            server_domain: "NS.Example.COM.".into(),
            upstream_timeout_ms: 5,
            blocklist_update_hours: 0,
            log_retention_days: 9999,
            cache_min_ttl: 900_000,
            cache_max_ttl: 600,
            block_ipv6: "0:0::0".into(),
            ..DnsSettings::default()
        };
        let s = validate_dns(&input).unwrap();
        assert_eq!(s.server_domain, "ns.example.com");
        assert_eq!(s.upstream_timeout_ms, 200);
        assert_eq!(s.blocklist_update_hours, 1);
        assert_eq!(s.log_retention_days, 365);
        assert_eq!((s.cache_min_ttl, s.cache_max_ttl), (600, 600));
        assert_eq!(s.block_ipv6, "::");

        let bad = DnsSettings {
            block_mode: BlockMode::CustomAddress,
            block_ipv4: String::new(),
            block_ipv6: String::new(),
            ..DnsSettings::default()
        };
        assert!(validate_dns(&bad).is_err());
        let bad = DnsSettings {
            server_domain: "kein name".into(),
            ..DnsSettings::default()
        };
        assert!(validate_dns(&bad).is_err());
    }
}
