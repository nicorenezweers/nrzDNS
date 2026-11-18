//! Reverse Proxy: Einträge `Name → HTTP-Ziel` (`proxy_hosts`) und die Adresse, mit der nrzNetwork
//! diese Namen beantwortet. Nach jeder Änderung bekommen der Proxy ([`crate::proxy::ProxyState`])
//! die Ziele und die Engine die DNS-Antworten (als eigene kleine Zonen, siehe [`dns_zones`]).

use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::proxy::Target;
use crate::services::settings;
use crate::services::zones::validate_comment;
use nrzdns_types::{normalize_domain, GatewayStatus, ProxyHost, ProxyHostInput, ProxySettings};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

/// Schlüssel in `app_settings`: [`ProxySettings`].
pub const SETTINGS: &str = "proxy";
/// Vom Umbrel-Wächter erkannte Adressen des Geräts (im Datenordner).
pub const HOST_ADDRESSES: &str = "host-addresses";
/// Für den Umbrel-Wächter: `on` = Port 80 an den Proxy geben, `off` = nicht.
pub const PORT80_FLAG: &str = "port80";
/// Zustand, den der Umbrel-Wächter schreibt (JSON, [`GatewayStatus`]).
pub const GATEWAY_STATE: &str = "gateway.json";

/// Schalter für den Umbrel-Wächter schreiben (Fehler nur ins Protokoll).
pub fn write_port80_flag(data_dir: &Path, settings: &ProxySettings) {
    let value = if settings.port80 { "on\n" } else { "off\n" };
    if let Err(e) = std::fs::write(data_dir.join(PORT80_FLAG), value) {
        tracing::warn!("{PORT80_FLAG} schreiben: {e}");
    }
}

/// Zustand des Umbrel-Wächters (`None` = kein Wächter, also nicht auf Umbrel).
pub fn gateway_status(data_dir: &Path) -> Option<GatewayStatus> {
    let raw = std::fs::read_to_string(data_dir.join(GATEWAY_STATE)).ok()?;
    let mut s: GatewayStatus = serde_json::from_str(&raw).ok()?;
    // Meldet sich der Wächter nicht mehr, gilt die Weiterleitung als aus
    if crate::db::now() - s.updated_at > 120 {
        s.active = false;
        s.message = "Der Wächter auf dem Gerät meldet sich nicht (App neu starten).".into();
    }
    Some(s)
}

type Row = (i64, String, String, bool, String, i64, i64, bool);

pub async fn settings(pool: &SqlitePool) -> AppResult<ProxySettings> {
    Ok(settings::get(pool, SETTINGS).await?.unwrap_or_default())
}

pub async fn save_settings(pool: &SqlitePool, input: &ProxySettings) -> AppResult<ProxySettings> {
    let mut parts = Vec::new();
    for p in input
        .address
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let ip: IpAddr = p
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .map_err(|_| {
                AppError::bad("Adresse: bitte eine IP-Adresse angeben, z. B. 192.168.1.10.")
            })?;
        if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() {
            return Err(AppError::bad("Adresse: diese IP-Adresse geht hier nicht."));
        }
        let ip = ip.to_string();
        if !parts.contains(&ip) {
            parts.push(ip);
        }
    }
    if parts.len() > 8 {
        return Err(AppError::bad("Adresse: höchstens 8 IP-Adressen."));
    }
    let mut minutes: Vec<u32> = input
        .unlock_minutes
        .iter()
        .copied()
        .filter(|m| (1..=crate::services::unlocks::MAX_MINUTES).contains(m))
        .collect();
    minutes.sort_unstable();
    minutes.dedup();
    minutes.truncate(6);
    if input.allow_unlock && minutes.is_empty() {
        return Err(AppError::bad(
            "Sperrseite: mindestens einen Zeitraum (1–1440 Minuten) angeben.",
        ));
    }
    let s = ProxySettings {
        address: parts.join(", "),
        allow_unlock: input.allow_unlock,
        unlock_minutes: minutes,
        allow_requests: input.allow_requests,
        port80: input.port80,
        access_log_days: input.access_log_days.min(365),
    };
    settings::set(pool, SETTINGS, &s).await?;
    Ok(s)
}

/// Name prüfen und vereinheitlichen (kein Platzhalter).
pub fn host(input: &str) -> AppResult<String> {
    let raw = input.trim();
    let bad = || AppError::bad("Name: bitte einen gültigen Namen angeben, z. B. music.nrz.ch.");
    if raw.starts_with('*') || raw.contains("://") || raw.contains('/') {
        return Err(bad());
    }
    let h = normalize_domain(raw).ok_or_else(bad)?;
    if h.parse::<IpAddr>().is_ok() {
        return Err(bad());
    }
    Ok(h)
}

/// Ziel prüfen: `http://adresse[:port][/pfad]`, ohne `http://` wird es ergänzt.
/// Ergebnis ohne `/` am Ende.
pub fn target(input: &str) -> AppResult<(String, Target)> {
    let raw = input.trim();
    let bad = || AppError::bad("Ziel: bitte eine Adresse wie http://192.168.1.10:8350 angeben.");
    if raw.len() > 500 || raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(bad());
    }
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Err(AppError::bad(
            "Ziel: nur HTTP-Ziele (http://…) – der Proxy spricht kein HTTPS zum Ziel.",
        ));
    }
    let with_scheme = if lower.starts_with("http://") {
        format!("http://{}", &raw[7..])
    } else if lower.contains("://") {
        return Err(bad());
    } else {
        format!("http://{raw}")
    };
    let uri: hyper::Uri = with_scheme.parse().map_err(|_| bad())?;
    let authority = uri.authority().ok_or_else(bad)?;
    if authority.as_str().contains('@') {
        return Err(bad());
    }
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let host_ok = host.parse::<IpAddr>().is_ok()
        || normalize_domain(host).as_deref() == Some(&host.to_ascii_lowercase());
    if host.is_empty() || !host_ok || uri.query().is_some() {
        return Err(bad());
    }
    let port = authority.port_u16().unwrap_or(80);
    if port == 0 {
        return Err(bad());
    }
    let host = host.to_ascii_lowercase();
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let base = uri.path().trim_end_matches('/').to_string();
    let shown = if port == 80 {
        authority.trim_end_matches(":80").to_string()
    } else {
        authority.clone()
    };
    let normalized = format!("http://{shown}{base}");
    Ok((
        normalized,
        Target {
            authority,
            host,
            base,
        },
    ))
}

fn to_host(r: Row, device: &[IpAddr]) -> ProxyHost {
    let (id, host, target, enabled, comment, created_at, updated_at, public) = r;
    let dns_address = if device.is_empty() {
        target_ip(&target)
            .map(|ip| ip.to_string())
            .unwrap_or_default()
    } else {
        device
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    ProxyHost {
        id,
        host,
        target,
        enabled,
        comment,
        dns_address,
        created_at,
        updated_at,
        public,
    }
}

/// Alle Einträge, alphabetisch (`device` = Adressen dieses Geräts für die Anzeige).
pub async fn list(pool: &SqlitePool, device: &[IpAddr]) -> AppResult<Vec<ProxyHost>> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, host, target, enabled, comment, created_at, updated_at, public FROM proxy_hosts ORDER BY host",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| to_host(r, device)).collect())
}

/// Über den Cloudflare Tunnel öffentlich machen (oder nicht).
pub async fn set_public(pool: &SqlitePool, id: i64, public: bool) -> AppResult<ProxyHost> {
    let done = sqlx::query("UPDATE proxy_hosts SET public = ?, updated_at = ? WHERE id = ?")
        .bind(public)
        .bind(crate::db::now())
        .bind(id)
        .execute(pool)
        .await?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    get(pool, id).await
}

pub async fn get(pool: &SqlitePool, id: i64) -> AppResult<ProxyHost> {
    let row: Option<Row> = sqlx::query_as(
        "SELECT id, host, target, enabled, comment, created_at, updated_at, public FROM proxy_hosts WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| to_host(r, &[])).ok_or(AppError::NotFound)
}

const DUPLICATE: &str = "Für diesen Namen gibt es schon einen Proxy-Eintrag.";

pub async fn create(pool: &SqlitePool, input: &ProxyHostInput) -> AppResult<ProxyHost> {
    let host = host(&input.host)?;
    let (target, _) = target(&input.target)?;
    let comment = validate_comment(&input.comment)?;
    let t = now();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO proxy_hosts (host, target, enabled, comment, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(&host)
    .bind(&target)
    .bind(input.enabled)
    .bind(&comment)
    .bind(t)
    .bind(t)
    .fetch_one(pool)
    .await
    .map_err(|e| AppError::unique(e, DUPLICATE))?;
    get(pool, id).await
}

pub async fn update(pool: &SqlitePool, id: i64, input: &ProxyHostInput) -> AppResult<ProxyHost> {
    let host = host(&input.host)?;
    let (target, _) = target(&input.target)?;
    let comment = validate_comment(&input.comment)?;
    let done = sqlx::query(
        "UPDATE proxy_hosts SET host = ?, target = ?, enabled = ?, comment = ?, updated_at = ?
         WHERE id = ?",
    )
    .bind(&host)
    .bind(&target)
    .bind(input.enabled)
    .bind(&comment)
    .bind(now())
    .bind(id)
    .execute(pool)
    .await
    .map_err(|e| AppError::unique(e, DUPLICATE))?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    get(pool, id).await
}

pub async fn delete(pool: &SqlitePool, id: i64) -> AppResult<()> {
    let done = sqlx::query("DELETE FROM proxy_hosts WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Aktive Einträge als Ziele für den Proxy.
pub async fn routes(pool: &SqlitePool) -> AppResult<HashMap<String, Target>> {
    Ok(list(pool, &[])
        .await?
        .into_iter()
        .filter(|h| h.enabled)
        .filter_map(|h| target(&h.target).ok().map(|(_, t)| (h.host, t)))
        .collect())
}

/// Adressen dieses Geräts: eingetragen (Einstellungen) oder vom Umbrel-Wächter erkannt
/// (`host-addresses` im Datenordner, eine IP je Zeile).
pub fn device_addresses(settings: &ProxySettings, data_dir: &Path) -> Vec<IpAddr> {
    let configured = parse_addresses(&settings.address);
    if !configured.is_empty() {
        return configured;
    }
    std::fs::read_to_string(data_dir.join(HOST_ADDRESSES))
        .map(|s| parse_addresses(&s))
        .unwrap_or_default()
}

/// IPs aus einer Liste (Kommas, Leerzeichen oder Zeilen), ohne Loopback und Unspezifische.
pub fn parse_addresses(s: &str) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for ip in s
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter_map(|p| {
            p.trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
                .ok()
        })
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast())
    {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// Namen für die Engine: aktive Einträge → eigene Adressen (leer = die des Geräts). Ohne
/// bekannte Geräteadressen gilt die IP aus dem Ziel.
pub fn local_hosts(hosts: &[ProxyHost], device: &[IpAddr]) -> HashMap<String, Vec<IpAddr>> {
    hosts
        .iter()
        .filter(|h| h.enabled)
        .filter_map(|h| {
            if !device.is_empty() {
                return Some((h.host.clone(), Vec::new()));
            }
            let ip = target_ip(&h.target)?;
            Some((h.host.clone(), vec![ip]))
        })
        .collect()
}

fn target_ip(target: &str) -> Option<IpAddr> {
    let (_, t) = self::target(target).ok()?;
    let ip: IpAddr = t.host.parse().ok()?;
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        let t = |s: &str| target(s).map(|(n, _)| n).ok();
        assert_eq!(
            t("http://100.78.107.162:8350/").as_deref(),
            Some("http://100.78.107.162:8350")
        );
        assert_eq!(
            t("100.78.107.162:8550").as_deref(),
            Some("http://100.78.107.162:8550")
        );
        assert_eq!(
            t("HTTP://Nas.Local/app/").as_deref(),
            Some("http://nas.local/app")
        );
        assert_eq!(
            t("http://[fd00::1]:81").as_deref(),
            Some("http://[fd00::1]:81")
        );
        assert!(t("https://x.example").is_none());
        assert!(t("ftp://x.example").is_none());
        assert!(t("http://user@x.example").is_none());
        assert!(t("http://x.example/?a=1").is_none());
        assert!(t("").is_none());
        let (_, tg) = target("http://10.0.0.5:8350/sub").unwrap();
        assert_eq!(tg.authority, "10.0.0.5:8350");
        assert_eq!(tg.base, "/sub");
    }

    #[test]
    fn hosts() {
        assert_eq!(host(" Music.NRZ.ch. ").unwrap(), "music.nrz.ch");
        assert!(host("*.nrz.ch").is_err());
        assert!(host("http://music.nrz.ch").is_err());
        assert!(host("10.0.0.1").is_err());
    }

    #[test]
    fn addresses() {
        let ips = |s: &str| {
            parse_addresses(s)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ips("192.168.0.198, 100.78.107.162\n127.0.0.1 0.0.0.0 x"),
            ["192.168.0.198", "100.78.107.162"]
        );
        let h = |t: &str| ProxyHost {
            id: 1,
            host: "music.nrz.ch".into(),
            target: t.into(),
            enabled: true,
            comment: String::new(),
            dns_address: String::new(),
            created_at: 0,
            updated_at: 0,
            public: false,
        };
        let m = local_hosts(&[h("http://100.78.107.162:8350")], &[]);
        assert_eq!(
            m["music.nrz.ch"],
            vec!["100.78.107.162".parse::<IpAddr>().unwrap()]
        );
        assert!(local_hosts(&[h("http://127.0.0.1:8350")], &[]).is_empty());
        let m = local_hosts(
            &[h("http://nas.local:8350")],
            &["192.168.0.198".parse().unwrap()],
        );
        assert!(m["music.nrz.ch"].is_empty());
    }
}
