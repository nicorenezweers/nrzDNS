//! Reverse Proxy: Einträge `Name → HTTP-Ziel` (`proxy_hosts`) und die Adresse, mit der nrzDNS
//! diese Namen beantwortet. Nach jeder Änderung bekommen der Proxy ([`crate::proxy::ProxyState`])
//! die Ziele und die Engine die DNS-Antworten (als eigene kleine Zonen, siehe [`dns_zones`]).

use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::proxy::Target;
use crate::services::settings;
use crate::services::zones::validate_comment;
use nrzdns_types::{
    normalize_domain, ProxyHost, ProxyHostInput, ProxySettings, RecordData, Soa, Zone, ZoneDetail,
    ZoneKind, ZoneRecord,
};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::net::IpAddr;

/// Schlüssel in `app_settings`: [`ProxySettings`].
pub const SETTINGS: &str = "proxy";
/// TTL der DNS-Antworten für Proxy-Namen (kurz, damit Änderungen schnell ankommen).
pub const DNS_TTL: u32 = 60;

type Row = (i64, String, String, bool, String, i64, i64);

pub async fn settings(pool: &SqlitePool) -> AppResult<ProxySettings> {
    Ok(settings::get(pool, SETTINGS).await?.unwrap_or_default())
}

pub async fn save_settings(pool: &SqlitePool, input: &ProxySettings) -> AppResult<ProxySettings> {
    let address = input.address.trim();
    if !address.is_empty() {
        let ip: IpAddr = address
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .map_err(|_| {
                AppError::bad("Adresse: bitte eine IP-Adresse angeben, z. B. 192.168.1.10.")
            })?;
        if ip.is_unspecified() || ip.is_multicast() {
            return Err(AppError::bad("Adresse: diese IP-Adresse geht hier nicht."));
        }
    }
    let s = ProxySettings {
        address: address
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string(),
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

/// Adresse für die DNS-Antwort: aus den Einstellungen, sonst die IP aus dem Ziel (ausser
/// Loopback – das wäre für andere Geräte falsch).
pub fn dns_address(settings: &ProxySettings, target: &str) -> Option<IpAddr> {
    if let Ok(ip) = settings.address.trim().parse::<IpAddr>() {
        return Some(ip);
    }
    let (_, t) = self::target(target).ok()?;
    let ip: IpAddr = t.host.parse().ok()?;
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

fn to_host(r: Row, settings: &ProxySettings) -> ProxyHost {
    let (id, host, target, enabled, comment, created_at, updated_at) = r;
    let dns_address = dns_address(settings, &target)
        .map(|ip| ip.to_string())
        .unwrap_or_default();
    ProxyHost {
        id,
        host,
        target,
        enabled,
        comment,
        dns_address,
        created_at,
        updated_at,
    }
}

/// Alle Einträge, alphabetisch.
pub async fn list(pool: &SqlitePool) -> AppResult<Vec<ProxyHost>> {
    let s = settings(pool).await?;
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, host, target, enabled, comment, created_at, updated_at FROM proxy_hosts ORDER BY host",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| to_host(r, &s)).collect())
}

async fn get(pool: &SqlitePool, id: i64) -> AppResult<ProxyHost> {
    let s = settings(pool).await?;
    let row: Option<Row> = sqlx::query_as(
        "SELECT id, host, target, enabled, comment, created_at, updated_at FROM proxy_hosts WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| to_host(r, &s)).ok_or(AppError::NotFound)
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
    Ok(list(pool)
        .await?
        .into_iter()
        .filter(|h| h.enabled)
        .filter_map(|h| target(&h.target).ok().map(|(_, t)| (h.host, t)))
        .collect())
}

/// DNS-Antworten für aktive Einträge: je Name eine kleine Primärzone mit einem A- bzw.
/// AAAA-Eintrag auf `@`. Gibt es schon eine eigene Zone mit genau diesem Namen, kommt der
/// Eintrag dort hinein (statt der Adresseinträge auf `@`). Zonen weiter oben (`nrz.ch`)
/// bleiben unberührt – die genauere Zone gewinnt.
pub fn merge_zones(zones: &mut Vec<ZoneDetail>, hosts: &[ProxyHost]) {
    for h in hosts.iter().filter(|h| h.enabled) {
        let Ok(ip) = h.dns_address.parse::<IpAddr>() else {
            continue;
        };
        let data = match ip {
            IpAddr::V4(a) => RecordData::A {
                address: a.to_string(),
            },
            IpAddr::V6(a) => RecordData::AAAA {
                address: a.to_string(),
            },
        };
        let record = |zone_id: i64| ZoneRecord {
            id: -h.id,
            zone_id,
            name: "@".into(),
            ttl: DNS_TTL,
            data: data.clone(),
            disabled: false,
            comment: "Reverse Proxy".into(),
            updated_at: h.updated_at,
        };
        if let Some(z) = zones
            .iter_mut()
            .find(|z| z.zone.name == h.host && z.zone.kind == ZoneKind::Primary && !z.zone.disabled)
        {
            z.records.retain(|r| {
                !(matches!(r.name.trim(), "@" | "")
                    && matches!(
                        r.data,
                        RecordData::A { .. } | RecordData::AAAA { .. } | RecordData::CNAME { .. }
                    ))
            });
            z.records.push(record(z.zone.id));
            continue;
        }
        zones.retain(|z| z.zone.name != h.host);
        zones.push(ZoneDetail {
            zone: Zone {
                id: -h.id,
                name: h.host.clone(),
                kind: ZoneKind::Primary,
                disabled: false,
                soa: Soa {
                    minimum: DNS_TTL,
                    ..Soa::default()
                },
                forwarders: Vec::new(),
                comment: "Reverse Proxy".into(),
                record_count: 1,
                created_at: h.created_at,
                updated_at: h.updated_at,
            },
            records: vec![record(-h.id)],
        });
    }
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
    fn dns_answer() {
        let none = ProxySettings::default();
        let ip = |s: &ProxySettings, t: &str| dns_address(s, t).map(|i| i.to_string());
        assert_eq!(
            ip(&none, "http://100.78.107.162:8350").as_deref(),
            Some("100.78.107.162")
        );
        assert_eq!(ip(&none, "http://nas.local:8350"), None);
        assert_eq!(ip(&none, "http://127.0.0.1:8350"), None);
        let set = ProxySettings {
            address: "192.168.0.198".into(),
        };
        assert_eq!(
            ip(&set, "http://127.0.0.1:8350").as_deref(),
            Some("192.168.0.198")
        );
    }
}
