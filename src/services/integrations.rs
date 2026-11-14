//! Verbindungen zu Cloudflare (ganze Domain: DNS-Einträge, dazu HTTPS-Zertifikate) und
//! NetBird (ganzes Netzwerk: Geräte, Gruppen, Zugriff, Netzwerke, DNS, Setup-Keys, Benutzer).
//!
//! Die Tokens bleiben auf dem Server. Die Oberfläche spricht beide APIs über
//! `/api/v1/cloudflare/…` und `/api/v1/netbird/…`; durchgereicht werden nur die Pfade aus
//! [`cloudflare_allowed`] und [`netbird_allowed`] – lesen darf jeder Angemeldete, ändern nur
//! Admins.

use crate::config::Config;
use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::services::settings;
use nrzdns_types::{IntegrationStatus, IntegrationsInput, IntegrationsStatus};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Duration;

const SETTINGS: &str = "integrations";
pub const NETBIRD_CLOUD: &str = "https://api.netbird.io";
/// Höchstens so gross darf ein Body an die APIs sein.
pub const MAX_BODY: usize = 256 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Stored {
    cloudflare_token: String,
    netbird_url: String,
    netbird_token: String,
}

async fn stored(pool: &SqlitePool) -> AppResult<Stored> {
    let mut s: Stored = settings::get(pool, SETTINGS).await?.unwrap_or_default();
    if s.cloudflare_token.is_empty() {
        // Früher stand das Cloudflare-Token bei den HTTPS-Einstellungen
        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase", default)]
        struct OldTls {
            cloudflare_token: String,
        }
        let old: OldTls = settings::get(pool, "tls").await?.unwrap_or_default();
        if !old.cloudflare_token.is_empty() {
            s.cloudflare_token = old.cloudflare_token;
            settings::set(pool, SETTINGS, &s).await?;
        }
    }
    Ok(s)
}

pub async fn cloudflare_token(pool: &SqlitePool) -> AppResult<String> {
    Ok(stored(pool).await?.cloudflare_token)
}

fn check_token(token: &str, what: &str) -> AppResult<()> {
    if token.len() > 300
        || !token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(AppError::bad(format!(
            "{what}: bitte das Token unverändert kopieren (Buchstaben, Ziffern, - _ .)."
        )));
    }
    Ok(())
}

pub async fn set_cloudflare_token(pool: &SqlitePool, token: &str) -> AppResult<()> {
    let token = token.trim();
    check_token(token, "Cloudflare-Token")?;
    let mut s = stored(pool).await?;
    s.cloudflare_token = token.to_string();
    settings::set(pool, SETTINGS, &s).await
}

fn netbird_url(s: &Stored) -> String {
    let u = s.netbird_url.trim().trim_end_matches('/');
    let u = u.strip_suffix("/api").unwrap_or(u);
    if u.is_empty() {
        NETBIRD_CLOUD.to_string()
    } else {
        u.to_string()
    }
}

pub async fn save(pool: &SqlitePool, input: &IntegrationsInput) -> AppResult<()> {
    let mut s = stored(pool).await?;
    if input.clear_cloudflare {
        s.cloudflare_token.clear();
    } else if !input.cloudflare_token.trim().is_empty() {
        check_token(input.cloudflare_token.trim(), "Cloudflare-Token")?;
        s.cloudflare_token = input.cloudflare_token.trim().to_string();
    }
    if input.clear_netbird {
        s.netbird_token.clear();
    } else if !input.netbird_token.trim().is_empty() {
        check_token(input.netbird_token.trim(), "NetBird-Token")?;
        s.netbird_token = input.netbird_token.trim().to_string();
    }
    let url = input.netbird_url.trim();
    if !url.is_empty() {
        let parsed = reqwest::Url::parse(url)
            .map_err(|_| AppError::bad("NetBird-Adresse: z. B. https://api.netbird.io"))?;
        if !matches!(parsed.scheme(), "https" | "http") || parsed.host_str().is_none() {
            return Err(AppError::bad(
                "NetBird-Adresse: z. B. https://api.netbird.io",
            ));
        }
    }
    s.netbird_url = url.to_string();
    settings::set(pool, SETTINGS, &s).await?;
    clear_peer_cache();
    Ok(())
}

fn client() -> AppResult<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent(concat!("nrzNetwork/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AppError::Config(e.to_string()))
}

/// Ist der Pfad (ohne `/client/v4/`) für Cloudflare erlaubt? Nur Zonen lesen und
/// DNS-Einträge verwalten.
pub fn cloudflare_allowed(method: &Method, segments: &[&str]) -> bool {
    let id =
        |s: &str| !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric());
    match segments {
        ["zones"] => *method == Method::GET,
        ["zones", z] => id(z) && *method == Method::GET,
        ["zones", z, "dns_records"] => id(z) && matches!(*method, Method::GET | Method::POST),
        ["zones", z, "dns_records", r] => {
            id(z)
                && id(r)
                && matches!(
                    *method,
                    Method::GET | Method::PUT | Method::PATCH | Method::DELETE
                )
        }
        _ => false,
    }
}

/// Ist der Pfad (ohne `/api/`) für NetBird erlaubt? Das Konto selbst, Passwörter und das
/// Ereignisprotokoll lassen sich nicht ändern.
pub fn netbird_allowed(method: &Method, segments: &[&str]) -> bool {
    const RESOURCES: &[&str] = &[
        "peers",
        "groups",
        "policies",
        "setup-keys",
        "networks",
        "dns",
        "users",
        "events",
        "posture-checks",
        "accounts",
        "routes",
        "reverse-proxies",
    ];
    let Some(first) = segments.first() else {
        return false;
    };
    if !RESOURCES.contains(first)
        || segments.len() > 5
        || !segments.iter().all(|s| {
            !s.is_empty()
                && s.len() <= 80
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        })
    {
        return false;
    }
    if *method == Method::GET {
        return true;
    }
    if matches!(*first, "accounts" | "events") {
        return false;
    }
    if *first == "users" && segments.iter().any(|s| matches!(*s, "password" | "accept")) {
        return false;
    }
    matches!(*method, Method::POST | Method::PUT | Method::DELETE)
}

/// Antwort einer der APIs.
pub struct Upstream {
    pub status: u16,
    pub body: Value,
}

fn hint_for(status: u16, service: &str) -> String {
    match status {
        401 => format!(" – das {service}-Token stimmt nicht oder ist abgelaufen."),
        403 => format!(" – dem {service}-Token fehlt dafür das Recht."),
        _ => String::new(),
    }
}

async fn send(req: reqwest::RequestBuilder, service: &str) -> AppResult<Upstream> {
    let resp = req
        .send()
        .await
        .map_err(|e| AppError::BadGateway(format!("{service} nicht erreichbar: {e}")))?;
    let status = resp.status().as_u16();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| AppError::BadGateway(format!("{service}: {e}")))?;
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            Value::String(String::from_utf8_lossy(&bytes).chars().take(500).collect())
        })
    };
    Ok(Upstream { status, body })
}

/// Fehlermeldung aus einer Antwort (Cloudflare: `errors[].message`, NetBird: `message`).
pub fn error_message(service: &str, up: &Upstream) -> String {
    let b = &up.body;
    let msg = b["errors"]
        .as_array()
        .map(|e| {
            e.iter()
                .filter_map(|x| x["message"].as_str())
                .collect::<Vec<_>>()
                .join("; ")
        })
        .filter(|m| !m.is_empty())
        .or_else(|| b["message"].as_str().map(str::to_string))
        .or_else(|| b.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("HTTP {}", up.status));
    format!("{service}: {msg}{}", hint_for(up.status, service))
}

/// Anfrage an Cloudflare (`segments` ohne `/client/v4`).
pub async fn cloudflare(
    pool: &SqlitePool,
    config: &Config,
    method: Method,
    segments: &[&str],
    query: Option<&str>,
    body: Option<Value>,
) -> AppResult<Upstream> {
    if !cloudflare_allowed(&method, segments) {
        return Err(AppError::Forbidden(
            "Diese Cloudflare-Funktion ist in nrzNetwork nicht freigegeben.".into(),
        ));
    }
    let token = cloudflare_token(pool).await?;
    if token.is_empty() {
        return Err(AppError::bad(
            "Cloudflare ist nicht verbunden – Token unter Einstellungen → Verbindungen eintragen.",
        ));
    }
    let mut url = format!(
        "{}/{}",
        config.cloudflare_api.trim_end_matches('/'),
        segments.join("/")
    );
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        url.push('?');
        url.push_str(q);
    }
    let mut req = client()?.request(method, url).bearer_auth(token);
    if let Some(b) = body {
        req = req.json(&b);
    }
    send(req, "Cloudflare").await
}

/// Interne Anfrage an Cloudflare ohne Freigabeliste (nur für nrzNetwork selbst, z. B. den
/// Tunnel). `path` ohne `/client/v4/`, darf eine Query enthalten.
pub(crate) async fn cloudflare_raw(
    pool: &SqlitePool,
    config: &Config,
    method: Method,
    path: &str,
    query: Option<&str>,
    body: Option<Value>,
) -> AppResult<Upstream> {
    let token = cloudflare_token(pool).await?;
    if token.is_empty() {
        return Err(AppError::bad(
            "Cloudflare ist nicht verbunden – Token unter Einstellungen → Verbindungen eintragen.",
        ));
    }
    let mut url = format!(
        "{}/{}",
        config.cloudflare_api.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        url.push(if url.contains('?') { '&' } else { '?' });
        url.push_str(q);
    }
    let mut req = client()?.request(method, url).bearer_auth(token);
    if let Some(b) = body {
        req = req.json(&b);
    }
    send(req, "Cloudflare").await
}

/// Anfrage an NetBird (`segments` ohne `/api`).
pub async fn netbird(
    pool: &SqlitePool,
    method: Method,
    segments: &[&str],
    query: Option<&str>,
    body: Option<Value>,
) -> AppResult<Upstream> {
    if !netbird_allowed(&method, segments) {
        return Err(AppError::Forbidden(
            "Diese NetBird-Funktion ist in nrzNetwork nicht freigegeben.".into(),
        ));
    }
    let s = stored(pool).await?;
    if s.netbird_token.is_empty() {
        return Err(AppError::bad(
            "NetBird ist nicht verbunden – Token unter Einstellungen → Verbindungen eintragen.",
        ));
    }
    let mut url = format!("{}/api/{}", netbird_url(&s), segments.join("/"));
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        url.push('?');
        url.push_str(q);
    }
    let mut req = client()?
        .request(method.clone(), url)
        .header("Authorization", format!("Token {}", s.netbird_token))
        .header("Accept", "application/json");
    if let Some(b) = body {
        req = req.json(&b);
    }
    let up = send(req, "NetBird").await?;
    if method != Method::GET && (200..300).contains(&up.status) {
        clear_peer_cache();
    }
    Ok(up)
}

/// Verbindungen prüfen (ruft beide APIs auf).
pub async fn status(
    pool: &SqlitePool,
    config: &Config,
    test: bool,
) -> AppResult<IntegrationsStatus> {
    let s = stored(pool).await?;
    let mut out = IntegrationsStatus {
        cloudflare: IntegrationStatus {
            configured: !s.cloudflare_token.is_empty(),
            ..IntegrationStatus::default()
        },
        netbird: IntegrationStatus {
            configured: !s.netbird_token.is_empty(),
            ..IntegrationStatus::default()
        },
        netbird_url: if s.netbird_url.is_empty() {
            String::new()
        } else {
            netbird_url(&s)
        },
    };
    if !test {
        return Ok(out);
    }
    if out.cloudflare.configured {
        match cloudflare(
            pool,
            config,
            Method::GET,
            &["zones"],
            Some("per_page=50"),
            None,
        )
        .await
        {
            Ok(up) if (200..300).contains(&up.status) => {
                let zones: Vec<String> = up.body["result"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|z| z["name"].as_str().map(str::to_string))
                    .collect();
                out.cloudflare.ok = true;
                out.cloudflare.detail = if zones.is_empty() {
                    "Verbunden, aber das Token sieht keine Zone.".into()
                } else {
                    format!("Verbunden: {}", zones.join(", "))
                };
            }
            Ok(up) => out.cloudflare.detail = error_message("Cloudflare", &up),
            Err(e) => out.cloudflare.detail = e.to_string(),
        }
    }
    if out.netbird.configured {
        match netbird(pool, Method::GET, &["users", "current"], None, None).await {
            Ok(up) if (200..300).contains(&up.status) => {
                let who = up.body["email"]
                    .as_str()
                    .filter(|e| !e.is_empty())
                    .or_else(|| up.body["name"].as_str())
                    .unwrap_or("?");
                let role = up.body["role"].as_str().unwrap_or("");
                out.netbird.ok = true;
                out.netbird.detail = format!("Verbunden als {who} ({role})");
            }
            Ok(up) => out.netbird.detail = error_message("NetBird", &up),
            Err(e) => out.netbird.detail = e.to_string(),
        }
    }
    Ok(out)
}

/// IP → Name der NetBird-Geräte (eine Minute zwischengespeichert, leer ohne Verbindung).
type PeerCache = Mutex<(i64, HashMap<IpAddr, String>)>;

fn peer_cache() -> &'static PeerCache {
    static CACHE: OnceLock<PeerCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new((0, HashMap::new())))
}

fn clear_peer_cache() {
    peer_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .0 = 0;
}

pub async fn netbird_peer_names(pool: &SqlitePool) -> HashMap<IpAddr, String> {
    {
        let c = peer_cache().lock().unwrap_or_else(PoisonError::into_inner);
        if now() - c.0 < 60 {
            return c.1.clone();
        }
    }
    let mut map = HashMap::new();
    let configured = stored(pool)
        .await
        .is_ok_and(|s| !s.netbird_token.is_empty());
    if configured {
        if let Ok(up) = netbird(pool, Method::GET, &["peers"], None, None).await {
            for p in up.body.as_array().into_iter().flatten() {
                let name = p["name"].as_str().unwrap_or_default().to_string();
                for key in ["ip", "ipv6"] {
                    if let Some(ip) = p[key].as_str().and_then(|s| s.parse::<IpAddr>().ok()) {
                        map.insert(ip, name.clone());
                    }
                }
            }
        }
    }
    *peer_cache().lock().unwrap_or_else(PoisonError::into_inner) = (now(), map.clone());
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_paths() {
        assert!(cloudflare_allowed(&Method::GET, &["zones"]));
        assert!(!cloudflare_allowed(&Method::DELETE, &["zones", "abc123"]));
        assert!(cloudflare_allowed(
            &Method::POST,
            &["zones", "abc123", "dns_records"]
        ));
        assert!(cloudflare_allowed(
            &Method::PATCH,
            &["zones", "abc", "dns_records", "r1"]
        ));
        assert!(!cloudflare_allowed(
            &Method::GET,
            &["zones", "abc", "settings"]
        ));
        assert!(!cloudflare_allowed(&Method::GET, &["accounts"]));
        assert!(!cloudflare_allowed(
            &Method::GET,
            &["zones", "a.b", "dns_records"]
        ));
    }

    #[test]
    fn netbird_paths() {
        assert!(netbird_allowed(&Method::GET, &["peers"]));
        assert!(netbird_allowed(&Method::PUT, &["peers", "abc"]));
        assert!(netbird_allowed(
            &Method::POST,
            &["networks", "n1", "resources"]
        ));
        assert!(netbird_allowed(&Method::GET, &["accounts"]));
        assert!(!netbird_allowed(&Method::DELETE, &["accounts", "a1"]));
        assert!(!netbird_allowed(&Method::PUT, &["users", "u1", "password"]));
        assert!(!netbird_allowed(&Method::GET, &["instance"]));
        assert!(!netbird_allowed(&Method::GET, &["peers", "a/b"]));
        assert!(!netbird_allowed(&Method::PATCH, &["peers", "abc"]));
    }
}
