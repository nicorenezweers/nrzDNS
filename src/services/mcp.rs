//! MCP-Server (Model Context Protocol): Zugang per Token und die Werkzeuge.
//!
//! Gedacht für nrzDashboard und andere MCP-Clients: Kennzahlen für eine Übersicht
//! (`get_overview`), Statistiken, Abfrageprotokoll, Zustand, Reverse Proxy, Docker,
//! Netzwerkkarte, DNS-Abfragen und die ganze REST-API (`api_request`) – und, wenn das Token es
//! darf, Sperren ein-/ausschalten, pausieren, Listen umschalten, Regeln, Cache und Änderungen
//! über die API.
//!
//! Das Protokoll (JSON-RPC über HTTP) steht in `routes::mcp`; hier nur Fachlogik. Es gibt
//! beliebig viele benannte Tokens, jedes mit eigenem Recht (nur lesen / ändern). Sie liegen nur
//! als SHA-256 in der Datenbank (`app_settings`, Schlüssel `mcp`); ein Token aus
//! `NRZDNS_MCP_TOKEN` gilt zusätzlich (id 0).

use crate::auth::session;
use crate::config::Config;
use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::services::blocking::{self, Updater};
use crate::services::dieter::{self, DieterState};
use crate::services::domains::{self, Kind};
use crate::services::{dashboard, querylog, settings, sync, zones};
use nrzdns_engine::Engine;
use nrzdns_types::{
    BlockListInput, Dashboard, DomainInput, McpStatus, McpToken, McpTokenInfo, McpTokenInput,
    QueryLogFilter, ResolveInput, StatsRange, TopEntry,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Mutex;

/// Schlüssel in `app_settings`.
const KEY: &str = "mcp";
/// Pfad des MCP-Servers.
pub const PATH: &str = "/mcp";
/// Präfix neuer Tokens (erkennbar in Konfigurationsdateien).
const TOKEN_PREFIX: &str = "nrzdns_mcp_";
/// Einträge je Top-Liste in der Übersicht.
const OVERVIEW_TOP: usize = 5;
/// Höchstens so viele Tokens.
const MAX_TOKENS: usize = 50;
/// „Zuletzt benutzt“ höchstens so oft (Sekunden) in die Datenbank schreiben.
const LAST_USED_PERSIST_SECS: i64 = 300;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct StoredToken {
    id: i64,
    name: String,
    hash: String,
    hint: String,
    created_at: i64,
    allow_changes: bool,
    last_used_at: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Stored {
    tokens: Vec<StoredToken>,
    next_id: i64,
    /// Rechte des Tokens aus `NRZDNS_MCP_TOKEN` (früher: Rechte des einzigen Tokens).
    allow_changes: bool,
    // Bis 1.13: genau ein Token – wird beim Lesen in `tokens` übernommen.
    #[serde(skip_serializing)]
    token_hash: Option<String>,
    #[serde(skip_serializing)]
    token_hint: Option<String>,
    #[serde(skip_serializing)]
    created_at: Option<i64>,
}

impl Stored {
    fn next_id(&mut self) -> i64 {
        let max = self.tokens.iter().map(|t| t.id).max().unwrap_or(0);
        self.next_id = self.next_id.max(max) + 1;
        self.next_id
    }
}

/// Laufzeit-Zustand: wann welches Token zuletzt benutzt wurde, und eine Sperre, damit sich
/// gleichzeitige Änderungen an den Tokens nicht überschreiben.
#[derive(Debug, Default)]
pub struct McpState {
    last_used: Mutex<HashMap<i64, i64>>,
    write: tokio::sync::Mutex<()>,
}

impl McpState {
    fn last_used(&self, id: i64) -> Option<i64> {
        self.last_used
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .copied()
    }

    /// Benutzung merken; `true`, wenn sie in die Datenbank soll.
    fn touch(&self, id: i64, stored: Option<i64>) -> bool {
        let t = now();
        self.last_used
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, t);
        id != 0 && stored.is_none_or(|s| t - s >= LAST_USED_PERSIST_SECS)
    }
}

async fn stored(pool: &SqlitePool) -> AppResult<Stored> {
    let mut s = settings::get::<Stored>(pool, KEY)
        .await?
        .unwrap_or_default();
    if let Some(hash) = s.token_hash.take() {
        if !s.tokens.iter().any(|t| t.hash == hash) {
            let id = s.next_id();
            s.tokens.push(StoredToken {
                id,
                name: "Standard".into(),
                hash,
                hint: s
                    .token_hint
                    .clone()
                    .unwrap_or_else(|| format!("{TOKEN_PREFIX}…")),
                created_at: s.created_at.unwrap_or_else(now),
                allow_changes: s.allow_changes,
                last_used_at: None,
            });
        }
    }
    Ok(s)
}

/// Erkennbarer Teil des Tokens: bei eigenen Tokens Präfix + 4 + … + 4 Zeichen, sonst 3 + … + 3.
fn hint(token: &str) -> String {
    let (prefix, rest) = match token.strip_prefix(TOKEN_PREFIX) {
        Some(rest) => (TOKEN_PREFIX, rest),
        None => ("", token),
    };
    let chars: Vec<char> = rest.chars().collect();
    let n = if prefix.is_empty() { 3 } else { 4 };
    if chars.len() < 4 * n {
        return format!("{prefix}…");
    }
    let head: String = chars[..n].iter().collect();
    let tail: String = chars[chars.len() - n..].iter().collect();
    format!("{prefix}{head}…{tail}")
}

/// Vergleich ohne frühes Abbrechen (beide Seiten sind gleich lange Hex-Hashes).
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn info(t: &StoredToken, state: &McpState) -> McpTokenInfo {
    McpTokenInfo {
        id: t.id,
        name: t.name.clone(),
        hint: t.hint.clone(),
        created_at: Some(t.created_at),
        allow_changes: t.allow_changes,
        last_used_at: state.last_used(t.id).max(t.last_used_at),
        from_env: false,
    }
}

fn build_status(s: &Stored, config: &Config, state: &McpState) -> McpStatus {
    let mut tokens = Vec::new();
    if let Some(t) = config.mcp_env_token() {
        tokens.push(McpTokenInfo {
            id: 0,
            name: "NRZDNS_MCP_TOKEN".into(),
            hint: hint(t),
            created_at: None,
            allow_changes: s.allow_changes,
            last_used_at: state.last_used(0),
            from_env: true,
        });
    }
    tokens.extend(s.tokens.iter().map(|t| info(t, state)));
    McpStatus {
        enabled: !tokens.is_empty(),
        tokens,
        path: PATH.into(),
    }
}

pub async fn status(pool: &SqlitePool, config: &Config, state: &McpState) -> AppResult<McpStatus> {
    Ok(build_status(&stored(pool).await?, config, state))
}

fn clean_name(name: &str) -> AppResult<String> {
    let name = name.trim();
    if name.chars().count() > 60 {
        return Err(AppError::bad("Name: höchstens 60 Zeichen."));
    }
    Ok(name.to_string())
}

/// Neues Token mit Namen und Rechten.
pub async fn create_token(
    pool: &SqlitePool,
    config: &Config,
    state: &McpState,
    input: &McpTokenInput,
) -> AppResult<McpToken> {
    let _guard = state.write.lock().await;
    let mut s = stored(pool).await?;
    if s.tokens.len() >= MAX_TOKENS {
        return Err(AppError::Conflict(format!(
            "Höchstens {MAX_TOKENS} Tokens – bitte zuerst ein altes löschen."
        )));
    }
    let token = format!("{TOKEN_PREFIX}{}", session::new_token());
    let id = s.next_id();
    let mut name = clean_name(&input.name)?;
    if name.is_empty() {
        name = format!("Token {id}");
    }
    let t = StoredToken {
        id,
        name,
        hash: session::hash_token(&token),
        hint: hint(&token),
        created_at: now(),
        allow_changes: input.allow_changes,
        last_used_at: None,
    };
    let info = info(&t, state);
    s.tokens.push(t);
    settings::set(pool, KEY, &s).await?;
    Ok(McpToken {
        token,
        info,
        status: build_status(&s, config, state),
    })
}

/// Name und Rechte eines Tokens ändern.
pub async fn update_token(
    pool: &SqlitePool,
    config: &Config,
    state: &McpState,
    id: i64,
    input: &McpTokenInput,
) -> AppResult<McpStatus> {
    let _guard = state.write.lock().await;
    let mut s = stored(pool).await?;
    let name = clean_name(&input.name)?;
    let t = s
        .tokens
        .iter_mut()
        .find(|t| t.id == id)
        .ok_or_else(|| AppError::NotFound)?;
    if !name.is_empty() {
        t.name = name;
    }
    t.allow_changes = input.allow_changes;
    settings::set(pool, KEY, &s).await?;
    Ok(build_status(&s, config, state))
}

/// Token löschen – es gilt sofort nicht mehr.
pub async fn revoke_token(
    pool: &SqlitePool,
    config: &Config,
    state: &McpState,
    id: i64,
) -> AppResult<McpStatus> {
    let _guard = state.write.lock().await;
    let mut s = stored(pool).await?;
    let before = s.tokens.len();
    s.tokens.retain(|t| t.id != id);
    if s.tokens.len() == before {
        return Err(AppError::NotFound);
    }
    settings::set(pool, KEY, &s).await?;
    Ok(build_status(&s, config, state))
}

/// Rechte des Tokens aus `NRZDNS_MCP_TOKEN`.
pub async fn set_allow_changes(
    pool: &SqlitePool,
    config: &Config,
    state: &McpState,
    allow: bool,
) -> AppResult<McpStatus> {
    let _guard = state.write.lock().await;
    let mut s = stored(pool).await?;
    s.allow_changes = allow;
    settings::set(pool, KEY, &s).await?;
    Ok(build_status(&s, config, state))
}

/// Ergebnis der Prüfung eines Tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    /// Kein Token eingerichtet – MCP ist aus.
    Disabled,
    Denied,
    Granted {
        token_id: i64,
        name: String,
        allow_changes: bool,
    },
}

pub async fn authorize(
    pool: &SqlitePool,
    config: &Config,
    state: &McpState,
    token: Option<&str>,
) -> AppResult<Access> {
    let s = stored(pool).await?;
    let env = config.mcp_env_token();
    if env.is_none() && s.tokens.is_empty() {
        return Ok(Access::Disabled);
    }
    let Some(token) = token.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(Access::Denied);
    };
    let hash = session::hash_token(token);
    if let Some(e) = env {
        if same(&hash, &session::hash_token(e)) {
            state.touch(0, None);
            return Ok(Access::Granted {
                token_id: 0,
                name: "NRZDNS_MCP_TOKEN".into(),
                allow_changes: s.allow_changes,
            });
        }
    }
    // Alle vergleichen (keine frühe Antwort, die verrät, welches passt)
    let found = s.tokens.iter().fold(
        None,
        |acc, t| if same(&hash, &t.hash) { Some(t) } else { acc },
    );
    let Some(t) = found else {
        return Ok(Access::Denied);
    };
    if state.touch(t.id, t.last_used_at) {
        // „Zuletzt benutzt“ dauerhaft merken (selten, ohne auf die Sperre zu warten)
        if let Ok(_guard) = state.write.try_lock() {
            if let Ok(mut fresh) = stored(pool).await {
                if let Some(ft) = fresh.tokens.iter_mut().find(|x| x.id == t.id) {
                    ft.last_used_at = Some(now());
                    let _ = settings::set(pool, KEY, &fresh).await;
                }
            }
        }
    }
    Ok(Access::Granted {
        token_id: t.id,
        name: t.name.clone(),
        allow_changes: t.allow_changes,
    })
}

// ------------------------------------------------------------------ Werkzeuge

/// Was die Werkzeuge brauchen.
pub struct Ctx<'a> {
    pub pool: &'a SqlitePool,
    pub config: &'a Config,
    pub engine: &'a Engine,
    pub updater: &'a Updater,
    /// Für Aufrufe der eigenen REST-API (`api_request` und die lesenden Werkzeuge darauf).
    pub dieter: &'a DieterState,
    pub allow_changes: bool,
}

struct Tool {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    /// Ändert etwas (nur mit „Änderungen erlauben“).
    changes: bool,
    idempotent: bool,
    schema: fn() -> Value,
}

fn no_args() -> Value {
    json!({ "type": "object", "properties": {}, "additionalProperties": false })
}

fn range_prop() -> Value {
    json!({
        "type": "string",
        "enum": ["hour", "day", "week", "month"],
        "default": "day",
        "description": "Zeitraum: letzte Stunde, 24 Stunden, 7 Tage oder 30 Tage."
    })
}

fn list_prop() -> Value {
    json!({
        "type": "string",
        "enum": ["blocked", "allowed"],
        "description": "blocked = eigene Sperren, allowed = Ausnahmen (schlagen jede Sperre)."
    })
}

const TOOLS: &[Tool] = &[
    Tool {
        name: "get_overview",
        title: "Übersicht",
        description: "Alle Kennzahlen für eine Übersichtskachel auf einen Blick: Zustand des \
            Servers (Version, Laufzeit, Anfragen/s, DNS-Ports), Sperren (an/aus/pausiert, \
            gesperrte Domains, Listen), Summen im Zeitraum (Anfragen, gesperrt, Anteil \
            gesperrt in %, Cache-Treffer in %, Fehler, Clients, mittlere Antwortzeit), \
            Weiterleitungen (gesund/gesamt) und die Top 5 Clients, Domains und gesperrten Domains.",
        changes: false,
        idempotent: true,
        schema: || {
            json!({
                "type": "object",
                "properties": { "range": range_prop() },
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "get_statistics",
        title: "Statistiken",
        description: "Vollständige Statistik wie das Dashboard von nrzNetwork: Summen, Zeitreihe \
            (Anfragen, gesperrt, Cache, weitergeleitet, eigene Zonen, Fehler je Abschnitt), \
            Top 10 Clients, Domains, gesperrte Domains und Abfragetypen, Serverzustand.",
        changes: false,
        idempotent: true,
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "range": range_prop(),
                    "includeSeries": { "type": "boolean", "default": true, "description": "Zeitreihe mitliefern." }
                },
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "get_server_status",
        title: "Serverzustand",
        description: "Laufender Zustand: Version, Start, Laufzeit, DNS-Adressen und Fehler beim \
            Öffnen, DoH, Anfragen seit Start und je Sekunde, Cache-Einträge, Zonen, gesperrte \
            Domains, Zustand jeder Weiterleitung (ok, Fehler, mittlere Antwortzeit).",
        changes: false,
        idempotent: true,
        schema: no_args,
    },
    Tool {
        name: "get_blocking_status",
        title: "Sperren: Zustand",
        description: "Sperren an/aus, Pause bis, Anzahl gesperrter Domains, alle Sperrlisten \
            (id, Name, aktiv, Domains, letzter Stand, Fehler), eigene Sperren und Ausnahmen, \
            nächstes Update.",
        changes: false,
        idempotent: true,
        schema: no_args,
    },
    Tool {
        name: "get_query_log",
        title: "Abfrageprotokoll",
        description: "Letzte DNS-Anfragen, neueste zuerst, mit Filtern. kind = Quelle der \
            Antwort (authoritative, forwarded, cached, blocked, local, dropped, failed).",
        changes: false,
        idempotent: true,
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "client": { "type": "string", "description": "Genau diese Client-IP." },
                    "qname": { "type": "string", "description": "Teil des Namens." },
                    "qtype": { "type": "string", "description": "Typ, z. B. A, AAAA, HTTPS." },
                    "kind": { "type": "string", "enum": ["authoritative", "forwarded", "cached", "blocked", "local", "dropped", "failed"] },
                    "rcode": { "type": "string", "description": "Antwortcode, z. B. NOERROR, NXDOMAIN." },
                    "from": { "type": "integer", "description": "Ab (Unix-Sekunden)." },
                    "to": { "type": "integer", "description": "Bis (Unix-Sekunden)." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 },
                    "page": { "type": "integer", "minimum": 1, "default": 1 }
                },
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "check_domain",
        title: "Domain prüfen",
        description: "Würde diese Domain gesperrt – und warum (welche Liste, eigene Sperre, Ausnahme)?",
        changes: false,
        idempotent: true,
        schema: || {
            json!({
                "type": "object",
                "properties": { "domain": { "type": "string", "description": "z. B. ads.example.com" } },
                "required": ["domain"],
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "list_zones",
        title: "Zonen",
        description: "Eigene Zonen (primär und Weiterleitungszonen) mit Anzahl Einträgen.",
        changes: false,
        idempotent: true,
        schema: no_args,
    },
    Tool {
        name: "list_rules",
        title: "Eigene Regeln",
        description: "Eigene Sperren oder Ausnahmen (gelten jeweils für die Domain und alle Subdomains).",
        changes: false,
        idempotent: true,
        schema: || {
            json!({
                "type": "object",
                "properties": { "list": list_prop() },
                "required": ["list"],
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "dns_lookup",
        title: "DNS-Abfrage",
        description: "DNS-Abfrage wie dig. server leer = nrzNetwork selbst (mit eigenen Zonen, \
            Sperren und Proxy-Namen); sonst z. B. 1.1.1.1 für die Sicht von aussen.",
        changes: false,
        idempotent: true,
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "z. B. example.com" },
                    "type": { "type": "string", "default": "A", "description": "A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, PTR, SRV, HTTPS …" },
                    "server": { "type": "string", "description": "Leer = nrzNetwork; sonst IP oder Name eines DNS-Servers." }
                },
                "required": ["name"],
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "get_zone",
        title: "Zone mit Einträgen",
        description: "Eine eigene Zone mit allen Einträgen (per id oder Name aus list_zones).",
        changes: false,
        idempotent: true,
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "zone": { "type": "string", "description": "Name (z. B. home.lan) oder id." }
                },
                "required": ["zone"],
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "get_cache",
        title: "DNS-Cache",
        description: "Einträge im DNS-Cache (Name, Typ, Antwortcode, Rest-TTL), optional gefiltert.",
        changes: false,
        idempotent: true,
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "q": { "type": "string", "description": "Teil des Namens." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000, "default": 100 }
                },
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "get_proxy",
        title: "Reverse Proxy",
        description: "Reverse Proxy: alle Einträge (Domain → Ziel), Ports, HTTPS, Zugriffsschutz, Adresse.",
        changes: false,
        idempotent: true,
        schema: no_args,
    },
    Tool {
        name: "get_tls",
        title: "HTTPS-Zertifikate",
        description: "HTTPS (Let's Encrypt): Einstellungen, Zertifikat (Domains, gültig bis), letzter Versuch.",
        changes: false,
        idempotent: true,
        schema: no_args,
    },
    Tool {
        name: "get_docker",
        title: "Docker",
        description: "Alle Docker-Container (Name, Zustand, interne IPs, Netze, Ports) und Docker-Netze.",
        changes: false,
        idempotent: true,
        schema: no_args,
    },
    Tool {
        name: "get_docker_logs",
        title: "Docker-Logs",
        description: "Letzte Log-Zeilen eines Containers.",
        changes: false,
        idempotent: true,
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "container": { "type": "string", "description": "Name aus get_docker." },
                    "tail": { "type": "integer", "minimum": 1, "maximum": 2000, "default": 200 }
                },
                "required": ["container"],
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "get_network_map",
        title: "Netzwerkkarte",
        description: "Die ganze Netzwerkkarte: Internet, Zugänge (Cloudflare-Tunnel, Proxy, DNS), \
            Reverse Proxy, Docker, LAN-Geräte und NetBird mit ihren Verbindungen.",
        changes: false,
        idempotent: true,
        schema: no_args,
    },
    Tool {
        name: "get_devices",
        title: "Geräte im Netz",
        description: "Geräte/Clients, die nrzNetwork als DNS benutzen (IP, Name, Anfragen, zuletzt gesehen).",
        changes: false,
        idempotent: true,
        schema: || {
            json!({
                "type": "object",
                "properties": { "days": { "type": "integer", "minimum": 1, "maximum": 90, "default": 7 } },
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "get_access_log",
        title: "Zugriffe (Reverse Proxy)",
        description: "Zugriffs-Monitor: letzte Zugriffe auf den Reverse Proxy, optional für einen Host.",
        changes: false,
        idempotent: true,
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "host": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000, "default": 100 }
                },
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "get_access_stats",
        title: "Zugriffs-Statistik",
        description: "Zugriffs-Monitor: Statistik (Zugriffe, Länder, Status, Top-Hosts) für einen Zeitraum.",
        changes: false,
        idempotent: true,
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "period": { "type": "string", "enum": ["hour", "day", "week", "month"], "default": "day" },
                    "host": { "type": "string" }
                },
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "get_components",
        title: "Komponenten",
        description: "Eingebaute Komponenten (Cloudflare Tunnel, NetBird-Client …): installiert, läuft, Version, Fehler.",
        changes: false,
        idempotent: true,
        schema: no_args,
    },
    Tool {
        name: "list_api_endpoints",
        title: "API-Übersicht",
        description: "Alle Endpunkte der REST-API von nrzNetwork (für api_request), mit Methode, Pfad und Rechten.",
        changes: false,
        idempotent: true,
        schema: no_args,
    },
    Tool {
        name: "api_request",
        title: "REST-API aufrufen",
        description: "Ruft die REST-API von nrzNetwork auf – alles, was die Oberfläche kann (Pfad ohne \
            /api/v1, siehe list_api_endpoints; z. B. GET /cloudflare/zones, GET /netbird/peers). \
            Tokens ohne Änderungsrecht dürfen nur GET. Antwort: HTTP-Status und JSON.",
        changes: false,
        idempotent: false,
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "method": { "type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"], "default": "GET" },
                    "path": { "type": "string", "description": "Pfad ohne /api/v1, z. B. /proxy/hosts" },
                    "query": { "type": "string", "description": "Optional: Query ohne ?, z. B. per_page=500" },
                    "body": { "description": "Optional: JSON-Körper" }
                },
                "required": ["path"],
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "set_blocking",
        title: "Sperren ein-/ausschalten",
        description: "Filter (alle Sperren) dauerhaft ein- oder ausschalten. Einschalten beendet \
            auch eine laufende Pause. Für eine Unterbrechung auf Zeit: pause_blocking.",
        changes: true,
        idempotent: true,
        schema: || {
            json!({
                "type": "object",
                "properties": { "enabled": { "type": "boolean" } },
                "required": ["enabled"],
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "pause_blocking",
        title: "Sperren pausieren",
        description: "Filter für N Minuten aussetzen (höchstens 10080 = 7 Tage); 0 setzt sofort fort.",
        changes: true,
        idempotent: true,
        schema: || {
            json!({
                "type": "object",
                "properties": { "minutes": { "type": "integer", "minimum": 0, "maximum": 10080 } },
                "required": ["minutes"],
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "set_blocklist",
        title: "Sperrliste ein-/ausschalten",
        description: "Eine Sperrliste (per id oder Name aus get_blocking_status) aktivieren oder deaktivieren.",
        changes: true,
        idempotent: true,
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "integer" },
                    "name": { "type": "string", "description": "Name der Liste (ohne Gross-/Kleinschreibung), wenn keine id." },
                    "enabled": { "type": "boolean" }
                },
                "required": ["enabled"],
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "update_blocklists",
        title: "Sperrlisten neu laden",
        description: "Alle aktiven Sperrlisten jetzt im Hintergrund neu laden.",
        changes: true,
        idempotent: true,
        schema: no_args,
    },
    Tool {
        name: "add_rule",
        title: "Regel hinzufügen",
        description: "Domain (mit allen Subdomains) sperren oder als Ausnahme freigeben.",
        changes: true,
        idempotent: false,
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "list": list_prop(),
                    "domain": { "type": "string" },
                    "comment": { "type": "string" }
                },
                "required": ["list", "domain"],
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "remove_rule",
        title: "Regel entfernen",
        description: "Eigene Sperre oder Ausnahme entfernen.",
        changes: true,
        idempotent: false,
        schema: || {
            json!({
                "type": "object",
                "properties": { "list": list_prop(), "domain": { "type": "string" } },
                "required": ["list", "domain"],
                "additionalProperties": false
            })
        },
    },
    Tool {
        name: "flush_cache",
        title: "Cache leeren",
        description: "Den DNS-Cache leeren – ganz oder nur für einen Namen (alle Typen).",
        changes: true,
        idempotent: true,
        schema: || {
            json!({
                "type": "object",
                "properties": { "name": { "type": "string", "description": "Leer = alles." } },
                "additionalProperties": false
            })
        },
    },
];

/// Werkzeuge für `tools/list`; ohne „Änderungen erlauben“ nur die lesenden.
pub fn tool_list(allow_changes: bool) -> Vec<Value> {
    // Ohne Änderungsrecht kennt api_request nur GET
    let read_only_api = || {
        json!({
            "type": "object",
            "properties": {
                "method": { "type": "string", "enum": ["GET"], "default": "GET" },
                "path": { "type": "string", "description": "Pfad ohne /api/v1, z. B. /proxy/hosts" },
                "query": { "type": "string", "description": "Optional: Query ohne ?, z. B. per_page=500" }
            },
            "required": ["path"],
            "additionalProperties": false
        })
    };
    TOOLS
        .iter()
        .filter(|t| allow_changes || !t.changes)
        .map(|t| {
            json!({
                "name": t.name,
                "title": t.title,
                "description": t.description,
                "inputSchema": if t.name == "api_request" && !allow_changes { read_only_api() } else { (t.schema)() },
                "annotations": {
                    "title": t.title,
                    "readOnlyHint": !t.changes && (t.name != "api_request" || !allow_changes),
                    "destructiveHint": t.name == "remove_rule" || t.name == "api_request",
                    "idempotentHint": t.idempotent,
                    "openWorldHint": matches!(t.name, "dns_lookup" | "api_request")
                }
            })
        })
        .collect()
}

/// Fehler eines Werkzeugs (kommt als `isError: true` zum Client, nicht als JSON-RPC-Fehler).
#[derive(Debug)]
pub enum ToolError {
    /// Unbekanntes Werkzeug → JSON-RPC-Fehler „Invalid params“.
    Unknown(String),
    Failed(String),
}

impl From<AppError> for ToolError {
    fn from(e: AppError) -> Self {
        if e.status().code >= 500 {
            tracing::error!("MCP: {e}");
        }
        ToolError::Failed(e.public_message())
    }
}

type ToolResult = Result<Value, ToolError>;

fn args<T: for<'de> Deserialize<'de> + Default>(v: &Value) -> Result<T, ToolError> {
    if v.is_null() {
        return Ok(T::default());
    }
    serde_json::from_value(v.clone())
        .map_err(|e| ToolError::Failed(format!("Ungültige Argumente: {e}")))
}

fn to_value<T: Serialize>(v: T) -> ToolResult {
    serde_json::to_value(v).map_err(|e| ToolError::Failed(e.to_string()))
}

fn range(r: Option<&str>) -> Result<StatsRange, ToolError> {
    match r.map(str::trim).filter(|r| !r.is_empty()) {
        None => Ok(StatsRange::Day),
        Some(r) => StatsRange::parse(r).ok_or_else(|| {
            ToolError::Failed("Unbekannter Zeitraum (hour, day, week, month).".into())
        }),
    }
}

fn kind(list: &str) -> Result<Kind, ToolError> {
    match list.trim() {
        "blocked" => Ok(Kind::Blocked),
        "allowed" => Ok(Kind::Allowed),
        _ => Err(ToolError::Failed("list: blocked oder allowed.".into())),
    }
}

fn percent(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (part as f64 * 1000.0 / total as f64).round() / 10.0
    }
}

fn top(list: &[TopEntry]) -> &[TopEntry] {
    &list[..list.len().min(OVERVIEW_TOP)]
}

/// Kompakte Kennzahlen für eine Übersicht (nrzDashboard).
pub async fn overview(ctx: &Ctx<'_>, range: StatsRange) -> AppResult<Value> {
    let d: Dashboard = dashboard::build(ctx.pool, ctx.engine, range).await?;
    let b = blocking::status(ctx.pool, ctx.engine, ctx.updater).await?;
    let t = &d.totals;
    let s = &d.server;
    let paused = b.paused_until.is_some();
    let healthy = s.upstreams.iter().filter(|u| u.failed <= u.ok).count();
    let answered_upstream = t.cached + t.forwarded;
    Ok(json!({
        "generatedAt": now(),
        "range": range.as_str(),
        "server": {
            "version": s.version,
            "startedAt": s.started_at,
            "uptimeSecs": s.uptime_secs,
            "dnsListening": !s.dns_listen.is_empty(),
            "dnsListen": s.dns_listen,
            "listenErrors": s.listen_errors,
            "dohEnabled": s.doh_enabled,
            "queriesPerSecond": s.queries_per_second,
            "queriesSinceStart": s.queries_since_start,
            "cacheEntries": s.cache_entries,
            "zones": s.zones,
        },
        "blocking": {
            "enabled": b.enabled,
            "paused": paused,
            "pausedUntil": b.paused_until,
            "active": b.enabled && !paused,
            "blockedDomains": b.total_domains,
            "lists": b.lists.len(),
            "listsEnabled": b.lists.iter().filter(|l| l.enabled).count(),
            "listsWithErrors": b.lists.iter().filter(|l| l.enabled && l.last_error.is_some()).count(),
            "customBlocked": b.custom_blocked,
            "allowed": b.allowed,
            "lastUpdateAt": b.last_update_at,
            "nextUpdateAt": b.next_update_at,
            "updating": b.updating,
        },
        "totals": {
            "queries": t.queries,
            "blocked": t.blocked,
            "blockedPercent": percent(t.blocked, t.queries),
            "cached": t.cached,
            "cacheHitPercent": percent(t.cached, answered_upstream),
            "forwarded": t.forwarded,
            "authoritative": t.authoritative,
            "local": t.local,
            "failed": t.failed,
            "dropped": t.dropped,
            "noError": t.no_error,
            "nxDomain": t.nx_domain,
            "serverFailure": t.server_failure,
            "refused": t.refused,
            "clients": t.clients,
            "avgDurationMs": t.avg_duration_ms,
        },
        "upstreams": {
            "total": s.upstreams.len(),
            "healthy": healthy,
            "items": s.upstreams,
        },
        "topClients": top(&d.top_clients),
        "topDomains": top(&d.top_domains),
        "topBlocked": top(&d.top_blocked),
    }))
}

/// Pfade, die über MCP nie erreichbar sind (Konten, Anmeldung, MCP selbst, Dieter).
const BLOCKED_PATHS: &[&str] = &[
    "/auth",
    "/users",
    "/admin",
    "/dieter",
    "/settings/mcp",
    "/account",
    "/me",
];
/// POST-Aufrufe, die nur lesen/prüfen (auch ohne Änderungsrecht erlaubt).
const READ_POSTS: &[&str] = &[
    "/tools/ping",
    "/tools/ports",
    "/tools/http",
    "/resolve",
    "/spy/scan",
    "/components/check",
];

fn check_api(method: &str, path: &str, allow_changes: bool) -> Result<(), ToolError> {
    let fail = |m: String| Err(ToolError::Failed(m));
    if !path.starts_with('/') || path.contains("..") || path.contains('#') || path.contains('?') {
        return fail("path muss mit / beginnen (ohne ?, Query in query).".into());
    }
    if !matches!(method, "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
        return fail("method: GET, POST, PUT, PATCH oder DELETE.".into());
    }
    for b in BLOCKED_PATHS {
        if path == *b || path.starts_with(&format!("{b}/")) {
            return fail(format!("{b} ist über MCP nicht erreichbar."));
        }
    }
    if method != "GET" && path == "/integrations" {
        return fail("Zugangsdaten ändern geht nur in der Oberfläche.".into());
    }
    if !allow_changes && method != "GET" && !(method == "POST" && READ_POSTS.contains(&path)) {
        return fail(
            "Dieses Token darf nur lesen (GET) – Änderungsrecht in nrzNetwork → Einstellungen → MCP."
                .into(),
        );
    }
    Ok(())
}

/// Eigene REST-API aufrufen; JSON-Antwort als Wert, Fehler (HTTP ≥ 400) als Werkzeugfehler.
async fn api(
    ctx: &Ctx<'_>,
    method: &str,
    path: &str,
    query: &[(&str, String)],
    body: Option<&Value>,
) -> ToolResult {
    let q = query
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={}", urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    api_raw(ctx, method, path, &q, body).await
}

async fn api_raw(
    ctx: &Ctx<'_>,
    method: &str,
    path: &str,
    query: &str,
    body: Option<&Value>,
) -> ToolResult {
    let (status, text) = dieter::internal_request(ctx.dieter, method, path, query, body)
        .await
        .map_err(|e| ToolError::Failed(format!("API nicht erreichbar: {e}")))?;
    let value = if text.trim().is_empty() {
        json!({ "ok": (200..300).contains(&status), "status": status })
    } else {
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    };
    if status >= 400 {
        let msg = value["error"]["message"]
            .as_str()
            .or(value["message"].as_str())
            .or(value.as_str())
            .unwrap_or("Fehler");
        return Err(ToolError::Failed(format!("HTTP {status}: {msg}")));
    }
    Ok(value)
}

/// Werkzeug ausführen.
pub async fn call(ctx: &Ctx<'_>, name: &str, arguments: &Value) -> ToolResult {
    let tool = TOOLS
        .iter()
        .find(|t| t.name == name)
        .ok_or_else(|| ToolError::Unknown(format!("Unbekanntes Werkzeug: {name}")))?;
    if tool.changes && !ctx.allow_changes {
        return Err(ToolError::Failed(
            "Änderungen über MCP sind ausgeschaltet (nrzNetwork → Einstellungen → MCP).".into(),
        ));
    }
    let result = run(ctx, name, arguments).await;
    if tool.changes && result.is_ok() {
        tracing::info!(tool = name, by = "mcp", "Änderung über MCP");
    }
    result
}

async fn run(ctx: &Ctx<'_>, name: &str, a: &Value) -> ToolResult {
    let (pool, engine, config, updater) = (ctx.pool, ctx.engine, ctx.config, ctx.updater);
    match name {
        "get_overview" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                range: Option<String>,
            }
            let a: A = args(a)?;
            Ok(overview(ctx, range(a.range.as_deref())?).await?)
        }
        "get_statistics" => {
            #[derive(Deserialize, Default)]
            #[serde(rename_all = "camelCase", deny_unknown_fields)]
            struct A {
                range: Option<String>,
                include_series: Option<bool>,
            }
            let a: A = args(a)?;
            let mut d = dashboard::build(pool, engine, range(a.range.as_deref())?).await?;
            if a.include_series == Some(false) {
                d.series.clear();
            }
            to_value(d)
        }
        "get_server_status" => to_value(engine.status()),
        "get_blocking_status" => to_value(blocking::status(pool, engine, updater).await?),
        "get_query_log" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                #[serde(default)]
                client: String,
                #[serde(default)]
                qname: String,
                #[serde(default)]
                qtype: String,
                kind: Option<String>,
                #[serde(default)]
                rcode: String,
                from: Option<i64>,
                to: Option<i64>,
                limit: Option<u32>,
                page: Option<u32>,
            }
            let a: A = args(a)?;
            let kind = match a.kind.as_deref() {
                Some(k) => querylog::parse_kind(k)?,
                None => None,
            };
            let filter = QueryLogFilter {
                page: a.page.unwrap_or(1).max(1),
                per_page: a.limit.unwrap_or(50).clamp(1, 500),
                client: a.client,
                qname: a.qname,
                qtype: a.qtype,
                kind,
                rcode: a.rcode,
                from: a.from,
                to: a.to,
            };
            let per_page = filter.per_page;
            let mut page = querylog::page(pool, filter).await?;
            // Die Seitengrösse der Oberfläche beginnt bei 10 – hier gilt das gewünschte Limit.
            page.entries.truncate(per_page as usize);
            to_value(page)
        }
        "check_domain" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                domain: String,
            }
            let a: A = args(a)?;
            let domain = domains::domain(&a.domain)?;
            to_value(engine.check_domain(&domain))
        }
        "list_zones" => Ok(json!({ "zones": zones::list(pool).await? })),
        "list_rules" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                list: String,
            }
            let a: A = args(a)?;
            let entries = domains::list(pool, kind(&a.list)?).await?;
            Ok(json!({ "list": a.list.trim(), "count": entries.len(), "entries": entries }))
        }
        "dns_lookup" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                name: String,
                #[serde(rename = "type")]
                qtype: Option<String>,
                #[serde(default)]
                server: String,
            }
            let a: A = args(a)?;
            if a.name.trim().is_empty() {
                return Err(ToolError::Failed("name fehlt.".into()));
            }
            let input = ResolveInput {
                name: a.name.trim().to_string(),
                qtype: a.qtype.unwrap_or_else(|| "A".into()).trim().to_uppercase(),
                server: a.server.trim().to_string(),
                ..ResolveInput::default()
            };
            let r = engine
                .resolve(&input)
                .await
                .map_err(|e| ToolError::Failed(e.to_string()))?;
            to_value(r)
        }
        "get_zone" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                zone: Value,
            }
            let a: A = args(a)?;
            let wanted = match &a.zone {
                Value::Number(n) => n.to_string(),
                Value::String(s) => s.trim().trim_end_matches('.').to_lowercase(),
                _ => String::new(),
            };
            let all = zones::list(pool).await?;
            let zone = all
                .iter()
                .find(|z| z.id.to_string() == wanted || z.name.eq_ignore_ascii_case(&wanted))
                .ok_or_else(|| {
                    ToolError::Failed("Zone nicht gefunden (siehe list_zones).".into())
                })?;
            api(ctx, "GET", &format!("/zones/{}", zone.id), &[], None).await
        }
        "get_cache" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                #[serde(default)]
                q: String,
                limit: Option<u32>,
            }
            let a: A = args(a)?;
            let limit = a.limit.unwrap_or(100).clamp(1, 1000).to_string();
            api(ctx, "GET", "/cache", &[("q", a.q), ("limit", limit)], None).await
        }
        "get_proxy" => api(ctx, "GET", "/proxy", &[], None).await,
        "get_tls" => api(ctx, "GET", "/tls", &[], None).await,
        "get_docker" => api(ctx, "GET", "/docker", &[], None).await,
        "get_network_map" => api(ctx, "GET", "/topology", &[], None).await,
        "get_components" => api(ctx, "GET", "/components", &[], None).await,
        "get_docker_logs" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                container: String,
                tail: Option<u32>,
            }
            let a: A = args(a)?;
            let name = a.container.trim();
            if name.is_empty() || name.contains('/') {
                return Err(ToolError::Failed("container: Name aus get_docker.".into()));
            }
            let tail = a.tail.unwrap_or(200).clamp(1, 2000).to_string();
            let path = format!("/docker/containers/{}/logs", urlencoding::encode(name));
            api(ctx, "GET", &path, &[("tail", tail)], None).await
        }
        "get_devices" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                days: Option<u32>,
            }
            let a: A = args(a)?;
            let days = a.days.unwrap_or(7).clamp(1, 90).to_string();
            api(ctx, "GET", "/devices", &[("days", days)], None).await
        }
        "get_access_log" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                #[serde(default)]
                host: String,
                limit: Option<u32>,
            }
            let a: A = args(a)?;
            let limit = a.limit.unwrap_or(100).clamp(1, 1000).to_string();
            api(
                ctx,
                "GET",
                "/access/log",
                &[("host", a.host), ("limit", limit)],
                None,
            )
            .await
        }
        "get_access_stats" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                #[serde(default)]
                period: String,
                #[serde(default)]
                host: String,
            }
            let a: A = args(a)?;
            api(
                ctx,
                "GET",
                "/access/stats",
                &[("period", a.period), ("host", a.host)],
                None,
            )
            .await
        }
        "list_api_endpoints" => Ok(json!({
            "basePath": "/api/v1",
            "note": "Für api_request den Pfad ohne /api/v1 angeben.",
            "endpoints": dieter::api_reference().lines().collect::<Vec<_>>(),
        })),
        "api_request" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                method: Option<String>,
                path: String,
                #[serde(default)]
                query: String,
                body: Option<Value>,
            }
            let a: A = args(a)?;
            let method = a
                .method
                .unwrap_or_else(|| "GET".into())
                .trim()
                .to_uppercase();
            let path = a.path.trim().trim_end_matches('/').to_string();
            let path = path.strip_prefix("/api/v1").unwrap_or(&path).to_string();
            check_api(&method, &path, ctx.allow_changes)?;
            let query = a.query.trim().trim_start_matches('?');
            let body = a.body.as_ref().filter(|b| !b.is_null());
            let r = api_raw(ctx, &method, &path, query, body).await;
            if method != "GET" && r.is_ok() {
                tracing::info!(by = "mcp", %method, %path, "Änderung über MCP (API)");
            }
            r
        }
        "set_blocking" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                enabled: bool,
            }
            let a: A = args(a)?;
            let mut dns = engine.settings();
            if dns.blocking_enabled != a.enabled {
                dns.blocking_enabled = a.enabled;
                let saved = settings::save_dns(pool, &dns).await?;
                engine.apply_settings(saved);
            }
            if a.enabled {
                blocking::pause(pool, engine, 0).await?;
            }
            to_value(blocking::status(pool, engine, updater).await?)
        }
        "pause_blocking" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                minutes: u32,
            }
            let a: A = args(a)?;
            blocking::pause(pool, engine, a.minutes).await?;
            to_value(blocking::status(pool, engine, updater).await?)
        }
        "set_blocklist" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                id: Option<i64>,
                name: Option<String>,
                enabled: bool,
            }
            let a: A = args(a)?;
            let lists = blocking::list(pool).await?;
            let list = match (a.id, a.name.as_deref().map(str::trim)) {
                (Some(id), _) => lists.into_iter().find(|l| l.id == id),
                (None, Some(n)) if !n.is_empty() => {
                    lists.into_iter().find(|l| l.name.eq_ignore_ascii_case(n))
                }
                _ => {
                    return Err(ToolError::Failed(
                        "Bitte id oder name der Liste angeben.".into(),
                    ))
                }
            }
            .ok_or_else(|| ToolError::Failed("Sperrliste nicht gefunden.".into()))?;
            let input = BlockListInput {
                name: list.name,
                url: list.url,
                enabled: a.enabled,
            };
            let changed = blocking::update(pool, list.id, &input).await?;
            blocking::apply_change(pool, config, engine, updater, &changed).await;
            to_value(changed.list)
        }
        "update_blocklists" => {
            blocking::spawn_update_all(pool, config, engine, updater);
            to_value(blocking::status(pool, engine, updater).await?)
        }
        "add_rule" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                list: String,
                domain: String,
                #[serde(default)]
                comment: String,
            }
            let a: A = args(a)?;
            let kind = kind(&a.list)?;
            let entry = domains::add(
                pool,
                kind,
                &DomainInput {
                    domain: a.domain,
                    comment: a.comment,
                },
            )
            .await?;
            sync::push_domains(pool, engine, kind).await?;
            to_value(entry)
        }
        "remove_rule" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                list: String,
                domain: String,
            }
            let a: A = args(a)?;
            let kind = kind(&a.list)?;
            domains::remove(pool, kind, &a.domain).await?;
            sync::push_domains(pool, engine, kind).await?;
            Ok(json!({ "removed": true, "domain": domains::domain(&a.domain)? }))
        }
        "flush_cache" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                #[serde(default)]
                name: String,
            }
            let a: A = args(a)?;
            let removed = if a.name.trim().is_empty() {
                engine.cache_flush()
            } else {
                engine.cache_remove(&domains::domain(&a.name)?)
            };
            Ok(json!({ "removed": removed }))
        }
        other => Err(ToolError::Unknown(format!("Unbekanntes Werkzeug: {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_and_compare() {
        assert_eq!(
            hint("nrzdns_mcp_ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            "nrzdns_mcp_ABCD…WXYZ"
        );
        assert_eq!(hint("kurz"), "…");
        assert_eq!(hint("0123456789abcdef"), "012…def");
        assert!(same("abc", "abc"));
        assert!(!same("abc", "abd"));
        assert!(!same("abc", "abcd"));
    }

    #[test]
    fn read_only_list_hides_changes() {
        let ro = tool_list(false);
        let all = tool_list(true);
        assert!(ro.len() < all.len());
        assert!(ro.iter().all(|t| t["annotations"]["readOnlyHint"] == true));
        assert!(all.iter().any(|t| t["name"] == "set_blocking"));
        assert_eq!(percent(1, 3), 33.3);
        assert_eq!(percent(0, 0), 0.0);
    }
}
