//! MCP-Server (Model Context Protocol): Zugang per Token und die Werkzeuge.
//!
//! Gedacht für nrzDashboard und andere MCP-Clients: Kennzahlen für eine Übersicht
//! (`get_overview`), Statistiken, Abfrageprotokoll, Zustand – und, wenn der Admin es erlaubt,
//! Sperren ein-/ausschalten, pausieren, Listen umschalten, Regeln und Cache.
//!
//! Das Protokoll (JSON-RPC über HTTP) steht in `routes::mcp`; hier nur Fachlogik. Das Token
//! liegt nur als SHA-256 in der Datenbank (`app_settings`, Schlüssel `mcp`); ein Token aus
//! `NRZDNS_MCP_TOKEN` hat Vorrang.

use crate::auth::session;
use crate::config::Config;
use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::services::blocking::{self, Updater};
use crate::services::domains::{self, Kind};
use crate::services::{dashboard, querylog, settings, sync, zones};
use nrzdns_engine::Engine;
use nrzdns_types::{
    BlockListInput, Dashboard, DomainInput, McpStatus, McpToken, QueryLogFilter, StatsRange,
    TopEntry,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::sync::atomic::{AtomicI64, Ordering};

/// Schlüssel in `app_settings`.
const KEY: &str = "mcp";
/// Pfad des MCP-Servers.
pub const PATH: &str = "/mcp";
/// Präfix neuer Tokens (erkennbar in Konfigurationsdateien).
const TOKEN_PREFIX: &str = "nrzdns_mcp_";
/// Einträge je Top-Liste in der Übersicht.
const OVERVIEW_TOP: usize = 5;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Stored {
    token_hash: Option<String>,
    token_hint: Option<String>,
    created_at: Option<i64>,
    allow_changes: bool,
}

/// Laufzeit-Zustand (nicht gespeichert): wann `/mcp` zuletzt erfolgreich benutzt wurde.
#[derive(Debug, Default)]
pub struct McpState {
    last_used: AtomicI64,
}

impl McpState {
    pub fn touch(&self) {
        self.last_used.store(now(), Ordering::Relaxed);
    }

    fn last_used(&self) -> Option<i64> {
        Some(self.last_used.load(Ordering::Relaxed)).filter(|t| *t > 0)
    }
}

async fn stored(pool: &SqlitePool) -> AppResult<Stored> {
    Ok(settings::get::<Stored>(pool, KEY)
        .await?
        .unwrap_or_default())
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

pub async fn status(pool: &SqlitePool, config: &Config, state: &McpState) -> AppResult<McpStatus> {
    let s = stored(pool).await?;
    let (enabled, from_env, token_hint, created_at) = match config.mcp_env_token() {
        Some(t) => (true, true, Some(hint(t)), None),
        None => (
            s.token_hash.is_some(),
            false,
            s.token_hint.clone(),
            s.created_at,
        ),
    };
    Ok(McpStatus {
        enabled,
        from_env,
        token_hint: token_hint.filter(|_| enabled),
        created_at: created_at.filter(|_| enabled),
        allow_changes: s.allow_changes,
        last_used_at: state.last_used(),
        path: PATH.into(),
    })
}

/// Neues Token (das alte gilt sofort nicht mehr). Nicht möglich, solange
/// `NRZDNS_MCP_TOKEN` gesetzt ist.
pub async fn create_token(
    pool: &SqlitePool,
    config: &Config,
    state: &McpState,
) -> AppResult<McpToken> {
    if config.mcp_env_token().is_some() {
        return Err(AppError::Conflict(
            "Das MCP-Token kommt aus NRZDNS_MCP_TOKEN und lässt sich hier nicht ändern.".into(),
        ));
    }
    let token = format!("{TOKEN_PREFIX}{}", session::new_token());
    let mut s = stored(pool).await?;
    s.token_hash = Some(session::hash_token(&token));
    s.token_hint = Some(hint(&token));
    s.created_at = Some(now());
    settings::set(pool, KEY, &s).await?;
    Ok(McpToken {
        token,
        status: status(pool, config, state).await?,
    })
}

/// Token löschen – `/mcp` nimmt danach nichts mehr an.
pub async fn revoke_token(
    pool: &SqlitePool,
    config: &Config,
    state: &McpState,
) -> AppResult<McpStatus> {
    if config.mcp_env_token().is_some() {
        return Err(AppError::Conflict(
            "Das MCP-Token kommt aus NRZDNS_MCP_TOKEN und lässt sich hier nicht ändern.".into(),
        ));
    }
    let mut s = stored(pool).await?;
    s.token_hash = None;
    s.token_hint = None;
    s.created_at = None;
    settings::set(pool, KEY, &s).await?;
    status(pool, config, state).await
}

pub async fn set_allow_changes(
    pool: &SqlitePool,
    config: &Config,
    state: &McpState,
    allow: bool,
) -> AppResult<McpStatus> {
    let mut s = stored(pool).await?;
    s.allow_changes = allow;
    settings::set(pool, KEY, &s).await?;
    status(pool, config, state).await
}

/// Ergebnis der Prüfung eines Tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Kein Token eingerichtet – MCP ist aus.
    Disabled,
    Denied,
    Granted {
        allow_changes: bool,
    },
}

pub async fn authorize(
    pool: &SqlitePool,
    config: &Config,
    token: Option<&str>,
) -> AppResult<Access> {
    let s = stored(pool).await?;
    let expected = match config.mcp_env_token() {
        Some(t) => session::hash_token(t),
        None => match s.token_hash {
            Some(h) => h,
            None => return Ok(Access::Disabled),
        },
    };
    let Some(token) = token.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(Access::Denied);
    };
    Ok(if same(&session::hash_token(token), &expected) {
        Access::Granted {
            allow_changes: s.allow_changes,
        }
    } else {
        Access::Denied
    })
}

// ------------------------------------------------------------------ Werkzeuge

/// Was die Werkzeuge brauchen.
pub struct Ctx<'a> {
    pub pool: &'a SqlitePool,
    pub config: &'a Config,
    pub engine: &'a Engine,
    pub updater: &'a Updater,
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
    TOOLS
        .iter()
        .filter(|t| allow_changes || !t.changes)
        .map(|t| {
            json!({
                "name": t.name,
                "title": t.title,
                "description": t.description,
                "inputSchema": (t.schema)(),
                "annotations": {
                    "title": t.title,
                    "readOnlyHint": !t.changes,
                    "destructiveHint": t.changes && t.name == "remove_rule",
                    "idempotentHint": t.idempotent,
                    "openWorldHint": false
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
