//! Dieter – KI-Assistent für das Netzwerk.
//!
//! * **Anbieter:** OpenRouter oder xAI (Grok) über die OpenAI-kompatible Chat-API mit
//!   Werkzeugen, oder die **Claude CLI** (von nrzNetwork geladen wie cloudflared), die die
//!   Werkzeuge über einen internen MCP-Zugang (`/mcp/dieter`) bekommt.
//! * **Werkzeuge:** `api_request` (die ganze REST-API von nrzNetwork – alles, was die
//!   Oberfläche kann; Konten, Schlüssel und Dieter selbst ausgenommen) und `dns_lookup`.
//!   Ohne „darf ändern“ nur lesend. Intern meldet sich Dieter mit einem Schlüssel an, der
//!   bei jedem Start neu entsteht und nur von 127.0.0.1 gilt.
//! * **Überwachung:** prüft regelmässig DNS, Komponenten, Proxy-Ziele, Zertifikat und Spy;
//!   bei neuen Problemen startet ein automatischer Einsatz (höchstens alle 6 h je Problem).

use crate::config::Config;
use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::proxy::ProxyState;
use crate::services::components::{self, Components};
use crate::services::settings;
use nrzdns_engine::Engine;
use nrzdns_types::{
    DieterConversation, DieterIncident, DieterMessage, DieterProvider, DieterSettings,
    DieterSettingsInput, DieterStatus, DieterThread, ResolveInput,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicI64, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};

const SETTINGS: &str = "dieter";
const MAX_STEPS: usize = 24;
const MAX_RESULT: usize = 24_000;
const OPENROUTER_MODEL: &str = "anthropic/claude-sonnet-5.5";
const XAI_MODEL: &str = "grok-4.7";
const CLAUDE_BASE: &str = "https://downloads.claude.ai/claude-code-releases";
/// Kopfzeile, mit der sich Dieter intern bei der eigenen API anmeldet.
pub const INTERNAL_HEADER: &str = "x-nrz-dieter";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Stored {
    #[serde(flatten)]
    settings: DieterSettings,
    openrouter_key: String,
    xai_key: String,
    claude_token: String,
}

async fn stored(pool: &SqlitePool) -> AppResult<Stored> {
    Ok(settings::get(pool, SETTINGS).await?.unwrap_or_default())
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Laufzeit (Rocket-State).
#[derive(Clone)]
pub struct DieterState(Arc<Inner>);

struct Inner {
    key: String,
    port: AtomicU16,
    running: Mutex<HashSet<i64>>,
    last_watch: AtomicI64,
}

impl Default for DieterState {
    fn default() -> Self {
        use ring::rand::SecureRandom;
        let mut b = [0u8; 32];
        let _ = ring::rand::SystemRandom::new().fill(&mut b);
        DieterState(Arc::new(Inner {
            key: b.iter().map(|x| format!("{x:02x}")).collect(),
            port: AtomicU16::new(0),
            running: Mutex::default(),
            last_watch: AtomicI64::new(0),
        }))
    }
}

impl DieterState {
    /// Interner Schlüssel (nur gültig von 127.0.0.1).
    pub fn key(&self) -> &str {
        &self.0.key
    }

    pub fn set_port(&self, port: u16) {
        self.0.port.store(port, Ordering::Relaxed);
    }

    fn running(&self, id: i64) -> bool {
        lock(&self.0.running).contains(&id)
    }
}

/// Alles, was ein Lauf braucht.
#[derive(Clone)]
pub struct Ctx {
    pub pool: SqlitePool,
    pub config: Config,
    pub engine: Engine,
    pub state: DieterState,
    pub components: Components,
    pub proxy: ProxyState,
}

// ------------------------------------------------------------------ Einstellungen

fn key_ok(k: &str) -> bool {
    k.len() <= 400 && k.chars().all(|c| c.is_ascii_graphic())
}

/// Darf Dieter ändern?
pub async fn allow_changes(pool: &SqlitePool) -> bool {
    stored(pool).await.is_ok_and(|s| s.settings.allow_changes)
}

pub async fn save(pool: &SqlitePool, input: &DieterSettingsInput) -> AppResult<()> {
    let mut s = stored(pool).await?;
    for (field, value, name) in [
        (
            &mut s.openrouter_key,
            &input.openrouter_key,
            "OpenRouter-Schlüssel",
        ),
        (&mut s.xai_key, &input.xai_key, "xAI-Schlüssel"),
        (&mut s.claude_token, &input.claude_token, "Claude-Token"),
    ] {
        let v = value.trim();
        if !v.is_empty() {
            if !key_ok(v) {
                return Err(AppError::bad(format!(
                    "{name}: bitte unverändert kopieren."
                )));
            }
            *field = v.to_string();
        }
    }
    for c in &input.clear {
        match c.as_str() {
            "openrouter" => s.openrouter_key.clear(),
            "xai" => s.xai_key.clear(),
            "claude" => s.claude_token.clear(),
            _ => {}
        }
    }
    let mut settings = input.settings.clone();
    settings.watch_minutes = settings.watch_minutes.clamp(5, 240);
    for m in [
        &settings.openrouter_model,
        &settings.xai_model,
        &settings.claude_model,
    ] {
        if m.len() > 120 || m.chars().any(|c| c.is_whitespace()) {
            return Err(AppError::bad(
                "Modell: ohne Leerzeichen, z. B. anthropic/claude-sonnet-5.5.",
            ));
        }
    }
    s.settings = settings;
    settings::set(pool, SETTINGS, &s).await
}

fn claude_bin(data: &Path) -> PathBuf {
    components::bin_dir(data).join("claude")
}

/// Bereit? (Text erklärt, was fehlt.)
fn readiness(s: &Stored, data: &Path) -> (bool, String) {
    match s.settings.provider {
        DieterProvider::Openrouter if s.openrouter_key.is_empty() => {
            (false, "OpenRouter-Schlüssel fehlt.".into())
        }
        DieterProvider::Xai if s.xai_key.is_empty() => (false, "xAI-Schlüssel fehlt.".into()),
        DieterProvider::ClaudeCli if s.claude_token.is_empty() => (
            false,
            "Claude-Token fehlt (claude setup-token oder API-Schlüssel).".into(),
        ),
        DieterProvider::ClaudeCli if !claude_bin(data).exists() => {
            (false, "Claude CLI ist noch nicht installiert.".into())
        }
        DieterProvider::Openrouter => (true, format!("OpenRouter · {}", model(s))),
        DieterProvider::Xai => (true, format!("xAI · {}", model(s))),
        DieterProvider::ClaudeCli => (true, format!("Claude CLI · {}", model(s))),
    }
}

fn model(s: &Stored) -> String {
    let (m, d) = match s.settings.provider {
        DieterProvider::Openrouter => (&s.settings.openrouter_model, OPENROUTER_MODEL),
        DieterProvider::Xai => (&s.settings.xai_model, XAI_MODEL),
        DieterProvider::ClaudeCli => (&s.settings.claude_model, "sonnet"),
    };
    if m.trim().is_empty() {
        d.to_string()
    } else {
        m.trim().to_string()
    }
}

pub async fn status(
    pool: &SqlitePool,
    config: &Config,
    state: &DieterState,
) -> AppResult<DieterStatus> {
    let s = stored(pool).await?;
    let (ready, ready_detail) = readiness(&s, &config.data_dir);
    let rows: Vec<(i64, String, bool, i64, i64)> = sqlx::query_as(
        "SELECT id, title, automatic, created_at, updated_at FROM dieter_conversations ORDER BY updated_at DESC LIMIT 100",
    )
    .fetch_all(pool)
    .await?;
    let conversations = rows
        .into_iter()
        .map(
            |(id, title, automatic, created_at, updated_at)| DieterConversation {
                running: state.running(id),
                id,
                title,
                automatic,
                created_at,
                updated_at,
            },
        )
        .collect();
    let inc: Vec<(String, String, i64, i64, bool, i64)> = sqlx::query_as(
        "SELECT key, text, first_seen, last_seen, active, conversation_id FROM dieter_incidents ORDER BY active DESC, last_seen DESC LIMIT 50",
    )
    .fetch_all(pool)
    .await?;
    let incidents = inc
        .into_iter()
        .map(
            |(key, text, first_seen, last_seen, active, conversation_id)| DieterIncident {
                key,
                text,
                first_seen,
                last_seen,
                active,
                conversation_id,
            },
        )
        .collect();
    Ok(DieterStatus {
        openrouter_key_set: !s.openrouter_key.is_empty(),
        xai_key_set: !s.xai_key.is_empty(),
        claude_token_set: !s.claude_token.is_empty(),
        claude_version: components::versions(&config.data_dir)
            .get("claude")
            .cloned()
            .unwrap_or_default(),
        settings: s.settings,
        ready,
        ready_detail,
        conversations,
        incidents,
        last_watch: state.0.last_watch.load(Ordering::Relaxed),
    })
}

// ------------------------------------------------------------------ Gespräche

async fn add_message(
    pool: &SqlitePool,
    conv: i64,
    role: &str,
    text: &str,
    tool: &str,
    detail: &str,
    raw: &str,
) -> AppResult<()> {
    sqlx::query("INSERT INTO dieter_messages (conversation_id, role, text, tool, detail, raw, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(conv)
        .bind(role)
        .bind(text)
        .bind(tool)
        .bind(detail)
        .bind(raw)
        .bind(now())
        .execute(pool)
        .await?;
    sqlx::query("UPDATE dieter_conversations SET updated_at = ? WHERE id = ?")
        .bind(now())
        .bind(conv)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn create_conversation(
    pool: &SqlitePool,
    title: &str,
    automatic: bool,
) -> AppResult<i64> {
    let t: String = title.trim().chars().take(80).collect();
    Ok(sqlx::query_scalar("INSERT INTO dieter_conversations (title, automatic, created_at, updated_at) VALUES (?, ?, ?, ?) RETURNING id")
        .bind(if t.is_empty() { "Neues Gespräch".to_string() } else { t })
        .bind(automatic)
        .bind(now())
        .bind(now())
        .fetch_one(pool)
        .await?)
}

pub async fn thread(pool: &SqlitePool, state: &DieterState, id: i64) -> AppResult<DieterThread> {
    let row: Option<(i64, String, bool, i64, i64)> =
        sqlx::query_as("SELECT id, title, automatic, created_at, updated_at FROM dieter_conversations WHERE id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    let (id, title, automatic, created_at, updated_at) = row.ok_or(AppError::NotFound)?;
    let msgs: Vec<(i64, String, String, String, String, i64)> = sqlx::query_as(
        "SELECT id, role, text, tool, detail, created_at FROM dieter_messages WHERE conversation_id = ? AND role != 'raw' ORDER BY id",
    )
    .bind(id)
    .fetch_all(pool)
    .await?;
    Ok(DieterThread {
        conversation: DieterConversation {
            running: state.running(id),
            id,
            title,
            automatic,
            created_at,
            updated_at,
        },
        messages: msgs
            .into_iter()
            .map(|(id, role, text, tool, detail, created_at)| DieterMessage {
                id,
                role,
                text,
                tool,
                detail,
                created_at,
            })
            .collect(),
    })
}

pub async fn delete_conversation(pool: &SqlitePool, id: i64) -> AppResult<()> {
    sqlx::query("DELETE FROM dieter_messages WHERE conversation_id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    let done = sqlx::query("DELETE FROM dieter_conversations WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Nachricht senden – Dieter antwortet im Hintergrund.
pub async fn send(ctx: &Ctx, conv: i64, text: &str) -> AppResult<()> {
    send_with_context(ctx, conv, text, "").await
}

/// Wie [`send`], mit der Seite, auf der der Benutzer gerade ist.
pub async fn send_with_context(ctx: &Ctx, conv: i64, text: &str, context: &str) -> AppResult<()> {
    let text = text.trim();
    if text.is_empty() || text.len() > 20_000 {
        return Err(AppError::bad(
            "Bitte eine Nachricht schreiben (höchstens 20 000 Zeichen).",
        ));
    }
    let s = stored(&ctx.pool).await?;
    let (ready, why) = readiness(&s, &ctx.config.data_dir);
    if !ready {
        return Err(AppError::bad(format!(
            "Dieter ist noch nicht bereit: {why}"
        )));
    }
    if !lock(&ctx.state.0.running).insert(conv) {
        return Err(AppError::Conflict(
            "Dieter arbeitet noch an der letzten Nachricht.".into(),
        ));
    }
    let context: String = context.trim().chars().take(120).collect();
    let for_model = if context.is_empty() {
        text.to_string()
    } else {
        format!("{text}\n\n[Der Benutzer ist gerade auf der Seite „{context}“ von nrzNetwork.]")
    };
    add_message(
        &ctx.pool,
        conv,
        "user",
        text,
        "",
        "",
        &json!({ "role": "user", "content": for_model }).to_string(),
    )
    .await?;
    let ctx2 = ctx.clone();
    let text = for_model;
    tokio::spawn(async move {
        let result = match s.settings.provider {
            DieterProvider::ClaudeCli => run_claude(&ctx2, &s, conv, &text).await,
            _ => run_chat(&ctx2, &s, conv).await,
        };
        if let Err(e) = result {
            tracing::warn!(conversation = conv, "Dieter: {e}");
            let _ = add_message(&ctx2.pool, conv, "error", &e.to_string(), "", "", "").await;
        }
        lock(&ctx2.state.0.running).remove(&conv);
    });
    Ok(())
}

// ------------------------------------------------------------------ Anweisungen

/// API-Übersicht aus der Dokumentation der Typen (Tabelle `| Methode Pfad | … |`).
pub fn api_reference() -> String {
    include_str!("../../types/src/lib.rs")
        .lines()
        .filter_map(|l| l.strip_prefix("//! | `"))
        .filter(|l| {
            !l.contains("/auth")
                && !l.contains("/users")
                && !l.contains("/dieter")
                && !l.contains("/settings/mcp")
        })
        .map(|l| {
            let l = l.replace("\\|", "|");
            let mut parts = l.splitn(2, "` |");
            let ep = parts.next().unwrap_or_default().trim().to_string();
            let rest = parts
                .next()
                .unwrap_or_default()
                .replace('`', "")
                .replace("[", "")
                .replace("]", "");
            let rest: String = rest
                .split(" | ")
                .next()
                .unwrap_or_default()
                .trim()
                .chars()
                .take(160)
                .collect();
            format!("- {ep} {rest}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

async fn system_prompt(ctx: &Ctx, s: &Stored) -> String {
    let device = ctx
        .engine
        .device_addresses()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "Du bist Dieter, der Netzwerk-Assistent von nrzNetwork (Version {ver}) auf einem Umbrel-Server zu Hause. \
nrzNetwork ist DNS-Server mit Sperrlisten und eigenen Zonen, Reverse Proxy mit HTTPS, Verwaltung der Cloudflare-DNS-Einträge, \
NetBird-Netz, eingebauter Cloudflare Tunnel und NetBird-Client, Zugriffs-Monitor und Spy (was andere über die Domains wissen).\n\
Adressen dieses Geräts: {device}. Jetzt: {time} (Unix {unix}).\n\n\
Werkzeuge: `api_request` ruft die REST-API von nrzNetwork auf (Pfad ohne /api/v1, z. B. GET /proxy, PUT /proxy/hosts/3), \
`dns_lookup` fragt DNS (leerer server = nrzNetwork selbst mit eigenen Zonen und Sperren; sonst z. B. 1.1.1.1 für die Sicht von aussen). \
Cloudflare-API: /cloudflare/<pfad> (Zonen lesen, DNS-Einträge verwalten), NetBird-API: /netbird/<pfad> (peers, groups, policies, networks, dns, setup-keys, users, reverse-proxies). \
Docker (nur lesend): GET /docker (alle Container mit Namen, internen IPs, Netzen, Ports; auch Docker-Netze), GET /docker/containers/<name>/logs?tail=200, GET /docker/containers/<name>. \
{changes}\n\n\
Arbeitsweise: Erst Zustand prüfen (lesen), dann handeln. Vor dem Löschen oder Überschreiben genau prüfen, ob es das Richtige ist. \
Nach einer Änderung prüfen, ob sie gewirkt hat. Keine Schlüssel oder Tokens ausgeben. Antworte auf Deutsch, knapp und übersichtlich (Markdown: kurze Absätze, Listen, **fett**, `code`), mit dem, was du gefunden und getan hast; \
wenn etwas nur der Besitzer tun kann (z. B. ein Token besorgen), sag genau wie.\n\nAPI:\n{api}",
        ver = crate::VERSION,
        time = jiff::Timestamp::now().to_zoned(components::time_zone()).strftime("%Y-%m-%d %H:%M %Z"),
        unix = now(),
        changes = if s.settings.allow_changes {
            "Du DARFST Einstellungen ändern (POST/PUT/PATCH/DELETE)."
        } else {
            "Du darfst NICHTS ändern – nur lesen, prüfen und Vorschläge machen (Änderungen sind gesperrt)."
        },
        api = api_reference(),
    )
}

// ------------------------------------------------------------------ Werkzeuge

fn tool_defs() -> Vec<(&'static str, &'static str, Value)> {
    vec![
        (
            "api_request",
            "Ruft die REST-API von nrzNetwork auf (alles, was die Oberfläche kann). Antwort: HTTP-Status und JSON.",
            json!({
                "type": "object",
                "properties": {
                    "method": { "type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"] },
                    "path": { "type": "string", "description": "Pfad ohne /api/v1, z. B. /proxy/hosts oder /cloudflare/zones" },
                    "query": { "type": "string", "description": "Optional: Query ohne ?, z. B. per_page=500" },
                    "body": { "type": "object", "description": "Optional: JSON-Körper" }
                },
                "required": ["method", "path"],
                "additionalProperties": false
            }),
        ),
        (
            "dns_lookup",
            "DNS-Abfrage. server leer = nrzNetwork selbst (mit eigenen Zonen, Sperren, Proxy-Namen); sonst z. B. 1.1.1.1.",
            json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "type": { "type": "string", "description": "A, AAAA, CNAME, MX, TXT, NS, SOA, CAA … (Vorgabe A)" },
                    "server": { "type": "string" }
                },
                "required": ["name"],
                "additionalProperties": false
            }),
        ),
    ]
}

/// Werkzeuge im MCP-Format (für die Claude CLI).
pub fn mcp_tools() -> Vec<Value> {
    tool_defs()
        .into_iter()
        .map(|(n, d, s)| json!({ "name": n, "description": d, "inputSchema": s }))
        .collect()
}

fn openai_tools() -> Vec<Value> {
    tool_defs()
        .into_iter()
        .map(|(n, d, s)| json!({ "type": "function", "function": { "name": n, "description": d, "parameters": s } }))
        .collect()
}

/// Darf Dieter diesen Aufruf machen?
fn allowed(method: &str, path: &str, allow_changes: bool) -> Result<(), String> {
    if !path.starts_with('/') || path.contains("..") || path.contains('#') {
        return Err("Pfad muss mit / beginnen.".into());
    }
    let p = path.split('?').next().unwrap_or_default();
    for blocked in [
        "/auth",
        "/users",
        "/dieter",
        "/settings/mcp",
        "/account",
        "/me",
    ] {
        if p == blocked || p.starts_with(&format!("{blocked}/")) {
            return Err(format!("{blocked} ist für Dieter gesperrt."));
        }
    }
    if method != "GET" && p == "/integrations" {
        return Err("Zugangsdaten ändern darf nur der Besitzer.".into());
    }
    let read_post = [
        "/tools/ping",
        "/tools/ports",
        "/tools/http",
        "/resolve",
        "/spy/scan",
        "/components/check",
    ];
    if !allow_changes && method != "GET" && !(method == "POST" && read_post.contains(&p)) {
        return Err(
            "Änderungen sind für Dieter gesperrt (Einstellungen → Dieter → „darf ändern“).".into(),
        );
    }
    Ok(())
}

fn clip(s: String) -> String {
    if s.len() <= MAX_RESULT {
        return s;
    }
    let mut end = MAX_RESULT;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… (gekürzt, {} Zeichen insgesamt)", &s[..end], s.len())
}

/// Ruft die eigene REST-API (`/api/v1<path>`) über 127.0.0.1 als Admin auf (auch für den
/// MCP-Server); `query` ohne `?`, schon kodiert. Ergebnis: HTTP-Status und Antworttext.
pub async fn internal_request(
    state: &DieterState,
    method: &str,
    path: &str,
    query: &str,
    body: Option<&Value>,
) -> Result<(u16, String), String> {
    let port = state.0.port.load(Ordering::Relaxed);
    if port == 0 {
        return Err("Server startet noch.".into());
    }
    let mut url = format!("http://127.0.0.1:{port}/api/v1{path}");
    if !query.is_empty() {
        url.push('?');
        url.push_str(query);
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| e.to_string())?;
    let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut req = client.request(m, url).header(INTERNAL_HEADER, state.key());
    if let Some(b) = body {
        req = req.json(b);
    }
    let r = req.send().await.map_err(|e| e.to_string())?;
    let status = r.status().as_u16();
    Ok((status, r.text().await.unwrap_or_default()))
}

/// Werkzeug ausführen: (Ergebnis für das Modell, Kurzform für die Anzeige).
pub async fn call_tool(
    ctx: &Ctx,
    allow_changes: bool,
    name: &str,
    args: &Value,
) -> (String, String) {
    match name {
        "api_request" => {
            let method = args["method"].as_str().unwrap_or("GET").to_uppercase();
            let path = args["path"].as_str().unwrap_or_default().to_string();
            let query = args["query"]
                .as_str()
                .unwrap_or_default()
                .trim_start_matches('?')
                .to_string();
            let short = format!(
                "{method} {path}{}",
                if query.is_empty() {
                    String::new()
                } else {
                    format!("?{query}")
                }
            );
            if let Err(e) = allowed(&method, &path, allow_changes) {
                return (format!("Abgelehnt: {e}"), format!("{short} → abgelehnt"));
            }
            let body = args.get("body").filter(|b| !b.is_null());
            match internal_request(&ctx.state, &method, &path, &query, body).await {
                Ok((status, text)) => {
                    if method != "GET" && (200..300).contains(&status) {
                        tracing::info!(by = "dieter", %short, status, "Änderung durch Dieter");
                    }
                    (
                        clip(format!("HTTP {status}\n{text}")),
                        format!("{short} → {status}"),
                    )
                }
                Err(e) => (format!("Fehler: {e}"), format!("{short} → Fehler")),
            }
        }
        "dns_lookup" => {
            let input = ResolveInput {
                name: args["name"].as_str().unwrap_or_default().to_string(),
                qtype: args["type"].as_str().unwrap_or("A").to_string(),
                server: args["server"].as_str().unwrap_or_default().to_string(),
                ..ResolveInput::default()
            };
            let short = format!(
                "{} {}{}",
                input.qtype,
                input.name,
                if input.server.is_empty() {
                    String::new()
                } else {
                    format!(" @{}", input.server)
                }
            );
            match ctx.engine.resolve(&input).await {
                Ok(r) => (
                    clip(serde_json::to_string(&r).unwrap_or_default()),
                    format!("DNS {short} → {} Antworten", r.answers.len()),
                ),
                Err(e) => (format!("Fehler: {e}"), format!("DNS {short} → Fehler")),
            }
        }
        _ => (format!("Unbekanntes Werkzeug: {name}"), name.to_string()),
    }
}

// ------------------------------------------------------------------ OpenRouter / xAI

async fn run_chat(ctx: &Ctx, s: &Stored, conv: i64) -> AppResult<()> {
    let (url, key) = match s.settings.provider {
        DieterProvider::Xai => (ctx.config.dieter_xai_url.clone(), s.xai_key.clone()),
        _ => (
            ctx.config.dieter_openrouter_url.clone(),
            s.openrouter_key.clone(),
        ),
    };
    let model = model(s);
    let raws: Vec<String> = sqlx::query_scalar(
        "SELECT raw FROM dieter_messages WHERE conversation_id = ? AND raw != '' ORDER BY id",
    )
    .bind(conv)
    .fetch_all(&ctx.pool)
    .await?;
    let mut messages: Vec<Value> =
        vec![json!({ "role": "system", "content": system_prompt(ctx, s).await })];
    messages.extend(
        raws.iter()
            .filter_map(|r| serde_json::from_str::<Value>(r).ok()),
    );
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .user_agent(concat!("nrzNetwork/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AppError::Config(e.to_string()))?;
    for _ in 0..MAX_STEPS {
        let body = json!({ "model": model, "messages": messages, "tools": openai_tools(), "tool_choice": "auto", "max_tokens": 4096 });
        let resp = http
            .post(&url)
            .bearer_auth(&key)
            .header("X-Title", "nrzNetwork Dieter")
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::BadGateway(format!("KI-Anbieter nicht erreichbar: {e}")))?;
        let status = resp.status();
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            let msg = v["error"]["message"]
                .as_str()
                .or(v["error"].as_str())
                .unwrap_or("unbekannter Fehler");
            return Err(AppError::BadGateway(format!(
                "KI-Anbieter: HTTP {status}: {msg}"
            )));
        }
        let msg = v["choices"][0]["message"].clone();
        if msg.is_null() {
            return Err(AppError::BadGateway("KI-Anbieter: leere Antwort".into()));
        }
        let mut stored_msg = json!({ "role": "assistant", "content": msg["content"].clone() });
        if msg["tool_calls"].is_array() {
            stored_msg["tool_calls"] = msg["tool_calls"].clone();
        }
        let text = msg["content"]
            .as_str()
            .unwrap_or_default()
            .trim()
            .to_string();
        add_message(
            &ctx.pool,
            conv,
            if text.is_empty() { "raw" } else { "assistant" },
            &text,
            "",
            "",
            &stored_msg.to_string(),
        )
        .await?;
        messages.push(stored_msg);
        let calls = msg["tool_calls"].as_array().cloned().unwrap_or_default();
        if calls.is_empty() {
            return Ok(());
        }
        for c in calls {
            let id = c["id"].as_str().unwrap_or_default().to_string();
            let name = c["function"]["name"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let args: Value = c["function"]["arguments"]
                .as_str()
                .and_then(|a| serde_json::from_str(a).ok())
                .unwrap_or(json!({}));
            let (result, short) = call_tool(ctx, s.settings.allow_changes, &name, &args).await;
            let tool_msg = json!({ "role": "tool", "tool_call_id": id, "content": result });
            add_message(
                &ctx.pool,
                conv,
                "action",
                "",
                &name,
                &short,
                &tool_msg.to_string(),
            )
            .await?;
            messages.push(tool_msg);
        }
    }
    add_message(
        &ctx.pool,
        conv,
        "error",
        &format!("Abgebrochen nach {MAX_STEPS} Schritten."),
        "",
        "",
        "",
    )
    .await
}

// ------------------------------------------------------------------ Claude CLI

/// Claude CLI laden oder aktualisieren (offizielle Releases, SHA-256 aus dem Manifest).
pub async fn install_claude(config: &Config) -> AppResult<String> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("nrzNetwork/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AppError::Config(e.to_string()))?;
    let version = http
        .get(format!("{CLAUDE_BASE}/latest"))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| AppError::BadGateway(format!("Claude CLI: {e}")))?
        .text()
        .await
        .map_err(|e| AppError::BadGateway(format!("Claude CLI: {e}")))?
        .trim()
        .to_string();
    if version.is_empty()
        || version.len() > 40
        || !version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(AppError::BadGateway(
            "Claude CLI: unerwartete Versionsangabe".into(),
        ));
    }
    if components::versions(&config.data_dir).get("claude") == Some(&version)
        && claude_bin(&config.data_dir).exists()
    {
        return Ok(format!("Claude CLI {version} ist aktuell"));
    }
    let arch = if components::arch() == "arm64" {
        "arm64"
    } else {
        "x64"
    };
    let platform = format!("linux-{arch}");
    let manifest: Value = http
        .get(format!("{CLAUDE_BASE}/{version}/manifest.json"))
        .send()
        .await
        .map_err(|e| AppError::BadGateway(format!("Claude CLI: {e}")))?
        .json()
        .await
        .map_err(|e| AppError::BadGateway(format!("Claude CLI: {e}")))?;
    let sha = manifest["platforms"][&platform]["checksum"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if sha.len() != 64 {
        return Err(AppError::BadGateway(format!(
            "Claude CLI: keine Prüfsumme für {platform}"
        )));
    }
    components::install(
        &config.data_dir,
        "claude",
        &format!("{CLAUDE_BASE}/{version}/{platform}/claude"),
        &sha,
        &version,
    )
    .await?;
    Ok(format!("Claude CLI {version} installiert"))
}

async fn run_claude(ctx: &Ctx, s: &Stored, conv: i64, text: &str) -> AppResult<()> {
    let data = &ctx.config.data_dir;
    let home = data.join("claude");
    std::fs::create_dir_all(&home).map_err(|e| AppError::Config(e.to_string()))?;
    let port = ctx.state.0.port.load(Ordering::Relaxed);
    let mcp = json!({ "mcpServers": { "nrznetwork": { "type": "http", "url": format!("http://127.0.0.1:{port}/mcp/dieter"), "headers": { "Authorization": format!("Bearer {}", ctx.state.key()) } } } });
    let mcp_path = home.join("mcp.json");
    std::fs::write(&mcp_path, mcp.to_string()).map_err(|e| AppError::Config(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&mcp_path, std::fs::Permissions::from_mode(0o600));
    }
    let session: String =
        sqlx::query_scalar("SELECT session FROM dieter_conversations WHERE id = ?")
            .bind(conv)
            .fetch_one(&ctx.pool)
            .await?;
    let mut args: Vec<String> = vec![
        "-p".into(),
        text.into(),
        "--output-format".into(),
        "stream-json".into(),
        "--verbose".into(),
        "--mcp-config".into(),
        mcp_path.display().to_string(),
        "--strict-mcp-config".into(),
        "--allowedTools".into(),
        "mcp__nrznetwork__api_request,mcp__nrznetwork__dns_lookup".into(),
        "--append-system-prompt".into(),
        system_prompt(ctx, s).await,
        "--model".into(),
        model(s),
        "--max-turns".into(),
        "40".into(),
    ];
    if !session.is_empty() {
        args.push("--resume".into());
        args.push(session);
    }
    let mut cmd = tokio::process::Command::new(claude_bin(data));
    cmd.args(&args)
        .current_dir(&home)
        .env("HOME", &home)
        .env("DISABLE_AUTOUPDATER", "1")
        .env("SSL_CERT_FILE", components::ca_bundle(data)?)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if s.claude_token.starts_with("sk-ant-oat") {
        cmd.env("CLAUDE_CODE_OAUTH_TOKEN", &s.claude_token);
    } else {
        cmd.env("ANTHROPIC_API_KEY", &s.claude_token);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| AppError::Config(format!("Claude CLI starten: {e}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AppError::Config("Claude CLI: keine Ausgabe".into()))?;
    let stderr = child.stderr.take();
    let err_task = tokio::spawn(async move {
        let mut out = String::new();
        if let Some(e) = stderr {
            let mut lines = BufReader::new(e).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                if out.len() < 4000 {
                    out.push_str(&l);
                    out.push('\n');
                }
            }
        }
        out
    });
    let mut lines = BufReader::new(stdout).lines();
    let mut final_text = String::new();
    let mut got_result = false;
    let read = async {
        while let Ok(Some(l)) = lines.next_line().await {
            let Ok(v) = serde_json::from_str::<Value>(&l) else {
                continue;
            };
            match v["type"].as_str() {
                Some("system") => {
                    if let Some(sid) = v["session_id"].as_str() {
                        let _ =
                            sqlx::query("UPDATE dieter_conversations SET session = ? WHERE id = ?")
                                .bind(sid)
                                .bind(conv)
                                .execute(&ctx.pool)
                                .await;
                    }
                }
                Some("assistant") => {
                    for c in v["message"]["content"].as_array().into_iter().flatten() {
                        match c["type"].as_str() {
                            Some("tool_use") => {
                                let name = c["name"]
                                    .as_str()
                                    .unwrap_or_default()
                                    .trim_start_matches("mcp__nrznetwork__")
                                    .to_string();
                                let i = &c["input"];
                                let short = if name == "api_request" {
                                    format!(
                                        "{} {}",
                                        i["method"].as_str().unwrap_or("GET"),
                                        i["path"].as_str().unwrap_or_default()
                                    )
                                } else {
                                    format!(
                                        "{} {}",
                                        i["type"].as_str().unwrap_or("A"),
                                        i["name"].as_str().unwrap_or_default()
                                    )
                                };
                                let _ =
                                    add_message(&ctx.pool, conv, "action", "", &name, &short, "")
                                        .await;
                            }
                            Some("text") => {
                                let t = c["text"].as_str().unwrap_or_default().trim();
                                if !t.is_empty() {
                                    final_text = t.to_string();
                                    let _ =
                                        add_message(&ctx.pool, conv, "assistant", t, "", "", "")
                                            .await;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Some("result") => {
                    got_result = true;
                    if let Some(sid) = v["session_id"].as_str() {
                        let _ =
                            sqlx::query("UPDATE dieter_conversations SET session = ? WHERE id = ?")
                                .bind(sid)
                                .bind(conv)
                                .execute(&ctx.pool)
                                .await;
                    }
                    if v["is_error"].as_bool() == Some(true) {
                        let r = v["result"]
                            .as_str()
                            .unwrap_or("Fehler der Claude CLI")
                            .to_string();
                        if r.trim() == final_text {
                            // Schon als Antwort gezeigt – als Fehler kennzeichnen statt doppelt
                            let _ = sqlx::query(
                                "UPDATE dieter_messages SET role = 'error' WHERE id = (SELECT max(id) FROM dieter_messages WHERE conversation_id = ? AND role = 'assistant')",
                            )
                            .bind(conv)
                            .execute(&ctx.pool)
                            .await;
                        } else {
                            let _ = add_message(&ctx.pool, conv, "error", &r, "", "", "").await;
                        }
                    } else if let Some(r) = v["result"].as_str() {
                        if r.trim() != final_text && !r.trim().is_empty() {
                            let _ = add_message(&ctx.pool, conv, "assistant", r.trim(), "", "", "")
                                .await;
                        }
                    }
                }
                _ => {}
            }
        }
    };
    if tokio::time::timeout(Duration::from_secs(900), read)
        .await
        .is_err()
    {
        let _ = child.kill().await;
        return Err(AppError::BadGateway(
            "Claude CLI: nach 15 Minuten abgebrochen".into(),
        ));
    }
    let _ = child.wait().await;
    let errs = err_task.await.unwrap_or_default();
    if !got_result {
        return Err(AppError::BadGateway(format!(
            "Claude CLI ohne Ergebnis: {}",
            errs.trim().chars().take(600).collect::<String>()
        )));
    }
    Ok(())
}

// ------------------------------------------------------------------ Überwachung

/// Gefundene Probleme: (Schlüssel, Beschreibung).
async fn check(ctx: &Ctx) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let pool = &ctx.pool;
    // DNS-Weiterleitung
    let r = ctx
        .engine
        .resolve(&ResolveInput {
            name: "example.com".into(),
            qtype: "A".into(),
            ..ResolveInput::default()
        })
        .await;
    if !r.as_ref().is_ok_and(|r| !r.answers.is_empty()) {
        out.push((
            "dns-forward".into(),
            format!(
                "DNS-Weiterleitung liefert keine Antwort für example.com ({})",
                r.err()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "leer".into())
            ),
        ));
    }
    let since = (now() - 900) * 1000;
    let (total, fails): (i64, i64) = sqlx::query_as(
        "SELECT count(*), coalesce(sum(rcode = 'SERVFAIL'), 0) FROM query_log WHERE at_ms >= ?",
    )
    .bind(since)
    .fetch_one(pool)
    .await
    .unwrap_or((0, 0));
    if total >= 30 && fails * 100 / total.max(1) >= 20 {
        out.push((
            "dns-servfail".into(),
            format!(
                "{fails} von {total} DNS-Anfragen der letzten 15 Minuten scheiterten (SERVFAIL)"
            ),
        ));
    }
    // Komponenten
    if let Ok(st) = components::status(pool, &ctx.config, &ctx.components).await {
        for c in st.components.iter().filter(|c| c.enabled) {
            let since_start = if c.started_at == 0 {
                i64::MAX
            } else {
                now() - c.started_at
            };
            if !c.running || (!c.connected && since_start > 300) {
                let last = c.log.last().cloned().unwrap_or_default();
                out.push((
                    format!("component-{}", c.name),
                    format!(
                        "{} läuft nicht oder ist nicht verbunden ({}){}",
                        c.name,
                        if c.detail.is_empty() {
                            c.last_error.clone()
                        } else {
                            c.detail.clone()
                        },
                        if last.is_empty() {
                            String::new()
                        } else {
                            format!(
                                " – letzte Ausgabe: {}",
                                last.chars().take(200).collect::<String>()
                            )
                        }
                    ),
                ));
            }
        }
    }
    // Proxy-Ziele
    let hosts: Vec<(String, String)> =
        sqlx::query_as("SELECT host, target FROM proxy_hosts WHERE enabled = 1")
            .fetch_all(pool)
            .await
            .unwrap_or_default();
    for (host, target) in hosts {
        let Ok(url) = reqwest::Url::parse(&target) else {
            continue;
        };
        let Some(h) = url.host_str() else { continue };
        let port = url.port_or_known_default().unwrap_or(80);
        let h = match h.parse::<std::net::IpAddr>() {
            Ok(ip)
                if ctx.config.host_gateway.is_some()
                    && (ip.is_loopback() || ctx.engine.device_addresses().contains(&ip)) =>
            {
                ctx.config.host_gateway.clone().unwrap_or_default()
            }
            _ => h.to_string(),
        };
        let ok = matches!(
            tokio::time::timeout(
                Duration::from_secs(4),
                tokio::net::TcpStream::connect((h.as_str(), port))
            )
            .await,
            Ok(Ok(_))
        );
        if !ok {
            out.push((
                format!("proxy-{host}"),
                format!("Reverse-Proxy-Ziel nicht erreichbar: {host} → {target}"),
            ));
        }
    }
    // Proxy-Fehler (5xx)
    let errs: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT host, count(*), coalesce(sum(status >= 500), 0) FROM access_log WHERE at_ms >= ? GROUP BY host",
    )
    .bind(since)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    for (host, n, bad) in errs {
        if n >= 10 && bad * 100 / n.max(1) >= 30 {
            out.push((
                format!("http5xx-{host}"),
                format!("{host}: {bad} von {n} Aufrufen der letzten 15 Minuten mit Serverfehler"),
            ));
        }
    }
    // Zertifikat
    let tls = ctx.proxy.tls();
    if let Some(c) = tls.cert() {
        let days = (c.not_after - now()) / 86_400;
        if days < 14 {
            out.push((
                "tls-expiry".into(),
                format!(
                    "HTTPS-Zertifikat für {} läuft in {days} Tagen ab",
                    c.names.join(", ")
                ),
            ));
        }
    }
    let le = tls.last_error();
    if !le.is_empty() {
        out.push((
            "tls-error".into(),
            format!("HTTPS-Zertifikat: letzter Versuch fehlgeschlagen: {le}"),
        ));
    }
    // Spy: hohe Risiken im neuesten Bericht je Domain
    let reports: Vec<String> = sqlx::query_scalar(
        "SELECT report FROM spy_reports r WHERE scanned_at = (SELECT max(scanned_at) FROM spy_reports WHERE domain = r.domain)",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    for raw in reports {
        let Ok(v) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let domain = v["domain"].as_str().unwrap_or_default();
        for f in v["findings"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|f| f["severity"] == "high")
        {
            out.push((
                format!("spy-{domain}-{}", f["id"].as_str().unwrap_or("?")),
                format!(
                    "Spy ({domain}): {}",
                    f["title"].as_str().unwrap_or_default()
                ),
            ));
        }
    }
    out
}

/// Einmal prüfen: Vorfälle festhalten, bei neuen Problemen Dieter einschalten.
pub async fn watch_once(ctx: &Ctx) -> AppResult<usize> {
    let problems = check(ctx).await;
    ctx.state.0.last_watch.store(now(), Ordering::Relaxed);
    let t = now();
    let keys: Vec<String> = problems.iter().map(|p| p.0.clone()).collect();
    sqlx::query("UPDATE dieter_incidents SET active = 0")
        .execute(&ctx.pool)
        .await?;
    for (k, text) in &problems {
        sqlx::query(
            "INSERT INTO dieter_incidents (key, text, first_seen, last_seen, active) VALUES (?, ?, ?, ?, 1)
             ON CONFLICT (key) DO UPDATE SET text = excluded.text, last_seen = excluded.last_seen, active = 1",
        )
        .bind(k)
        .bind(text)
        .bind(t)
        .bind(t)
        .execute(&ctx.pool)
        .await?;
    }
    let s = stored(&ctx.pool).await?;
    if keys.is_empty() || !s.settings.auto_watch || !readiness(&s, &ctx.config.data_dir).0 {
        return Ok(problems.len());
    }
    let due: Vec<(String, String)> = sqlx::query_as(
        "SELECT key, text FROM dieter_incidents WHERE active = 1 AND handled_at < ?",
    )
    .bind(t - 6 * 3600)
    .fetch_all(&ctx.pool)
    .await?;
    if due.is_empty() {
        return Ok(problems.len());
    }
    let title = if due.len() == 1 {
        format!("Automatisch: {}", due[0].1)
    } else {
        format!("Automatisch: {} Probleme", due.len())
    };
    let conv = create_conversation(&ctx.pool, &title, true).await?;
    for (k, _) in &due {
        sqlx::query(
            "UPDATE dieter_incidents SET handled_at = ?, conversation_id = ? WHERE key = ?",
        )
        .bind(t)
        .bind(conv)
        .bind(k)
        .execute(&ctx.pool)
        .await?;
    }
    let list = due
        .iter()
        .map(|(_, text)| format!("- {text}"))
        .collect::<Vec<_>>()
        .join("\n");
    let task = if s.settings.auto_fix && s.settings.allow_changes {
        "Untersuche die Ursache und behebe sie, wenn es sicher geht. Prüfe danach, ob es wirkt. Berichte kurz, was du gefunden und getan hast und was der Besitzer selbst tun muss."
    } else {
        "Untersuche die Ursache, ändere aber nichts. Berichte kurz, was du gefunden hast und was zu tun ist."
    };
    let prompt =
        format!("Die automatische Überwachung hat folgende Probleme gefunden:\n{list}\n\n{task}");
    tracing::info!(
        problems = due.len(),
        conversation = conv,
        "Dieter: automatischer Einsatz"
    );
    send(ctx, conv, &prompt).await?;
    Ok(problems.len())
}

pub async fn watcher(ctx: Ctx, mut shutdown: rocket::Shutdown) {
    let mut last = 0i64;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
            _ = &mut shutdown => return,
        }
        let minutes = stored(&ctx.pool)
            .await
            .map(|s| i64::from(s.settings.watch_minutes.clamp(5, 240)))
            .unwrap_or(10);
        if now() - last < minutes * 60 {
            continue;
        }
        last = now();
        if let Err(e) = watch_once(&ctx).await {
            tracing::warn!("Dieter-Überwachung: {e}");
        }
    }
}

/// Für Tests: Prüfungen ohne Einsatz.
pub async fn problems(ctx: &Ctx) -> BTreeMap<String, String> {
    check(ctx).await.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions() {
        assert!(allowed("GET", "/proxy", false).is_ok());
        assert!(allowed("POST", "/tools/ping", false).is_ok());
        assert!(allowed("PUT", "/proxy/hosts/1", false).is_err());
        assert!(allowed("PUT", "/proxy/hosts/1", true).is_ok());
        assert!(allowed("GET", "/users", true).is_err());
        assert!(allowed("POST", "/auth/login", true).is_err());
        assert!(allowed("PUT", "/dieter/settings", true).is_err());
        assert!(allowed("PUT", "/integrations", true).is_err());
        assert!(allowed("GET", "/integrations", true).is_ok());
        assert!(allowed("GET", "/../etc", true).is_err());
    }

    #[test]
    fn api_reference_lists_endpoints() {
        let r = api_reference();
        assert!(r.contains("/proxy/hosts"), "{r}");
        assert!(r.contains("/cloudflare/"));
        assert!(!r.contains("/auth/login") && !r.contains("/dieter"));
        assert!(r.lines().count() > 40);
    }
}
