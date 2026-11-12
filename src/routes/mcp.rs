//! MCP-Server unter `/mcp`: Model Context Protocol über „Streamable HTTP“ (JSON-RPC 2.0).
//!
//! Zustandslos: jede `POST`-Anfrage trägt eine JSON-RPC-Nachricht (oder eine Liste davon) und
//! bekommt die Antwort als `application/json` – ohne Sitzungs-ID und ohne SSE-Strom (`GET`
//! und `DELETE` → 405). Zugang mit `Authorization: Bearer <Token>` (Einstellungen → MCP oder
//! `NRZDNS_MCP_TOKEN`). Die Werkzeuge stehen in `services::mcp`.

use crate::auth::guards::is_cross_origin;
use crate::config::Config;
use crate::services::blocking::Updater;
use crate::services::mcp::{self, Access, Ctx, McpState, ToolError};
use nrzdns_engine::Engine;
use rocket::data::{Data, ToByteUnit};
use rocket::http::{ContentType, Header, Status};
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::{self, Responder, Response};
use rocket::{delete, get, post, routes, Route, State};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::io::Cursor;

pub fn routes() -> Vec<Route> {
    routes![post_mcp, get_mcp, delete_mcp]
}

/// Protokollversionen, die dieser Server spricht (neueste zuerst).
const VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
/// Grösster Anfragekörper.
const MAX_BODY_KIB: u64 = 256;

const INSTRUCTIONS: &str = "nrzDNS ist ein DNS-Server mit Sperrlisten (Werbe-/Tracking-Filter). \
    Für eine Übersicht get_overview aufrufen (alle Kennzahlen in einem Aufruf); Details mit \
    get_statistics, get_server_status, get_blocking_status und get_query_log. Filter schalten \
    set_blocking (dauerhaft) und pause_blocking (auf Zeit), sofern Änderungen erlaubt sind.";

/// Was die Anfrage an Kopfzeilen mitbringt (nie abweisend – die Antwort baut der Handler).
struct McpHeaders {
    token: Option<String>,
    cross_origin: bool,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for McpHeaders {
    type Error = std::convert::Infallible;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let token = req.headers().get_one("Authorization").and_then(|h| {
            let (scheme, token) = h.trim().split_once(' ')?;
            scheme
                .eq_ignore_ascii_case("bearer")
                .then(|| token.trim().to_string())
        });
        Outcome::Success(McpHeaders {
            token,
            cross_origin: is_cross_origin(req),
        })
    }
}

/// Antwort des MCP-Endpunkts.
struct Reply {
    status: Status,
    body: Option<Value>,
    /// `WWW-Authenticate: Bearer` mitsenden (401).
    challenge: bool,
}

impl Reply {
    fn json(body: Value) -> Self {
        Reply {
            status: Status::Ok,
            body: Some(body),
            challenge: false,
        }
    }

    fn error(status: Status, message: &str) -> Self {
        Reply {
            status,
            body: Some(json!({ "error": { "code": status.code, "message": message } })),
            challenge: status == Status::Unauthorized,
        }
    }
}

impl<'r> Responder<'r, 'static> for Reply {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        let mut r = Response::build();
        r.status(self.status)
            .header(Header::new("Cache-Control", "no-store"));
        if self.challenge {
            r.header(Header::new(
                "WWW-Authenticate",
                "Bearer realm=\"nrzDNS MCP\"",
            ));
        }
        if self.status == Status::MethodNotAllowed {
            r.header(Header::new("Allow", "POST"));
        }
        if let Some(body) = self.body {
            let text = body.to_string();
            r.header(ContentType::JSON)
                .sized_body(text.len(), Cursor::new(text));
        }
        r.ok()
    }
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

#[allow(clippy::too_many_arguments)]
#[post("/mcp", data = "<data>")]
async fn post_mcp(
    headers: McpHeaders,
    data: Data<'_>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    engine: &State<Engine>,
    updater: &State<Updater>,
    state: &State<McpState>,
) -> Reply {
    // Schutz gegen DNS-Rebinding: Browser von fremden Seiten abweisen
    if headers.cross_origin {
        return Reply::error(
            Status::Forbidden,
            "Anfrage von einer fremden Seite abgewiesen.",
        );
    }
    let allow_changes = match mcp::authorize(pool, config, headers.token.as_deref()).await {
        Ok(Access::Granted { allow_changes }) => allow_changes,
        Ok(Access::Disabled) => {
            return Reply::error(
                Status::Unauthorized,
                "MCP ist aus – in nrzDNS unter Einstellungen → MCP ein Token erzeugen.",
            )
        }
        Ok(Access::Denied) => {
            return Reply::error(Status::Unauthorized, "Token fehlt oder ist falsch.")
        }
        Err(e) => {
            tracing::error!("MCP: {e}");
            return Reply::error(Status::InternalServerError, "Interner Fehler.");
        }
    };
    state.touch();

    let text = match data.open(MAX_BODY_KIB.kibibytes()).into_string().await {
        Ok(t) if t.is_complete() => t.into_inner(),
        Ok(_) => return Reply::error(Status::PayloadTooLarge, "Anfrage zu gross."),
        Err(_) => return Reply::error(Status::BadRequest, "Anfrage nicht lesbar."),
    };
    let message: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return Reply::json(rpc_error(Value::Null, -32700, "Parse error")),
    };

    let ctx = Ctx {
        pool,
        config,
        engine,
        updater,
        allow_changes,
    };
    match message {
        Value::Array(batch) => {
            if batch.is_empty() {
                return Reply::json(rpc_error(Value::Null, -32600, "Invalid Request"));
            }
            let mut out = Vec::new();
            for m in &batch {
                if let Some(r) = handle(&ctx, m).await {
                    out.push(r);
                }
            }
            if out.is_empty() {
                accepted()
            } else {
                Reply::json(Value::Array(out))
            }
        }
        m => match handle(&ctx, &m).await {
            Some(r) => Reply::json(r),
            None => accepted(),
        },
    }
}

/// Nur Benachrichtigungen oder Antworten erhalten → 202 ohne Körper.
fn accepted() -> Reply {
    Reply {
        status: Status::Accepted,
        body: None,
        challenge: false,
    }
}

/// Eine JSON-RPC-Nachricht; `None` für Benachrichtigungen und Antworten (ohne `method`/`id`).
async fn handle(ctx: &Ctx<'_>, m: &Value) -> Option<Value> {
    let Some(obj) = m.as_object() else {
        return Some(rpc_error(Value::Null, -32600, "Invalid Request"));
    };
    let method = obj.get("method").and_then(Value::as_str);
    let id = obj.get("id").cloned();
    let (Some(method), Some(id)) = (method, id) else {
        // Benachrichtigung (z. B. notifications/initialized) oder Antwort des Clients
        return if obj.contains_key("method")
            || obj.contains_key("result")
            || obj.contains_key("error")
        {
            None
        } else {
            Some(rpc_error(Value::Null, -32600, "Invalid Request"))
        };
    };
    let params = obj.get("params").cloned().unwrap_or(Value::Null);
    Some(match method {
        "initialize" => {
            let requested = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let version = VERSIONS
                .iter()
                .find(|v| **v == requested)
                .unwrap_or(&VERSIONS[0]);
            rpc_result(
                id,
                json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": {
                        "name": "nrzDNS",
                        "title": "nrzDNS",
                        "version": crate::VERSION
                    },
                    "instructions": INSTRUCTIONS
                }),
            )
        }
        "ping" => rpc_result(id, json!({})),
        "tools/list" => rpc_result(id, json!({ "tools": mcp::tool_list(ctx.allow_changes) })),
        "tools/call" => {
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return Some(rpc_error(id, -32602, "Werkzeugname fehlt."));
            };
            let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
            match mcp::call(ctx, name, &arguments).await {
                Ok(value) => rpc_result(id, tool_content(value, false)),
                Err(ToolError::Failed(msg)) => {
                    rpc_result(id, tool_content(Value::String(msg), true))
                }
                Err(ToolError::Unknown(msg)) => rpc_error(id, -32602, &msg),
            }
        }
        "resources/list" => rpc_result(id, json!({ "resources": [] })),
        "prompts/list" => rpc_result(id, json!({ "prompts": [] })),
        _ => rpc_error(id, -32601, "Method not found"),
    })
}

/// Ergebnis eines Werkzeugs: JSON als Text (für jeden Client) und als `structuredContent`.
fn tool_content(value: Value, is_error: bool) -> Value {
    let text = match &value {
        Value::String(s) => s.clone(),
        v => v.to_string(),
    };
    let mut r = json!({ "content": [{ "type": "text", "text": text }], "isError": is_error });
    if value.is_object() {
        r["structuredContent"] = value;
    }
    r
}

/// Kein SSE-Strom vom Server (erlaubt laut Spezifikation).
#[get("/mcp", rank = 1)]
fn get_mcp() -> Reply {
    Reply::error(Status::MethodNotAllowed, "Nur POST.")
}

#[delete("/mcp")]
fn delete_mcp() -> Reply {
    Reply::error(Status::MethodNotAllowed, "Nur POST.")
}
