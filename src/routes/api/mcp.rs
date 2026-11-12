//! MCP-Server einrichten: Token erzeugen oder löschen, Änderungen erlauben (nur Admins).

use crate::auth::AdminUser;
use crate::config::Config;
use crate::error::AppResult;
use crate::services::mcp::{self, McpState};
use nrzdns_types::{McpSettingsInput, McpStatus, McpToken};
use rocket::serde::json::Json;
use rocket::{delete, get, post, put, routes, Route, State};
use sqlx::SqlitePool;

pub fn routes() -> Vec<Route> {
    routes![status, update, create_token, revoke_token]
}

#[get("/settings/mcp")]
async fn status(
    _admin: AdminUser,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    state: &State<McpState>,
) -> AppResult<Json<McpStatus>> {
    Ok(Json(mcp::status(pool, config, state).await?))
}

#[put("/settings/mcp", data = "<body>")]
async fn update(
    admin: AdminUser,
    body: Json<McpSettingsInput>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    state: &State<McpState>,
) -> AppResult<Json<McpStatus>> {
    let status = mcp::set_allow_changes(pool, config, state, body.allow_changes).await?;
    tracing::info!(allow_changes = body.allow_changes, by = %admin.0.username, "MCP-Einstellungen geändert");
    Ok(Json(status))
}

/// Neues Token, nur in dieser Antwort im Klartext; das alte gilt sofort nicht mehr.
#[post("/settings/mcp/token")]
async fn create_token(
    admin: AdminUser,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    state: &State<McpState>,
) -> AppResult<Json<McpToken>> {
    let token = mcp::create_token(pool, config, state).await?;
    tracing::info!(by = %admin.0.username, "MCP-Token erzeugt");
    Ok(Json(token))
}

#[delete("/settings/mcp/token")]
async fn revoke_token(
    admin: AdminUser,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    state: &State<McpState>,
) -> AppResult<Json<McpStatus>> {
    let status = mcp::revoke_token(pool, config, state).await?;
    tracing::info!(by = %admin.0.username, "MCP-Token gelöscht");
    Ok(Json(status))
}
