//! MCP-Server einrichten: beliebig viele benannte Tokens mit eigenen Rechten (nur Admins).

use crate::auth::AdminUser;
use crate::config::Config;
use crate::error::AppResult;
use crate::services::mcp::{self, McpState};
use nrzdns_types::{McpSettingsInput, McpStatus, McpToken, McpTokenInput};
use rocket::serde::json::Json;
use rocket::{delete, get, post, put, routes, Route, State};
use sqlx::SqlitePool;

pub fn routes() -> Vec<Route> {
    routes![status, update, create_token, update_token, revoke_token]
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

/// Rechte des Tokens aus `NRZDNS_MCP_TOKEN`.
#[put("/settings/mcp", data = "<body>")]
async fn update(
    admin: AdminUser,
    body: Json<McpSettingsInput>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    state: &State<McpState>,
) -> AppResult<Json<McpStatus>> {
    let status = mcp::set_allow_changes(pool, config, state, body.allow_changes).await?;
    tracing::info!(allow_changes = body.allow_changes, by = %admin.0.username, "MCP: Rechte des Umgebungs-Tokens geändert");
    Ok(Json(status))
}

/// Neues Token, nur in dieser Antwort im Klartext.
#[post("/settings/mcp/tokens", data = "<body>")]
async fn create_token(
    admin: AdminUser,
    body: Json<McpTokenInput>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    state: &State<McpState>,
) -> AppResult<Json<McpToken>> {
    let token = mcp::create_token(pool, config, state, &body).await?;
    tracing::info!(id = token.info.id, name = %token.info.name, allow_changes = token.info.allow_changes, by = %admin.0.username, "MCP-Token erzeugt");
    Ok(Json(token))
}

#[put("/settings/mcp/tokens/<id>", data = "<body>")]
async fn update_token(
    admin: AdminUser,
    id: i64,
    body: Json<McpTokenInput>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    state: &State<McpState>,
) -> AppResult<Json<McpStatus>> {
    let status = mcp::update_token(pool, config, state, id, &body).await?;
    tracing::info!(id, allow_changes = body.allow_changes, by = %admin.0.username, "MCP-Token geändert");
    Ok(Json(status))
}

#[delete("/settings/mcp/tokens/<id>")]
async fn revoke_token(
    admin: AdminUser,
    id: i64,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    state: &State<McpState>,
) -> AppResult<Json<McpStatus>> {
    let status = mcp::revoke_token(pool, config, state, id).await?;
    tracing::info!(id, by = %admin.0.username, "MCP-Token gelöscht");
    Ok(Json(status))
}
