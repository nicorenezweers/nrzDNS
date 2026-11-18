//! Monitor: Zugriffe auf die Websites hinter dem Reverse Proxy.

use crate::auth::{AdminUser, CurrentUser};
use crate::error::AppResult;
use crate::proxy::ProxyState;
use crate::services::access;
use nrzdns_types::{AccessEntry, AccessStats};
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{delete, get, routes, Route, State};
use sqlx::SqlitePool;

pub fn routes() -> Vec<Route> {
    routes![stats, log, clear]
}

#[get("/access/stats?<period>&<host>")]
async fn stats(
    _user: CurrentUser,
    period: Option<&str>,
    host: Option<&str>,
    pool: &State<SqlitePool>,
    state: &State<ProxyState>,
) -> AppResult<Json<AccessStats>> {
    Ok(Json(
        access::stats(pool, state, period.unwrap_or("24h"), host).await?,
    ))
}

#[get("/access/log?<host>&<limit>&<before>")]
async fn log(
    _user: CurrentUser,
    host: Option<&str>,
    limit: Option<u32>,
    before: Option<i64>,
    pool: &State<SqlitePool>,
    state: &State<ProxyState>,
) -> AppResult<Json<Vec<AccessEntry>>> {
    Ok(Json(
        access::log(pool, state, host, limit.unwrap_or(100), before).await?,
    ))
}

#[delete("/access/log")]
async fn clear(
    admin: AdminUser,
    pool: &State<SqlitePool>,
    state: &State<ProxyState>,
) -> AppResult<Status> {
    state.access().take();
    access::clear(pool).await?;
    tracing::info!(by = %admin.0.username, "Zugriffsprotokoll geleert");
    Ok(Status::NoContent)
}
