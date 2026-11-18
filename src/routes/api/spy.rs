//! Spy: was andere über eine Domain wissen können. Lesen darf jeder Angemeldete, Scans
//! starten nur Admins.

use crate::auth::{AdminUser, CurrentUser};
use crate::config::Config;
use crate::error::AppResult;
use crate::services::spy::{self, SpyState};
use nrzdns_types::{SpyReport, SpyScanInput, SpySettings, SpyStatus};
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{delete, get, post, put, routes, Route, State};
use sqlx::SqlitePool;

pub fn routes() -> Vec<Route> {
    routes![status, scan, remove, report, save_settings]
}

#[get("/spy")]
async fn status(
    _user: CurrentUser,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    state: &State<SpyState>,
) -> AppResult<Json<SpyStatus>> {
    Ok(Json(spy::status(pool, config, state).await?))
}

#[post("/spy/scan", data = "<body>")]
async fn scan(
    admin: AdminUser,
    body: Json<SpyScanInput>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    state: &State<SpyState>,
) -> AppResult<Json<SpyStatus>> {
    let domain = spy::check_input(&body.domain)?;
    tracing::info!(by = %admin.0.username, domain = %domain, active = body.active, "Spy-Scan gestartet");
    spy::start(
        pool.inner().clone(),
        config.inner().clone(),
        state.inner().clone(),
        domain,
        body.active,
    )
    .await?;
    let mut s = spy::status(pool, config, state).await?;
    s.running = true;
    Ok(Json(s))
}

#[delete("/spy/reports/<domain>")]
async fn remove(_admin: AdminUser, domain: &str, pool: &State<SqlitePool>) -> AppResult<Status> {
    spy::delete_report(pool, domain).await?;
    Ok(Status::NoContent)
}

#[get("/spy/report?<domain>&<at>")]
async fn report(
    _user: CurrentUser,
    domain: &str,
    at: i64,
    pool: &State<SqlitePool>,
) -> AppResult<Json<SpyReport>> {
    Ok(Json(spy::report_at(pool, domain, at).await?))
}

#[put("/spy/settings", data = "<body>")]
async fn save_settings(
    admin: AdminUser,
    body: Json<SpySettings>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    state: &State<SpyState>,
) -> AppResult<Json<SpyStatus>> {
    spy::save_settings(pool, &body).await?;
    tracing::info!(by = %admin.0.username, "Spy-Zeitplan geändert");
    Ok(Json(spy::status(pool, config, state).await?))
}
