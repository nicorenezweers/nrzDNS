//! DNS-Einstellungen, Vorlagen, Zustand des Servers und Dashboard.

use crate::auth::{AdminUser, CurrentUser};
use crate::error::{AppError, AppResult};
use crate::services::blocking::Updater;
use crate::services::{dashboard, settings};
use nrzdns_engine::Engine;
use nrzdns_types::{Dashboard, DnsSettings, Presets, ServerStatus, StatsRange};
use rocket::serde::json::Json;
use rocket::{get, put, routes, Route, State};
use sqlx::SqlitePool;

pub fn routes() -> Vec<Route> {
    routes![get_dns, put_dns, presets, server, get_dashboard]
}

#[get("/settings/dns")]
async fn get_dns(_user: CurrentUser, pool: &State<SqlitePool>) -> AppResult<Json<DnsSettings>> {
    Ok(Json(settings::dns(pool).await?))
}

/// Speichern und sofort aktiv (ohne Neustart). Zahlen ausserhalb ihres Bereichs werden auf
/// die Grenze gesetzt; die Antwort zeigt, was gilt.
#[put("/settings/dns", data = "<body>")]
async fn put_dns(
    admin: AdminUser,
    body: Json<DnsSettings>,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
    updater: &State<Updater>,
) -> AppResult<Json<DnsSettings>> {
    let before = engine.settings();
    let saved = settings::save_dns(pool, &body).await?;
    engine.apply_settings(saved.clone());
    if before.blocklist_update_hours != saved.blocklist_update_hours {
        updater.wake();
    }
    tracing::info!(by = %admin.0.username, "DNS-Einstellungen geändert");
    Ok(Json(saved))
}

/// Weiterleitungen und Sperrlisten zum Übernehmen.
#[get("/presets")]
fn presets(_user: CurrentUser) -> Json<Presets> {
    Json(Presets::builtin())
}

#[get("/server")]
fn server(_user: CurrentUser, engine: &State<Engine>) -> Json<ServerStatus> {
    Json(engine.status())
}

/// `range` = `hour`, `day` (Vorgabe), `week` oder `month`.
#[get("/dashboard?<range>")]
async fn get_dashboard(
    _user: CurrentUser,
    range: Option<&str>,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
) -> AppResult<Json<Dashboard>> {
    let range = match range.map(str::trim).filter(|r| !r.is_empty()) {
        None => StatsRange::Day,
        Some(r) => StatsRange::parse(r).ok_or_else(|| AppError::bad("Unbekannter Zeitraum."))?,
    };
    Ok(Json(dashboard::build(pool, engine, range).await?))
}
