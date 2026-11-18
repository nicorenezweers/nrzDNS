//! Komponenten, die nrzNetwork selbst betreibt (Cloudflare Tunnel, NetBird), und ihre Updates.

use crate::auth::{AdminUser, CurrentUser};
use crate::config::Config;
use crate::error::AppResult;
use crate::services::components::{self, Components};
use nrzdns_types::{ComponentsInput, ComponentsStatus};
use rocket::serde::json::Json;
use rocket::{delete, get, post, put, routes, Route, State};
use sqlx::SqlitePool;

pub fn routes() -> Vec<Route> {
    routes![status, save, check, tunnel, netbird_key, clear]
}

#[get("/components")]
async fn status(
    _user: CurrentUser,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    comps: &State<Components>,
) -> AppResult<Json<ComponentsStatus>> {
    Ok(Json(components::status(pool, config, comps).await?))
}

#[put("/components", data = "<body>")]
async fn save(
    admin: AdminUser,
    body: Json<ComponentsInput>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    comps: &State<Components>,
) -> AppResult<Json<ComponentsStatus>> {
    components::save(pool, config, comps, &body).await?;
    tracing::info!(by = %admin.0.username, "Komponenten geändert");
    Ok(Json(components::status(pool, config, comps).await?))
}

/// Startet im Hintergrund (Downloads dauern); Ergebnis über `GET /components`.
#[post("/components/check")]
async fn check(
    _admin: AdminUser,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    comps: &State<Components>,
) -> AppResult<Json<ComponentsStatus>> {
    let (p, c, k) = (
        pool.inner().clone(),
        config.inner().clone(),
        comps.inner().clone(),
    );
    tokio::spawn(async move {
        let _ = components::check_updates(&p, &c, &k).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut s = components::status(pool, config, comps).await?;
    s.checking = true;
    Ok(Json(s))
}

#[post("/components/tunnel")]
async fn tunnel(
    admin: AdminUser,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    comps: &State<Components>,
) -> AppResult<Json<ComponentsStatus>> {
    components::create_tunnel(pool, config, comps).await?;
    tracing::info!(by = %admin.0.username, "Cloudflare Tunnel angelegt");
    Ok(Json(components::status(pool, config, comps).await?))
}

#[post("/components/netbird-key")]
async fn netbird_key(
    admin: AdminUser,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    comps: &State<Components>,
) -> AppResult<Json<ComponentsStatus>> {
    components::create_netbird_key(pool, config, comps).await?;
    tracing::info!(by = %admin.0.username, "NetBird-Setup-Key erzeugt");
    Ok(Json(components::status(pool, config, comps).await?))
}

#[delete("/components/<which>")]
async fn clear(
    _admin: AdminUser,
    which: &str,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    comps: &State<Components>,
) -> AppResult<Json<ComponentsStatus>> {
    components::clear_secret(pool, config, comps, which).await?;
    Ok(Json(components::status(pool, config, comps).await?))
}
