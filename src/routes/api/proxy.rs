//! Reverse Proxy: Einträge `Name → HTTP-Ziel` und die Adresse für die DNS-Antworten.
//! Jede Änderung gilt sofort (Proxy und DNS), ohne Neustart.

use crate::auth::{AdminUser, CurrentUser};
use crate::config::Config;
use crate::error::AppResult;
use crate::proxy::ProxyState;
use crate::services::{proxy, sync};
use nrzdns_engine::Engine;
use nrzdns_types::{ProxyHost, ProxyHostInput, ProxySettings, ProxyStatus};
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{delete, get, post, put, routes, Route, State};
use sqlx::SqlitePool;

pub fn routes() -> Vec<Route> {
    routes![status, save_settings, create, update, remove]
}

async fn build_status(
    pool: &SqlitePool,
    config: &Config,
    state: &ProxyState,
) -> AppResult<ProxyStatus> {
    Ok(ProxyStatus {
        listen: config
            .proxy_listen
            .iter()
            .map(ToString::to_string)
            .collect(),
        port: config.proxy_listen.first().map_or(0, |a| a.port()),
        listen_errors: state.listen_errors(),
        settings: proxy::settings(pool).await?,
        hosts: proxy::list(pool).await?,
    })
}

#[get("/proxy")]
async fn status(
    _user: CurrentUser,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    state: &State<ProxyState>,
) -> AppResult<Json<ProxyStatus>> {
    Ok(Json(build_status(pool, config, state).await?))
}

#[put("/proxy/settings", data = "<body>")]
async fn save_settings(
    _admin: AdminUser,
    body: Json<ProxySettings>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    engine: &State<Engine>,
    state: &State<ProxyState>,
) -> AppResult<Json<ProxyStatus>> {
    proxy::save_settings(pool, &body).await?;
    sync::push_proxy(pool, engine, state).await?;
    Ok(Json(build_status(pool, config, state).await?))
}

#[post("/proxy/hosts", data = "<body>")]
async fn create(
    admin: AdminUser,
    body: Json<ProxyHostInput>,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
    state: &State<ProxyState>,
) -> AppResult<(Status, Json<ProxyHost>)> {
    let host = proxy::create(pool, &body).await?;
    sync::push_proxy(pool, engine, state).await?;
    tracing::info!(host = %host.host, target = %host.target, by = %admin.0.username, "Proxy-Eintrag angelegt");
    Ok((Status::Created, Json(host)))
}

#[put("/proxy/hosts/<id>", data = "<body>")]
async fn update(
    _admin: AdminUser,
    id: i64,
    body: Json<ProxyHostInput>,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
    state: &State<ProxyState>,
) -> AppResult<Json<ProxyHost>> {
    let host = proxy::update(pool, id, &body).await?;
    sync::push_proxy(pool, engine, state).await?;
    Ok(Json(host))
}

#[delete("/proxy/hosts/<id>")]
async fn remove(
    _admin: AdminUser,
    id: i64,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
    state: &State<ProxyState>,
) -> AppResult<Status> {
    proxy::delete(pool, id).await?;
    sync::push_proxy(pool, engine, state).await?;
    Ok(Status::NoContent)
}
