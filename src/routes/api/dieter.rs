//! Dieter (KI-Assistent): Einstellungen, Gespräche, Überwachung, Claude CLI.

use crate::auth::{AdminUser, CurrentUser};
use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::proxy::ProxyState;
use crate::services::components::Components;
use crate::services::dieter::{self, Ctx, DieterState};
use nrzdns_engine::Engine;
use nrzdns_types::{DieterSendInput, DieterSettingsInput, DieterStatus, DieterThread};
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{delete, get, post, put, routes, Route, State};
use sqlx::SqlitePool;

pub fn routes() -> Vec<Route> {
    routes![status, save, create, get_thread, send, remove, watch, install]
}

fn ctx(
    pool: &SqlitePool,
    config: &Config,
    engine: &Engine,
    state: &DieterState,
    comps: &Components,
    proxy: &ProxyState,
) -> Ctx {
    Ctx {
        pool: pool.clone(),
        config: config.clone(),
        engine: engine.clone(),
        state: state.clone(),
        components: comps.clone(),
        proxy: proxy.clone(),
    }
}

fn not_dieter(user: &AdminUser) -> AppResult<()> {
    if user.0.id == 0 {
        return Err(AppError::forbidden(
            "Dieter darf sich nicht selbst steuern.",
        ));
    }
    Ok(())
}

#[get("/dieter")]
async fn status(
    _u: CurrentUser,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    state: &State<DieterState>,
) -> AppResult<Json<DieterStatus>> {
    Ok(Json(dieter::status(pool, config, state).await?))
}

#[put("/dieter/settings", data = "<body>")]
async fn save(
    a: AdminUser,
    body: Json<DieterSettingsInput>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    state: &State<DieterState>,
) -> AppResult<Json<DieterStatus>> {
    not_dieter(&a)?;
    dieter::save(pool, &body).await?;
    tracing::info!(by = %a.0.username, "Dieter-Einstellungen geändert");
    Ok(Json(dieter::status(pool, config, state).await?))
}

#[allow(clippy::too_many_arguments)]
#[post("/dieter/conversations", data = "<body>")]
async fn create(
    a: AdminUser,
    body: Json<DieterSendInput>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    engine: &State<Engine>,
    state: &State<DieterState>,
    comps: &State<Components>,
    proxy: &State<ProxyState>,
) -> AppResult<Json<DieterThread>> {
    not_dieter(&a)?;
    let title: String = body
        .text
        .lines()
        .next()
        .unwrap_or_default()
        .chars()
        .take(60)
        .collect();
    let id = dieter::create_conversation(pool, &title, false).await?;
    if let Err(e) = dieter::send_with_context(&ctx(pool, config, engine, state, comps, proxy), id, &body.text, &body.context)
    .await
    {
        dieter::delete_conversation(pool, id).await.ok();
        return Err(e);
    }
    Ok(Json(dieter::thread(pool, state, id).await?))
}

#[get("/dieter/conversations/<id>")]
async fn get_thread(
    _u: CurrentUser,
    id: i64,
    pool: &State<SqlitePool>,
    state: &State<DieterState>,
) -> AppResult<Json<DieterThread>> {
    Ok(Json(dieter::thread(pool, state, id).await?))
}

#[allow(clippy::too_many_arguments)]
#[post("/dieter/conversations/<id>/messages", data = "<body>")]
async fn send(
    a: AdminUser,
    id: i64,
    body: Json<DieterSendInput>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    engine: &State<Engine>,
    state: &State<DieterState>,
    comps: &State<Components>,
    proxy: &State<ProxyState>,
) -> AppResult<Json<DieterThread>> {
    not_dieter(&a)?;
    dieter::thread(pool, state, id).await?;
    dieter::send_with_context(&ctx(pool, config, engine, state, comps, proxy), id, &body.text, &body.context)
    .await?;
    Ok(Json(dieter::thread(pool, state, id).await?))
}

#[delete("/dieter/conversations/<id>")]
async fn remove(a: AdminUser, id: i64, pool: &State<SqlitePool>) -> AppResult<Status> {
    not_dieter(&a)?;
    dieter::delete_conversation(pool, id).await?;
    Ok(Status::NoContent)
}

#[allow(clippy::too_many_arguments)]
#[post("/dieter/watch")]
async fn watch(
    a: AdminUser,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    engine: &State<Engine>,
    state: &State<DieterState>,
    comps: &State<Components>,
    proxy: &State<ProxyState>,
) -> AppResult<Json<DieterStatus>> {
    not_dieter(&a)?;
    dieter::watch_once(&ctx(pool, config, engine, state, comps, proxy)).await?;
    Ok(Json(dieter::status(pool, config, state).await?))
}

#[post("/dieter/claude/install")]
async fn install(
    a: AdminUser,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    state: &State<DieterState>,
) -> AppResult<Json<DieterStatus>> {
    not_dieter(&a)?;
    let r = dieter::install_claude(config).await?;
    tracing::info!(by = %a.0.username, "{r}");
    Ok(Json(dieter::status(pool, config, state).await?))
}
