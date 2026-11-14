//! Verbindungen zu Cloudflare und NetBird: Tokens speichern/prüfen und die beiden APIs
//! durchreichen (nur freigegebene Pfade, siehe `services::integrations`). Lesen darf jeder
//! Angemeldete, ändern nur Admins.

use crate::auth::{AdminUser, CurrentUser};
use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::services::integrations::{self, error_message, Upstream, MAX_BODY};
use nrzdns_types::{IntegrationsInput, IntegrationsStatus};
use reqwest::Method;
use rocket::data::{Data, ToByteUnit};
use rocket::http::uri::Origin;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{delete, get, patch, post, put, routes, Route, State};
use serde_json::Value;
use sqlx::SqlitePool;
use std::path::PathBuf;

pub fn routes() -> Vec<Route> {
    routes![
        status, save, cf_get, cf_post, cf_put, cf_patch, cf_delete, nb_get, nb_post, nb_put,
        nb_delete
    ]
}

#[get("/integrations?<test>")]
async fn status(
    _user: CurrentUser,
    test: Option<bool>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
) -> AppResult<Json<IntegrationsStatus>> {
    Ok(Json(
        integrations::status(pool, config, test.unwrap_or(false)).await?,
    ))
}

#[put("/integrations", data = "<body>")]
async fn save(
    admin: AdminUser,
    body: Json<IntegrationsInput>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
) -> AppResult<Json<IntegrationsStatus>> {
    integrations::save(pool, &body).await?;
    tracing::info!(by = %admin.0.username, "Verbindungen geändert");
    Ok(Json(integrations::status(pool, config, true).await?))
}

fn segments(path: &std::path::Path) -> AppResult<Vec<String>> {
    path.iter()
        .map(|s| s.to_str().map(str::to_string).ok_or(AppError::NotFound))
        .collect()
}

async fn body(data: Data<'_>) -> AppResult<Option<Value>> {
    let raw = data
        .open(MAX_BODY.bytes())
        .into_bytes()
        .await
        .map_err(|e| AppError::bad(e.to_string()))?;
    if !raw.is_complete() {
        return Err(AppError::bad("Anfrage zu gross."));
    }
    if raw.is_empty() {
        return Ok(None);
    }
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|e| AppError::bad(format!("Ungültiges JSON: {e}")))
}

/// Antwort weitergeben: Erfolg unverändert, Fehler als verständliche Meldung.
fn reply(service: &str, up: Upstream) -> AppResult<(Status, Json<Value>)> {
    if (200..300).contains(&up.status) {
        let status = Status::from_code(up.status).unwrap_or(Status::Ok);
        return Ok((status, Json(up.body)));
    }
    let msg = error_message(service, &up);
    Err(match up.status {
        404 => AppError::bad(msg),
        401 | 403 | 400 | 409 | 412 | 422 => AppError::bad(msg),
        _ => AppError::BadGateway(msg),
    })
}

async fn cf(
    pool: &SqlitePool,
    config: &Config,
    method: Method,
    path: PathBuf,
    origin: &Origin<'_>,
    data: Option<Data<'_>>,
    who: Option<&str>,
) -> AppResult<(Status, Json<Value>)> {
    let segs = segments(&path)?;
    let refs: Vec<&str> = segs.iter().map(String::as_str).collect();
    let b = match data {
        Some(d) => body(d).await?,
        None => None,
    };
    if let Some(who) = who {
        tracing::info!(by = %who, method = %method, path = %segs.join("/"), "Cloudflare geändert");
    }
    let q = origin.query().map(|q| q.as_str().to_string());
    let up = integrations::cloudflare(pool, config, method, &refs, q.as_deref(), b).await?;
    reply("Cloudflare", up)
}

async fn nb(
    pool: &SqlitePool,
    method: Method,
    path: PathBuf,
    origin: &Origin<'_>,
    data: Option<Data<'_>>,
    who: Option<&str>,
) -> AppResult<(Status, Json<Value>)> {
    let segs = segments(&path)?;
    let refs: Vec<&str> = segs.iter().map(String::as_str).collect();
    let b = match data {
        Some(d) => body(d).await?,
        None => None,
    };
    if let Some(who) = who {
        tracing::info!(by = %who, method = %method, path = %segs.join("/"), "NetBird geändert");
    }
    let q = origin.query().map(|q| q.as_str().to_string());
    let up = integrations::netbird(pool, method, &refs, q.as_deref(), b).await?;
    reply("NetBird", up)
}

#[get("/cloudflare/<path..>", rank = 2)]
async fn cf_get(
    _u: CurrentUser,
    path: PathBuf,
    origin: &Origin<'_>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
) -> AppResult<(Status, Json<Value>)> {
    cf(pool, config, Method::GET, path, origin, None, None).await
}
#[post("/cloudflare/<path..>", data = "<data>", rank = 2)]
async fn cf_post(
    a: AdminUser,
    path: PathBuf,
    origin: &Origin<'_>,
    data: Data<'_>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
) -> AppResult<(Status, Json<Value>)> {
    cf(
        pool,
        config,
        Method::POST,
        path,
        origin,
        Some(data),
        Some(&a.0.username),
    )
    .await
}
#[put("/cloudflare/<path..>", data = "<data>", rank = 2)]
async fn cf_put(
    a: AdminUser,
    path: PathBuf,
    origin: &Origin<'_>,
    data: Data<'_>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
) -> AppResult<(Status, Json<Value>)> {
    cf(
        pool,
        config,
        Method::PUT,
        path,
        origin,
        Some(data),
        Some(&a.0.username),
    )
    .await
}
#[patch("/cloudflare/<path..>", data = "<data>", rank = 2)]
async fn cf_patch(
    a: AdminUser,
    path: PathBuf,
    origin: &Origin<'_>,
    data: Data<'_>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
) -> AppResult<(Status, Json<Value>)> {
    cf(
        pool,
        config,
        Method::PATCH,
        path,
        origin,
        Some(data),
        Some(&a.0.username),
    )
    .await
}
#[delete("/cloudflare/<path..>", rank = 2)]
async fn cf_delete(
    a: AdminUser,
    path: PathBuf,
    origin: &Origin<'_>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
) -> AppResult<(Status, Json<Value>)> {
    cf(
        pool,
        config,
        Method::DELETE,
        path,
        origin,
        None,
        Some(&a.0.username),
    )
    .await
}

#[get("/netbird/<path..>", rank = 2)]
async fn nb_get(
    _u: CurrentUser,
    path: PathBuf,
    origin: &Origin<'_>,
    pool: &State<SqlitePool>,
) -> AppResult<(Status, Json<Value>)> {
    nb(pool, Method::GET, path, origin, None, None).await
}
#[post("/netbird/<path..>", data = "<data>", rank = 2)]
async fn nb_post(
    a: AdminUser,
    path: PathBuf,
    origin: &Origin<'_>,
    data: Data<'_>,
    pool: &State<SqlitePool>,
) -> AppResult<(Status, Json<Value>)> {
    nb(
        pool,
        Method::POST,
        path,
        origin,
        Some(data),
        Some(&a.0.username),
    )
    .await
}
#[put("/netbird/<path..>", data = "<data>", rank = 2)]
async fn nb_put(
    a: AdminUser,
    path: PathBuf,
    origin: &Origin<'_>,
    data: Data<'_>,
    pool: &State<SqlitePool>,
) -> AppResult<(Status, Json<Value>)> {
    nb(
        pool,
        Method::PUT,
        path,
        origin,
        Some(data),
        Some(&a.0.username),
    )
    .await
}
#[delete("/netbird/<path..>", rank = 2)]
async fn nb_delete(
    a: AdminUser,
    path: PathBuf,
    origin: &Origin<'_>,
    pool: &State<SqlitePool>,
) -> AppResult<(Status, Json<Value>)> {
    nb(
        pool,
        Method::DELETE,
        path,
        origin,
        None,
        Some(&a.0.username),
    )
    .await
}
