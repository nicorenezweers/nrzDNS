//! Sperrseite: auf Zeit freigeschaltete Domains und Anträge auf dauerhafte Ausnahmen.
//! Lesen darf jeder Angemeldete, entscheiden nur Admins.

use crate::auth::{AdminUser, CurrentUser};
use crate::error::AppResult;
use crate::services::domains::Kind;
use crate::services::{sync, unlocks};
use nrzdns_engine::Engine;
use nrzdns_types::{AllowRequest, TempUnlock};
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{delete, get, post, routes, Route, State};
use sqlx::SqlitePool;

pub fn routes() -> Vec<Route> {
    routes![
        list_unlocks,
        end_unlock,
        list_requests,
        approve,
        reject,
        remove
    ]
}

#[get("/unlocks")]
async fn list_unlocks(
    _user: CurrentUser,
    pool: &State<SqlitePool>,
) -> AppResult<Json<Vec<TempUnlock>>> {
    Ok(Json(unlocks::active(pool).await?))
}

#[delete("/unlocks/<domain>")]
async fn end_unlock(
    _admin: AdminUser,
    domain: &str,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
) -> AppResult<Status> {
    unlocks::end(pool, domain).await?;
    sync::push_domains(pool, engine, Kind::Allowed).await?;
    engine.cache_remove(domain);
    Ok(Status::NoContent)
}

#[get("/requests")]
async fn list_requests(
    _user: CurrentUser,
    pool: &State<SqlitePool>,
) -> AppResult<Json<Vec<AllowRequest>>> {
    Ok(Json(unlocks::requests(pool).await?))
}

#[post("/requests/<id>/approve")]
async fn approve(
    admin: AdminUser,
    id: i64,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
) -> AppResult<Json<AllowRequest>> {
    let r = unlocks::approve(pool, id, &admin.0.username).await?;
    sync::push_domains(pool, engine, Kind::Allowed).await?;
    engine.cache_remove(&r.domain);
    tracing::info!(domain = %r.domain, by = %admin.0.username, "Antrag genehmigt");
    Ok(Json(r))
}

#[post("/requests/<id>/reject")]
async fn reject(
    admin: AdminUser,
    id: i64,
    pool: &State<SqlitePool>,
) -> AppResult<Json<AllowRequest>> {
    Ok(Json(unlocks::reject(pool, id, &admin.0.username).await?))
}

#[delete("/requests/<id>")]
async fn remove(_admin: AdminUser, id: i64, pool: &State<SqlitePool>) -> AppResult<Status> {
    unlocks::delete_request(pool, id).await?;
    Ok(Status::NoContent)
}
