//! Zonen und Einträge, Import und Export von Zonendateien. Nach jeder Änderung bekommt die
//! Engine den neuen Bestand.

use super::Download;
use crate::auth::{AdminUser, CurrentUser};
use crate::error::AppResult;
use crate::services::{sync, zones};
use nrzdns_engine::Engine;
use nrzdns_types::{
    RecordInput, UpdateZoneInput, Zone, ZoneDetail, ZoneImportInput, ZoneImportResult, ZoneInput,
    ZoneRecord,
};
use rocket::http::{ContentType, Status};
use rocket::serde::json::Json;
use rocket::{delete, get, post, put, routes, Route, State};
use sqlx::SqlitePool;

pub fn routes() -> Vec<Route> {
    routes![
        list,
        create,
        import,
        detail,
        update,
        remove,
        export,
        add_record,
        update_record,
        delete_record
    ]
}

#[get("/zones")]
async fn list(_user: CurrentUser, pool: &State<SqlitePool>) -> AppResult<Json<Vec<Zone>>> {
    Ok(Json(zones::list(pool).await?))
}

/// Primärzone (mit SOA und NS bei `@`) oder bedingte Weiterleitung.
#[post("/zones", data = "<body>")]
async fn create(
    admin: AdminUser,
    body: Json<ZoneInput>,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
) -> AppResult<(Status, Json<Zone>)> {
    let zone = zones::create(pool, &engine.settings(), &body).await?;
    sync::push_zones(pool, engine).await?;
    tracing::info!(zone = %zone.name, by = %admin.0.username, "Zone angelegt");
    Ok((Status::Created, Json(zone)))
}

/// Zonendatei im BIND-Format übernehmen.
#[post("/zones/import", data = "<body>")]
async fn import(
    admin: AdminUser,
    body: Json<ZoneImportInput>,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
) -> AppResult<Json<ZoneImportResult>> {
    let result = zones::import(pool, &engine.settings(), &body).await?;
    sync::push_zones(pool, engine).await?;
    tracing::info!(
        zone = %result.zone.name,
        imported = result.imported,
        skipped = result.skipped.len(),
        by = %admin.0.username,
        "Zone importiert"
    );
    Ok(Json(result))
}

#[get("/zones/<id>")]
async fn detail(
    _user: CurrentUser,
    id: i64,
    pool: &State<SqlitePool>,
) -> AppResult<Json<ZoneDetail>> {
    Ok(Json(zones::detail(pool, id).await?))
}

#[put("/zones/<id>", data = "<body>")]
async fn update(
    _admin: AdminUser,
    id: i64,
    body: Json<UpdateZoneInput>,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
) -> AppResult<Json<Zone>> {
    let zone = zones::update(pool, id, &body).await?;
    sync::push_zones(pool, engine).await?;
    Ok(Json(zone))
}

#[delete("/zones/<id>")]
async fn remove(
    admin: AdminUser,
    id: i64,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
) -> AppResult<Status> {
    let zone = zones::get(pool, id).await?;
    zones::delete(pool, id).await?;
    sync::push_zones(pool, engine).await?;
    tracing::info!(zone = %zone.name, by = %admin.0.username, "Zone gelöscht");
    Ok(Status::NoContent)
}

/// Zonendatei zum Herunterladen (`<zone>.zone`).
#[get("/zones/<id>/export")]
async fn export(_user: CurrentUser, id: i64, pool: &State<SqlitePool>) -> AppResult<Download> {
    let (filename, body) = zones::export(pool, id).await?;
    Ok(Download {
        filename,
        content_type: ContentType::new("text", "plain").with_params(("charset", "utf-8")),
        body,
    })
}

#[post("/zones/<id>/records", data = "<body>")]
async fn add_record(
    _admin: AdminUser,
    id: i64,
    body: Json<RecordInput>,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
) -> AppResult<(Status, Json<ZoneRecord>)> {
    let record = zones::add_record(pool, &engine.settings(), id, &body).await?;
    sync::push_zones(pool, engine).await?;
    Ok((Status::Created, Json(record)))
}

#[put("/zones/<id>/records/<rid>", data = "<body>")]
async fn update_record(
    _admin: AdminUser,
    id: i64,
    rid: i64,
    body: Json<RecordInput>,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
) -> AppResult<Json<ZoneRecord>> {
    let record = zones::update_record(pool, &engine.settings(), id, rid, &body).await?;
    sync::push_zones(pool, engine).await?;
    Ok(Json(record))
}

#[delete("/zones/<id>/records/<rid>")]
async fn delete_record(
    _admin: AdminUser,
    id: i64,
    rid: i64,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
) -> AppResult<Status> {
    zones::delete_record(pool, id, rid).await?;
    sync::push_zones(pool, engine).await?;
    Ok(Status::NoContent)
}
