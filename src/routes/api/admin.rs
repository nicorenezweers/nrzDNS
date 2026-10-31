//! Verwaltung (nur Administratoren): Benutzerkonten und Einstellungen der Instanz.

use crate::auth::AdminUser;
use crate::config::Config;
use crate::error::AppResult;
use crate::services::{settings, users};
use nrzdns_types::{CreateUserInput, InstanceSettings, UpdateUserInput, User};
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{delete, get, post, put, routes, Route, State};
use sqlx::SqlitePool;

pub fn routes() -> Vec<Route> {
    routes![
        list_users,
        create_user,
        update_user,
        delete_user,
        get_instance,
        put_instance
    ]
}

// ------------------------------------------------------------------ Benutzer

#[get("/admin/users")]
async fn list_users(_admin: AdminUser, pool: &State<SqlitePool>) -> AppResult<Json<Vec<User>>> {
    Ok(Json(users::list(pool).await?))
}

#[post("/admin/users", data = "<body>")]
async fn create_user(
    admin: AdminUser,
    body: Json<CreateUserInput>,
    pool: &State<SqlitePool>,
) -> AppResult<(Status, Json<User>)> {
    let user = users::create(
        pool,
        &body.username,
        &body.password,
        &body.display_name,
        body.role,
    )
    .await?;
    tracing::info!(user = %user.username, by = %admin.0.username, "Konto angelegt");
    Ok((Status::Created, Json(user)))
}

/// Name, Rolle, Sperre oder neues Passwort (beendet die Sitzungen des Kontos).
#[put("/admin/users/<id>", data = "<body>")]
async fn update_user(
    admin: AdminUser,
    id: i64,
    body: Json<UpdateUserInput>,
    pool: &State<SqlitePool>,
) -> AppResult<Json<User>> {
    Ok(Json(users::update(pool, &admin.0, id, &body).await?))
}

/// Konto mit seinen Sitzungen löschen.
#[delete("/admin/users/<id>")]
async fn delete_user(admin: AdminUser, id: i64, pool: &State<SqlitePool>) -> AppResult<Status> {
    users::delete(pool, &admin.0, id).await?;
    Ok(Status::NoContent)
}

// ------------------------------------------------------------------ Instanz

#[get("/settings/instance")]
async fn get_instance(
    _admin: AdminUser,
    pool: &State<SqlitePool>,
    config: &State<Config>,
) -> AppResult<Json<InstanceSettings>> {
    Ok(Json(settings::instance(pool, config).await?))
}

/// Registrierung offen oder geschlossen.
#[put("/settings/instance", data = "<body>")]
async fn put_instance(
    admin: AdminUser,
    body: Json<InstanceSettings>,
    pool: &State<SqlitePool>,
) -> AppResult<Json<InstanceSettings>> {
    settings::set(pool, settings::INSTANCE, &body.0).await?;
    tracing::info!(by = %admin.0.username, "Einstellungen der Instanz geändert");
    Ok(body)
}
