//! Eigenes Konto: Daten und persönliche Einstellungen, Passwort ändern.

use crate::auth::{session, CurrentUser};
use crate::error::AppResult;
use crate::services::users;
use nrzdns_types::{ChangePasswordInput, UpdateMeInput, User};
use rocket::http::{CookieJar, Status};
use rocket::serde::json::Json;
use rocket::{get, put, routes, Route, State};
use sqlx::SqlitePool;

pub fn routes() -> Vec<Route> {
    routes![me, update_me, change_password]
}

#[get("/me")]
fn me(user: CurrentUser) -> Json<User> {
    Json(user.0)
}

/// Anzeigename und Einstellungen (Sprache, Dashboard, Protokoll); nur gesetzte Felder.
#[put("/me", data = "<body>")]
async fn update_me(
    user: CurrentUser,
    body: Json<UpdateMeInput>,
    pool: &State<SqlitePool>,
) -> AppResult<Json<User>> {
    Ok(Json(users::update_me(pool, user.id(), &body).await?))
}

/// Passwort ändern (bisheriges nötig). Alle anderen Sitzungen enden – wer das Passwort
/// eines gestohlenen Geräts ändert, wirft es damit hinaus; dieses Gerät bleibt angemeldet.
#[put("/me/password", data = "<body>")]
async fn change_password(
    user: CurrentUser,
    body: Json<ChangePasswordInput>,
    cookies: &CookieJar<'_>,
    pool: &State<SqlitePool>,
) -> AppResult<Status> {
    users::change_password(pool, user.id(), &body.current, &body.new).await?;
    match session::token_from(cookies) {
        Some(token) => session::destroy_others(pool, user.id(), &token).await?,
        None => session::destroy_all(pool, user.id()).await?,
    };
    tracing::info!(user = %user.0.username, "Passwort geändert");
    Ok(Status::NoContent)
}
