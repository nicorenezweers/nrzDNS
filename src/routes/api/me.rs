//! Eigenes Konto: Daten und persönliche Einstellungen, Passwort ändern.

use crate::auth::{session, CurrentUser};
use crate::error::AppResult;
use crate::services::users;
use nrzdns_types::{
    ChangePasswordInput, TwoFactorCodes, TwoFactorInput, TwoFactorSetup, TwoFactorStatus,
    UpdateMeInput, User,
};
use rocket::http::{CookieJar, Status};
use rocket::serde::json::Json;
use rocket::{get, post, put, routes, Route, State};
use sqlx::SqlitePool;

pub fn routes() -> Vec<Route> {
    routes![
        me,
        update_me,
        change_password,
        tf_status,
        tf_setup,
        tf_enable,
        tf_disable,
        tf_recovery
    ]
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

// ------------------------------------------------------------------ Zwei-Faktor-Anmeldung

fn not_internal(user: &CurrentUser) -> AppResult<()> {
    if user.id() == 0 {
        return Err(crate::error::AppError::forbidden("Nicht für Dieter."));
    }
    Ok(())
}

#[get("/me/2fa")]
async fn tf_status(
    user: CurrentUser,
    pool: &State<SqlitePool>,
) -> AppResult<Json<TwoFactorStatus>> {
    not_internal(&user)?;
    Ok(Json(users::two_factor_status(pool, user.id()).await?))
}

#[post("/me/2fa/setup")]
async fn tf_setup(user: CurrentUser, pool: &State<SqlitePool>) -> AppResult<Json<TwoFactorSetup>> {
    not_internal(&user)?;
    Ok(Json(users::setup_two_factor(pool, &user.0).await?))
}

#[post("/me/2fa/enable", data = "<body>")]
async fn tf_enable(
    user: CurrentUser,
    body: Json<TwoFactorInput>,
    pool: &State<SqlitePool>,
) -> AppResult<Json<TwoFactorCodes>> {
    not_internal(&user)?;
    Ok(Json(
        users::enable_two_factor(pool, user.id(), &body.code).await?,
    ))
}

#[post("/me/2fa/disable", data = "<body>")]
async fn tf_disable(
    user: CurrentUser,
    body: Json<TwoFactorInput>,
    pool: &State<SqlitePool>,
) -> AppResult<Status> {
    not_internal(&user)?;
    users::disable_two_factor(pool, user.id(), &body.password, &body.code).await?;
    Ok(Status::NoContent)
}

#[post("/me/2fa/recovery", data = "<body>")]
async fn tf_recovery(
    user: CurrentUser,
    body: Json<TwoFactorInput>,
    pool: &State<SqlitePool>,
) -> AppResult<Json<TwoFactorCodes>> {
    not_internal(&user)?;
    Ok(Json(
        users::regenerate_recovery(pool, user.id(), &body.password, &body.code).await?,
    ))
}
