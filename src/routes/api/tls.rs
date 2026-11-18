//! HTTPS für eigene Domains (Let's Encrypt über Cloudflare). Lesen darf jeder Angemeldete
//! (ohne Token), ändern und Zertifikate holen nur Admins.

use crate::auth::{AdminUser, CurrentUser};
use crate::config::Config;
use crate::error::AppResult;
use crate::proxy::ProxyState;
use crate::services::tls;
use nrzdns_engine::Engine;
use nrzdns_types::{TlsSettingsInput, TlsStatus};
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{delete, get, post, put, routes, Route, State};
use sqlx::SqlitePool;

pub fn routes() -> Vec<Route> {
    routes![status, save, issue, remove]
}

#[get("/tls")]
async fn status(
    _user: CurrentUser,
    pool: &State<SqlitePool>,
    state: &State<ProxyState>,
    config: &State<Config>,
) -> AppResult<Json<TlsStatus>> {
    Ok(Json(tls::status(pool, state, config).await?))
}

#[put("/tls", data = "<body>")]
async fn save(
    _admin: AdminUser,
    body: Json<TlsSettingsInput>,
    pool: &State<SqlitePool>,
    state: &State<ProxyState>,
    config: &State<Config>,
) -> AppResult<Json<TlsStatus>> {
    tls::save(pool, state, &config.data_dir, &body).await?;
    Ok(Json(tls::status(pool, state, config).await?))
}

/// Startet im Hintergrund (dauert 30 s bis 3 Min.); den Fortschritt liefert `GET /tls`.
#[post("/tls/issue")]
async fn issue(
    admin: AdminUser,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
    state: &State<ProxyState>,
    config: &State<Config>,
) -> AppResult<Json<TlsStatus>> {
    let s = tls::status(pool, state, config).await?;
    if s.issuing {
        return Err(crate::error::AppError::Conflict(
            "Es wird schon ein Zertifikat geholt.".into(),
        ));
    }
    if !s.token_set {
        return Err(crate::error::AppError::bad(
            "Bitte zuerst ein Cloudflare-API-Token speichern.",
        ));
    }
    if s.settings.domains.is_empty() {
        return Err(crate::error::AppError::bad(
            "Bitte zuerst die Namen speichern, z. B. *.zweers.ch.",
        ));
    }
    tracing::info!(by = %admin.0.username, "HTTPS: Zertifikat angefordert");
    let (pool2, engine2, state2, config2) = (
        pool.inner().clone(),
        engine.inner().clone(),
        state.inner().clone(),
        config.inner().clone(),
    );
    tokio::spawn(async move {
        let _ = tls::issue(&pool2, &engine2, &state2, &config2).await;
    });
    let mut s = tls::status(pool, state, config).await?;
    s.issuing = true;
    Ok(Json(s))
}

#[delete("/tls/certificate")]
async fn remove(
    _admin: AdminUser,
    pool: &State<SqlitePool>,
    state: &State<ProxyState>,
    config: &State<Config>,
) -> AppResult<Status> {
    tls::remove_certificate(state, &config.data_dir, pool).await?;
    Ok(Status::NoContent)
}
