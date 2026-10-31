//! Cache der Engine ansehen und leeren, DNS-Client der Oberfläche.

use crate::auth::{AdminUser, CurrentUser};
use crate::error::{AppError, AppResult};
use crate::services::domains;
use nrzdns_engine::Engine;
use nrzdns_types::{CacheFlushResult, CacheList, ResolveInput, ResolveResult};
use rocket::serde::json::Json;
use rocket::{delete, get, post, routes, Route, State};

pub fn routes() -> Vec<Route> {
    routes![list, flush, remove, resolve]
}

/// Einträge, deren Name `q` enthält (leer = alle), häufigste zuerst; `limit` 1–1000
/// (Vorgabe 100).
#[get("/cache?<q>&<limit>")]
fn list(
    _user: CurrentUser,
    q: Option<&str>,
    limit: Option<usize>,
    engine: &State<Engine>,
) -> Json<CacheList> {
    let query = q.unwrap_or_default().trim().to_ascii_lowercase();
    Json(engine.cache_list(&query, limit.unwrap_or(100).clamp(1, 1000)))
}

#[delete("/cache")]
fn flush(admin: AdminUser, engine: &State<Engine>) -> Json<CacheFlushResult> {
    let removed = engine.cache_flush();
    tracing::info!(removed, by = %admin.0.username, "Cache geleert");
    Json(CacheFlushResult { removed })
}

/// Alle Typen dieses Namens aus dem Cache.
#[delete("/cache/<name>")]
fn remove(
    _admin: AdminUser,
    name: &str,
    engine: &State<Engine>,
) -> AppResult<Json<CacheFlushResult>> {
    let name = domains::domain(name)?;
    Ok(Json(CacheFlushResult {
        removed: engine.cache_remove(&name),
    }))
}

/// Diesen oder einen anderen Server fragen. Ungültige Eingaben → 400, keine Antwort → 502.
#[post("/resolve", data = "<body>")]
async fn resolve(
    _user: CurrentUser,
    body: Json<ResolveInput>,
    engine: &State<Engine>,
) -> AppResult<Json<ResolveResult>> {
    if body.name.trim().is_empty() {
        return Err(AppError::bad("Bitte einen Namen angeben."));
    }
    Ok(Json(engine.resolve(&body).await?))
}
