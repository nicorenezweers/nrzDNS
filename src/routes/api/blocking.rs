//! Sperren: Sperrlisten, Pause, Prüfen einer Domain, eigene Sperren und Ausnahmen.
//!
//! Neue Listen (und Listen mit neuer Adresse) lädt der Server sofort im Hintergrund; die
//! Antwort wartet nicht darauf. Ohne Hintergrundarbeiten (`background = false`, Tests) wird
//! nichts geladen.

use crate::auth::{AdminUser, CurrentUser};
use crate::config::Config;
use crate::error::AppResult;
use crate::services::blocking::{self, Updater};
use crate::services::domains::{self, Kind};
use crate::services::sync;
use nrzdns_engine::Engine;
use nrzdns_types::{
    BlockList, BlockListInput, BlockingStatus, DomainCheck, DomainEntry, DomainInput, PauseInput,
};
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{delete, get, post, put, routes, Route, State};
use sqlx::SqlitePool;

pub fn routes() -> Vec<Route> {
    routes![
        status,
        create_list,
        update_list,
        delete_list,
        update_all,
        pause,
        check,
        list_blocked,
        add_blocked,
        remove_blocked,
        list_allowed,
        add_allowed,
        remove_allowed
    ]
}

/// Alles, was Routen zum Laden im Hintergrund brauchen.
struct Ctx<'a> {
    pool: &'a SqlitePool,
    config: &'a Config,
    engine: &'a Engine,
    updater: &'a Updater,
}

impl Ctx<'_> {
    /// Eine Liste im Hintergrund laden (nur mit `background = true`).
    fn spawn_download(&self, id: i64) {
        if !self.config.background {
            return;
        }
        let (pool, config, engine, updater) = self.owned();
        updater.mark_updating();
        tokio::spawn(async move {
            if let Err(e) = blocking::update_one(&pool, &config, &engine, &updater, id).await {
                tracing::warn!(id, "Sperrliste laden: {e}");
            }
        });
    }

    fn owned(&self) -> (SqlitePool, Config, Engine, Updater) {
        (
            self.pool.clone(),
            self.config.clone(),
            self.engine.clone(),
            self.updater.clone(),
        )
    }

    async fn status(&self) -> AppResult<Json<BlockingStatus>> {
        Ok(Json(
            blocking::status(self.pool, self.engine, self.updater).await?,
        ))
    }
}

macro_rules! ctx {
    ($pool:expr, $config:expr, $engine:expr, $updater:expr) => {
        Ctx {
            pool: $pool.inner(),
            config: $config.inner(),
            engine: $engine.inner(),
            updater: $updater.inner(),
        }
    };
}

#[get("/blocking")]
async fn status(
    _user: CurrentUser,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
    updater: &State<Updater>,
) -> AppResult<Json<BlockingStatus>> {
    Ok(Json(blocking::status(pool, engine, updater).await?))
}

/// Liste anlegen und (wenn aktiv) sofort laden.
#[post("/blocking/lists", data = "<body>")]
async fn create_list(
    admin: AdminUser,
    body: Json<BlockListInput>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    engine: &State<Engine>,
    updater: &State<Updater>,
) -> AppResult<(Status, Json<BlockList>)> {
    let ctx = ctx!(pool, config, engine, updater);
    let list = blocking::create(pool, &body).await?;
    if list.enabled {
        ctx.spawn_download(list.id);
    }
    tracing::info!(list = %list.name, by = %admin.0.username, "Sperrliste angelegt");
    Ok((Status::Created, Json(list)))
}

/// Name, Adresse, aktiv. Neue Adresse oder noch nie geladen → sofort laden.
#[put("/blocking/lists/<id>", data = "<body>")]
async fn update_list(
    _admin: AdminUser,
    id: i64,
    body: Json<BlockListInput>,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    engine: &State<Engine>,
    updater: &State<Updater>,
) -> AppResult<Json<BlockList>> {
    let ctx = ctx!(pool, config, engine, updater);
    let changed = blocking::update(pool, id, &body).await?;
    let list = changed.list;
    if !list.enabled {
        engine.remove_block_list(list.id);
    } else if changed.url_changed || list.last_updated_at.is_none() {
        ctx.spawn_download(list.id);
    } else {
        // Umbenannt oder wieder aktiviert: die gespeicherte Fassung genügt
        blocking::push_cached(engine, config, &list).await;
    }
    Ok(Json(list))
}

#[delete("/blocking/lists/<id>")]
async fn delete_list(
    _admin: AdminUser,
    id: i64,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    engine: &State<Engine>,
) -> AppResult<Status> {
    blocking::delete(pool, config, id).await?;
    engine.remove_block_list(id);
    Ok(Status::NoContent)
}

/// Alle aktiven Listen jetzt neu laden (im Hintergrund; `updating` zeigt es an).
#[post("/blocking/update")]
async fn update_all(
    _admin: AdminUser,
    pool: &State<SqlitePool>,
    config: &State<Config>,
    engine: &State<Engine>,
    updater: &State<Updater>,
) -> AppResult<Json<BlockingStatus>> {
    let ctx = ctx!(pool, config, engine, updater);
    if config.background {
        let (pool, config, engine, updater) = ctx.owned();
        updater.mark_updating();
        tokio::spawn(async move {
            match blocking::update_due(&pool, &config, &engine, &updater, true).await {
                Ok(n) => tracing::info!("{n} Sperrlisten neu geladen"),
                Err(e) => tracing::warn!("Sperrlisten laden: {e}"),
            }
        });
    }
    ctx.status().await
}

/// Sperren für `minutes` Minuten aussetzen; 0 setzt sofort fort.
#[post("/blocking/pause", data = "<body>")]
async fn pause(
    admin: AdminUser,
    body: Json<PauseInput>,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
    updater: &State<Updater>,
) -> AppResult<Json<BlockingStatus>> {
    blocking::pause(pool, engine, body.minutes).await?;
    tracing::info!(minutes = body.minutes, by = %admin.0.username, "Sperren pausiert");
    Ok(Json(blocking::status(pool, engine, updater).await?))
}

/// Würde diese Domain gesperrt – und warum?
#[get("/blocking/check?<domain>")]
fn check(
    _user: CurrentUser,
    domain: Option<&str>,
    engine: &State<Engine>,
) -> AppResult<Json<DomainCheck>> {
    let domain = domains::domain(domain.unwrap_or_default())?;
    Ok(Json(engine.check_domain(&domain)))
}

// ------------------------------------------------------------------ Eigene Listen

async fn list_of(pool: &SqlitePool, kind: Kind) -> AppResult<Json<Vec<DomainEntry>>> {
    Ok(Json(domains::list(pool, kind).await?))
}

async fn add_to(
    pool: &SqlitePool,
    engine: &Engine,
    kind: Kind,
    input: &DomainInput,
) -> AppResult<(Status, Json<DomainEntry>)> {
    let entry = domains::add(pool, kind, input).await?;
    sync::push_domains(pool, engine, kind).await?;
    Ok((Status::Created, Json(entry)))
}

async fn remove_from(
    pool: &SqlitePool,
    engine: &Engine,
    kind: Kind,
    domain: &str,
) -> AppResult<Status> {
    domains::remove(pool, kind, domain).await?;
    sync::push_domains(pool, engine, kind).await?;
    Ok(Status::NoContent)
}

#[get("/blocked")]
async fn list_blocked(
    _user: CurrentUser,
    pool: &State<SqlitePool>,
) -> AppResult<Json<Vec<DomainEntry>>> {
    list_of(pool, Kind::Blocked).await
}

#[post("/blocked", data = "<body>")]
async fn add_blocked(
    _admin: AdminUser,
    body: Json<DomainInput>,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
) -> AppResult<(Status, Json<DomainEntry>)> {
    add_to(pool, engine, Kind::Blocked, &body).await
}

#[delete("/blocked/<domain>")]
async fn remove_blocked(
    _admin: AdminUser,
    domain: &str,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
) -> AppResult<Status> {
    remove_from(pool, engine, Kind::Blocked, domain).await
}

#[get("/allowed")]
async fn list_allowed(
    _user: CurrentUser,
    pool: &State<SqlitePool>,
) -> AppResult<Json<Vec<DomainEntry>>> {
    list_of(pool, Kind::Allowed).await
}

#[post("/allowed", data = "<body>")]
async fn add_allowed(
    _admin: AdminUser,
    body: Json<DomainInput>,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
) -> AppResult<(Status, Json<DomainEntry>)> {
    add_to(pool, engine, Kind::Allowed, &body).await
}

#[delete("/allowed/<domain>")]
async fn remove_allowed(
    _admin: AdminUser,
    domain: &str,
    pool: &State<SqlitePool>,
    engine: &State<Engine>,
) -> AppResult<Status> {
    remove_from(pool, engine, Kind::Allowed, domain).await
}
