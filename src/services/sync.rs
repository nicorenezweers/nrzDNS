//! Den Bestand aus der Datenbank in die Engine bringen: beim Start alles, danach nach jeder
//! Änderung den betroffenen Teil. Die Engine hält nur Speicher – Quelle ist immer SQLite.

use crate::config::Config;
use crate::error::AppResult;
use crate::services::{blocking, domains, settings, zones};
use nrzdns_engine::Engine;
use sqlx::SqlitePool;

/// Alle Zonen mit ihren Einträgen.
pub async fn push_zones(pool: &SqlitePool, engine: &Engine) -> AppResult<()> {
    engine.set_zones(zones::all_details(pool).await?);
    Ok(())
}

/// Eigene Sperren bzw. Ausnahmen.
pub async fn push_domains(
    pool: &SqlitePool,
    engine: &Engine,
    kind: domains::Kind,
) -> AppResult<()> {
    let names = domains::names(pool, kind).await?;
    match kind {
        domains::Kind::Blocked => engine.set_custom_blocked(names),
        domains::Kind::Allowed => engine.set_allowed(names),
    }
    Ok(())
}

/// Beim Start: Zonen, eigene Sperren, Ausnahmen, zwischengespeicherte Sperrlisten (nur
/// aktive) und eine noch laufende Pause.
pub async fn load_all(pool: &SqlitePool, engine: &Engine, config: &Config) -> AppResult<()> {
    push_zones(pool, engine).await?;
    push_domains(pool, engine, domains::Kind::Blocked).await?;
    push_domains(pool, engine, domains::Kind::Allowed).await?;
    let lists = blocking::list(pool).await?;
    for list in lists.iter().filter(|l| l.enabled) {
        blocking::push_cached(engine, config, list).await;
    }
    engine.pause_blocking(settings::paused_until(pool).await?);
    tracing::debug!(lists = lists.len(), "Bestand an die Engine übergeben");
    Ok(())
}
