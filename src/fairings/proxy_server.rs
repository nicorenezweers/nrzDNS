//! Reverse Proxy im Hintergrund (Liftoff): Ports aus `proxy_listen` öffnen. Ist ein Port
//! belegt, steht das im Protokoll und unter `GET /proxy` – der Rest läuft weiter.

use crate::config::Config;
use crate::proxy::ProxyState;
use crate::services::{domains, proxy, sync, unlocks};
use nrzdns_engine::Engine;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Orbit, Rocket};
use sqlx::SqlitePool;
use std::time::Duration;

pub struct ProxyServer;

#[rocket::async_trait]
impl Fairing for ProxyServer {
    fn info(&self) -> Info {
        Info {
            name: "Reverse Proxy",
            kind: Kind::Liftoff,
        }
    }

    async fn on_liftoff(&self, rocket: &Rocket<Orbit>) {
        let (Some(config), Some(state)) = (rocket.state::<Config>(), rocket.state::<ProxyState>())
        else {
            return;
        };
        if !config.background {
            return;
        }
        if let (Some(pool), Some(engine)) = (
            rocket.state::<SqlitePool>().cloned(),
            rocket.state::<Engine>().cloned(),
        ) {
            tokio::spawn(housekeeping(
                pool.clone(),
                engine.clone(),
                state.clone(),
                rocket.shutdown(),
            ));
            tokio::spawn(renew_certificates(
                pool,
                engine,
                state.clone(),
                config.clone(),
                rocket.shutdown(),
            ));
        }
        if !config.proxy_tls_listen.is_empty() {
            state
                .serve_tls(&config.proxy_tls_listen, rocket.shutdown())
                .await;
        }
        if config.proxy_listen.is_empty() {
            tracing::info!("Kein Reverse Proxy (proxy_listen ist leer)");
            return;
        }
        state.serve(&config.proxy_listen, rocket.shutdown()).await;
    }
}

/// Alle 30 s: abgelaufene Freischaltungen entfernen, neu erkannte Adressen des Geräts
/// übernehmen.
async fn housekeeping(
    pool: SqlitePool,
    engine: Engine,
    state: ProxyState,
    mut shutdown: rocket::Shutdown,
) {
    let mut last = engine.device_addresses();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(30)) => {}
            _ = &mut shutdown => break,
        }
        match unlocks::purge_expired(&pool).await {
            Ok(n) if n > 0 => {
                if let Err(e) = sync::push_domains(&pool, &engine, domains::Kind::Allowed).await {
                    tracing::warn!("Freischaltungen: {e}");
                }
                tracing::info!("{n} Freischaltung(en) abgelaufen");
            }
            Err(e) => tracing::warn!("Freischaltungen aufräumen: {e}"),
            _ => {}
        }
        let settings = match proxy::settings(&pool).await {
            Ok(s) => s,
            Err(_) => continue,
        };
        let now = proxy::device_addresses(&settings, state.data_dir());
        if now != last {
            tracing::info!(addresses = ?now, "Adressen des Geräts geändert");
            if let Err(e) = sync::push_proxy(&pool, &engine, &state).await {
                tracing::warn!("Reverse Proxy: {e}");
            }
            last = now;
        }
    }
}

/// HTTPS-Zertifikat: eine Minute nach dem Start, danach stündlich prüfen und bei Bedarf erneuern.
async fn renew_certificates(
    pool: SqlitePool,
    engine: Engine,
    state: ProxyState,
    config: Config,
    mut shutdown: rocket::Shutdown,
) {
    let mut wait = Duration::from_secs(60);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = &mut shutdown => break,
        }
        crate::services::tls::maybe_renew(&pool, &engine, &state, &config).await;
        wait = Duration::from_secs(3600);
    }
}
