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
        if let Some(d) = rocket.state::<crate::services::dieter::DieterState>() {
            d.set_port(rocket.config().port);
        }
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
            {
                // Containernamen je IP (Zugriffe), jede Minute
                let config = config.clone();
                let mut shutdown = rocket.shutdown();
                tokio::spawn(async move {
                    loop {
                        crate::services::docker::refresh_names(&config).await;
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                            _ = &mut shutdown => break,
                        }
                    }
                });
            }
            tokio::spawn(write_access_log(
                pool.clone(),
                state.clone(),
                config.host_gateway.clone(),
                rocket.shutdown(),
            ));
            if let Some(comps) = rocket.state::<crate::services::components::Components>() {
                comps.spawn_supervisors(rocket.shutdown());
                if let Err(e) = comps.apply(&pool, config).await {
                    tracing::warn!("Komponenten: {e}");
                }
                tokio::spawn(crate::services::components::scheduler(
                    pool.clone(),
                    config.clone(),
                    comps.clone(),
                    rocket.shutdown(),
                ));
            }
            if let (Some(d), Some(comps)) = (
                rocket.state::<crate::services::dieter::DieterState>(),
                rocket.state::<crate::services::components::Components>(),
            ) {
                d.set_port(rocket.config().port);
                tokio::spawn(crate::services::dieter::watcher(
                    crate::services::dieter::Ctx {
                        pool: pool.clone(),
                        config: config.clone(),
                        engine: engine.clone(),
                        state: d.clone(),
                        components: comps.clone(),
                        proxy: state.clone(),
                    },
                    rocket.shutdown(),
                ));
            }
            if let Some(spy) = rocket.state::<crate::services::spy::SpyState>() {
                tokio::spawn(crate::services::spy::scheduler(
                    pool.clone(),
                    config.clone(),
                    spy.clone(),
                    rocket.shutdown(),
                ));
            }
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

/// Zugriffsprotokoll: alle 2 s speichern, stündlich alte Einträge löschen.
async fn write_access_log(
    pool: SqlitePool,
    state: ProxyState,
    gateway: Option<String>,
    mut shutdown: rocket::Shutdown,
) {
    state
        .access()
        .set_gateway(crate::services::access::resolve_gateway(gateway.as_deref()).await);
    let mut tick: u32 = 0;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            _ = &mut shutdown => {
                let _ = crate::services::access::flush(&pool, &state).await;
                break;
            }
        }
        if let Err(e) = crate::services::access::flush(&pool, &state).await {
            tracing::warn!("Zugriffsprotokoll: {e}");
        }
        tick = tick.wrapping_add(1);
        if tick % 1800 == 1 {
            match crate::services::access::purge(&pool).await {
                Ok(n) if n > 0 => tracing::info!("Zugriffsprotokoll: {n} alte Einträge gelöscht"),
                Err(e) => tracing::warn!("Zugriffsprotokoll aufräumen: {e}"),
                _ => {}
            }
        }
    }
}
