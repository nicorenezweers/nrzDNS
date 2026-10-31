//! Lädt Sperrlisten im Hintergrund neu: gleich beim Start alle aktiven, die noch nie oder
//! vor mehr als `blocklist_update_hours` geladen wurden, danach alle zehn Minuten die
//! fälligen (oder sofort, wenn jemand [`Updater::wake`] ruft). Nur mit `background = true`.

use crate::config::Config;
use crate::services::blocking::{self, Updater};
use nrzdns_engine::Engine;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Orbit, Rocket};
use sqlx::SqlitePool;
use std::time::Duration;

/// So oft wird geprüft, ob Listen fällig sind.
const CHECK_EVERY: Duration = Duration::from_secs(600);

pub struct BlocklistUpdater;

#[rocket::async_trait]
impl Fairing for BlocklistUpdater {
    fn info(&self) -> Info {
        Info {
            name: "Sperrlisten laden",
            kind: Kind::Liftoff,
        }
    }

    async fn on_liftoff(&self, rocket: &Rocket<Orbit>) {
        let (Some(pool), Some(config), Some(engine), Some(updater)) = (
            rocket.state::<SqlitePool>().cloned(),
            rocket.state::<Config>().cloned(),
            rocket.state::<Engine>().cloned(),
            rocket.state::<Updater>().cloned(),
        ) else {
            return;
        };
        if !config.background {
            return;
        }
        let mut shutdown = rocket.shutdown();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    r = blocking::update_due(&pool, &config, &engine, &updater, false) => match r {
                        Ok(n) if n > 0 => tracing::info!("{n} Sperrlisten geladen"),
                        Err(e) => tracing::warn!("Sperrlisten laden: {e}"),
                        _ => {}
                    },
                    _ = &mut shutdown => break,
                }
                tokio::select! {
                    _ = tokio::time::sleep(CHECK_EVERY) => {}
                    _ = updater.woken() => {}
                    _ = &mut shutdown => break,
                }
            }
        });
    }
}
