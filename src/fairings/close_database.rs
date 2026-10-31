//! Beim Herunterfahren die Datenbank sauber schliessen: erst den Rest des Abfrageprotokolls
//! schreiben lassen, dann laufende Abfragen beenden, WAL zurückschreiben, Verbindungs-Threads
//! stoppen. Ohne das schliesst ein sqlx-Thread seine Verbindung erst, während der Prozess
//! schon endet – und die `-wal`-Datei bleibt liegen.

use super::LogWriter;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Orbit, Rocket};
use sqlx::SqlitePool;
use std::time::Duration;

pub struct CloseDatabase;

#[rocket::async_trait]
impl Fairing for CloseDatabase {
    fn info(&self) -> Info {
        Info {
            name: "Datenbank schliessen",
            kind: Kind::Shutdown,
        }
    }

    async fn on_shutdown(&self, rocket: &Rocket<Orbit>) {
        let writer = rocket
            .state::<LogWriter>()
            .and_then(|w| w.0.lock().ok()?.take());
        if let Some(handle) = writer {
            if tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .is_err()
            {
                tracing::warn!("Abfrageprotokoll: Schreiben beim Beenden abgebrochen");
            }
        }
        if let Some(pool) = rocket.state::<SqlitePool>() {
            pool.close().await;
            tracing::info!("Datenbank geschlossen");
        }
    }
}
