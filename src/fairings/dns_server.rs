//! Der DNS-Server im Hintergrund (Liftoff):
//!
//! * Ports öffnen (`dns_listen`). Ist eine Adresse belegt, steht das im Protokoll und unter
//!   `GET /server` – die Oberfläche bleibt trotzdem erreichbar.
//! * Abfrageprotokoll schreiben: die Engine schickt jede Anfrage in einen Kanal, hier wird
//!   gebündelt gespeichert (jede Sekunde oder alle [`BATCH`] Einträge, je eine Transaktion).
//!   Läuft immer, auch ohne Hintergrundarbeiten – sonst gingen DoH-Anfragen verloren.
//! * Stündlich Einträge löschen, die älter als `log_retention_days` sind.
//!
//! Beim Beenden schreibt der Protokoll-Schreiber den Rest; `CloseDatabase` wartet darauf.

use crate::config::Config;
use crate::services::querylog;
use nrzdns_engine::Engine;
use nrzdns_types::QueryLogEntry;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Orbit, Rocket, Shutdown};
use sqlx::SqlitePool;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinHandle;

/// So viele Einträge auf einmal speichern.
pub const BATCH: usize = 1000;

/// Hält den Kanal der Engine bis zum Start und danach den Schreiber (für `CloseDatabase`).
pub struct DnsServer {
    log: Mutex<Option<Receiver<QueryLogEntry>>>,
}

impl DnsServer {
    pub fn new(log: Receiver<QueryLogEntry>) -> Self {
        Self {
            log: Mutex::new(Some(log)),
        }
    }
}

/// Der laufende Protokoll-Schreiber (Rocket-State); `CloseDatabase` wartet beim Beenden auf ihn.
#[derive(Default)]
pub struct LogWriter(pub Mutex<Option<JoinHandle<()>>>);

#[rocket::async_trait]
impl Fairing for DnsServer {
    fn info(&self) -> Info {
        Info {
            name: "DNS-Server",
            kind: Kind::Liftoff,
        }
    }

    async fn on_liftoff(&self, rocket: &Rocket<Orbit>) {
        let (Some(pool), Some(config), Some(engine)) = (
            rocket.state::<SqlitePool>().cloned(),
            rocket.state::<Config>(),
            rocket.state::<Engine>().cloned(),
        ) else {
            return;
        };
        if let Some(rx) = self.log.lock().ok().and_then(|mut l| l.take()) {
            let handle = tokio::spawn(write_log(pool.clone(), rx, rocket.shutdown()));
            if let Some(slot) = rocket.state::<LogWriter>() {
                if let Ok(mut slot) = slot.0.lock() {
                    *slot = Some(handle);
                }
            }
        }
        if !config.background {
            return;
        }
        if config.dns_listen.is_empty() {
            tracing::info!("Kein DNS über UDP/TCP (dns_listen ist leer)");
        } else {
            let errors = engine.listen(&config.dns_listen).await;
            for e in &errors {
                tracing::error!("DNS-Server: {e}");
            }
            let addrs: Vec<String> = config.dns_listen.iter().map(ToString::to_string).collect();
            if errors.is_empty() {
                tracing::info!("DNS-Server läuft auf {}", addrs.join(", "));
            }
        }
        tokio::spawn(purge_log(pool, engine, rocket.shutdown()));
    }
}

/// Einträge aus dem Kanal sammeln und gebündelt speichern, bis der Server endet.
async fn write_log(pool: SqlitePool, mut rx: Receiver<QueryLogEntry>, mut shutdown: Shutdown) {
    let mut buf: Vec<QueryLogEntry> = Vec::with_capacity(BATCH);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            entry = rx.recv() => match entry {
                Some(e) => {
                    buf.push(e);
                    if buf.len() >= BATCH {
                        flush(&pool, &mut buf).await;
                    }
                }
                None => break,
            },
            _ = tick.tick() => flush(&pool, &mut buf).await,
        }
    }
    // Was noch im Kanal steckt, auch speichern
    while let Ok(e) = rx.try_recv() {
        buf.push(e);
        if buf.len() >= BATCH {
            flush(&pool, &mut buf).await;
        }
    }
    flush(&pool, &mut buf).await;
}

async fn flush(pool: &SqlitePool, buf: &mut Vec<QueryLogEntry>) {
    if buf.is_empty() {
        return;
    }
    if let Err(e) = querylog::insert_batch(pool, buf).await {
        // Lieber Einträge verlieren als den Speicher füllen
        tracing::warn!(entries = buf.len(), "Abfrageprotokoll speichern: {e}");
    }
    buf.clear();
}

/// Stündlich alte Einträge löschen.
async fn purge_log(pool: SqlitePool, engine: Engine, mut shutdown: Shutdown) {
    loop {
        let days = i64::from(engine.settings().log_retention_days.clamp(1, 365));
        let cutoff_ms = (crate::db::now() - days * 86_400) * 1000;
        match querylog::purge_before(&pool, cutoff_ms).await {
            Ok(n) if n > 0 => tracing::info!("{n} alte Einträge aus dem Abfrageprotokoll gelöscht"),
            Err(e) => tracing::warn!("Abfrageprotokoll aufräumen: {e}"),
            _ => {}
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(3600)) => {}
            _ = &mut shutdown => break,
        }
    }
}
