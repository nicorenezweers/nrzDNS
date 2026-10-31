//! nrzdns-engine – der DNS-Server selbst, unabhängig von Rocket und Datenbank.
//!
//! Der Server (`src/`) hält die Daten (Einstellungen, Zonen, Listen) in SQLite und reicht sie
//! hier hinein; die Engine beantwortet Anfragen nur aus ihrem Speicher. Jede beantwortete
//! Anfrage kommt als [`QueryLogEntry`] aus dem Kanal von [`Engine::new`] zurück.
//!
//! Ablauf einer Anfrage (`handle`):
//! 1. Rate-Limit je Client → sonst verwerfen (`dropped`)
//! 2. Eigene Zonen (Primär: verbindlich mit AA; Platzhalter, CNAME innerhalb der Zone, NXDOMAIN
//!    mit SOA) → `authoritative`
//! 3. Ausnahmen / Sperren (Domain und alle Elterndomains) → `blocked`, je nach [`BlockMode`]
//! 4. Lokale Antworten: `localhost`, private PTR ohne Zone, AAAA bei abgeschaltetem IPv6 → `local`
//! 5. Cache → `cached` (abgelaufen nur, wenn kein vorgelagerter Server antwortet)
//! 6. Bedingte Weiterleitung (Forwarder-Zone) oder die Weiterleitungen der Einstellungen
//!    (UDP mit TCP-Rückfall, TCP, DoT, DoH; Strategie der Reihe nach / zufällig / parallel)
//!    → `forwarded`, sonst SERVFAIL → `failed`
//!
//! **Vertrag:** Die öffentlichen Signaturen in dieser Datei benutzt der Server. Sie dürfen
//! wachsen, aber nicht brechen.
//!
//! [`BlockMode`]: nrzdns_types::BlockMode

pub mod blocklist;
pub mod zonefile;

mod blocking;
mod cache;
mod pipeline;
mod server;
mod stats;
mod upstream;
mod wire;
mod zones;

pub use nrzdns_types as types;

use blocking::{distinct_total, BlockData, DomainSet};
use cache::{Cache, Limits};
use nrzdns_types::{
    CacheList, DnsSettings, DomainCheck, Protocol, QueryLogEntry, ResolveInput, ResolveResult,
    ServerStatus, ZoneDetail,
};
use stats::{lock, HealthMap, Listeners, QueryStats, RateLimiter};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use upstream::Clients;
use zones::ZoneSet;

/// Pfad für DNS über HTTPS (der Server hängt die Route dort ein).
pub const DOH_PATH: &str = "/dns-query";

/// So viele Protokolleinträge dürfen im Kanal warten; darüber gehen neue verloren, statt den
/// DNS-Server zu bremsen.
pub const LOG_CHANNEL_CAPACITY: usize = 50_000;

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// Ungültige Eingabe (Name, Typ, Adresse, Zonendatei …) – Meldung auf Deutsch.
    #[error("{0}")]
    Invalid(String),
    /// Netzwerk- oder Protokollfehler beim Fragen eines anderen Servers / Laden einer Liste.
    #[error("{0}")]
    Network(String),
    #[error("Zeitlimit überschritten")]
    Timeout,
}

/// Die Engine. Günstig zu klonen (alles hinter einem `Arc`).
#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}

struct Inner {
    version: String,
    started_at: i64,
    started: Instant,
    settings: RwLock<Arc<DnsSettings>>,
    log: mpsc::Sender<QueryLogEntry>,
    zones: RwLock<Arc<ZoneSet>>,
    blocking: RwLock<BlockData>,
    /// Hält Änderungen an den Sperrdaten nacheinander (die Zählung läuft ausserhalb der Sperre).
    blocking_update: Mutex<()>,
    cache: Cache,
    limiter: RateLimiter,
    queries: QueryStats,
    health: HealthMap,
    listeners: Mutex<Listeners>,
    clients: Clients,
}

fn read<T>(l: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(PoisonError::into_inner)
}

fn write<T>(l: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl Engine {
    /// Neue Engine mit diesen Einstellungen. Der Empfänger liefert jede beantwortete Anfrage,
    /// solange [`DnsSettings::log_queries`] an ist (Anfragen des DNS-Clients nie).
    pub fn new(settings: DnsSettings, version: &str) -> (Engine, mpsc::Receiver<QueryLogEntry>) {
        let (tx, rx) = mpsc::channel(LOG_CHANNEL_CAPACITY);
        upstream::set_bootstrap(&settings.forwarders);
        let started = Instant::now();
        let engine = Engine {
            inner: Arc::new(Inner {
                version: version.to_string(),
                started_at: now_unix(),
                started,
                settings: RwLock::new(Arc::new(settings)),
                log: tx,
                zones: RwLock::new(Arc::new(ZoneSet::default())),
                blocking: RwLock::new(BlockData::default()),
                blocking_update: Mutex::new(()),
                cache: Cache::default(),
                limiter: RateLimiter::default(),
                queries: QueryStats::new(started),
                health: HealthMap::default(),
                listeners: Mutex::new(Listeners::default()),
                clients: Clients::default(),
            }),
        };
        (engine, rx)
    }

    pub fn settings(&self) -> DnsSettings {
        (**read(&self.inner.settings)).clone()
    }

    pub(crate) fn settings_arc(&self) -> Arc<DnsSettings> {
        read(&self.inner.settings).clone()
    }

    pub(crate) fn zones(&self) -> Arc<ZoneSet> {
        read(&self.inner.zones).clone()
    }

    /// Neue Einstellungen sofort übernehmen (Cache-Grenzen, Weiterleitungen, Sperrmodus …).
    pub fn apply_settings(&self, settings: DnsSettings) {
        upstream::set_bootstrap(&settings.forwarders);
        let limits = Limits::from_settings(&settings);
        let cache_enabled = settings.cache_enabled;
        let qps = settings.rate_limit_qps;
        let old = std::mem::replace(&mut *write(&self.inner.settings), Arc::new(settings));
        if cache_enabled {
            self.inner.cache.apply_limits(&limits, Instant::now());
        } else {
            self.inner.cache.flush();
        }
        if old.rate_limit_qps != qps {
            self.inner.limiter.clear();
        }
    }

    /// Alle Zonen ersetzen (der Server ruft das nach jeder Änderung mit dem ganzen Bestand auf).
    /// Deaktivierte Zonen und Einträge beachtet die Engine selbst nicht.
    pub fn set_zones(&self, zones: Vec<ZoneDetail>) {
        let set = ZoneSet::build(&zones, &self.settings_arc().server_domain);
        *write(&self.inner.zones) = Arc::new(set);
    }

    /// Domains einer Sperrliste setzen oder ersetzen (schon normalisiert, siehe
    /// [`blocklist::parse`]). `name` erscheint in [`DomainCheck::matches`].
    pub fn set_block_list(&self, list_id: i64, name: &str, domains: Vec<String>) {
        let set = DomainSet::new(&domains);
        drop(domains);
        let _guard = lock(&self.inner.blocking_update);
        write(&self.inner.blocking).set_list(list_id, name, set);
        self.recount_blocked();
    }

    /// Sperrliste entfernen (gelöscht oder deaktiviert).
    pub fn remove_block_list(&self, list_id: i64) {
        let _guard = lock(&self.inner.blocking_update);
        if write(&self.inner.blocking).remove_list(list_id) {
            self.recount_blocked();
        }
    }

    /// Eigene Sperren ersetzen (jede gilt auch für alle Subdomains).
    pub fn set_custom_blocked(&self, domains: Vec<String>) {
        let set = DomainSet::new(&domains);
        let _guard = lock(&self.inner.blocking_update);
        write(&self.inner.blocking).set_custom(set);
        self.recount_blocked();
    }

    /// Ausnahmen ersetzen (schlagen jede Sperre, auch für Subdomains).
    pub fn set_allowed(&self, domains: Vec<String>) {
        let set = DomainSet::new(&domains);
        write(&self.inner.blocking).set_allowed(set);
    }

    /// Verschiedene Domains neu zählen – ausserhalb der Lese-/Schreibsperre, damit Anfragen
    /// nicht warten. Aufrufer hält `blocking_update`.
    fn recount_blocked(&self) {
        let sets = read(&self.inner.blocking).block_sets();
        let total = distinct_total(&sets);
        write(&self.inner.blocking).set_total(total);
    }

    /// Sperren bis zu diesem Zeitpunkt (Unix-Sekunden) aussetzen; `None` = fortsetzen.
    pub fn pause_blocking(&self, until: Option<i64>) {
        write(&self.inner.blocking).pause(until.filter(|&t| t > now_unix()));
    }

    pub fn blocking_paused_until(&self) -> Option<i64> {
        read(&self.inner.blocking).paused_until(now_unix())
    }

    /// Verschiedene gesperrte Domains (Listen + eigene Sperren).
    pub fn blocked_domain_count(&self) -> u64 {
        read(&self.inner.blocking).total()
    }

    /// Würde diese Domain gesperrt – und warum?
    pub fn check_domain(&self, domain: &str) -> DomainCheck {
        read(&self.inner.blocking).check(domain)
    }

    /// UDP und TCP auf allen Adressen öffnen und im Hintergrund bedienen. Liefert die Fehler
    /// (z. B. „0.0.0.0:53/udp: Address in use“); leer = alles offen. Die Adressen erscheinen in
    /// [`ServerStatus::dns_listen`] bzw. [`ServerStatus::listen_errors`].
    pub async fn listen(&self, addrs: &[SocketAddr]) -> Vec<String> {
        let mut opened = Vec::new();
        let mut errors = Vec::new();
        for &addr in addrs {
            match server::bind_udp(addr) {
                Ok(sock) => {
                    let local = sock.local_addr().unwrap_or(addr);
                    opened.push(format!("{local}/udp"));
                    server::serve_udp(self.clone(), sock);
                }
                Err(e) => errors.push(format!(
                    "{addr}/udp: {}",
                    wire::strip_os_error(&e.to_string())
                )),
            }
            match server::bind_tcp(addr) {
                Ok(listener) => {
                    let local = listener.local_addr().unwrap_or(addr);
                    opened.push(format!("{local}/tcp"));
                    server::serve_tcp(self.clone(), listener);
                }
                Err(e) => errors.push(format!(
                    "{addr}/tcp: {}",
                    wire::strip_os_error(&e.to_string())
                )),
            }
        }
        for e in &errors {
            tracing::warn!("DNS-Adresse nicht geöffnet: {e}");
        }
        let mut l = lock(&self.inner.listeners);
        l.listen.extend(opened);
        l.errors.extend(errors.iter().cloned());
        errors
    }

    /// Eine DNS-Nachricht (Wire-Format) beantworten – für UDP, TCP und DoH. `None` = verwerfen
    /// (Rate-Limit, Unlesbares ohne Kopf).
    pub async fn handle(
        &self,
        request: &[u8],
        client: IpAddr,
        protocol: Protocol,
    ) -> Option<Vec<u8>> {
        pipeline::handle(self, request, client, protocol).await
    }

    /// DNS-Client der Oberfläche: diesen Server (leeres `server`) oder einen anderen fragen.
    pub async fn resolve(&self, input: &ResolveInput) -> Result<ResolveResult, EngineError> {
        pipeline::resolve(self, input).await
    }

    /// Cache-Einträge, deren Name `query` enthält (leer = alle), häufigste zuerst.
    pub fn cache_list(&self, query: &str, limit: usize) -> CacheList {
        let limits = Limits::from_settings(&self.settings_arc());
        self.inner.cache.list(query, limit, &limits, Instant::now())
    }

    /// Cache leeren; liefert die Anzahl entfernter Einträge.
    pub fn cache_flush(&self) -> u64 {
        self.inner.cache.flush()
    }

    /// Alle Einträge dieses Namens (alle Typen) entfernen.
    pub fn cache_remove(&self, name: &str) -> u64 {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        self.inner.cache.remove_name(&name)
    }

    /// Laufender Zustand (Version, Laufzeit, Adressen, Zähler, Zustand der Weiterleitungen).
    pub fn status(&self) -> ServerStatus {
        let s = self.settings_arc();
        let now = Instant::now();
        let limits = Limits::from_settings(&s);
        let (dns_listen, listen_errors) = {
            let l = lock(&self.inner.listeners);
            (l.listen.clone(), l.errors.clone())
        };
        let (blocked_domains, blocking_paused_until) = {
            let b = read(&self.inner.blocking);
            (b.total(), b.paused_until(now_unix()))
        };
        ServerStatus {
            version: self.inner.version.clone(),
            started_at: self.inner.started_at,
            uptime_secs: now.saturating_duration_since(self.inner.started).as_secs(),
            dns_listen,
            listen_errors,
            doh_enabled: s.doh_enabled,
            doh_path: DOH_PATH.into(),
            queries_since_start: self.inner.queries.total(),
            queries_per_second: (self.inner.queries.per_second(now) * 100.0).round() / 100.0,
            cache_entries: self.inner.cache.len(&limits, now),
            zones: self.zones().total as u32,
            blocked_domains,
            blocking_enabled: s.blocking_enabled,
            blocking_paused_until,
            upstreams: self.inner.health.snapshot(&s.forwarders),
        }
    }
}
