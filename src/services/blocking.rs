//! Sperrlisten: verwalten, laden und zwischenspeichern.
//!
//! * Jede geladene Liste liegt normalisiert (eine Domain je Zeile) unter
//!   `<data_dir>/blocklists/<id>.txt`; beim Start bekommt die Engine die Listen von dort, ohne
//!   etwas herunterzuladen.
//! * Neu geladen wird alle `blocklist_update_hours` Stunden (siehe `fairings::BlocklistUpdater`),
//!   nach einem Fehler frühestens nach einer Stunde wieder. Schlägt das Laden fehl, bleibt die
//!   alte Fassung aktiv und der Fehler steht in `last_error`.
//! * Es lädt immer nur einer zur Zeit ([`Updater`]); das hält Speicher und Netz im Rahmen.

use crate::config::Config;
use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::services::{domains, settings};
use nrzdns_engine::{blocklist, Engine};
use nrzdns_types::{BlockList, BlockListInput, BlockingStatus, Presets};
use sqlx::SqlitePool;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

/// Nach einem Fehler frühestens so spät erneut versuchen (Sekunden).
pub const RETRY_AFTER_ERROR_SECS: i64 = 3600;
const MAX_NAME: usize = 100;
const MAX_URL: usize = 2000;

/// Gemeinsamer Zustand des Ladens (Rocket-State, günstig zu klonen): nur einer lädt zur
/// Zeit, und der Hintergrund lässt sich wecken (z. B. nach geänderter Update-Frequenz).
#[derive(Clone, Default)]
pub struct Updater(Arc<UpdaterInner>);

#[derive(Default)]
struct UpdaterInner {
    lock: Mutex<()>,
    updating: AtomicBool,
    wake: Notify,
}

impl Updater {
    /// Läuft gerade ein Laden (oder ist eines angestossen)?
    pub fn updating(&self) -> bool {
        self.0.updating.load(Ordering::Relaxed)
    }

    /// Schon vor dem Start als „lädt“ zeigen (die Antwort auf „jetzt laden“ kommt sofort).
    pub fn mark_updating(&self) {
        self.0.updating.store(true, Ordering::Relaxed);
    }

    /// Den Hintergrund sofort prüfen lassen, ob Listen fällig sind.
    pub fn wake(&self) {
        self.0.wake.notify_one();
    }

    pub async fn woken(&self) {
        self.0.wake.notified().await;
    }
}

#[derive(sqlx::FromRow)]
struct ListRow {
    id: i64,
    name: String,
    url: String,
    enabled: bool,
    domain_count: i64,
    last_updated_at: Option<i64>,
    last_error: Option<String>,
    created_at: i64,
}

impl ListRow {
    fn into_list(self) -> BlockList {
        BlockList {
            id: self.id,
            name: self.name,
            url: self.url,
            enabled: self.enabled,
            domain_count: u32::try_from(self.domain_count).unwrap_or(u32::MAX),
            last_updated_at: self.last_updated_at,
            last_error: self.last_error,
            created_at: self.created_at,
        }
    }
}

macro_rules! select_lists {
    ($rest:literal) => {
        concat!(
            "SELECT id, name, url, enabled, domain_count, last_updated_at, last_error, created_at \
             FROM block_lists ",
            $rest
        )
    };
}

pub async fn list(pool: &SqlitePool) -> AppResult<Vec<BlockList>> {
    let rows: Vec<ListRow> = sqlx::query_as(select_lists!("ORDER BY name COLLATE NOCASE, id"))
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(ListRow::into_list).collect())
}

pub async fn get(pool: &SqlitePool, id: i64) -> AppResult<BlockList> {
    let row: Option<ListRow> = sqlx::query_as(select_lists!("WHERE id = ?"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    row.map(ListRow::into_list).ok_or(AppError::NotFound)
}

/// Adresse prüfen: nur http(s), ohne Leerzeichen.
fn validate_url(url: &str) -> AppResult<String> {
    let url = url.trim();
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    let host = rest
        .and_then(|r| r.split(['/', '?', '#']).next())
        .unwrap_or_default();
    if host.is_empty()
        || url.len() > MAX_URL
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(AppError::bad(
            "Adresse der Liste: bitte eine http- oder https-Adresse angeben.",
        ));
    }
    Ok(url.to_string())
}

/// Name aus der Eingabe, sonst aus den Vorlagen, sonst aus der Adresse
/// (`hosts (raw.githubusercontent.com)`).
fn list_name(input: &str, url: &str) -> AppResult<String> {
    let name = input.trim();
    if name.chars().count() > MAX_NAME || name.chars().any(char::is_control) {
        return Err(AppError::bad(format!(
            "Name der Liste: höchstens {MAX_NAME} Zeichen."
        )));
    }
    if !name.is_empty() {
        return Ok(name.to_string());
    }
    if let Some(p) = Presets::builtin()
        .blocklists
        .into_iter()
        .find(|p| p.url == url)
    {
        return Ok(p.name);
    }
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let path = rest.split(['?', '#']).next().unwrap_or(rest);
    let host = path.split('/').next().unwrap_or(path);
    let last = path
        .rsplit('/')
        .next()
        .filter(|l| !l.is_empty() && *l != host);
    Ok(match last {
        Some(file) => format!("{file} ({host})"),
        None => host.to_string(),
    }
    .chars()
    .take(MAX_NAME)
    .collect())
}

pub async fn create(pool: &SqlitePool, input: &BlockListInput) -> AppResult<BlockList> {
    let url = validate_url(&input.url)?;
    let name = list_name(&input.name, &url)?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO block_lists (name, url, enabled, created_at) VALUES (?, ?, ?, ?) RETURNING id",
    )
    .bind(&name)
    .bind(&url)
    .bind(input.enabled)
    .bind(now())
    .fetch_one(pool)
    .await
    .map_err(|e| AppError::unique(e, "Diese Liste gibt es schon."))?;
    get(pool, id).await
}

/// Was sich durch [`update`] geändert hat – davon hängt ab, was die Engine bekommt.
pub struct Changed {
    pub list: BlockList,
    pub url_changed: bool,
}

/// Name, Adresse, aktiv. Eine neue Adresse gilt als noch nicht geladen.
pub async fn update(pool: &SqlitePool, id: i64, input: &BlockListInput) -> AppResult<Changed> {
    let old = get(pool, id).await?;
    let url = validate_url(&input.url)?;
    let name = list_name(&input.name, &url)?;
    let url_changed = url != old.url;
    sqlx::query(
        "UPDATE block_lists SET name = ?, url = ?, enabled = ?,
            last_checked_at = CASE WHEN ? THEN NULL ELSE last_checked_at END
         WHERE id = ?",
    )
    .bind(&name)
    .bind(&url)
    .bind(input.enabled)
    .bind(url_changed)
    .bind(id)
    .execute(pool)
    .await
    .map_err(|e| AppError::unique(e, "Diese Liste gibt es schon."))?;
    Ok(Changed {
        list: get(pool, id).await?,
        url_changed,
    })
}

/// Liste und ihre zwischengespeicherte Datei löschen.
pub async fn delete(pool: &SqlitePool, config: &Config, id: i64) -> AppResult<()> {
    let done = sqlx::query("DELETE FROM block_lists WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    match tokio::fs::remove_file(cache_path(config, id)).await {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            tracing::warn!(id, "Sperrliste löschen: {e}");
        }
        _ => {}
    }
    Ok(())
}

// ------------------------------------------------------------------ Laden

pub fn cache_path(config: &Config, id: i64) -> PathBuf {
    config.blocklist_dir().join(format!("{id}.txt"))
}

/// Zuletzt geladene Fassung (eine Domain je Zeile); `None`, wenn es noch keine gibt.
pub async fn read_cached(config: &Config, id: i64) -> Option<Vec<String>> {
    let text = tokio::fs::read_to_string(cache_path(config, id))
        .await
        .ok()?;
    Some(
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

/// Erst in eine Hilfsdatei schreiben, dann umbenennen – ein Absturz hinterlässt nie eine
/// halbe Liste.
async fn write_cached(config: &Config, id: i64, domains: &[String]) -> std::io::Result<()> {
    let dir = config.blocklist_dir();
    tokio::fs::create_dir_all(&dir).await?;
    let tmp = dir.join(format!("{id}.txt.tmp"));
    let mut text = domains.join("\n");
    text.push('\n');
    tokio::fs::write(&tmp, text).await?;
    tokio::fs::rename(&tmp, cache_path(config, id)).await
}

/// Zwischengespeicherte Fassung einer aktiven Liste an die Engine geben (Start, Umbenennen,
/// Aktivieren). Ohne Datei passiert nichts – dann muss die Liste erst geladen werden.
pub async fn push_cached(engine: &Engine, config: &Config, list: &BlockList) {
    if !list.enabled {
        engine.remove_block_list(list.id);
        return;
    }
    if let Some(domains) = read_cached(config, list.id).await {
        engine.set_block_list(list.id, &list.name, domains);
    }
}

/// Eine Liste herunterladen, speichern und an die Engine geben. Fehler beim Laden landen in
/// `last_error` (die alte Fassung bleibt); nur Datenbankfehler sind ein `Err`.
pub async fn download(
    pool: &SqlitePool,
    config: &Config,
    engine: &Engine,
    id: i64,
) -> AppResult<Option<String>> {
    let list = get(pool, id).await?;
    let result = match blocklist::download(&list.url).await {
        Ok(domains) => write_cached(config, id, &domains)
            .await
            .map(|()| domains)
            .map_err(|e| {
                tracing::error!(id, "Sperrliste speichern: {e}");
                "Die Liste liess sich nicht speichern.".to_string()
            }),
        Err(e) => Err(e.to_string()),
    };
    let ts = now();
    match result {
        Ok(domains) => {
            let count = domains.len();
            // Inzwischen deaktiviert oder gelöscht? Dann nicht wieder einschalten.
            match get(pool, id).await {
                Ok(current) if current.enabled => engine.set_block_list(id, &current.name, domains),
                Ok(_) => {}
                Err(AppError::NotFound) => {
                    let _ = tokio::fs::remove_file(cache_path(config, id)).await;
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
            sqlx::query(
                "UPDATE block_lists SET domain_count = ?, last_updated_at = ?, last_checked_at = ?,
                    last_error = NULL WHERE id = ?",
            )
            .bind(i64::try_from(count).unwrap_or(i64::MAX))
            .bind(ts)
            .bind(ts)
            .bind(id)
            .execute(pool)
            .await?;
            tracing::info!(list = %list.name, domains = count, "Sperrliste geladen");
            Ok(None)
        }
        Err(msg) => {
            sqlx::query("UPDATE block_lists SET last_checked_at = ?, last_error = ? WHERE id = ?")
                .bind(ts)
                .bind(&msg)
                .bind(id)
                .execute(pool)
                .await?;
            tracing::warn!(list = %list.name, "Sperrliste laden: {msg}");
            Ok(Some(msg))
        }
    }
}

/// Aktive Listen, die neu geladen werden sollten: noch nie versucht, älter als das
/// Intervall oder (nach einem Fehler) älter als eine Stunde. `force` = alle aktiven.
pub async fn due(pool: &SqlitePool, interval_secs: i64, force: bool) -> AppResult<Vec<i64>> {
    let ts = now();
    Ok(sqlx::query_scalar(
        "SELECT id FROM block_lists WHERE enabled = 1 AND (
            ? OR last_checked_at IS NULL
            OR (last_error IS NULL AND last_checked_at <= ?)
            OR (last_error IS NOT NULL AND last_checked_at <= ?))
         ORDER BY id",
    )
    .bind(force)
    .bind(ts - interval_secs)
    .bind(ts - RETRY_AFTER_ERROR_SECS)
    .fetch_all(pool)
    .await?)
}

/// Fällige Listen nacheinander laden (`force` = alle aktiven); läuft schon ein Laden,
/// wartet es darauf. Liefert die Zahl geladener Listen.
pub async fn update_due(
    pool: &SqlitePool,
    config: &Config,
    engine: &Engine,
    updater: &Updater,
    force: bool,
) -> AppResult<usize> {
    let _guard = updater.0.lock.lock().await;
    let result = async {
        let interval = i64::from(engine.settings().blocklist_update_hours.clamp(1, 168)) * 3600;
        let mut done = 0;
        for id in due(pool, interval, force).await? {
            updater.mark_updating();
            match download(pool, config, engine, id).await {
                Ok(_) => done += 1,
                Err(AppError::NotFound) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(done)
    }
    .await;
    updater.0.updating.store(false, Ordering::Relaxed);
    result
}

/// Eine Liste sofort laden (neu angelegt oder neue Adresse) – nacheinander mit allen anderen.
pub async fn update_one(
    pool: &SqlitePool,
    config: &Config,
    engine: &Engine,
    updater: &Updater,
    id: i64,
) -> AppResult<()> {
    let _guard = updater.0.lock.lock().await;
    updater.mark_updating();
    let result = download(pool, config, engine, id).await;
    updater.0.updating.store(false, Ordering::Relaxed);
    match result {
        Ok(_) | Err(AppError::NotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Überblick für die Oberfläche.
pub async fn status(
    pool: &SqlitePool,
    engine: &Engine,
    updater: &Updater,
) -> AppResult<BlockingStatus> {
    let dns = engine.settings();
    let lists = list(pool).await?;
    let interval = i64::from(dns.blocklist_update_hours.clamp(1, 168)) * 3600;
    let (last_update_at, next_update_at): (Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT
            (SELECT max(last_updated_at) FROM block_lists),
            (SELECT min(CASE
                WHEN last_checked_at IS NULL THEN ?1
                WHEN last_error IS NOT NULL THEN last_checked_at + ?3
                ELSE last_checked_at + ?2 END)
             FROM block_lists WHERE enabled = 1)",
    )
    .bind(now())
    .bind(interval)
    .bind(RETRY_AFTER_ERROR_SECS)
    .fetch_one(pool)
    .await?;
    Ok(BlockingStatus {
        enabled: dns.blocking_enabled,
        paused_until: settings::paused_until(pool).await?,
        total_domains: engine.blocked_domain_count(),
        lists,
        custom_blocked: domains::count(pool, domains::Kind::Blocked).await?,
        allowed: domains::count(pool, domains::Kind::Allowed).await?,
        last_update_at,
        next_update_at,
        updating: updater.updating(),
    })
}

/// Sperren für `minutes` Minuten aussetzen (0 = fortsetzen), gespeichert über Neustarts.
pub async fn pause(pool: &SqlitePool, engine: &Engine, minutes: u32) -> AppResult<()> {
    if minutes > 7 * 24 * 60 {
        return Err(AppError::bad("Pause: höchstens 7 Tage (10080 Minuten)."));
    }
    let until = (minutes > 0).then(|| now() + i64::from(minutes) * 60);
    settings::set_paused_until(pool, until).await?;
    engine.pause_blocking(until);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_from_urls() {
        let n = |url: &str| list_name("", url).unwrap();
        assert_eq!(
            n("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
            "StevenBlack Unified"
        );
        assert_eq!(
            n("https://example.org/lists/ads.txt?x=1"),
            "ads.txt (example.org)"
        );
        assert_eq!(n("http://example.org"), "example.org");
        assert_eq!(n("http://example.org/"), "example.org");
        assert_eq!(list_name(" Eigene ", "https://x.org/a").unwrap(), "Eigene");
    }

    #[test]
    fn urls() {
        assert!(validate_url("https://example.org/list.txt").is_ok());
        assert!(validate_url("http://10.0.0.1:8080/hosts").is_ok());
        for bad in [
            "",
            "ftp://example.org/x",
            "https://",
            "https://exa mple.org/",
            "example.org",
        ] {
            assert!(validate_url(bad).is_err(), "{bad}");
        }
    }
}
