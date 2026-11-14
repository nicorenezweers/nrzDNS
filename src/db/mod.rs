//! Die eine Datenbank: SQLite (WAL). Konten, Einstellungen, Zonen, Listen und Abfrageprotokoll.

use crate::config::Config;
use crate::error::AppError;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;
use std::time::Duration;

/// Jetzt als Unix-Sekunden (UTC).
pub fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// Jetzt in Unix-Millisekunden.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Öffnet (bzw. erstellt) die Datenbank.
pub async fn open(config: &Config) -> Result<SqlitePool, AppError> {
    std::fs::create_dir_all(&config.data_dir)?;
    let options = SqliteConnectOptions::new()
        .filename(config.database_path())
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(10));
    Ok(SqlitePoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(15))
        .connect_with(options)
        .await?)
}

/// Schema auf den neuesten Stand bringen. Die Migrationen (`migrations/`) sind ins Programm
/// eingebettet; sqlx merkt sich in `_sqlx_migrations`, was schon gelaufen ist.
pub async fn migrate(pool: &SqlitePool) -> Result<(), AppError> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| AppError::Config(format!("Migration fehlgeschlagen: {e}")))
}

/// Öffnen und migrieren in einem Schritt.
pub async fn connect(config: &Config) -> Result<SqlitePool, AppError> {
    let pool = open(config).await?;
    if let Err(e) = migrate(&pool).await {
        pool.close().await;
        return Err(e);
    }
    Ok(pool)
}
