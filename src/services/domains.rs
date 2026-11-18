//! Eigene Sperren und Ausnahmen (`custom_domains`). Beide gelten für die Domain und alle
//! Subdomains; Ausnahmen schlagen jede Sperre. Nach jeder Änderung bekommt die Engine die
//! ganze Liste (siehe `services::sync`).

use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::services::zones::MAX_COMMENT;
use nrzdns_types::{normalize_domain, DomainEntry, DomainInput};
use sqlx::SqlitePool;

/// Welche Liste.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Blocked,
    Allowed,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Blocked => "blocked",
            Kind::Allowed => "allowed",
        }
    }
}

/// Domain aus Eingabe oder Pfad prüfen und vereinheitlichen.
pub fn domain(input: &str) -> AppResult<String> {
    normalize_domain(input).ok_or_else(|| {
        AppError::bad("Domain: bitte einen gültigen Namen angeben, z. B. ads.example.com.")
    })
}

/// Alle Einträge, alphabetisch.
pub async fn list(pool: &SqlitePool, kind: Kind) -> AppResult<Vec<DomainEntry>> {
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT domain, comment, created_at FROM custom_domains WHERE kind = ? ORDER BY domain",
    )
    .bind(kind.as_str())
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(domain, comment, created_at)| DomainEntry {
            domain,
            comment,
            created_at,
        })
        .collect())
}

/// Nur die Domains (für die Engine).
pub async fn names(pool: &SqlitePool, kind: Kind) -> AppResult<Vec<String>> {
    Ok(
        sqlx::query_scalar("SELECT domain FROM custom_domains WHERE kind = ? ORDER BY domain")
            .bind(kind.as_str())
            .fetch_all(pool)
            .await?,
    )
}

pub async fn count(pool: &SqlitePool, kind: Kind) -> AppResult<u32> {
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM custom_domains WHERE kind = ?")
        .bind(kind.as_str())
        .fetch_one(pool)
        .await?;
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

pub async fn add(pool: &SqlitePool, kind: Kind, input: &DomainInput) -> AppResult<DomainEntry> {
    let domain = domain(&input.domain)?;
    let comment = input.comment.trim();
    if comment.chars().count() > MAX_COMMENT || comment.chars().any(char::is_control) {
        return Err(AppError::bad(format!(
            "Kommentar: höchstens {MAX_COMMENT} Zeichen, ohne Steuerzeichen."
        )));
    }
    let created_at = now();
    sqlx::query(
        "INSERT INTO custom_domains (kind, domain, comment, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(kind.as_str())
    .bind(&domain)
    .bind(comment)
    .bind(created_at)
    .execute(pool)
    .await
    .map_err(|e| AppError::unique(e, "Diese Domain steht schon in der Liste."))?;
    Ok(DomainEntry {
        domain,
        comment: comment.to_string(),
        created_at,
    })
}

pub async fn remove(pool: &SqlitePool, kind: Kind, input: &str) -> AppResult<()> {
    let domain = domain(input)?;
    let done = sqlx::query("DELETE FROM custom_domains WHERE kind = ? AND domain = ?")
        .bind(kind.as_str())
        .bind(&domain)
        .execute(pool)
        .await?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}
