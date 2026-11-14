//! Sperrseite: Domains auf Zeit freischalten (`temp_unlocks`) und dauerhafte Ausnahmen
//! beantragen (`allow_requests`). Freigeschaltete Domains bekommt die Engine zusammen mit den
//! Ausnahmen (siehe `services::sync::push_domains`); abgelaufene räumt [`purge_expired`] weg.

use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::services::domains::{self, Kind};
use nrzdns_types::{normalize_domain, AllowRequest, DomainInput, RequestStatus, TempUnlock};
use sqlx::SqlitePool;

/// Höchstens so lange (Minuten).
pub const MAX_MINUTES: u32 = 1440;
/// Begründung höchstens so lang.
pub const MAX_REASON: usize = 500;

fn domain(input: &str) -> AppResult<String> {
    normalize_domain(input)
        .ok_or_else(|| AppError::bad("Domain: bitte einen gültigen Namen angeben."))
}

/// Gerade freigeschaltete Domains.
pub async fn active(pool: &SqlitePool) -> AppResult<Vec<TempUnlock>> {
    let rows: Vec<(String, i64, String, i64)> = sqlx::query_as(
        "SELECT domain, until, client, created_at FROM temp_unlocks WHERE until > ? ORDER BY until",
    )
    .bind(now())
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(domain, until, client, created_at)| TempUnlock {
            domain,
            until,
            client,
            created_at,
        })
        .collect())
}

pub async fn active_names(pool: &SqlitePool) -> AppResult<Vec<String>> {
    Ok(active(pool).await?.into_iter().map(|u| u.domain).collect())
}

/// Für `minutes` freischalten (eine schon längere Freischaltung bleibt).
pub async fn unlock(
    pool: &SqlitePool,
    input: &str,
    minutes: u32,
    client: &str,
) -> AppResult<TempUnlock> {
    let domain = domain(input)?;
    if minutes == 0 || minutes > MAX_MINUTES {
        return Err(AppError::bad("Zeitraum: 1 bis 1440 Minuten."));
    }
    let t = now();
    let until = t + i64::from(minutes) * 60;
    sqlx::query(
        "INSERT INTO temp_unlocks (domain, until, client, created_at) VALUES (?, ?, ?, ?)
         ON CONFLICT (domain) DO UPDATE SET
           until = max(temp_unlocks.until, excluded.until),
           client = excluded.client, created_at = excluded.created_at",
    )
    .bind(&domain)
    .bind(until)
    .bind(client)
    .bind(t)
    .execute(pool)
    .await?;
    Ok(TempUnlock {
        domain,
        until,
        client: client.to_string(),
        created_at: t,
    })
}

pub async fn end(pool: &SqlitePool, input: &str) -> AppResult<()> {
    let domain = domain(input)?;
    let done = sqlx::query("DELETE FROM temp_unlocks WHERE domain = ?")
        .bind(&domain)
        .execute(pool)
        .await?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Abgelaufene löschen; liefert, wie viele.
pub async fn purge_expired(pool: &SqlitePool) -> AppResult<u64> {
    Ok(sqlx::query("DELETE FROM temp_unlocks WHERE until <= ?")
        .bind(now())
        .execute(pool)
        .await?
        .rows_affected())
}

type ReqRow = (
    i64,
    String,
    String,
    String,
    String,
    i64,
    Option<i64>,
    String,
);

fn to_request(r: ReqRow) -> AllowRequest {
    let (id, domain, client, reason, status, created_at, decided_at, decided_by) = r;
    AllowRequest {
        id,
        domain,
        client,
        reason,
        status: match status.as_str() {
            "approved" => RequestStatus::Approved,
            "rejected" => RequestStatus::Rejected,
            _ => RequestStatus::Pending,
        },
        created_at,
        decided_at,
        decided_by,
    }
}

/// Offene zuerst, dann die letzten entschiedenen (höchstens 200).
pub async fn requests(pool: &SqlitePool) -> AppResult<Vec<AllowRequest>> {
    let rows: Vec<ReqRow> = sqlx::query_as(
        "SELECT id, domain, client, reason, status, created_at, decided_at, decided_by FROM allow_requests
         ORDER BY status = 'pending' DESC, created_at DESC LIMIT 200",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(to_request).collect())
}

async fn request(pool: &SqlitePool, id: i64) -> AppResult<AllowRequest> {
    let row: Option<ReqRow> = sqlx::query_as(
        "SELECT id, domain, client, reason, status, created_at, decided_at, decided_by FROM allow_requests WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(to_request).ok_or(AppError::NotFound)
}

/// Offener Antrag für diese Domain?
pub async fn pending_for(pool: &SqlitePool, input: &str) -> AppResult<Option<AllowRequest>> {
    let domain = domain(input)?;
    let row: Option<ReqRow> = sqlx::query_as(
        "SELECT id, domain, client, reason, status, created_at, decided_at, decided_by FROM allow_requests WHERE domain = ? AND status = 'pending' LIMIT 1",
    )
    .bind(&domain)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(to_request))
}

/// Antrag stellen; gibt es schon einen offenen für die Domain, wird dessen Begründung ergänzt.
pub async fn create_request(
    pool: &SqlitePool,
    input: &str,
    reason: &str,
    client: &str,
) -> AppResult<AllowRequest> {
    let domain = domain(input)?;
    let reason: String = reason
        .trim()
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(MAX_REASON)
        .collect();
    if let Some(open) = pending_for(pool, &domain).await? {
        if !reason.is_empty() && !open.reason.contains(&reason) {
            let merged: String = if open.reason.is_empty() {
                reason
            } else {
                format!("{}\n{reason}", open.reason)
            }
            .chars()
            .take(MAX_REASON * 2)
            .collect();
            sqlx::query("UPDATE allow_requests SET reason = ? WHERE id = ?")
                .bind(merged)
                .bind(open.id)
                .execute(pool)
                .await?;
        }
        return request(pool, open.id).await;
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO allow_requests (domain, client, reason, created_at) VALUES (?, ?, ?, ?) RETURNING id",
    )
    .bind(&domain)
    .bind(client)
    .bind(&reason)
    .bind(now())
    .fetch_one(pool)
    .await?;
    request(pool, id).await
}

/// Genehmigen: Domain kommt in die Ausnahmen (Kommentar mit Antragsteller und Begründung).
pub async fn approve(pool: &SqlitePool, id: i64, by: &str) -> AppResult<AllowRequest> {
    let r = request(pool, id).await?;
    if r.status != RequestStatus::Pending {
        return Err(AppError::Conflict(
            "Dieser Antrag ist schon entschieden.".into(),
        ));
    }
    let mut comment = format!("Antrag von {}", r.client);
    if !r.reason.is_empty() {
        comment.push_str(": ");
        comment.push_str(&r.reason.replace('\n', " "));
    }
    let comment: String = comment
        .chars()
        .take(crate::services::zones::MAX_COMMENT)
        .collect();
    match domains::add(
        pool,
        Kind::Allowed,
        &DomainInput {
            domain: r.domain.clone(),
            comment,
        },
    )
    .await
    {
        Ok(_) | Err(AppError::Conflict(_)) => {}
        Err(e) => return Err(e),
    }
    decide(pool, id, "approved", by).await
}

pub async fn reject(pool: &SqlitePool, id: i64, by: &str) -> AppResult<AllowRequest> {
    let r = request(pool, id).await?;
    if r.status != RequestStatus::Pending {
        return Err(AppError::Conflict(
            "Dieser Antrag ist schon entschieden.".into(),
        ));
    }
    decide(pool, id, "rejected", by).await
}

async fn decide(pool: &SqlitePool, id: i64, status: &str, by: &str) -> AppResult<AllowRequest> {
    sqlx::query(
        "UPDATE allow_requests SET status = ?, decided_at = ?, decided_by = ? WHERE id = ?",
    )
    .bind(status)
    .bind(now())
    .bind(by)
    .bind(id)
    .execute(pool)
    .await?;
    request(pool, id).await
}

pub async fn delete_request(pool: &SqlitePool, id: i64) -> AppResult<()> {
    let done = sqlx::query("DELETE FROM allow_requests WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

pub async fn pending_count(pool: &SqlitePool) -> AppResult<u32> {
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM allow_requests WHERE status = 'pending'")
        .fetch_one(pool)
        .await?;
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}
