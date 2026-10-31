//! Dashboard: Zahlen aus dem Abfrageprotokoll für einen Zeitraum.
//!
//! Der Zeitraum besteht aus `span / bucket` Abschnitten, an den Grenzen der Abschnitte (UTC)
//! ausgerichtet; der letzte enthält „jetzt“. Summen und Top-Listen zählen genau über diese
//! Abschnitte, damit sie zum Diagramm passen.

use crate::db::now;
use crate::error::AppResult;
use nrzdns_engine::Engine;
use nrzdns_types::{Dashboard, StatsPoint, StatsRange, StatsTotals, TopEntry};
use sqlx::SqlitePool;

/// Einträge je Top-Liste.
pub const TOP: i64 = 10;

/// Beginn des ersten Abschnitts und Anzahl der Abschnitte.
pub fn window(range: StatsRange, now: i64) -> (i64, i64, i64) {
    let (span, bucket) = range.span_and_bucket();
    let n = span / bucket;
    let start = now.div_euclid(bucket) * bucket - (n - 1) * bucket;
    (start, bucket, n)
}

pub async fn build(pool: &SqlitePool, engine: &Engine, range: StatsRange) -> AppResult<Dashboard> {
    build_at(pool, engine, range, now()).await
}

/// Wie [`build`], mit vorgegebenem „jetzt“ (Tests).
pub async fn build_at(
    pool: &SqlitePool,
    engine: &Engine,
    range: StatsRange,
    now: i64,
) -> AppResult<Dashboard> {
    let (start, bucket, n) = window(range, now);
    let from_ms = start * 1000;
    let to_ms = (now + 1) * 1000;
    Ok(Dashboard {
        range,
        totals: totals(pool, from_ms, to_ms).await?,
        series: series(pool, start, bucket, n, to_ms).await?,
        top_clients: top(pool, "client", "1 = 1", from_ms, to_ms).await?,
        top_domains: top(pool, "qname", "kind <> 'blocked'", from_ms, to_ms).await?,
        top_blocked: top(pool, "qname", "kind = 'blocked'", from_ms, to_ms).await?,
        query_types: top(pool, "qtype", "1 = 1", from_ms, to_ms).await?,
        server: engine.status(),
    })
}

fn u(v: i64) -> u64 {
    u64::try_from(v).unwrap_or_default()
}

async fn totals(pool: &SqlitePool, from_ms: i64, to_ms: i64) -> AppResult<StatsTotals> {
    #[derive(sqlx::FromRow)]
    struct Row {
        queries: i64,
        no_error: i64,
        nx_domain: i64,
        server_failure: i64,
        refused: i64,
        authoritative: i64,
        forwarded: i64,
        cached: i64,
        blocked: i64,
        local: i64,
        dropped: i64,
        failed: i64,
        clients: i64,
        avg_duration_ms: f64,
    }
    let r: Row = sqlx::query_as(
        "SELECT count(*) AS queries,
            coalesce(sum(rcode = 'NOERROR'), 0) AS no_error,
            coalesce(sum(rcode = 'NXDOMAIN'), 0) AS nx_domain,
            coalesce(sum(rcode = 'SERVFAIL'), 0) AS server_failure,
            coalesce(sum(rcode = 'REFUSED'), 0) AS refused,
            coalesce(sum(kind = 'authoritative'), 0) AS authoritative,
            coalesce(sum(kind = 'forwarded'), 0) AS forwarded,
            coalesce(sum(kind = 'cached'), 0) AS cached,
            coalesce(sum(kind = 'blocked'), 0) AS blocked,
            coalesce(sum(kind = 'local'), 0) AS local,
            coalesce(sum(kind = 'dropped'), 0) AS dropped,
            coalesce(sum(kind = 'failed'), 0) AS failed,
            count(DISTINCT client) AS clients,
            coalesce(avg(duration_ms), 0.0) AS avg_duration_ms
         FROM query_log WHERE at_ms >= ? AND at_ms < ?",
    )
    .bind(from_ms)
    .bind(to_ms)
    .fetch_one(pool)
    .await?;
    Ok(StatsTotals {
        queries: u(r.queries),
        no_error: u(r.no_error),
        nx_domain: u(r.nx_domain),
        server_failure: u(r.server_failure),
        refused: u(r.refused),
        authoritative: u(r.authoritative),
        forwarded: u(r.forwarded),
        cached: u(r.cached),
        blocked: u(r.blocked),
        local: u(r.local),
        dropped: u(r.dropped),
        failed: u(r.failed),
        clients: u(r.clients),
        avg_duration_ms: (r.avg_duration_ms * 10.0).round() / 10.0,
    })
}

/// Lückenlose Reihe: Abschnitte ohne Anfragen kommen mit 0.
async fn series(
    pool: &SqlitePool,
    start: i64,
    bucket: i64,
    n: i64,
    to_ms: i64,
) -> AppResult<Vec<StatsPoint>> {
    let mut points: Vec<StatsPoint> = (0..n)
        .map(|i| StatsPoint {
            at: start + i * bucket,
            ..StatsPoint::default()
        })
        .collect();
    let rows: Vec<(i64, i64, i64, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT (at_ms / 1000 - ?1) / ?2 AS idx, count(*),
            coalesce(sum(kind = 'blocked'), 0),
            coalesce(sum(kind = 'cached'), 0),
            coalesce(sum(kind = 'forwarded'), 0),
            coalesce(sum(kind = 'authoritative'), 0),
            coalesce(sum(kind <> 'blocked' AND (rcode IN ('NXDOMAIN', 'SERVFAIL') OR kind = 'dropped')), 0)
         FROM query_log WHERE at_ms >= ?1 * 1000 AND at_ms < ?3
         GROUP BY idx",
    )
    .bind(start)
    .bind(bucket)
    .bind(to_ms)
    .fetch_all(pool)
    .await?;
    for (idx, total, blocked, cached, forwarded, authoritative, failed) in rows {
        if let Some(p) = usize::try_from(idx).ok().and_then(|i| points.get_mut(i)) {
            p.total = u(total);
            p.blocked = u(blocked);
            p.cached = u(cached);
            p.forwarded = u(forwarded);
            p.authoritative = u(authoritative);
            p.failed = u(failed);
        }
    }
    Ok(points)
}

/// Häufigste Werte einer Spalte (`column` und `condition` sind feste Zeichenketten aus
/// diesem Modul, nie Eingaben).
async fn top(
    pool: &SqlitePool,
    column: &'static str,
    condition: &'static str,
    from_ms: i64,
    to_ms: i64,
) -> AppResult<Vec<TopEntry>> {
    let sql = format!(
        "SELECT {column}, count(*) AS hits FROM query_log
         WHERE at_ms >= ? AND at_ms < ? AND {condition}
         GROUP BY {column} ORDER BY hits DESC, {column} LIMIT ?"
    );
    let rows: Vec<(String, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(from_ms)
        .bind(to_ms)
        .bind(TOP)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(name, hits)| TopEntry {
            name,
            hits: u(hits),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows() {
        // 2026-10-31 12:34:56 UTC
        let now = 1_793_449_696;
        let (start, bucket, n) = window(StatsRange::Day, now);
        assert_eq!((bucket, n), (3600, 24));
        assert_eq!(start % 3600, 0);
        assert!(start + (n - 1) * bucket <= now && now < start + n * bucket);
        let (start, bucket, n) = window(StatsRange::Week, now);
        assert_eq!((bucket, n), (6 * 3600, 28));
        assert_eq!(start % (6 * 3600), 0);
        assert!(now < start + n * bucket);
        let (_, bucket, n) = window(StatsRange::Hour, now);
        assert_eq!((bucket, n), (60, 60));
        let (start, _, n) = window(StatsRange::Month, now);
        assert_eq!((start % 86_400, n), (0, 30));
    }
}
