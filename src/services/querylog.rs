//! Abfrageprotokoll: speichern (gebündelt aus dem Kanal der Engine), durchsuchen, als CSV
//! ausgeben, aufräumen.

use crate::error::{AppError, AppResult};
use futures::TryStreamExt;
use nrzdns_types::{Protocol, QueryLogEntry, QueryLogFilter, QueryLogPage, ResponseKind};
use sqlx::{QueryBuilder, Sqlite, SqlitePool};

/// Höchstens so viele Zeilen im CSV-Export.
pub const EXPORT_MAX_ROWS: u32 = 100_000;
/// So viele Zeilen löscht das Aufräumen auf einmal (hält die Sperre der Datenbank kurz).
const PURGE_CHUNK: i64 = 10_000;

/// Einträge in einer Transaktion speichern.
pub async fn insert_batch(pool: &SqlitePool, entries: &[QueryLogEntry]) -> AppResult<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    for e in entries {
        sqlx::query(
            "INSERT INTO query_log (at_ms, client, protocol, qname, qtype, rcode, kind, answer,
                duration_ms, upstream)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(e.at_ms)
        .bind(&e.client)
        .bind(e.protocol.as_str())
        .bind(&e.qname)
        .bind(&e.qtype)
        .bind(&e.rcode)
        .bind(e.kind.as_str())
        .bind(&e.answer)
        .bind(e.duration_ms)
        .bind(&e.upstream)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Einträge vor diesem Zeitpunkt (Unix-Millisekunden) löschen, in Häppchen.
pub async fn purge_before(pool: &SqlitePool, cutoff_ms: i64) -> AppResult<u64> {
    let mut total = 0;
    loop {
        let n = sqlx::query(
            "DELETE FROM query_log WHERE id IN (SELECT id FROM query_log WHERE at_ms < ? LIMIT ?)",
        )
        .bind(cutoff_ms)
        .bind(PURGE_CHUNK)
        .execute(pool)
        .await?
        .rows_affected();
        total += n;
        if n < PURGE_CHUNK as u64 {
            return Ok(total);
        }
    }
}

/// Ganzes Protokoll leeren.
pub async fn clear(pool: &SqlitePool) -> AppResult<u64> {
    Ok(sqlx::query("DELETE FROM query_log")
        .execute(pool)
        .await?
        .rows_affected())
}

#[derive(sqlx::FromRow)]
struct LogRow {
    id: i64,
    at_ms: i64,
    client: String,
    protocol: String,
    qname: String,
    qtype: String,
    rcode: String,
    kind: String,
    answer: String,
    duration_ms: i64,
    upstream: String,
}

impl LogRow {
    fn into_entry(self) -> QueryLogEntry {
        QueryLogEntry {
            id: self.id,
            at_ms: self.at_ms,
            client: self.client,
            protocol: match self.protocol.as_str() {
                "tcp" => Protocol::Tcp,
                "https" => Protocol::Https,
                _ => Protocol::Udp,
            },
            qname: self.qname,
            qtype: self.qtype,
            rcode: self.rcode,
            kind: ResponseKind::parse(&self.kind).unwrap_or_default(),
            answer: self.answer,
            duration_ms: u32::try_from(self.duration_ms).unwrap_or_default(),
            upstream: self.upstream,
        }
    }
}

/// Filter auf gültige Werte bringen: Seite ab 1, 10–500 je Seite, Typ und Antwortcode gross.
pub fn normalize_filter(mut f: QueryLogFilter) -> QueryLogFilter {
    f.page = f.page.max(1);
    f.per_page = f.per_page.clamp(10, 500);
    f.client = f.client.trim().to_string();
    f.qname = f.qname.trim().trim_end_matches('.').to_ascii_lowercase();
    f.qtype = f.qtype.trim().to_ascii_uppercase();
    f.rcode = f.rcode.trim().to_ascii_uppercase();
    f
}

/// `WHERE …` für die Filter anhängen.
fn push_where(qb: &mut QueryBuilder<Sqlite>, f: &QueryLogFilter) {
    qb.push(" WHERE 1 = 1");
    if !f.client.is_empty() {
        qb.push(" AND client = ").push_bind(f.client.clone());
    }
    if !f.qname.is_empty() {
        let pattern = format!(
            "%{}%",
            f.qname
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        qb.push(" AND qname LIKE ")
            .push_bind(pattern)
            .push(" ESCAPE '\\'");
    }
    if !f.qtype.is_empty() {
        qb.push(" AND qtype = ").push_bind(f.qtype.clone());
    }
    if let Some(kind) = f.kind {
        qb.push(" AND kind = ").push_bind(kind.as_str());
    }
    if !f.rcode.is_empty() {
        qb.push(" AND rcode = ").push_bind(f.rcode.clone());
    }
    if let Some(from) = f.from {
        qb.push(" AND at_ms >= ")
            .push_bind(from.saturating_mul(1000));
    }
    if let Some(to) = f.to {
        // „bis“ schliesst die ganze Sekunde ein
        qb.push(" AND at_ms < ")
            .push_bind(to.saturating_add(1).saturating_mul(1000));
    }
}

const COLUMNS: &str = "SELECT id, at_ms, client, protocol, qname, qtype, rcode, kind, answer, \
                       duration_ms, upstream FROM query_log";

/// Eine Seite, neueste zuerst.
pub async fn page(pool: &SqlitePool, filter: QueryLogFilter) -> AppResult<QueryLogPage> {
    let f = normalize_filter(filter);
    let mut count: QueryBuilder<Sqlite> = QueryBuilder::new("SELECT count(*) FROM query_log");
    push_where(&mut count, &f);
    let total: i64 = count.build_query_scalar().fetch_one(pool).await?;

    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(COLUMNS);
    push_where(&mut qb, &f);
    qb.push(" ORDER BY at_ms DESC, id DESC LIMIT ")
        .push_bind(i64::from(f.per_page))
        .push(" OFFSET ")
        .push_bind(i64::from(f.page - 1) * i64::from(f.per_page));
    let rows: Vec<LogRow> = qb.build_query_as().fetch_all(pool).await?;
    Ok(QueryLogPage {
        entries: rows.into_iter().map(LogRow::into_entry).collect(),
        total: u64::try_from(total).unwrap_or_default(),
        page: f.page,
        per_page: f.per_page,
    })
}

/// CSV mit denselben Filtern (ohne Seiten), neueste zuerst, höchstens [`EXPORT_MAX_ROWS`].
pub async fn export_csv(pool: &SqlitePool, filter: QueryLogFilter) -> AppResult<String> {
    let f = normalize_filter(filter);
    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(COLUMNS);
    push_where(&mut qb, &f);
    qb.push(" ORDER BY at_ms DESC, id DESC LIMIT ")
        .push_bind(i64::from(EXPORT_MAX_ROWS));
    let mut out =
        String::from("time,client,protocol,qname,qtype,rcode,kind,answer,duration_ms,upstream\r\n");
    let mut rows = qb.build_query_as::<LogRow>().fetch(pool);
    while let Some(row) = rows.try_next().await? {
        let e = row.into_entry();
        let fields = [
            iso_time(e.at_ms),
            e.client,
            e.protocol.as_str().to_string(),
            e.qname,
            e.qtype,
            e.rcode,
            e.kind.as_str().to_string(),
            e.answer,
            e.duration_ms.to_string(),
            e.upstream,
        ];
        for (i, field) in fields.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&csv_field(field));
        }
        out.push_str("\r\n");
    }
    Ok(out)
}

/// `2026-10-31T12:00:00.123Z`
fn iso_time(at_ms: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(at_ms) * 1_000_000)
        .ok()
        .and_then(|t| {
            t.format(time::macros::format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
            ))
            .ok()
        })
        .unwrap_or_default()
}

/// Feld für CSV (RFC 4180). Was eine Tabellenkalkulation als Formel lesen würde
/// (`=`, `+`, `-`, `@` am Anfang), bekommt ein `'` davor – Namen und Antworten kommen
/// schliesslich von beliebigen Clients im Netz.
fn csv_field(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

/// Antwortart aus einem Query-Parameter (leer = alle).
pub fn parse_kind(s: &str) -> AppResult<Option<ResponseKind>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    ResponseKind::parse(&s.to_ascii_lowercase())
        .map(Some)
        .ok_or_else(|| AppError::bad("Unbekannte Antwortart."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_escaping() {
        assert_eq!(csv_field("example.com"), "example.com");
        assert_eq!(csv_field("a, b"), "\"a, b\"");
        assert_eq!(csv_field("sagt \"hi\""), "\"sagt \"\"hi\"\"\"");
        assert_eq!(csv_field("=1+1"), "'=1+1");
        assert_eq!(iso_time(1_700_000_000_123), "2023-11-14T22:13:20.123Z");
    }
}
