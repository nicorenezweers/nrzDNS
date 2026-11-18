//! Abfrageprotokoll: blättern mit Filtern, als CSV herunterladen, leeren.

use super::Download;
use crate::auth::{AdminUser, CurrentUser};
use crate::db::now;
use crate::error::AppResult;
use crate::services::querylog;
use nrzdns_types::{QueryLogFilter, QueryLogPage};
use rocket::http::{ContentType, Status};
use rocket::serde::json::Json;
use rocket::{delete, get, routes, FromForm, Route, State};
use sqlx::SqlitePool;

pub fn routes() -> Vec<Route> {
    routes![list, export, clear]
}

/// Query-Parameter wie [`QueryLogFilter`] (alle optional, leer = egal).
#[derive(FromForm, Default)]
struct Params<'r> {
    page: Option<u32>,
    #[field(name = "perPage")]
    #[field(name = "per_page")]
    per_page: Option<u32>,
    client: Option<&'r str>,
    qname: Option<&'r str>,
    qtype: Option<&'r str>,
    kind: Option<&'r str>,
    rcode: Option<&'r str>,
    from: Option<i64>,
    to: Option<i64>,
}

impl Params<'_> {
    fn filter(&self) -> AppResult<QueryLogFilter> {
        let d = QueryLogFilter::default();
        let s = |v: Option<&str>| v.unwrap_or_default().to_string();
        Ok(QueryLogFilter {
            page: self.page.unwrap_or(d.page),
            per_page: self.per_page.unwrap_or(d.per_page),
            client: s(self.client),
            qname: s(self.qname),
            qtype: s(self.qtype),
            kind: querylog::parse_kind(self.kind.unwrap_or_default())?,
            rcode: s(self.rcode),
            from: self.from,
            to: self.to,
        })
    }
}

/// Neueste zuerst.
#[get("/logs?<params..>")]
async fn list(
    _user: CurrentUser,
    params: Params<'_>,
    pool: &State<SqlitePool>,
) -> AppResult<Json<QueryLogPage>> {
    Ok(Json(querylog::page(pool, params.filter()?).await?))
}

/// CSV mit denselben Filtern, höchstens 100 000 Zeilen.
#[get("/logs/export?<params..>")]
async fn export(
    _user: CurrentUser,
    params: Params<'_>,
    pool: &State<SqlitePool>,
) -> AppResult<Download> {
    let body = querylog::export_csv(pool, params.filter()?).await?;
    let stamp = time::OffsetDateTime::from_unix_timestamp(now())
        .ok()
        .and_then(|t| {
            t.format(time::macros::format_description!(
                "[year][month][day]-[hour][minute]"
            ))
            .ok()
        })
        .unwrap_or_default();
    Ok(Download {
        filename: format!("nrzdns-abfragen-{stamp}.csv"),
        content_type: ContentType::CSV.with_params(("charset", "utf-8")),
        body,
    })
}

/// Ganzes Abfrageprotokoll leeren.
#[delete("/logs")]
async fn clear(admin: AdminUser, pool: &State<SqlitePool>) -> AppResult<Status> {
    let n = querylog::clear(pool).await?;
    tracing::info!(entries = n, by = %admin.0.username, "Abfrageprotokoll geleert");
    Ok(Status::NoContent)
}
