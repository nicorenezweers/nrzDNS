//! Dashboard: Summen, lückenlose Reihe und Top-Listen aus dem Abfrageprotokoll.

mod common;

use common::{engine, get, log_entry, login_as, pool};
use nrzdns::services::{dashboard, querylog};
use nrzdns_types::{Dashboard, ResponseKind, StatsRange, TopEntry};
use rocket::http::Status;

fn top(list: &[TopEntry]) -> Vec<(&str, u64)> {
    list.iter().map(|t| (t.name.as_str(), t.hits)).collect()
}

#[rocket::async_test]
async fn aggregates_over_the_range() {
    let (client, _dir) = common::client().await;
    let db = pool(&client);
    // „Jetzt“ fest: 2026-10-31 12:30:00 UTC; der Tag beginnt im Abschnitt 13:00 des Vortags
    let now = 1_793_449_800;
    let hour = 3600;
    let (start, _, _) = dashboard::window(StatsRange::Day, now);
    assert_eq!(start, now - 30 * 60 - 23 * hour);

    let at = |secs: i64| secs * 1000;
    let mut rows = Vec::new();
    // Aktueller Abschnitt: 3 Anfragen von .10 (eine gesperrt, eine aus dem Cache)
    let mut e = log_entry(at(now - 60), "192.168.1.10", "example.com");
    e.duration_ms = 30;
    rows.push(e);
    let mut e = log_entry(at(now - 120), "192.168.1.10", "ads.tracker.org");
    e.kind = ResponseKind::Blocked;
    e.rcode = "NXDOMAIN".into();
    e.duration_ms = 0;
    rows.push(e);
    let mut e = log_entry(at(now - 180), "192.168.1.10", "example.com");
    e.kind = ResponseKind::Cached;
    e.qtype = "AAAA".into();
    e.duration_ms = 0;
    rows.push(e);
    // Vor fünf Stunden: .20 mit SERVFAIL und eine eigene Zone
    let mut e = log_entry(at(now - 5 * hour), "192.168.1.20", "kaputt.example");
    e.rcode = "SERVFAIL".into();
    e.kind = ResponseKind::Failed;
    e.duration_ms = 2000;
    rows.push(e);
    let mut e = log_entry(at(now - 5 * hour - 10), "192.168.1.20", "nas.home.arpa");
    e.kind = ResponseKind::Authoritative;
    e.duration_ms = 1;
    rows.push(e);
    // Erster Abschnitt (genau am Beginn) zählt, davor nicht mehr
    rows.push(log_entry(at(start), "192.168.1.30", "early.example"));
    rows.push(log_entry(at(start - 1), "192.168.1.40", "too-old.example"));
    // Verworfen (Rate-Limit)
    let mut e = log_entry(at(now - 10), "10.0.0.66", "flood.example");
    e.kind = ResponseKind::Dropped;
    e.rcode = "REFUSED".into();
    e.duration_ms = 0;
    rows.push(e);
    querylog::insert_batch(db, &rows).await.unwrap();

    let d = dashboard::build_at(db, engine(&client), StatsRange::Day, now)
        .await
        .unwrap();
    assert_eq!(d.range, StatsRange::Day);
    let t = &d.totals;
    assert_eq!(t.queries, 7);
    assert_eq!(
        (t.no_error, t.nx_domain, t.server_failure, t.refused),
        (4, 1, 1, 1)
    );
    assert_eq!(
        (
            t.authoritative,
            t.forwarded,
            t.cached,
            t.blocked,
            t.local,
            t.dropped
        ),
        (1, 2, 1, 1, 0, 1)
    );
    assert_eq!(t.clients, 4);
    // (30 + 0 + 0 + 2000 + 1 + 12 + 0) / 7
    assert!(
        (t.avg_duration_ms - 291.9).abs() < 0.01,
        "{}",
        t.avg_duration_ms
    );

    // 24 Abschnitte je Stunde, lückenlos
    assert_eq!(d.series.len(), 24);
    assert!(d.series.windows(2).all(|w| w[1].at - w[0].at == hour));
    assert_eq!(d.series[0].at, start);
    let first = &d.series[0];
    assert_eq!((first.total, first.forwarded), (1, 1));
    let last = &d.series[23];
    assert_eq!(
        (
            last.total,
            last.blocked,
            last.cached,
            last.forwarded,
            last.failed
        ),
        (4, 1, 1, 1, 1),
        "gesperrt zählt nicht als Fehler, verworfen schon"
    );
    let five = &d.series[18];
    assert_eq!((five.total, five.authoritative, five.failed), (2, 1, 1));
    let sum: u64 = d.series.iter().map(|p| p.total).sum();
    assert_eq!(sum, t.queries);
    assert!(d.series[1..18].iter().all(|p| p.total == 0));

    assert_eq!(
        top(&d.top_clients),
        [
            ("192.168.1.10", 3),
            ("192.168.1.20", 2),
            ("10.0.0.66", 1),
            ("192.168.1.30", 1)
        ]
    );
    assert_eq!(top(&d.top_domains)[0], ("example.com", 2));
    assert!(!top(&d.top_domains)
        .iter()
        .any(|(n, _)| *n == "ads.tracker.org"));
    assert_eq!(top(&d.top_blocked), [("ads.tracker.org", 1)]);
    assert_eq!(top(&d.query_types), [("A", 6), ("AAAA", 1)]);
    assert_eq!(d.server.version, env!("CARGO_PKG_VERSION"));

    // Andere Zeiträume: Anzahl der Abschnitte
    for (range, n) in [
        (StatsRange::Hour, 60),
        (StatsRange::Week, 28),
        (StatsRange::Month, 30),
    ] {
        let d = dashboard::build_at(db, engine(&client), range, now)
            .await
            .unwrap();
        assert_eq!(d.series.len(), n, "{range:?}");
        assert_eq!(
            d.series.iter().map(|p| p.total).sum::<u64>(),
            d.totals.queries
        );
    }
    let hour_view = dashboard::build_at(db, engine(&client), StatsRange::Hour, now)
        .await
        .unwrap();
    assert_eq!(hour_view.totals.queries, 4);
    client.terminate().await;
}

#[rocket::async_test]
async fn dashboard_endpoint() {
    let (client, _dir) = common::client().await;
    login_as(&client, "mia", false).await;
    let now_ms = nrzdns::db::now() * 1000;
    querylog::insert_batch(pool(&client), &[log_entry(now_ms, "10.0.0.1", "a.example")])
        .await
        .unwrap();
    for (url, range, n) in [
        ("/api/v1/dashboard", StatsRange::Day, 24),
        ("/api/v1/dashboard?range=hour", StatsRange::Hour, 60),
        ("/api/v1/dashboard?range=month", StatsRange::Month, 30),
    ] {
        let (s, v) = get(&client, url).await;
        assert_eq!(s, Status::Ok, "{url}: {v}");
        let d: Dashboard = serde_json::from_value(v).unwrap();
        assert_eq!(
            (d.range, d.series.len(), d.totals.queries),
            (range, n, 1),
            "{url}"
        );
    }
    let (s, v) = get(&client, "/api/v1/dashboard?range=year").await;
    assert_eq!(s, Status::BadRequest, "{v}");
    assert_eq!(v["error"]["message"], "Unbekannter Zeitraum.");
    client.terminate().await;
}
