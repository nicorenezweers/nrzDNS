//! Abfrageprotokoll: Zeilen direkt speichern, dann filtern, blättern, als CSV laden, leeren,
//! Aufräumen nach Alter.

mod common;

use common::{delete, get, log_entry, login_as, logout, pool};
use nrzdns::services::querylog;
use nrzdns_types::{Protocol, QueryLogEntry, QueryLogPage, ResponseKind};
use rocket::http::{ContentType, Status};

/// 30 Einträge im Abstand von einer Sekunde ab `base` (Unix-Sekunden): abwechselnd zwei
/// Clients, jeder fünfte gesperrt, jeder dritte AAAA.
fn sample(base: i64) -> Vec<QueryLogEntry> {
    (0..30)
        .map(|i| {
            let mut e = log_entry(
                (base + i) * 1000 + 250,
                if i % 2 == 0 {
                    "192.168.1.10"
                } else {
                    "192.168.1.20"
                },
                &format!("host{i}.example.com"),
            );
            if i % 5 == 0 {
                e.kind = ResponseKind::Blocked;
                e.qname = format!("ads{i}.tracker.org");
                e.answer = "0.0.0.0".into();
            }
            if i % 3 == 0 {
                e.qtype = "AAAA".into();
            }
            if i == 7 {
                e.rcode = "NXDOMAIN".into();
                e.protocol = Protocol::Https;
                e.answer = "Antwort, mit \"Komma\"".into();
            }
            e
        })
        .collect()
}

async fn page(client: &rocket::local::asynchronous::Client, query: &str) -> QueryLogPage {
    let (s, v) = get(client, format!("/api/v1/logs{query}")).await;
    assert_eq!(s, Status::Ok, "{query}: {v}");
    serde_json::from_value(v).unwrap()
}

#[rocket::async_test]
async fn filter_and_page() {
    let (client, _dir) = common::client().await;
    let base = 1_790_000_000;
    querylog::insert_batch(pool(&client), &sample(base))
        .await
        .unwrap();
    login_as(&client, "mia", false).await;

    // Neueste zuerst, Vorgabe 50 je Seite
    let p = page(&client, "").await;
    assert_eq!(
        (p.total, p.page, p.per_page, p.entries.len()),
        (30, 1, 50, 30)
    );
    assert_eq!(p.entries[0].at_ms, (base + 29) * 1000 + 250);
    assert!(p.entries.windows(2).all(|w| w[0].at_ms > w[1].at_ms));
    assert!(p.entries.iter().all(|e| e.id > 0));

    // Blättern (mindestens 10 je Seite)
    let p = page(&client, "?page=3&perPage=10").await;
    assert_eq!((p.total, p.entries.len()), (30, 10));
    assert_eq!(p.entries[0].qname, "host9.example.com");
    let p = page(&client, "?page=2&perPage=3").await;
    assert_eq!((p.per_page, p.entries.len()), (10, 10));
    let p = page(&client, "?page=9&perPage=10").await;
    assert!(p.entries.is_empty());

    // Filter
    assert_eq!(page(&client, "?client=192.168.1.10").await.total, 15);
    assert_eq!(page(&client, "?kind=blocked").await.total, 6);
    assert_eq!(page(&client, "?qtype=aaaa").await.total, 10);
    assert_eq!(
        page(&client, "?rcode=nxdomain").await.entries[0].qname,
        "host7.example.com"
    );
    assert_eq!(page(&client, "?qname=TRACKER").await.total, 6);
    // host1, host11…host19 ohne die gesperrten host10 und host15
    assert_eq!(page(&client, "?qname=host1").await.total, 9);
    // `_` und `%` sind keine Platzhalter
    assert_eq!(page(&client, "?qname=host_").await.total, 0);
    assert_eq!(page(&client, "?qname=%25").await.total, 0);
    // Zeitraum in Sekunden, „bis“ einschliesslich
    let range = format!("?from={}&to={}", base + 10, base + 14);
    assert_eq!(page(&client, &range).await.total, 5);
    let combined = format!("?from={}&kind=blocked&client=192.168.1.10", base + 10);
    assert_eq!(page(&client, &combined).await.total, 2); // 10, 20 (nur gerade = .10)
                                                         // Leere Werte = egal
    assert_eq!(page(&client, "?client=&kind=&qtype=").await.total, 30);

    let (s, v) = get(&client, "/api/v1/logs?kind=gibtsnicht").await;
    assert_eq!(s, Status::BadRequest, "{v}");
    assert_eq!(v["error"]["message"], "Unbekannte Antwortart.");

    // Leeren nur als Admin
    assert_eq!(delete(&client, "/api/v1/logs").await.0, Status::Forbidden);
    logout(&client).await;
    assert_eq!(get(&client, "/api/v1/logs").await.0, Status::Unauthorized);
    login_as(&client, "admin", true).await;
    assert_eq!(delete(&client, "/api/v1/logs").await.0, Status::NoContent);
    assert_eq!(page(&client, "").await.total, 0);
    client.terminate().await;
}

#[rocket::async_test]
async fn csv_export_uses_the_same_filters() {
    let (client, _dir) = common::client().await;
    let base = 1_790_000_000;
    querylog::insert_batch(pool(&client), &sample(base))
        .await
        .unwrap();
    login_as(&client, "mia", false).await;

    let res = client
        .get("/api/v1/logs/export?client=192.168.1.20&page=2&perPage=10")
        .dispatch()
        .await;
    assert_eq!(res.status(), Status::Ok);
    assert_eq!(res.content_type(), Some(ContentType::CSV));
    let disposition = res
        .headers()
        .get_one("Content-Disposition")
        .unwrap()
        .to_string();
    assert!(
        disposition.starts_with("attachment; filename=\"nrzdns-abfragen-"),
        "{disposition}"
    );
    assert!(disposition.ends_with(".csv\""), "{disposition}");
    let csv = res.into_string().await.unwrap();
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(
        lines[0],
        "time,client,protocol,qname,qtype,rcode,kind,answer,duration_ms,upstream"
    );
    // Seiten zählen nicht: alle 15 des Clients, neueste zuerst
    assert_eq!(lines.len(), 16);
    assert!(lines[1].starts_with("2026-09-21T"), "{}", lines[1]);
    assert!(lines[1].contains(",192.168.1.20,udp,host29.example.com,A,NOERROR,forwarded,"));
    // Anführungszeichen und Kommas sauber maskiert
    let row7 = lines.iter().find(|l| l.contains("host7.")).unwrap();
    assert!(
        row7.contains(
            ",https,host7.example.com,A,NXDOMAIN,forwarded,\"Antwort, mit \"\"Komma\"\"\",12,"
        ),
        "{row7}"
    );

    let (s, _) = get(&client, "/api/v1/logs/export?kind=x").await;
    assert_eq!(s, Status::BadRequest);
    client.terminate().await;
}

#[rocket::async_test]
async fn old_entries_are_purged() {
    let (client, _dir) = common::client().await;
    let db = pool(&client);
    let now_ms = nrzdns::db::now() * 1000;
    let mut entries = Vec::new();
    for days_ago in [0, 1, 29, 31, 40] {
        entries.push(log_entry(
            now_ms - days_ago * 86_400_000,
            "10.0.0.1",
            "a.example",
        ));
    }
    querylog::insert_batch(db, &entries).await.unwrap();
    let removed = querylog::purge_before(db, now_ms - 30 * 86_400_000)
        .await
        .unwrap();
    assert_eq!(removed, 2);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM query_log")
        .fetch_one(db)
        .await
        .unwrap();
    assert_eq!(left, 3);
    client.terminate().await;
}
