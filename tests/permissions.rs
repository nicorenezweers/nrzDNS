//! Rechte: Mitglieder lesen alles, ändern aber nichts (403); ohne Anmeldung gibt es 401.

mod common;

use common::{login_as, logout, pool};
use rocket::http::Status;
use serde_json::json;

/// Jede ändernde Route der DNS-Verwaltung.
const MUTATIONS: &[(&str, &str)] = &[
    ("PUT", "/api/v1/settings/dns"),
    ("POST", "/api/v1/zones"),
    ("POST", "/api/v1/zones/import"),
    ("PUT", "/api/v1/zones/1"),
    ("DELETE", "/api/v1/zones/1"),
    ("POST", "/api/v1/zones/1/records"),
    ("PUT", "/api/v1/zones/1/records/1"),
    ("DELETE", "/api/v1/zones/1/records/1"),
    ("POST", "/api/v1/blocking/lists"),
    ("PUT", "/api/v1/blocking/lists/1"),
    ("DELETE", "/api/v1/blocking/lists/1"),
    ("POST", "/api/v1/blocking/update"),
    ("POST", "/api/v1/blocking/pause"),
    ("POST", "/api/v1/blocked"),
    ("DELETE", "/api/v1/blocked/example.com"),
    ("POST", "/api/v1/allowed"),
    ("DELETE", "/api/v1/allowed/example.com"),
    ("DELETE", "/api/v1/logs"),
    ("DELETE", "/api/v1/cache"),
    ("DELETE", "/api/v1/cache/example.com"),
];

/// Was jeder Angemeldete lesen darf.
const READS: &[&str] = &[
    "/api/v1/settings/dns",
    "/api/v1/presets",
    "/api/v1/server",
    "/api/v1/dashboard",
    "/api/v1/zones",
    "/api/v1/zones/1",
    "/api/v1/zones/1/export",
    "/api/v1/blocking",
    "/api/v1/blocking/check?domain=example.com",
    "/api/v1/blocked",
    "/api/v1/allowed",
    "/api/v1/logs",
    "/api/v1/logs/export",
    "/api/v1/cache",
];

/// Ein Körper, der für jede Route gültiges JSON ist.
fn body() -> Option<serde_json::Value> {
    Some(json!({
        "name": "x.example", "url": "https://example.org/list.txt", "minutes": 5,
        "domain": "example.com", "text": "x", "data": { "type": "A", "address": "1.2.3.4" }
    }))
}

#[rocket::async_test]
async fn members_read_but_do_not_change() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    let (s, v) = common::post(&client, "/api/v1/zones", json!({ "name": "home.arpa" })).await;
    assert_eq!(s, Status::Created, "{v}");
    let (s, _) = common::post(
        &client,
        "/api/v1/zones/1/records",
        json!({ "name": "nas", "data": { "type": "A", "address": "192.168.1.10" } }),
    )
    .await;
    assert_eq!(s, Status::Created);
    logout(&client).await;
    login_as(&client, "mia", false).await;

    for url in READS {
        let res = client.get(*url).dispatch().await;
        assert_eq!(res.status(), Status::Ok, "{url}");
    }
    for (method, url) in MUTATIONS {
        let (s, v) = common::call(&client, method, url, body()).await;
        assert_eq!(s, Status::Forbidden, "{method} {url}: {v}");
        assert_eq!(
            v["error"]["message"], "Nur für Administratoren.",
            "{method} {url}"
        );
    }
    // Nichts hat sich geändert
    let records: i64 = sqlx::query_scalar("SELECT count(*) FROM zone_records")
        .fetch_one(pool(&client))
        .await
        .unwrap();
    assert_eq!(records, 2);
    let zones: i64 = sqlx::query_scalar("SELECT count(*) FROM zones")
        .fetch_one(pool(&client))
        .await
        .unwrap();
    assert_eq!(zones, 1);

    logout(&client).await;
    for url in READS {
        let (s, _) = common::get(&client, url).await;
        assert_eq!(s, Status::Unauthorized, "{url}");
    }
    for (method, url) in MUTATIONS {
        let (s, _) = common::call(&client, method, url, body()).await;
        assert_eq!(s, Status::Unauthorized, "{method} {url}");
    }
    // Der DNS-Client braucht nur eine Anmeldung
    let (s, _) = common::post(&client, "/api/v1/resolve", json!({ "name": "example.com" })).await;
    assert_eq!(s, Status::Unauthorized);
    client.terminate().await;
}
