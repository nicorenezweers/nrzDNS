//! Verbindungen zu Cloudflare und NetBird gegen kleine Nachbauten der APIs: Tokens speichern
//! (nie zurückgeben), prüfen, durchreichen (nur freigegebene Pfade, Mitglieder nur lesen),
//! Fehlermeldungen, NetBird-Namen auf der Geräte-Seite, altes HTTPS-Token übernehmen.

mod common;

use common::{delete, get, login_as, post, put};
use rocket::http::Status;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

/// Nachbau: merkt sich Anfragen (Methode, Pfad mit Query, Authorization, Body).
#[derive(Default)]
struct Fake {
    seen: Mutex<Vec<(String, String, String, Value)>>,
}

async fn fake(state: Arc<Fake>, answer: fn(&str, &str, &str) -> (u16, Value)) -> String {
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{Body, Request, Response, Server};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let make = make_service_fn(move |_| {
        let state = state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                let state = state.clone();
                async move {
                    let auth = req
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let method = req.method().to_string();
                    let path = req.uri().path_and_query().unwrap().to_string();
                    let raw = hyper::body::to_bytes(req.into_body()).await.unwrap();
                    let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
                    state.seen.lock().unwrap().push((
                        method.clone(),
                        path.clone(),
                        auth.clone(),
                        body,
                    ));
                    let (status, v) = answer(&method, &path, &auth);
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .header("content-type", "application/json")
                            .body(Body::from(v.to_string()))
                            .unwrap(),
                    )
                }
            }))
        }
    });
    tokio::spawn(Server::from_tcp(listener).unwrap().serve(make));
    format!("http://127.0.0.1:{port}")
}

fn netbird_answer(method: &str, path: &str, auth: &str) -> (u16, Value) {
    if auth != "Token nb-good" {
        return (401, json!({ "message": "token invalid", "code": 401 }));
    }
    match (method, path) {
        ("GET", "/api/users/current") => {
            (200, json!({ "email": "nico@zweers.ch", "role": "owner" }))
        }
        ("GET", "/api/peers") => (
            200,
            json!([
                { "id": "p1", "name": "macbook", "ip": "100.78.26.136", "connected": true },
                { "id": "p2", "name": "umbrel", "ip": "100.78.107.162", "connected": true }
            ]),
        ),
        ("PUT", "/api/peers/p1") => (200, json!({ "id": "p1", "name": "laptop" })),
        ("DELETE", "/api/groups/g9") => (200, json!({})),
        ("POST", "/api/dns/nameservers") => (200, json!({ "id": "ns1" })),
        _ => (404, json!({ "message": "not found", "code": 404 })),
    }
}

fn cloudflare_answer(method: &str, path: &str, auth: &str) -> (u16, Value) {
    if auth != "Bearer cf-good" {
        return (
            403,
            json!({ "success": false, "errors": [{ "code": 9109, "message": "Invalid access token" }] }),
        );
    }
    match (method, path.split('?').next().unwrap()) {
        ("GET", "/zones") => (
            200,
            json!({ "success": true, "result": [{ "id": "z1", "name": "zweers.ch" }] }),
        ),
        ("GET", "/zones/z1/dns_records") => (
            200,
            json!({ "success": true, "result": [{ "id": "r1", "type": "A", "name": "zweers.ch", "content": "1.2.3.4", "proxied": true }] }),
        ),
        ("POST", "/zones/z1/dns_records") => {
            (200, json!({ "success": true, "result": { "id": "r2" } }))
        }
        ("DELETE", "/zones/z1/dns_records/r1") => {
            (200, json!({ "success": true, "result": { "id": "r1" } }))
        }
        _ => (
            404,
            json!({ "success": false, "errors": [{ "message": "not found" }] }),
        ),
    }
}

#[rocket::async_test]
async fn connect_test_and_pass_through() {
    let nb_state = Arc::new(Fake::default());
    let cf_state = Arc::new(Fake::default());
    let nb_url = fake(nb_state.clone(), netbird_answer).await;
    let cf_url = fake(cf_state.clone(), cloudflare_answer).await;
    let (client, _dir) = common::client_with(|f| f.merge(("cloudflare_api", cf_url.clone()))).await;
    login_as(&client, "admin", true).await;

    // Noch nicht verbunden
    let (s, v) = get(&client, "/api/v1/netbird/peers").await;
    assert_eq!(s, Status::BadRequest, "{v}");
    assert!(v.to_string().contains("nicht verbunden"), "{v}");

    // Falsche Tokens: verständliche Meldungen
    let (s, v) = put(
        &client,
        "/api/v1/integrations",
        json!({ "cloudflareToken": "cf-bad", "netbirdUrl": nb_url, "netbirdToken": "nb-bad" }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["cloudflare"]["ok"], false);
    assert!(
        v["cloudflare"]["detail"]
            .as_str()
            .unwrap()
            .contains("Invalid access token"),
        "{v}"
    );
    assert!(
        v["netbird"]["detail"]
            .as_str()
            .unwrap()
            .contains("stimmt nicht"),
        "{v}"
    );
    let (s, _) = put(
        &client,
        "/api/v1/integrations",
        json!({ "netbirdToken": "a b" }),
    )
    .await;
    assert_eq!(s, Status::BadRequest);

    // Richtige Tokens
    let (s, v) = put(
        &client,
        "/api/v1/integrations",
        json!({ "cloudflareToken": "cf-good", "netbirdUrl": format!("{nb_url}/api/"), "netbirdToken": "nb-good" }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["cloudflare"]["ok"], true, "{v}");
    assert_eq!(v["cloudflare"]["detail"], "Verbunden: zweers.ch");
    assert_eq!(
        v["netbird"]["detail"],
        "Verbunden als nico@zweers.ch (owner)"
    );
    assert_eq!(v["netbirdUrl"], nb_url, "/api am Ende wird entfernt");
    let all = v.to_string();
    assert!(
        !all.contains("cf-good") && !all.contains("nb-good"),
        "Tokens nie zurückgeben: {all}"
    );
    // Leere Tokens behalten die alten
    let (_, v) = put(
        &client,
        "/api/v1/integrations",
        json!({ "netbirdUrl": nb_url }),
    )
    .await;
    assert_eq!(v["netbird"]["ok"], true, "{v}");

    // Durchreichen
    let (s, v) = get(&client, "/api/v1/netbird/peers").await;
    assert_eq!(s, Status::Ok);
    assert_eq!(v[0]["name"], "macbook");
    let (s, v) = put(
        &client,
        "/api/v1/netbird/peers/p1",
        json!({ "name": "laptop", "ssh_enabled": false }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    let last = nb_state.seen.lock().unwrap().last().unwrap().clone();
    assert_eq!((last.0.as_str(), last.1.as_str()), ("PUT", "/api/peers/p1"));
    assert_eq!(last.3["name"], "laptop");
    let (s, _) = delete(&client, "/api/v1/netbird/groups/g9").await;
    assert_eq!(s, Status::Ok);
    let (s, v) = get(
        &client,
        "/api/v1/cloudflare/zones/z1/dns_records?per_page=5000&type=A",
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["result"][0]["content"], "1.2.3.4");
    assert!(cf_state
        .seen
        .lock()
        .unwrap()
        .iter()
        .any(|r| r.1 == "/zones/z1/dns_records?per_page=5000&type=A"));
    let (s, _) = post(
        &client,
        "/api/v1/cloudflare/zones/z1/dns_records",
        json!({ "type": "TXT", "name": "x", "content": "y" }),
    )
    .await;
    assert_eq!(s, Status::Ok);
    let (s, _) = delete(&client, "/api/v1/cloudflare/zones/z1/dns_records/r1").await;
    assert_eq!(s, Status::Ok);

    // Nicht freigegeben
    for (path, method) in [
        ("/api/v1/cloudflare/zones/z1/settings", "GET"),
        ("/api/v1/cloudflare/accounts", "GET"),
        ("/api/v1/netbird/instance", "GET"),
        ("/api/v1/netbird/accounts/a1", "DELETE"),
    ] {
        let s = if method == "GET" {
            get(&client, path).await.0
        } else {
            delete(&client, path).await.0
        };
        assert_eq!(s, Status::Forbidden, "{method} {path}");
    }
    // Fehler der API: Meldung kommt durch
    let (s, v) = get(&client, "/api/v1/netbird/policies").await;
    assert_eq!(s, Status::BadRequest);
    assert!(v.to_string().contains("NetBird: not found"), "{v}");

    // Geräte-Seite: NetBird-Namen
    let now = nrzdns::db::now() * 1000;
    let entries = vec![
        common::log_entry(now - 100, "100.78.26.136", "example.com"),
        common::log_entry(now - 50, "192.168.0.20", "example.org"),
    ];
    nrzdns::services::querylog::insert_batch(common::pool(&client), &entries)
        .await
        .unwrap();
    let (_, v) = get(&client, "/api/v1/devices?days=1").await;
    let names: Vec<(String, String)> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["ip"].as_str().unwrap().into(),
                d["netbirdName"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert!(
        names.contains(&("100.78.26.136".into(), "macbook".into())),
        "{v}"
    );
    assert!(
        names.contains(&("192.168.0.20".into(), String::new())),
        "{v}"
    );

    // Mitglieder: lesen ja, ändern nein
    common::logout(&client).await;
    login_as(&client, "member", false).await;
    let (s, _) = get(&client, "/api/v1/netbird/peers").await;
    assert_eq!(s, Status::Ok);
    let (s, _) = put(&client, "/api/v1/netbird/peers/p1", json!({ "name": "x" })).await;
    assert_eq!(s, Status::Forbidden);
    let (s, _) = delete(&client, "/api/v1/cloudflare/zones/z1/dns_records/r1").await;
    assert_eq!(s, Status::Forbidden);
    let (s, _) = put(
        &client,
        "/api/v1/integrations",
        json!({ "netbirdToken": "x" }),
    )
    .await;
    assert_eq!(s, Status::Forbidden);
}

#[rocket::async_test]
async fn old_tls_token_moves_to_integrations() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    nrzdns::services::settings::set(
        common::pool(&client),
        "tls",
        &json!({ "enabled": false, "domains": ["zweers.ch"], "cloudflareToken": "alt-token" }),
    )
    .await
    .unwrap();
    let (_, v) = get(&client, "/api/v1/integrations").await;
    assert_eq!(v["cloudflare"]["configured"], true, "{v}");
    let (_, v) = get(&client, "/api/v1/tls").await;
    assert_eq!(v["tokenSet"], true, "{v}");
    // Beim nächsten Speichern verschwindet es aus den HTTPS-Einstellungen
    let (s, _) = put(
        &client,
        "/api/v1/tls",
        json!({ "enabled": false, "domains": ["zweers.ch"] }),
    )
    .await;
    assert_eq!(s, Status::Ok);
    let raw: Value = nrzdns::services::settings::get(common::pool(&client), "tls")
        .await
        .unwrap()
        .unwrap();
    assert!(raw.get("cloudflareToken").is_none(), "{raw}");
    let (_, v) = get(&client, "/api/v1/integrations").await;
    assert_eq!(v["cloudflare"]["configured"], true);
}
