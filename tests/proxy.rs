//! Reverse Proxy: Einträge über die API, DNS-Antworten für die Namen und echtes Weiterreichen
//! über HTTP (Host-Header, X-Forwarded-For, Location-Umschreibung, unbekannte Namen).

mod common;

use common::{delete, get, login_as, post, put};
use nrzdns::proxy::ProxyState;
use rocket::http::Status;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn resolve(
    client: &rocket::local::asynchronous::Client,
    name: &str,
    qtype: &str,
) -> serde_json::Value {
    let (s, v) = post(
        client,
        "/api/v1/resolve",
        json!({ "name": name, "qtype": qtype }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    v
}

#[rocket::async_test]
async fn hosts_api_and_dns_answers() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;

    let (s, v) = post(
        &client,
        "/api/v1/proxy/hosts",
        json!({ "host": "Music.NRZ.ch", "target": "http://100.78.107.162:8350/" }),
    )
    .await;
    assert_eq!(s, Status::Created, "{v}");
    assert_eq!(v["host"], "music.nrz.ch");
    assert_eq!(v["target"], "http://100.78.107.162:8350");
    assert_eq!(v["dnsAddress"], "100.78.107.162");
    let music = v["id"].as_i64().unwrap();

    let (s, _) = post(
        &client,
        "/api/v1/proxy/hosts",
        json!({ "host": "music.nrz.ch", "target": "100.78.107.162:8550" }),
    )
    .await;
    assert_eq!(s, Status::Conflict);
    let (s, _) = post(
        &client,
        "/api/v1/proxy/hosts",
        json!({ "host": "bench.nrz.ch", "target": "https://100.78.107.162:8550" }),
    )
    .await;
    assert_eq!(s, Status::BadRequest);
    let (s, v) = post(
        &client,
        "/api/v1/proxy/hosts",
        json!({ "host": "bench.nrz.ch", "target": "100.78.107.162:8550" }),
    )
    .await;
    assert_eq!(s, Status::Created, "{v}");

    // nrzDNS beantwortet die Namen selbst
    let v = resolve(&client, "music.nrz.ch", "A").await;
    assert_eq!(v["rcode"], "NOERROR", "{v}");
    assert_eq!(v["answers"][0]["data"], "100.78.107.162", "{v}");
    let v = resolve(&client, "bench.nrz.ch", "AAAA").await;
    assert_eq!(v["rcode"], "NOERROR", "{v}");
    assert!(v["answers"].as_array().unwrap().is_empty(), "{v}");

    // Eigene Adresse für alle Namen
    let (s, v) = put(
        &client,
        "/api/v1/proxy/settings",
        json!({ "address": "192.168.0.198" }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["hosts"][0]["dnsAddress"], "192.168.0.198");
    let v = resolve(&client, "music.nrz.ch", "A").await;
    assert_eq!(v["answers"][0]["data"], "192.168.0.198", "{v}");
    let (s, _) = put(
        &client,
        "/api/v1/proxy/settings",
        json!({ "address": "kein-ip" }),
    )
    .await;
    assert_eq!(s, Status::BadRequest);

    // Ausschalten → keine eigene Antwort mehr (Weiterleitung schlägt in Tests fehl)
    let (s, v) = put(
        &client,
        format!("/api/v1/proxy/hosts/{music}"),
        json!({ "host": "music.nrz.ch", "target": "100.78.107.162:8350", "enabled": false }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    let v = resolve(&client, "music.nrz.ch", "A").await;
    assert_ne!(v["kind"], "authoritative", "{v}");

    let (s, v) = get(&client, "/api/v1/proxy").await;
    assert_eq!(s, Status::Ok);
    assert_eq!(v["hosts"].as_array().unwrap().len(), 2);
    assert_eq!(v["port"], 80);

    let (s, _) = delete(&client, format!("/api/v1/proxy/hosts/{music}")).await;
    assert_eq!(s, Status::NoContent);
    let (s, _) = delete(&client, format!("/api/v1/proxy/hosts/{music}")).await;
    assert_eq!(s, Status::NotFound);
}

#[rocket::async_test]
async fn members_only_read() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    common::logout(&client).await;
    login_as(&client, "member", false).await;
    let (s, _) = get(&client, "/api/v1/proxy").await;
    assert_eq!(s, Status::Ok);
    let (s, _) = post(
        &client,
        "/api/v1/proxy/hosts",
        json!({ "host": "music.nrz.ch", "target": "10.0.0.1:8350" }),
    )
    .await;
    assert_eq!(s, Status::Forbidden);
}

/// Kleiner HTTP-Server: antwortet mit der empfangenen Anfrage als Text; `/go` leitet um.
async fn backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let resp = if req.starts_with("GET /go ") {
                    format!("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/login\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{req}",
                        req.len()
                    )
                };
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

async fn http(port: u16, host: &str, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = String::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_string(&mut out))
        .await
        .unwrap()
        .unwrap();
    out
}

#[rocket::async_test]
async fn forwards_by_host_header() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    let backend = backend().await;
    let (s, v) = post(
        &client,
        "/api/v1/proxy/hosts",
        json!({ "host": "music.nrz.ch", "target": format!("127.0.0.1:{backend}") }),
    )
    .await;
    assert_eq!(s, Status::Created, "{v}");

    let proxy_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let state = client.rocket().state::<ProxyState>().unwrap().clone();
    state
        .serve(
            &[format!("127.0.0.1:{proxy_port}").parse().unwrap()],
            client.rocket().shutdown(),
        )
        .await;
    assert!(state.listen_errors().is_empty());

    let out = http(proxy_port, "music.nrz.ch", "/song?id=1").await;
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.contains("GET /song?id=1 HTTP/1.1"), "{out}");
    assert!(
        out.to_ascii_lowercase().contains("host: music.nrz.ch"),
        "{out}"
    );
    assert!(out.contains("x-forwarded-for: 127.0.0.1"), "{out}");

    let out = http(proxy_port, "music.nrz.ch", "/go").await;
    assert!(out.starts_with("HTTP/1.1 302"), "{out}");
    assert!(out.contains("location: http://music.nrz.ch/login"), "{out}");

    let out = http(proxy_port, "bench.nrz.ch", "/").await;
    assert!(out.starts_with("HTTP/1.1 404"), "{out}");
}
