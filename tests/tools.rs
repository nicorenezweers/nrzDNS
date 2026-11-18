//! Netzwerk-Tools und Geräte: Port-Check gegen einen eigenen Port, HTTP-Check gegen einen
//! kleinen Server, Ping-Eingaben, Geräte aus dem Abfrageprotokoll mit eigenen Namen.

mod common;

use common::{get, login_as, post, put};
use rocket::http::Status;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[rocket::async_test]
async fn ports_http_and_ping_input() {
    let (client, _dir) = common::client().await;
    login_as(&client, "member", false).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let open = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 204 No Content\r\nServer: test\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            });
        }
    });
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let (s, v) = post(
        &client,
        "/api/v1/tools/ports",
        json!({ "host": "127.0.0.1", "ports": format!("{open},{closed}") }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    let states: Vec<(u64, String)> = v["ports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["port"].as_u64().unwrap(),
                p["state"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(states.contains(&(u64::from(open), "open".into())), "{v}");
    assert!(
        states.contains(&(u64::from(closed), "closed".into())),
        "{v}"
    );
    let (s, _) = post(
        &client,
        "/api/v1/tools/ports",
        json!({ "host": "127.0.0.1", "ports": "1-1000" }),
    )
    .await;
    assert_eq!(s, Status::BadRequest);

    let (s, v) = post(
        &client,
        "/api/v1/tools/http",
        json!({ "url": format!("127.0.0.1:{open}/x") }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["status"], 204, "{v}");
    assert!(v["headers"].to_string().contains("server"), "{v}");
    let (s, _) = post(
        &client,
        "/api/v1/tools/http",
        json!({ "url": "ftp://example.com" }),
    )
    .await;
    assert_eq!(s, Status::BadRequest);

    for host in ["", "255.255.255.255", "0.0.0.0", "a b"] {
        let (s, _) = post(&client, "/api/v1/tools/ping", json!({ "host": host })).await;
        assert_eq!(s, Status::BadRequest, "{host}");
    }
}

#[rocket::async_test]
async fn devices_with_names() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    let now = nrzdns::db::now() * 1000;
    let mut a = common::log_entry(now - 1000, "192.168.0.20", "example.com");
    a.kind = nrzdns_types::ResponseKind::Blocked;
    let entries = vec![
        a,
        common::log_entry(now - 500, "192.168.0.20", "example.org"),
        common::log_entry(now - 200, "192.168.0.30", "example.net"),
    ];
    nrzdns::services::querylog::insert_batch(common::pool(&client), &entries)
        .await
        .unwrap();
    let (s, v) = put(
        &client,
        "/api/v1/devices/192.168.0.20",
        json!({ "name": "Laptop" }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    let (s, v) = get(&client, "/api/v1/devices?days=7").await;
    assert_eq!(s, Status::Ok);
    assert_eq!(v[0]["ip"], "192.168.0.20", "{v}");
    assert_eq!(v[0]["name"], "Laptop");
    assert_eq!(v[0]["queries"], 2);
    assert_eq!(v[0]["blocked"], 1);
    assert_eq!(v[1]["name"], "");
    let (s, _) = put(&client, "/api/v1/devices/kein-ip", json!({ "name": "x" })).await;
    assert_eq!(s, Status::BadRequest);

    common::logout(&client).await;
    login_as(&client, "member", false).await;
    let (s, _) = put(
        &client,
        "/api/v1/devices/192.168.0.20",
        json!({ "name": "X" }),
    )
    .await;
    assert_eq!(s, Status::Forbidden);
}
