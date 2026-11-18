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

    // nrzNetwork beantwortet die Namen selbst
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

async fn http_raw(port: u16, request: String) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(request.as_bytes()).await.unwrap();
    let mut out = String::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_string(&mut out))
        .await
        .unwrap()
        .unwrap();
    out
}

async fn start_proxy(client: &rocket::local::asynchronous::Client) -> u16 {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let state = client.rocket().state::<ProxyState>().unwrap().clone();
    state
        .serve(
            &[format!("127.0.0.1:{port}").parse().unwrap()],
            client.rocket().shutdown(),
        )
        .await;
    port
}

#[rocket::async_test]
async fn block_page_unlock_and_request() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    let (_, mut dns) = get(&client, "/api/v1/settings/dns").await;
    dns["blockMode"] = json!("blockPage");
    dns["forwarders"] = json!([]);
    let (s, v) = put(&client, "/api/v1/settings/dns", dns).await;
    assert_eq!(s, Status::Ok, "{v}");
    let (s, v) = put(
        &client,
        "/api/v1/proxy/settings",
        json!({ "address": "192.168.0.198, 100.78.107.162", "allowUnlock": true, "unlockMinutes": [15, 60], "allowRequests": true }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(
        v["deviceAddresses"],
        json!(["192.168.0.198", "100.78.107.162"])
    );
    for d in ["ads.example.com", "tracker.example.net"] {
        let (s, v) = post(&client, "/api/v1/blocked", json!({ "domain": d })).await;
        assert_eq!(s, Status::Created, "{v}");
    }

    // DNS: gesperrte Namen zeigen auf dieses Gerät
    let v = resolve(&client, "x.ads.example.com", "A").await;
    assert_eq!(v["kind"], "blocked", "{v}");
    assert_eq!(v["answers"][0]["data"], "192.168.0.198", "{v}");

    let port = start_proxy(&client).await;
    let out = http(port, "x.ads.example.com", "/").await;
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert!(out.contains("durch nrzNetwork gesperrt"), "{out}");
    assert!(
        out.contains("15 Minuten") && out.contains("1 Stunde"),
        "{out}"
    );

    let out = http(port, "irgendwas", "/.nrznetwork/health").await;
    assert!(out.ends_with("nrznetwork-ok"), "{out}");

    // Fremde Seite darf nicht freischalten
    let body = "minutes=15&back=%2Fseite";
    let foreign = http_raw(port, format!(
        "POST /.nrznetwork/unlock HTTP/1.1\r\nHost: x.ads.example.com\r\nOrigin: http://evil.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
    )).await;
    assert!(foreign.starts_with("HTTP/1.1 403"), "{foreign}");
    // Nicht angebotener Zeitraum
    let body5 = "minutes=5";
    let bad = http_raw(port, format!(
        "POST /.nrznetwork/unlock HTTP/1.1\r\nHost: x.ads.example.com\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body5}", body5.len()
    )).await;
    assert!(bad.starts_with("HTTP/1.1 400"), "{bad}");

    let ok = http_raw(port, format!(
        "POST /.nrznetwork/unlock HTTP/1.1\r\nHost: x.ads.example.com\r\nOrigin: http://x.ads.example.com\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
    )).await;
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
    assert!(
        ok.contains("Freigeschaltet") && ok.contains("http://x.ads.example.com/seite"),
        "{ok}"
    );
    let (_, v) = get(&client, "/api/v1/unlocks").await;
    assert_eq!(v[0]["domain"], "x.ads.example.com", "{v}");
    assert_eq!(v[0]["client"], "127.0.0.1", "{v}");
    let (_, v) = get(&client, "/api/v1/blocking/check?domain=x.ads.example.com").await;
    assert_eq!(v["allowed"], true, "{v}");
    let (s, _) = delete(&client, "/api/v1/unlocks/x.ads.example.com").await;
    assert_eq!(s, Status::NoContent);
    let (_, v) = get(&client, "/api/v1/blocking/check?domain=x.ads.example.com").await;
    assert_eq!(v["allowed"], false, "{v}");

    // Antrag → Admin genehmigt → Ausnahme
    let body = "reason=Brauche+ich+f%C3%BCr+die+Arbeit";
    let out = http_raw(port, format!(
        "POST /.nrznetwork/request HTTP/1.1\r\nHost: tracker.example.net\r\nAccept-Language: en-US\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
    )).await;
    assert!(
        out.starts_with("HTTP/1.1 200") && out.contains("Request sent"),
        "{out}"
    );
    let out = http(port, "tracker.example.net", "/").await;
    assert!(out.contains("wartet schon eine Anfrage"), "{out}");
    let (_, v) = get(&client, "/api/v1/requests").await;
    assert_eq!(v[0]["status"], "pending", "{v}");
    assert_eq!(v[0]["reason"], "Brauche ich für die Arbeit", "{v}");
    let id = v[0]["id"].as_i64().unwrap();
    let (s, v) = post(&client, format!("/api/v1/requests/{id}/approve"), json!({})).await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["status"], "approved");
    let (s, _) = post(&client, format!("/api/v1/requests/{id}/reject"), json!({})).await;
    assert_eq!(s, Status::Conflict);
    let (_, v) = get(&client, "/api/v1/allowed").await;
    assert_eq!(v[0]["domain"], "tracker.example.net", "{v}");
}

/// Ziel auf einer NetBird-Adresse, die das Gerät gerade nicht hat (z. B. NetBird-App
/// entfernt): über das Gerät verbinden statt ins Leere.
#[rocket::async_test]
async fn former_netbird_address_goes_through_device() {
    let (client, _dir) = common::client_with(|f| f.merge(("host_gateway", "127.0.0.1"))).await;
    login_as(&client, "admin", true).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let be = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ngeraet",
                    )
                    .await;
            });
        }
    });
    let (s, v) = post(
        &client,
        "/api/v1/proxy/hosts",
        json!({ "host": "music.nrz.local", "target": format!("http://100.78.107.162:{be}") }),
    )
    .await;
    assert_eq!(s, Status::Created, "{v}");
    let port = start_proxy(&client).await;
    let out = http(port, "music.nrz.local", "/").await;
    assert!(
        out.starts_with("HTTP/1.1 200") && out.ends_with("geraet"),
        "{out}"
    );
}
