//! Monitor und Komponenten: Zugriffe über den Proxy (Herkunft, Cloudflare-Kopfzeilen nur von
//! innen, keine Weiterleitungsschleife über den Tunnel), Statistik; Updates gegen ein
//! nachgebautes GitHub (Prüfsumme); Tunnel-Abgleich gegen ein nachgebautes Cloudflare.

mod common;

use common::{delete, get, login_as, post, put};
use nrzdns::proxy::ProxyState;
use rocket::http::Status;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn backend() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhallo",
                    )
                    .await;
            });
        }
    });
    port
}

async fn http(port: u16, host: &str, path: &str, extra: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 Firefox/130.0\r\n{extra}Connection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_string(&mut out)).await;
    out
}

#[rocket::async_test]
async fn access_log_and_stats() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    let be = backend().await;
    let (s, _) = post(
        &client,
        "/api/v1/proxy/hosts",
        json!({ "host": "music.zweers.ch", "target": format!("http://127.0.0.1:{be}") }),
    )
    .await;
    assert_eq!(s, Status::Created);
    // http → https für Namen mit Zertifikat: über Cloudflare (https am Rand) darf das nicht schleifen
    let (s, _) = put(
        &client,
        "/api/v1/tls",
        json!({ "enabled": true, "domains": ["*.zweers.ch"], "redirectHttp": true }),
    )
    .await;
    assert_eq!(s, Status::Ok);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["*.zweers.ch".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let state = client.rocket().state::<ProxyState>().unwrap().clone();
    state.tls().set_cert(Some(
        nrzdns::proxy::tls::load_pem(&cert.pem(), &key.serialize_pem()).unwrap(),
    ));
    let port = free_port();
    state
        .serve(
            &[format!("127.0.0.1:{port}").parse::<SocketAddr>().unwrap()],
            client.rocket().shutdown(),
        )
        .await;

    // Direkt von hier (127.0.0.1, ohne Cloudflare): Umleitung auf https
    let out = http(port, "music.zweers.ch", "/a?x=1", "").await;
    assert!(out.starts_with("HTTP/1.1 308"), "{out}");
    // Über den Tunnel (CF-Kopfzeilen von 127.0.0.1): keine Umleitung, echte Adresse und Land
    let cf = "CF-Connecting-IP: 203.0.113.7\r\nCF-IPCountry: de\r\nCF-Visitor: {\"scheme\":\"https\"}\r\nReferer: https://www.google.com/search?q=x\r\n";
    for _ in 0..3 {
        let out = http(port, "music.zweers.ch", "/song/1?t=2", cf).await;
        assert!(
            out.starts_with("HTTP/1.1 200") && out.ends_with("hallo"),
            "{out}"
        );
    }
    // Gesundheitscheck wird nicht protokolliert
    http(port, "music.zweers.ch", "/.nrznetwork/health", "").await;

    let (s, v) = get(&client, "/api/v1/access/stats?period=24h").await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["requests"], 4, "{v}");
    assert_eq!(v["visitors"], 2);
    assert_eq!(v["hosts"][0]["host"], "music.zweers.ch");
    assert_eq!(v["timeline"].as_array().unwrap().len(), 24);
    let src: Vec<(String, u64)> = v["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["key"].as_str().unwrap().into(),
                x["count"].as_u64().unwrap(),
            )
        })
        .collect();
    assert!(
        src.contains(&("cloudflare".into(), 3)) && src.contains(&("local".into(), 1)),
        "{src:?}"
    );
    assert_eq!(v["countries"][0]["key"], "DE");
    assert_eq!(v["agents"][0]["key"], "Firefox");
    assert!(
        v["paths"].to_string().contains("music.zweers.ch/song/1"),
        "{v}"
    );
    let (_, log) = get(&client, "/api/v1/access/log?limit=10").await;
    assert_eq!(log[0]["client"], "203.0.113.7", "{log}");
    assert_eq!(log[0]["source"], "cloudflare");
    assert_eq!(log[0]["referer"], "www.google.com");
    assert_eq!(log[0]["path"], "/song/1", "ohne Query");
    assert_eq!(log[3]["kind"], "redirect");
    let (s, _) = get(&client, "/api/v1/access/stats?period=1y").await;
    assert_eq!(s, Status::BadRequest);

    // Protokoll aus (0 Tage): nichts Neues
    let (_, mut ps) = get(&client, "/api/v1/proxy").await;
    ps["settings"]["accessLogDays"] = json!(0);
    let (s, v) = put(&client, "/api/v1/proxy/settings", ps["settings"].clone()).await;
    assert_eq!(s, Status::Ok, "{v}");
    http(port, "music.zweers.ch", "/b", cf).await;
    let (_, v) = get(&client, "/api/v1/access/stats").await;
    assert_eq!(v["requests"], 4);

    let (s, _) = delete(&client, "/api/v1/access/log").await;
    assert_eq!(s, Status::NoContent);
    common::logout(&client).await;
    login_as(&client, "member", false).await;
    let (s, _) = get(&client, "/api/v1/access/stats").await;
    assert_eq!(s, Status::Ok);
    let (s, _) = delete(&client, "/api/v1/access/log").await;
    assert_eq!(s, Status::Forbidden);
}

/// Nachbau für GitHub-Releases und die Cloudflare-API (Tunnel, Zonen, DNS).
#[derive(Default)]
struct Fake {
    ingress: Mutex<Value>,
    records: Mutex<Vec<Value>>,
    put_bodies: Mutex<Vec<Value>>,
}

async fn fake(state: Arc<Fake>, binary: &'static [u8], digest: String) -> String {
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{Body, Request, Response, Server};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{port}");
    let base2 = base.clone();
    let make = make_service_fn(move |_| {
        let state = state.clone();
        let digest = digest.clone();
        let base = base2.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                let state = state.clone();
                let digest = digest.clone();
                let base = base.clone();
                async move {
                    let method = req.method().to_string();
                    let path = req.uri().path().to_string();
                    let query = req.uri().query().unwrap_or("").to_string();
                    let body: Value = serde_json::from_slice(
                        &hyper::body::to_bytes(req.into_body()).await.unwrap(),
                    )
                    .unwrap_or(Value::Null);
                    let j = |v: Value| Response::new(Body::from(v.to_string()));
                    let arch = if std::env::consts::ARCH == "aarch64" {
                        "arm64"
                    } else {
                        "amd64"
                    };
                    let resp = match (method.as_str(), path.as_str()) {
                        ("GET", "/repos/cloudflare/cloudflared/releases/latest") => j(json!({
                            "tag_name": "2026.11.0",
                            "assets": [{ "name": format!("cloudflared-linux-{arch}"), "browser_download_url": format!("{base}/dl/cloudflared"), "digest": format!("sha256:{digest}") }]
                        })),
                        ("GET", "/repos/netbirdio/netbird/releases/latest") => {
                            j(json!({ "tag_name": "v0.83.1", "assets": [] }))
                        }
                        ("GET", "/dl/cloudflared") => Response::new(Body::from(binary)),
                        ("GET", "/zones") => j(
                            json!({ "success": true, "result": [{ "id": "z1", "name": "zweers.ch", "account": { "id": "acc1" } }] }),
                        ),
                        ("GET", "/accounts/acc1/cfd_tunnel/t1/configurations") => j(
                            json!({ "success": true, "result": { "config": { "ingress": state.ingress.lock().unwrap().clone(), "warp-routing": { "enabled": false } } } }),
                        ),
                        ("PUT", "/accounts/acc1/cfd_tunnel/t1/configurations") => {
                            *state.ingress.lock().unwrap() = body["config"]["ingress"].clone();
                            state.put_bodies.lock().unwrap().push(body);
                            j(json!({ "success": true, "result": {} }))
                        }
                        ("GET", "/zones/z1/dns_records") => {
                            let name = query
                                .split('&')
                                .find_map(|kv| kv.strip_prefix("name="))
                                .unwrap_or("")
                                .to_string();
                            let r: Vec<Value> = state
                                .records
                                .lock()
                                .unwrap()
                                .iter()
                                .filter(|r| r["name"] == name)
                                .cloned()
                                .collect();
                            j(json!({ "success": true, "result": r }))
                        }
                        ("POST", "/zones/z1/dns_records") => {
                            let mut r = body.clone();
                            r["id"] =
                                json!(format!("r{}", state.records.lock().unwrap().len() + 1));
                            state.records.lock().unwrap().push(r);
                            j(json!({ "success": true, "result": {} }))
                        }
                        ("DELETE", p) if p.starts_with("/zones/z1/dns_records/") => {
                            let id = p.rsplit('/').next().unwrap().to_string();
                            state.records.lock().unwrap().retain(|r| r["id"] != id);
                            j(json!({ "success": true, "result": {} }))
                        }
                        _ => Response::builder()
                            .status(404)
                            .body(Body::from("{}"))
                            .unwrap(),
                    };
                    Ok::<_, Infallible>(resp)
                }
            }))
        }
    });
    tokio::spawn(Server::from_tcp(listener).unwrap().serve(make));
    base
}

fn sha(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

const BINARY: &[u8] = b"#!/bin/sh\necho cloudflared\n";

#[rocket::async_test]
async fn components_update_and_tunnel_sync() {
    let state = Arc::new(Fake::default());
    *state.ingress.lock().unwrap() = json!([
        { "hostname": "fremd.zweers.ch", "service": "http://10.0.0.5:8080" },
        { "service": "http_status:404" }
    ]);
    let base = fake(state.clone(), BINARY, sha(BINARY)).await;
    let (client, dir) = common::client_with(|f| {
        f.merge(("github_api", base.clone()))
            .merge(("cloudflare_api", base.clone()))
    })
    .await;
    login_as(&client, "admin", true).await;

    // Token prüfen, speichern, nie zurückgeben
    let (s, _) = put(
        &client,
        "/api/v1/components",
        json!({ "tunnelToken": "unsinn" }),
    )
    .await;
    assert_eq!(s, Status::BadRequest);
    use base64::Engine as _;
    let token =
        base64::engine::general_purpose::STANDARD.encode(r#"{"a":"acc1","t":"t1","s":"geheim"}"#);
    let (s, v) = put(&client, "/api/v1/components", json!({ "tunnelToken": token, "cloudflaredEnabled": true, "updateHour": 3, "autoUpdate": true, "netbirdHostname": "nrznetwork" })).await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["tunnelTokenSet"], true);
    assert_eq!(v["tunnelId"], "t1");
    assert!(!v.to_string().contains("geheim") && !v.to_string().contains(&token));
    let (s, _) = put(&client, "/api/v1/components", json!({ "updateHour": 25 })).await;
    assert_eq!(s, Status::BadRequest);

    // Update: herunterladen, Prüfsumme, installieren
    let config = client
        .rocket()
        .state::<nrzdns::config::Config>()
        .unwrap()
        .clone();
    let comps = client
        .rocket()
        .state::<nrzdns::services::components::Components>()
        .unwrap()
        .clone();
    let pool = common::pool(&client).clone();
    let r = nrzdns::services::components::check_updates(&pool, &config, &comps)
        .await
        .unwrap();
    assert!(r.contains("cloudflared 2026.11.0 installiert"), "{r}");
    let bin = dir.path().join("bin/cloudflared");
    assert_eq!(std::fs::read(&bin).unwrap(), BINARY);
    let r = nrzdns::services::components::check_updates(&pool, &config, &comps)
        .await
        .unwrap();
    assert!(r.contains("ist aktuell"), "{r}");
    let (_, v) = get(&client, "/api/v1/components").await;
    let cf = v["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "cloudflared")
        .unwrap()
        .clone();
    assert_eq!(cf["installedVersion"], "2026.11.0", "{v}");
    assert_eq!(cf["latestVersion"], "2026.11.0");
    assert!(dir.path().join("bin/ca-certificates.pem").exists());

    // Tunnel: ohne Cloudflare-Verbindung geht Freigeben nicht
    let (s, h) = post(
        &client,
        "/api/v1/proxy/hosts",
        json!({ "host": "music.zweers.ch", "target": "http://127.0.0.1:9" }),
    )
    .await;
    assert_eq!(s, Status::Created);
    let id = h["id"].as_i64().unwrap();
    let (s, v) = put(
        &client,
        format!("/api/v1/proxy/hosts/{id}/public"),
        json!({ "public": true }),
    )
    .await;
    assert_eq!(s, Status::BadRequest, "{v}");
    let (_, h) = get(&client, "/api/v1/proxy").await;
    assert_eq!(
        h["hosts"][0]["public"], false,
        "bei Fehler bleibt der Eintrag privat"
    );

    let (s, _) = put(
        &client,
        "/api/v1/integrations",
        json!({ "cloudflareToken": "cf-token" }),
    )
    .await;
    assert_eq!(s, Status::Ok);
    let (s, v) = put(
        &client,
        format!("/api/v1/proxy/hosts/{id}/public"),
        json!({ "public": true }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["public"], true);
    let ingress = state.ingress.lock().unwrap().clone();
    let hosts: Vec<&str> = ingress
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["hostname"].as_str())
        .collect();
    assert_eq!(
        hosts,
        ["fremd.zweers.ch", "music.zweers.ch"],
        "fremde Regel bleibt: {ingress}"
    );
    assert_eq!(
        ingress.as_array().unwrap().last().unwrap()["service"],
        "http_status:404"
    );
    assert!(
        ingress.to_string().contains("http://127.0.0.1:80"),
        "{ingress}"
    );
    assert_eq!(
        state.put_bodies.lock().unwrap()[0]["config"]["warp-routing"]["enabled"],
        false,
        "andere Einstellungen bleiben"
    );
    let recs = state.records.lock().unwrap().clone();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["type"], "CNAME");
    assert_eq!(recs[0]["content"], "t1.cfargotunnel.com");
    assert_eq!(recs[0]["proxied"], true);

    // Name schon anders belegt → Fehler, nichts überschrieben
    state
        .records
        .lock()
        .unwrap()
        .push(json!({ "id": "x9", "type": "A", "name": "blog.zweers.ch", "content": "1.2.3.4" }));
    let (_, h2) = post(
        &client,
        "/api/v1/proxy/hosts",
        json!({ "host": "blog.zweers.ch", "target": "http://127.0.0.1:9" }),
    )
    .await;
    let (s, v) = put(
        &client,
        format!("/api/v1/proxy/hosts/{}/public", h2["id"]),
        json!({ "public": true }),
    )
    .await;
    assert_eq!(s, Status::Conflict, "{v}");

    // Zurücknehmen: Regel und CNAME weg, fremde Regel bleibt
    let (s, _) = put(
        &client,
        format!("/api/v1/proxy/hosts/{id}/public"),
        json!({ "public": false }),
    )
    .await;
    assert_eq!(s, Status::Ok);
    let ingress = state.ingress.lock().unwrap().clone();
    let hosts: Vec<&str> = ingress
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["hostname"].as_str())
        .collect();
    assert_eq!(hosts, ["fremd.zweers.ch"]);
    assert!(state
        .records
        .lock()
        .unwrap()
        .iter()
        .all(|r| r["content"] != "t1.cfargotunnel.com"));
}
