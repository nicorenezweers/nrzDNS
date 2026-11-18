//! HTTPS: TLS-Eingang mit eigenem Zertifikat, Durchreichen fremder Namen (umbrelOS),
//! Umleitung http → https, Einstellungen und der Ablauf über einen Cloudflare-Nachbau.
//! Mit `NRZ_PEBBLE_DIR` und `NRZ_PEBBLE_ROOT` läuft zusätzlich der ganze ACME-Ablauf gegen
//! Pebble (Testserver von Let's Encrypt, `PEBBLE_VA_ALWAYS_VALID=1`).

mod common;

use common::{get, login_as, post, put};
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

/// Kleines Ziel: antwortet mit dem empfangenen `X-Forwarded-Proto` im Text.
async fn backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_lowercase();
                let proto = req
                    .lines()
                    .find_map(|l| l.strip_prefix("x-forwarded-proto: "))
                    .unwrap_or("-")
                    .trim()
                    .to_string();
                let body = format!("backend proto={proto}");
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    port
}

/// „umbrelOS“: schreibt einen festen Text und schliesst.
async fn fallback_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                let _ = s.read(&mut buf).await;
                let _ = s.write_all(b"UMBRELOS").await;
            });
        }
    });
    port
}

fn self_signed(names: &[&str]) -> (String, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let params =
        rcgen::CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem())
}

fn client_config(cert_pem: &str) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut cert_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

async fn https_get(port: u16, name: &str, cert_pem: &str) -> String {
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(client_config(cert_pem));
    let server_name = rustls::pki_types::ServerName::try_from(name.to_string()).unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();
    tls.write_all(
        format!("GET /x HTTP/1.1\r\nHost: {name}\r\nX-Forwarded-Proto: http\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut out = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_string(&mut out)).await;
    out
}

async fn http_get(port: u16, host: &str, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_string(&mut out)).await;
    out
}

#[rocket::async_test]
async fn tls_terminates_own_names_and_passes_others_through() {
    let fb = fallback_server().await;
    let (client, _dir) =
        common::client_with(|f| f.merge(("tls_fallback", format!("127.0.0.1:{fb}")))).await;
    login_as(&client, "admin", true).await;
    let be = backend().await;
    let (s, v) = post(
        &client,
        "/api/v1/proxy/hosts",
        json!({ "host": "music.zweers.ch", "target": format!("http://127.0.0.1:{be}") }),
    )
    .await;
    assert_eq!(s, Status::Created, "{v}");
    let (s, v) = put(
        &client,
        "/api/v1/tls",
        json!({ "enabled": true, "domains": ["zweers.ch", "*.zweers.ch"], "redirectHttp": true, "cloudflareToken": "abc_DEF-123" }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["tokenSet"], true);
    assert!(
        v.get("cloudflareToken").is_none(),
        "Token darf nie zurückkommen: {v}"
    );
    assert_eq!(v["certificate"], Value::Null);

    let (cert, key) = self_signed(&["zweers.ch", "*.zweers.ch"]);
    let state = client.rocket().state::<ProxyState>().unwrap().clone();
    state
        .tls()
        .set_cert(Some(nrzdns::proxy::tls::load_pem(&cert, &key).unwrap()));

    let tls_port = free_port();
    let http_port = free_port();
    let shutdown = client.rocket().shutdown();
    state
        .serve_tls(
            &[format!("127.0.0.1:{tls_port}")
                .parse::<SocketAddr>()
                .unwrap()],
            shutdown.clone(),
        )
        .await;
    state
        .serve(
            &[format!("127.0.0.1:{http_port}")
                .parse::<SocketAddr>()
                .unwrap()],
            shutdown,
        )
        .await;

    // Eigener Name: nrzNetwork verschlüsselt, Ziel sieht https (vorgetäuschtes http ersetzt)
    let out = https_get(tls_port, "music.zweers.ch", &cert).await;
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.ends_with("backend proto=https"), "{out}");

    // http → https
    let out = http_get(http_port, "music.zweers.ch", "/a?b=1").await;
    assert!(out.starts_with("HTTP/1.1 308"), "{out}");
    assert!(
        out.to_lowercase()
            .contains("location: https://music.zweers.ch/a?b=1"),
        "{out}"
    );
    // Lebenszeichen bleibt auf http
    let out = http_get(http_port, "music.zweers.ch", "/.nrznetwork/health").await;
    assert!(out.ends_with("nrznetwork-ok"), "{out}");

    // Fremder Name (umbrel.local) und kein TLS: unverändert an den Fallback
    for first in [hello("umbrel.local"), b"GET / HTTP/1.1\r\n\r\n".to_vec()] {
        let mut s = TcpStream::connect(("127.0.0.1", tls_port)).await.unwrap();
        s.write_all(&first).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
        assert_eq!(out, b"UMBRELOS");
    }

    // Status zeigt das Zertifikat
    let (_, v) = get(&client, "/api/v1/tls").await;
    assert_eq!(
        v["certificate"]["names"],
        json!(["zweers.ch", "*.zweers.ch"]),
        "{v}"
    );

    // Ausschalten: keine Umleitung mehr, Zertifikat aus dem Proxy
    let (s, _) = put(
        &client,
        "/api/v1/tls",
        json!({ "enabled": false, "domains": ["*.zweers.ch"], "redirectHttp": true }),
    )
    .await;
    assert_eq!(s, Status::Ok);
    let out = http_get(http_port, "music.zweers.ch", "/").await;
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(!state.tls().covers("music.zweers.ch"));
}

fn hello(name: &str) -> Vec<u8> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let mut conn = rustls::ClientConnection::new(
        Arc::new(config),
        rustls::pki_types::ServerName::try_from(name.to_string()).unwrap(),
    )
    .unwrap();
    let mut out = Vec::new();
    conn.write_tls(&mut out).unwrap();
    out
}

#[rocket::async_test]
async fn settings_validation_and_rights() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    for (body, ok) in [
        (json!({ "enabled": true, "domains": [] }), false),
        (
            json!({ "enabled": true, "domains": ["*.*.zweers.ch"] }),
            false,
        ),
        (
            json!({ "enabled": false, "domains": ["zweers.ch"], "email": "kein-mail" }),
            false,
        ),
        (
            json!({ "enabled": false, "domains": ["zweers.ch"], "cloudflareToken": "a b" }),
            false,
        ),
        (
            json!({ "enabled": false, "domains": ["Zweers.ch", "*.zweers.ch"], "email": "a@b.ch" }),
            true,
        ),
    ] {
        let (s, v) = put(&client, "/api/v1/tls", body.clone()).await;
        assert_eq!(s == Status::Ok, ok, "{body} → {v}");
    }
    let (_, v) = get(&client, "/api/v1/tls").await;
    assert_eq!(
        v["settings"]["domains"],
        json!(["zweers.ch", "*.zweers.ch"])
    );
    // Ohne Token kein Zertifikat
    let (s, _) = post(&client, "/api/v1/tls/issue", json!({})).await;
    assert_eq!(s, Status::BadRequest);

    common::logout(&client).await;
    login_as(&client, "member", false).await;
    let (s, _) = get(&client, "/api/v1/tls").await;
    assert_eq!(s, Status::Ok);
    let (s, _) = put(&client, "/api/v1/tls", json!({ "enabled": false })).await;
    assert_eq!(s, Status::Forbidden);
    let (s, _) = post(&client, "/api/v1/tls/issue", json!({})).await;
    assert_eq!(s, Status::Forbidden);
}

/// Nachbau der Cloudflare-API: eine Zone `zweers.ch`, TXT-Einträge im Speicher.
#[derive(Default)]
struct FakeCf {
    records: Mutex<Vec<(String, String, String)>>, // id, name, content
    log: Mutex<Vec<String>>,
    next: Mutex<u32>,
}

async fn fake_cloudflare(cf: Arc<FakeCf>) -> u16 {
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{Body, Request, Response, Server};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let make = make_service_fn(move |_| {
        let cf = cf.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                let cf = cf.clone();
                async move {
                    let auth = req
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let method = req.method().clone();
                    let path = req.uri().path().to_string();
                    let query = req.uri().query().unwrap_or("").to_string();
                    let body = hyper::body::to_bytes(req.into_body()).await.unwrap();
                    cf.log.lock().unwrap().push(format!("{method} {path}"));
                    let reply = |status: u16, v: Value| {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .body(Body::from(v.to_string()))
                                .unwrap(),
                        )
                    };
                    if auth != "Bearer good-token" {
                        return reply(
                            403,
                            json!({ "success": false, "errors": [{ "message": "Authentication error" }] }),
                        );
                    }
                    match (method.as_str(), path.as_str()) {
                        ("GET", "/zones") => {
                            let r = if query.contains("name=zweers.ch") {
                                json!([{ "id": "z1", "name": "zweers.ch", "name_servers": ["ns.invalid"] }])
                            } else {
                                json!([])
                            };
                            reply(200, json!({ "success": true, "result": r }))
                        }
                        ("POST", "/zones/z1/dns_records") => {
                            let v: Value = serde_json::from_slice(&body).unwrap();
                            let mut n = cf.next.lock().unwrap();
                            *n += 1;
                            let id = format!("r{n}");
                            cf.records.lock().unwrap().push((
                                id.clone(),
                                v["name"].as_str().unwrap().into(),
                                v["content"].as_str().unwrap().into(),
                            ));
                            reply(200, json!({ "success": true, "result": { "id": id } }))
                        }
                        ("GET", "/zones/z1/dns_records") => {
                            let r: Vec<Value> = cf
                                .records
                                .lock()
                                .unwrap()
                                .iter()
                                .filter(|(_, name, _)| query.contains(&format!("name={name}")))
                                .map(|(id, name, content)| json!({ "id": id, "name": name, "content": content }))
                                .collect();
                            reply(200, json!({ "success": true, "result": r }))
                        }
                        ("DELETE", p) if p.starts_with("/zones/z1/dns_records/") => {
                            let id = p.rsplit('/').next().unwrap().to_string();
                            cf.records.lock().unwrap().retain(|r| r.0 != id);
                            reply(200, json!({ "success": true, "result": { "id": id } }))
                        }
                        _ => reply(
                            404,
                            json!({ "success": false, "errors": [{ "message": "not found" }] }),
                        ),
                    }
                }
            }))
        }
    });
    tokio::spawn(Server::from_tcp(listener).unwrap().serve(make));
    port
}

#[rocket::async_test]
async fn cloudflare_client() {
    use nrzdns::services::tls::Cloudflare;
    let cf = Arc::new(FakeCf::default());
    let port = fake_cloudflare(cf.clone()).await;
    let base = format!("http://127.0.0.1:{port}");

    let bad = Cloudflare::new(&base, "falsch").unwrap();
    let e = bad.zone_for("*.zweers.ch").await.unwrap_err().to_string();
    assert!(e.contains("Zone → DNS → Bearbeiten"), "{e}");

    let c = Cloudflare::new(&base, "good-token").unwrap();
    let z = c.zone_for("a.b.zweers.ch").await.unwrap();
    assert_eq!((z.id.as_str(), z.name.as_str()), ("z1", "zweers.ch"));
    assert!(c.zone_for("example.org").await.is_err());
    let id = c
        .create_txt("z1", "_acme-challenge.zweers.ch", "wert1")
        .await
        .unwrap();
    c.create_txt("z1", "_acme-challenge.zweers.ch", "wert2")
        .await
        .unwrap();
    assert_eq!(cf.records.lock().unwrap()[0].2, "\"wert1\"");
    c.delete_record("z1", &id).await.unwrap();
    assert_eq!(cf.records.lock().unwrap().len(), 1);
    c.delete_txt("z1", "_acme-challenge.zweers.ch", None)
        .await
        .unwrap();
    assert!(cf.records.lock().unwrap().is_empty());
}

/// Ganzer Ablauf gegen Pebble (nur mit `NRZ_PEBBLE_DIR`/`NRZ_PEBBLE_ROOT`, sonst übersprungen).
#[rocket::async_test]
async fn acme_with_pebble() {
    let (Ok(dir), Ok(root)) = (
        std::env::var("NRZ_PEBBLE_DIR"),
        std::env::var("NRZ_PEBBLE_ROOT"),
    ) else {
        eprintln!("übersprungen: NRZ_PEBBLE_DIR/NRZ_PEBBLE_ROOT nicht gesetzt");
        return;
    };
    let cf = Arc::new(FakeCf::default());
    let port = fake_cloudflare(cf.clone()).await;
    let (client, data) = common::client_with(|f| {
        f.merge(("acme_directory", dir.clone()))
            .merge(("acme_root", root.clone()))
            .merge(("cloudflare_api", format!("http://127.0.0.1:{port}")))
            .merge(("acme_dns_check", false))
    })
    .await;
    login_as(&client, "admin", true).await;
    let (s, v) = put(
        &client,
        "/api/v1/tls",
        json!({ "enabled": true, "domains": ["zweers.ch", "*.zweers.ch"], "email": "admin@zweers.ch", "cloudflareToken": "good-token" }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    let (s, v) = post(&client, "/api/v1/tls/issue", json!({})).await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["issuing"], true);
    let mut v = Value::Null;
    for _ in 0..120 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        v = get(&client, "/api/v1/tls").await.1;
        if v["issuing"] == false {
            break;
        }
    }
    assert_eq!(v["lastError"], "", "{v}");
    let mut names: Vec<String> = serde_json::from_value(v["certificate"]["names"].clone()).unwrap();
    names.sort();
    assert_eq!(names, ["*.zweers.ch", "zweers.ch"], "{v}");
    assert!(v["certificate"]["notAfter"].as_i64().unwrap() > nrzdns::db::now());
    // TXT-Einträge wieder weg, Dateien da, Schalter für den Wächter an
    assert!(
        cf.records.lock().unwrap().is_empty(),
        "{:?}",
        cf.log.lock().unwrap()
    );
    assert!(data.path().join("tls/cert.pem").exists());
    assert_eq!(
        std::fs::read_to_string(data.path().join("tls-active")).unwrap(),
        "on\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(data.path().join("tls/key.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "Schlüssel nur für den Besitzer");
    }
}
