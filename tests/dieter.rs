//! Dieter Ende zu Ende: nrzNetwork läuft auf einem Port, ein nachgebauter KI-Anbieter
//! (OpenAI-kompatibel) ruft Werkzeuge auf, Dieter führt sie über die echte API aus.

mod common;

use serde_json::{json, Value};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Nachbau: 1. Antwort = Werkzeugaufruf (aus `plan`), danach Abschlusstext.
async fn fake_llm(seen: Arc<Mutex<Vec<Value>>>, plan: Value) -> String {
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{Body, Request, Response, Server};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let make = make_service_fn(move |_| {
        let seen = seen.clone();
        let plan = plan.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                let seen = seen.clone();
                let plan = plan.clone();
                async move {
                    let body: Value = serde_json::from_slice(
                        &hyper::body::to_bytes(req.into_body()).await.unwrap(),
                    )
                    .unwrap();
                    let has_tool = body["messages"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|m| m["role"] == "tool");
                    seen.lock().unwrap().push(body);
                    let msg = if has_tool {
                        json!({ "role": "assistant", "content": "Alles geprüft." })
                    } else {
                        json!({ "role": "assistant", "content": null, "tool_calls": [{ "id": "c1", "type": "function", "function": { "name": "api_request", "arguments": plan.to_string() } }] })
                    };
                    Ok::<_, Infallible>(Response::new(Body::from(
                        json!({ "choices": [{ "message": msg }] }).to_string(),
                    )))
                }
            }))
        }
    });
    tokio::spawn(Server::from_tcp(listener).unwrap().serve(make));
    format!("http://127.0.0.1:{port}/v1/chat/completions")
}

struct App {
    base: String,
    cookie: String,
    http: reqwest::Client,
    _dir: tempfile::TempDir,
}

impl App {
    async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut r = self
            .http
            .request(method, format!("{}{path}", self.base))
            .header("cookie", &self.cookie);
        if let Some(b) = body {
            r = r.json(&b);
        }
        let resp = r.send().await.unwrap();
        let s = resp.status().as_u16();
        (s, resp.json().await.unwrap_or(Value::Null))
    }
}

async fn start(llm: &str) -> App {
    let dir = tempfile::tempdir().unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let figment = common::figment(&dir)
        .merge(("port", port))
        .merge(("address", "127.0.0.1"))
        .merge(("dieter_openrouter_url", llm.to_string()))
        .merge(("proxy_listen", Vec::<String>::new()))
        .merge(("proxy_tls_listen", Vec::<String>::new()));
    let rocket = nrzdns::build_with(figment).await.unwrap();
    tokio::spawn(rocket.launch());
    let base = format!("http://127.0.0.1:{port}");
    let http = reqwest::Client::new();
    for _ in 0..50 {
        if http
            .get(format!("{base}/api/v1/health"))
            .send()
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let resp = http
        .post(format!("{base}/api/v1/auth/register"))
        .json(&json!({ "username": "admin", "password": common::PASSWORD }))
        .send()
        .await
        .unwrap();
    let cookie = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap().to_string())
        .collect::<Vec<_>>()
        .join("; ");
    App {
        base,
        cookie,
        http,
        _dir: dir,
    }
}

async fn wait(app: &App, id: i64) -> Value {
    let mut v = Value::Null;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        v = app
            .call(
                reqwest::Method::GET,
                &format!("/api/v1/dieter/conversations/{id}"),
                None,
            )
            .await
            .1;
        if v["conversation"]["running"] == false {
            break;
        }
    }
    v
}

#[tokio::test]
async fn chat_with_tools_end_to_end() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let llm = fake_llm(seen.clone(), json!({ "method": "GET", "path": "/proxy" })).await;
    let app = start(&llm).await;
    use reqwest::Method;

    // Ohne Schlüssel nicht bereit
    let (s, v) = app
        .call(
            Method::POST,
            "/api/v1/dieter/conversations",
            Some(json!({ "text": "Hallo" })),
        )
        .await;
    assert_eq!(s, 400, "{v}");
    let (s, v) = app.call(Method::PUT, "/api/v1/dieter/settings", Some(json!({ "provider": "openrouter", "openrouterKey": "sk-or-test", "allowChanges": false, "autoWatch": false, "watchMinutes": 10 }))).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["ready"], true, "{v}");
    assert!(
        !v.to_string().contains("sk-or-test"),
        "Schlüssel nie zurückgeben"
    );

    let (s, v) = app
        .call(
            Method::POST,
            "/api/v1/dieter/conversations",
            Some(json!({ "text": "Prüf bitte den Reverse Proxy" })),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let id = v["conversation"]["id"].as_i64().unwrap();
    let t = wait(&app, id).await;
    let roles: Vec<&str> = t["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["role"].as_str().unwrap())
        .collect();
    assert_eq!(roles, ["user", "action", "assistant"], "{t}");
    assert_eq!(t["messages"][1]["detail"], "GET /proxy → 200", "{t}");
    assert_eq!(t["messages"][2]["text"], "Alles geprüft.");
    {
        let seen = seen.lock().unwrap();
        let second = &seen[1];
        let tool = second["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["role"] == "tool")
            .unwrap();
        assert!(
            tool["content"].as_str().unwrap().starts_with("HTTP 200"),
            "{tool}"
        );
        assert!(
            seen[0]["messages"][0]["content"]
                .as_str()
                .unwrap()
                .contains("/proxy/hosts"),
            "API-Übersicht im Systemtext"
        );
        assert!(seen[0]["tools"].to_string().contains("dns_lookup"));
    }

    // Folgefrage im selben Gespräch: Verlauf geht mit
    let (s, _) = app
        .call(
            Method::POST,
            &format!("/api/v1/dieter/conversations/{id}/messages"),
            Some(json!({ "text": "Und jetzt?" })),
        )
        .await;
    assert_eq!(s, 200);
    wait(&app, id).await;
    let n = seen.lock().unwrap().last().unwrap()["messages"]
        .as_array()
        .unwrap()
        .len();
    assert!(n >= 6, "Verlauf fehlt: {n} Nachrichten");

    // Interner Zugang mit falschem Schlüssel
    let r = app
        .http
        .get(format!("{}/api/v1/proxy", app.base))
        .header("x-nrz-dieter", "falsch")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    let r = app
        .http
        .post(format!("{}/mcp/dieter", app.base))
        .header("authorization", "Bearer falsch")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
}

#[tokio::test]
async fn changes_blocked_unless_allowed() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let llm = fake_llm(seen.clone(), json!({ "method": "POST", "path": "/proxy/hosts", "body": { "host": "x.zweers.ch", "target": "http://127.0.0.1:9" } })).await;
    let app = start(&llm).await;
    use reqwest::Method;
    app.call(Method::PUT, "/api/v1/dieter/settings", Some(json!({ "provider": "openrouter", "openrouterKey": "k", "allowChanges": false, "autoWatch": false, "watchMinutes": 10 }))).await;
    let (_, v) = app
        .call(
            Method::POST,
            "/api/v1/dieter/conversations",
            Some(json!({ "text": "Leg einen Eintrag an" })),
        )
        .await;
    let t = wait(&app, v["conversation"]["id"].as_i64().unwrap()).await;
    assert_eq!(
        t["messages"][1]["detail"], "POST /proxy/hosts → abgelehnt",
        "{t}"
    );
    let (_, hosts) = app.call(Method::GET, "/api/v1/proxy", None).await;
    assert_eq!(hosts["hosts"], json!([]));

    app.call(Method::PUT, "/api/v1/dieter/settings", Some(json!({ "provider": "openrouter", "allowChanges": true, "autoWatch": false, "watchMinutes": 10 }))).await;
    let (_, v) = app
        .call(
            Method::POST,
            "/api/v1/dieter/conversations",
            Some(json!({ "text": "Jetzt darfst du" })),
        )
        .await;
    let t = wait(&app, v["conversation"]["id"].as_i64().unwrap()).await;
    assert_eq!(t["messages"][1]["detail"], "POST /proxy/hosts → 201", "{t}");
    let (_, hosts) = app.call(Method::GET, "/api/v1/proxy", None).await;
    assert_eq!(hosts["hosts"][0]["host"], "x.zweers.ch");
}

#[tokio::test]
async fn watch_finds_problem_and_starts_dieter() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let llm = fake_llm(seen.clone(), json!({ "method": "GET", "path": "/proxy" })).await;
    let app = start(&llm).await;
    use reqwest::Method;
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let (s, v) = app.call(Method::POST, "/api/v1/proxy/hosts", Some(json!({ "host": "kaputt.zweers.ch", "target": format!("http://127.0.0.1:{closed}") }))).await;
    assert_eq!(s, 201, "{v}");
    // Überwachung ohne Einsatz
    app.call(Method::PUT, "/api/v1/dieter/settings", Some(json!({ "provider": "openrouter", "openrouterKey": "k", "allowChanges": true, "autoWatch": false, "watchMinutes": 10 }))).await;
    let (s, v) = app.call(Method::POST, "/api/v1/dieter/watch", None).await;
    assert_eq!(s, 200, "{v}");
    let inc = v["incidents"].as_array().unwrap();
    assert!(
        inc.iter()
            .any(|i| i["key"] == "proxy-kaputt.zweers.ch" && i["active"] == true),
        "{v}"
    );
    assert_eq!(v["conversations"], json!([]));
    // Mit Überwachung: automatischer Einsatz, nur einmal
    app.call(Method::PUT, "/api/v1/dieter/settings", Some(json!({ "provider": "openrouter", "allowChanges": true, "autoWatch": true, "autoFix": true, "watchMinutes": 10 }))).await;
    let (_, v) = app.call(Method::POST, "/api/v1/dieter/watch", None).await;
    let conv = v["conversations"][0].clone();
    assert_eq!(conv["automatic"], true, "{v}");
    assert!(
        conv["title"].as_str().unwrap().starts_with("Automatisch:"),
        "{conv}"
    );
    let t = wait(&app, conv["id"].as_i64().unwrap()).await;
    assert!(
        t["messages"][0]["text"]
            .as_str()
            .unwrap()
            .contains("kaputt.zweers.ch"),
        "{t}"
    );
    assert_eq!(
        t["messages"].as_array().unwrap().last().unwrap()["text"],
        "Alles geprüft."
    );
    let (_, v) = app.call(Method::POST, "/api/v1/dieter/watch", None).await;
    assert_eq!(
        v["conversations"].as_array().unwrap().len(),
        1,
        "nicht nochmal innerhalb von 6 Stunden"
    );
}
