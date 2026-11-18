//! MCP-Server (`/mcp`): Token einrichten (nur Admins), Zugang per Bearer-Token, JSON-RPC
//! (initialize, tools/list, tools/call), Übersicht mit Werten aus dem Abfrageprotokoll und
//! Filter schalten nur mit „Änderungen erlauben“.

mod common;

use common::{delete, get, log_entry, login_as, logout, pool, post, put};
use nrzdns::services::querylog;
use nrzdns_types::{McpStatus, McpToken, ResponseKind};
use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;
use serde_json::{json, Value};

async fn rpc_raw(client: &Client, token: Option<&str>, body: Value) -> (Status, Value) {
    let mut req = client
        .post("/mcp")
        .header(ContentType::JSON)
        .header(Header::new("Accept", "application/json, text/event-stream"))
        .body(body.to_string());
    if let Some(t) = token {
        req = req.header(Header::new("Authorization", format!("Bearer {t}")));
    }
    let res = req.dispatch().await;
    let status = res.status();
    let text = res.into_string().await.unwrap_or_default();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

async fn rpc(client: &Client, token: &str, method: &str, params: Value) -> Value {
    let (s, v) = rpc_raw(
        client,
        Some(token),
        json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{method}: {v}");
    assert_eq!(v["id"], 7);
    v
}

/// Werkzeug aufrufen; zurück kommen der geparste Text und `isError`.
async fn tool(client: &Client, token: &str, name: &str, args: Value) -> (Value, bool) {
    let v = rpc(
        client,
        token,
        "tools/call",
        json!({ "name": name, "arguments": args }),
    )
    .await;
    let r = &v["result"];
    let text = r["content"][0]["text"].as_str().unwrap_or_default();
    let parsed = serde_json::from_str(text).unwrap_or(Value::String(text.into()));
    (parsed, r["isError"].as_bool().unwrap_or(false))
}

async fn setup() -> (Client, tempfile::TempDir, String) {
    let (client, dir) = common::client().await;
    login_as(&client, "admin", true).await;
    let (s, v) = post(&client, "/api/v1/settings/mcp/token", json!({})).await;
    assert_eq!(s, Status::Ok, "{v}");
    let t: McpToken = serde_json::from_value(v).unwrap();
    (client, dir, t.token)
}

#[rocket::async_test]
async fn token_lifecycle_and_access() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;

    let (s, v) = get(&client, "/api/v1/settings/mcp").await;
    assert_eq!(s, Status::Ok);
    let st: McpStatus = serde_json::from_value(v).unwrap();
    assert!(!st.enabled && !st.allow_changes && st.token_hint.is_none());
    assert_eq!(st.path, "/mcp");

    // Ohne Token ist MCP aus
    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    let (s, _) = rpc_raw(&client, Some("irgendwas"), ping.clone()).await;
    assert_eq!(s, Status::Unauthorized);

    let (_, v) = post(&client, "/api/v1/settings/mcp/token", json!({})).await;
    let first: McpToken = serde_json::from_value(v).unwrap();
    assert!(first.token.starts_with("nrzdns_mcp_"));
    assert!(first.status.enabled);
    let hint = first.status.token_hint.clone().unwrap();
    assert!(hint.starts_with("nrzdns_mcp_") && hint.contains('…'));
    assert!(!hint.contains(&first.token[11..]));

    // Richtiges Token → ok, falsches/fehlendes → 401 mit WWW-Authenticate
    let (s, v) = rpc_raw(&client, Some(&first.token), ping.clone()).await;
    assert_eq!((s, &v["result"]), (Status::Ok, &json!({})));
    let res = client
        .post("/mcp")
        .header(ContentType::JSON)
        .body(ping.to_string())
        .dispatch()
        .await;
    assert_eq!(res.status(), Status::Unauthorized);
    assert!(res
        .headers()
        .get_one("WWW-Authenticate")
        .unwrap()
        .starts_with("Bearer"));
    let (s, _) = rpc_raw(&client, Some("nrzdns_mcp_falsch"), ping.clone()).await;
    assert_eq!(s, Status::Unauthorized);

    // Fremde Seite (Browser) → 403
    let res = client
        .post("/mcp")
        .header(Header::new(
            "Authorization",
            format!("Bearer {}", first.token),
        ))
        .header(Header::new("Origin", "https://evil.example"))
        .body(ping.to_string())
        .dispatch()
        .await;
    assert_eq!(res.status(), Status::Forbidden);

    // Neues Token: das alte gilt nicht mehr
    let (_, v) = post(&client, "/api/v1/settings/mcp/token", json!({})).await;
    let second: McpToken = serde_json::from_value(v).unwrap();
    assert_ne!(first.token, second.token);
    let (s, _) = rpc_raw(&client, Some(&first.token), ping.clone()).await;
    assert_eq!(s, Status::Unauthorized);
    let (s, _) = rpc_raw(&client, Some(&second.token), ping.clone()).await;
    assert_eq!(s, Status::Ok);
    let (_, v) = get(&client, "/api/v1/settings/mcp").await;
    assert!(v["lastUsedAt"].as_i64().is_some());

    // Löschen → aus
    let (s, v) = delete(&client, "/api/v1/settings/mcp/token").await;
    assert_eq!(s, Status::Ok);
    assert_eq!(v["enabled"], false);
    let (s, _) = rpc_raw(&client, Some(&second.token), ping).await;
    assert_eq!(s, Status::Unauthorized);

    // GET /mcp: kein SSE-Strom
    assert_eq!(
        client.get("/mcp").dispatch().await.status(),
        Status::MethodNotAllowed
    );

    // Nur Admins
    logout(&client).await;
    login_as(&client, "bob", false).await;
    for (s, _) in [
        get(&client, "/api/v1/settings/mcp").await,
        post(&client, "/api/v1/settings/mcp/token", json!({})).await,
        put(
            &client,
            "/api/v1/settings/mcp",
            json!({ "allowChanges": true }),
        )
        .await,
    ] {
        assert_eq!(s, Status::Forbidden);
    }
}

#[rocket::async_test]
async fn env_token_wins() {
    let (client, _dir) =
        common::client_with(|f| f.merge(("mcp_token", "ein-sehr-geheimes-token"))).await;
    login_as(&client, "admin", true).await;
    let (_, v) = get(&client, "/api/v1/settings/mcp").await;
    assert_eq!(
        (v["enabled"].clone(), v["fromEnv"].clone()),
        (json!(true), json!(true))
    );
    assert_eq!(v["tokenHint"], "ein…ken");
    let (s, _) = post(&client, "/api/v1/settings/mcp/token", json!({})).await;
    assert_eq!(s, Status::Conflict);
    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    let (s, _) = rpc_raw(&client, Some("ein-sehr-geheimes-token"), ping).await;
    assert_eq!(s, Status::Ok);

    let dir = tempfile::tempdir().unwrap();
    let short = nrzdns::build_with(common::figment(&dir).merge(("mcp_token", "kurz"))).await;
    assert!(short.is_err());
}

#[rocket::async_test]
async fn protocol_and_overview() {
    let (client, _dir, token) = setup().await;

    let v = rpc(
        &client,
        &token,
        "initialize",
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "nrzDashboard", "version": "1" }
        }),
    )
    .await;
    assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(v["result"]["serverInfo"]["name"], "nrzDNS");
    assert!(v["result"]["capabilities"]["tools"].is_object());
    let v = rpc(
        &client,
        &token,
        "initialize",
        json!({ "protocolVersion": "1999-01-01" }),
    )
    .await;
    assert_eq!(v["result"]["protocolVersion"], "2025-06-18");

    // Benachrichtigung → 202 ohne Körper
    let (s, v) = rpc_raw(
        &client,
        Some(&token),
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    )
    .await;
    assert_eq!((s, v), (Status::Accepted, Value::Null));

    // Fehler nach JSON-RPC
    let v = rpc(&client, &token, "gibt/es/nicht", json!({})).await;
    assert_eq!(v["error"]["code"], -32601);
    let v = rpc(
        &client,
        &token,
        "tools/call",
        json!({ "name": "gibt_es_nicht" }),
    )
    .await;
    assert_eq!(v["error"]["code"], -32602);
    let res = client
        .post("/mcp")
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .body("{kaputt")
        .dispatch()
        .await;
    let v: Value = serde_json::from_str(&res.into_string().await.unwrap()).unwrap();
    assert_eq!(v["error"]["code"], -32700);

    // Ohne „Änderungen erlauben“: nur lesende Werkzeuge
    let v = rpc(&client, &token, "tools/list", json!({})).await;
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"get_overview") && names.contains(&"get_query_log"));
    assert!(!names.contains(&"set_blocking"));

    // Werte aus dem Abfrageprotokoll
    let now_ms = nrzdns::db::now() * 1000;
    let mut rows = Vec::new();
    for i in 0..6 {
        rows.push(log_entry(now_ms - 1000 * i, "10.0.0.2", "example.com"));
    }
    let mut b = log_entry(now_ms - 500, "10.0.0.3", "ads.tracker.net");
    b.kind = ResponseKind::Blocked;
    rows.push(b.clone());
    rows.push(b);
    let mut c = log_entry(now_ms - 700, "10.0.0.2", "example.com");
    c.kind = ResponseKind::Cached;
    rows.push(c);
    querylog::insert_batch(pool(&client), &rows).await.unwrap();

    let (o, err) = tool(&client, &token, "get_overview", json!({ "range": "hour" })).await;
    assert!(!err, "{o}");
    assert_eq!(o["range"], "hour");
    assert_eq!(o["totals"]["queries"], 9);
    assert_eq!(o["totals"]["blocked"], 2);
    assert_eq!(o["totals"]["blockedPercent"], 22.2);
    assert_eq!(o["totals"]["cacheHitPercent"], 14.3);
    assert_eq!(o["totals"]["clients"], 2);
    assert_eq!(o["topBlocked"][0]["name"], "ads.tracker.net");
    assert_eq!(
        o["topDomains"][0],
        json!({ "name": "example.com", "hits": 7 })
    );
    assert_eq!(o["blocking"]["enabled"], true);
    assert_eq!(o["blocking"]["active"], true);
    assert!(o["server"]["version"].is_string());

    // structuredContent = dasselbe Objekt
    let v = rpc(
        &client,
        &token,
        "tools/call",
        json!({ "name": "get_overview" }),
    )
    .await;
    assert_eq!(v["result"]["structuredContent"]["range"], "day");

    let (d, _) = tool(
        &client,
        &token,
        "get_statistics",
        json!({ "range": "day", "includeSeries": false }),
    )
    .await;
    assert_eq!(d["series"], json!([]));
    assert_eq!(d["totals"]["queries"], 9);
    let (d, _) = tool(
        &client,
        &token,
        "get_statistics",
        json!({ "range": "week" }),
    )
    .await;
    assert_eq!(d["series"].as_array().unwrap().len(), 28);
    let (_, err) = tool(
        &client,
        &token,
        "get_statistics",
        json!({ "range": "jahr" }),
    )
    .await;
    assert!(err);

    let (l, _) = tool(
        &client,
        &token,
        "get_query_log",
        json!({ "kind": "blocked", "limit": 1 }),
    )
    .await;
    assert_eq!(l["total"], 2);
    assert_eq!(l["entries"].as_array().unwrap().len(), 1);
    let (c, _) = tool(
        &client,
        &token,
        "check_domain",
        json!({ "domain": "ads.example.com" }),
    )
    .await;
    assert_eq!(c["blocked"], false);
    let (z, _) = tool(&client, &token, "list_zones", json!({})).await;
    assert!(z["zones"].is_array());
    let (_, err) = tool(&client, &token, "get_overview", json!({ "unbekannt": 1 })).await;
    assert!(err);

    // Schalten ist (noch) verboten
    let (msg, err) = tool(&client, &token, "set_blocking", json!({ "enabled": false })).await;
    assert!(err);
    assert!(msg.as_str().unwrap().contains("ausgeschaltet"));
}

#[rocket::async_test]
async fn filters_can_be_switched_when_allowed() {
    let (client, _dir, token) = setup().await;
    let (s, v) = put(
        &client,
        "/api/v1/settings/mcp",
        json!({ "allowChanges": true }),
    )
    .await;
    assert_eq!(s, Status::Ok);
    assert_eq!(v["allowChanges"], true);

    let v = rpc(&client, &token, "tools/list", json!({})).await;
    let tools = v["result"]["tools"].as_array().unwrap();
    let set = tools.iter().find(|t| t["name"] == "set_blocking").unwrap();
    assert_eq!(set["annotations"]["readOnlyHint"], false);

    // Filter aus → Engine und Einstellungen
    let (b, err) = tool(&client, &token, "set_blocking", json!({ "enabled": false })).await;
    assert!(!err, "{b}");
    assert_eq!(b["enabled"], false);
    let (_, dns) = get(&client, "/api/v1/settings/dns").await;
    assert_eq!(dns["blockingEnabled"], false);
    assert!(!common::engine(&client).settings().blocking_enabled);

    // Pause, dann einschalten beendet die Pause
    tool(&client, &token, "set_blocking", json!({ "enabled": true })).await;
    let (b, _) = tool(&client, &token, "pause_blocking", json!({ "minutes": 15 })).await;
    assert!(b["pausedUntil"].as_i64().is_some());
    let (o, _) = tool(&client, &token, "get_overview", json!({})).await;
    assert_eq!(
        (
            o["blocking"]["paused"].clone(),
            o["blocking"]["active"].clone()
        ),
        (json!(true), json!(false))
    );
    let (b, _) = tool(&client, &token, "set_blocking", json!({ "enabled": true })).await;
    assert_eq!(b["pausedUntil"], Value::Null);
    let (_, err) = tool(
        &client,
        &token,
        "pause_blocking",
        json!({ "minutes": 99999 }),
    )
    .await;
    assert!(err);

    // Eigene Regeln
    let (e, err) = tool(
        &client,
        &token,
        "add_rule",
        json!({ "list": "blocked", "domain": "Ads.Example.com", "comment": "per MCP" }),
    )
    .await;
    assert!(!err, "{e}");
    assert_eq!(e["domain"], "ads.example.com");
    let (c, _) = tool(
        &client,
        &token,
        "check_domain",
        json!({ "domain": "x.ads.example.com" }),
    )
    .await;
    assert_eq!(c["blocked"], true);
    let (r, _) = tool(&client, &token, "list_rules", json!({ "list": "blocked" })).await;
    assert_eq!(r["count"], 1);
    let (_, err) = tool(
        &client,
        &token,
        "remove_rule",
        json!({ "list": "blocked", "domain": "ads.example.com" }),
    )
    .await;
    assert!(!err);
    let (c, _) = tool(
        &client,
        &token,
        "check_domain",
        json!({ "domain": "x.ads.example.com" }),
    )
    .await;
    assert_eq!(c["blocked"], false);
    let (_, err) = tool(
        &client,
        &token,
        "add_rule",
        json!({ "list": "falsch", "domain": "a.com" }),
    )
    .await;
    assert!(err);

    // Sperrliste per Name ausschalten (ohne Laden – keine Hintergrundarbeiten im Test)
    let (s, v) = post(
        &client,
        "/api/v1/blocking/lists",
        json!({ "name": "Testliste", "url": "https://example.org/hosts", "enabled": true }),
    )
    .await;
    assert_eq!(s, Status::Created, "{v}");
    let (l, err) = tool(
        &client,
        &token,
        "set_blocklist",
        json!({ "name": "testliste", "enabled": false }),
    )
    .await;
    assert!(!err, "{l}");
    assert_eq!(l["enabled"], false);
    let (_, err) = tool(
        &client,
        &token,
        "set_blocklist",
        json!({ "id": 999, "enabled": true }),
    )
    .await;
    assert!(err);

    let (f, _) = tool(&client, &token, "flush_cache", json!({})).await;
    assert_eq!(f["removed"], 0);
}
