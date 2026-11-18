//! Zusammenspiel mit der echten DNS-Engine: DoH-Antworten aus eigenen Zonen (mit
//! Protokolleintrag), DNS-Client, Sperren, Sperrlisten aus dem Zwischenspeicher, Import und
//! Export von Zonendateien.

mod common;

use base64::Engine as _;
use common::{get, login_as, post};
use rocket::http::{ContentType, Status};
use serde_json::json;
use std::time::Duration;

/// DNS-Anfrage im Wire-Format.
fn query(name: &str, qtype: u16) -> Vec<u8> {
    let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&[0, 1]);
    m
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Zone `home.arpa` mit `nas A 192.168.1.10`.
async fn home_zone(client: &rocket::local::asynchronous::Client) {
    let (s, v) = post(client, "/api/v1/zones", json!({ "name": "home.arpa" })).await;
    assert_eq!(s, Status::Created, "{v}");
    let (s, v) = post(
        client,
        format!("/api/v1/zones/{}/records", v["id"]),
        json!({ "name": "nas", "data": { "type": "A", "address": "192.168.1.10" } }),
    )
    .await;
    assert_eq!(s, Status::Created, "{v}");
}

#[rocket::async_test]
async fn doh_answers_from_zones_and_logs() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    home_zone(&client).await;

    let q = query("nas.home.arpa", 1);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&q);
    let res = client
        .get(format!("/dns-query?dns={encoded}"))
        .dispatch()
        .await;
    assert_eq!(res.status(), Status::Ok);
    assert_eq!(
        res.content_type(),
        Some(ContentType::new("application", "dns-message"))
    );
    let cache = res.headers().get_one("Cache-Control").unwrap().to_string();
    assert!(cache.starts_with("max-age="), "{cache}");
    let answer = res.into_bytes().await.unwrap();
    assert_eq!(&answer[..2], &[0x12, 0x34], "gleiche ID");
    assert!(answer[2] & 0x80 != 0, "QR gesetzt");
    assert!(answer[2] & 0x04 != 0, "AA gesetzt");
    assert!(contains(&answer, &[192, 168, 1, 10]));

    let res = client
        .post("/dns-query")
        .header(ContentType::new("application", "dns-message"))
        .body(query("gibtsnicht.home.arpa", 1))
        .dispatch()
        .await;
    assert_eq!(res.status(), Status::Ok);
    let answer = res.into_bytes().await.unwrap();
    assert_eq!(answer[3] & 0x0f, 3, "NXDOMAIN");

    // Der Protokoll-Schreiber speichert spätestens nach einer Sekunde
    let mut logged = serde_json::Value::Null;
    for _ in 0..30 {
        let (_, v) = get(&client, "/api/v1/logs?qname=home.arpa").await;
        if v["total"] == 2 {
            logged = v;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(logged["total"], 2, "{logged}");
    let entries = logged["entries"].as_array().unwrap();
    assert!(entries.iter().all(|e| e["protocol"] == "https"));
    assert!(entries.iter().all(|e| e["kind"] == "authoritative"));
    assert!(entries.iter().any(|e| e["rcode"] == "NXDOMAIN"));
    client.terminate().await;
}

#[rocket::async_test]
async fn resolve_uses_zones_and_reports_errors() {
    let (client, _dir) = common::client().await;
    login_as(&client, "mia", false).await;
    login_as(&client, "admin", true).await;
    home_zone(&client).await;

    let (s, v) = post(
        &client,
        "/api/v1/resolve",
        json!({ "name": "nas.home.arpa", "qtype": "A" }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["rcode"], "NOERROR");
    assert_eq!(v["kind"], "authoritative");
    assert!(v["answers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["data"] == "192.168.1.10"));

    let (s, v) = post(
        &client,
        "/api/v1/resolve",
        json!({ "name": "nas.home.arpa", "qtype": "KEINTYP" }),
    )
    .await;
    assert_eq!(s, Status::BadRequest, "{v}");
    // Ein Server, der nicht antwortet → 502 mit Meldung
    let (s, v) = post(
        &client,
        "/api/v1/resolve",
        json!({ "name": "example.com", "server": "127.0.0.1:9", "protocol": "tcp" }),
    )
    .await;
    assert_eq!(s, Status::BadGateway, "{v}");
    assert!(!v["error"]["message"].as_str().unwrap().is_empty());
    client.terminate().await;
}

#[rocket::async_test]
async fn custom_blocks_and_exceptions_reach_the_engine() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    post(
        &client,
        "/api/v1/blocked",
        json!({ "domain": "tracker.example" }),
    )
    .await;
    let (_, v) = get(&client, "/api/v1/blocking/check?domain=ads.tracker.example").await;
    assert_eq!(v["blocked"], true, "{v}");
    assert!(!v["matches"].as_array().unwrap().is_empty());

    post(
        &client,
        "/api/v1/allowed",
        json!({ "domain": "ok.tracker.example" }),
    )
    .await;
    let (_, v) = get(&client, "/api/v1/blocking/check?domain=ok.tracker.example").await;
    assert_eq!(
        (v["blocked"].clone(), v["allowed"].clone()),
        (json!(false), json!(true)),
        "{v}"
    );

    common::delete(&client, "/api/v1/blocked/tracker.example").await;
    let (_, v) = get(&client, "/api/v1/blocking/check?domain=ads.tracker.example").await;
    assert_eq!(v["blocked"], false, "{v}");
    client.terminate().await;
}

#[rocket::async_test]
async fn cached_block_lists_are_loaded_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    {
        let rocket = nrzdns::build_with(common::figment(&dir)).await.unwrap();
        let client = rocket::local::asynchronous::Client::tracked(rocket)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO block_lists (id, name, url, enabled, domain_count, last_updated_at, created_at)
             VALUES (1, 'Testliste', 'https://example.org/list.txt', 1, 2, 0, 0),
                    (2, 'Aus', 'https://example.org/off.txt', 0, 1, 0, 0)",
        )
        .execute(common::pool(&client))
        .await
        .unwrap();
        client.terminate().await;
    }
    std::fs::create_dir_all(dir.path().join("blocklists")).unwrap();
    std::fs::write(
        dir.path().join("blocklists/1.txt"),
        "ads.example.com\ntracker.example.net\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("blocklists/2.txt"), "off.example.com\n").unwrap();

    let rocket = nrzdns::build_with(common::figment(&dir)).await.unwrap();
    let client = rocket::local::asynchronous::Client::tracked(rocket)
        .await
        .unwrap();
    let engine = common::engine(&client);
    let check = engine.check_domain("x.ads.example.com");
    assert!(check.blocked, "{check:?}");
    assert!(
        check.matches.iter().any(|m| m.contains("Testliste")),
        "{check:?}"
    );
    assert!(
        !engine.check_domain("off.example.com").blocked,
        "deaktivierte Liste"
    );
    assert_eq!(engine.blocked_domain_count(), 2);
    client.terminate().await;
}

#[test]
fn block_list_formats() {
    let text = "# Kommentar\n0.0.0.0 ads.example.com\n127.0.0.1 a.com b.com\n\
                ||tracker.example.net^\n@@||ok.example.org^\n*.wild.example\nlocalhost\n! Adblock\n";
    let domains = nrzdns_engine::blocklist::parse(text);
    assert_eq!(
        domains,
        [
            "a.com",
            "ads.example.com",
            "b.com",
            "tracker.example.net",
            "wild.example"
        ]
    );
}

#[rocket::async_test]
async fn zone_files_round_trip() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    let text = "$ORIGIN lab.example.\n$TTL 300\n\
        @ IN SOA ns1.lab.example. hostmaster.lab.example. ( 2024010101 3600 600 86400 300 )\n\
        @ IN NS ns1.lab.example.\n\
        ns1 IN A 10.0.0.1\n\
        www 60 IN A 10.0.0.5\n\
        alias IN CNAME www\n\
        @ IN MX 10 mail.lab.example.\n\
        @ IN TXT \"v=spf1 -all\"\n\
        x IN HINFO \"pc\" \"linux\"\n";
    let (s, v) = post(&client, "/api/v1/zones/import", json!({ "text": text })).await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["zone"]["name"], "lab.example");
    assert_eq!(v["zone"]["soa"]["primaryNs"], "ns1.lab.example");
    assert_eq!(v["imported"], 6, "{v}");
    assert!(
        !v["skipped"].as_array().unwrap().is_empty(),
        "HINFO übersprungen"
    );

    let res = client
        .get(format!("/api/v1/zones/{}/export", v["zone"]["id"]))
        .dispatch()
        .await;
    let exported = res.into_string().await.unwrap();
    for part in [
        "$ORIGIN lab.example.",
        "SOA",
        "10.0.0.5",
        "mail.lab.example.",
        "v=spf1 -all",
    ] {
        assert!(exported.contains(part), "{part} fehlt in:\n{exported}");
    }
    client.terminate().await;
}
