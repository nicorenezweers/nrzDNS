//! Spy gegen ein nachgebautes Internet (DNS über HTTPS, crt.sh, RDAP, Trace auf einem
//! Testserver): Bericht, Erkenntnisse, Bewertung, Rechte, aktive Prüfung nur für eigene
//! Domains.

mod common;

use common::{delete, get, login_as, post, put};
use rocket::http::Status;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::time::Duration;

fn dns(name: &str, qtype: &str) -> Value {
    let a = |t: u16, data: &str| json!({ "name": name, "type": t, "TTL": 300, "data": data });
    let answers: Vec<Value> = match (name, qtype) {
        ("zweers.ch", "NS") => vec![
            a(2, "ada.ns.cloudflare.com."),
            a(2, "bob.ns.cloudflare.com."),
        ],
        ("zweers.ch", "A") => vec![a(1, "104.21.1.1")],
        ("zweers.ch", "MX") => vec![a(15, "route1.mx.cloudflare.net.")],
        ("zweers.ch", "TXT") => vec![
            a(16, "\"v=spf1 include:_spf.mx.cloudflare.net ~all\""),
            a(16, "\"google-site-verification=abc\""),
        ],
        ("_dmarc.zweers.ch", "TXT") => vec![a(16, "\"v=DMARC1; p=none\"")],
        ("cf2024-1._domainkey.zweers.ch", "TXT") | ("google._domainkey.zweers.ch", "TXT") => {
            vec![a(16, "\"v=DKIM1; k=rsa; p=x\"")]
        }
        ("www.zweers.ch", "A") => vec![a(5, "zweers.ch."), a(1, "104.21.1.1")],
        ("nas.zweers.ch", "A") => vec![a(1, "192.168.0.198")],
        ("home.zweers.ch", "A") => vec![a(1, "85.1.2.3")],
        _ => vec![],
    };
    json!({ "Status": 0, "AD": false, "Answer": answers })
}

async fn fake_internet() -> String {
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{Body, Request, Response, Server};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let make = make_service_fn(|_| async {
        Ok::<_, Infallible>(service_fn(|req: Request<Body>| async move {
            let path = req.uri().path().to_string();
            let query: std::collections::HashMap<String, String> = req
                .uri()
                .query()
                .unwrap_or("")
                .split('&')
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| (k.to_string(), urlencoding::decode(v).unwrap().into_owned()))
                .collect();
            let json_reply = |v: Value| Response::new(Body::from(v.to_string()));
            let resp = match path.as_str() {
                "/dns-query" => json_reply(dns(&query["name"], &query["type"])),
                "/crt/" => json_reply(json!([
                    { "id": 1, "issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": "zweers.ch", "name_value": "zweers.ch\nnas.zweers.ch\nhome.zweers.ch", "not_before": "2025-03-01T00:00:00" },
                    { "id": 2, "issuer_name": "C=US, O=Let's Encrypt, CN=E6", "common_name": "*.zweers.ch", "name_value": "*.zweers.ch", "not_before": "2026-11-14T15:53:16" },
                    { "id": 3, "issuer_name": "C=BE, O=GlobalSign nv-sa, CN=X", "common_name": "nico@zweers.ch", "name_value": "nico@zweers.ch", "not_before": "2024-01-01T00:00:00" }
                ])),
                "/rdap/domain/zweers.ch" => json_reply(json!({
                    "secureDNS": { "delegationSigned": false },
                    "events": [{ "eventAction": "registration", "eventDate": "2015-03-02T10:00:00Z" }, { "eventAction": "expiration", "eventDate": "2099-03-02T10:00:00Z" }],
                    "entities": [{ "roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Hostpoint AG"]]] }]
                })),
                p if p.starts_with("/rdap/ip/104.") => json_reply(
                    json!({ "name": "CLOUDFLARENET", "country": "US", "entities": [{ "roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc."]]] }] }),
                ),
                p if p.starts_with("/rdap/ip/85.") => json_reply(
                    json!({ "name": "SWISSCOM-NET", "country": "CH", "entities": [{ "roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Swisscom (Schweiz) AG"]]] }] }),
                ),
                "/trace" => Response::new(Body::from("fl=1\nip=85.1.2.3\nts=1\n")),
                _ => Response::builder().status(404).body(Body::empty()).unwrap(),
            };
            Ok::<_, Infallible>(resp)
        }))
    });
    tokio::spawn(Server::from_tcp(listener).unwrap().serve(make));
    format!("http://127.0.0.1:{port}")
}

#[rocket::async_test]
async fn passive_scan_report() {
    let base = fake_internet().await;
    let (client, _dir) = common::client_with(|f| {
        f.merge(("spy_doh", format!("{base}/dns-query")))
            .merge(("spy_crtsh", format!("{base}/crt")))
            .merge(("spy_rdap", format!("{base}/rdap")))
            .merge(("spy_trace", format!("{base}/trace")))
    })
    .await;
    login_as(&client, "admin", true).await;

    // Aktiv nur für eigene Domains
    let (s, v) = post(
        &client,
        "/api/v1/spy/scan",
        json!({ "domain": "example.org", "active": true }),
    )
    .await;
    assert_eq!(s, Status::Forbidden, "{v}");
    let (s, _) = post(
        &client,
        "/api/v1/spy/scan",
        json!({ "domain": "kein domain" }),
    )
    .await;
    assert_eq!(s, Status::BadRequest);
    let (s, _) = put(
        &client,
        "/api/v1/tls",
        json!({ "enabled": false, "domains": ["*.zweers.ch"] }),
    )
    .await;
    assert_eq!(s, Status::Ok);
    let (_, v) = get(&client, "/api/v1/spy").await;
    assert_eq!(v["ownDomains"], json!(["zweers.ch"]), "{v}");

    let (s, v) = post(
        &client,
        "/api/v1/spy/scan",
        json!({ "domain": "Zweers.CH" }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["running"], true);
    let mut v = Value::Null;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(150)).await;
        v = get(&client, "/api/v1/spy").await.1;
        if v["running"] == false {
            break;
        }
    }
    let r = &v["reports"][0];
    assert_eq!(r["domain"], "zweers.ch", "{v}");
    assert_eq!(r["errors"], json!([]), "{r}");
    assert_eq!(r["dnsProvider"], "Cloudflare");
    assert_eq!(r["mail"]["provider"], "Cloudflare Email Routing");
    assert_eq!(r["mail"]["dkim"], json!(["cf2024-1", "google"]));
    assert_eq!(r["registration"]["registrar"], "Hostpoint AG");
    assert_eq!(r["certCount"], 3);
    assert_eq!(r["certEmails"], json!(["nico@zweers.ch"]));
    assert!(r["services"].to_string().contains("Google"), "{r}");
    let addr = |ip: &str| {
        r["addresses"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["ip"] == ip)
            .cloned()
            .unwrap()
    };
    assert_eq!(addr("104.21.1.1")["cdn"], true);
    assert_eq!(addr("85.1.2.3")["home"], true);
    assert_eq!(addr("85.1.2.3")["provider"], "Swisscom (Schweiz) AG");
    assert_eq!(addr("192.168.0.198")["private"], true);
    let titles: Vec<String> = r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["title"].as_str().unwrap().to_string())
        .collect();
    for t in [
        "Einträge zeigen auf deinen Anschluss zu Hause",
        "Interne Adressen im öffentlichen DNS",
        "1 E-Mail-Adresse(n) in Zertifikaten",
        "2 Namen in öffentlichen Zertifikaten",
        "DMARC nur beobachtend (p=none)",
        "Kein DNSSEC",
        "Kein CAA-Eintrag",
    ] {
        assert!(titles.iter().any(|x| x == t), "{t} fehlt: {titles:?}");
    }
    assert_eq!(r["findings"][0]["severity"], "high");
    assert!(r["score"].as_u64().unwrap() < 60, "{}", r["score"]);
    assert!(v["progress"].to_string().contains("Fertig"), "{v}");

    // Mitglieder lesen, starten nicht
    common::logout(&client).await;
    login_as(&client, "member", false).await;
    let (s, _) = get(&client, "/api/v1/spy").await;
    assert_eq!(s, Status::Ok);
    let (s, _) = post(
        &client,
        "/api/v1/spy/scan",
        json!({ "domain": "zweers.ch" }),
    )
    .await;
    assert_eq!(s, Status::Forbidden);
    let (s, _) = delete(&client, "/api/v1/spy/reports/zweers.ch").await;
    assert_eq!(s, Status::Forbidden);
}
