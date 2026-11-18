//! DNS über HTTPS: abschaltbar (404), Prüfung der Eingabe (400, 413, 415), ohne Anmeldung
//! und ohne Herkunftsprüfung. Antworten mit echten Daten prüft `tests/dns.rs`.

mod common;

use base64::Engine as _;
use common::{login_as, put};
use rocket::http::{ContentType, Header, Status};
use serde_json::json;

/// Anfrage `example.com A` mit RD-Bit.
pub fn query() -> Vec<u8> {
    let mut m = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    m.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    m
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn dns_message() -> ContentType {
    ContentType::new("application", "dns-message")
}

#[rocket::async_test]
async fn disabled_doh_is_not_found() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    let (s, _) = put(
        &client,
        "/api/v1/settings/dns",
        json!({ "dohEnabled": false }),
    )
    .await;
    assert_eq!(s, Status::Ok);

    let res = client
        .get(format!("/dns-query?dns={}", b64(&query())))
        .dispatch()
        .await
        .status();
    assert_eq!(res, Status::NotFound);
    let res = client
        .post("/dns-query")
        .header(dns_message())
        .body(query())
        .dispatch()
        .await
        .status();
    assert_eq!(res, Status::NotFound);
    client.terminate().await;
}

#[rocket::async_test]
async fn bad_requests_are_rejected() {
    let (client, _dir) = common::client().await;
    for url in [
        "/dns-query".to_string(),
        "/dns-query?dns=".to_string(),
        "/dns-query?dns=%%%".to_string(),
        "/dns-query?dns=!!kein-base64!!".to_string(),
        // Zu kurz für einen DNS-Kopf
        format!("/dns-query?dns={}", b64(&[1, 2, 3])),
    ] {
        let res = client.get(url.clone()).dispatch().await.status();
        assert_eq!(res, Status::BadRequest, "{url}");
    }
    // Falscher Typ
    let res = client
        .post("/dns-query")
        .header(ContentType::JSON)
        .body(query())
        .dispatch()
        .await
        .status();
    assert_eq!(res, Status::UnsupportedMediaType);
    // Zu gross
    let res = client
        .post("/dns-query")
        .header(dns_message())
        .body(vec![0u8; 70_000])
        .dispatch()
        .await
        .status();
    assert_eq!(res, Status::PayloadTooLarge);
    // Leer
    let res = client
        .post("/dns-query")
        .header(dns_message())
        .dispatch()
        .await
        .status();
    assert_eq!(res, Status::BadRequest);
    client.terminate().await;
}

/// Eine gültige Anfrage kommt bis zur Engine – ohne Sitzung und auch mit fremdem `Origin`
/// (die Antwort selbst prüft `tests/dns.rs` mit der echten Engine).
#[rocket::async_test]
async fn no_session_or_origin_check() {
    let (client, _dir) = common::client().await;
    let res = client
        .post("/dns-query")
        .header(dns_message())
        .header(Header::new("Origin", "https://fremd.example"))
        .header(Header::new("Host", "dns.example"))
        .body(query())
        .dispatch()
        .await
        .status();
    assert_ne!(res, Status::Forbidden);
    assert_ne!(res, Status::Unauthorized);
    assert_ne!(res, Status::NotFound);
    assert_ne!(res, Status::BadRequest);
    client.terminate().await;
}
