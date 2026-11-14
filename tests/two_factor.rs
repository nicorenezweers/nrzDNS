//! Zwei-Faktor-Anmeldung: einrichten, Anmeldung mit Code, falscher Code, Wiederherstellungscode
//! (nur einmal), abschalten, Admin-Reset.

mod common;

use common::{delete, get, login_as, post, PASSWORD};
use nrzdns::auth::totp;
use rocket::http::Status;
use serde_json::json;

fn code(secret: &str, offset: i64) -> String {
    let s = totp::base32_decode(secret).unwrap();
    format!(
        "{:06}",
        totp::hotp(&s, (nrzdns::db::now() / 30 + offset) as u64)
    )
}

#[rocket::async_test]
async fn totp_login_flow() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    let (s, v) = get(&client, "/api/v1/me/2fa").await;
    assert_eq!(s, Status::Ok);
    assert_eq!(v["enabled"], false);
    let (s, setup) = post(&client, "/api/v1/me/2fa/setup", json!({})).await;
    assert_eq!(s, Status::Ok, "{setup}");
    let secret = setup["secret"].as_str().unwrap().to_string();
    assert!(setup["uri"]
        .as_str()
        .unwrap()
        .starts_with("otpauth://totp/nrzNetwork%3Aadmin?secret="));
    assert!(setup["qrSvg"].as_str().unwrap().contains("<svg"));
    let (s, _) = post(
        &client,
        "/api/v1/me/2fa/enable",
        json!({ "code": "000000" }),
    )
    .await;
    assert_eq!(s, Status::Unauthorized);
    let (s, v) = post(
        &client,
        "/api/v1/me/2fa/enable",
        json!({ "code": code(&secret, 0) }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    let codes: Vec<String> = serde_json::from_value(v["recoveryCodes"].clone()).unwrap();
    assert_eq!(codes.len(), 10);
    let (_, me) = get(&client, "/api/v1/me").await;
    assert_eq!(me["totpEnabled"], true);

    common::logout(&client).await;
    // Passwort allein reicht nicht
    let (s, v) = post(
        &client,
        "/api/v1/auth/login",
        json!({ "username": "admin", "password": PASSWORD }),
    )
    .await;
    assert_eq!(s, Status::Unauthorized);
    assert_eq!(v["error"]["code"], "totp_required", "{v}");
    let (s, v) = post(
        &client,
        "/api/v1/auth/login",
        json!({ "username": "admin", "password": PASSWORD, "code": "123456" }),
    )
    .await;
    assert_eq!(s, Status::Unauthorized, "{v}");
    assert_ne!(v["error"]["code"], "totp_required");
    // Gleicher Code wie beim Einschalten gilt nicht nochmal, der nächste schon
    let (s, _) = post(
        &client,
        "/api/v1/auth/login",
        json!({ "username": "admin", "password": PASSWORD, "code": code(&secret, 0) }),
    )
    .await;
    assert_eq!(s, Status::Unauthorized, "Code nicht zweimal");
    let (s, v) = post(
        &client,
        "/api/v1/auth/login",
        json!({ "username": "admin", "password": PASSWORD, "code": code(&secret, 1) }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    common::logout(&client).await;
    // Wiederherstellungscode: einmal
    let (s, _) = post(
        &client,
        "/api/v1/auth/login",
        json!({ "username": "admin", "password": PASSWORD, "code": codes[0].to_uppercase() }),
    )
    .await;
    assert_eq!(s, Status::Ok);
    let (_, st) = get(&client, "/api/v1/me/2fa").await;
    assert_eq!(st["recoveryLeft"], 9);
    common::logout(&client).await;
    let (s, _) = post(
        &client,
        "/api/v1/auth/login",
        json!({ "username": "admin", "password": PASSWORD, "code": codes[0] }),
    )
    .await;
    assert_eq!(s, Status::Unauthorized, "nur einmal");
    let (s, _) = post(
        &client,
        "/api/v1/auth/login",
        json!({ "username": "admin", "password": PASSWORD, "code": codes[1] }),
    )
    .await;
    assert_eq!(s, Status::Ok);

    // Abschalten: Passwort und Code nötig
    let (s, _) = post(
        &client,
        "/api/v1/me/2fa/disable",
        json!({ "password": "falsch", "code": codes[2] }),
    )
    .await;
    assert_eq!(s, Status::BadRequest);
    let (s, _) = post(
        &client,
        "/api/v1/me/2fa/disable",
        json!({ "password": PASSWORD, "code": codes[2] }),
    )
    .await;
    assert_eq!(s, Status::NoContent);
    let (_, me) = get(&client, "/api/v1/me").await;
    assert_eq!(me["totpEnabled"], false);

    // Admin-Reset für ein anderes Konto
    let (s, v) = post(
        &client,
        "/api/v1/admin/users",
        json!({ "username": "mia", "password": "Sehr-Geheim-123", "role": "member" }),
    )
    .await;
    assert_eq!(s, Status::Created, "{v}");
    let id = v["id"].as_i64().unwrap();
    let (s, _) = delete(&client, format!("/api/v1/admin/users/{id}/2fa")).await;
    assert_eq!(s, Status::NoContent);
}
