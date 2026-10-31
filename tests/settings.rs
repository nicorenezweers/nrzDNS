//! DNS-Einstellungen (prüfen, Grenzen, sofort in der Engine, gespeichert), Vorlagen,
//! Zustand des Servers, Cache und DNS-Client.

mod common;

use common::{engine, get, login_as, pool, post, put};
use nrzdns_types::{DnsSettings, Presets, ServerStatus};
use rocket::http::Status;
use serde_json::json;

#[rocket::async_test]
async fn dns_settings_are_validated_saved_and_applied() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;

    let (s, v) = get(&client, "/api/v1/settings/dns").await;
    assert_eq!(s, Status::Ok);
    let defaults: DnsSettings = serde_json::from_value(v).unwrap();
    assert_eq!(defaults, DnsSettings::default());

    // Zahlen ausserhalb ihres Bereichs → Grenze; Namen vereinheitlicht
    let (s, v) = put(
        &client,
        "/api/v1/settings/dns",
        json!({
            "serverDomain": "NS1.Home.Arpa.",
            "upstreamTimeoutMs": 50,
            "blocklistUpdateHours": 500,
            "logRetentionDays": 0,
            "dohEnabled": false,
            "forwarders": [{ "protocol": "https", "address": "https://dns.quad9.net/dns-query", "name": "Quad9" }],
            "forwardingStrategy": "parallel",
            "blockMode": "nxDomain"
        }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    let saved: DnsSettings = serde_json::from_value(v).unwrap();
    assert_eq!(saved.server_domain, "ns1.home.arpa");
    assert_eq!(saved.upstream_timeout_ms, 200);
    assert_eq!(saved.blocklist_update_hours, 168);
    assert_eq!(saved.log_retention_days, 1);
    assert!(!saved.doh_enabled);
    assert_eq!(
        saved.forwarding_strategy,
        nrzdns_types::ForwardingStrategy::Parallel
    );
    // Fehlende Felder bekommen ihre Vorgabe
    assert_eq!(saved.default_ttl, 3600);

    // Gespeichert und sofort in der Engine
    assert_eq!(
        get(&client, "/api/v1/settings/dns").await.1,
        serde_json::to_value(&saved).unwrap()
    );
    assert_eq!(engine(&client).settings(), saved);
    assert_eq!(
        nrzdns::services::settings::dns(pool(&client))
            .await
            .unwrap(),
        saved
    );

    for (bad, needle) in [
        (json!({ "serverDomain": "kein name" }), "Servername"),
        (
            json!({ "forwarders": [{ "protocol": "udp", "address": "dns.google" }] }),
            "IP-Adresse",
        ),
        (
            json!({ "forwarders": [{ "protocol": "https", "address": "http://1.1.1.1/dns-query" }] }),
            "HTTPS",
        ),
        (
            json!({ "blockMode": "customAddress", "blockIpv4": "", "blockIpv6": "" }),
            "Sperradresse",
        ),
        (json!({ "blockIpv4": "1.2.3.400" }), "IPv4"),
    ] {
        let (s, v) = put(&client, "/api/v1/settings/dns", bad.clone()).await;
        assert_eq!(s, Status::BadRequest, "{bad}: {v}");
        assert!(
            v["error"]["message"].as_str().unwrap().contains(needle),
            "{bad}: {v}"
        );
    }
    let many: Vec<_> = (0..21)
        .map(|i| json!({ "address": format!("10.0.0.{i}") }))
        .collect();
    let (s, _) = put(
        &client,
        "/api/v1/settings/dns",
        json!({ "forwarders": many }),
    )
    .await;
    assert_eq!(s, Status::BadRequest);
    // Nichts davon wurde übernommen
    assert_eq!(engine(&client).settings(), saved);
    client.terminate().await;
}

#[rocket::async_test]
async fn settings_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    {
        let rocket = nrzdns::build_with(common::figment(&dir)).await.unwrap();
        let client = rocket::local::asynchronous::Client::tracked(rocket)
            .await
            .unwrap();
        login_as(&client, "admin", true).await;
        let (s, _) = put(
            &client,
            "/api/v1/settings/dns",
            json!({ "defaultTtl": 120 }),
        )
        .await;
        assert_eq!(s, Status::Ok);
        client.terminate().await;
    }
    let rocket = nrzdns::build_with(common::figment(&dir)).await.unwrap();
    let client = rocket::local::asynchronous::Client::tracked(rocket)
        .await
        .unwrap();
    assert_eq!(engine(&client).settings().default_ttl, 120);
    client.terminate().await;
}

#[rocket::async_test]
async fn presets_server_cache_and_resolve() {
    let (client, _dir) = common::client().await;
    login_as(&client, "mia", false).await;

    let (s, v) = get(&client, "/api/v1/presets").await;
    assert_eq!(s, Status::Ok);
    let presets: Presets = serde_json::from_value(v).unwrap();
    assert_eq!(presets, Presets::builtin());

    let (s, v) = get(&client, "/api/v1/server").await;
    assert_eq!(s, Status::Ok);
    let server: ServerStatus = serde_json::from_value(v).unwrap();
    assert_eq!(server.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(server.doh_path, "/dns-query");
    assert!(server.doh_enabled);

    let (s, v) = get(&client, "/api/v1/cache?q=example&limit=5000").await;
    assert_eq!(s, Status::Ok, "{v}");
    assert!(v["entries"].is_array());

    // Ohne Namen gar nicht erst fragen
    let (s, v) = post(&client, "/api/v1/resolve", json!({ "name": " " })).await;
    assert_eq!(s, Status::BadRequest, "{v}");
    assert_eq!(v["error"]["message"], "Bitte einen Namen angeben.");
    client.terminate().await;
}

#[rocket::async_test]
async fn admins_flush_the_cache() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    let (s, v) = common::delete(&client, "/api/v1/cache").await;
    assert_eq!(s, Status::Ok);
    assert!(v["removed"].is_u64());
    let (s, v) = common::delete(&client, "/api/v1/cache/Example.com").await;
    assert_eq!(s, Status::Ok);
    assert!(v["removed"].is_u64());
    assert_eq!(
        common::delete(&client, "/api/v1/cache/a..b").await.0,
        Status::BadRequest
    );
    client.terminate().await;
}
