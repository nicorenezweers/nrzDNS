//! Zonen: anlegen (SOA, NS), Einträge mit Prüfung, Seriennummer, Weiterleitungszonen,
//! Export als Datei, Import, Löschen mit allen Einträgen.

mod common;

use common::{delete, get, login_as, pool, post, put};
use nrzdns_types::{Zone, ZoneDetail, ZoneRecord};
use rocket::http::{Accept, ContentType, Status};
use serde_json::{json, Value};

fn today_base() -> u32 {
    let d = time::OffsetDateTime::now_utc().date();
    (d.year() as u32 * 10_000 + u32::from(u8::from(d.month())) * 100 + u32::from(d.day())) * 100
}

#[rocket::async_test]
async fn primary_zone_with_soa_ns_and_records() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;

    let (s, v) = post(&client, "/api/v1/zones", json!({ "name": " Home.ARPA. " })).await;
    assert_eq!(s, Status::Created, "{v}");
    let zone: Zone = serde_json::from_value(v).unwrap();
    assert_eq!(zone.name, "home.arpa");
    assert_eq!(zone.soa.primary_ns, "ns.nrzdns.local");
    assert_eq!(zone.soa.responsible, "hostmaster.home.arpa");
    assert_eq!(zone.soa.serial, today_base() + 1);
    assert_eq!(zone.record_count, 1);
    let url = format!("/api/v1/zones/{}", zone.id);

    let (s, v) = get(&client, &url).await;
    assert_eq!(s, Status::Ok);
    let detail: ZoneDetail = serde_json::from_value(v).unwrap();
    assert_eq!(detail.records.len(), 1);
    assert_eq!(detail.records[0].name, "@");
    assert_eq!(
        detail.records[0].data,
        nrzdns_types::RecordData::NS {
            host: "ns.nrzdns.local".into()
        }
    );
    assert_eq!(detail.records[0].ttl, 3600);

    // Eintrag anlegen: Name relativ, Adresse kanonisch, TTL 0 = Vorgabe
    let (s, v) = post(
        &client,
        format!("{url}/records"),
        json!({ "name": "NAS", "data": { "type": "AAAA", "address": "FD00:0::10" } }),
    )
    .await;
    assert_eq!(s, Status::Created, "{v}");
    let nas: ZoneRecord = serde_json::from_value(v).unwrap();
    assert_eq!((nas.name.as_str(), nas.ttl), ("nas", 3600));
    assert_eq!(
        nas.data,
        nrzdns_types::RecordData::AAAA {
            address: "fd00::10".into()
        }
    );
    let serial = |v: &Value| v["soa"]["serial"].as_u64().unwrap() as u32;
    let (_, v) = get(&client, &url).await;
    assert_eq!(serial(&v["zone"]), today_base() + 2, "Seriennummer erhöht");
    assert_eq!(v["zone"]["recordCount"], 2);

    // Ändern und löschen erhöhen die Seriennummer ebenfalls
    let rurl = format!("{url}/records/{}", nas.id);
    let (s, v) = put(
        &client,
        &rurl,
        json!({ "name": "nas.home.arpa.", "ttl": 60, "data": { "type": "A", "address": "192.168.1.10" }, "comment": "Keller" }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(
        (v["name"].clone(), v["ttl"].clone()),
        (json!("nas"), json!(60))
    );
    assert_eq!(v["comment"], "Keller");
    assert_eq!(
        serial(&get(&client, &url).await.1["zone"]),
        today_base() + 3
    );
    assert_eq!(delete(&client, &rurl).await.0, Status::NoContent);
    assert_eq!(delete(&client, &rurl).await.0, Status::NotFound);
    assert_eq!(
        serial(&get(&client, &url).await.1["zone"]),
        today_base() + 4
    );

    // Zone ändern: SOA geprüft, Seriennummer weiter
    let (s, v) = put(
        &client,
        &url,
        json!({ "disabled": true, "comment": "Heimnetz",
                "soa": { "primaryNs": "ns1.home.arpa", "responsible": "admin@home.arpa", "serial": 1,
                         "refresh": 10, "retry": 300, "expire": 604800, "minimum": 60 } }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["disabled"], true);
    assert_eq!(v["comment"], "Heimnetz");
    assert_eq!(v["soa"]["responsible"], "admin.home.arpa");
    assert_eq!(v["soa"]["refresh"], 60, "auf die Grenze gesetzt");
    assert_eq!(serial(&v), today_base() + 5);
    // Ausdrücklich höhere Seriennummer gilt
    let (_, v) = put(
        &client,
        &url,
        json!({ "soa": { "primaryNs": "ns1.home.arpa", "responsible": "admin.home.arpa", "serial": 4000000000u32 } }),
    )
    .await;
    assert_eq!(serial(&v), 4_000_000_000);
    let (s, _) = put(
        &client,
        &url,
        json!({ "soa": { "primaryNs": "kein name", "responsible": "x.y" } }),
    )
    .await;
    assert_eq!(s, Status::BadRequest);

    // Gleicher Name noch einmal → Konflikt
    let (s, v) = post(&client, "/api/v1/zones", json!({ "name": "home.arpa" })).await;
    assert_eq!(s, Status::Conflict, "{v}");
    assert_eq!(v["error"]["message"], "Diese Zone gibt es schon.");

    // Liste
    let (_, v) = get(&client, "/api/v1/zones").await;
    assert_eq!(v.as_array().unwrap().len(), 1);

    // Löschen nimmt die Einträge mit
    assert_eq!(delete(&client, &url).await.0, Status::NoContent);
    assert_eq!(get(&client, &url).await.0, Status::NotFound);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM zone_records")
        .fetch_one(pool(&client))
        .await
        .unwrap();
    assert_eq!(left, 0);
    client.terminate().await;
}

#[rocket::async_test]
async fn records_are_validated() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    let (_, v) = post(&client, "/api/v1/zones", json!({ "name": "example.com" })).await;
    let records = format!("/api/v1/zones/{}/records", v["id"]);

    for (body, status, needle) in [
        (
            json!({ "name": "a", "data": { "type": "A", "address": "1.2.3" } }),
            400,
            "IPv4",
        ),
        (
            json!({ "name": "a", "data": { "type": "AAAA", "address": "1.2.3.4" } }),
            400,
            "IPv6",
        ),
        (
            json!({ "name": "a b", "data": { "type": "A", "address": "1.2.3.4" } }),
            400,
            "Name",
        ),
        (
            json!({ "name": "x.other.org.", "data": { "type": "A", "address": "1.2.3.4" } }),
            400,
            "nicht in der Zone",
        ),
        (
            json!({ "name": "@", "data": { "type": "CNAME", "target": "other.org" } }),
            400,
            "Zonenspitze",
        ),
        (
            json!({ "name": "mx", "data": { "type": "MX", "preference": 10, "exchange": "-bad-" } }),
            400,
            "MX",
        ),
        (
            json!({ "name": "t", "data": { "type": "TXT", "text": "" } }),
            400,
            "TXT",
        ),
        (
            json!({ "name": "t", "data": { "type": "TXT", "text": "x".repeat(4001) } }),
            400,
            "TXT",
        ),
        (
            json!({ "name": "@", "data": { "type": "CAA", "flags": 0, "tag": "is sue", "value": "x" } }),
            400,
            "CAA",
        ),
        (
            json!({ "name": "s", "data": { "type": "SRV", "priority": 1, "weight": 1, "port": 80, "target": "" } }),
            400,
            "SRV",
        ),
    ] {
        let (s, v) = post(&client, &records, body.clone()).await;
        assert_eq!(s.code, status, "{body}: {v}");
        assert!(
            v["error"]["message"].as_str().unwrap().contains(needle),
            "{body}: {v}"
        );
    }
    // Unbekannter Typ ist kein gültiges JSON → 422
    let (s, _) = post(
        &client,
        &records,
        json!({ "name": "a", "data": { "type": "HINFO" } }),
    )
    .await;
    assert_eq!(s, Status::UnprocessableEntity);

    // Gültige Einträge, auch Platzhalter und lange TXT
    for body in [
        json!({ "name": "www", "data": { "type": "A", "address": "93.184.215.14" } }),
        json!({ "name": "www", "data": { "type": "A", "address": "93.184.215.15" } }),
        json!({ "name": "*.dev", "data": { "type": "A", "address": "10.0.0.1" } }),
        json!({ "name": "@", "data": { "type": "MX", "preference": 10, "exchange": "Mail.Example.com." } }),
        json!({ "name": "@", "data": { "type": "TXT", "text": "v=spf1 -all ".repeat(40) } }),
        json!({ "name": "_sip._tcp", "data": { "type": "SRV", "priority": 10, "weight": 5, "port": 5060, "target": "sip.example.com" } }),
        json!({ "name": "@", "data": { "type": "CAA", "flags": 0, "tag": "issue", "value": "letsencrypt.org" } }),
        json!({ "name": "alias", "data": { "type": "CNAME", "target": "www.example.com" } }),
    ] {
        let (s, v) = post(&client, &records, body.clone()).await;
        assert_eq!(s, Status::Created, "{body}: {v}");
    }
    // Doppelt → Konflikt
    let (s, v) = post(
        &client,
        &records,
        json!({ "name": "WWW", "ttl": 5, "data": { "type": "A", "address": "93.184.215.14" } }),
    )
    .await;
    assert_eq!(s, Status::Conflict, "{v}");
    assert_eq!(v["error"]["message"], "Diesen Eintrag gibt es schon.");
    // CNAME neben anderen Einträgen desselben Namens → Konflikt (in beide Richtungen)
    for body in [
        json!({ "name": "www", "data": { "type": "CNAME", "target": "other.org" } }),
        json!({ "name": "alias", "data": { "type": "TXT", "text": "hallo" } }),
        json!({ "name": "alias", "data": { "type": "CNAME", "target": "other.org" } }),
    ] {
        let (s, v) = post(&client, &records, body.clone()).await;
        assert_eq!(s, Status::Conflict, "{body}: {v}");
        assert!(
            v["error"]["message"].as_str().unwrap().contains("CNAME"),
            "{v}"
        );
    }
    // Einen CNAME durch einen anderen ersetzen geht (der Eintrag selbst zählt nicht)
    let (_, v) = get(&client, records.trim_end_matches("/records")).await;
    let alias = v["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "alias")
        .unwrap()
        .clone();
    let (s, v) = put(
        &client,
        format!("{records}/{}", alias["id"]),
        json!({ "name": "alias", "data": { "type": "CNAME", "target": "other.org" } }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["data"]["target"], "other.org");
    // Eintrag einer fremden Zone gibt es hier nicht
    let (s, _) = put(
        &client,
        format!("/api/v1/zones/999/records/{}", alias["id"]),
        json!({ "name": "alias", "data": { "type": "CNAME", "target": "x.org" } }),
    )
    .await;
    assert_eq!(s, Status::NotFound);
    client.terminate().await;
}

#[rocket::async_test]
async fn forwarder_zones_need_a_server() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    let (s, v) = post(
        &client,
        "/api/v1/zones",
        json!({ "name": "fritz.box", "kind": "forwarder" }),
    )
    .await;
    assert_eq!(s, Status::BadRequest, "{v}");
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("mindestens einen Server"));
    let (s, v) = post(
        &client,
        "/api/v1/zones",
        json!({ "name": "fritz.box", "kind": "forwarder", "forwarders": [{ "address": "fritz.box" }] }),
    )
    .await;
    assert_eq!(s, Status::BadRequest, "{v}");

    let (s, v) = post(
        &client,
        "/api/v1/zones",
        json!({ "name": "fritz.box", "kind": "forwarder", "comment": "Router",
                "forwarders": [{ "protocol": "udp", "address": " 192.168.178.1 " }] }),
    )
    .await;
    assert_eq!(s, Status::Created, "{v}");
    let zone: Zone = serde_json::from_value(v).unwrap();
    assert_eq!(zone.kind, nrzdns_types::ZoneKind::Forwarder);
    assert_eq!(zone.forwarders[0].address, "192.168.178.1");
    assert_eq!(zone.record_count, 0, "kein NS bei Weiterleitungen");
    let url = format!("/api/v1/zones/{}", zone.id);
    let (s, _) = put(&client, &url, json!({ "forwarders": [] })).await;
    assert_eq!(s, Status::BadRequest);
    let (s, v) = put(
        &client,
        &url,
        json!({ "forwarders": [{ "protocol": "tls", "address": "192.168.178.1:853", "tlsName": "Fritz.Box" }] }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["forwarders"][0]["tlsName"], "fritz.box");

    // Ungültige Zonennamen
    for name in ["", "a..b", "-x.org", "mit leer.org"] {
        let (s, _) = post(&client, "/api/v1/zones", json!({ "name": name })).await;
        assert_eq!(s, Status::BadRequest, "{name}");
    }
    client.terminate().await;
}

#[rocket::async_test]
async fn export_is_a_download() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    let (_, v) = post(&client, "/api/v1/zones", json!({ "name": "example.com" })).await;
    let res = client
        .get(format!("/api/v1/zones/{}/export", v["id"]))
        .header(Accept::JSON)
        .dispatch()
        .await;
    assert_eq!(res.status(), Status::Ok);
    assert_eq!(res.content_type(), Some(ContentType::Plain));
    assert_eq!(
        res.headers().get_one("Content-Disposition"),
        Some("attachment; filename=\"example.com.zone\"")
    );
    let text = res.into_string().await.unwrap();
    assert!(text.contains("$ORIGIN example.com."), "{text}");
    assert_eq!(
        client
            .get("/api/v1/zones/999/export")
            .dispatch()
            .await
            .status(),
        Status::NotFound
    );
    client.terminate().await;
}

#[rocket::async_test]
async fn import_creates_or_replaces_zones() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;
    // Leer oder ohne Namen geht nicht
    let (s, _) = post(&client, "/api/v1/zones/import", json!({ "text": "  " })).await;
    assert_eq!(s, Status::BadRequest);
    let (s, v) = post(
        &client,
        "/api/v1/zones/import",
        json!({ "text": "www 3600 IN A 1.2.3.4\n" }),
    )
    .await;
    // Ohne Namen braucht es $ORIGIN oder SOA (die Engine liest die Datei)
    if s == Status::BadRequest {
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("Zonenname"),
            "{v}"
        );
    }

    let text = "$ORIGIN lab.example.\n@ 3600 IN NS ns.lab.example.\nwww 300 IN A 10.0.0.5\n";
    let (s, v) = post(
        &client,
        "/api/v1/zones/import",
        json!({ "name": "lab.example", "text": text }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["zone"]["name"], "lab.example");
    assert_eq!(v["zone"]["kind"], "primary");
    // Gibt es die Zone schon: Konflikt, ausser mit `replace`
    let (s, v) = post(
        &client,
        "/api/v1/zones/import",
        json!({ "name": "lab.example", "text": text }),
    )
    .await;
    assert_eq!(s, Status::Conflict, "{v}");
    let (s, v) = post(
        &client,
        "/api/v1/zones/import",
        json!({ "name": "lab.example", "text": text, "replace": true }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert!(v["zone"]["soa"]["serial"].as_u64().unwrap() > u64::from(today_base()));
    let (_, zones) = get(&client, "/api/v1/zones").await;
    assert_eq!(zones.as_array().unwrap().len(), 1);
    client.terminate().await;
}
