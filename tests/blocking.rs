//! Sperren: eigene Sperren und Ausnahmen, Sperrlisten verwalten (ohne Laden – die Tests
//! laufen ohne Hintergrundarbeiten), Pause, Überblick.

mod common;

use common::{delete, get, login_as, pool, post, put};
use nrzdns_types::{BlockList, BlockingStatus, DomainEntry};
use rocket::http::Status;
use serde_json::json;

#[rocket::async_test]
async fn custom_blocked_and_allowed_domains() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;

    for list in ["blocked", "allowed"] {
        let url = format!("/api/v1/{list}");
        let (s, v) = post(
            &client,
            &url,
            json!({ "domain": " *.Ads.Example.COM. ", "comment": " Werbung " }),
        )
        .await;
        assert_eq!(s, Status::Created, "{list}: {v}");
        let entry: DomainEntry = serde_json::from_value(v).unwrap();
        assert_eq!(entry.domain, "ads.example.com");
        assert_eq!(entry.comment, "Werbung");

        let (s, v) = post(&client, &url, json!({ "domain": "ADS.example.com" })).await;
        assert_eq!(s, Status::Conflict, "{list}: {v}");
        assert_eq!(
            v["error"]["message"],
            "Diese Domain steht schon in der Liste."
        );
        for bad in ["", "a..b", "exa mple.com", "-x.com"] {
            let (s, _) = post(&client, &url, json!({ "domain": bad })).await;
            assert_eq!(s, Status::BadRequest, "{list}: {bad}");
        }
        post(&client, &url, json!({ "domain": "tracker.org" })).await;

        let (s, v) = get(&client, &url).await;
        assert_eq!(s, Status::Ok);
        let names: Vec<&str> = v
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["domain"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["ads.example.com", "tracker.org"]);

        assert_eq!(
            delete(&client, format!("{url}/Tracker.org")).await.0,
            Status::NoContent
        );
        assert_eq!(
            delete(&client, format!("{url}/tracker.org")).await.0,
            Status::NotFound
        );
    }
    // Beide Listen sind getrennt und zählen im Überblick
    let (_, v) = get(&client, "/api/v1/blocking").await;
    let status: BlockingStatus = serde_json::from_value(v).unwrap();
    assert_eq!((status.custom_blocked, status.allowed), (1, 1));
    client.terminate().await;
}

#[rocket::async_test]
async fn block_lists_are_managed() {
    let (client, dir) = common::client().await;
    login_as(&client, "admin", true).await;

    let (s, v) = post(
        &client,
        "/api/v1/blocking/lists",
        json!({ "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "enabled": true }),
    )
    .await;
    assert_eq!(s, Status::Created, "{v}");
    let list: BlockList = serde_json::from_value(v).unwrap();
    assert_eq!(list.name, "StevenBlack Unified", "Name aus den Vorlagen");
    assert!(list.enabled);
    assert_eq!(list.domain_count, 0);
    assert_eq!(list.last_updated_at, None);

    let (s, v) = post(
        &client,
        "/api/v1/blocking/lists",
        json!({ "url": "https://example.org/lists/ads.txt", "enabled": false }),
    )
    .await;
    assert_eq!(s, Status::Created, "{v}");
    assert_eq!(v["name"], "ads.txt (example.org)");
    let second = v["id"].as_i64().unwrap();

    // Gleiche Adresse oder ungültige Adresse
    let (s, _) = post(
        &client,
        "/api/v1/blocking/lists",
        json!({ "url": "https://example.org/lists/ads.txt" }),
    )
    .await;
    assert_eq!(s, Status::Conflict);
    for bad in ["", "ftp://example.org/x", "example.org/list"] {
        let (s, _) = post(&client, "/api/v1/blocking/lists", json!({ "url": bad })).await;
        assert_eq!(s, Status::BadRequest, "{bad}");
    }

    let (s, v) = put(
        &client,
        format!("/api/v1/blocking/lists/{second}"),
        json!({ "name": "Meine Liste", "url": "https://example.org/lists/ads.txt", "enabled": true }),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(
        (v["name"].clone(), v["enabled"].clone()),
        (json!("Meine Liste"), json!(true))
    );
    assert_eq!(
        put(
            &client,
            "/api/v1/blocking/lists/999",
            json!({ "url": "https://x.org/a" })
        )
        .await
        .0,
        Status::NotFound
    );

    // Überblick: Listen, nächstes Laden sofort fällig (noch nie geladen)
    let (s, v) = get(&client, "/api/v1/blocking").await;
    assert_eq!(s, Status::Ok);
    let status: BlockingStatus = serde_json::from_value(v).unwrap();
    assert_eq!(status.lists.len(), 2);
    assert!(status.enabled);
    assert!(!status.updating);
    assert_eq!(status.last_update_at, None);
    assert!(status.next_update_at.is_some());

    // „Jetzt laden“ antwortet sofort mit dem Überblick
    let (s, v) = common::call(&client, "POST", "/api/v1/blocking/update", None).await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["lists"].as_array().unwrap().len(), 2);

    // Löschen entfernt auch die zwischengespeicherte Datei
    let cache = dir.path().join("blocklists");
    std::fs::create_dir_all(&cache).unwrap();
    let file = cache.join(format!("{second}.txt"));
    std::fs::write(&file, "ads.example.com\n").unwrap();
    assert_eq!(
        delete(&client, format!("/api/v1/blocking/lists/{second}"))
            .await
            .0,
        Status::NoContent
    );
    assert!(!file.exists());
    assert_eq!(
        delete(&client, format!("/api/v1/blocking/lists/{second}"))
            .await
            .0,
        Status::NotFound
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM block_lists")
        .fetch_one(pool(&client))
        .await
        .unwrap();
    assert_eq!(n, 1);
    client.terminate().await;
}

#[rocket::async_test]
async fn pause_is_persisted_and_resumes() {
    let (client, _dir) = common::client().await;
    login_as(&client, "admin", true).await;

    let before = nrzdns::db::now();
    let (s, v) = post(&client, "/api/v1/blocking/pause", json!({ "minutes": 15 })).await;
    assert_eq!(s, Status::Ok, "{v}");
    let until = v["pausedUntil"].as_i64().unwrap();
    assert!((before + 15 * 60..=before + 15 * 60 + 5).contains(&until));
    // Gespeichert (übersteht einen Neustart)
    assert_eq!(
        nrzdns::services::settings::paused_until(pool(&client))
            .await
            .unwrap(),
        Some(until)
    );
    assert_eq!(
        get(&client, "/api/v1/blocking").await.1["pausedUntil"],
        until
    );

    let (s, _) = post(
        &client,
        "/api/v1/blocking/pause",
        json!({ "minutes": 10081 }),
    )
    .await;
    assert_eq!(s, Status::BadRequest);

    let (s, v) = post(&client, "/api/v1/blocking/pause", json!({ "minutes": 0 })).await;
    assert_eq!(s, Status::Ok);
    assert!(v["pausedUntil"].is_null());
    client.terminate().await;
}

#[rocket::async_test]
async fn checking_a_domain() {
    let (client, _dir) = common::client().await;
    login_as(&client, "mia", false).await;
    let (s, v) = get(&client, "/api/v1/blocking/check?domain=Ads.Example.com.").await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["domain"], "ads.example.com");
    for url in [
        "/api/v1/blocking/check",
        "/api/v1/blocking/check?domain=a..b",
    ] {
        assert_eq!(get(&client, url).await.0, Status::BadRequest, "{url}");
    }
    client.terminate().await;
}
