//! Migrationen laufen auf einer leeren Datenbank; Fremdschlüssel und Eindeutigkeit greifen.

use nrzdns::config::Config;

#[tokio::test]
async fn migrations_and_constraints() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        data_dir: dir.path().to_path_buf(),
        ..Config::default()
    };
    let pool = nrzdns::db::connect(&config).await.unwrap();

    let tables: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .fetch_all(&pool)
            .await
            .unwrap();
    for t in [
        "app_settings",
        "block_lists",
        "custom_domains",
        "query_log",
        "sessions",
        "users",
        "zone_records",
        "zones",
    ] {
        assert!(
            tables.iter().any(|n| n == t),
            "Tabelle {t} fehlt: {tables:?}"
        );
    }
    let indexes: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'query_log'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    for i in [
        "query_log_at",
        "query_log_qname",
        "query_log_client",
        "query_log_kind",
    ] {
        assert!(indexes.iter().any(|n| n == i), "Index {i} fehlt");
    }

    // Einträge verschwinden mit ihrer Zone
    sqlx::query("INSERT INTO zones (name, created_at, updated_at) VALUES ('home.arpa', 0, 0)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO zone_records (zone_id, name, type, data, ttl, created_at, updated_at)
         VALUES (1, 'nas', 'A', '{\"type\":\"A\",\"address\":\"192.168.1.10\"}', 3600, 0, 0)",
    )
    .execute(&pool)
    .await
    .unwrap();
    // Derselbe Eintrag zweimal geht nicht
    assert!(sqlx::query(
        "INSERT INTO zone_records (zone_id, name, type, data, ttl, created_at, updated_at)
         VALUES (1, 'nas', 'A', '{\"type\":\"A\",\"address\":\"192.168.1.10\"}', 60, 0, 0)",
    )
    .execute(&pool)
    .await
    .is_err());
    sqlx::query("DELETE FROM zones WHERE id = 1")
        .execute(&pool)
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM zone_records")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 0);

    // Eine Domain je Liste einmal, aber in beiden Listen erlaubt
    for kind in ["blocked", "allowed"] {
        sqlx::query(
            "INSERT INTO custom_domains (kind, domain, created_at) VALUES (?, 'ads.example.com', 0)",
        )
        .bind(kind)
        .execute(&pool)
        .await
        .unwrap();
    }
    assert!(sqlx::query(
        "INSERT INTO custom_domains (kind, domain, created_at) VALUES ('blocked', 'ads.example.com', 0)"
    )
    .execute(&pool)
    .await
    .is_err());
    assert!(sqlx::query(
        "INSERT INTO custom_domains (kind, domain, created_at) VALUES ('sonstwas', 'x.com', 0)"
    )
    .execute(&pool)
    .await
    .is_err());
    pool.close().await;
}
