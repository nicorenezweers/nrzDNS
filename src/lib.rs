//! nrzDNS – selbst gehosteter DNS-Server (Zonen, Weiterleitung, Cache, Sperrlisten,
//! Abfrageprotokoll, DNS über HTTPS). Aufbau: siehe ARCHITECTURE.md.
//!
//! Der Server hält alles in SQLite und reicht es an die Engine (`nrzdns-engine`) weiter, die
//! DNS-Anfragen nur aus ihrem Speicher beantwortet.

pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod fairings;
pub mod routes;
pub mod services;

use nrzdns_engine::Engine;
use rocket::figment::Figment;
use rocket::{Build, Rocket};

/// Version für Oberfläche, `GET /server` und die Engine.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Baut die Rocket-Instanz mit der normalen Konfiguration (`Rocket.toml`, `NRZDNS_*`).
pub async fn build() -> Result<Rocket<Build>, error::AppError> {
    build_with(config::figment()).await
}

/// Baut die Rocket-Instanz aus einer gegebenen Konfiguration (auch für Tests):
/// Datenbank öffnen und migrieren, Cookie-Schlüssel laden, Engine mit Einstellungen, Zonen,
/// Listen und zwischengespeicherten Sperrlisten füllen, Fairings, Routen, Catcher.
/// Mit `background = false` (Tests) öffnet nichts DNS-Ports oder lädt Listen.
pub async fn build_with(figment: Figment) -> Result<Rocket<Build>, error::AppError> {
    let config: config::Config = figment
        .extract()
        .map_err(|e| error::AppError::Config(e.to_string()))?;
    if config
        .mcp_env_token()
        .is_some_and(|t| t.chars().count() < 16)
    {
        return Err(error::AppError::Config(
            "NRZDNS_MCP_TOKEN: mindestens 16 Zeichen.".into(),
        ));
    }
    let pool = db::connect(&config).await?;
    // Ein selbst gesetzter secret_key hat Vorrang; sonst der aus der Datenbank.
    let figment = figment.join((
        "secret_key",
        services::settings::cookie_secret(&pool).await?,
    ));

    let dns = services::settings::dns(&pool).await?;
    let (engine, log) = Engine::new(dns, VERSION);
    services::sync::load_all(&pool, &engine, &config).await?;

    Ok(rocket::custom(figment)
        .manage(pool)
        .manage(engine)
        .manage(config)
        .manage(auth::throttle::LoginThrottle::default())
        .manage(services::blocking::Updater::default())
        .manage(fairings::LogWriter::default())
        .manage(services::mcp::McpState::default())
        .attach(fairings::RequestLog)
        // Rockets Shield ohne eigene Header: die setzt alle SecurityHeaders (sonst gewönne
        // Shields X-Frame-Options: SAMEORIGIN über unser DENY)
        .attach(rocket::shield::Shield::new())
        .attach(fairings::SecurityHeaders)
        .attach(fairings::DnsServer::new(log))
        .attach(fairings::BlocklistUpdater)
        .attach(fairings::SessionCleanup)
        .attach(fairings::CloseDatabase)
        .mount("/", routes::assets::routes())
        .mount("/", routes::spa::routes())
        .mount("/", routes::doh::routes())
        .mount("/", routes::mcp::routes())
        .mount("/api/v1", routes::api::routes())
        .register("/", routes::catchers::all()))
}
