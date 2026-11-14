//! REST-API unter `/api/v1`. Typen der Körper und Antworten: Crate `nrzdns-types` (dort steht
//! auch die ganze Tabelle der Endpunkte). Lesen darf jeder Angemeldete, ändern nur Admins.

mod access;
mod admin;
mod auth;
mod blocking;
mod cache;
mod components;
mod integrations;
mod logs;
mod mcp;
mod me;
mod proxy;
mod requests;
mod settings;
mod spy;
mod tls;
mod tools;
mod zones;

use rocket::http::{ContentType, Header};
use rocket::response::{self, Responder, Response};
use rocket::serde::json::{json, Value};
use rocket::{get, routes, Request, Route};
use std::io::Cursor;

pub fn routes() -> Vec<Route> {
    let mut r = routes![health];
    r.extend(admin::routes());
    r.extend(auth::routes());
    r.extend(blocking::routes());
    r.extend(cache::routes());
    r.extend(logs::routes());
    r.extend(mcp::routes());
    r.extend(me::routes());
    r.extend(proxy::routes());
    r.extend(requests::routes());
    r.extend(settings::routes());
    r.extend(components::routes());
    r.extend(access::routes());
    r.extend(spy::routes());
    r.extend(integrations::routes());
    r.extend(tls::routes());
    r.extend(tools::routes());
    r.extend(zones::routes());
    r
}

/// Lebenszeichen für Docker-Healthcheck und Monitoring.
#[get("/health")]
pub fn health() -> Value {
    json!({ "status": "ok", "name": "nrzNetwork", "version": env!("CARGO_PKG_VERSION") })
}

/// Datei zum Herunterladen (Zonendatei, CSV): `Content-Disposition: attachment`.
pub struct Download {
    pub filename: String,
    pub content_type: ContentType,
    pub body: String,
}

impl<'r> Responder<'r, 'static> for Download {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        // Nur harmlose Zeichen im Dateinamen (er steht in einem Header)
        let name: String = self
            .filename
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || "._-".contains(c) {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        Response::build()
            .header(self.content_type)
            .header(Header::new(
                "Content-Disposition",
                format!("attachment; filename=\"{name}\""),
            ))
            .header(Header::new("Cache-Control", "no-store"))
            .sized_body(self.body.len(), Cursor::new(self.body))
            .ok()
    }
}
