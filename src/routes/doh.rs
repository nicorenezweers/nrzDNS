//! DNS über HTTPS (RFC 8484) unter `/dns-query`, ohne Anmeldung:
//!
//! * `GET /dns-query?dns=<base64url ohne Auffüllung>`
//! * `POST /dns-query` mit `Content-Type: application/dns-message` (höchstens 64 KiB)
//!
//! Antwort `200 application/dns-message`, zwischenspeicherbar bis zur kleinsten TTL der
//! Antwort. Abgeschaltet ([`DnsSettings::doh_enabled`](nrzdns_types::DnsSettings)) → 404;
//! kaputte Anfrage → 400, falscher Typ → 415, zu gross → 413, verworfen (Rate-Limit) → 429.
//!
//! Der Client fürs Protokoll und das Rate-Limit kommt aus Rockets `ip_header` (hinter einem
//! Proxy), sonst aus der Verbindung. Keine Herkunftsprüfung: DoH-Clients sind keine Browser-
//! Formulare, und ohne Cookie gibt es nichts zu fälschen.

use base64::Engine as _;
use nrzdns_engine::Engine;
use nrzdns_types::Protocol;
use rocket::data::{Data, ToByteUnit};
use rocket::http::{ContentType, Header, Status};
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::{self, Responder, Response};
use rocket::{get, post, routes, Route, State};
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr};

/// Grösste DNS-Nachricht.
pub const MAX_MESSAGE: usize = 65_535;
/// Kopf einer DNS-Nachricht.
const HEADER_LEN: usize = 12;

pub fn routes() -> Vec<Route> {
    routes![query_get, query_post]
}

/// `application/dns-message`
pub fn dns_message() -> ContentType {
    ContentType::new("application", "dns-message")
}

/// IP-Adresse des Clients: aus `ip_header`, sonst die der Verbindung.
pub struct PeerIp(pub IpAddr);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for PeerIp {
    type Error = std::convert::Infallible;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(PeerIp(
            req.client_ip().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ))
    }
}

/// Antwort der Engine im Wire-Format.
pub struct DnsMessage(pub Vec<u8>);

impl<'r> Responder<'r, 'static> for DnsMessage {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        let cache = match min_ttl(&self.0) {
            Some(ttl) => format!("max-age={ttl}"),
            None => "no-store".into(),
        };
        Response::build()
            .header(dns_message())
            .header(Header::new("Cache-Control", cache))
            .sized_body(self.0.len(), Cursor::new(self.0))
            .ok()
    }
}

async fn answer(engine: &Engine, msg: &[u8], client: IpAddr) -> Result<DnsMessage, Status> {
    if msg.len() < HEADER_LEN || msg.len() > MAX_MESSAGE {
        return Err(Status::BadRequest);
    }
    engine
        .handle(msg, client, Protocol::Https)
        .await
        .map(DnsMessage)
        .ok_or(Status::TooManyRequests)
}

#[get("/dns-query?<dns>")]
async fn query_get(
    dns: Option<&str>,
    ip: PeerIp,
    engine: &State<Engine>,
) -> Result<DnsMessage, Status> {
    if !engine.settings().doh_enabled {
        return Err(Status::NotFound);
    }
    let encoded = dns.unwrap_or_default().trim().trim_end_matches('=');
    if encoded.is_empty() || encoded.len() > MAX_MESSAGE * 4 / 3 + 4 {
        return Err(Status::BadRequest);
    }
    let msg = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Status::BadRequest)?;
    answer(engine, &msg, ip.0).await
}

#[post("/dns-query", data = "<body>")]
async fn query_post(
    content_type: Option<&ContentType>,
    body: Data<'_>,
    ip: PeerIp,
    engine: &State<Engine>,
) -> Result<DnsMessage, Status> {
    if !engine.settings().doh_enabled {
        return Err(Status::NotFound);
    }
    if content_type != Some(&dns_message()) {
        return Err(Status::UnsupportedMediaType);
    }
    let bytes = body
        .open(64.kibibytes())
        .into_bytes()
        .await
        .map_err(|_| Status::BadRequest)?;
    if !bytes.is_complete() {
        return Err(Status::PayloadTooLarge);
    }
    answer(engine, &bytes, ip.0).await
}

/// Kleinste TTL aus Antwort- und Autoritätsteil (bei NXDOMAIN zählt so das SOA). `None` bei
/// Fehlern (SERVFAIL, REFUSED …), ohne Einträge oder bei unlesbarer Nachricht – dann wird
/// nicht zwischengespeichert.
pub fn min_ttl(msg: &[u8]) -> Option<u32> {
    let u16_at = |i: usize| Some(u16::from_be_bytes([*msg.get(i)?, *msg.get(i + 1)?]));
    let rcode = msg.get(3)? & 0x0f;
    if rcode != 0 && rcode != 3 {
        return None;
    }
    let qd = u16_at(4)?;
    let records = usize::from(u16_at(6)?) + usize::from(u16_at(8)?);
    let mut pos = HEADER_LEN;
    for _ in 0..qd {
        pos = skip_name(msg, pos)? + 4;
    }
    let mut min: Option<u32> = None;
    for _ in 0..records {
        pos = skip_name(msg, pos)?;
        let ttl = u32::from_be_bytes(msg.get(pos + 4..pos + 8)?.try_into().ok()?);
        let len = usize::from(u16_at(pos + 8)?);
        pos += 10 + len;
        if pos > msg.len() {
            return None;
        }
        min = Some(min.map_or(ttl, |m| m.min(ttl)));
    }
    min
}

/// Position nach einem Namen (Labels bis 0 oder ein Zeiger der Komprimierung).
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)?;
        match len {
            0 => return Some(pos + 1),
            l if l & 0xc0 == 0xc0 => return Some(pos + 2),
            l if l & 0xc0 == 0 => pos += 1 + usize::from(l),
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Antwort auf `example.com A` mit zwei Einträgen (TTL 300 und 60, Name komprimiert).
    fn response(rcode: u8) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80 | rcode, 0, 1, 0, 2, 0, 0, 0, 0];
        m.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        for ttl in [300u32, 60] {
            m.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
            m.extend_from_slice(&ttl.to_be_bytes());
            m.extend_from_slice(&[0, 4, 93, 184, 215, 14]);
        }
        m
    }

    #[test]
    fn ttl_of_answers() {
        assert_eq!(min_ttl(&response(0)), Some(60));
        assert_eq!(min_ttl(&response(2)), None);
        let mut cut = response(0);
        cut.truncate(cut.len() - 2);
        assert_eq!(min_ttl(&cut), None);
        assert_eq!(min_ttl(&[0; 5]), None);
        // Nur die Frage, keine Einträge
        let mut empty = response(0);
        empty[7] = 0;
        assert_eq!(min_ttl(&empty), None);
    }
}
