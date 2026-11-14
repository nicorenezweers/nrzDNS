//! Zugriffsprotokoll des Proxys: wer welche Website aufruft. Pro Anfrage werden Kopfzeilen
//! gelesen, bevor sie weitergereicht wird ([`RequestMeta`]); nach der Antwort entsteht ein
//! [`AccessEntry`] im Puffer, den `services::access::flush` gesammelt speichert.
//!
//! Herkunft: Kommt eine Anfrage von `127.0.0.1` oder aus dem LAN und trägt
//! `CF-Connecting-IP`, lief sie über den Cloudflare Tunnel – dann zählen die echte Adresse,
//! das Land (`CF-IPCountry`) und das Schema (`CF-Visitor`). Kopfzeilen von Adressen aus dem
//! Internet werden nie geglaubt.

use super::{ProxyState, Scheme};
use hyper::header::{self, HeaderMap};
use hyper::{Body, Request, Response};
use nrzdns_types::AccessEntry;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

/// Höchstens so viele ungespeicherte Einträge (danach werden neue verworfen).
const MAX_BUFFER: usize = 20_000;

/// Art der Antwort (als Erweiterung an der Antwort, nur diese werden protokolliert).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Entry,
    Redirect,
    Blocked,
}

impl AccessKind {
    fn as_str(self) -> &'static str {
        match self {
            AccessKind::Entry => "entry",
            AccessKind::Redirect => "redirect",
            AccessKind::Blocked => "blocked",
        }
    }
}

/// Merkt sich die Antwortart.
pub fn mark(mut resp: Response<Body>, kind: AccessKind) -> Response<Body> {
    resp.extensions_mut().insert(kind);
    resp
}

#[derive(Default)]
pub struct AccessBuffer {
    entries: Mutex<Vec<AccessEntry>>,
    /// Adresse, unter der das Gerät selbst (Docker-Host) Verbindungen weitergibt.
    gateway: Mutex<Option<IpAddr>>,
}

impl AccessBuffer {
    pub fn take(&self) -> Vec<AccessEntry> {
        std::mem::take(&mut *self.entries.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn push(&self, e: AccessEntry) {
        let mut v = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if v.len() < MAX_BUFFER {
            v.push(e);
        }
    }

    pub fn set_gateway(&self, ip: Option<IpAddr>) {
        *self.gateway.lock().unwrap_or_else(PoisonError::into_inner) = ip;
    }

    fn gateway(&self) -> Option<IpAddr> {
        *self.gateway.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn header(h: &HeaderMap, k: &str) -> String {
    h.get(k)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn trusted_hop(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_loopback() || a.is_private(),
        IpAddr::V6(a) => a.is_loopback() || (a.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn is_cgnat(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(a) if a.octets()[0] == 100 && (64..128).contains(&a.octets()[1]))
}

/// Was vor dem Weiterreichen bekannt ist.
pub struct RequestMeta {
    started: Instant,
    host: String,
    method: String,
    path: String,
    client: String,
    source: &'static str,
    country: String,
    user_agent: String,
    referer: String,
    /// Der Besucher kam über HTTPS bei Cloudflare an (Tunnel spricht intern HTTP).
    pub edge_https: bool,
}

impl RequestMeta {
    pub fn read(req: &Request<Body>, peer: SocketAddr, state: &ProxyState) -> Self {
        let h = req.headers();
        let ip = peer.ip().to_canonical();
        let cf_ip = header(h, "cf-connecting-ip")
            .parse::<IpAddr>()
            .ok()
            .filter(|_| trusted_hop(ip));
        let (client, source, country, edge_https) = match cf_ip {
            Some(real) => (
                real,
                "cloudflare",
                header(h, "cf-ipcountry")
                    .chars()
                    .take(2)
                    .collect::<String>()
                    .to_uppercase(),
                header(h, "cf-visitor").contains("https")
                    || header(h, "x-forwarded-proto").eq_ignore_ascii_case("https"),
            ),
            None => {
                let source = if is_cgnat(ip) {
                    "netbird"
                } else if Some(ip) == state.access().gateway() {
                    "device"
                } else if ip.is_loopback() {
                    "local"
                } else if trusted_hop(ip)
                    || matches!(ip, IpAddr::V6(a) if (a.segments()[0] & 0xffc0) == 0xfe80)
                {
                    "lan"
                } else {
                    "internet"
                };
                (ip, source, String::new(), false)
            }
        };
        let host = super::request_host(req).map(|(h, _)| h).unwrap_or_default();
        let referer = header(h, header::REFERER.as_str());
        let referer = referer
            .split("://")
            .nth(1)
            .and_then(|r| r.split(['/', '?', '#']).next())
            .unwrap_or_default()
            .to_lowercase();
        RequestMeta {
            started: Instant::now(),
            host,
            method: req.method().as_str().to_string(),
            path: req.uri().path().chars().take(300).collect(),
            client: client.to_string(),
            source,
            country,
            user_agent: header(h, header::USER_AGENT.as_str())
                .chars()
                .take(200)
                .collect(),
            referer: if referer.chars().count() > 120 {
                String::new()
            } else {
                referer
            },
            edge_https,
        }
    }

    /// Schema, wie der Besucher es benutzt hat.
    pub fn scheme(&self, local: Scheme) -> Scheme {
        if self.edge_https {
            Scheme::Https
        } else {
            local
        }
    }
}

impl ProxyState {
    pub fn access(&self) -> &AccessBuffer {
        &self.0.access
    }

    /// Nach der Antwort: protokollieren, falls sie markiert ist und das Protokoll an ist.
    pub(super) fn record(&self, meta: RequestMeta, resp: &Response<Body>) {
        let Some(kind) = resp.extensions().get::<AccessKind>().copied() else {
            return;
        };
        if self.settings().access_log_days == 0 {
            return;
        }
        let bytes = resp
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        self.0.access.push(AccessEntry {
            at_ms: crate::db::now_ms(),
            host: meta.host,
            method: meta.method,
            path: meta.path,
            status: resp.status().as_u16(),
            bytes,
            duration_ms: u32::try_from(meta.started.elapsed().as_millis()).unwrap_or(u32::MAX),
            client: meta.client,
            source: meta.source.to_string(),
            country: meta.country,
            user_agent: meta.user_agent,
            referer: meta.referer,
            kind: kind.as_str().to_string(),
            client_name: String::new(),
        });
    }
}
