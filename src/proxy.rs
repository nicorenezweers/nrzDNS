//! Eingebauter Reverse Proxy (HTTP/1.1): nimmt auf `proxy_listen` (Vorgabe `0.0.0.0:80`)
//! Anfragen an und reicht sie nach dem `Host`-Header an das eingetragene Ziel weiter, z. B.
//! `music.nrz.ch` → `http://100.78.107.162:8350`. Antworten werden gestreamt (Musik, Videos,
//! Downloads), WebSockets und andere Upgrades durchgereicht.
//!
//! Der `Host`-Header bleibt wie vom Browser geschickt; dazu kommen `X-Forwarded-For`,
//! `X-Real-IP`, `X-Forwarded-Host` und `X-Forwarded-Proto`. Weiterleitungen des Ziels auf seine
//! eigene Adresse (`Location: http://100.78.107.162:8350/…`) werden auf den Namen umgeschrieben.

use hyper::client::HttpConnector;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Client, Request, Response, StatusCode, Uri};
use rocket::Shutdown;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;
use tokio::net::TcpListener;

/// Ziel eines Eintrags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// `100.78.107.162:8350`, `[fd00::1]:80`
    pub authority: String,
    /// Host ohne Port und Klammern (`100.78.107.162`, `nas.local`).
    pub host: String,
    /// Pfad davor, ohne `/` am Ende (meist leer).
    pub base: String,
}

/// Merkt sich Ziele und Fehler beim Öffnen der Ports (Rocket-State, günstig zu klonen).
#[derive(Clone, Default)]
pub struct ProxyState(Arc<Inner>);

#[derive(Default)]
struct Inner {
    routes: RwLock<HashMap<String, Target>>,
    errors: Mutex<Vec<String>>,
}

/// Kennzeichnet weitergereichte Anfragen – kommt eine davon wieder an, zeigt ein Eintrag auf
/// den Proxy selbst.
const LOOP_HEADER: &str = "x-nrzdns-proxy";

impl ProxyState {
    pub fn set_routes(&self, routes: HashMap<String, Target>) {
        *self
            .0
            .routes
            .write()
            .unwrap_or_else(PoisonError::into_inner) = routes;
    }

    fn route(&self, host: &str) -> Option<Target> {
        self.0
            .routes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(host)
            .cloned()
    }

    pub fn listen_errors(&self) -> Vec<String> {
        self.0
            .errors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Ports öffnen und Anfragen annehmen, bis der Server endet. Fehler beim Öffnen stehen
    /// danach in [`Self::listen_errors`].
    pub async fn serve(&self, addrs: &[SocketAddr], shutdown: Shutdown) {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(Duration::from_secs(10)));
        connector.set_nodelay(true);
        let client: Client<HttpConnector> = Client::builder()
            .pool_idle_timeout(Duration::from_secs(30))
            .build(connector);
        let mut errors = Vec::new();
        for addr in addrs {
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    tracing::info!("Reverse Proxy läuft auf {addr}");
                    tokio::spawn(accept(
                        listener,
                        self.clone(),
                        client.clone(),
                        shutdown.clone(),
                    ));
                }
                Err(e) => {
                    let msg = format!("{addr}: {e}");
                    tracing::error!("Reverse Proxy: {msg}");
                    errors.push(msg);
                }
            }
        }
        *self.0.errors.lock().unwrap_or_else(PoisonError::into_inner) = errors;
    }
}

async fn accept(
    listener: TcpListener,
    state: ProxyState,
    client: Client<HttpConnector>,
    mut shutdown: Shutdown,
) {
    loop {
        let (stream, peer) = tokio::select! {
            _ = &mut shutdown => break,
            r = listener.accept() => match r {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Reverse Proxy: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let _ = stream.set_nodelay(true);
        let state = state.clone();
        let client = client.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| handle(state.clone(), client.clone(), peer, req));
            if let Err(e) = Http::new()
                .http1_only(true)
                .http1_keep_alive(true)
                .serve_connection(stream, service)
                .with_upgrades()
                .await
            {
                tracing::debug!("Reverse Proxy, Verbindung von {peer}: {e}");
            }
        });
    }
}

/// Host aus dem Header (oder der absoluten URI), klein, ohne Port und Punkt am Ende.
/// Zweiter Wert: wie der Browser ihn geschrieben hat (mit Port), für `Location`.
fn request_host(req: &Request<Body>) -> Option<(String, String)> {
    let raw = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.to_string()))?;
    let raw = raw.trim().to_string();
    let host = if let Some(rest) = raw.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default().to_string()
    } else {
        raw.rsplit_once(':')
            .map_or(raw.as_str(), |(h, _)| h)
            .to_string()
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some((host, raw))
}

/// Verbindungsbezogene Header (RFC 9110, 7.6.1), dazu alle, die `Connection` nennt.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for n in named {
        headers.remove(n);
    }
    for n in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(n);
    }
}

fn wants_upgrade(headers: &HeaderMap) -> Option<HeaderValue> {
    let connection_upgrade = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
    if connection_upgrade {
        headers.get(header::UPGRADE).cloned()
    } else {
        None
    }
}

async fn handle(
    state: ProxyState,
    client: Client<HttpConnector>,
    peer: SocketAddr,
    mut req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    let Some((host, raw_host)) = request_host(&req) else {
        return Ok(page(StatusCode::BAD_REQUEST, "Anfrage ohne Host-Header."));
    };
    if req.headers().contains_key(LOOP_HEADER) {
        return Ok(page(
            StatusCode::LOOP_DETECTED,
            &format!(
                "Der Eintrag für {} zeigt auf den Proxy selbst.",
                escape(&host)
            ),
        ));
    }
    let Some(target) = state.route(&host) else {
        return Ok(page(
            StatusCode::NOT_FOUND,
            &format!(
                "Für <b>{}</b> gibt es keinen Eintrag im Reverse Proxy von nrzDNS.",
                escape(&host)
            ),
        ));
    };

    let pq = req
        .uri()
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_string();
    let uri: Uri = match format!("http://{}{}{}", target.authority, target.base, pq).parse() {
        Ok(u) => u,
        Err(_) => return Ok(page(StatusCode::BAD_REQUEST, "Ungültiger Pfad.")),
    };

    let upgrade = wants_upgrade(req.headers());
    let client_upgrade = upgrade.as_ref().map(|_| hyper::upgrade::on(&mut req));

    let (mut parts, body) = req.into_parts();
    parts.uri = uri;
    parts.version = hyper::Version::HTTP_11;
    let headers = &mut parts.headers;
    strip_hop_by_hop(headers);
    if let Some(proto) = &upgrade {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(header::UPGRADE, proto.clone());
    }
    let ip = peer.ip().to_canonical().to_string();
    let xff = match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        Some(prev) if !prev.trim().is_empty() => format!("{prev}, {ip}"),
        _ => ip.clone(),
    };
    for (name, value) in [
        ("x-forwarded-for", xff),
        ("x-real-ip", ip),
        ("x-forwarded-host", raw_host.clone()),
    ] {
        if let Ok(v) = HeaderValue::from_str(&value) {
            headers.insert(name, v);
        }
    }
    if !headers.contains_key("x-forwarded-proto") {
        headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
    }
    headers.insert(LOOP_HEADER, HeaderValue::from_static("1"));

    let mut resp = match client.request(Request::from_parts(parts, body)).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(host = %host, target = %target.authority, "Reverse Proxy: {e}");
            return Ok(page(
                StatusCode::BAD_GATEWAY,
                &format!(
                    "Das Ziel für <b>{}</b> (http://{}) antwortet nicht: {}",
                    escape(&host),
                    escape(&target.authority),
                    escape(&e.to_string())
                ),
            ));
        }
    };

    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(client_upgrade) = client_upgrade {
            let server_upgrade = hyper::upgrade::on(&mut resp);
            tokio::spawn(async move {
                match tokio::try_join!(client_upgrade, server_upgrade) {
                    Ok((mut a, mut b)) => {
                        let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
                    }
                    Err(e) => tracing::debug!("Reverse Proxy, Upgrade: {e}"),
                }
            });
            return Ok(resp);
        }
    }

    strip_hop_by_hop(resp.headers_mut());
    rewrite_location(resp.headers_mut(), &target, &raw_host);
    Ok(resp)
}

/// `Location: http://<ziel>/…` → `http://<name>/…` (ohne den Pfad davor).
fn rewrite_location(headers: &mut HeaderMap, target: &Target, raw_host: &str) {
    let Some(loc) = headers.get(header::LOCATION).and_then(|v| v.to_str().ok()) else {
        return;
    };
    let mut prefixes = vec![format!("http://{}", target.authority)];
    if let Some(no_port) = target.authority.strip_suffix(":80") {
        prefixes.push(format!("http://{no_port}"));
    }
    for prefix in prefixes {
        let Some(rest) = loc.strip_prefix(&prefix) else {
            continue;
        };
        if !(rest.is_empty() || rest.starts_with(['/', '?', '#'])) {
            continue;
        }
        let rest = rest.strip_prefix(target.base.as_str()).unwrap_or(rest);
        let rest = if rest.is_empty() { "/" } else { rest };
        if let Ok(v) = HeaderValue::from_str(&format!("http://{raw_host}{rest}")) {
            headers.insert(header::LOCATION, v);
        }
        return;
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Kleine Fehlerseite des Proxys.
fn page(status: StatusCode, message: &str) -> Response<Body> {
    let html = format!(
        "<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\"><title>{code}</title>\
         <style>body{{font-family:system-ui,sans-serif;background:#18181b;color:#e4e4e7;\
         display:grid;place-items:center;min-height:100vh;margin:0}}main{{max-width:36rem;\
         padding:2rem}}h1{{font-size:1.25rem;margin:0 0 .5rem}}p{{color:#a1a1aa}}</style></head>\
         <body><main><h1>{code} · nrzDNS Reverse Proxy</h1><p>{message}</p></main></body></html>",
        code = status.as_u16()
    );
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(html))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(host: &str) -> Request<Body> {
        Request::builder()
            .uri("/x")
            .header("host", host)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn host_header() {
        assert_eq!(
            request_host(&req("Music.NRZ.ch")),
            Some(("music.nrz.ch".into(), "Music.NRZ.ch".into()))
        );
        assert_eq!(
            request_host(&req("music.nrz.ch.:8480")).map(|h| h.0),
            Some("music.nrz.ch".into())
        );
        assert_eq!(
            request_host(&req("[fd00::1]:80")).map(|h| h.0),
            Some("fd00::1".into())
        );
    }

    #[test]
    fn location() {
        let t = Target {
            authority: "100.78.107.162:8350".into(),
            host: "100.78.107.162".into(),
            base: String::new(),
        };
        let mut h = HeaderMap::new();
        h.insert(
            header::LOCATION,
            HeaderValue::from_static("http://100.78.107.162:8350/login?x=1"),
        );
        rewrite_location(&mut h, &t, "music.nrz.ch");
        assert_eq!(h[header::LOCATION], "http://music.nrz.ch/login?x=1");
        h.insert(
            header::LOCATION,
            HeaderValue::from_static("http://100.78.107.162:83500/"),
        );
        rewrite_location(&mut h, &t, "music.nrz.ch");
        assert_eq!(h[header::LOCATION], "http://100.78.107.162:83500/");
    }

    #[test]
    fn hop_by_hop() {
        let mut h = HeaderMap::new();
        h.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-foo"),
        );
        h.insert("x-foo", HeaderValue::from_static("1"));
        h.insert("x-bar", HeaderValue::from_static("1"));
        h.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        strip_hop_by_hop(&mut h);
        assert_eq!(h.len(), 1);
        assert!(h.contains_key("x-bar"));
    }
}
