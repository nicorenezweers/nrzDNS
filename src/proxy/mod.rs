//! Eingebauter Reverse Proxy (HTTP/1.1): nimmt auf `proxy_listen` (Vorgabe `0.0.0.0:80`)
//! Anfragen an und entscheidet nach dem `Host`-Header:
//!
//! 1. **Eintrag** (`music.nrz.ch` → `http://100.78.107.162:8350`): weiterreichen. Liegt das Ziel
//!    auf einer Adresse dieses Geräts, geht die Verbindung über `host_gateway`.
//! 2. **Gesperrte Domain** (Sperrmodus „Sperrseite“): die Sperrseite von nrzNetwork mit
//!    „auf Zeit freischalten“ und „Ausnahme beantragen“ (`/.nrznetwork/…`, siehe [`page`]).
//! 3. **IP-Adresse, `.local`, Name dieses Geräts** und alles, was auf das Gerät zeigt: an
//!    `proxy_fallback` (auf Umbrel: umbrelOS), damit dessen Oberfläche auf Port 80 bleibt.
//! 4. **Andere Domain**: normal auflösen und durchreichen – so klappt eine eben
//!    freigeschaltete Seite sofort, obwohl der Browser noch die alte Antwort im Cache hat.
//!
//! Antworten werden gestreamt, WebSockets und andere Upgrades durchgereicht. Der `Host`-Header
//! bleibt; dazu kommen `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, `X-Forwarded-Proto`.
//! Weiterleitungen des Ziels auf seine eigene Adresse werden auf den Namen umgeschrieben.

mod page;
pub mod tls;

use crate::services::unlocks;
use hyper::client::HttpConnector;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Client, Method, Request, Response, StatusCode, Uri};
use nrzdns_engine::Engine;
use nrzdns_types::{ProxySettings, ResolveInput};
use rocket::Shutdown;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;
use tokio::net::TcpListener;

/// Pfade der Sperrseite und des Lebenszeichens (für jeden Namen).
pub const ACTION_PREFIX: &str = "/.nrznetwork/";
/// Antwort von `GET /.nrznetwork/health` (der Umbrel-Wächter prüft darauf).
pub const HEALTH_BODY: &str = "nrznetwork-ok";
/// Höchstens so viele Aktionen (freischalten, beantragen) je Client in 10 Minuten.
const ACTIONS_PER_WINDOW: usize = 20;

/// Wie die Anfrage hereinkam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

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

impl Target {
    fn port(&self) -> u16 {
        self.authority
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(80)
    }
}

/// Was der Proxy zum Arbeiten braucht.
pub struct ProxyContext {
    pub pool: SqlitePool,
    pub engine: Engine,
    pub data_dir: PathBuf,
    pub host_gateway: Option<String>,
    pub fallback: Option<Target>,
    /// HTTPS für fremde Namen unverändert hierhin (`host:port`, auf Umbrel umbrelOS).
    pub tls_fallback: Option<String>,
}

/// Ziele, Einstellungen und Fehler beim Öffnen der Ports (Rocket-State, günstig zu klonen).
#[derive(Clone)]
pub struct ProxyState(Arc<Inner>);

struct Inner {
    ctx: ProxyContext,
    routes: RwLock<HashMap<String, Target>>,
    settings: RwLock<ProxySettings>,
    errors: Mutex<Vec<String>>,
    actions: Mutex<HashMap<IpAddr, Vec<i64>>>,
    tls: tls::TlsRuntime,
}

/// Kennzeichnet weitergereichte Anfragen – kommt eine davon wieder an, zeigt ein Eintrag auf
/// den Proxy selbst.
const LOOP_HEADER: &str = "x-nrzdns-proxy";

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl ProxyState {
    pub fn new(ctx: ProxyContext) -> Self {
        Self(Arc::new(Inner {
            ctx,
            routes: RwLock::default(),
            settings: RwLock::default(),
            errors: Mutex::default(),
            actions: Mutex::default(),
            tls: tls::TlsRuntime::default(),
        }))
    }

    pub fn data_dir(&self) -> &Path {
        &self.0.ctx.data_dir
    }

    pub fn set_routes(&self, routes: HashMap<String, Target>) {
        *self
            .0
            .routes
            .write()
            .unwrap_or_else(PoisonError::into_inner) = routes;
    }

    pub fn set_settings(&self, settings: ProxySettings) {
        *self
            .0
            .settings
            .write()
            .unwrap_or_else(PoisonError::into_inner) = settings;
    }

    fn settings(&self) -> ProxySettings {
        self.0
            .settings
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
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
        lock(&self.0.errors).clone()
    }

    /// Eine Aktion mehr für diesen Client; `false` = zu viele.
    fn allow_action(&self, client: IpAddr) -> bool {
        let now = crate::db::now();
        let mut map = lock(&self.0.actions);
        map.retain(|_, v| {
            v.retain(|t| now - t < 600);
            !v.is_empty()
        });
        let list = map.entry(client).or_default();
        if list.len() >= ACTIONS_PER_WINDOW {
            return false;
        }
        list.push(now);
        true
    }

    /// Adresse, über die der Proxy ein Ziel verbindet: liegt es auf diesem Gerät (oder
    /// Loopback), über `host_gateway`.
    fn connect_authority(&self, t: &Target) -> String {
        let Some(gw) = &self.0.ctx.host_gateway else {
            return t.authority.clone();
        };
        let Ok(ip) = t.host.parse::<IpAddr>() else {
            return t.authority.clone();
        };
        if ip.is_loopback() || self.0.ctx.engine.device_addresses().contains(&ip) {
            format!("{gw}:{}", t.port())
        } else {
            t.authority.clone()
        }
    }

    fn is_device(&self, ip: IpAddr) -> bool {
        ip.is_loopback() || self.0.ctx.engine.device_addresses().contains(&ip)
    }

    /// Gesperrt (Sperren an, nicht pausiert, keine Ausnahme)? Liefert die Treffer.
    fn blocked(&self, host: &str) -> Option<Vec<String>> {
        let engine = &self.0.ctx.engine;
        if !engine.settings().blocking_enabled
            || engine
                .blocking_paused_until()
                .is_some_and(|t| t > crate::db::now())
        {
            return None;
        }
        let check = engine.check_domain(host);
        (check.blocked && !check.allowed).then_some(check.matches)
    }

    /// IPv4-Adresse einer Domain über die eigene Engine (ohne Protokolleintrag).
    async fn lookup(&self, host: &str) -> Option<IpAddr> {
        let r = self
            .0
            .ctx
            .engine
            .resolve(&ResolveInput {
                name: host.to_string(),
                qtype: "A".into(),
                ..ResolveInput::default()
            })
            .await
            .ok()?;
        r.answers
            .iter()
            .filter(|a| a.qtype == "A")
            .find_map(|a| a.data.parse::<IpAddr>().ok())
            .filter(|ip| !ip.is_unspecified())
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
        *lock(&self.0.errors) = errors;
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
            let service = service_fn(move |req| {
                handle(state.clone(), client.clone(), peer, Scheme::Http, req)
            });
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

/// Namen, die sicher das Gerät selbst meinen (IP, ohne Punkt, `.local`).
fn is_device_name(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
        || !host.contains('.')
        || host.ends_with(".local")
        || host.ends_with(".localhost")
}

async fn handle(
    state: ProxyState,
    client: Client<HttpConnector>,
    peer: SocketAddr,
    scheme: Scheme,
    req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    let lang = page::Lang::from_headers(req.headers());
    if req.uri().path() == "/.nrznetwork/health" {
        return Ok(Response::new(Body::from(HEALTH_BODY)));
    }
    let Some((host, raw_host)) = request_host(&req) else {
        return Ok(page::message(
            lang,
            StatusCode::BAD_REQUEST,
            "Anfrage ohne Host-Header.",
        ));
    };
    if req.headers().contains_key(LOOP_HEADER) {
        return Ok(page::message(
            lang,
            StatusCode::LOOP_DETECTED,
            &format!(
                "Der Eintrag für {} zeigt auf den Proxy selbst.",
                page::escape(&host)
            ),
        ));
    }

    // 1. Eintrag (mit Zertifikat und eingeschalteter Umleitung: erst auf HTTPS)
    if let Some(target) = state.route(&host) {
        if scheme == Scheme::Http
            && state
                .tls()
                .redirect
                .load(std::sync::atomic::Ordering::Relaxed)
            && state.tls().covers(&host)
            && !req.uri().path().starts_with(ACTION_PREFIX)
        {
            return Ok(https_redirect(&req, &host));
        }
        let authority = state.connect_authority(&target);
        return Ok(forward(
            &client, req, peer, scheme, &host, &raw_host, &target, &authority, lang,
        )
        .await);
    }

    // 2. Gesperrt → Sperrseite (auch für ihre Aktionen)
    if !is_device_name(&host) {
        if let Some(matches) = state.blocked(&host) {
            return Ok(
                page::handle_blocked(&state, req, peer, &host, &raw_host, matches, lang).await,
            );
        }
    }

    // 3. Gerät selbst → Fallback (umbrelOS)
    let fallback = state.0.ctx.fallback.clone();
    let resolved = if is_device_name(&host) {
        None
    } else {
        state.lookup(&host).await
    };
    let to_device = is_device_name(&host) || resolved.is_some_and(|ip| state.is_device(ip));
    if to_device {
        return Ok(match fallback {
            Some(t) => {
                let authority = t.authority.clone();
                forward(
                    &client, req, peer, scheme, &host, &raw_host, &t, &authority, lang,
                )
                .await
            }
            None => page::message(
                lang,
                StatusCode::NOT_FOUND,
                &format!(
                    "Für <b>{}</b> gibt es keinen Eintrag im Reverse Proxy von nrzNetwork.",
                    page::escape(&host)
                ),
            ),
        });
    }

    // 4. Andere Domain → durchreichen
    match resolved {
        Some(ip) => {
            let authority = match ip {
                IpAddr::V4(a) => format!("{a}:80"),
                IpAddr::V6(a) => format!("[{a}]:80"),
            };
            let t = Target {
                authority: authority.clone(),
                host: host.clone(),
                base: String::new(),
            };
            Ok(forward(
                &client, req, peer, scheme, &host, &raw_host, &t, &authority, lang,
            )
            .await)
        }
        None => Ok(page::message(
            lang,
            StatusCode::NOT_FOUND,
            &format!(
                "Für <b>{}</b> gibt es keinen Eintrag im Reverse Proxy von nrzNetwork.",
                page::escape(&host)
            ),
        )),
    }
}

/// Anfrage an `authority` weiterreichen (Ziel `target` für Pfad und `Location`).
#[allow(clippy::too_many_arguments)]
async fn forward(
    client: &Client<HttpConnector>,
    mut req: Request<Body>,
    peer: SocketAddr,
    scheme: Scheme,
    host: &str,
    raw_host: &str,
    target: &Target,
    authority: &str,
    lang: page::Lang,
) -> Response<Body> {
    let pq = req
        .uri()
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_string();
    let uri: Uri = match format!("http://{authority}{}{pq}", target.base).parse() {
        Ok(u) => u,
        Err(_) => return page::message(lang, StatusCode::BAD_REQUEST, "Ungültiger Pfad."),
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
        ("x-forwarded-host", raw_host.to_string()),
    ] {
        if let Ok(v) = HeaderValue::from_str(&value) {
            headers.insert(name, v);
        }
    }
    // Immer selbst setzen – ein Client soll nicht „https“ vortäuschen können
    headers.insert(
        "x-forwarded-proto",
        HeaderValue::from_static(scheme.as_str()),
    );
    headers.insert(LOOP_HEADER, HeaderValue::from_static("1"));

    let mut resp = match client.request(Request::from_parts(parts, body)).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(host = %host, target = %authority, "Reverse Proxy: {e}");
            return page::message(
                lang,
                StatusCode::BAD_GATEWAY,
                &format!(
                    "Das Ziel für <b>{}</b> (http://{}) antwortet nicht: {}",
                    page::escape(host),
                    page::escape(&target.authority),
                    page::escape(&e.to_string())
                ),
            );
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
            return resp;
        }
    }

    strip_hop_by_hop(resp.headers_mut());
    rewrite_location(resp.headers_mut(), target, authority, raw_host, scheme);
    resp
}

/// `https://<name>/<pfad>` (308, Methode bleibt).
fn https_redirect(req: &Request<Body>, host: &str) -> Response<Body> {
    let pq = req.uri().path_and_query().map_or("/", |p| p.as_str());
    Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(header::LOCATION, format!("https://{host}{pq}"))
        .body(Body::empty())
        .unwrap_or_default()
}

/// `Location: http://<ziel>/…` → `<schema>://<name>/…` (ohne den Pfad davor).
fn rewrite_location(
    headers: &mut HeaderMap,
    target: &Target,
    connected: &str,
    raw_host: &str,
    scheme: Scheme,
) {
    let Some(loc) = headers.get(header::LOCATION).and_then(|v| v.to_str().ok()) else {
        return;
    };
    let mut prefixes = vec![
        format!("http://{}", target.authority),
        format!("http://{connected}"),
    ];
    for a in [target.authority.as_str(), connected] {
        if let Some(no_port) = a.strip_suffix(":80") {
            prefixes.push(format!("http://{no_port}"));
        }
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
        if let Ok(v) = HeaderValue::from_str(&format!("{}://{raw_host}{rest}", scheme.as_str())) {
            headers.insert(header::LOCATION, v);
        }
        return;
    }
}

/// Ist eine POST-Anfrage von einer fremden Seite? (`Origin` gesetzt und anderer Host.)
fn foreign_origin(req: &Request<Body>, raw_host: &str) -> bool {
    req.headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|o| {
            let o = o
                .trim_start_matches("http://")
                .trim_start_matches("https://");
            !o.eq_ignore_ascii_case(raw_host)
        })
}

/// Formular lesen (`application/x-www-form-urlencoded`, höchstens 8 KB).
async fn read_form(req: Request<Body>) -> Option<HashMap<String, String>> {
    if req.method() != Method::POST {
        return None;
    }
    let too_big = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > 8192);
    if too_big {
        return None;
    }
    let bytes = hyper::body::to_bytes(req.into_body()).await.ok()?;
    if bytes.len() > 8192 {
        return None;
    }
    Some(parse_form(&String::from_utf8_lossy(&bytes)))
}

fn parse_form(s: &str) -> HashMap<String, String> {
    s.split('&')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            Some((url_decode(k)?, url_decode(v)?))
        })
        .collect()
}

fn url_decode(s: &str) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// Freischalten (aus der Sperrseite) und an die Engine geben.
async fn unlock(state: &ProxyState, host: &str, minutes: u32, client: IpAddr) -> bool {
    let ctx = &state.0.ctx;
    match unlocks::unlock(&ctx.pool, host, minutes, &client.to_string()).await {
        Ok(_) => {
            if let Err(e) = crate::services::sync::push_domains(
                &ctx.pool,
                &ctx.engine,
                crate::services::domains::Kind::Allowed,
            )
            .await
            {
                tracing::warn!("Freischalten: {e}");
            }
            ctx.engine.cache_remove(host);
            tracing::info!(domain = %host, minutes, client = %client, "Auf Zeit freigeschaltet");
            true
        }
        Err(e) => {
            tracing::warn!("Freischalten: {e}");
            false
        }
    }
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
        rewrite_location(
            &mut h,
            &t,
            "host.docker.internal:8350",
            "music.nrz.ch",
            Scheme::Http,
        );
        assert_eq!(h[header::LOCATION], "http://music.nrz.ch/login?x=1");
        h.insert(
            header::LOCATION,
            HeaderValue::from_static("http://host.docker.internal:8350/a"),
        );
        rewrite_location(
            &mut h,
            &t,
            "host.docker.internal:8350",
            "music.nrz.ch",
            Scheme::Https,
        );
        assert_eq!(h[header::LOCATION], "https://music.nrz.ch/a");
        h.insert(
            header::LOCATION,
            HeaderValue::from_static("http://100.78.107.162:83500/"),
        );
        rewrite_location(
            &mut h,
            &t,
            "100.78.107.162:8350",
            "music.nrz.ch",
            Scheme::Https,
        );
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

    #[test]
    fn forms() {
        let f = parse_form("minutes=15&reason=Brauche+das%20f%C3%BCr+Schule&back=%2Fa%3Fb");
        assert_eq!(f["minutes"], "15");
        assert_eq!(f["reason"], "Brauche das für Schule");
        assert_eq!(f["back"], "/a?b");
        assert!(url_decode("%zz").is_none());
        assert_eq!(url_decode("100%").as_deref(), Some("100%"));
    }

    #[test]
    fn device_names() {
        assert!(is_device_name("192.168.0.198"));
        assert!(is_device_name("umbrel"));
        assert!(is_device_name("umbrel.local"));
        assert!(!is_device_name("dns.nrz.ch"));
    }
}
