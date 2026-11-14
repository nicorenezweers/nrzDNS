//! HTTPS-Eingang des Proxys. Je Verbindung wird zuerst der Name aus dem TLS-ClientHello
//! gelesen (SNI, ohne etwas zu verbrauchen):
//!
//! * **Name passt zum Zertifikat** (z. B. `music.zweers.ch` bei `*.zweers.ch`): nrzNetwork
//!   verschlüsselt selbst und behandelt die Anfrage wie auf Port 80 (Einträge, Sperrseite …).
//! * **Sonst** (umbrelOS mit eigenem Zertifikat, Aufruf per IP ohne SNI …): die Verbindung geht
//!   unverändert an `tls_fallback` (auf Umbrel `host.docker.internal:443`) – umbrelOS merkt
//!   davon nichts.

use super::{handle, ProxyState, Scheme};
use hyper::client::HttpConnector;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::Client;
use rocket::Shutdown;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Geladenes Zertifikat.
#[derive(Clone)]
pub struct LoadedCert {
    pub key: Arc<CertifiedKey>,
    /// Namen (SAN), klein, ggf. mit `*.` vorn.
    pub names: Vec<String>,
    pub issuer: String,
    pub not_before: i64,
    pub not_after: i64,
}

/// Zustand rund um HTTPS (Teil von [`ProxyState`]).
#[derive(Default)]
pub struct TlsRuntime {
    cert: RwLock<Option<LoadedCert>>,
    /// `http://` für abgedeckte Namen auf `https://` umleiten.
    pub redirect: AtomicBool,
    /// Gerade läuft ein Versuch, ein Zertifikat zu holen.
    pub issuing: AtomicBool,
    pub last_attempt: AtomicI64,
    pub last_error: Mutex<String>,
    pub progress: Mutex<Vec<String>>,
    pub errors: Mutex<Vec<String>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Passt `host` zu einem Namen im Zertifikat? `*.zweers.ch` deckt genau eine Ebene ab
/// (`a.zweers.ch`, nicht `zweers.ch` und nicht `a.b.zweers.ch`).
pub fn name_matches(names: &[String], host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    names.iter().any(|n| {
        if let Some(base) = n.strip_prefix("*.") {
            host.strip_suffix(base)
                .and_then(|l| l.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty() && !label.contains('.'))
        } else {
            *n == host
        }
    })
}

impl TlsRuntime {
    pub fn set_cert(&self, cert: Option<LoadedCert>) {
        *self.cert.write().unwrap_or_else(PoisonError::into_inner) = cert;
    }

    pub fn cert(&self) -> Option<LoadedCert> {
        self.cert
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Ist für diesen Namen ein Zertifikat da?
    pub fn covers(&self, host: &str) -> bool {
        self.cert
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|c| name_matches(&c.names, host))
    }

    pub fn set_progress(&self, step: impl Into<String>) {
        let step = step.into();
        tracing::info!("HTTPS: {step}");
        lock(&self.progress).push(step);
    }

    pub fn progress(&self) -> Vec<String> {
        lock(&self.progress).clone()
    }

    pub fn last_error(&self) -> String {
        lock(&self.last_error).clone()
    }

    pub fn listen_errors(&self) -> Vec<String> {
        lock(&self.errors).clone()
    }
}

/// Wählt das Zertifikat nach dem Namen (rustls verlangt `Debug`).
struct Resolver(ProxyState);

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Resolver")
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?;
        let cert = self.0.tls().cert()?;
        name_matches(&cert.names, name).then(|| cert.key.clone())
    }
}

fn server_config(state: &ProxyState) -> Arc<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS-Versionen")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Resolver(state.clone())));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Ergebnis beim Lesen des ClientHello.
#[derive(Debug, PartialEq, Eq)]
pub enum Sni {
    /// Vollständig gelesen; Name, falls angegeben.
    Done(Option<String>),
    /// Noch nicht alles da.
    More,
    /// Kein TLS.
    NotTls,
}

/// Namen (SNI) aus dem Anfang einer TLS-Verbindung lesen (RFC 8446, 4.1.2 und RFC 6066, 3).
pub fn parse_sni(buf: &[u8]) -> Sni {
    // TLS-Record: Typ 22 (Handshake), Version, Länge
    if buf.is_empty() {
        return Sni::More;
    }
    if buf[0] != 22 {
        return Sni::NotTls;
    }
    if buf.len() < 5 {
        return Sni::More;
    }
    let rec_len = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
    if buf.len() < 5 + rec_len.min(4) {
        return Sni::More;
    }
    let hs = &buf[5..];
    if hs.first() != Some(&1) {
        return Sni::NotTls; // kein ClientHello
    }
    if hs.len() < 4 {
        return Sni::More;
    }
    let hs_len = (usize::from(hs[1]) << 16) | (usize::from(hs[2]) << 8) | usize::from(hs[3]);
    // Ein ClientHello über mehrere Records kommt praktisch nicht vor: dann ohne Namen
    if hs_len + 4 > rec_len {
        return Sni::Done(None);
    }
    if hs.len() < 4 + hs_len {
        return Sni::More;
    }
    let body = &hs[4..4 + hs_len];
    Sni::Done(client_hello_sni(body))
}

fn client_hello_sni(b: &[u8]) -> Option<String> {
    let mut p = 2 + 32; // Version, Zufall
    let sid = usize::from(*b.get(p)?);
    p += 1 + sid;
    let cs = usize::from(u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]));
    p += 2 + cs;
    let comp = usize::from(*b.get(p)?);
    p += 1 + comp;
    let ext_len = usize::from(u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]));
    p += 2;
    let end = (p + ext_len).min(b.len());
    while p + 4 <= end {
        let typ = u16::from_be_bytes([b[p], b[p + 1]]);
        let len = usize::from(u16::from_be_bytes([b[p + 2], b[p + 3]]));
        p += 4;
        let ext = b.get(p..p + len)?;
        if typ == 0 {
            // server_name: Listenlänge, dann Typ (0 = host_name), Länge, Name
            let mut q = 2;
            while q + 3 <= ext.len() {
                let kind = ext[q];
                let n = usize::from(u16::from_be_bytes([ext[q + 1], ext[q + 2]]));
                q += 3;
                let name = ext.get(q..q + n)?;
                if kind == 0 {
                    let name = std::str::from_utf8(name).ok()?;
                    return Some(name.trim_end_matches('.').to_ascii_lowercase());
                }
                q += n;
            }
            return None;
        }
        p += len;
    }
    None
}

/// ClientHello abwarten (ohne es zu verbrauchen), höchstens 5 s.
async fn peek_sni(stream: &TcpStream) -> Sni {
    let mut buf = vec![0u8; 16 * 1024 + 5];
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last = 0;
    loop {
        let n = match tokio::time::timeout_at(deadline.into(), stream.peek(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return Sni::NotTls,
            Ok(Ok(n)) => n,
        };
        match parse_sni(&buf[..n]) {
            Sni::More if n == buf.len() => return Sni::Done(None),
            Sni::More => {
                if Instant::now() >= deadline {
                    return Sni::NotTls;
                }
                // `peek` liefert dieselben Bytes sofort wieder – kurz warten, bis mehr da ist
                if n == last {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                last = n;
            }
            other => return other,
        }
    }
}

impl ProxyState {
    pub fn tls(&self) -> &TlsRuntime {
        &self.0.tls
    }

    /// HTTPS-Eingang öffnen. Fehler beim Öffnen stehen danach in
    /// [`TlsRuntime::listen_errors`].
    pub async fn serve_tls(&self, addrs: &[SocketAddr], shutdown: Shutdown) {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(Duration::from_secs(10)));
        connector.set_nodelay(true);
        let client: Client<HttpConnector> = Client::builder()
            .pool_idle_timeout(Duration::from_secs(30))
            .build(connector);
        let acceptor = TlsAcceptor::from(server_config(self));
        let mut errors = Vec::new();
        for addr in addrs {
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    tracing::info!("HTTPS-Eingang läuft auf {addr}");
                    tokio::spawn(accept_tls(
                        listener,
                        self.clone(),
                        client.clone(),
                        acceptor.clone(),
                        shutdown.clone(),
                    ));
                }
                Err(e) => {
                    let msg = format!("{addr}: {e}");
                    tracing::error!("HTTPS-Eingang: {msg}");
                    errors.push(msg);
                }
            }
        }
        *lock(&self.0.tls.errors) = errors;
    }
}

async fn accept_tls(
    listener: TcpListener,
    state: ProxyState,
    client: Client<HttpConnector>,
    acceptor: TlsAcceptor,
    mut shutdown: Shutdown,
) {
    loop {
        let (stream, peer) = tokio::select! {
            _ = &mut shutdown => break,
            r = listener.accept() => match r {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("HTTPS-Eingang: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let _ = stream.set_nodelay(true);
        let state = state.clone();
        let client = client.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let sni = peek_sni(&stream).await;
            let ours = matches!(&sni, Sni::Done(Some(name)) if state.tls().covers(name));
            if !ours {
                passthrough(&state, stream, peer).await;
                return;
            }
            let tls = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("HTTPS von {peer}: {e}");
                    return;
                }
            };
            let service = service_fn(move |req| {
                handle(state.clone(), client.clone(), peer, Scheme::Https, req)
            });
            if let Err(e) = Http::new()
                .http1_only(true)
                .http1_keep_alive(true)
                .serve_connection(tls, service)
                .with_upgrades()
                .await
            {
                tracing::debug!("HTTPS, Verbindung von {peer}: {e}");
            }
        });
    }
}

/// Unverändert an `tls_fallback` weiterreichen (oder schliessen, wenn keiner da ist).
async fn passthrough(state: &ProxyState, mut stream: TcpStream, peer: SocketAddr) {
    let Some(fallback) = state.0.ctx.tls_fallback.clone() else {
        return;
    };
    let connect = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&fallback));
    match connect.await {
        Ok(Ok(mut upstream)) => {
            let _ = upstream.set_nodelay(true);
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
        }
        Ok(Err(e)) => tracing::warn!("HTTPS von {peer} an {fallback}: {e}"),
        Err(_) => tracing::warn!("HTTPS von {peer} an {fallback}: keine Antwort"),
    }
}

/// Zertifikat (Kette, PEM) und Schlüssel (PEM) laden und prüfen.
pub fn load_pem(cert_pem: &str, key_pem: &str) -> Result<LoadedCert, String> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| format!("Zertifikat lesen: {e}"))?;
    let first = certs.first().ok_or("Zertifikat: keines gefunden")?.clone();
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| format!("Schlüssel lesen: {e}"))?
        .ok_or("Schlüssel: keiner gefunden")?;
    let provider = rustls::crypto::ring::default_provider();
    let signing = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| format!("Schlüssel: {e}"))?;
    let (_, parsed) = x509_parser::parse_x509_certificate(first.as_ref())
        .map_err(|e| format!("Zertifikat: {e}"))?;
    let mut names = Vec::new();
    if let Ok(Some(san)) = parsed.subject_alternative_name() {
        for n in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(d) = n {
                names.push(d.to_ascii_lowercase());
            }
        }
    }
    if names.is_empty() {
        return Err("Zertifikat: keine Namen (SAN)".into());
    }
    let issuer = parsed
        .issuer()
        .iter_organization()
        .chain(parsed.issuer().iter_common_name())
        .filter_map(|a| a.as_str().ok())
        .collect::<Vec<_>>()
        .join(" – ");
    let validity = parsed.validity();
    let key = CertifiedKey::new(certs, signing);
    key.keys_match()
        .map_err(|e| format!("Schlüssel passt nicht zum Zertifikat: {e}"))?;
    Ok(LoadedCert {
        key: Arc::new(key),
        names,
        issuer,
        not_before: validity.not_before.timestamp(),
        not_after: validity.not_after.timestamp(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_names() {
        let n = vec!["zweers.ch".to_string(), "*.zweers.ch".to_string()];
        assert!(name_matches(&n, "zweers.ch"));
        assert!(name_matches(&n, "Music.Zweers.CH."));
        assert!(!name_matches(&n, "a.b.zweers.ch"));
        assert!(!name_matches(&n, "evilzweers.ch"));
        assert!(!name_matches(&n, "zweers.ch.evil.com"));
        assert!(!name_matches(&["*.zweers.ch".into()], "zweers.ch"));
    }

    fn client_hello(name: Option<&str>) -> Vec<u8> {
        let roots = rustls::RootCertStore::empty();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = match name {
            Some(n) => rustls::pki_types::ServerName::try_from(n.to_string()).unwrap(),
            None => {
                config.enable_sni = false;
                rustls::pki_types::ServerName::try_from("x.invalid".to_string()).unwrap()
            }
        };
        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }

    #[test]
    fn sni_from_client_hello() {
        let hello = client_hello(Some("music.zweers.ch"));
        assert_eq!(parse_sni(&hello), Sni::Done(Some("music.zweers.ch".into())));
        assert_eq!(parse_sni(&hello[..hello.len() - 10]), Sni::More);
        assert_eq!(parse_sni(&hello[..3]), Sni::More);
        assert_eq!(parse_sni(&client_hello(None)), Sni::Done(None));
        assert_eq!(parse_sni(b"GET / HTTP/1.1\r\n"), Sni::NotTls);
    }
}
