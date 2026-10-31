//! Vorgelagerte Server fragen: UDP (mit TCP-Rückfall bei TC), TCP, DNS über TLS (RFC 7858)
//! und DNS über HTTPS (RFC 8484, POST). TCP- und TLS-Verbindungen werden kurz offen gehalten
//! und wiederverwendet.
//!
//! Hostnamen (DoH-URLs, Sperrlisten) löst ein eigener Bootstrap-Resolver per UDP über die
//! eingestellten Weiterleitungen auf – nicht über das System, das womöglich diesen Server
//! selbst fragt (Schleife).

use crate::stats::lock;
use crate::wire::{error_chain, name_str, parse_name};
use crate::EngineError;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use nrzdns_types::{Upstream, UpstreamProtocol};
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

/// So lange darf eine TCP/TLS-Verbindung unbenutzt im Vorrat liegen.
const POOL_IDLE: Duration = Duration::from_secs(10);
/// Höchstens so viele freie Verbindungen je Server.
const POOL_MAX: usize = 4;
/// Grösste Antwort, die wir annehmen.
const MAX_MESSAGE: usize = 65_535;

pub(crate) trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

type Pool = HashMap<String, Vec<(Instant, Box<dyn Stream>)>>;

/// Netzwerk-Clients der Engine (Verbindungsvorrat für TCP und TLS).
#[derive(Default)]
pub(crate) struct Clients {
    pool: Mutex<Pool>,
}

impl Clients {
    /// Eine Anfrage an einen vorgelagerten Server; die ID der Antwort ist geprüft.
    pub async fn exchange(
        &self,
        upstream: &Upstream,
        query: &Message,
        timeout: Duration,
    ) -> Result<Message, EngineError> {
        match upstream.protocol {
            UpstreamProtocol::Udp => {
                let addr = resolve_addr(&upstream.address, 53).await?;
                let resp = with_timeout(timeout, udp_exchange(addr, query)).await?;
                if resp.metadata.truncation {
                    return self.stream_exchange(addr, None, query, timeout).await;
                }
                Ok(resp)
            }
            UpstreamProtocol::Tcp => {
                let addr = resolve_addr(&upstream.address, 53).await?;
                self.stream_exchange(addr, None, query, timeout).await
            }
            UpstreamProtocol::Tls => {
                let addr = resolve_addr(&upstream.address, 853).await?;
                let name = tls_server_name(upstream)?;
                self.stream_exchange(addr, Some(name), query, timeout).await
            }
            UpstreamProtocol::Https => doh_exchange(&upstream.address, query, timeout).await,
        }
    }

    async fn stream_exchange(
        &self,
        addr: SocketAddr,
        tls: Option<ServerName<'static>>,
        query: &Message,
        timeout: Duration,
    ) -> Result<Message, EngineError> {
        let bytes = query
            .to_vec()
            .map_err(|e| EngineError::Invalid(e.to_string()))?;
        let key = match &tls {
            Some(name) => format!("tls|{addr}|{name:?}"),
            None => format!("tcp|{addr}"),
        };
        // Erst eine offene Verbindung versuchen; ist sie tot, gleich eine neue
        if let Some(mut stream) = self.take_idle(&key) {
            if let Ok(Ok(resp)) =
                tokio::time::timeout(timeout / 2, framed_exchange(&mut stream, &bytes, query)).await
            {
                self.put_idle(&key, stream);
                return Ok(resp);
            }
        }
        with_timeout(timeout, async {
            let mut stream = connect(addr, tls).await?;
            let resp = framed_exchange(&mut stream, &bytes, query).await?;
            self.put_idle(&key, stream);
            Ok(resp)
        })
        .await
    }

    fn take_idle(&self, key: &str) -> Option<Box<dyn Stream>> {
        let mut pool = lock(&self.pool);
        let list = pool.get_mut(key)?;
        while let Some((at, stream)) = list.pop() {
            if at.elapsed() < POOL_IDLE {
                return Some(stream);
            }
        }
        None
    }

    fn put_idle(&self, key: &str, stream: Box<dyn Stream>) {
        let mut pool = lock(&self.pool);
        let list = pool.entry(key.to_string()).or_default();
        list.retain(|(at, _)| at.elapsed() < POOL_IDLE);
        if list.len() < POOL_MAX {
            list.push((Instant::now(), stream));
        }
    }
}

async fn with_timeout<T>(
    timeout: Duration,
    fut: impl Future<Output = Result<T, EngineError>>,
) -> Result<T, EngineError> {
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| EngineError::Timeout)?
}

fn io_error(what: &str, e: std::io::Error) -> EngineError {
    EngineError::Network(format!("{what}: {}", error_chain(&e)))
}

/// Gehört die Antwort zu dieser Anfrage (ID, Antwort-Bit, Frage)?
pub(crate) fn matches_query(query: &Message, resp: &Message) -> bool {
    if resp.metadata.id != query.metadata.id || resp.metadata.message_type != MessageType::Response
    {
        return false;
    }
    let (Some(q), Some(r)) = (query.queries.first(), resp.queries.first()) else {
        // Manche Server lassen die Frage bei Fehlern weg
        return resp.queries.is_empty() && resp.metadata.response_code != ResponseCode::NoError;
    };
    resp.queries.len() == 1
        && name_str(&q.name) == name_str(&r.name)
        && q.query_type == r.query_type
        && q.query_class == r.query_class
}

async fn udp_exchange(addr: SocketAddr, query: &Message) -> Result<Message, EngineError> {
    let bytes = query
        .to_vec()
        .map_err(|e| EngineError::Invalid(e.to_string()))?;
    let bind: SocketAddr = if addr.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(bind)
        .await
        .map_err(|e| io_error("UDP", e))?;
    sock.connect(addr).await.map_err(|e| io_error("UDP", e))?;
    sock.send(&bytes).await.map_err(|e| io_error("UDP", e))?;
    let mut buf = vec![0u8; MAX_MESSAGE];
    loop {
        let n = sock.recv(&mut buf).await.map_err(|e| io_error("UDP", e))?;
        // Fremde oder kaputte Pakete ignorieren (Schutz vor gefälschten Antworten)
        if let Ok(resp) = Message::from_vec(&buf[..n]) {
            if matches_query(query, &resp) {
                return Ok(resp);
            }
        }
    }
}

async fn connect(
    addr: SocketAddr,
    tls: Option<ServerName<'static>>,
) -> Result<Box<dyn Stream>, EngineError> {
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| io_error("Verbindung fehlgeschlagen", e))?;
    let _ = tcp.set_nodelay(true);
    match tls {
        None => Ok(Box::new(tcp)),
        Some(name) => {
            let stream = tls_connector()?
                .connect(name, tcp)
                .await
                .map_err(|e| io_error("TLS", e))?;
            Ok(Box::new(stream))
        }
    }
}

/// Nachricht mit 2-Byte-Länge schreiben und die Antwort lesen.
async fn framed_exchange(
    stream: &mut Box<dyn Stream>,
    bytes: &[u8],
    query: &Message,
) -> Result<Message, EngineError> {
    let len =
        u16::try_from(bytes.len()).map_err(|_| EngineError::Invalid("Anfrage zu gross".into()))?;
    let mut out = Vec::with_capacity(bytes.len() + 2);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    stream
        .write_all(&out)
        .await
        .map_err(|e| io_error("Senden", e))?;
    stream.flush().await.map_err(|e| io_error("Senden", e))?;
    loop {
        let mut len = [0u8; 2];
        stream
            .read_exact(&mut len)
            .await
            .map_err(|e| io_error("Empfangen", e))?;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| io_error("Empfangen", e))?;
        let resp = Message::from_vec(&buf)
            .map_err(|_| EngineError::Network("Unlesbare Antwort".into()))?;
        if matches_query(query, &resp) {
            return Ok(resp);
        }
    }
}

fn tls_connector() -> Result<TlsConnector, EngineError> {
    static CONNECTOR: OnceLock<Result<TlsConnector, String>> = OnceLock::new();
    CONNECTOR
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .with_root_certificates(roots)
                .with_no_client_auth();
            Ok(TlsConnector::from(Arc::new(config)))
        })
        .clone()
        .map_err(|e| EngineError::Network(format!("TLS nicht verfügbar: {e}")))
}

/// Name im Zertifikat: `tls_name`, sonst der Host aus der Adresse.
fn tls_server_name(upstream: &Upstream) -> Result<ServerName<'static>, EngineError> {
    let name = if upstream.tls_name.trim().is_empty() {
        match split_host_port(&upstream.address, 853)? {
            (Host::Ip(ip), _) => return Ok(ServerName::IpAddress(ip.into())),
            (Host::Name(n), _) => n,
        }
    } else {
        upstream.tls_name.trim().to_string()
    };
    ServerName::try_from(name.clone())
        .map_err(|_| EngineError::Invalid(format!("Ungültiger TLS-Name „{name}“")))
}

async fn doh_exchange(
    url: &str,
    query: &Message,
    timeout: Duration,
) -> Result<Message, EngineError> {
    let url = reqwest::Url::parse(url.trim())
        .ok()
        .filter(|u| u.scheme() == "https" || u.scheme() == "http")
        .ok_or_else(|| EngineError::Invalid(format!("Ungültige DoH-Adresse „{url}“")))?;
    // RFC 8484: ID 0, damit HTTP-Caches greifen
    let mut q = query.clone();
    q.metadata.id = 0;
    let bytes = q
        .to_vec()
        .map_err(|e| EngineError::Invalid(e.to_string()))?;
    let resp = http_client()
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
        .header(reqwest::header::ACCEPT, "application/dns-message")
        .body(bytes)
        .timeout(timeout)
        .send()
        .await
        .map_err(http_error)?;
    let status = resp.status();
    if !status.is_success() {
        return Err(EngineError::Network(format!("HTTP {}", status.as_u16())));
    }
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_MESSAGE as u64)
    {
        return Err(EngineError::Network("Antwort zu gross".into()));
    }
    let body = resp.bytes().await.map_err(http_error)?;
    let mut msg =
        Message::from_vec(&body).map_err(|_| EngineError::Network("Unlesbare Antwort".into()))?;
    if !matches_query(&q, &msg) {
        return Err(EngineError::Network(
            "Antwort passt nicht zur Anfrage".into(),
        ));
    }
    msg.metadata.id = query.metadata.id;
    Ok(msg)
}

fn http_error(e: reqwest::Error) -> EngineError {
    if e.is_timeout() {
        EngineError::Timeout
    } else {
        EngineError::Network(error_chain(&e))
    }
}

/// Gemeinsamer HTTP-Client (DoH und Sperrlisten): rustls mit eingebauten Wurzelzertifikaten,
/// eigener Resolver.
pub(crate) fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .user_agent(concat!("nrzDNS/", env!("CARGO_PKG_VERSION")))
            .dns_resolver(Arc::new(BootstrapResolver))
            .connect_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .unwrap_or_default()
    })
}

// ------------------------------------------------------------------ Adressen

pub(crate) enum Host {
    Ip(IpAddr),
    Name(String),
}

/// `1.1.1.1`, `1.1.1.1:53`, `[2606:4700::1111]:53`, `2606:4700::1111`, `dns.example:853`.
pub(crate) fn split_host_port(addr: &str, default_port: u16) -> Result<(Host, u16), EngineError> {
    let a = addr.trim();
    let invalid = || EngineError::Invalid(format!("Ungültige Adresse „{addr}“"));
    if let Ok(sa) = a.parse::<SocketAddr>() {
        return Ok((Host::Ip(sa.ip()), sa.port()));
    }
    if let Ok(ip) = a
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
    {
        return Ok((Host::Ip(ip), default_port));
    }
    let (host, port) = match a.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| invalid())?),
        None => (a, default_port),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let valid = !host.is_empty()
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if !valid || port == 0 {
        return Err(invalid());
    }
    Ok((Host::Name(host), port))
}

pub(crate) async fn resolve_addr(addr: &str, default_port: u16) -> Result<SocketAddr, EngineError> {
    match split_host_port(addr, default_port)? {
        (Host::Ip(ip), port) => Ok(SocketAddr::new(ip, port)),
        (Host::Name(name), port) => {
            let ips = resolve_host(&name).await?;
            ips.first()
                .map(|ip| SocketAddr::new(*ip, port))
                .ok_or_else(|| EngineError::Network(format!("{name} nicht gefunden")))
        }
    }
}

// ------------------------------------------------------------------ Bootstrap-Resolver

/// Server für den Bootstrap: die klassischen Adressen der eingestellten Weiterleitungen,
/// sonst Cloudflare und Quad9.
static BOOTSTRAP: RwLock<Vec<SocketAddr>> = RwLock::new(Vec::new());

type HostCache = HashMap<String, (Vec<IpAddr>, Instant)>;

fn host_cache() -> &'static Mutex<HostCache> {
    static CACHE: OnceLock<Mutex<HostCache>> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// Bootstrap-Server aus den Weiterleitungen ableiten (bei jeder Änderung der Einstellungen).
pub(crate) fn set_bootstrap(forwarders: &[Upstream]) {
    let servers = derive_bootstrap(forwarders);
    if let Ok(mut b) = BOOTSTRAP.write() {
        *b = servers;
    }
}

/// Klassische Adressen (Port 53) der Weiterleitungen; DoT/DoH nur, wenn als IP angegeben.
fn derive_bootstrap(forwarders: &[Upstream]) -> Vec<SocketAddr> {
    let mut servers: Vec<SocketAddr> = Vec::new();
    for u in forwarders {
        let ip = match u.protocol {
            UpstreamProtocol::Udp | UpstreamProtocol::Tcp | UpstreamProtocol::Tls => {
                match split_host_port(&u.address, 53) {
                    Ok((Host::Ip(ip), port)) if u.protocol != UpstreamProtocol::Tls => {
                        Some(SocketAddr::new(ip, port))
                    }
                    Ok((Host::Ip(ip), _)) => Some(SocketAddr::new(ip, 53)),
                    _ => None,
                }
            }
            UpstreamProtocol::Https => reqwest::Url::parse(&u.address)
                .ok()
                .and_then(|url| {
                    url.host_str()
                        .map(|h| h.trim_matches(['[', ']']).to_string())
                })
                .and_then(|h| h.parse::<IpAddr>().ok())
                .map(|ip| SocketAddr::new(ip, 53)),
        };
        if let Some(sa) = ip.filter(|sa| !servers.contains(sa)) {
            servers.push(sa);
        }
    }
    servers
}

fn bootstrap_servers() -> Vec<SocketAddr> {
    let configured = BOOTSTRAP.read().map(|b| b.clone()).unwrap_or_default();
    if configured.is_empty() {
        vec![
            SocketAddr::from(([1, 1, 1, 1], 53)),
            SocketAddr::from(([9, 9, 9, 9], 53)),
        ]
    } else {
        configured
    }
}

/// Hostname → Adressen (IPv4 zuerst). Erst per Bootstrap-UDP, notfalls über das System.
pub(crate) async fn resolve_host(host: &str) -> Result<Vec<IpAddr>, EngineError> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    if host == "localhost" {
        return Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }
    if let Some((ips, until)) = lock(host_cache()).get(&host) {
        if *until > Instant::now() {
            return Ok(ips.clone());
        }
    }
    let name = parse_name(&host)
        .ok_or_else(|| EngineError::Invalid(format!("Ungültiger Name „{host}“")))?;
    let mut found: Option<(Vec<IpAddr>, u32)> = None;
    for server in bootstrap_servers() {
        let (v4, v6) = tokio::join!(
            bootstrap_query(server, &name, RecordType::A),
            bootstrap_query(server, &name, RecordType::AAAA)
        );
        let mut ips = Vec::new();
        let mut ttl = u32::MAX;
        for (list, t) in [v4, v6].into_iter().flatten() {
            ips.extend(list);
            ttl = ttl.min(t);
        }
        if !ips.is_empty() {
            found = Some((ips, ttl));
            break;
        }
    }
    let (ips, ttl) = match found {
        Some(f) => f,
        None => {
            let addrs = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((host.as_str(), 0)),
            )
            .await
            .map_err(|_| EngineError::Timeout)?
            .map_err(|e| {
                EngineError::Network(format!("{host} nicht gefunden: {}", error_chain(&e)))
            })?;
            let mut ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            ips.sort_by_key(|ip| ip.is_ipv6());
            ips.dedup();
            (ips, 300)
        }
    };
    if ips.is_empty() {
        return Err(EngineError::Network(format!("{host} nicht gefunden")));
    }
    let keep = Duration::from_secs(ttl.clamp(60, 3600) as u64);
    lock(host_cache()).insert(host, (ips.clone(), Instant::now() + keep));
    Ok(ips)
}

async fn bootstrap_query(
    server: SocketAddr,
    name: &hickory_proto::rr::Name,
    qtype: RecordType,
) -> Option<(Vec<IpAddr>, u32)> {
    let mut msg = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name.clone(), qtype));
    let mut edns = Edns::new();
    edns.set_max_payload(crate::wire::EDNS_PAYLOAD);
    msg.set_edns(edns);
    let resp = tokio::time::timeout(Duration::from_millis(1500), udp_exchange(server, &msg))
        .await
        .ok()?
        .ok()?;
    let mut ttl = u32::MAX;
    let ips: Vec<IpAddr> = resp
        .answers
        .iter()
        .filter_map(|r| {
            let ip = match &r.data {
                RData::A(a) => IpAddr::V4(a.0),
                RData::AAAA(a) => IpAddr::V6(a.0),
                _ => return None,
            };
            ttl = ttl.min(r.ttl);
            Some(ip)
        })
        .collect();
    (!ips.is_empty()).then_some((ips, ttl))
}

struct BootstrapResolver;

impl reqwest::dns::Resolve for BootstrapResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let ips = resolve_host(&host)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            let addrs: reqwest::dns::Addrs =
                Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        let ok = |a: &str, p: u16| match split_host_port(a, p).unwrap() {
            (Host::Ip(ip), port) => SocketAddr::new(ip, port).to_string(),
            (Host::Name(n), port) => format!("{n}:{port}"),
        };
        assert_eq!(ok("1.1.1.1", 53), "1.1.1.1:53");
        assert_eq!(ok("1.1.1.1:5353", 53), "1.1.1.1:5353");
        assert_eq!(ok("[2606:4700::1111]:853", 53), "[2606:4700::1111]:853");
        assert_eq!(ok("2606:4700::1111", 853), "[2606:4700::1111]:853");
        assert_eq!(ok("[::1]", 53), "[::1]:53");
        assert_eq!(ok("dns.Example.net:853", 53), "dns.example.net:853");
        assert!(split_host_port("", 53).is_err());
        assert!(split_host_port("bad host", 53).is_err());
        assert!(split_host_port("host:99999", 53).is_err());
    }

    #[test]
    fn tls_names() {
        let u = Upstream::new(
            UpstreamProtocol::Tls,
            "1.1.1.1:853",
            "cloudflare-dns.com",
            "",
        );
        assert!(matches!(
            tls_server_name(&u).unwrap(),
            ServerName::DnsName(_)
        ));
        let u = Upstream::new(UpstreamProtocol::Tls, "1.1.1.1", "", "");
        assert!(matches!(
            tls_server_name(&u).unwrap(),
            ServerName::IpAddress(_)
        ));
        assert!(tls_connector().is_ok());
    }

    #[test]
    fn bootstrap_from_forwarders() {
        let s = derive_bootstrap(&[
            Upstream::new(UpstreamProtocol::Https, "https://9.9.9.9/dns-query", "", ""),
            Upstream::new(
                UpstreamProtocol::Tls,
                "1.1.1.1:853",
                "cloudflare-dns.com",
                "",
            ),
            Upstream::new(
                UpstreamProtocol::Https,
                "https://dns.mullvad.net/dns-query",
                "",
                "",
            ),
            Upstream::new(UpstreamProtocol::Udp, "127.0.0.1:5353", "", ""),
        ]);
        let want: Vec<SocketAddr> = ["9.9.9.9:53", "1.1.1.1:53", "127.0.0.1:5353"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(s, want);
    }
}
