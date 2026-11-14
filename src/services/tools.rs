//! Netzwerk-Tools: Ping (ICMP über Datagramm-Sockets, sonst TCP-Verbindungsaufbau),
//! Port-Check, HTTP-Check und die Geräte aus dem Abfrageprotokoll mit eigenen Namen.

use crate::db::now;
use crate::error::{AppError, AppResult};
use futures::StreamExt;
use nrzdns_engine::Engine;
use nrzdns_types::{
    Device, HttpCheckResult, PingResult, PortProbe, PortState, PortsResult, ResolveInput,
};
use socket2::{Domain, Protocol, Socket, Type};
use sqlx::SqlitePool;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// Höchstens so viele Ports je Check.
pub const MAX_PORTS: usize = 200;

/// Name oder IP → IP (Namen über die eigene Engine, also mit eigenen Zonen).
pub async fn resolve_host(engine: &Engine, host: &str) -> AppResult<IpAddr> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() || host.len() > 253 || host.contains(['/', ' ', '@']) {
        return Err(AppError::bad(
            "Bitte einen Namen oder eine IP-Adresse angeben.",
        ));
    }
    let ip = if let Ok(ip) = host.parse::<IpAddr>() {
        ip
    } else {
        let mut found = None;
        for qtype in ["A", "AAAA"] {
            let r = engine
                .resolve(&ResolveInput {
                    name: host.to_string(),
                    qtype: qtype.into(),
                    ..ResolveInput::default()
                })
                .await?;
            found = r
                .answers
                .iter()
                .filter(|a| a.qtype == qtype)
                .find_map(|a| a.data.parse::<IpAddr>().ok());
            if found.is_some() {
                break;
            }
        }
        found.ok_or_else(|| AppError::bad(format!("„{host}“ lässt sich nicht auflösen.")))?
    };
    if ip.is_unspecified() || ip.is_multicast() || ip == IpAddr::from([255, 255, 255, 255]) {
        return Err(AppError::bad("Diese Adresse geht hier nicht."));
    }
    Ok(ip)
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Ping über einen ICMP-Datagramm-Socket (ohne Root). `Err` = ICMP nicht erlaubt.
fn icmp_ping(ip: IpAddr, count: u32) -> std::io::Result<Vec<Option<f64>>> {
    let (domain, proto, req_type, reply_type) = match ip {
        IpAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4, 8u8, 0u8),
        IpAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6, 128u8, 129u8),
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(proto))?;
    sock.connect(&SocketAddr::new(ip, 0).into())?;
    let mut out = Vec::new();
    for seq in 0..count as u16 {
        let mut pkt = vec![req_type, 0, 0, 0, 0x6e, 0x72, (seq >> 8) as u8, seq as u8];
        pkt.extend_from_slice(b"nrzNetwork-ping!");
        if ip.is_ipv4() {
            let c = checksum(&pkt);
            pkt[2..4].copy_from_slice(&c.to_be_bytes());
        }
        let started = Instant::now();
        let deadline = started + Duration::from_secs(2);
        sock.send(&pkt)?;
        let mut got = None;
        let mut buf = [0u8; 1500];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            sock.set_read_timeout(Some(left))?;
            let n = match (&sock).read(&mut buf) {
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break
                }
                Err(e) => return Err(e),
            };
            // macOS liefert bei IPv4 den IP-Kopf mit
            let off = if ip.is_ipv4() && n >= 20 && buf[0] >> 4 == 4 {
                usize::from(buf[0] & 0x0f) * 4
            } else {
                0
            };
            if n >= off + 8 && buf[off] == reply_type && buf[off + 6..off + 8] == seq.to_be_bytes()
            {
                got = Some(started.elapsed().as_secs_f64() * 1000.0);
                break;
            }
        }
        out.push(got);
        if u32::from(seq) + 1 < count {
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    Ok(out)
}

async fn tcp_time(ip: IpAddr, port: u16, timeout: Duration) -> (PortState, Option<f64>) {
    let started = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(ip, port))).await {
        Ok(Ok(_)) => (
            PortState::Open,
            Some(started.elapsed().as_secs_f64() * 1000.0),
        ),
        Ok(Err(_)) => (PortState::Closed, None),
        Err(_) => (PortState::Timeout, None),
    }
}

fn round(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

pub async fn ping(engine: &Engine, host: &str, count: u32) -> AppResult<PingResult> {
    let count = if count == 0 { 4 } else { count.min(10) };
    let ip = resolve_host(engine, host).await?;
    let icmp = tokio::task::spawn_blocking(move || icmp_ping(ip, count))
        .await
        .map_err(|e| AppError::Config(e.to_string()))?;
    let (method, probes) = match icmp {
        Ok(p) => ("icmp", p),
        Err(e) => {
            tracing::debug!("ICMP nicht möglich ({e}), TCP stattdessen");
            let port = match tcp_time(ip, 443, Duration::from_secs(2)).await {
                (PortState::Closed, _) => 80,
                _ => 443,
            };
            let mut p = Vec::new();
            for i in 0..count {
                let (state, ms) = tcp_time(ip, port, Duration::from_secs(2)).await;
                p.push(if state == PortState::Open { ms } else { None });
                if i + 1 < count {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
            ("tcp", p)
        }
    };
    let ok: Vec<f64> = probes.iter().flatten().copied().collect();
    let loss = if probes.is_empty() {
        100.0
    } else {
        (probes.len() - ok.len()) as f64 * 100.0 / probes.len() as f64
    };
    Ok(PingResult {
        host: host.trim().to_string(),
        ip: ip.to_string(),
        method: method.into(),
        min_ms: ok.iter().copied().reduce(f64::min).map(round),
        max_ms: ok.iter().copied().reduce(f64::max).map(round),
        avg_ms: (!ok.is_empty()).then(|| round(ok.iter().sum::<f64>() / ok.len() as f64)),
        probes: probes.into_iter().map(|p| p.map(round)).collect(),
        loss_percent: round(loss),
    })
}

/// `22,80,443,8000-8010` → Ports (sortiert, ohne Doppelte).
pub fn parse_ports(spec: &str) -> AppResult<Vec<u16>> {
    let bad = || AppError::bad("Ports: z. B. 22,80,443 oder 8000-8010 (1–65535).");
    let mut out = Vec::new();
    for part in spec
        .split([',', ' ', ';'])
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let (a, b) = match part.split_once('-') {
            Some((a, b)) => (
                a.trim().parse::<u16>().map_err(|_| bad())?,
                b.trim().parse::<u16>().map_err(|_| bad())?,
            ),
            None => {
                let p = part.parse::<u16>().map_err(|_| bad())?;
                (p, p)
            }
        };
        if a == 0 || b < a {
            return Err(bad());
        }
        if usize::from(b - a) + out.len() >= MAX_PORTS {
            return Err(AppError::bad(format!(
                "Höchstens {MAX_PORTS} Ports auf einmal."
            )));
        }
        out.extend(a..=b);
    }
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        return Err(bad());
    }
    Ok(out)
}

pub async fn ports(engine: &Engine, host: &str, spec: &str) -> AppResult<PortsResult> {
    let list = parse_ports(spec)?;
    let ip = resolve_host(engine, host).await?;
    let mut probes: Vec<PortProbe> = futures::stream::iter(list)
        .map(|port| async move {
            let (state, ms) = tcp_time(ip, port, Duration::from_millis(1500)).await;
            PortProbe {
                port,
                state,
                ms: ms.map(round),
            }
        })
        .buffer_unordered(50)
        .collect()
        .await;
    probes.sort_by_key(|p| p.port);
    Ok(PortsResult {
        host: host.trim().to_string(),
        ip: ip.to_string(),
        ports: probes,
    })
}

pub async fn http_check(input: &str) -> AppResult<HttpCheckResult> {
    let raw = input.trim();
    let url = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{raw}")
    };
    let parsed = reqwest::Url::parse(&url)
        .map_err(|_| AppError::bad("Bitte eine Adresse wie https://example.com angeben."))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(AppError::bad("Nur http:// und https://."));
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("nrzNetwork/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AppError::Config(e.to_string()))?;
    let started = Instant::now();
    let resp = client
        .get(parsed.clone())
        .send()
        .await
        .map_err(|e| AppError::BadGateway(format!("Keine Antwort: {e}")))?;
    let ms = round(started.elapsed().as_secs_f64() * 1000.0);
    let status = resp.status();
    let headers = resp
        .headers()
        .iter()
        .take(50)
        .map(|(k, v)| {
            (
                k.to_string(),
                String::from_utf8_lossy(v.as_bytes())
                    .chars()
                    .take(300)
                    .collect(),
            )
        })
        .collect();
    Ok(HttpCheckResult {
        url: parsed.to_string(),
        final_url: resp.url().to_string(),
        status: status.as_u16(),
        reason: status.canonical_reason().unwrap_or("").to_string(),
        ms,
        remote: resp
            .remote_addr()
            .map(|a| a.to_string())
            .unwrap_or_default(),
        tls: resp.url().scheme() == "https",
        headers,
    })
}

/// Geräte, die in den letzten `days` Tagen gefragt haben, meiste Anfragen zuerst.
pub async fn devices(pool: &SqlitePool, days: u32) -> AppResult<Vec<Device>> {
    let days = i64::from(days.clamp(1, 30));
    let since_ms = (now() - days * 86_400) * 1000;
    let rows: Vec<(String, i64, i64, i64, Option<String>)> = sqlx::query_as(
        "SELECT q.client, count(*), sum(q.kind = 'blocked'), max(q.at_ms), d.name
         FROM query_log q LEFT JOIN device_names d ON d.ip = q.client
         WHERE q.at_ms >= ? GROUP BY q.client ORDER BY count(*) DESC LIMIT 500",
    )
    .bind(since_ms)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(ip, queries, blocked, last_ms, name)| Device {
            ip,
            name: name.unwrap_or_default(),
            queries: queries.max(0) as u64,
            blocked: blocked.max(0) as u64,
            last_seen: last_ms / 1000,
        })
        .collect())
}

pub async fn set_device_name(pool: &SqlitePool, ip: &str, name: &str) -> AppResult<Device> {
    let ip: IpAddr = ip
        .trim()
        .parse()
        .map_err(|_| AppError::bad("Ungültige IP-Adresse."))?;
    let ip = ip.to_string();
    let name = name.trim();
    if name.chars().count() > 60 || name.chars().any(char::is_control) {
        return Err(AppError::bad(
            "Name: höchstens 60 Zeichen, ohne Steuerzeichen.",
        ));
    }
    if name.is_empty() {
        sqlx::query("DELETE FROM device_names WHERE ip = ?")
            .bind(&ip)
            .execute(pool)
            .await?;
    } else {
        sqlx::query(
            "INSERT INTO device_names (ip, name, updated_at) VALUES (?, ?, ?)
             ON CONFLICT (ip) DO UPDATE SET name = excluded.name, updated_at = excluded.updated_at",
        )
        .bind(&ip)
        .bind(name)
        .bind(now())
        .execute(pool)
        .await?;
    }
    let found = devices(pool, 30).await?.into_iter().find(|d| d.ip == ip);
    Ok(found.unwrap_or(Device {
        ip,
        name: name.to_string(),
        ..Device::default()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_specs() {
        assert_eq!(
            parse_ports("443, 22,80-82,80").unwrap(),
            [22, 80, 81, 82, 443]
        );
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("90-80").is_err());
        assert!(parse_ports("1-1000").is_err());
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("").is_err());
    }

    #[test]
    fn icmp_checksum() {
        // Beispiel aus RFC 1071: 0001 f203 f4f5 f6f7 → Summe ddf2, Prüfsumme 220d
        assert_eq!(
            checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            0x220d
        );
    }
}
