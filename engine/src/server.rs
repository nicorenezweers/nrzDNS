//! UDP- und TCP-Listener. TCP: 2-Byte-Länge, mehrere Anfragen je Verbindung (auch
//! gleichzeitig, Antworten in beliebiger Reihenfolge, RFC 7766), Leerlauf-Zeitlimit,
//! begrenzte Zahl gleichzeitiger Verbindungen.

use crate::wire::UDP_MAX;
use crate::Engine;
use nrzdns_types::Protocol;
use socket2::{Domain, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Semaphore};

/// Ohne neue Anfrage wird eine TCP-Verbindung nach dieser Zeit geschlossen.
const TCP_IDLE: Duration = Duration::from_secs(10);
/// Höchstens so viele TCP-Verbindungen gleichzeitig.
const TCP_MAX_CONNECTIONS: usize = 512;
/// Höchstens so viele Anfragen je TCP-Verbindung gleichzeitig in Arbeit.
const TCP_MAX_INFLIGHT: usize = 32;
/// Höchstens so viele UDP-Anfragen gleichzeitig in Arbeit; darüber wird verworfen.
const UDP_MAX_INFLIGHT: usize = 4096;

/// Socket für eine Adresse; IPv6 nur für IPv6 (sonst kollidiert `[::]:53` mit `0.0.0.0:53`).
fn socket(addr: SocketAddr, ty: Type) -> std::io::Result<Socket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, ty, None)?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    if ty == Type::STREAM {
        sock.set_reuse_address(true)?;
    }
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    Ok(sock)
}

pub(crate) fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let sock = socket(addr, Type::DGRAM)?;
    UdpSocket::from_std(sock.into())
}

pub(crate) fn bind_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let sock = socket(addr, Type::STREAM)?;
    sock.listen(1024)?;
    TcpListener::from_std(sock.into())
}

pub(crate) fn serve_udp(engine: Engine, sock: UdpSocket) {
    let sock = Arc::new(sock);
    let limit = Arc::new(Semaphore::new(UDP_MAX_INFLIGHT));
    tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_MAX];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    // z. B. ICMP-Fehler früherer Antworten; kurz warten statt heisser Schleife
                    tracing::debug!(error = %e, "UDP-Empfang fehlgeschlagen");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                }
            };
            let Ok(permit) = limit.clone().try_acquire_owned() else {
                continue;
            };
            let data = buf[..n].to_vec();
            let engine = engine.clone();
            let sock = sock.clone();
            tokio::spawn(async move {
                if let Some(resp) = engine.handle(&data, peer.ip(), Protocol::Udp).await {
                    let _ = sock.send_to(&resp, peer).await;
                }
                drop(permit);
            });
        }
    });
}

pub(crate) fn serve_tcp(engine: Engine, listener: TcpListener) {
    let limit = Arc::new(Semaphore::new(TCP_MAX_CONNECTIONS));
    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(error = %e, "TCP-Annahme fehlgeschlagen");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
            };
            // Zu viele Verbindungen: die neue sofort schliessen
            let Ok(permit) = limit.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let engine = engine.clone();
            tokio::spawn(async move {
                serve_connection(engine, stream, peer).await;
                drop(permit);
            });
        }
    });
}

async fn serve_connection(engine: Engine, stream: TcpStream, peer: SocketAddr) {
    let _ = stream.set_nodelay(true);
    let (mut reader, mut writer) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(TCP_MAX_INFLIGHT);

    let write_task = tokio::spawn(async move {
        while let Some(resp) = rx.recv().await {
            let Ok(len) = u16::try_from(resp.len()) else {
                continue;
            };
            let mut out = Vec::with_capacity(resp.len() + 2);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&resp);
            match tokio::time::timeout(TCP_IDLE, writer.write_all(&out)).await {
                Ok(Ok(())) => {}
                _ => break,
            }
        }
        let _ = writer.shutdown().await;
    });

    let inflight = Arc::new(Semaphore::new(TCP_MAX_INFLIGHT));
    loop {
        let mut len = [0u8; 2];
        match tokio::time::timeout(TCP_IDLE, reader.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let n = u16::from_be_bytes(len) as usize;
        if n == 0 {
            break;
        }
        let mut msg = vec![0u8; n];
        match tokio::time::timeout(TCP_IDLE, reader.read_exact(&mut msg)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let Ok(permit) = inflight.clone().acquire_owned().await else {
            break;
        };
        let engine = engine.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Some(resp) = engine.handle(&msg, peer.ip(), Protocol::Tcp).await {
                let _ = tx.send(resp).await;
            }
            drop(permit);
        });
    }
    drop(tx);
    let _ = write_task.await;
}
