//! Engine von aussen: echte UDP/TCP-Listener auf localhost, ein falscher vorgelagerter
//! Server auf localhost, Abfrageprotokoll über den Kanal. Kein Internet nötig.

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use nrzdns_engine::types::{
    BlockMode, DnsSettings, Protocol, QueryLogEntry, RecordData, ResolveInput, ResponseKind, Soa,
    Upstream, UpstreamProtocol, Zone, ZoneDetail, ZoneKind, ZoneRecord,
};
use nrzdns_engine::Engine;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc::Receiver;

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

// ------------------------------------------------------------------ Falscher Upstream

struct FakeUpstream {
    port: u16,
    udp_hits: Arc<AtomicUsize>,
    tcp_hits: Arc<AtomicUsize>,
}

impl FakeUpstream {
    fn upstream(&self) -> Upstream {
        Upstream::new(
            UpstreamProtocol::Udp,
            &format!("127.0.0.1:{}", self.port),
            "",
            "Test",
        )
    }
}

fn name(s: &str) -> Name {
    Name::from_ascii(format!("{s}.")).unwrap()
}

fn a(owner: &Name, ttl: u32, ip: [u8; 4]) -> Record {
    Record::from_rdata(owner.clone(), ttl, RData::A(A(ip.into())))
}

/// Antworten des falschen Servers je nach Name.
fn fake_answer(req: &Message, udp: bool) -> Message {
    let mut resp = Message::new(req.metadata.id, MessageType::Response, OpCode::Query);
    resp.metadata.recursion_desired = true;
    resp.metadata.recursion_available = true;
    resp.queries = req.queries.clone();
    if let Some(e) = &req.edns {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.set_dnssec_ok(e.flags().dnssec_ok);
        resp.set_edns(edns);
    }
    let q = &req.queries[0];
    let owner = q.name.clone();
    let lname = owner.to_ascii().trim_end_matches('.').to_ascii_lowercase();
    match lname.as_str() {
        "big.test" if udp => resp.metadata.truncation = true,
        "big.test" => {
            for i in 1..=3 {
                resp.add_answer(a(&owner, 300, [10, 0, 0, i]));
            }
        }
        "many.test" => {
            for i in 1..=60 {
                resp.add_answer(a(&owner, 300, [10, 1, 0, i]));
            }
        }
        "nx.test" => {
            resp.metadata.response_code = ResponseCode::NXDomain;
            resp.add_authority(Record::from_rdata(
                name("test"),
                3600,
                RData::SOA(SOA::new(name("ns.test"), name("hm.test"), 1, 1, 1, 1, 60)),
            ));
        }
        "fail.test" => resp.metadata.response_code = ResponseCode::ServFail,
        "cloaked.test" => {
            resp.add_answer(Record::from_rdata(
                owner.clone(),
                300,
                RData::CNAME(CNAME(name("tracker.blocked.test"))),
            ));
            resp.add_answer(a(&name("tracker.blocked.test"), 300, [5, 6, 7, 8]));
        }
        "short.test" => {
            resp.add_answer(a(&owner, 1, [9, 9, 9, 9]));
        }
        _ if q.query_type == RecordType::A => {
            resp.add_answer(a(&owner, 300, [1, 2, 3, 4]));
        }
        _ => {}
    }
    resp
}

async fn fake_upstream() -> FakeUpstream {
    let (udp, tcp, port) = loop {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        if let Ok(tcp) = TcpListener::bind(("127.0.0.1", port)).await {
            break (udp, tcp, port);
        }
    };
    let udp_hits = Arc::new(AtomicUsize::new(0));
    let tcp_hits = Arc::new(AtomicUsize::new(0));
    let hits = udp_hits.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = udp.recv_from(&mut buf).await else {
                continue;
            };
            let Ok(req) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            hits.fetch_add(1, Ordering::SeqCst);
            let resp = fake_answer(&req, true).to_vec().unwrap();
            let _ = udp.send_to(&resp, peer).await;
        }
    });
    let hits = tcp_hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = tcp.accept().await else {
                continue;
            };
            let hits = hits.clone();
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 2];
                    if stream.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut msg = vec![0u8; u16::from_be_bytes(len) as usize];
                    if stream.read_exact(&mut msg).await.is_err() {
                        return;
                    }
                    let Ok(req) = Message::from_vec(&msg) else {
                        return;
                    };
                    hits.fetch_add(1, Ordering::SeqCst);
                    let resp = fake_answer(&req, false).to_vec().unwrap();
                    let mut out = (resp.len() as u16).to_be_bytes().to_vec();
                    out.extend_from_slice(&resp);
                    if stream.write_all(&out).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    FakeUpstream {
        port,
        udp_hits,
        tcp_hits,
    }
}

// ------------------------------------------------------------------ Hilfen

/// Freier Port für UDP und TCP zugleich.
async fn free_port() -> u16 {
    loop {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        if TcpListener::bind(("127.0.0.1", port)).await.is_ok() {
            return port;
        }
    }
}

fn settings(up: &FakeUpstream) -> DnsSettings {
    DnsSettings {
        forwarders: vec![up.upstream()],
        upstream_timeout_ms: 1000,
        ..DnsSettings::default()
    }
}

async fn start(settings: DnsSettings) -> (Engine, Receiver<QueryLogEntry>, SocketAddr) {
    let (engine, rx) = Engine::new(settings, "test");
    let port = free_port().await;
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let errors = engine.listen(&[addr]).await;
    assert!(errors.is_empty(), "{errors:?}");
    (engine, rx, addr)
}

fn query(n: &str, qtype: RecordType, edns: bool) -> Message {
    let mut msg = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(Name::from_ascii(n).unwrap(), qtype));
    if edns {
        let mut e = Edns::new();
        e.set_max_payload(1232);
        msg.set_edns(e);
    }
    msg
}

async fn ask_udp(addr: SocketAddr, n: &str, qtype: RecordType, edns: bool) -> Message {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let q = query(n, qtype, edns);
    sock.send_to(&q.to_vec().unwrap(), addr).await.unwrap();
    let mut buf = vec![0u8; 65535];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("keine Antwort")
        .unwrap();
    let resp = Message::from_vec(&buf[..len]).unwrap();
    assert_eq!(resp.metadata.id, q.metadata.id);
    assert_eq!(resp.queries, q.queries);
    resp
}

async fn ask(engine: &Engine, n: &str, qtype: RecordType) -> Message {
    let q = query(n, qtype, true);
    let bytes = engine
        .handle(&q.to_vec().unwrap(), LOCAL, Protocol::Https)
        .await
        .unwrap();
    Message::from_vec(&bytes).unwrap()
}

async fn next_log(rx: &mut Receiver<QueryLogEntry>) -> QueryLogEntry {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("kein Protokolleintrag")
        .unwrap()
}

fn ips(msg: &Message) -> Vec<String> {
    msg.answers
        .iter()
        .filter_map(|r| r.data.ip_addr().map(|i| i.to_string()))
        .collect()
}

fn zone(name: &str, kind: ZoneKind, records: Vec<(&str, RecordData)>) -> ZoneDetail {
    ZoneDetail {
        zone: Zone {
            id: 1,
            name: name.into(),
            kind,
            disabled: false,
            soa: Soa {
                primary_ns: format!("ns1.{name}"),
                responsible: format!("hostmaster.{name}"),
                serial: 7,
                minimum: 120,
                ..Soa::default()
            },
            forwarders: vec![],
            comment: String::new(),
            record_count: records.len() as u32,
            created_at: 0,
            updated_at: 0,
        },
        records: records
            .into_iter()
            .enumerate()
            .map(|(i, (n, data))| ZoneRecord {
                id: i as i64,
                zone_id: 1,
                name: n.into(),
                ttl: 600,
                data,
                disabled: false,
                comment: String::new(),
                updated_at: 0,
            })
            .collect(),
    }
}

fn rec_a(ip: &str) -> RecordData {
    RecordData::A { address: ip.into() }
}

// ------------------------------------------------------------------ Tests

#[tokio::test(flavor = "multi_thread")]
async fn forwards_caches_and_logs() {
    let up = fake_upstream().await;
    let (engine, mut log, addr) = start(settings(&up)).await;

    let resp = ask_udp(addr, "www.example.org.", RecordType::A, true).await;
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert!(resp.metadata.recursion_available);
    assert!(resp.edns.is_some());
    assert_eq!(ips(&resp), ["1.2.3.4"]);
    let entry = next_log(&mut log).await;
    assert_eq!(entry.kind, ResponseKind::Forwarded);
    assert_eq!(entry.qname, "www.example.org");
    assert_eq!(entry.qtype, "A");
    assert_eq!(entry.rcode, "NOERROR");
    assert_eq!(entry.answer, "1.2.3.4");
    assert_eq!(entry.client, "127.0.0.1");
    assert_eq!(entry.protocol, Protocol::Udp);
    assert_eq!(entry.upstream, format!("udp://127.0.0.1:{}", up.port));
    assert!(entry.at_ms > 0);

    // zweites Mal aus dem Cache, mit kleinerer oder gleicher TTL
    let resp = ask_udp(addr, "WWW.Example.ORG.", RecordType::A, false).await;
    assert_eq!(ips(&resp), ["1.2.3.4"]);
    assert!(resp.answers[0].ttl <= 300);
    assert!(resp.edns.is_none());
    let entry = next_log(&mut log).await;
    assert_eq!(entry.kind, ResponseKind::Cached);
    assert_eq!(up.udp_hits.load(Ordering::SeqCst), 1);

    // Cache-Liste und Status
    let list = engine.cache_list("example.org", 10);
    assert_eq!(list.entries.len(), 1);
    assert_eq!(list.entries[0].answers, ["A 1.2.3.4"]);
    assert_eq!(list.entries[0].hits, 1);
    let status = engine.status();
    assert_eq!(status.version, "test");
    assert!(status.dns_listen.contains(&format!("{addr}/udp")));
    assert!(status.dns_listen.contains(&format!("{addr}/tcp")));
    assert_eq!(status.queries_since_start, 2);
    assert_eq!(status.cache_entries, 1);
    assert_eq!(status.upstreams.len(), 1);
    assert_eq!(status.upstreams[0].ok, 1);
    assert_eq!(status.upstreams[0].name, "Test");
    assert_eq!(engine.cache_remove("www.example.org."), 1);
    assert_eq!(engine.cache_flush(), 0);

    // negative Antworten werden ebenfalls gespeichert
    let resp = ask_udp(addr, "nx.test.", RecordType::A, true).await;
    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(next_log(&mut log).await.answer, "NXDOMAIN");
    let resp = ask_udp(addr, "nx.test.", RecordType::A, true).await;
    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(next_log(&mut log).await.kind, ResponseKind::Cached);

    // SERVFAIL vom Upstream: nicht gespeichert, kind failed
    let resp = ask_udp(addr, "fail.test.", RecordType::A, true).await;
    assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(next_log(&mut log).await.kind, ResponseKind::Failed);
    let before = up.udp_hits.load(Ordering::SeqCst);
    ask_udp(addr, "fail.test.", RecordType::A, true).await;
    assert_eq!(up.udp_hits.load(Ordering::SeqCst), before + 1);
    let _ = next_log(&mut log).await;

    // Protokoll aus: keine Einträge mehr
    engine.apply_settings(DnsSettings {
        log_queries: false,
        ..settings(&up)
    });
    ask_udp(addr, "quiet.test.", RecordType::A, true).await;
    assert!(log.try_recv().is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_fallback_and_truncation() {
    let up = fake_upstream().await;
    let (_engine, mut log, addr) = start(settings(&up)).await;

    // Upstream setzt über UDP TC → Engine fragt per TCP nach
    let resp = ask_udp(addr, "big.test.", RecordType::A, true).await;
    assert_eq!(ips(&resp), ["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    assert_eq!(up.udp_hits.load(Ordering::SeqCst), 1);
    assert_eq!(up.tcp_hits.load(Ordering::SeqCst), 1);
    assert_eq!(next_log(&mut log).await.kind, ResponseKind::Forwarded);

    // 60 A-Einträge passen nicht in 512 Bytes: ohne EDNS TC-Bit für den Client
    let resp = ask_udp(addr, "many.test.", RecordType::A, false).await;
    assert!(resp.metadata.truncation);
    assert!(resp.answers.is_empty());
    let _ = next_log(&mut log).await;

    // … und über TCP (zwei Anfragen hintereinander auf einer Verbindung) vollständig
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let q1 = query("many.test.", RecordType::A, false);
    let q2 = query("other.test.", RecordType::A, false);
    let mut out = Vec::new();
    for q in [&q1, &q2] {
        let b = q.to_vec().unwrap();
        out.extend_from_slice(&(b.len() as u16).to_be_bytes());
        out.extend_from_slice(&b);
    }
    stream.write_all(&out).await.unwrap();
    let mut got = Vec::new();
    for _ in 0..2 {
        let mut len = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len))
            .await
            .unwrap()
            .unwrap();
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut buf).await.unwrap();
        got.push(Message::from_vec(&buf).unwrap());
    }
    let r1 = got
        .iter()
        .find(|m| m.metadata.id == q1.metadata.id)
        .unwrap();
    let r2 = got
        .iter()
        .find(|m| m.metadata.id == q2.metadata.id)
        .unwrap();
    assert_eq!(r1.answers.len(), 60);
    assert!(!r1.metadata.truncation);
    assert_eq!(ips(r2), ["1.2.3.4"]);
    let e = next_log(&mut log).await;
    assert_eq!(e.protocol, Protocol::Tcp);
}

#[tokio::test(flavor = "multi_thread")]
async fn blocking_modes_and_cloaking() {
    let up = fake_upstream().await;
    let (engine, mut log, addr) = start(settings(&up)).await;
    engine.set_custom_blocked(vec!["blocked.test".into()]);
    engine.set_block_list(
        1,
        "Testliste",
        vec!["ads.example.net".into(), "blocked.test".into()],
    );
    engine.set_allowed(vec!["ok.ads.example.net".into()]);
    assert_eq!(engine.blocked_domain_count(), 2);

    let resp = ask_udp(addr, "x.blocked.test.", RecordType::A, true).await;
    assert_eq!(ips(&resp), ["0.0.0.0"]);
    assert_eq!(resp.answers[0].ttl, 60);
    let e = next_log(&mut log).await;
    assert_eq!(e.kind, ResponseKind::Blocked);
    assert_eq!(e.answer, "0.0.0.0 (gesperrt)");

    let resp = ask_udp(addr, "ads.example.net.", RecordType::AAAA, true).await;
    assert_eq!(ips(&resp), ["::"]);
    let _ = next_log(&mut log).await;

    // Ausnahme schlägt Liste
    let resp = ask_udp(addr, "ok.ads.example.net.", RecordType::A, true).await;
    assert_eq!(ips(&resp), ["1.2.3.4"]);
    assert_eq!(next_log(&mut log).await.kind, ResponseKind::Forwarded);

    // CNAME auf eine gesperrte Domain
    let resp = ask_udp(addr, "cloaked.test.", RecordType::A, true).await;
    assert_eq!(ips(&resp), ["0.0.0.0"]);
    assert_eq!(next_log(&mut log).await.kind, ResponseKind::Blocked);

    // Firefox-Kanarienvogel
    let resp = ask_udp(addr, "use-application-dns.net.", RecordType::A, true).await;
    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    let _ = next_log(&mut log).await;

    // andere Modi
    for (mode, rcode) in [
        (BlockMode::NxDomain, ResponseCode::NXDomain),
        (BlockMode::Refused, ResponseCode::Refused),
    ] {
        engine.apply_settings(DnsSettings {
            block_mode: mode,
            ..settings(&up)
        });
        let resp = ask(&engine, "blocked.test.", RecordType::A).await;
        assert_eq!(resp.metadata.response_code, rcode);
    }
    engine.apply_settings(DnsSettings {
        block_mode: BlockMode::CustomAddress,
        block_ipv4: "192.168.1.250".into(),
        ..settings(&up)
    });
    assert_eq!(
        ips(&ask(&engine, "blocked.test.", RecordType::A).await),
        ["192.168.1.250"]
    );
    assert_eq!(
        ips(&ask(&engine, "blocked.test.", RecordType::AAAA).await),
        ["::"]
    );
    let mx = ask(&engine, "blocked.test.", RecordType::MX).await;
    assert!(mx.answers.is_empty() && mx.metadata.response_code == ResponseCode::NoError);

    // Pause und Schalter
    engine.pause_blocking(Some(i64::MAX / 2));
    assert!(engine.blocking_paused_until().is_some());
    assert_eq!(
        ips(&ask(&engine, "blocked.test.", RecordType::A).await),
        ["1.2.3.4"]
    );
    engine.pause_blocking(None);
    assert_eq!(engine.blocking_paused_until(), None);
    engine.apply_settings(DnsSettings {
        blocking_enabled: false,
        ..settings(&up)
    });
    engine.cache_flush();
    assert_eq!(
        ips(&ask(&engine, "ads.example.net.", RecordType::A).await),
        ["1.2.3.4"]
    );

    let check = engine.check_domain("www.ads.example.net");
    assert!(check.blocked);
    assert_eq!(check.matches, ["Liste „Testliste“: ads.example.net"]);
    engine.remove_block_list(1);
    assert_eq!(engine.blocked_domain_count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn own_zones() {
    let up = fake_upstream().await;
    let (engine, _log) = Engine::new(settings(&up), "test");
    let mut fwd = zone(
        "fritz.box",
        ZoneKind::Forwarder,
        vec![("nas", rec_a("192.168.178.5"))],
    );
    fwd.zone.forwarders = vec![up.upstream()];
    engine.set_zones(vec![
        zone(
            "home.test",
            ZoneKind::Primary,
            vec![
                ("@", rec_a("10.0.0.1")),
                ("www", rec_a("10.0.0.2")),
                ("*.dev", rec_a("10.0.0.3")),
                (
                    "alias",
                    RecordData::CNAME {
                        target: "www.home.test".into(),
                    },
                ),
                (
                    "ext",
                    RecordData::CNAME {
                        target: "upstream.example.org".into(),
                    },
                ),
                (
                    "@",
                    RecordData::NS {
                        host: "ns1.home.test".into(),
                    },
                ),
                ("ns1", rec_a("10.0.0.53")),
            ],
        ),
        fwd,
    ]);
    assert_eq!(engine.status().zones, 2);

    let r = ask(&engine, "www.home.test.", RecordType::A).await;
    assert!(r.metadata.authoritative);
    assert_eq!(ips(&r), ["10.0.0.2"]);

    let r = ask(&engine, "app.dev.home.test.", RecordType::A).await;
    assert_eq!(ips(&r), ["10.0.0.3"]);
    assert_eq!(r.answers[0].name, name("app.dev.home.test"));

    let r = ask(&engine, "alias.home.test.", RecordType::A).await;
    assert_eq!(r.answers.len(), 2);
    assert_eq!(r.answers[0].record_type(), RecordType::CNAME);
    assert_eq!(ips(&r), ["10.0.0.2"]);

    // CNAME aus der Zone hinaus: Rest über den Upstream
    let r = ask(&engine, "ext.home.test.", RecordType::A).await;
    assert_eq!(r.answers.len(), 2);
    assert_eq!(ips(&r), ["1.2.3.4"]);

    // NXDOMAIN und NODATA mit SOA
    let r = ask(&engine, "nope.home.test.", RecordType::A).await;
    assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
    assert!(r.metadata.authoritative);
    assert_eq!(r.authorities.len(), 1);
    assert_eq!(r.authorities[0].record_type(), RecordType::SOA);
    assert_eq!(r.authorities[0].ttl, 120);
    let r = ask(&engine, "www.home.test.", RecordType::AAAA).await;
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert!(r.answers.is_empty());
    assert_eq!(r.authorities[0].record_type(), RecordType::SOA);

    // SOA und NS der Zone
    let r = ask(&engine, "home.test.", RecordType::SOA).await;
    match &r.answers[0].data {
        RData::SOA(soa) => assert_eq!(soa.serial, 7),
        other => panic!("{other:?}"),
    }
    let r = ask(&engine, "home.test.", RecordType::NS).await;
    assert_eq!(r.answers.len(), 1);
    assert_eq!(r.additionals.len(), 1);

    // Weiterleitungszone: eigener Eintrag zuerst, sonst an die Weiterleitung der Zone
    assert_eq!(
        ips(&ask(&engine, "nas.fritz.box.", RecordType::A).await),
        ["192.168.178.5"]
    );
    assert_eq!(
        ips(&ask(&engine, "router.fritz.box.", RecordType::A).await),
        ["1.2.3.4"]
    );

    // DNS-Client: dieser Server
    let res = engine
        .resolve(&ResolveInput {
            name: "alias.home.test".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(res.kind, Some(ResponseKind::Authoritative));
    assert_eq!(res.server, "Dieser Server");
    assert!(res.flags.contains(&"aa".to_string()));
    assert_eq!(res.answers[0].data, "www.home.test.");
    assert_eq!(res.answers[1].data, "10.0.0.2");
    assert_eq!(res.answers[0].qtype, "CNAME");

    // DNS-Client: anderer Server, PTR mit IP
    let res = engine
        .resolve(&ResolveInput {
            name: "www.example.org".into(),
            qtype: "a".into(),
            server: format!("127.0.0.1:{}", up.port),
            protocol: UpstreamProtocol::Udp,
        })
        .await
        .unwrap();
    assert_eq!(res.server, format!("udp://127.0.0.1:{}", up.port));
    assert_eq!(res.answers[0].data, "1.2.3.4");
    assert_eq!(res.kind, None);
    let res = engine
        .resolve(&ResolveInput {
            name: "8.8.4.4".into(),
            qtype: "PTR".into(),
            server: format!("127.0.0.1:{}", up.port),
            protocol: UpstreamProtocol::Tcp,
        })
        .await
        .unwrap();
    assert_eq!(res.rcode, "NOERROR");
    assert!(engine
        .resolve(&ResolveInput {
            name: "x".into(),
            qtype: "NOPE".into(),
            ..Default::default()
        })
        .await
        .is_err());
    assert!(engine.resolve(&ResolveInput::default()).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn local_answers_and_errors() {
    let up = fake_upstream().await;
    let (engine, mut log) = Engine::new(
        DnsSettings {
            disable_ipv6_answers: true,
            ..settings(&up)
        },
        "test",
    );
    assert_eq!(
        ips(&ask(&engine, "localhost.", RecordType::A).await),
        ["127.0.0.1"]
    );
    assert_eq!(next_log(&mut log).await.kind, ResponseKind::Local);
    assert_eq!(
        ips(&ask(&engine, "app.localhost.", RecordType::AAAA).await),
        ["::1"]
    );
    let _ = next_log(&mut log).await;
    let r = ask(&engine, "10.1.168.192.in-addr.arpa.", RecordType::PTR).await;
    assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(next_log(&mut log).await.kind, ResponseKind::Local);
    let r = ask(&engine, "www.example.org.", RecordType::AAAA).await;
    assert!(r.answers.is_empty());
    assert_eq!(next_log(&mut log).await.kind, ResponseKind::Local);
    assert_eq!(up.udp_hits.load(Ordering::SeqCst), 0);

    // Unlesbares: FORMERR mit Kopf, ohne Kopf nichts
    let garbage = [
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
    ];
    let resp = engine.handle(&garbage, LOCAL, Protocol::Udp).await.unwrap();
    let resp = Message::from_vec(&resp).unwrap();
    assert_eq!(resp.metadata.id, 0xabcd);
    assert_eq!(resp.metadata.response_code, ResponseCode::FormErr);
    assert!(engine
        .handle(&[1, 2, 3], LOCAL, Protocol::Udp)
        .await
        .is_none());

    // Kein Upstream erreichbar → SERVFAIL
    engine.apply_settings(DnsSettings {
        forwarders: vec![Upstream::new(UpstreamProtocol::Udp, "127.0.0.1:9", "", "")],
        upstream_timeout_ms: 300,
        ..DnsSettings::default()
    });
    let r = ask(&engine, "unreachable.example.", RecordType::A).await;
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    let e = next_log(&mut log).await;
    assert_eq!(e.kind, ResponseKind::Failed);
    assert_eq!(e.rcode, "SERVFAIL");
    let status = engine.status();
    assert_eq!(status.upstreams[0].failed, 1);
    assert!(status.upstreams[0].last_error.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_stale_when_upstream_fails() {
    let up = fake_upstream().await;
    let base = DnsSettings {
        cache_min_ttl: 1,
        ..settings(&up)
    };
    let (engine, mut log) = Engine::new(base.clone(), "test");
    let r = ask(&engine, "short.test.", RecordType::A).await;
    assert_eq!(ips(&r), ["9.9.9.9"]);
    let _ = next_log(&mut log).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    engine.apply_settings(DnsSettings {
        forwarders: vec![Upstream::new(UpstreamProtocol::Udp, "127.0.0.1:9", "", "")],
        upstream_timeout_ms: 300,
        ..base
    });
    let r = ask(&engine, "short.test.", RecordType::A).await;
    assert_eq!(ips(&r), ["9.9.9.9"]);
    assert_eq!(r.answers[0].ttl, 30);
    let e = next_log(&mut log).await;
    assert_eq!(e.kind, ResponseKind::Cached);
    let list = engine.cache_list("", 0);
    assert!(list.entries[0].stale);
}

#[tokio::test(flavor = "multi_thread")]
async fn rate_limit_drops() {
    let up = fake_upstream().await;
    let (engine, mut log) = Engine::new(
        DnsSettings {
            rate_limit_qps: 2,
            ..settings(&up)
        },
        "test",
    );
    let q = query("localhost.", RecordType::A, false).to_vec().unwrap();
    let client: IpAddr = "192.0.2.7".parse().unwrap();
    assert!(engine.handle(&q, client, Protocol::Udp).await.is_some());
    assert!(engine.handle(&q, client, Protocol::Udp).await.is_some());
    assert!(engine.handle(&q, client, Protocol::Udp).await.is_none());
    // anderer Client nicht betroffen
    assert!(engine.handle(&q, LOCAL, Protocol::Udp).await.is_some());
    let kinds: Vec<ResponseKind> = [
        next_log(&mut log).await,
        next_log(&mut log).await,
        next_log(&mut log).await,
        next_log(&mut log).await,
    ]
    .iter()
    .map(|e| e.kind)
    .collect();
    assert_eq!(
        kinds
            .iter()
            .filter(|k| **k == ResponseKind::Dropped)
            .count(),
        1
    );
    assert_eq!(engine.status().queries_since_start, 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn listen_errors_are_reported() {
    let up = fake_upstream().await;
    let (engine, _log, addr) = start(settings(&up)).await;
    let errors = engine.listen(&[addr]).await;
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(
        errors[0].starts_with(&format!("{addr}/udp: ")),
        "{errors:?}"
    );
    assert!(
        errors[1].starts_with(&format!("{addr}/tcp: ")),
        "{errors:?}"
    );
    assert!(!errors[0].contains("os error"), "{errors:?}");
    assert_eq!(engine.status().listen_errors, errors);
}

#[tokio::test(flavor = "multi_thread")]
async fn zone_file_round_trip_through_engine() {
    // Zonendatei lesen, als Zone setzen, beantworten
    let text = "$ORIGIN lan.test.\n$TTL 300\n@ SOA ns hm 3 1 1 1 60\nprinter A 10.0.0.9\n";
    let parsed = nrzdns_engine::zonefile::parse(text, "", 3600).unwrap();
    let mut z = zone("lan.test", ZoneKind::Primary, vec![]);
    z.zone.soa = parsed.soa.unwrap();
    for (i, r) in parsed.records.into_iter().enumerate() {
        z.records.push(ZoneRecord {
            id: i as i64,
            zone_id: 1,
            name: r.name,
            ttl: r.ttl,
            data: r.data,
            disabled: r.disabled,
            comment: r.comment,
            updated_at: 0,
        });
    }
    let (engine, _log) = Engine::new(DnsSettings::default(), "test");
    engine.set_zones(vec![z.clone()]);
    let r = ask(&engine, "printer.lan.test.", RecordType::A).await;
    assert_eq!(ips(&r), ["10.0.0.9"]);
    assert_eq!(r.answers[0].ttl, 300);
    let exported = nrzdns_engine::zonefile::export(&z);
    assert!(exported.contains("printer"));
}

#[tokio::test(flavor = "multi_thread")]
async fn forwarding_strategies() {
    use nrzdns_engine::types::ForwardingStrategy;
    let up = fake_upstream().await;
    let dead = Upstream::new(UpstreamProtocol::Udp, "127.0.0.1:9", "", "Tot");
    let tcp = Upstream::new(
        UpstreamProtocol::Tcp,
        &format!("127.0.0.1:{}", up.port),
        "",
        "",
    );
    for (i, strategy) in [
        ForwardingStrategy::Sequential,
        ForwardingStrategy::Random,
        ForwardingStrategy::Parallel,
    ]
    .into_iter()
    .enumerate()
    {
        let (engine, mut log) = Engine::new(
            DnsSettings {
                forwarders: vec![dead.clone(), tcp.clone()],
                forwarding_strategy: strategy,
                upstream_timeout_ms: 500,
                cache_enabled: false,
                ..DnsSettings::default()
            },
            "test",
        );
        let n = format!("s{i}.example.org.");
        let r = ask(&engine, &n, RecordType::A).await;
        assert_eq!(ips(&r), ["1.2.3.4"], "{strategy:?}");
        let e = next_log(&mut log).await;
        assert_eq!(e.kind, ResponseKind::Forwarded);
        assert_eq!(e.upstream, tcp.label(), "{strategy:?}");
        let status = engine.status();
        assert_eq!(status.upstreams[1].ok, 1, "{strategy:?}");
        if strategy == ForwardingStrategy::Sequential {
            assert_eq!(status.upstreams[0].failed, 1);
            assert_eq!(status.upstreams[0].name, "Tot");
        }
    }
    assert!(up.tcp_hits.load(Ordering::SeqCst) >= 3);
}
