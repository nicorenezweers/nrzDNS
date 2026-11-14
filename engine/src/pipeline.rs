//! Der Weg einer Anfrage: Rate-Limit → Zonen → Sperren → lokale Antworten → Cache →
//! Weiterleitung. Dazu der DNS-Client der Oberfläche.

use crate::cache::{self, CacheKey, CacheLookup, Cached, Limits};
use crate::wire::{
    self, name_str, parse_name, parse_qtype, qtype_str, rcode_str, record_view, reverse_name,
    summarize, EDNS_PAYLOAD, UDP_MAX,
};
use crate::zones::{Lookup, ZoneSet};
use crate::{now_ms, now_unix, read, Engine, EngineError};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use nrzdns_types::{
    BlockMode, DnsSettings, ForwardingStrategy, Protocol, QueryLogEntry, ResolveInput,
    ResolveResult, ResponseKind, Upstream, UpstreamProtocol, ZoneKind,
};
use rand::seq::SliceRandom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

/// Firefox fragt das, um DoH abzuschalten, wenn das Netz filtert.
const FIREFOX_CANARY: &str = "use-application-dns.net";
/// Höchstens so viele CNAME-Schritte in eigenen Zonen.
const MAX_CNAME_CHAIN: usize = 12;
/// TTL lokaler Antworten (`localhost` …).
const LOCAL_TTL: u32 = 3600;
/// TTL der Antworten für Namen des Reverse Proxys.
const PROXY_TTL: u32 = 60;

/// Die Frage einer Anfrage.
#[derive(Clone, Debug)]
pub(crate) struct QueryCtx {
    /// Wie gefragt (Gross-/Kleinschreibung bleibt).
    pub name: Name,
    /// Klein, ohne Punkt am Ende.
    pub lname: String,
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub dnssec_ok: bool,
    pub checking_disabled: bool,
    /// Fragender Client (für Antworten mit Adressen dieses Geräts); `None` beim DNS-Client.
    pub client: Option<IpAddr>,
}

/// Ergebnis der Pipeline, bevor es zur Nachricht wird.
#[derive(Debug)]
pub(crate) struct Answer {
    pub rcode: ResponseCode,
    pub aa: bool,
    pub ad: bool,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
    pub kind: ResponseKind,
    /// [`Upstream::label`] des antwortenden Servers.
    pub upstream: String,
}

impl Answer {
    fn new(kind: ResponseKind, rcode: ResponseCode) -> Answer {
        Answer {
            rcode,
            aa: false,
            ad: false,
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            kind,
            upstream: String::new(),
        }
    }

    fn records(kind: ResponseKind, answers: Vec<Record>) -> Answer {
        Answer {
            answers,
            ..Answer::new(kind, ResponseCode::NoError)
        }
    }

    fn from_cached(c: Cached) -> Answer {
        Answer {
            rcode: c.rcode,
            aa: false,
            ad: c.ad,
            answers: c.answers,
            authority: c.authority,
            additional: c.additional,
            kind: ResponseKind::Cached,
            upstream: String::new(),
        }
    }

    fn from_message(msg: Message, label: String) -> Answer {
        let rcode = msg.metadata.response_code;
        Answer {
            rcode,
            aa: false,
            ad: msg.metadata.authentic_data,
            answers: msg.answers,
            authority: msg.authorities,
            additional: msg.additionals,
            kind: if rcode == ResponseCode::ServFail {
                ResponseKind::Failed
            } else {
                ResponseKind::Forwarded
            },
            upstream: label,
        }
    }
}

// ------------------------------------------------------------------ Einstieg

pub(crate) async fn handle(
    engine: &Engine,
    request: &[u8],
    client: IpAddr,
    protocol: Protocol,
) -> Option<Vec<u8>> {
    let started = Instant::now();
    let at_ms = now_ms();
    let inner = &engine.inner;
    inner.queries.count(started);
    let client = client.to_canonical();

    let req = match Message::from_vec(request) {
        Ok(m) => m,
        Err(_) => return wire::formerr(request),
    };
    if req.metadata.message_type != MessageType::Query {
        return None;
    }
    let settings = engine.settings_arc();

    if !inner
        .limiter
        .allow(client, settings.rate_limit_qps, started)
    {
        if let Some(ctx) = req.queries.first().map(|q| ctx_for(q, &req, Some(client))) {
            let dropped = Answer::new(ResponseKind::Dropped, ResponseCode::NoError);
            log(
                engine, &settings, at_ms, started, client, protocol, &ctx, &dropped, true,
            );
        }
        return None;
    }

    let (resp, outcome) = process(engine, &req, &settings, Some(client)).await;
    // UDP: so gross, wie der Client per EDNS annimmt (ohne OPT 512), sonst TC-Bit
    let max = match protocol {
        Protocol::Udp => req
            .edns
            .as_ref()
            .map_or(512, |e| (e.max_payload() as usize).clamp(512, UDP_MAX)),
        Protocol::Tcp | Protocol::Https => u16::MAX as usize,
    };
    let bytes = wire::encode(&resp, max)?;
    if let Some((ctx, answer)) = outcome {
        log(
            engine, &settings, at_ms, started, client, protocol, &ctx, &answer, false,
        );
    }
    Some(bytes)
}

fn ctx_for(q: &Query, req: &Message, client: Option<IpAddr>) -> QueryCtx {
    QueryCtx {
        name: q.name.clone(),
        lname: name_str(&q.name),
        qtype: q.query_type,
        qclass: q.query_class,
        dnssec_ok: req.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok),
        checking_disabled: req.metadata.checking_disabled,
        client,
    }
}

/// Anfrage → Antwortnachricht (plus Frage und Ergebnis fürs Protokoll).
async fn process(
    engine: &Engine,
    req: &Message,
    settings: &Arc<DnsSettings>,
    client: Option<IpAddr>,
) -> (Message, Option<(QueryCtx, Answer)>) {
    let mut resp = Message::new(req.metadata.id, MessageType::Response, req.metadata.op_code);
    resp.metadata.recursion_desired = req.metadata.recursion_desired;
    resp.metadata.checking_disabled = req.metadata.checking_disabled;
    resp.metadata.recursion_available = true;
    resp.queries = req.queries.clone();
    if let Some(client_edns) = &req.edns {
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_PAYLOAD);
        edns.set_dnssec_ok(client_edns.flags().dnssec_ok);
        resp.set_edns(edns);
    }

    let ctx = req.queries.first().map(|q| ctx_for(q, req, client));
    let refuse = |rcode| Answer::new(ResponseKind::Dropped, rcode);
    let answer = match &ctx {
        _ if req.metadata.op_code != OpCode::Query => refuse(ResponseCode::NotImp),
        _ if req.edns.as_ref().is_some_and(|e| e.version() > 0) => refuse(ResponseCode::BADVERS),
        _ if req.queries.len() != 1 => refuse(ResponseCode::FormErr),
        None => refuse(ResponseCode::FormErr),
        Some(q) if q.qclass != DNSClass::IN => refuse(ResponseCode::Refused),
        Some(q)
            if matches!(
                q.qtype,
                RecordType::AXFR | RecordType::IXFR | RecordType::OPT
            ) =>
        {
            refuse(ResponseCode::Refused)
        }
        Some(q) => resolve_query(engine, q, settings).await,
    };

    resp.metadata.response_code = answer.rcode;
    resp.metadata.authoritative = answer.aa;
    let dnssec_ok = ctx.as_ref().is_some_and(|q| q.dnssec_ok);
    resp.metadata.authentic_data = answer.ad && (dnssec_ok || req.metadata.authentic_data);
    let qtype = ctx.as_ref().map(|q| q.qtype);
    // Ohne DO-Bit keine DNSSEC-Einträge, ausser sie wurden gefragt (RFC 4035 3.2.1)
    let keep =
        |r: &&Record| dnssec_ok || Some(r.record_type()) == qtype || !r.record_type().is_dnssec();
    resp.answers = answer.answers.iter().filter(keep).cloned().collect();
    resp.authorities = answer.authority.iter().filter(keep).cloned().collect();
    resp.additionals = answer.additional.iter().filter(keep).cloned().collect();
    (resp, ctx.map(|c| (c, answer)))
}

#[allow(clippy::too_many_arguments)]
fn log(
    engine: &Engine,
    settings: &DnsSettings,
    at_ms: i64,
    started: Instant,
    client: IpAddr,
    protocol: Protocol,
    ctx: &QueryCtx,
    answer: &Answer,
    dropped: bool,
) {
    if !settings.log_queries {
        return;
    }
    let (rcode, summary) = if dropped {
        (String::new(), "verworfen (Rate-Limit)".to_string())
    } else {
        let mut s = summarize(answer.rcode, &answer.answers);
        if answer.kind == ResponseKind::Blocked {
            s.push_str(" (gesperrt)");
        }
        (rcode_str(answer.rcode), s)
    };
    let entry = QueryLogEntry {
        id: 0,
        at_ms,
        client: client.to_string(),
        protocol,
        qname: ctx.lname.clone(),
        qtype: qtype_str(ctx.qtype),
        rcode,
        kind: answer.kind,
        answer: summary,
        duration_ms: u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX),
        upstream: answer.upstream.clone(),
    };
    // Nie warten: ist der Kanal voll, geht der Eintrag verloren
    let _ = engine.inner.log.try_send(entry);
}

// ------------------------------------------------------------------ Pipeline

/// Schritte 2–6 für eine Frage.
pub(crate) async fn resolve_query(engine: &Engine, q: &QueryCtx, s: &Arc<DnsSettings>) -> Answer {
    if let Some(answer) = local_host_answer(engine, q, s) {
        return answer;
    }
    let zones = engine.zones();
    let mut zone_forwarders = None;
    let mut in_zone = false;
    if let Some(zone) = zones.find(&q.lname) {
        in_zone = true;
        match zone.kind {
            ZoneKind::Primary => return zone_chain(engine, &zones, q, s).await,
            ZoneKind::Forwarder => {
                if zone.lookup_own(&q.lname, &q.name, q.qtype).is_some() {
                    return zone_chain(engine, &zones, q, s).await;
                }
                zone_forwarders = Some(zone.forwarders.clone()).filter(|f| !f.is_empty());
            }
        }
    }
    after_zones(engine, q, s, zone_forwarders, in_zone).await
}

/// Antwort aus eigenen Zonen, CNAME-Ketten auch über Zonen hinweg; verlässt die Kette die
/// eigenen Zonen, wird der Rest normal aufgelöst.
async fn zone_chain(
    engine: &Engine,
    zones: &ZoneSet,
    q: &QueryCtx,
    s: &Arc<DnsSettings>,
) -> Answer {
    let mut answers: Vec<Record> = Vec::new();
    let mut lname = q.lname.clone();
    let mut name = q.name.clone();
    let mut first_aa: Option<bool> = None;
    let mut seen: Vec<String> = Vec::new();

    for _ in 0..MAX_CNAME_CHAIN {
        let zone = zones.find(&lname).cloned();
        let lookup = zone.as_ref().and_then(|z| match z.kind {
            ZoneKind::Primary => Some(z.lookup(&lname, &name, q.qtype)),
            ZoneKind::Forwarder => z.lookup_own(&lname, &name, q.qtype),
        });
        let aa =
            *first_aa.get_or_insert(zone.as_ref().is_some_and(|z| z.kind == ZoneKind::Primary));
        let (Some(zone), Some(lookup)) = (zone.clone(), lookup) else {
            // Ziel ausserhalb eigener Zonen (oder Weiterleitungszone ohne eigenen Eintrag)
            let forwarders = zone
                .as_ref()
                .filter(|z| z.kind == ZoneKind::Forwarder)
                .map(|z| z.forwarders.clone())
                .filter(|f| !f.is_empty());
            let sub = QueryCtx {
                name: name.clone(),
                lname: lname.clone(),
                ..q.clone()
            };
            let ext = after_zones(engine, &sub, s, forwarders, zone.is_some()).await;
            answers.extend(ext.answers);
            return Answer {
                rcode: ext.rcode,
                aa: false,
                ad: false,
                answers,
                authority: ext.authority,
                additional: ext.additional,
                kind: if ext.kind == ResponseKind::Blocked {
                    ResponseKind::Blocked
                } else {
                    ResponseKind::Authoritative
                },
                upstream: ext.upstream,
            };
        };
        let base = |rcode| Answer {
            aa,
            ..Answer::new(ResponseKind::Authoritative, rcode)
        };
        match lookup {
            Lookup::Records {
                answers: found,
                additional,
            } => {
                answers.extend(found);
                return Answer {
                    answers,
                    additional,
                    ..base(ResponseCode::NoError)
                };
            }
            Lookup::Cname(record, target) => {
                answers.push(*record);
                if seen.contains(&target) || target == q.lname {
                    // Schleife: liefern, was da ist
                    return Answer {
                        answers,
                        ..base(ResponseCode::ServFail)
                    };
                }
                let Some(next) = parse_name(&target) else {
                    return Answer {
                        answers,
                        ..base(ResponseCode::NoError)
                    };
                };
                seen.push(target.clone());
                lname = target;
                name = next;
            }
            Lookup::NoData => {
                return Answer {
                    answers,
                    authority: vec![zone.negative_soa()],
                    ..base(ResponseCode::NoError)
                }
            }
            Lookup::NxDomain => {
                return Answer {
                    answers,
                    authority: vec![zone.negative_soa()],
                    ..base(ResponseCode::NXDomain)
                }
            }
            Lookup::Referral { ns, glue } => {
                return Answer {
                    aa: false,
                    answers,
                    authority: ns,
                    additional: glue,
                    ..base(ResponseCode::NoError)
                }
            }
        }
    }
    Answer {
        answers,
        ..Answer::new(ResponseKind::Authoritative, ResponseCode::ServFail)
    }
}

/// Namen des Reverse Proxys: A/AAAA mit der passendsten Adresse dieses Geräts, andere
/// Typen leer (der Name gehört nrzNetwork).
fn local_host_answer(engine: &Engine, q: &QueryCtx, s: &DnsSettings) -> Option<Answer> {
    let hosts = engine.local_hosts();
    let candidates = hosts.candidates(&q.lname)?;
    let ttl = PROXY_TTL;
    let rdata = match q.qtype {
        RecordType::A => crate::local::pick(candidates, q.client, true).map(|ip| match ip {
            IpAddr::V4(a) => RData::A(rdata::A(a)),
            IpAddr::V6(a) => RData::AAAA(rdata::AAAA(a)),
        }),
        RecordType::AAAA => crate::local::pick(candidates, q.client, false).map(|ip| match ip {
            IpAddr::V4(a) => RData::A(rdata::A(a)),
            IpAddr::V6(a) => RData::AAAA(rdata::AAAA(a)),
        }),
        _ => None,
    };
    let mut answer = match rdata {
        Some(rd) => Answer::records(
            ResponseKind::Authoritative,
            vec![Record::from_rdata(q.name.clone(), ttl, rd)],
        ),
        None => Answer {
            authority: vec![synthetic_soa(&q.lname, s, ttl)],
            ..Answer::new(ResponseKind::Authoritative, ResponseCode::NoError)
        },
    };
    answer.aa = true;
    Some(answer)
}

/// Schritte 3–6: Sperren, lokale Antworten, Cache, Weiterleitung.
async fn after_zones(
    engine: &Engine,
    q: &QueryCtx,
    s: &Arc<DnsSettings>,
    forwarders: Option<Vec<Upstream>>,
    in_zone: bool,
) -> Answer {
    if let Some(blocked) = block_answer(engine, q, s) {
        return blocked;
    }
    if let Some(local) = local_answer(q, s, in_zone) {
        return local;
    }
    cache_or_forward(engine, q, s, forwarders).await
}

// ------------------------------------------------------------------ Sperren

fn blocking_active(engine: &Engine, s: &DnsSettings) -> bool {
    s.blocking_enabled
        && read(&engine.inner.blocking)
            .paused_until(now_unix())
            .is_none()
}

fn block_answer(engine: &Engine, q: &QueryCtx, s: &DnsSettings) -> Option<Answer> {
    if !blocking_active(engine, s) {
        return None;
    }
    let hit = {
        let data = read(&engine.inner.blocking);
        if q.lname == FIREFOX_CANARY && !data.is_allowed(&q.lname) {
            return Some(Answer::new(ResponseKind::Blocked, ResponseCode::NXDomain));
        }
        data.blocked_by(&q.lname)?.to_string()
    };
    Some(blocked_answer(engine, q, s, &hit))
}

/// Gesperrte Domain hinter einem CNAME einer weitergeleiteten Antwort (CNAME-Tarnung).
fn cname_block_check(engine: &Engine, q: &QueryCtx, s: &DnsSettings, answer: Answer) -> Answer {
    if answer.answers.is_empty() || !blocking_active(engine, s) {
        return answer;
    }
    let hit = {
        let data = read(&engine.inner.blocking);
        answer.answers.iter().find_map(|r| match &r.data {
            RData::CNAME(c) => data.blocked_by(&name_str(&c.0)).map(str::to_string),
            _ => None,
        })
    };
    match hit {
        Some(hit) => blocked_answer(engine, q, s, &hit),
        None => answer,
    }
}

fn blocked_answer(engine: &Engine, q: &QueryCtx, s: &DnsSettings, matched: &str) -> Answer {
    let ttl = s.block_ttl;
    let soa = synthetic_soa(matched, s, ttl);
    let mut answer = match s.block_mode {
        BlockMode::Refused => Answer::new(ResponseKind::Blocked, ResponseCode::Refused),
        BlockMode::NxDomain => Answer {
            authority: vec![soa],
            ..Answer::new(ResponseKind::Blocked, ResponseCode::NXDomain)
        },
        BlockMode::BlockPage => {
            let device = engine.device_addresses();
            let ip = crate::local::pick(&device, q.client, q.qtype == RecordType::A);
            let rdata = match (q.qtype, ip) {
                (RecordType::A, Some(IpAddr::V4(a))) => Some(RData::A(rdata::A(a))),
                (RecordType::A, _) => Some(RData::A(rdata::A(Ipv4Addr::UNSPECIFIED))),
                (RecordType::AAAA, Some(IpAddr::V6(a))) => Some(RData::AAAA(rdata::AAAA(a))),
                (RecordType::AAAA, _) => Some(RData::AAAA(rdata::AAAA(Ipv6Addr::UNSPECIFIED))),
                _ => None,
            };
            match rdata {
                Some(rd) => Answer::records(
                    ResponseKind::Blocked,
                    vec![Record::from_rdata(q.name.clone(), ttl, rd)],
                ),
                None => Answer {
                    authority: vec![soa],
                    ..Answer::new(ResponseKind::Blocked, ResponseCode::NoError)
                },
            }
        }
        BlockMode::NullAddress | BlockMode::CustomAddress => {
            let custom = s.block_mode == BlockMode::CustomAddress;
            let rdata = match q.qtype {
                RecordType::A => Some(RData::A(rdata::A(if custom {
                    s.block_ipv4.trim().parse().unwrap_or(Ipv4Addr::UNSPECIFIED)
                } else {
                    Ipv4Addr::UNSPECIFIED
                }))),
                RecordType::AAAA => Some(RData::AAAA(rdata::AAAA(if custom {
                    s.block_ipv6.trim().parse().unwrap_or(Ipv6Addr::UNSPECIFIED)
                } else {
                    Ipv6Addr::UNSPECIFIED
                }))),
                _ => None,
            };
            match rdata {
                Some(rd) => Answer::records(
                    ResponseKind::Blocked,
                    vec![Record::from_rdata(q.name.clone(), ttl, rd)],
                ),
                None => Answer {
                    authority: vec![soa],
                    ..Answer::new(ResponseKind::Blocked, ResponseCode::NoError)
                },
            }
        }
    };
    answer.kind = ResponseKind::Blocked;
    answer
}

/// SOA für selbst erzeugte negative Antworten (steuert, wie lange Clients sie behalten).
fn synthetic_soa(owner: &str, s: &DnsSettings, ttl: u32) -> Record {
    let owner = parse_name(owner).unwrap_or_else(Name::root);
    let mname = parse_name(&s.server_domain)
        .filter(|n| !n.is_root())
        .unwrap_or_else(|| owner.clone());
    let rname = parse_name(&format!(
        "hostmaster.{}",
        s.server_domain.trim_end_matches('.')
    ))
    .unwrap_or_else(|| mname.clone());
    Record::from_rdata(
        owner,
        ttl,
        RData::SOA(rdata::SOA::new(mname, rname, 1, 3600, 600, 86_400, ttl)),
    )
}

// ------------------------------------------------------------------ Lokal

fn local_answer(q: &QueryCtx, s: &DnsSettings, in_zone: bool) -> Option<Answer> {
    let l = q.lname.as_str();
    if l == "localhost" || l.ends_with(".localhost") {
        let rdata = match q.qtype {
            RecordType::A => Some(RData::A(rdata::A(Ipv4Addr::LOCALHOST))),
            RecordType::AAAA => Some(RData::AAAA(rdata::AAAA(Ipv6Addr::LOCALHOST))),
            _ => None,
        };
        let answers = rdata
            .map(|rd| vec![Record::from_rdata(q.name.clone(), LOCAL_TTL, rd)])
            .unwrap_or_default();
        return Some(Answer::records(ResponseKind::Local, answers));
    }
    if !in_zone {
        let loopback_ptr =
            l == "1.0.0.127.in-addr.arpa" || l == reverse_name(IpAddr::V6(Ipv6Addr::LOCALHOST));
        if loopback_ptr && q.qtype == RecordType::PTR {
            let target = Name::from_ascii("localhost.").unwrap_or_else(|_| Name::root());
            return Some(Answer::records(
                ResponseKind::Local,
                vec![Record::from_rdata(
                    q.name.clone(),
                    LOCAL_TTL,
                    RData::PTR(rdata::PTR(target)),
                )],
            ));
        }
        if s.local_ptr_no_forward && is_private_reverse(l) {
            return Some(Answer::new(ResponseKind::Local, ResponseCode::NXDomain));
        }
    }
    if q.qtype == RecordType::AAAA && s.disable_ipv6_answers {
        return Some(Answer::new(ResponseKind::Local, ResponseCode::NoError));
    }
    None
}

/// Liegt der Name in einem Rückwärtsbereich privater Netze (RFC 1918, 6598, 3927, 4193,
/// Loopback, Link-Local)?
pub(crate) fn is_private_reverse(name: &str) -> bool {
    if let Some(rest) = name.strip_suffix(".in-addr.arpa") {
        let octets: Option<Vec<u8>> = rest
            .split('.')
            .rev()
            .map(|o| o.parse::<u8>().ok())
            .collect();
        let Some(o) = octets else { return false };
        return match o.as_slice() {
            [10, ..] | [127, ..] => true,
            [192, 168, ..] | [169, 254, ..] => true,
            [172, b, ..] => (16..=31).contains(b),
            [100, b, ..] => (64..=127).contains(b),
            _ => false,
        };
    }
    if let Some(rest) = name.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = rest.split('.').rev().collect();
        if nibbles
            .iter()
            .any(|n| n.len() != 1 || !n.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return false;
        }
        return match nibbles.as_slice() {
            ["f", "c" | "d", ..] => true,
            ["f", "e", "8" | "9" | "a" | "b", ..] => true,
            n if n.len() == 32 => n[..31].iter().all(|x| *x == "0") && n[31] == "1",
            _ => false,
        };
    }
    false
}

// ------------------------------------------------------------------ Cache und Weiterleitung

async fn cache_or_forward(
    engine: &Engine,
    q: &QueryCtx,
    s: &Arc<DnsSettings>,
    forwarders: Option<Vec<Upstream>>,
) -> Answer {
    let inner = &engine.inner;
    let limits = Limits::from_settings(s);
    let key = cache::key_for(&q.name, q.qtype, u16::from(q.qclass));
    let mut stale = None;
    if s.cache_enabled {
        match inner.cache.get(&key, q.dnssec_ok, &limits, Instant::now()) {
            CacheLookup::Fresh(cached, prefetch) => {
                if prefetch {
                    spawn_prefetch(engine.clone(), q.clone(), s.clone(), forwarders, key);
                }
                return cname_block_check(engine, q, s, Answer::from_cached(cached));
            }
            CacheLookup::Stale(cached) => stale = Some(cached),
            CacheLookup::Miss => {}
        }
    }

    let upstreams = forwarders.unwrap_or_else(|| s.forwarders.clone());
    match forward(engine, q, &upstreams, s).await {
        Forwarded::Good(msg, label) => {
            if s.cache_enabled {
                store(engine, key, &msg, q.dnssec_ok, &limits);
            }
            cname_block_check(engine, q, s, Answer::from_message(msg, label))
        }
        other => {
            if let Some(cached) = stale {
                inner.cache.touch(&key, Instant::now());
                return cname_block_check(engine, q, s, Answer::from_cached(cached));
            }
            match other {
                Forwarded::Soft(msg, label) => Answer::from_message(msg, label),
                _ => Answer::new(ResponseKind::Failed, ResponseCode::ServFail),
            }
        }
    }
}

fn store(engine: &Engine, key: CacheKey, msg: &Message, dnssec: bool, limits: &Limits) {
    engine.inner.cache.insert(
        key,
        msg.metadata.response_code,
        msg.metadata.authentic_data,
        dnssec,
        msg.answers.clone(),
        msg.authorities.clone(),
        msg.additionals.clone(),
        limits,
        Instant::now(),
    );
}

fn spawn_prefetch(
    engine: Engine,
    q: QueryCtx,
    s: Arc<DnsSettings>,
    forwarders: Option<Vec<Upstream>>,
    key: CacheKey,
) {
    tokio::spawn(async move {
        let upstreams = forwarders.unwrap_or_else(|| s.forwarders.clone());
        match forward(&engine, &q, &upstreams, &s).await {
            Forwarded::Good(msg, _) => {
                store(&engine, key, &msg, q.dnssec_ok, &Limits::from_settings(&s))
            }
            _ => engine.inner.cache.prefetch_done(&key),
        }
    });
}

enum Forwarded {
    /// NOERROR, NXDOMAIN, YXDOMAIN.
    Good(Message, String),
    /// Antwort, aber SERVFAIL/REFUSED/… (der Nächste wurde schon versucht).
    Soft(Message, String),
    Failed,
}

fn is_good(msg: &Message) -> bool {
    matches!(
        msg.metadata.response_code,
        ResponseCode::NoError | ResponseCode::NXDomain | ResponseCode::YXDomain
    )
}

/// Anfrage an einen vorgelagerten Server: neue Zufalls-ID, EDNS mit DO-Bit wie beim Client.
fn upstream_query(q: &QueryCtx) -> Message {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.metadata.checking_disabled = q.checking_disabled;
    let mut query = Query::query(q.name.to_lowercase(), q.qtype);
    query.set_query_class(q.qclass);
    msg.add_query(query);
    let mut edns = Edns::new();
    edns.set_max_payload(EDNS_PAYLOAD);
    edns.set_dnssec_ok(q.dnssec_ok);
    msg.set_edns(edns);
    msg
}

fn upstream_timeout(s: &DnsSettings) -> Duration {
    Duration::from_millis(s.upstream_timeout_ms.clamp(200, 15_000) as u64)
}

async fn forward(
    engine: &Engine,
    q: &QueryCtx,
    upstreams: &[Upstream],
    s: &DnsSettings,
) -> Forwarded {
    if upstreams.is_empty() {
        return Forwarded::Failed;
    }
    let timeout = upstream_timeout(s);
    let query = upstream_query(q);
    let mut soft: Option<(Message, String)> = None;
    match s.forwarding_strategy {
        ForwardingStrategy::Sequential | ForwardingStrategy::Random => {
            let mut order: Vec<&Upstream> = upstreams.iter().collect();
            if s.forwarding_strategy == ForwardingStrategy::Random {
                order.shuffle(&mut rand::thread_rng());
            }
            for u in order {
                if let Ok(msg) = ask(engine, u, &query, timeout).await {
                    if is_good(&msg) {
                        return Forwarded::Good(msg, u.label());
                    }
                    soft = Some((msg, u.label()));
                }
            }
        }
        ForwardingStrategy::Parallel => {
            let mut set = JoinSet::new();
            for u in upstreams {
                let u = u.clone();
                let engine = engine.clone();
                let query = query.clone();
                set.spawn(async move {
                    let r = ask(&engine, &u, &query, timeout).await;
                    (u.label(), r)
                });
            }
            while let Some(done) = set.join_next().await {
                if let Ok((label, Ok(msg))) = done {
                    if is_good(&msg) {
                        return Forwarded::Good(msg, label);
                    }
                    soft = Some((msg, label));
                }
            }
        }
    }
    match soft {
        Some((msg, label)) => Forwarded::Soft(msg, label),
        None => Forwarded::Failed,
    }
}

/// Einen Server fragen und seinen Zustand mitschreiben.
async fn ask(
    engine: &Engine,
    u: &Upstream,
    query: &Message,
    timeout: Duration,
) -> Result<Message, EngineError> {
    let mut query = query.clone();
    query.metadata.id = rand::random();
    let label = u.label();
    let started = Instant::now();
    let result = engine.inner.clients.exchange(u, &query, timeout).await;
    let health = &engine.inner.health;
    match &result {
        Ok(msg) if is_good(msg) => health.ok(&label, started.elapsed().as_secs_f64() * 1000.0),
        Ok(msg) => health.failed(
            &label,
            &format!("Antwort {}", rcode_str(msg.metadata.response_code)),
            now_unix(),
        ),
        Err(e) => {
            tracing::debug!(upstream = %label, error = %e, "Weiterleitung fehlgeschlagen");
            health.failed(&label, &e.to_string(), now_unix());
        }
    }
    result
}

// ------------------------------------------------------------------ DNS-Client

pub(crate) async fn resolve(
    engine: &Engine,
    input: &ResolveInput,
) -> Result<ResolveResult, EngineError> {
    let raw = input.name.trim();
    if raw.is_empty() {
        return Err(EngineError::Invalid("Bitte einen Namen eingeben".into()));
    }
    let qtype = if input.qtype.trim().is_empty() {
        RecordType::A
    } else {
        parse_qtype(&input.qtype).ok_or_else(|| {
            EngineError::Invalid(format!("Unbekannter Typ „{}“", input.qtype.trim()))
        })?
    };
    if matches!(qtype, RecordType::OPT | RecordType::AXFR | RecordType::IXFR) {
        return Err(EngineError::Invalid(format!(
            "Typ {} wird nicht unterstützt",
            qtype_str(qtype)
        )));
    }
    let text = match raw.parse::<IpAddr>() {
        Ok(ip) if qtype == RecordType::PTR => reverse_name(ip),
        _ => raw.trim_end_matches('.').to_string(),
    };
    let name = if text.is_empty() {
        Some(Name::root())
    } else {
        Name::from_ascii(format!("{text}."))
            .or_else(|_| Name::from_utf8(format!("{text}.")))
            .ok()
    }
    .ok_or_else(|| EngineError::Invalid(format!("Ungültiger Name „{raw}“")))?;

    let s = engine.settings_arc();
    let started = Instant::now();
    let server = input.server.trim();

    if server.is_empty() {
        let mut req = Message::new(rand::random(), MessageType::Query, OpCode::Query);
        req.metadata.recursion_desired = true;
        req.add_query(Query::query(name, qtype));
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_PAYLOAD);
        req.set_edns(edns);
        let (resp, outcome) = process(engine, &req, &s, None).await;
        return Ok(ResolveResult {
            server: "Dieser Server".into(),
            rcode: rcode_str(resp.metadata.response_code),
            flags: flags(&resp),
            answers: resp.answers.iter().map(record_view).collect(),
            authority: resp.authorities.iter().map(record_view).collect(),
            additional: resp.additionals.iter().map(record_view).collect(),
            duration_ms: elapsed_ms(started),
            kind: outcome.map(|(_, a)| a.kind),
        });
    }

    let address = if input.protocol == UpstreamProtocol::Https && !server.contains("://") {
        if server.contains('/') {
            format!("https://{server}")
        } else {
            format!("https://{server}/dns-query")
        }
    } else {
        server.to_string()
    };
    let upstream = Upstream::new(input.protocol, &address, "", "");
    let ctx = QueryCtx {
        lname: name_str(&name),
        name,
        qtype,
        qclass: DNSClass::IN,
        dnssec_ok: false,
        checking_disabled: false,
        client: None,
    };
    let mut query = upstream_query(&ctx);
    query.queries[0].name = ctx.name.clone();
    query.metadata.id = rand::random();
    let timeout = upstream_timeout(&s).max(Duration::from_secs(3));
    let resp = engine
        .inner
        .clients
        .exchange(&upstream, &query, timeout)
        .await
        .map_err(|e| match e {
            EngineError::Network(m) => EngineError::Network(format!("{}: {m}", upstream.label())),
            other => other,
        })?;
    Ok(ResolveResult {
        server: upstream.label(),
        rcode: rcode_str(resp.metadata.response_code),
        flags: flags(&resp),
        answers: resp.answers.iter().map(record_view).collect(),
        authority: resp.authorities.iter().map(record_view).collect(),
        additional: resp.additionals.iter().map(record_view).collect(),
        duration_ms: elapsed_ms(started),
        kind: None,
    })
}

fn elapsed_ms(started: Instant) -> u32 {
    u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX)
}

fn flags(msg: &Message) -> Vec<String> {
    let m = &msg.metadata;
    [
        ("qr", m.message_type == MessageType::Response),
        ("aa", m.authoritative),
        ("tc", m.truncation),
        ("rd", m.recursion_desired),
        ("ra", m.recursion_available),
        ("ad", m.authentic_data),
        ("cd", m.checking_disabled),
    ]
    .into_iter()
    .filter(|(_, on)| *on)
    .map(|(f, _)| f.to_string())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_reverse_ranges() {
        for n in [
            "1.1.168.192.in-addr.arpa",
            "168.192.in-addr.arpa",
            "5.0.0.10.in-addr.arpa",
            "10.in-addr.arpa",
            "1.0.20.172.in-addr.arpa",
            "1.0.0.127.in-addr.arpa",
            "4.3.254.169.in-addr.arpa",
            "1.0.64.100.in-addr.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa",
            "c.f.ip6.arpa",
            "0.8.e.f.ip6.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        ] {
            assert!(is_private_reverse(n), "{n}");
        }
        for n in [
            "8.8.8.8.in-addr.arpa",
            "1.0.32.172.in-addr.arpa",
            "172.in-addr.arpa",
            "in-addr.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            "example.com",
            "x.168.192.in-addr.arpa",
        ] {
            assert!(!is_private_reverse(n), "{n}");
        }
    }
}
