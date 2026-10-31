//! Hilfen rund um DNS-Nachrichten: Namen, Typen, Antwortcodes, Zonendatei-Schreibweise und
//! das Kodieren mit Grössengrenze.

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecoder, Restrict};
use nrzdns_types::{RecordData, RecordView};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Nutzlast, die wir per EDNS anbieten und bei vorgelagerten Servern erbitten (DNS Flag Day 2020).
pub(crate) const EDNS_PAYLOAD: u16 = 1232;

/// Grösste Antwort über UDP, egal was der Client anbietet.
pub(crate) const UDP_MAX: usize = 4096;

/// Name als Text: klein, ohne Punkt am Ende; die Wurzel ist `.`.
pub(crate) fn name_str(name: &Name) -> String {
    if name.is_root() {
        return ".".into();
    }
    let mut s = name.to_ascii();
    if s.ends_with('.') {
        s.pop();
    }
    s.make_ascii_lowercase();
    s
}

/// Name in Zonendatei-Schreibweise (voll qualifiziert, mit Punkt am Ende).
pub(crate) fn name_fqdn(name: &Name) -> String {
    let mut s = name.to_ascii();
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

/// Text → voll qualifizierter Name (`example.com` und `example.com.` sind gleich).
pub(crate) fn parse_name(s: &str) -> Option<Name> {
    let s = s.trim().trim_end_matches('.');
    if s.is_empty() {
        return Some(Name::root());
    }
    Name::from_ascii(format!("{s}.")).ok()
}

/// Typ als Text: `A`, `HTTPS`, unbekannte als `TYPE65534`.
pub(crate) fn qtype_str(t: RecordType) -> String {
    match t {
        RecordType::Unknown(n) => format!("TYPE{n}"),
        other => other.to_string(),
    }
}

/// `A`, `aaaa`, `TYPE65` … → Typ.
pub(crate) fn parse_qtype(s: &str) -> Option<RecordType> {
    let up = s.trim().to_ascii_uppercase();
    if let Some(n) = up.strip_prefix("TYPE") {
        if let Ok(n) = n.parse::<u16>() {
            return Some(RecordType::from(n));
        }
    }
    RecordType::from_str(&up).ok()
}

/// Antwortcode als Text: `NOERROR`, `NXDOMAIN`, `SERVFAIL` …
pub(crate) fn rcode_str(rc: ResponseCode) -> String {
    let s = match u16::from(rc) {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        16 => "BADVERS",
        23 => "BADCOOKIE",
        n => return format!("RCODE{n}"),
    };
    s.to_string()
}

/// Zeichenkette für Zonendateien in Anführungszeichen, mit `\"`, `\\` und `\DDD`.
pub(crate) fn quote(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                let _ = write!(out, "\\{:03}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Daten eines Eintrags in Zonendatei-Schreibweise (ohne Name, TTL und Typ).
pub(crate) fn rdata_text(data: &RData) -> String {
    match data {
        RData::A(a) => a.0.to_string(),
        RData::AAAA(a) => a.0.to_string(),
        RData::CNAME(n) => name_fqdn(&n.0),
        RData::NS(n) => name_fqdn(&n.0),
        RData::PTR(n) => name_fqdn(&n.0),
        RData::ANAME(n) => name_fqdn(&n.0),
        RData::MX(mx) => format!("{} {}", mx.preference, name_fqdn(&mx.exchange)),
        RData::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            name_fqdn(&srv.target)
        ),
        RData::SOA(soa) => format!(
            "{} {} {} {} {} {} {}",
            name_fqdn(&soa.mname),
            name_fqdn(&soa.rname),
            soa.serial,
            soa.refresh,
            soa.retry,
            soa.expire,
            soa.minimum
        ),
        RData::TXT(txt) => txt
            .txt_data
            .iter()
            .map(|s| quote(s))
            .collect::<Vec<_>>()
            .join(" "),
        RData::CAA(caa) => format!("{} {} {}", caa.flags(), caa.tag, quote(&caa.value)),
        RData::Unknown { rdata, .. } | RData::NULL(rdata) => generic_rdata(&rdata.anything),
        RData::OPT(_) | RData::Update0(_) => String::new(),
        // hickory hängt an Adresslisten ein Komma an (`ipv4hint=1.2.3.4,`)
        RData::HTTPS(_) | RData::SVCB(_) => {
            let mut s = String::new();
            let _ = write!(s, "{data}");
            s.split(' ')
                .map(|t| t.trim_end_matches(','))
                .collect::<Vec<_>>()
                .join(" ")
        }
        other => {
            let mut s = String::new();
            if write!(s, "{other}").is_err() {
                s.clear();
            }
            s
        }
    }
}

/// RFC 3597: `\# 4 0a000001`.
fn generic_rdata(bytes: &[u8]) -> String {
    let mut s = format!("\\# {}", bytes.len());
    if !bytes.is_empty() {
        s.push(' ');
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
    }
    s
}

/// Kurzform für das Abfrageprotokoll: Adressen und Namen ohne Punkt am Ende.
fn short_data(data: &RData) -> String {
    match data {
        RData::A(a) => a.0.to_string(),
        RData::AAAA(a) => a.0.to_string(),
        RData::CNAME(n) => name_str(&n.0),
        RData::NS(n) => name_str(&n.0),
        RData::PTR(n) => name_str(&n.0),
        RData::MX(mx) => format!("{} {}", mx.preference, name_str(&mx.exchange)),
        RData::TXT(txt) => txt
            .txt_data
            .iter()
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect::<String>(),
        other => rdata_text(other),
    }
}

/// Ein Eintrag für den DNS-Client der Oberfläche.
pub(crate) fn record_view(r: &Record) -> RecordView {
    RecordView {
        name: name_str(&r.name),
        qtype: qtype_str(r.record_type()),
        ttl: r.ttl,
        data: rdata_text(&r.data),
    }
}

/// `A 93.184.215.14` – für die Cache-Liste.
pub(crate) fn record_line(r: &Record) -> String {
    format!("{} {}", qtype_str(r.record_type()), rdata_text(&r.data))
}

/// Kurzfassung einer Antwort: `93.184.215.14, 93.184.215.15`, `CNAME a.example → 1.2.3.4`,
/// `NXDOMAIN`, `NODATA`.
pub(crate) fn summarize(rcode: ResponseCode, answers: &[Record]) -> String {
    if rcode != ResponseCode::NoError {
        return rcode_str(rcode);
    }
    let mut chain: Vec<String> = Vec::new();
    let mut data: Vec<String> = Vec::new();
    for r in answers {
        match &r.data {
            RData::CNAME(c) => chain.push(format!("CNAME {}", name_str(&c.0))),
            _ if r.record_type() == RecordType::RRSIG => {}
            other => data.push(short_data(other)),
        }
    }
    if chain.is_empty() && data.is_empty() {
        return "NODATA".into();
    }
    if !data.is_empty() {
        chain.push(data.join(", "));
    }
    let mut s = chain.join(" → ");
    if s.chars().count() > 300 {
        s = s.chars().take(299).collect();
        s.push('…');
    }
    s
}

/// Nachricht kodieren; ist sie grösser als `max`, nur Kopf, Frage und OPT mit TC-Bit.
pub(crate) fn encode(msg: &Message, max: usize) -> Option<Vec<u8>> {
    let bytes = msg.to_vec().ok()?;
    if bytes.len() <= max {
        return Some(bytes);
    }
    msg.truncate().to_vec().ok()
}

/// FORMERR nur aus dem Kopf einer unlesbaren Anfrage; `None`, wenn nicht einmal der Kopf da
/// ist oder es selbst eine Antwort ist.
pub(crate) fn formerr(request: &[u8]) -> Option<Vec<u8>> {
    if request.len() < 12 || request[2] & 0x80 != 0 {
        return None;
    }
    let opcode = (request[2] >> 3) & 0x0f;
    let rd = request[2] & 0x01;
    let mut out = vec![0u8; 12];
    out[0] = request[0];
    out[1] = request[1];
    out[2] = 0x80 | (opcode << 3) | rd;
    out[3] = 0x80 | 0x01;
    Some(out)
}

/// TXT-Text in Zeichenketten zu höchstens 255 Bytes teilen (an Zeichengrenzen).
pub(crate) fn split_txt(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    for c in text.chars() {
        if cur.len() + c.len_utf8() > 255 {
            parts.push(std::mem::take(&mut cur));
        }
        cur.push(c);
    }
    if !cur.is_empty() || parts.is_empty() {
        parts.push(cur);
    }
    parts
}

/// Eintrag aus den Daten einer Zone; `None` bei ungültigen Daten.
pub(crate) fn record_from_data(owner: Name, ttl: u32, data: &RecordData) -> Option<Record> {
    let name = |s: &str| parse_name(s).filter(|n| !n.is_root() || s.trim() == ".");
    let rdata = match data {
        RecordData::A { address } => RData::A(rdata::A(address.trim().parse::<Ipv4Addr>().ok()?)),
        RecordData::AAAA { address } => {
            RData::AAAA(rdata::AAAA(address.trim().parse::<Ipv6Addr>().ok()?))
        }
        RecordData::CNAME { target } => RData::CNAME(rdata::CNAME(name(target)?)),
        RecordData::NS { host } => RData::NS(rdata::NS(name(host)?)),
        RecordData::PTR { target } => RData::PTR(rdata::PTR(name(target)?)),
        RecordData::MX {
            preference,
            exchange,
        } => RData::MX(rdata::MX::new(*preference, name(exchange)?)),
        RecordData::TXT { text } => RData::TXT(rdata::TXT::new(split_txt(text))),
        RecordData::SRV {
            priority,
            weight,
            port,
            target,
        } => RData::SRV(rdata::SRV::new(*priority, *weight, *port, name(target)?)),
        RecordData::CAA { flags, tag, value } => caa(*flags, tag, value.as_bytes())?,
    };
    Some(Record::from_rdata(owner, ttl, rdata))
}

/// CAA über das Wire-Format bauen (die Struktur ist in hickory nicht direkt konstruierbar).
fn caa(flags: u8, tag: &str, value: &[u8]) -> Option<RData> {
    let tag = tag.trim();
    if tag.is_empty() || tag.len() > 255 || !tag.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let mut raw = Vec::with_capacity(2 + tag.len() + value.len());
    raw.push(flags);
    raw.push(tag.len() as u8);
    raw.extend_from_slice(tag.as_bytes());
    raw.extend_from_slice(value);
    let len = u16::try_from(raw.len()).ok()?;
    let mut decoder = BinDecoder::new(&raw);
    RData::read(&mut decoder, RecordType::CAA, Restrict::new(len)).ok()
}

/// IP-Adresse → Name für Rückwärtsanfragen (`4.3.2.1.in-addr.arpa`, `….ip6.arpa`).
pub(crate) fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(72);
            for b in v6.octets().iter().rev() {
                let _ = write!(s, "{:x}.{:x}.", b & 0x0f, b >> 4);
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

/// Alle Endungen eines Namens: `a.b.c` → `a.b.c`, `b.c`, `c`.
pub(crate) fn suffixes(name: &str) -> impl Iterator<Item = &str> {
    let mut rest = Some(name);
    std::iter::from_fn(move || {
        let cur = rest?;
        rest = cur
            .split_once('.')
            .map(|(_, r)| r)
            .filter(|r| !r.is_empty());
        Some(cur)
    })
}

/// Fehlerkette als ein Text (`Verbindung abgelehnt: …`), ohne „(os error N)“.
pub(crate) fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = cur {
        let text = strip_os_error(&err.to_string());
        if !parts.iter().any(|p| p.contains(&text)) {
            parts.push(text);
        }
        cur = err.source();
    }
    parts.join(": ")
}

/// „Address already in use (os error 48)“ → „Address already in use“.
pub(crate) fn strip_os_error(s: &str) -> String {
    match s.rfind(" (os error ") {
        Some(i) => s[..i].to_string(),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_types() {
        let n = parse_name("WWW.Example.COM.").unwrap();
        assert_eq!(name_str(&n), "www.example.com");
        assert_eq!(name_fqdn(&n), "WWW.Example.COM.");
        assert_eq!(name_str(&Name::root()), ".");
        assert_eq!(parse_qtype("aaaa"), Some(RecordType::AAAA));
        assert_eq!(parse_qtype("TYPE65534"), Some(RecordType::Unknown(65534)));
        assert_eq!(qtype_str(RecordType::Unknown(65534)), "TYPE65534");
        assert_eq!(qtype_str(RecordType::HTTPS), "HTTPS");
        assert_eq!(rcode_str(ResponseCode::NXDomain), "NXDOMAIN");
        assert!(parse_name("*.example.com").is_some());
        let s: Vec<&str> = suffixes("a.b.example.com").collect();
        assert_eq!(
            s,
            ["a.b.example.com", "b.example.com", "example.com", "com"]
        );
    }

    #[test]
    fn reverse_names() {
        assert_eq!(
            reverse_name("192.168.1.10".parse().unwrap()),
            "10.1.168.192.in-addr.arpa"
        );
        assert_eq!(
            reverse_name("2001:db8::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn records_and_text() {
        let owner = parse_name("example.com").unwrap();
        let caa = record_from_data(
            owner.clone(),
            300,
            &RecordData::CAA {
                flags: 0,
                tag: "issue".into(),
                value: "letsencrypt.org".into(),
            },
        )
        .unwrap();
        assert_eq!(record_line(&caa), "CAA 0 issue \"letsencrypt.org\"");
        let txt = record_from_data(
            owner.clone(),
            300,
            &RecordData::TXT {
                text: "a \"quoted\" text".into(),
            },
        )
        .unwrap();
        assert_eq!(rdata_text(&txt.data), r#""a \"quoted\" text""#);
        let mx = record_from_data(
            owner,
            300,
            &RecordData::MX {
                preference: 10,
                exchange: "mail.example.com".into(),
            },
        )
        .unwrap();
        assert_eq!(rdata_text(&mx.data), "10 mail.example.com.");
        assert_eq!(split_txt(&"x".repeat(600)).len(), 3);
        assert_eq!(split_txt("").len(), 1);
    }

    #[test]
    fn summaries() {
        let owner = parse_name("www.example.com").unwrap();
        let cname = Record::from_rdata(
            owner.clone(),
            60,
            RData::CNAME(rdata::CNAME(parse_name("a.example").unwrap())),
        );
        let a1 = Record::from_rdata(owner.clone(), 60, RData::A(rdata::A([1, 2, 3, 4].into())));
        let a2 = Record::from_rdata(owner, 60, RData::A(rdata::A([1, 2, 3, 5].into())));
        assert_eq!(
            summarize(ResponseCode::NoError, &[cname, a1.clone(), a2.clone()]),
            "CNAME a.example → 1.2.3.4, 1.2.3.5"
        );
        assert_eq!(
            summarize(ResponseCode::NoError, &[a1, a2]),
            "1.2.3.4, 1.2.3.5"
        );
        assert_eq!(summarize(ResponseCode::NXDomain, &[]), "NXDOMAIN");
        assert_eq!(summarize(ResponseCode::NoError, &[]), "NODATA");
    }

    #[test]
    fn formerr_from_header() {
        let mut req = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xff];
        let resp = formerr(&req).unwrap();
        assert_eq!(&resp[..4], &[0x12, 0x34, 0x81, 0x81]);
        req[2] |= 0x80;
        assert!(formerr(&req).is_none());
        assert!(formerr(&[1, 2, 3]).is_none());
    }
}
