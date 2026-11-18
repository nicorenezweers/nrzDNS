//! Zonendateien im BIND-Format (RFC 1035) schreiben und lesen.

use crate::wire::{quote, split_txt};
use crate::EngineError;
use hickory_proto::rr::RecordType as WireType;
use nrzdns_types::{RecordData, RecordInput, RecordType, Soa, ZoneDetail};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Ergebnis von [`parse`].
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedZone {
    /// Zonenname aus `$ORIGIN`/SOA bzw. der übergebene.
    pub origin: String,
    pub soa: Option<Soa>,
    /// Einträge mit Namen relativ zur Zone (`@`, `www`, `*.dev`). SOA nicht dabei.
    pub records: Vec<RecordInput>,
    /// Übersprungene Zeilen mit Grund (unbekannter Typ, ausserhalb der Zone …).
    pub skipped: Vec<String>,
}

// ------------------------------------------------------------------ Schreiben

/// Zone als Zonendatei: `$ORIGIN`, `$TTL`, SOA, dann alle aktiven Einträge.
pub fn export(zone: &ZoneDetail) -> String {
    let name = zone
        .zone
        .name
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let soa = &zone.zone.soa;
    let records: Vec<_> = zone.records.iter().filter(|r| !r.disabled).collect();

    // $TTL = häufigste TTL der Einträge (jede Zeile trägt ihre TTL trotzdem selbst)
    let mut counts: HashMap<u32, usize> = HashMap::new();
    for r in &records {
        *counts.entry(r.ttl).or_default() += 1;
    }
    let default_ttl = counts
        .into_iter()
        .max_by_key(|&(ttl, n)| (n, std::cmp::Reverse(ttl)))
        .map(|(ttl, _)| ttl)
        .unwrap_or(if soa.minimum > 0 { soa.minimum } else { 3600 });

    let primary = if soa.primary_ns.trim().is_empty() {
        format!("ns.{name}.")
    } else {
        absolute(&soa.primary_ns)
    };
    let responsible = if soa.responsible.trim().is_empty() {
        format!("hostmaster.{name}.")
    } else {
        absolute(&soa.responsible)
    };

    let mut rows: Vec<[String; 4]> = vec![[
        "@".into(),
        default_ttl.to_string(),
        "SOA".into(),
        format!(
            "{primary} {responsible} {} {} {} {} {}",
            soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum
        ),
    ]];
    for r in &records {
        rows.push([
            relative(&r.fqdn(&name), &name),
            r.ttl.to_string(),
            r.data.record_type().as_str().into(),
            data_text(&r.data),
        ]);
    }

    let w0 = rows.iter().map(|r| r[0].len()).max().unwrap_or(1);
    let w1 = rows.iter().map(|r| r[1].len()).max().unwrap_or(1);
    let w2 = rows.iter().map(|r| r[2].len()).max().unwrap_or(1);
    let mut out =
        format!("; Zone {name} - exportiert von nrzDNS\n$ORIGIN {name}.\n$TTL {default_ttl}\n");
    for [owner, ttl, kind, data] in rows {
        out.push_str(&format!(
            "{owner:<w0$}  {ttl:<w1$}  IN  {kind:<w2$}  {data}\n"
        ));
    }
    out
}

/// `host.example.com` → `host.example.com.`
fn absolute(name: &str) -> String {
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    format!("{n}.")
}

/// Voller Name → relativ zur Zone (`@`, `www`), sonst absolut mit Punkt.
fn relative(fqdn: &str, zone: &str) -> String {
    if fqdn == zone {
        "@".into()
    } else if let Some(rel) = fqdn.strip_suffix(zone).and_then(|r| r.strip_suffix('.')) {
        rel.to_string()
    } else {
        format!("{fqdn}.")
    }
}

/// Daten in Zonendatei-Schreibweise (TXT geteilt in Zeichenketten zu höchstens 255 Bytes).
fn data_text(data: &RecordData) -> String {
    match data {
        RecordData::A { address } | RecordData::AAAA { address } => address.trim().to_string(),
        RecordData::CNAME { target } | RecordData::PTR { target } => absolute(target),
        RecordData::NS { host } => absolute(host),
        RecordData::MX {
            preference,
            exchange,
        } => format!("{preference} {}", absolute(exchange)),
        RecordData::TXT { text } => split_txt(text)
            .iter()
            .map(|s| quote(s.as_bytes()))
            .collect::<Vec<_>>()
            .join(" "),
        RecordData::SRV {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {}", absolute(target)),
        RecordData::CAA { flags, tag, value } => {
            format!("{flags} {tag} {}", quote(value.as_bytes()))
        }
    }
}

// ------------------------------------------------------------------ Lesen

/// Ein Wort einer Zeile; `quoted` = stand in Anführungszeichen.
#[derive(Debug)]
struct Token {
    text: String,
    quoted: bool,
}

/// Eine logische Zeile (Klammern können mehrere physische Zeilen zusammenfassen).
#[derive(Debug)]
struct Line {
    no: usize,
    /// Beginnt mit Leerraum: Name wie in der Zeile davor.
    blank_start: bool,
    tokens: Vec<Token>,
}

fn lex(text: &str) -> (Vec<Line>, Vec<String>) {
    let mut lines = Vec::new();
    let mut errors = Vec::new();
    let mut tokens: Vec<Token> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut in_token = false;
    let mut depth = 0usize;
    let mut line_no = 1usize;
    let mut start_no = 1usize;
    let mut blank_start = false;
    let mut fresh = true;

    fn end_token(cur: &mut Vec<u8>, in_token: &mut bool, tokens: &mut Vec<Token>) {
        if *in_token {
            tokens.push(Token {
                text: String::from_utf8_lossy(cur).into_owned(),
                quoted: false,
            });
            cur.clear();
            *in_token = false;
        }
    }

    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if fresh && c != b'\n' && c != b'\r' {
            blank_start = c == b' ' || c == b'\t';
            start_no = line_no;
            fresh = false;
        }
        match c {
            b'\n' => {
                end_token(&mut cur, &mut in_token, &mut tokens);
                line_no += 1;
                if depth == 0 {
                    if !tokens.is_empty() {
                        lines.push(Line {
                            no: start_no,
                            blank_start,
                            tokens: std::mem::take(&mut tokens),
                        });
                    }
                    fresh = true;
                }
            }
            b';' => {
                end_token(&mut cur, &mut in_token, &mut tokens);
                while i + 1 < bytes.len() && bytes[i + 1] != b'\n' {
                    i += 1;
                }
            }
            b'"' => {
                end_token(&mut cur, &mut in_token, &mut tokens);
                let mut s: Vec<u8> = Vec::new();
                let mut closed = false;
                i += 1;
                while i < bytes.len() {
                    match bytes[i] {
                        b'"' => {
                            closed = true;
                            break;
                        }
                        b'\\' if i + 1 < bytes.len() => {
                            let (b, used) = unescape(&bytes[i + 1..]);
                            s.push(b);
                            i += used;
                        }
                        b'\n' => {
                            line_no += 1;
                            s.push(b'\n');
                        }
                        b => s.push(b),
                    }
                    i += 1;
                }
                if !closed {
                    errors.push(format!(
                        "Zeile {start_no}: Anführungszeichen nicht geschlossen"
                    ));
                }
                tokens.push(Token {
                    text: String::from_utf8_lossy(&s).into_owned(),
                    quoted: true,
                });
            }
            b'(' => {
                end_token(&mut cur, &mut in_token, &mut tokens);
                depth += 1;
            }
            b')' => {
                end_token(&mut cur, &mut in_token, &mut tokens);
                if depth == 0 {
                    errors.push(format!("Zeile {line_no}: „)“ ohne „(“"));
                } else {
                    depth -= 1;
                }
            }
            b' ' | b'\t' | b'\r' => end_token(&mut cur, &mut in_token, &mut tokens),
            b'\\' if i + 1 < bytes.len() => {
                let (b, used) = unescape(&bytes[i + 1..]);
                cur.push(b);
                in_token = true;
                i += used;
            }
            b => {
                cur.push(b);
                in_token = true;
            }
        }
        i += 1;
    }
    end_token(&mut cur, &mut in_token, &mut tokens);
    if depth > 0 {
        errors.push(format!("Zeile {start_no}: Klammer nicht geschlossen"));
    }
    if !tokens.is_empty() {
        lines.push(Line {
            no: start_no,
            blank_start,
            tokens,
        });
    }
    (lines, errors)
}

/// `\DDD` oder `\X` nach einem Backslash → (Byte, verbrauchte Zeichen).
fn unescape(rest: &[u8]) -> (u8, usize) {
    if rest.len() >= 3 && rest[..3].iter().all(u8::is_ascii_digit) {
        let v =
            (rest[0] - b'0') as u32 * 100 + (rest[1] - b'0') as u32 * 10 + (rest[2] - b'0') as u32;
        if let Ok(b) = u8::try_from(v) {
            return (b, 3);
        }
    }
    (rest[0], 1)
}

/// TTL: Sekunden oder BIND-Einheiten (`1h30m`, `2d`, `1w`).
fn parse_ttl(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    if let Ok(v) = s.parse::<u32>() {
        return Some(v);
    }
    let mut total: u64 = 0;
    let mut num: Option<u64> = None;
    for c in s.chars() {
        if let Some(d) = c.to_digit(10) {
            num = Some(num.unwrap_or(0) * 10 + d as u64);
            if num > Some(u32::MAX as u64) {
                return None;
            }
        } else {
            let factor = match c.to_ascii_lowercase() {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86_400,
                'w' => 604_800,
                _ => return None,
            };
            total += num.take()? * factor;
        }
    }
    if let Some(n) = num {
        total += n;
    }
    u32::try_from(total).ok()
}

fn is_class(s: &str) -> bool {
    ["IN", "CH", "CS", "HS"]
        .iter()
        .any(|c| c.eq_ignore_ascii_case(s))
}

/// Name einer Zeile → voller Name (klein, ohne Punkt am Ende).
fn resolve_name(token: &str, origin: Option<&str>, allow_wildcard: bool) -> Result<String, String> {
    let full = if token == "@" {
        origin
            .map(str::to_string)
            .ok_or_else(|| "„@“ ohne Zonenname".to_string())?
    } else if let Some(abs) = token.strip_suffix('.') {
        abs.to_ascii_lowercase()
    } else {
        let origin = origin.ok_or_else(|| format!("relativer Name „{token}“ ohne Zonenname"))?;
        format!("{}.{origin}", token.to_ascii_lowercase())
    };
    let valid = !full.is_empty()
        && full.len() <= 253
        && full.split('.').enumerate().all(|(i, label)| {
            !label.is_empty()
                && label.len() <= 63
                && ((allow_wildcard && i == 0 && label == "*")
                    || label.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'
                    }))
        });
    if valid {
        Ok(full)
    } else {
        Err(format!("ungültiger Name „{token}“"))
    }
}

/// Zonendatei lesen: `$ORIGIN`, `$TTL`, `@`, relative und absolute Namen, Klammern über
/// mehrere Zeilen, Kommentare, Zeilen ohne Namen (gleicher Name wie davor).
/// `origin` leer = aus der Datei; `default_ttl` gilt ohne `$TTL`/TTL in der Zeile.
pub fn parse(text: &str, origin: &str, default_ttl: u32) -> Result<ParsedZone, EngineError> {
    let (lines, mut skipped) = lex(text);

    // Zonenname: übergeben, sonst erstes $ORIGIN, sonst SOA mit absolutem Namen
    let mut zone: Option<String> = None;
    if !origin.trim().is_empty() {
        let z = origin.trim().trim_end_matches('.').to_ascii_lowercase();
        resolve_name(&format!("{z}."), None, false)
            .map_err(|_| EngineError::Invalid(format!("Ungültiger Zonenname „{origin}“")))?;
        zone = Some(z);
    } else {
        for line in &lines {
            let first = &line.tokens[0];
            if !line.blank_start && first.text.eq_ignore_ascii_case("$ORIGIN") {
                if let Some(name) = line.tokens.get(1).and_then(|t| t.text.strip_suffix('.')) {
                    zone = Some(name.to_ascii_lowercase());
                }
                break;
            }
            let is_soa = line
                .tokens
                .iter()
                .take(4)
                .any(|t| t.text.eq_ignore_ascii_case("SOA"));
            if is_soa && !line.blank_start && first.text.ends_with('.') {
                zone = Some(first.text.trim_end_matches('.').to_ascii_lowercase());
                break;
            }
        }
    }
    let Some(zone) = zone.filter(|z| !z.is_empty()) else {
        return Err(EngineError::Invalid(
            "Kein Zonenname gefunden – bitte angeben oder $ORIGIN in die Datei schreiben".into(),
        ));
    };

    let mut current_origin = zone.clone();
    let mut ttl_directive: Option<u32> = None;
    let mut last_owner: Option<String> = None;
    let mut soa: Option<Soa> = None;
    let mut records = Vec::new();

    for line in &lines {
        let no = line.no;
        let toks = &line.tokens;
        let first = &toks[0];

        if !line.blank_start && !first.quoted && first.text.starts_with('$') {
            let arg = toks.get(1).map(|t| t.text.as_str()).unwrap_or("");
            match first.text.to_ascii_uppercase().as_str() {
                "$ORIGIN" => match resolve_name(arg, Some(&current_origin), false) {
                    Ok(o) => current_origin = o,
                    Err(e) => skipped.push(format!("Zeile {no}: $ORIGIN: {e}")),
                },
                "$TTL" => match parse_ttl(arg) {
                    Some(t) => ttl_directive = Some(t),
                    None => skipped.push(format!("Zeile {no}: ungültige $TTL „{arg}“")),
                },
                other => skipped.push(format!("Zeile {no}: {other} wird nicht unterstützt")),
            }
            continue;
        }

        // Name
        let mut idx = 0;
        let owner = if line.blank_start {
            match &last_owner {
                Some(o) => o.clone(),
                None => {
                    skipped.push(format!("Zeile {no}: Name fehlt"));
                    continue;
                }
            }
        } else {
            idx = 1;
            match resolve_name(&first.text, Some(&current_origin), true) {
                Ok(o) => o,
                Err(e) => {
                    skipped.push(format!("Zeile {no}: {e}"));
                    continue;
                }
            }
        };
        last_owner = Some(owner.clone());

        // TTL und Klasse in beliebiger Reihenfolge
        let mut ttl = None;
        let mut class = None;
        for _ in 0..2 {
            let Some(t) = toks.get(idx).filter(|t| !t.quoted) else {
                break;
            };
            if class.is_none() && is_class(&t.text) {
                class = Some(t.text.to_ascii_uppercase());
            } else if ttl.is_none() {
                match parse_ttl(&t.text) {
                    Some(v) => ttl = Some(v),
                    None => break,
                }
            } else {
                break;
            }
            idx += 1;
        }

        let Some(type_tok) = toks.get(idx) else {
            skipped.push(format!("Zeile {no}: Typ fehlt"));
            continue;
        };
        idx += 1;
        let tname = type_tok.text.to_ascii_uppercase();
        let rdata = &toks[idx..];

        if let Some(c) = class.filter(|c| c != "IN") {
            skipped.push(format!("Zeile {no}: Klasse {c} wird nicht unterstützt"));
            continue;
        }

        if tname == "SOA" {
            if owner != zone {
                skipped.push(format!(
                    "Zeile {no}: SOA für {owner} gehört nicht zur Zone {zone}"
                ));
                continue;
            }
            match parse_soa(rdata, &current_origin) {
                Ok(s) => soa = Some(s),
                Err(e) => skipped.push(format!("Zeile {no}: SOA: {e}")),
            }
            continue;
        }

        let Some(rtype) = RecordType::parse(&tname) else {
            let known = WireType::from_str(&tname).is_ok()
                || tname
                    .strip_prefix("TYPE")
                    .is_some_and(|n| n.parse::<u16>().is_ok());
            if known {
                skipped.push(format!("Zeile {no}: Typ {tname} wird nicht unterstützt"));
            } else {
                skipped.push(format!("Zeile {no}: unverständlich („{}“)", type_tok.text));
            }
            continue;
        };

        let name = if owner == zone {
            "@".to_string()
        } else if let Some(rel) = owner.strip_suffix(&format!(".{zone}")) {
            rel.to_string()
        } else {
            skipped.push(format!(
                "Zeile {no}: {owner} liegt ausserhalb der Zone {zone}"
            ));
            continue;
        };

        match parse_rdata(rtype, rdata, &current_origin) {
            Ok(data) => records.push(RecordInput {
                name,
                ttl: ttl.or(ttl_directive).unwrap_or(default_ttl),
                data,
                disabled: false,
                comment: String::new(),
            }),
            Err(e) => skipped.push(format!("Zeile {no}: {} {e}", rtype.as_str())),
        }
    }

    Ok(ParsedZone {
        origin: zone,
        soa,
        records,
        skipped,
    })
}

fn parse_soa(toks: &[Token], origin: &str) -> Result<Soa, String> {
    if toks.len() != 7 {
        return Err(format!("7 Werte erwartet, {} gefunden", toks.len()));
    }
    let primary_ns = resolve_name(&toks[0].text, Some(origin), false)?;
    let responsible = resolve_name(&toks[1].text, Some(origin), false)?;
    let serial = toks[2]
        .text
        .parse::<u32>()
        .map_err(|_| format!("ungültige Seriennummer „{}“", toks[2].text))?;
    let mut times = [0u32; 4];
    for (i, t) in toks[3..].iter().enumerate() {
        times[i] = parse_ttl(&t.text).ok_or_else(|| format!("ungültige Zeit „{}“", t.text))?;
    }
    Ok(Soa {
        primary_ns,
        responsible,
        serial,
        refresh: times[0],
        retry: times[1],
        expire: times[2],
        minimum: times[3],
    })
}

fn parse_rdata(rtype: RecordType, toks: &[Token], origin: &str) -> Result<RecordData, String> {
    let want = |n: usize| -> Result<(), String> {
        if toks.len() == n {
            Ok(())
        } else {
            Err(format!("{n} Werte erwartet, {} gefunden", toks.len()))
        }
    };
    let num = |t: &Token| -> Result<u16, String> {
        t.text
            .parse::<u16>()
            .map_err(|_| format!("ungültige Zahl „{}“", t.text))
    };
    let name = |t: &Token| resolve_name(&t.text, Some(origin), false);
    Ok(match rtype {
        RecordType::A => {
            want(1)?;
            let ip = Ipv4Addr::from_str(&toks[0].text)
                .map_err(|_| format!("ungültige IPv4-Adresse „{}“", toks[0].text))?;
            RecordData::A {
                address: ip.to_string(),
            }
        }
        RecordType::AAAA => {
            want(1)?;
            let ip = Ipv6Addr::from_str(&toks[0].text)
                .map_err(|_| format!("ungültige IPv6-Adresse „{}“", toks[0].text))?;
            RecordData::AAAA {
                address: ip.to_string(),
            }
        }
        RecordType::CNAME => {
            want(1)?;
            RecordData::CNAME {
                target: name(&toks[0])?,
            }
        }
        RecordType::NS => {
            want(1)?;
            RecordData::NS {
                host: name(&toks[0])?,
            }
        }
        RecordType::PTR => {
            want(1)?;
            RecordData::PTR {
                target: name(&toks[0])?,
            }
        }
        RecordType::MX => {
            want(2)?;
            RecordData::MX {
                preference: num(&toks[0])?,
                exchange: name(&toks[1])?,
            }
        }
        RecordType::TXT => {
            if toks.is_empty() {
                return Err("Text fehlt".into());
            }
            RecordData::TXT {
                text: toks.iter().map(|t| t.text.as_str()).collect(),
            }
        }
        RecordType::SRV => {
            want(4)?;
            RecordData::SRV {
                priority: num(&toks[0])?,
                weight: num(&toks[1])?,
                port: num(&toks[2])?,
                target: name(&toks[3])?,
            }
        }
        RecordType::CAA => {
            want(3)?;
            let flags = toks[0]
                .text
                .parse::<u8>()
                .map_err(|_| format!("ungültige Flags „{}“", toks[0].text))?;
            let tag = toks[1].text.to_ascii_lowercase();
            if tag.is_empty() || !tag.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return Err(format!("ungültiges Tag „{}“", toks[1].text));
            }
            RecordData::CAA {
                flags,
                tag,
                value: toks[2].text.clone(),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrzdns_types::{Zone, ZoneKind, ZoneRecord};

    const SAMPLE: &str = r#"
; Beispielzone
$ORIGIN example.com.
$TTL 1h
@   IN  SOA ns1.example.com. hostmaster.example.com. (
            2024010101 ; Seriennummer
            7200       ; refresh
            3600       ; retry
            1209600    ; expire
            300 )      ; minimum
    IN  NS  ns1
    IN  NS  ns2.example.net.
@       IN  MX  10 mail
        IN  MX  20 mail2.example.net.
www     300 IN  A   192.0.2.10
        IN  300 AAAA 2001:db8::10
ftp         CNAME www
mail    A   192.0.2.20
txt     TXT "v=spf1 include:_spf.example.net ~all"
dkim    TXT ( "v=DKIM1; k=rsa; "
              "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ" )
quote   TXT "a \"quoted\" \\ text" ; Kommentar
_sip._tcp SRV 10 60 5060 sip
*       A   192.0.2.99
*.dev   A   192.0.2.100
@       CAA 0 issue "letsencrypt.org"
10      PTR host.example.com.
other.org. A 192.0.2.1
host    HINFO "PC" "Linux"
host    CH  A 192.0.2.2
broken  A   999.1.1.1
$INCLUDE other.zone
"#;

    #[test]
    fn parses_bind_format() {
        let z = parse(SAMPLE, "", 3600).unwrap();
        assert_eq!(z.origin, "example.com");
        let soa = z.soa.as_ref().unwrap();
        assert_eq!(soa.primary_ns, "ns1.example.com");
        assert_eq!(soa.responsible, "hostmaster.example.com");
        assert_eq!(
            (soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum),
            (2024010101, 7200, 3600, 1209600, 300)
        );

        let find = |name: &str, t: RecordType| {
            z.records
                .iter()
                .filter(|r| r.name == name && r.data.record_type() == t)
                .collect::<Vec<_>>()
        };
        let ns = find("@", RecordType::NS);
        assert_eq!(ns.len(), 2);
        assert_eq!(
            ns[0].data,
            RecordData::NS {
                host: "ns1.example.com".into()
            }
        );
        assert_eq!(
            ns[1].data,
            RecordData::NS {
                host: "ns2.example.net".into()
            }
        );
        assert_eq!(ns[0].ttl, 3600);
        assert_eq!(find("@", RecordType::MX).len(), 2);
        let www = find("www", RecordType::A);
        assert_eq!(www[0].ttl, 300);
        assert_eq!(find("www", RecordType::AAAA)[0].ttl, 300);
        assert_eq!(
            find("ftp", RecordType::CNAME)[0].data,
            RecordData::CNAME {
                target: "www.example.com".into()
            }
        );
        assert_eq!(
            find("dkim", RecordType::TXT)[0].data,
            RecordData::TXT {
                text: "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ".into()
            }
        );
        assert_eq!(
            find("quote", RecordType::TXT)[0].data,
            RecordData::TXT {
                text: "a \"quoted\" \\ text".into()
            }
        );
        assert_eq!(
            find("_sip._tcp", RecordType::SRV)[0].data,
            RecordData::SRV {
                priority: 10,
                weight: 60,
                port: 5060,
                target: "sip.example.com".into()
            }
        );
        assert_eq!(find("*", RecordType::A).len(), 1);
        assert_eq!(find("*.dev", RecordType::A).len(), 1);
        assert_eq!(
            find("@", RecordType::CAA)[0].data,
            RecordData::CAA {
                flags: 0,
                tag: "issue".into(),
                value: "letsencrypt.org".into()
            }
        );
        assert_eq!(find("10", RecordType::PTR).len(), 1);

        let skipped = z.skipped.join("\n");
        assert!(
            skipped.contains("other.org liegt ausserhalb der Zone example.com"),
            "{skipped}"
        );
        assert!(
            skipped.contains("Typ HINFO wird nicht unterstützt"),
            "{skipped}"
        );
        assert!(skipped.contains("Klasse CH"), "{skipped}");
        assert!(skipped.contains("999.1.1.1"), "{skipped}");
        assert!(skipped.contains("$INCLUDE"), "{skipped}");
        assert_eq!(z.skipped.len(), 5, "{skipped}");
    }

    #[test]
    fn origin_from_parameter_and_errors() {
        let z = parse("www A 1.2.3.4\n@ 60 TXT hello\n", "Example.ORG.", 120).unwrap();
        assert_eq!(z.origin, "example.org");
        assert_eq!(z.records.len(), 2);
        assert_eq!(z.records[0].ttl, 120);
        assert_eq!(z.records[1].ttl, 60);
        assert!(parse("www A 1.2.3.4\n", "", 120).is_err());
        let z = parse(
            "example.net. 60 IN SOA ns hm 1 2 3 4 5\nwww A 1.1.1.1\n",
            "",
            1,
        )
        .unwrap();
        assert_eq!(z.origin, "example.net");
        assert_eq!(z.soa.unwrap().primary_ns, "ns.example.net");
        assert_eq!(parse_ttl("1h30m"), Some(5400));
        assert_eq!(parse_ttl("1w"), Some(604_800));
        assert_eq!(parse_ttl("abc"), None);
    }

    #[test]
    fn export_round_trip() {
        let rec = |id: i64, name: &str, ttl: u32, data: RecordData| ZoneRecord {
            id,
            zone_id: 1,
            name: name.into(),
            ttl,
            data,
            disabled: false,
            comment: String::new(),
            updated_at: 0,
        };
        let mut records = vec![
            rec(
                1,
                "@",
                3600,
                RecordData::NS {
                    host: "ns1.example.com".into(),
                },
            ),
            rec(
                2,
                "www",
                300,
                RecordData::A {
                    address: "192.0.2.10".into(),
                },
            ),
            rec(
                3,
                "www",
                300,
                RecordData::AAAA {
                    address: "2001:db8::10".into(),
                },
            ),
            rec(
                4,
                "@",
                3600,
                RecordData::MX {
                    preference: 10,
                    exchange: "mail.example.com".into(),
                },
            ),
            rec(
                5,
                "txt",
                3600,
                RecordData::TXT {
                    text: format!("say \"hi\" {}", "x".repeat(300)),
                },
            ),
            rec(
                6,
                "_sip._tcp",
                3600,
                RecordData::SRV {
                    priority: 1,
                    weight: 2,
                    port: 5060,
                    target: "sip.other.net".into(),
                },
            ),
            rec(
                7,
                "*.dev",
                60,
                RecordData::CNAME {
                    target: "www.example.com".into(),
                },
            ),
            rec(
                8,
                "@",
                3600,
                RecordData::CAA {
                    flags: 128,
                    tag: "issue".into(),
                    value: "ca.example".into(),
                },
            ),
            rec(
                9,
                "10",
                3600,
                RecordData::PTR {
                    target: "host.example.com".into(),
                },
            ),
        ];
        let mut disabled = rec(
            10,
            "old",
            3600,
            RecordData::A {
                address: "192.0.2.1".into(),
            },
        );
        disabled.disabled = true;
        records.push(disabled);
        let detail = ZoneDetail {
            zone: Zone {
                id: 1,
                name: "example.com".into(),
                kind: ZoneKind::Primary,
                disabled: false,
                soa: Soa {
                    primary_ns: "ns1.example.com".into(),
                    responsible: "hostmaster.example.com".into(),
                    serial: 42,
                    ..Soa::default()
                },
                forwarders: vec![],
                comment: String::new(),
                record_count: 10,
                created_at: 0,
                updated_at: 0,
            },
            records,
        };
        let text = export(&detail);
        assert!(text.contains("$ORIGIN example.com.\n$TTL 3600\n"), "{text}");
        assert!(!text.contains("old"), "{text}");
        let parsed = parse(&text, "", 1).unwrap();
        assert!(parsed.skipped.is_empty(), "{:?}", parsed.skipped);
        assert_eq!(parsed.origin, "example.com");
        assert_eq!(parsed.soa.as_ref(), Some(&detail.zone.soa));
        let expected: Vec<(String, u32, RecordData)> = detail
            .records
            .iter()
            .filter(|r| !r.disabled)
            .map(|r| (r.name.clone(), r.ttl, r.data.clone()))
            .collect();
        let got: Vec<(String, u32, RecordData)> = parsed
            .records
            .iter()
            .map(|r| (r.name.clone(), r.ttl, r.data.clone()))
            .collect();
        assert_eq!(got, expected);
    }
}
