//! Sperrlisten lesen und laden.

use crate::upstream::http_client;
use crate::wire::error_chain;
use crate::EngineError;
use nrzdns_types::normalize_domain;
use std::io::Read;
use std::net::IpAddr;
use std::time::Duration;

/// Grösste Liste, die geladen wird.
pub const MAX_LIST_BYTES: usize = 64 * 1024 * 1024;

/// Zeitlimit für das Laden einer Liste.
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

/// Namen aus hosts-Dateien, die nie gesperrt werden.
const IGNORED: &[&str] = &["localhost.localdomain", "local.localdomain"];

/// Liest eine Sperrliste in allen üblichen Formaten:
/// * hosts: `0.0.0.0 ads.example.com`, `127.0.0.1 a.com b.com`
/// * reine Domains: `ads.example.com`, Platzhalter `*.ads.example.com`
/// * Adblock: `||ads.example.com^` (Ausnahmen `@@` und Regeln mit Pfad/Optionen übersprungen)
///
/// Kommentare (`#`, `!`), `localhost`-Einträge und Ungültiges werden übersprungen.
/// Ergebnis: normalisiert ([`nrzdns_types::normalize_domain`]), sortiert, ohne Duplikate.
pub fn parse(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with('!')
            || line.starts_with('[')
            || line.starts_with("@@")
        {
            continue;
        }
        if let Some(rule) = line.strip_prefix("||") {
            // Nur reine Domain-Regeln: `||example.com^`
            if let Some(domain) = rule.strip_suffix('^') {
                push_domain(&mut out, domain);
            }
            continue;
        }
        let line = line.split('#').next().unwrap_or("");
        let mut parts = line.split_whitespace();
        let Some(first) = parts.next() else { continue };
        if first.parse::<IpAddr>().is_ok() {
            for name in parts {
                push_domain(&mut out, name);
            }
        } else if parts.next().is_none() {
            push_domain(&mut out, first);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn push_domain(out: &mut Vec<String>, raw: &str) {
    let Some(domain) = normalize_domain(raw) else {
        return;
    };
    if !domain.contains('.')
        || domain.ends_with(".localhost")
        || IGNORED.contains(&domain.as_str())
        || domain.parse::<IpAddr>().is_ok()
    {
        return;
    }
    out.push(domain);
}

/// Lädt eine Liste über http/https (höchstens 64 MiB, Zeitlimit 60 s) und liest sie mit [`parse`].
pub async fn download(url: &str) -> Result<Vec<String>, EngineError> {
    let parsed = reqwest::Url::parse(url.trim())
        .map_err(|_| EngineError::Invalid(format!("Ungültige Adresse „{url}“")))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(EngineError::Invalid(
            "Nur Adressen mit http:// oder https:// werden unterstützt".into(),
        ));
    }
    let mut resp = http_client()
        .get(parsed)
        .timeout(DOWNLOAD_TIMEOUT)
        .send()
        .await
        .map_err(net_error)?;
    let status = resp.status();
    if !status.is_success() {
        return Err(EngineError::Network(format!(
            "Der Server antwortet mit HTTP {}",
            status.as_u16()
        )));
    }
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_LIST_BYTES as u64)
    {
        return Err(too_large());
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(net_error)? {
        if body.len() + chunk.len() > MAX_LIST_BYTES {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    let domains = tokio::task::spawn_blocking(move || -> Result<Vec<String>, EngineError> {
        let text = decode_body(body)?;
        Ok(parse(&text))
    })
    .await
    .map_err(|_| EngineError::Network("Die Liste konnte nicht gelesen werden".into()))??;
    if domains.is_empty() {
        return Err(EngineError::Invalid(
            "Die Liste enthält keine gültigen Domains".into(),
        ));
    }
    Ok(domains)
}

/// Text der Liste; gzip-Dateien (`.gz` ohne Content-Encoding) werden entpackt.
fn decode_body(body: Vec<u8>) -> Result<String, EngineError> {
    if body.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(body.as_slice())
            .take(MAX_LIST_BYTES as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|_| EngineError::Network("Die gzip-Datei ist beschädigt".into()))?;
        if out.len() > MAX_LIST_BYTES {
            return Err(too_large());
        }
        return Ok(String::from_utf8_lossy(&out).into_owned());
    }
    Ok(match String::from_utf8(body) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    })
}

fn too_large() -> EngineError {
    EngineError::Network("Die Liste ist grösser als 64 MiB".into())
}

fn net_error(e: reqwest::Error) -> EngineError {
    if e.is_timeout() {
        EngineError::Timeout
    } else {
        EngineError::Network(format!("Laden fehlgeschlagen: {}", error_chain(&e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_formats() {
        let text = "\
# Kommentar
! Adblock-Kommentar
[Adblock Plus 2.0]
127.0.0.1 localhost
::1 localhost ip6-localhost
255.255.255.255 broadcasthost
0.0.0.0 0.0.0.0
0.0.0.0 ads.example.com tracker.example.com # zwei auf einer Zeile
127.0.0.1\tAds.Example.COM.
plain.example.org
*.wild.example.net
||adblock.example.com^
||withpath.example.com/banner^
||options.example.com^$third-party
@@||allowed.example.com^
not a domain line
bad_domain-.com
1.2.3.4
single
";
        let list = parse(text);
        assert_eq!(
            list,
            [
                "adblock.example.com",
                "ads.example.com",
                "plain.example.org",
                "tracker.example.com",
                "wild.example.net",
            ]
        );
    }

    #[test]
    fn gzip_bodies() {
        use flate2::write::GzEncoder;
        use std::io::Write;
        let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"0.0.0.0 gz.example.com\n").unwrap();
        let text = decode_body(enc.finish().unwrap()).unwrap();
        assert_eq!(parse(&text), ["gz.example.com"]);
    }

    #[tokio::test]
    async fn rejects_other_schemes() {
        assert!(matches!(
            download("ftp://example.com/list").await,
            Err(EngineError::Invalid(_))
        ));
        assert!(matches!(
            download("kein url").await,
            Err(EngineError::Invalid(_))
        ));
    }
}
