//! Spy: Was wissen andere über eine Domain? Gesammelt wird nur, was jeder im Internet sehen
//! kann – so wie ein Angreifer vorgehen würde:
//!
//! * **Registrierung** (RDAP, Nachfolger von WHOIS): Registrar, Daten, DNSSEC, Kontakte.
//! * **DNS von aussen** (DNS über HTTPS bei Cloudflare, nicht das eigene nrzNetwork mit
//!   seinen lokalen Antworten): Nameserver, Mail (MX, SPF, DMARC, DKIM), TXT, CAA.
//! * **Certificate Transparency** (crt.sh): jedes öffentliche Zertifikat verrät seine Namen
//!   – und manchmal E-Mail-Adressen.
//! * **Adressen** der gefundenen Namen und wem das Netz gehört (RDAP): Hoster, CDN, der
//!   eigene Anschluss zu Hause, private Adressen im öffentlichen DNS.
//! * **Aktiv** (nur eigene Domains): Webserver-Kopfzeilen und offene Ports.
//!
//! Daraus entstehen Erkenntnisse mit Empfehlungen und eine Bewertung.

use crate::config::Config;
use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::services::{integrations, settings, tls};
use futures::StreamExt;
use nrzdns_types::{
    normalize_domain, Severity, SpyAddress, SpyCertName, SpyFinding, SpyHost, SpyRecord,
    SpyRegistration, SpyReport, SpyStatus,
};
use reqwest::Method;
use serde_json::Value;
use sqlx::SqlitePool;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

const REPORTS: &str = "spy_reports";
const KEEP_REPORTS: usize = 10;
const MAX_HOSTS: usize = 60;
const MAX_RDAP_IPS: usize = 30;
const MAX_ACTIVE_HOSTS: usize = 40;
/// Ports, die man von aussen nicht offen haben möchte (oder zumindest kennen sollte).
pub const PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1883, 3306, 3389, 5000, 5432,
    5900, 6379, 8080, 8443, 9000, 9200, 27017,
];
const DKIM_SELECTORS: &[&str] = &[
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "s1",
    "s2",
    "mail",
    "dkim",
    "key1",
    "protonmail",
    "protonmail2",
    "fm1",
    "zoho",
    "mx",
    "hostingermail1",
    "hostingermail2",
    "hostingermail-a",
    "hostingermail-b",
    "titan1",
    "cf2024-1",
];

/// Laufender Scan und Fortschritt (Rocket-State).
#[derive(Clone, Default)]
pub struct SpyState(Arc<Inner>);

#[derive(Default)]
struct Inner {
    running: AtomicBool,
    progress: Mutex<Vec<String>>,
}

impl SpyState {
    fn step(&self, s: impl Into<String>) {
        let s = s.into();
        tracing::debug!("Spy: {s}");
        self.0
            .progress
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(s);
    }

    fn progress(&self) -> Vec<String> {
        self.0
            .progress
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

fn client(timeout: u64) -> AppResult<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .user_agent(concat!("nrzNetwork/", env!("CARGO_PKG_VERSION"), " (Spy)"))
        .build()
        .map_err(|e| AppError::Config(e.to_string()))
}

// ------------------------------------------------------------------ eigene Domains, Berichte

/// Eigene Domains: Cloudflare-Zonen und HTTPS-Namen.
pub async fn own_domains(pool: &SqlitePool, config: &Config) -> Vec<String> {
    let mut out = BTreeSet::new();
    if let Ok(s) = tls::settings(pool).await {
        for d in s.domains {
            out.insert(d.trim_start_matches("*.").to_string());
        }
    }
    let has_cf = integrations::cloudflare_token(pool)
        .await
        .is_ok_and(|t| !t.is_empty());
    if has_cf {
        if let Ok(up) = integrations::cloudflare(
            pool,
            config,
            Method::GET,
            &["zones"],
            Some("per_page=50"),
            None,
        )
        .await
        {
            for z in up.body["result"].as_array().into_iter().flatten() {
                if let Some(n) = z["name"].as_str() {
                    out.insert(n.to_string());
                }
            }
        }
    }
    out.into_iter().collect()
}

fn is_own(domain: &str, own: &[String]) -> bool {
    own.iter()
        .any(|o| domain == o || domain.ends_with(&format!(".{o}")))
}

async fn reports(pool: &SqlitePool) -> AppResult<Vec<SpyReport>> {
    Ok(settings::get(pool, REPORTS).await?.unwrap_or_default())
}

pub async fn status(pool: &SqlitePool, config: &Config, state: &SpyState) -> AppResult<SpyStatus> {
    Ok(SpyStatus {
        running: state.0.running.load(Ordering::Relaxed),
        progress: state.progress(),
        own_domains: own_domains(pool, config).await,
        reports: reports(pool).await?,
    })
}

async fn store(pool: &SqlitePool, report: SpyReport) -> AppResult<()> {
    let mut all = reports(pool).await?;
    all.retain(|r| r.domain != report.domain);
    all.insert(0, report);
    all.truncate(KEEP_REPORTS);
    settings::set(pool, REPORTS, &all).await
}

pub async fn delete_report(pool: &SqlitePool, domain: &str) -> AppResult<()> {
    let mut all = reports(pool).await?;
    let before = all.len();
    all.retain(|r| r.domain != domain);
    if all.len() == before {
        return Err(AppError::NotFound);
    }
    settings::set(pool, REPORTS, &all).await
}

/// Domain prüfen; aktiv nur für eigene. Läuft im Hintergrund weiter (Fortschritt über
/// [`status`]).
pub fn check_input(domain: &str) -> AppResult<String> {
    let d = normalize_domain(domain.trim().trim_start_matches("*."))
        .filter(|d| d.contains('.'))
        .ok_or_else(|| AppError::bad("Bitte eine Domain angeben, z. B. zweers.ch."))?;
    Ok(d)
}

pub async fn start(
    pool: SqlitePool,
    config: Config,
    state: SpyState,
    domain: String,
    active: bool,
) -> AppResult<()> {
    let own = own_domains(&pool, &config).await;
    if active && !is_own(&domain, &own) {
        return Err(AppError::Forbidden(
            "Aktive Prüfungen (Webserver, Ports) gibt es nur für eigene Domains – aus Cloudflare oder den HTTPS-Einstellungen.".into(),
        ));
    }
    if state.0.running.swap(true, Ordering::SeqCst) {
        return Err(AppError::Conflict("Es läuft schon ein Scan.".into()));
    }
    state
        .0
        .progress
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
    tokio::spawn(async move {
        let report = scan(&config, &state, &domain, active).await;
        match report {
            Ok(r) => {
                state.step(format!(
                    "Fertig: {} Erkenntnisse, Bewertung {}/100",
                    r.findings.len(),
                    r.score
                ));
                if let Err(e) = store(&pool, r).await {
                    tracing::warn!("Spy: Bericht speichern: {e}");
                }
            }
            Err(e) => state.step(format!("Fehlgeschlagen: {e}")),
        }
        state.0.running.store(false, Ordering::SeqCst);
    });
    Ok(())
}

// ------------------------------------------------------------------ Quellen

/// Ein Eintrag aus DNS über HTTPS (JSON).
#[derive(Debug, Clone)]
struct Answer {
    qtype: u16,
    data: String,
}

fn type_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        43 => "DS",
        257 => "CAA",
        _ => "?",
    }
}

/// DNS-Abfrage von aussen. Zweiter Wert: DNSSEC bestätigt (AD).
async fn doh(
    http: &reqwest::Client,
    base: &str,
    name: &str,
    qtype: &str,
) -> Result<(Vec<Answer>, bool), String> {
    let resp = http
        .get(base)
        .query(&[("name", name), ("type", qtype)])
        .header("accept", "application/dns-json")
        .send()
        .await
        .map_err(|e| format!("DNS ({name} {qtype}): {e}"))?;
    let v: Value = resp
        .json()
        .await
        .map_err(|e| format!("DNS ({name} {qtype}): {e}"))?;
    let answers = v["Answer"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| Answer {
            qtype: a["type"].as_u64().unwrap_or(0) as u16,
            data: a["data"].as_str().unwrap_or_default().to_string(),
        })
        .collect();
    Ok((answers, v["AD"].as_bool().unwrap_or(false)))
}

/// `10 mx1.example.com.` → `mx1.example.com`.
fn mx_host(data: &str) -> String {
    data.split_whitespace()
        .last()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_lowercase()
}

fn txt_unquote(s: &str) -> String {
    // "v=spf1 …" "…" → zusammengesetzt
    let s = s.trim();
    if !s.starts_with('"') {
        return s.to_string();
    }
    s.split('"')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, p)| p)
        .collect::<String>()
}

fn vcard_get(entity: &Value, key: &str) -> Vec<String> {
    entity["vcardArray"][1]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f[0].as_str() == Some(key))
        .filter_map(|f| match &f[3] {
            Value::String(s) => Some(s.clone()),
            Value::Array(a) => Some(
                a.iter()
                    .filter_map(|x| x.as_str())
                    .filter(|x| !x.is_empty())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            _ => None,
        })
        .filter(|s| !s.trim().is_empty())
        .collect()
}

fn rfc3339(s: &str) -> i64 {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map(|t| t.unix_timestamp())
        .unwrap_or(0)
}

/// Registrierung aus RDAP lesen.
pub fn parse_rdap_domain(v: &Value, source: &str) -> SpyRegistration {
    let mut r = SpyRegistration {
        source: source.to_string(),
        dnssec: v["secureDNS"]["delegationSigned"]
            .as_bool()
            .unwrap_or(false),
        status: v["status"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s.as_str().map(str::to_string))
            .collect(),
        ..SpyRegistration::default()
    };
    for e in v["events"].as_array().into_iter().flatten() {
        let t = rfc3339(e["eventDate"].as_str().unwrap_or_default());
        match e["eventAction"].as_str().unwrap_or_default() {
            "registration" => r.created = t,
            "expiration" => r.expires = t,
            "last changed" | "last update of RDAP database" if r.updated == 0 => r.updated = t,
            "last changed" => r.updated = t,
            _ => {}
        }
    }
    fn walk(e: &Value, r: &mut SpyRegistration, depth: u8) {
        let roles: Vec<String> = e["roles"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect();
        let names = vcard_get(e, "fn");
        let orgs = vcard_get(e, "org");
        let emails = vcard_get(e, "email");
        let label = names.first().or(orgs.first()).cloned().unwrap_or_default();
        if roles.iter().any(|x| x == "registrar") && r.registrar.is_empty() {
            r.registrar = label.trim().to_string();
        } else if !label.is_empty() || !emails.is_empty() {
            let redacted = |s: &str| {
                let l = s.to_lowercase();
                l.contains("redacted")
                    || l.contains("privacy")
                    || l.contains("not disclosed")
                    || l.contains("data protected")
            };
            let mut parts = Vec::new();
            if !label.is_empty() && !redacted(&label) {
                parts.push(label);
            }
            parts.extend(emails.into_iter().filter(|m| !redacted(m)));
            if !parts.is_empty() {
                let role = roles.first().cloned().unwrap_or_else(|| "Kontakt".into());
                r.contacts.push(format!("{role}: {}", parts.join(", ")));
            }
        }
        if depth < 2 {
            for sub in e["entities"].as_array().into_iter().flatten() {
                walk(sub, r, depth + 1);
            }
        }
    }
    for e in v["entities"].as_array().into_iter().flatten() {
        walk(e, &mut r, 0);
    }
    r.contacts.sort();
    r.contacts.dedup();
    r
}

/// Netzbetreiber einer IP aus RDAP: (Anbieter, Netz, Land).
pub fn parse_rdap_ip(v: &Value) -> (String, String, String) {
    let mut provider = String::new();
    for e in v["entities"].as_array().into_iter().flatten() {
        let roles: Vec<&str> = e["roles"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| x.as_str())
            .collect();
        let name = vcard_get(e, "fn").into_iter().next().unwrap_or_default();
        if !name.is_empty() && (roles.contains(&"registrant") || provider.is_empty()) {
            provider = name;
        }
    }
    if provider.is_empty() {
        provider = v["name"].as_str().unwrap_or_default().to_string();
    }
    let network = v["cidr0_cidrs"]
        .as_array()
        .and_then(|a| a.first())
        .map(|c| {
            let p = c["v4prefix"]
                .as_str()
                .or(c["v6prefix"].as_str())
                .unwrap_or_default();
            format!("{p}/{}", c["length"].as_u64().unwrap_or(0))
        })
        .filter(|s| !s.starts_with('/'))
        .unwrap_or_else(|| {
            let (a, b) = (
                v["startAddress"].as_str().unwrap_or_default(),
                v["endAddress"].as_str().unwrap_or_default(),
            );
            if a.is_empty() {
                String::new()
            } else {
                format!("{a} – {b}")
            }
        });
    let name = v["name"].as_str().unwrap_or_default();
    let network = if name.is_empty() {
        network
    } else {
        format!("{name} ({network})")
    };
    (
        provider,
        network,
        v["country"].as_str().unwrap_or_default().to_string(),
    )
}

/// WHOIS (Port 43) über `<tld>.whois-servers.net`.
async fn whois(domain: &str, tld: &str) -> Result<(String, String), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let server = format!("{tld}.whois-servers.net");
    let fut = async {
        let mut s = tokio::net::TcpStream::connect((server.as_str(), 43))
            .await
            .map_err(|e| e.to_string())?;
        s.write_all(format!("{domain}\r\n").as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        s.take(64 * 1024)
            .read_to_end(&mut buf)
            .await
            .map_err(|e| e.to_string())?;
        Ok::<_, String>(String::from_utf8_lossy(&buf).into_owned())
    };
    let text = tokio::time::timeout(Duration::from_secs(15), fut)
        .await
        .map_err(|_| "keine Antwort".to_string())??;
    Ok((server, text))
}

fn whois_time(s: &str) -> i64 {
    let s = s.trim();
    if let Ok(t) = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339) {
        return t.unix_timestamp();
    }
    let d = s.get(..10).unwrap_or(s);
    let fmt = time::macros::format_description!("[year]-[month]-[day]");
    if let Ok(date) = time::Date::parse(d, &fmt) {
        return date.midnight().assume_utc().unix_timestamp();
    }
    let fmt = time::macros::format_description!("[day].[month].[year]");
    time::Date::parse(d, &fmt)
        .map(|date| date.midnight().assume_utc().unix_timestamp())
        .unwrap_or(0)
}

fn redacted(v: &str) -> bool {
    let v = v.to_lowercase();
    v.contains("redacted")
        || v.contains("privacy")
        || v.contains("not disclosed")
        || v.contains("not public")
}

/// WHOIS-Text lesen: „Schlüssel: Wert“ (gTLDs) und Blöcke wie bei .ch („Registrar:“, Wert
/// auf der nächsten Zeile).
pub fn parse_whois(text: &str, source: &str) -> SpyRegistration {
    let mut r = SpyRegistration {
        source: source.to_string(),
        ..SpyRegistration::default()
    };
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    for (i, line) in lines.iter().enumerate() {
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        let val = match val.trim() {
            "" => lines
                .get(i + 1)
                .map(|l| l.trim().to_string())
                .unwrap_or_default(),
            v => v.to_string(),
        };
        let lv = val.to_lowercase();
        match key.as_str() {
            "registrar" | "registrar name" | "sponsoring registrar" => {
                if r.registrar.is_empty() {
                    r.registrar = val;
                }
            }
            "creation date"
            | "created"
            | "registered"
            | "first registration date"
            | "registration time" => {
                if r.created == 0 {
                    r.created = whois_time(&val);
                }
            }
            "registry expiry date"
            | "expiry date"
            | "expires"
            | "expiration date"
            | "paid-till" => {
                if r.expires == 0 {
                    r.expires = whois_time(&val);
                }
            }
            "updated date" | "changed" | "last-update" => {
                if r.updated == 0 {
                    r.updated = whois_time(&val);
                }
            }
            "dnssec" => {
                r.dnssec =
                    lv.starts_with('y') || (lv.contains("signed") && !lv.contains("unsigned"))
            }
            "domain status" | "status" => {
                if let Some(s) = val.split_whitespace().next() {
                    r.status.push(s.to_string());
                }
            }
            k if (k.starts_with("registrant")
                || k.starts_with("holder")
                || k.starts_with("admin"))
                && (k.contains("email") || k.contains("name") || k.contains("organization"))
                && !val.is_empty()
                && !redacted(&val) =>
            {
                r.contacts.push(format!("{key}: {val}"));
            }
            _ => {}
        }
    }
    r.status.dedup();
    r.contacts.sort();
    r.contacts.dedup();
    r
}

fn ct_time(s: &str) -> i64 {
    let s = s.get(..19).unwrap_or(s);
    let fmt = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    time::PrimitiveDateTime::parse(s, &fmt)
        .map(|t| t.assume_utc().unix_timestamp())
        .unwrap_or(0)
}

/// Zertifikate aus crt.sh: Namen (mit Anzahl, Zeitraum, Ausstellern), E-Mails, Anzahl.
pub fn parse_crtsh(v: &Value, domain: &str) -> (Vec<SpyCertName>, Vec<String>, u32) {
    let mut names: BTreeMap<String, SpyCertName> = BTreeMap::new();
    let mut emails = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for c in v.as_array().into_iter().flatten() {
        ids.insert(c["id"].as_u64().unwrap_or(0));
        let issuer = c["issuer_name"]
            .as_str()
            .unwrap_or_default()
            .split(',')
            .find_map(|p| p.trim().strip_prefix("O="))
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();
        let t = ct_time(c["not_before"].as_str().unwrap_or_default());
        let mut all: Vec<String> = c["name_value"]
            .as_str()
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_lowercase())
            .collect();
        all.push(
            c["common_name"]
                .as_str()
                .unwrap_or_default()
                .trim()
                .to_lowercase(),
        );
        let all: BTreeSet<String> = all.into_iter().filter(|n| !n.is_empty()).collect();
        for n in all {
            if n.contains('@') {
                emails.insert(n);
                continue;
            }
            let n = n.trim_end_matches('.').to_string();
            if n != domain && !n.ends_with(&format!(".{domain}")) {
                continue;
            }
            let e = names.entry(n.clone()).or_insert_with(|| SpyCertName {
                name: n,
                first_seen: i64::MAX,
                ..SpyCertName::default()
            });
            e.certificates += 1;
            if t > 0 {
                e.first_seen = e.first_seen.min(t);
                e.last_seen = e.last_seen.max(t);
            }
            if !issuer.is_empty() && !e.issuers.contains(&issuer) {
                e.issuers.push(issuer.clone());
            }
        }
    }
    let mut out: Vec<SpyCertName> = names
        .into_values()
        .map(|mut n| {
            if n.first_seen == i64::MAX {
                n.first_seen = 0;
            }
            n
        })
        .collect();
    out.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.name.cmp(&b.name)));
    ids.remove(&0);
    (out, emails.into_iter().collect(), ids.len() as u32)
}

// ------------------------------------------------------------------ Anbieter erkennen

fn known(host: &str, table: &[(&str, &str)]) -> Option<String> {
    let h = host.to_lowercase();
    table
        .iter()
        .find(|(k, _)| h.contains(k))
        .map(|(_, v)| v.to_string())
}

pub fn dns_provider(ns: &[String]) -> String {
    const T: &[(&str, &str)] = &[
        ("cloudflare.com", "Cloudflare"),
        ("awsdns", "Amazon Route 53"),
        ("azure-dns", "Microsoft Azure DNS"),
        ("googledomains", "Google"),
        ("ns-cloud", "Google Cloud DNS"),
        ("domaincontrol", "GoDaddy"),
        ("hostpoint", "Hostpoint"),
        ("infomaniak", "Infomaniak"),
        ("cyon", "cyon"),
        ("metanet", "METANET"),
        ("gandi", "Gandi"),
        ("ovh", "OVHcloud"),
        ("hetzner", "Hetzner"),
        ("ui-dns", "IONOS"),
        ("digitalocean", "DigitalOcean"),
        ("netlify", "Netlify"),
        ("vercel-dns", "Vercel"),
        ("namecheap", "Namecheap"),
        ("registrar-servers", "Namecheap"),
        ("inwx", "INWX"),
        ("strato", "STRATO"),
        ("nsone", "NS1"),
        ("he.net", "Hurricane Electric"),
        ("dns-parking", "Hostinger"),
        ("hostinger", "Hostinger"),
    ];
    let mut found: Vec<String> = ns.iter().filter_map(|n| known(n, T)).collect();
    found.dedup();
    found.join(", ")
}

pub fn mail_provider(mx: &[String], spf: &str) -> String {
    const T: &[(&str, &str)] = &[
        ("google.com", "Google Workspace"),
        ("googlemail.com", "Google Workspace"),
        ("outlook.com", "Microsoft 365"),
        ("protonmail.ch", "Proton Mail"),
        ("infomaniak", "Infomaniak"),
        ("zoho", "Zoho Mail"),
        ("icloud.com", "iCloud Mail"),
        ("messagingengine.com", "Fastmail"),
        ("mailgun", "Mailgun"),
        ("sendgrid", "SendGrid"),
        ("mimecast", "Mimecast"),
        ("hostpoint", "Hostpoint"),
        ("cyon", "cyon"),
        ("ionos", "IONOS"),
        ("ovh", "OVHcloud"),
        ("mxroute", "MXroute"),
        ("improvmx", "ImprovMX"),
        ("forwardemail", "Forward Email"),
        ("cloudflare.net", "Cloudflare Email Routing"),
        ("mx.cloudflare", "Cloudflare Email Routing"),
        ("migadu", "Migadu"),
        ("tutanota", "Tuta"),
        ("posteo", "Posteo"),
        ("hostinger", "Hostinger"),
        ("titan.email", "Titan (Hostinger)"),
        ("secureserver.net", "GoDaddy"),
        ("one.com", "one.com"),
    ];
    let mut found: Vec<String> = mx.iter().filter_map(|m| known(m, T)).collect();
    if found.is_empty() {
        found.extend(known(spf, T));
    }
    found.dedup();
    found.join(", ")
}

/// Dienste, die TXT-Einträge verraten (Verifizierungen, SPF-Includes).
pub fn services_from_txt(txts: &[String]) -> Vec<String> {
    const T: &[(&str, &str)] = &[
        (
            "google-site-verification",
            "Google (Search Console/Workspace)",
        ),
        ("ms=", "Microsoft 365"),
        ("facebook-domain-verification", "Facebook/Meta"),
        ("apple-domain-verification", "Apple"),
        ("atlassian-domain-verification", "Atlassian"),
        ("docusign", "DocuSign"),
        ("adobe-idp-site-verification", "Adobe"),
        ("stripe-verification", "Stripe"),
        ("zoom-domain-verification", "Zoom"),
        ("slack-domain-verification", "Slack"),
        ("dropbox-domain-verification", "Dropbox"),
        ("github-challenge", "GitHub"),
        ("_github-pages-challenge", "GitHub Pages"),
        ("openai-domain-verification", "OpenAI"),
        ("anthropic-domain-verification", "Anthropic"),
        ("brevo-code", "Brevo"),
        ("mailchimp", "Mailchimp"),
        ("hubspot", "HubSpot"),
        ("shopify", "Shopify"),
        ("wix-verification", "Wix"),
        ("yandex-verification", "Yandex"),
        ("include:_spf.google.com", "Google Workspace (Mail)"),
        ("include:spf.protection.outlook.com", "Microsoft 365 (Mail)"),
        ("include:mailgun.org", "Mailgun"),
        ("include:sendgrid.net", "SendGrid"),
        ("include:_spf.mx.cloudflare.net", "Cloudflare Email Routing"),
        ("include:spf.infomaniak.ch", "Infomaniak (Mail)"),
        ("include:_spf.protonmail.ch", "Proton Mail"),
        ("include:icloud.com", "iCloud Mail"),
        ("include:amazonses.com", "Amazon SES"),
        ("include:spf.brevo.com", "Brevo"),
        ("include:servers.mcsv.net", "Mailchimp"),
        ("include:_spf.mail.hostinger.com", "Hostinger (Mail)"),
        ("include:spf.titan.email", "Titan Mail"),
    ];
    let mut out = BTreeSet::new();
    for t in txts {
        let l = t.to_lowercase();
        for (k, v) in T {
            if l.contains(k) {
                out.insert(v.to_string());
            }
        }
    }
    out.into_iter().collect()
}

fn is_cdn(provider: &str) -> bool {
    let p = provider.to_lowercase();
    [
        "cloudflare",
        "fastly",
        "akamai",
        "incapsula",
        "imperva",
        "sucuri",
        "bunny",
        "stackpath",
        "edgecast",
        "cloudfront",
    ]
    .iter()
    .any(|k| p.contains(k))
}

/// Private oder interne Adresse (gehört nicht ins öffentliche DNS).
pub fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(a) => {
            a.is_loopback()
                || a.is_unspecified()
                || (a.segments()[0] & 0xfe00) == 0xfc00
                || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

// ------------------------------------------------------------------ Scan

async fn scan(
    config: &Config,
    state: &SpyState,
    domain: &str,
    active: bool,
) -> AppResult<SpyReport> {
    let http = client(20)?;
    let doh_url: Arc<str> = Arc::from(config.spy_doh.as_str());
    let mut report = SpyReport {
        domain: domain.to_string(),
        scanned_at: now(),
        active,
        ..SpyReport::default()
    };
    let mut records: Vec<SpyRecord> = Vec::new();
    let add = |records: &mut Vec<SpyRecord>, name: &str, a: &[Answer]| {
        for x in a {
            records.push(SpyRecord {
                name: name.to_string(),
                qtype: type_name(x.qtype).to_string(),
                data: if x.qtype == 16 {
                    txt_unquote(&x.data)
                } else {
                    x.data.clone()
                },
            });
        }
    };

    // Registrierung: RDAP (über rdap.org, sonst direkt bei der Registry), sonst WHOIS
    state.step("Registrierung (RDAP/WHOIS)");
    let tld = domain.rsplit('.').next().unwrap_or_default();
    let mut rdap_urls = vec![format!(
        "{}/domain/{domain}",
        config.spy_rdap.trim_end_matches('/')
    )];
    let public = config.spy_rdap.contains("rdap.org");
    if public {
        rdap_urls.push(format!("https://rdap.nic.{tld}/domain/{domain}"));
    }
    let mut got = false;
    let mut last_err = String::new();
    for url in &rdap_urls {
        match http
            .get(url)
            .header("accept", "application/rdap+json")
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                let source = resp.url().host_str().unwrap_or_default().to_string();
                match resp.json::<Value>().await {
                    Ok(v) => {
                        report.registration = parse_rdap_domain(&v, &source);
                        got = true;
                        break;
                    }
                    Err(e) => last_err = format!("RDAP: {e}"),
                }
            }
            Ok(resp) => last_err = format!("RDAP: HTTP {}", resp.status()),
            Err(e) => last_err = format!("RDAP: {e}"),
        }
    }
    if !got && public {
        match whois(domain, tld).await {
            Ok((server, text)) => {
                report.registration = parse_whois(&text, &server);
                got = true;
            }
            Err(e) => last_err = format!("{last_err}; WHOIS: {e}"),
        }
    }
    if !got {
        report.errors.push(last_err);
    }

    // DNS von aussen
    state.step("DNS von aussen (Nameserver, Mail, TXT, CAA)");
    let mut dnssec_ad = false;
    let mut txts = Vec::new();
    for qtype in ["NS", "SOA", "A", "AAAA", "MX", "TXT", "CAA", "DS"] {
        match doh(&http, &doh_url, domain, qtype).await {
            Ok((a, ad)) => {
                dnssec_ad |= ad;
                let a: Vec<Answer> = a
                    .into_iter()
                    .filter(|x| type_name(x.qtype) == qtype)
                    .collect();
                match qtype {
                    "NS" => {
                        report.name_servers = a
                            .iter()
                            .map(|x| x.data.trim_end_matches('.').to_string())
                            .collect()
                    }
                    "MX" => {
                        report.mail.mx = a
                            .iter()
                            .map(|x| mx_host(&x.data))
                            .filter(|h| !h.is_empty())
                            .collect();
                        report.mail.mx.sort();
                    }
                    "TXT" => txts.extend(a.iter().map(|x| txt_unquote(&x.data))),
                    _ => {}
                }
                add(&mut records, domain, &a);
            }
            Err(e) => report.errors.push(e),
        }
    }
    report.registration.dnssec |= dnssec_ad;
    report.name_servers.sort();
    report.dns_provider = dns_provider(&report.name_servers);
    report.mail.spf = txts
        .iter()
        .find(|t| t.to_lowercase().starts_with("v=spf1"))
        .cloned()
        .unwrap_or_default();
    if let Ok((a, _)) = doh(&http, &doh_url, &format!("_dmarc.{domain}"), "TXT").await {
        let a: Vec<Answer> = a.into_iter().filter(|x| x.qtype == 16).collect();
        report.mail.dmarc = a
            .iter()
            .map(|x| txt_unquote(&x.data))
            .find(|t| t.to_lowercase().starts_with("v=dmarc1"))
            .unwrap_or_default();
        add(&mut records, &format!("_dmarc.{domain}"), &a);
    }
    let selectors: Vec<String> = DKIM_SELECTORS.iter().map(|s| (*s).to_string()).collect();
    let dkim: Vec<(String, bool)> = futures::stream::iter(selectors)
        .map(|sel| {
            let http = http.clone();
            let doh_url = doh_url.clone();
            let name = format!("{sel}._domainkey.{domain}");
            async move {
                let ok = doh(&http, &doh_url, &name, "TXT")
                    .await
                    .map(|(a, _)| a.iter().any(|x| x.qtype == 16 || x.qtype == 5))
                    .unwrap_or(false);
                (sel, ok)
            }
        })
        .buffer_unordered(6)
        .collect()
        .await;
    report.mail.dkim = dkim
        .into_iter()
        .filter(|(_, ok)| *ok)
        .map(|(s, _)| s)
        .collect();
    report.mail.dkim.sort();
    report.mail.provider = mail_provider(&report.mail.mx, &report.mail.spf);
    let mut all_txt = txts.clone();
    all_txt.push(report.mail.spf.clone());
    report.services = services_from_txt(&all_txt);

    // Platzhalter (*.domain)?
    let probe = format!("nrz-spy-{:x}.{domain}", now() ^ 0x5eed);
    let wildcard = doh(&http, &doh_url, &probe, "A")
        .await
        .map(|(a, _)| a.iter().any(|x| x.qtype == 1 || x.qtype == 5))
        .unwrap_or(false);

    // Certificate Transparency
    state.step("Zertifikate (Certificate Transparency, crt.sh – kann dauern)");
    let ct_http = client(60)?;
    let ct_url = format!("{}/", config.spy_crtsh.trim_end_matches('/'));
    let mut ct: Option<Value> = None;
    for attempt in 0..2 {
        match ct_http
            .get(&ct_url)
            .query(&[("q", format!("%.{domain}").as_str()), ("output", "json")])
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
                Ok(v) => {
                    ct = Some(v);
                    break;
                }
                Err(e) => report.errors.push(format!("crt.sh: {e}")),
            },
            Ok(resp) => {
                if attempt == 1 {
                    report
                        .errors
                        .push(format!("crt.sh: HTTP {}", resp.status()));
                }
            }
            Err(e) => {
                if attempt == 1 {
                    report.errors.push(format!("crt.sh: {e}"));
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    if let Some(v) = &ct {
        let (names, emails, count) = parse_crtsh(v, domain);
        report.cert_names = names;
        report.cert_emails = emails;
        report.cert_count = count;
    }

    // Namen sammeln und auflösen
    state.step("Namen auflösen");
    let mut hosts: BTreeMap<String, BTreeSet<&'static str>> = BTreeMap::new();
    hosts.entry(domain.to_string()).or_default().insert("dns");
    hosts
        .entry(format!("www.{domain}"))
        .or_default()
        .insert("dns");
    for m in &report.mail.mx {
        hosts.entry(m.clone()).or_default().insert("mx");
    }
    for c in &report.cert_names {
        if !c.name.starts_with("*.") {
            hosts.entry(c.name.clone()).or_default().insert("ct");
        }
    }
    let names: Vec<(String, Vec<String>)> = hosts
        .into_iter()
        .take(MAX_HOSTS)
        .map(|(k, v)| (k, v.into_iter().map(str::to_string).collect()))
        .collect();
    let resolved: Vec<SpyHost> = futures::stream::iter(names)
        .map(|(name, sources)| {
            let http = http.clone();
            let doh_url = doh_url.clone();
            async move {
                let mut h = SpyHost {
                    name: name.clone(),
                    sources,
                    ..SpyHost::default()
                };
                for qtype in ["A", "AAAA"] {
                    if let Ok((a, _)) = doh(&http, &doh_url, &name, qtype).await {
                        for x in a {
                            match x.qtype {
                                1 | 28 => h.addresses.push(x.data),
                                5 if h.cname.is_empty() => {
                                    h.cname = x.data.trim_end_matches('.').to_string()
                                }
                                _ => {}
                            }
                        }
                    }
                }
                h.addresses.sort();
                h.addresses.dedup();
                h
            }
        })
        .buffer_unordered(8)
        .collect()
        .await;
    let mut resolved = resolved;
    resolved.sort_by(|a, b| a.name.cmp(&b.name));
    for h in resolved.iter().filter(|h| h.name != domain) {
        for a in &h.addresses {
            records.push(SpyRecord {
                name: h.name.clone(),
                qtype: if a.contains(':') {
                    "AAAA".into()
                } else {
                    "A".into()
                },
                data: a.clone(),
            });
        }
    }
    report.records = records;

    // Adressen: wem gehört das Netz?
    state.step("Netzbetreiber der Adressen (RDAP)");
    let home: Option<IpAddr> = match http.get(&config.spy_trace).send().await {
        Ok(r) => r.text().await.ok().and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("ip="))
                .and_then(|ip| ip.trim().parse().ok())
        }),
        Err(_) => None,
    };
    let mut ips: Vec<IpAddr> = resolved
        .iter()
        .flat_map(|h| h.addresses.iter())
        .filter_map(|a| a.parse().ok())
        .collect();
    ips.sort();
    ips.dedup();
    let rdap_base = config.spy_rdap.trim_end_matches('/').to_string();
    let addresses: Vec<SpyAddress> = futures::stream::iter(ips.into_iter().enumerate())
        .map(|(i, ip)| {
            let http = http.clone();
            let rdap_base = rdap_base.clone();
            async move {
                let mut a = SpyAddress {
                    ip: ip.to_string(),
                    private: is_internal(ip),
                    home: home == Some(ip),
                    ..SpyAddress::default()
                };
                if !a.private && i < MAX_RDAP_IPS {
                    if let Ok(resp) = http
                        .get(format!("{rdap_base}/ip/{ip}"))
                        .header("accept", "application/rdap+json")
                        .send()
                        .await
                    {
                        if let Ok(v) = resp.json::<Value>().await {
                            let (p, n, c) = parse_rdap_ip(&v);
                            a.provider = p;
                            a.network = n;
                            a.country = c;
                        }
                    }
                }
                a.cdn = is_cdn(&a.provider) || is_cdn(&a.network);
                a
            }
        })
        .buffer_unordered(4)
        .collect()
        .await;
    let mut addresses = addresses;
    addresses.sort_by(|a, b| a.ip.cmp(&b.ip));

    // Aktiv: Webserver und Ports
    if active {
        state.step("Webserver prüfen");
        let checked: Vec<SpyHost> =
            futures::stream::iter(resolved.clone().into_iter().take(MAX_ACTIVE_HOSTS))
                .map(|mut h| async move {
                    let Some(ip) = h
                        .addresses
                        .iter()
                        .filter_map(|a| a.parse::<IpAddr>().ok())
                        .find(|ip| !is_internal(*ip))
                    else {
                        return h;
                    };
                    if h.sources.iter().all(|s| s == "mx") {
                        return h;
                    }
                    web_check(&mut h, ip).await;
                    h
                })
                .buffer_unordered(6)
                .collect()
                .await;
        let mut checked = checked;
        checked.sort_by(|a, b| a.name.cmp(&b.name));
        resolved = checked;

        state.step("Offene Ports der direkt erreichbaren Adressen (von innen geprüft)");
        for a in addresses.iter_mut().filter(|a| !a.cdn && !a.private) {
            let Ok(ip) = a.ip.parse::<IpAddr>() else {
                continue;
            };
            let open: Vec<u16> = futures::stream::iter(PORTS.iter().copied())
                .map(|port| async move {
                    let ok = matches!(
                        tokio::time::timeout(
                            Duration::from_millis(1500),
                            tokio::net::TcpStream::connect(SocketAddr::new(ip, port))
                        )
                        .await,
                        Ok(Ok(_))
                    );
                    (port, ok)
                })
                .buffer_unordered(16)
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .filter(|(_, ok)| *ok)
                .map(|(p, _)| p)
                .collect();
            let mut open = open;
            open.sort_unstable();
            a.open_ports = open;
        }
    }
    report.hosts = resolved;
    report.addresses = addresses;

    state.step("Auswerten");
    report.findings = findings(&report, wildcard);
    report.score = score(&report.findings);
    Ok(report)
}

/// Webserver eines Namens über seine öffentliche Adresse prüfen (nicht über das lokale DNS).
async fn web_check(h: &mut SpyHost, ip: IpAddr) {
    for scheme in ["https", "http"] {
        let port = if scheme == "https" { 443 } else { 80 };
        let Ok(c) = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none())
            .resolve(&h.name, SocketAddr::new(ip, port))
            .user_agent(concat!("nrzNetwork/", env!("CARGO_PKG_VERSION"), " (Spy)"))
            .build()
        else {
            return;
        };
        let Ok(resp) = c.get(format!("{scheme}://{}/", h.name)).send().await else {
            continue;
        };
        let hv = |k: &str| {
            resp.headers()
                .get(k)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .chars()
                .take(120)
                .collect::<String>()
        };
        h.http_status = resp.status().as_u16();
        h.server = hv("server");
        h.powered_by = hv("x-powered-by");
        h.hsts = !hv("strict-transport-security").is_empty();
        h.https = scheme == "https";
        if let Ok(body) = resp.text().await {
            let lower = body.to_lowercase();
            if let (Some(a), Some(b)) = (lower.find("<title"), lower.find("</title>")) {
                if let Some(start) = body[a..].find('>').map(|i| a + i + 1) {
                    if start < b {
                        h.title = body[start..b]
                            .split_whitespace()
                            .collect::<Vec<_>>()
                            .join(" ")
                            .chars()
                            .take(100)
                            .collect();
                    }
                }
            }
        }
        return;
    }
}

fn f(
    severity: Severity,
    title: String,
    detail: &str,
    advice: &str,
    items: Vec<String>,
) -> SpyFinding {
    SpyFinding {
        severity,
        title,
        detail: detail.into(),
        advice: advice.into(),
        items,
    }
}

/// Erkenntnisse aus dem Bericht.
pub fn findings(r: &SpyReport, wildcard: bool) -> Vec<SpyFinding> {
    let mut out = Vec::new();
    let d = &r.domain;

    // Zertifikate
    let named: Vec<String> = r
        .cert_names
        .iter()
        .filter(|c| !c.name.starts_with("*.") && c.name != *d && c.name != format!("www.{d}"))
        .map(|c| c.name.clone())
        .collect();
    if !named.is_empty() {
        out.push(f(
            if named.len() > 5 { Severity::Medium } else { Severity::Low },
            format!("{} Namen in öffentlichen Zertifikaten", named.len()),
            "Jedes Zertifikat landet für immer in den Certificate-Transparency-Logs. Damit kennt jeder deine Subdomains – auch interne wie dns., git. oder nas. – und kann sie gezielt angreifen.",
            "Für interne Dienste ein Platzhalter-Zertifikat (*.domain) benutzen – so wie nrzNetwork unter HTTPS. Alte Namen bleiben sichtbar, verraten aber nur, dass es sie einmal gab.",
            named,
        ));
    }
    if !r.cert_emails.is_empty() {
        out.push(f(
            Severity::Medium,
            format!("{} E-Mail-Adresse(n) in Zertifikaten", r.cert_emails.len()),
            "Adressen in Zertifikaten sind öffentlich und dauerhaft – beliebt für Phishing und Spam.",
            "Für neue Zertifikate keine E-Mail im Namen verwenden (S/MIME- und manche Firmenzertifikate tun das).",
            r.cert_emails.clone(),
        ));
    }

    // Adressen
    let private: Vec<String> = r
        .addresses
        .iter()
        .filter(|a| a.private)
        .map(|a| a.ip.clone())
        .collect();
    if !private.is_empty() {
        let names = hosts_with(r, &private);
        out.push(f(
            Severity::Medium,
            "Interne Adressen im öffentlichen DNS".into(),
            "Öffentliche Einträge zeigen auf private Adressen (LAN oder VPN). Das verrät den Aufbau deines Netzes und welche Geräte es gibt.",
            "Diese Einträge bei Cloudflare löschen – im eigenen Netz beantwortet nrzNetwork die Namen ohnehin (Reverse Proxy oder eigene Zone).",
            names,
        ));
    }
    let home: Vec<String> = r
        .addresses
        .iter()
        .filter(|a| a.home)
        .map(|a| a.ip.clone())
        .collect();
    if !home.is_empty() {
        out.push(f(
            Severity::High,
            "Einträge zeigen auf deinen Anschluss zu Hause".into(),
            "Jeder sieht deine Heim-IP, kann deinen Internetanbieter und ungefähren Ort ablesen und deinen Router direkt angreifen.",
            "Bei Cloudflare den Proxy (orange Wolke) einschalten oder die Dienste über einen Cloudflare Tunnel oder NetBird statt über offene Ports anbieten.",
            hosts_with(r, &home),
        ));
    }
    let origin: Vec<SpyAddress> = r
        .addresses
        .iter()
        .filter(|a| !a.cdn && !a.private && !a.home)
        .cloned()
        .collect();
    let web_names: Vec<&SpyHost> = r
        .hosts
        .iter()
        .filter(|h| !h.sources.iter().all(|s| s == "mx"))
        .collect();
    let origin_ips: Vec<String> = origin.iter().map(|a| a.ip.clone()).collect();
    let exposed = hosts_with_filtered(&web_names, &origin_ips);
    if !exposed.is_empty() {
        let providers: BTreeSet<String> = origin
            .iter()
            .filter(|a| !a.provider.is_empty())
            .map(|a| a.provider.clone())
            .collect();
        out.push(f(
            Severity::Low,
            format!("Server direkt sichtbar ({})", if providers.is_empty() { "Hoster unbekannt".to_string() } else { providers.into_iter().collect::<Vec<_>>().join(", ") }),
            "Diese Namen zeigen ohne CDN direkt auf den Server – Hoster und Adresse sind bekannt, Angriffe treffen den Server selbst.",
            "Wenn möglich über Cloudflare (Proxy) leiten; sonst Firewall und Updates im Blick behalten.",
            exposed,
        ));
    }
    let risky: &[u16] = &[21, 23, 445, 1883, 3306, 3389, 5432, 5900, 6379, 9200, 27017];
    let mut ports_items = Vec::new();
    let mut worst = Severity::Info;
    for a in &r.addresses {
        if a.open_ports.is_empty() {
            continue;
        }
        let bad: Vec<u16> = a
            .open_ports
            .iter()
            .copied()
            .filter(|p| risky.contains(p))
            .collect();
        if !bad.is_empty() {
            worst = Severity::High;
        } else if a.open_ports.iter().any(|p| ![80, 443].contains(p)) && worst < Severity::Medium {
            worst = Severity::Medium;
        }
        ports_items.push(format!(
            "{}: {}",
            a.ip,
            a.open_ports
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if worst > Severity::Info {
        out.push(f(
            worst,
            "Offene Ports auf öffentlichen Adressen".into(),
            "Datenbanken, Fernwartung (RDP, VNC), SMB oder SSH im Internet werden ständig automatisch angegriffen. Hinweis: von innen geprüft – ein Router kann von aussen anders aussehen.",
            "Nur 80/443 öffnen; alles andere schliessen oder nur über NetBird erreichbar machen.",
            ports_items,
        ));
    }

    // Webserver
    let leaky: Vec<String> = r
        .hosts
        .iter()
        .filter(|h| {
            let s = h.server.to_lowercase();
            (!h.powered_by.is_empty()) || (s.chars().any(|c| c.is_ascii_digit()) && s.contains('/'))
        })
        .map(|h| {
            format!(
                "{}: {}{}",
                h.name,
                h.server,
                if h.powered_by.is_empty() {
                    String::new()
                } else {
                    format!(" · {}", h.powered_by)
                }
            )
        })
        .collect();
    if !leaky.is_empty() {
        out.push(f(
            Severity::Low,
            "Webserver verraten Software und Version".into(),
            "Mit Name und Version sucht ein Angreifer gezielt nach bekannten Lücken.",
            "Versionsangaben abschalten (z. B. nginx: server_tokens off; X-Powered-By entfernen).",
            leaky,
        ));
    }
    let no_hsts: Vec<String> = r
        .hosts
        .iter()
        .filter(|h| h.https && h.http_status > 0 && !h.hsts)
        .map(|h| h.name.clone())
        .collect();
    if !no_hsts.is_empty() {
        out.push(f(
            Severity::Low,
            "HTTPS ohne HSTS".into(),
            "Ohne HSTS kann ein Angreifer im selben WLAN Besucher auf unverschlüsseltes HTTP umlenken.",
            "Strict-Transport-Security setzen (bei Cloudflare: SSL/TLS → Edge-Zertifikate → HSTS).",
            no_hsts,
        ));
    }

    // Mail
    let spf = r.mail.spf.to_lowercase();
    if spf.is_empty() {
        out.push(f(Severity::Medium, "Kein SPF".into(), "Jeder kann E-Mails im Namen deiner Domain verschicken, ohne dass Empfänger es erkennen.", if r.mail.mx.is_empty() { "Für eine Domain ohne Mail: TXT „v=spf1 -all“ anlegen." } else { "TXT mit v=spf1 für deinen Mail-Anbieter anlegen, endend mit -all." }, vec![]));
    } else if spf.contains("+all") || spf.ends_with(" ?all") {
        out.push(f(
            Severity::High,
            "SPF erlaubt allen das Senden".into(),
            "„+all“/„?all“ macht SPF wirkungslos.",
            "Auf „-all“ (oder zumindest „~all“) umstellen.",
            vec![r.mail.spf.clone()],
        ));
    }
    let dmarc = r.mail.dmarc.to_lowercase();
    if dmarc.is_empty() {
        out.push(f(Severity::Medium, "Kein DMARC".into(), "Empfänger wissen nicht, was mit gefälschten Mails deiner Domain passieren soll – Phishing mit deinem Namen wird leichter.", "TXT _dmarc mit „v=DMARC1; p=quarantine“ (später p=reject) anlegen.", vec![]));
    } else if dmarc.contains("p=none") {
        out.push(f(
            Severity::Low,
            "DMARC nur beobachtend (p=none)".into(),
            "Gefälschte Mails werden trotzdem zugestellt.",
            "Nach einer Beobachtungszeit auf p=quarantine oder p=reject umstellen.",
            vec![r.mail.dmarc.clone()],
        ));
    }
    if !r.mail.mx.is_empty() {
        out.push(f(
            Severity::Info,
            format!(
                "Mail-Anbieter: {}",
                if r.mail.provider.is_empty() {
                    "unbekannt".to_string()
                } else {
                    r.mail.provider.clone()
                }
            ),
            "MX-Einträge sind öffentlich – Angreifer passen Phishing-Seiten an den Anbieter an.",
            "",
            r.mail.mx.clone(),
        ));
    }

    // DNS
    if !r.registration.dnssec {
        out.push(f(Severity::Low, "Kein DNSSEC".into(), "Antworten deiner Domain sind nicht signiert – gefälschte DNS-Antworten fallen Resolvern nicht auf.", "Bei Cloudflare: DNS → Einstellungen → DNSSEC aktivieren und den DS-Eintrag beim Registrar hinterlegen.", vec![]));
    }
    if !r.records.iter().any(|x| x.qtype == "CAA") {
        out.push(f(Severity::Low, "Kein CAA-Eintrag".into(), "Jede Zertifizierungsstelle darf Zertifikate für deine Domain ausstellen.", "CAA anlegen, z. B. 0 issue \"letsencrypt.org\" (und die Stellen, die Cloudflare nutzt).", vec![]));
    }
    if wildcard {
        out.push(f(Severity::Info, "Platzhalter im öffentlichen DNS (*)".into(), "Jeder beliebige Name löst auf – das verschleiert echte Subdomains, kann aber auch ungewollt Dienste erreichbar machen.", "", vec![format!("*.{d}")]));
    }
    if !r.dns_provider.is_empty() {
        out.push(f(
            Severity::Info,
            format!("DNS-Anbieter: {}", r.dns_provider),
            "Nameserver sind öffentlich – wer dort dein Konto übernimmt, kontrolliert die Domain.",
            "Beim DNS-Anbieter und Registrar Zwei-Faktor-Anmeldung einschalten.",
            r.name_servers.clone(),
        ));
    }
    if !r.services.is_empty() {
        out.push(f(Severity::Info, format!("{} Dienste über TXT-Einträge erkennbar", r.services.len()), "Verifizierungs- und SPF-Einträge zeigen, welche Dienste du nutzt – nützlich für gezieltes Phishing.", "Nicht mehr benötigte Verifizierungs-Einträge löschen.", r.services.clone()));
    }

    // Registrierung
    if !r.registration.contacts.is_empty() {
        out.push(f(
            Severity::Medium,
            "Kontaktdaten im Registrierungseintrag".into(),
            "Name und E-Mail im öffentlichen RDAP/WHOIS sind ein Einstieg für Social Engineering.",
            "Beim Registrar den Datenschutz (Privacy/Redaction) einschalten.",
            r.registration.contacts.clone(),
        ));
    }
    if r.registration.expires > 0 {
        let days = (r.registration.expires - r.scanned_at) / 86_400;
        if days < 30 {
            out.push(f(Severity::High, format!("Domain läuft in {days} Tagen ab"), "Abgelaufene Domains werden sofort von Fremden registriert – samt deinen Mails und Diensten.", "Beim Registrar automatische Verlängerung einschalten.", vec![]));
        }
    }
    if !r.registration.registrar.is_empty() {
        out.push(f(
            Severity::Info,
            format!("Registrar: {}", r.registration.registrar),
            "Öffentlich sichtbar; wer dein Konto dort übernimmt, kann die Domain umziehen.",
            "Zwei-Faktor-Anmeldung und Transfersperre beim Registrar.",
            vec![],
        ));
    }

    out.sort_by_key(|f| std::cmp::Reverse(f.severity));
    out
}

fn hosts_with(r: &SpyReport, ips: &[String]) -> Vec<String> {
    let all: Vec<&SpyHost> = r.hosts.iter().collect();
    hosts_with_filtered(&all, ips)
}

fn hosts_with_filtered(hosts: &[&SpyHost], ips: &[String]) -> Vec<String> {
    let mut out: Vec<String> = hosts
        .iter()
        .filter_map(|h| {
            let hit: Vec<&String> = h.addresses.iter().filter(|a| ips.contains(a)).collect();
            (!hit.is_empty()).then(|| {
                format!(
                    "{} → {}",
                    h.name,
                    hit.iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
        })
        .collect();
    out.sort();
    out
}

pub fn score(findings: &[SpyFinding]) -> u8 {
    let minus: u32 = findings
        .iter()
        .map(|f| match f.severity {
            Severity::High => 25,
            Severity::Medium => 12,
            Severity::Low => 5,
            Severity::Info => 0,
        })
        .sum();
    100u32.saturating_sub(minus) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrzdns_types::SpyMail;
    use serde_json::json;

    #[test]
    fn crtsh() {
        let v = json!([
            { "id": 1, "issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": "zweers.ch", "name_value": "zweers.ch\nwww.zweers.ch", "not_before": "2025-01-01T00:00:00" },
            { "id": 2, "issuer_name": "C=US, O=Let's Encrypt, CN=E6", "common_name": "*.zweers.ch", "name_value": "*.zweers.ch\nzweers.ch", "not_before": "2026-11-14T15:53:16" },
            { "id": 3, "issuer_name": "C=BE, O=GlobalSign nv-sa, CN=X", "common_name": "nico@zweers.ch", "name_value": "nico@zweers.ch\ngit.zweers.ch\nevil.example.com", "not_before": "2024-06-01T00:00:00.123" }
        ]);
        let (names, emails, count) = parse_crtsh(&v, "zweers.ch");
        assert_eq!(count, 3);
        assert_eq!(emails, ["nico@zweers.ch"]);
        let n: Vec<&str> = names.iter().map(|x| x.name.as_str()).collect();
        assert!(
            n.contains(&"git.zweers.ch")
                && n.contains(&"*.zweers.ch")
                && !n.contains(&"evil.example.com")
        );
        let apex = names.iter().find(|x| x.name == "zweers.ch").unwrap();
        assert_eq!(
            apex.certificates, 2,
            "je Zertifikat einmal, auch wenn der Name doppelt drinsteht"
        );
        assert_eq!(apex.issuers, ["Let's Encrypt"]);
        assert!(apex.first_seen < apex.last_seen);
    }

    #[test]
    fn rdap() {
        let v = json!({
            "secureDNS": { "delegationSigned": true },
            "status": ["active"],
            "events": [
                { "eventAction": "registration", "eventDate": "2015-03-02T10:00:00Z" },
                { "eventAction": "expiration", "eventDate": "2027-03-02T10:00:00Z" }
            ],
            "entities": [
                { "roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Hostpoint AG"]]] },
                { "roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"], ["email", {}, "text", "nico@zweers.ch"]]] }
            ]
        });
        let r = parse_rdap_domain(&v, "rdap.nic.ch");
        assert!(r.dnssec);
        assert_eq!(r.registrar, "Hostpoint AG");
        assert_eq!(r.contacts, ["registrant: nico@zweers.ch"]);
        assert!(r.expires > r.created && r.created > 0);
        let ip = json!({ "name": "CLOUDFLARENET", "country": "US", "cidr0_cidrs": [{ "v4prefix": "104.16.0.0", "length": 13 }],
            "entities": [{ "roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc."]]] }] });
        let (p, n, c) = parse_rdap_ip(&ip);
        assert_eq!((p.as_str(), c.as_str()), ("Cloudflare, Inc.", "US"));
        assert_eq!(n, "CLOUDFLARENET (104.16.0.0/13)");
        assert!(is_cdn(&p));
    }

    #[test]
    fn whois_texts() {
        let ch = "Domain name:\nzweers.ch\n\nHolder of domain name:\nThe domain holder is not public.\n\nRegistrar:\nHostinger operations, UAB\n\nFirst registration date:\n2019-05-12\n\nDNSSEC:Y\n\nName servers:\nalbert.ns.cloudflare.com\n";
        let r = parse_whois(ch, "ch.whois-servers.net");
        assert_eq!(r.registrar, "Hostinger operations, UAB");
        assert!(r.created > 0 && r.dnssec);
        assert!(r.contacts.is_empty(), "{:?}", r.contacts);
        let com = "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar, Inc.\nCreation Date: 1995-08-14T04:00:00Z\nRegistry Expiry Date: 2027-08-13T04:00:00Z\nDNSSEC: unsigned\nRegistrant Email: REDACTED FOR PRIVACY\nRegistrant Name: Max Muster\n";
        let r = parse_whois(com, "com.whois-servers.net");
        assert_eq!(r.registrar, "Example Registrar, Inc.");
        assert!(r.expires > r.created && !r.dnssec);
        assert_eq!(r.contacts, ["registrant name: Max Muster"]);
        assert_eq!(mx_host("10 mx2.hostinger.com."), "mx2.hostinger.com");
        assert_eq!(
            mail_provider(&["mx1.hostinger.com".into()], ""),
            "Hostinger"
        );
    }

    #[test]
    fn providers_and_services() {
        assert_eq!(
            dns_provider(&[
                "ada.ns.cloudflare.com".into(),
                "bob.ns.cloudflare.com".into()
            ]),
            "Cloudflare"
        );
        assert_eq!(
            mail_provider(&["route1.mx.cloudflare.net".into()], ""),
            "Cloudflare Email Routing"
        );
        assert_eq!(
            mail_provider(&[], "v=spf1 include:_spf.google.com -all"),
            "Google Workspace"
        );
        let s = services_from_txt(&[
            "google-site-verification=abc".into(),
            "MS=ms123".into(),
            "v=spf1 include:_spf.mx.cloudflare.net ~all".into(),
        ]);
        assert_eq!(
            s,
            [
                "Cloudflare Email Routing",
                "Google (Search Console/Workspace)",
                "Microsoft 365"
            ]
        );
        assert_eq!(txt_unquote("\"v=spf1 \" \"-all\""), "v=spf1 -all");
        assert!(is_internal("192.168.0.198".parse().unwrap()));
        assert!(is_internal("100.78.107.162".parse().unwrap()));
        assert!(!is_internal("104.16.1.1".parse().unwrap()));
    }

    #[test]
    fn findings_and_score() {
        let r = SpyReport {
            domain: "zweers.ch".into(),
            scanned_at: 1_000_000,
            cert_names: vec![
                SpyCertName {
                    name: "git.zweers.ch".into(),
                    ..Default::default()
                },
                SpyCertName {
                    name: "*.zweers.ch".into(),
                    ..Default::default()
                },
            ],
            addresses: vec![
                SpyAddress {
                    ip: "192.168.0.198".into(),
                    private: true,
                    ..Default::default()
                },
                SpyAddress {
                    ip: "85.1.2.3".into(),
                    home: true,
                    open_ports: vec![443, 3306],
                    ..Default::default()
                },
            ],
            hosts: vec![
                SpyHost {
                    name: "nas.zweers.ch".into(),
                    addresses: vec!["192.168.0.198".into()],
                    sources: vec!["ct".into()],
                    ..Default::default()
                },
                SpyHost {
                    name: "zweers.ch".into(),
                    addresses: vec!["85.1.2.3".into()],
                    sources: vec!["dns".into()],
                    https: true,
                    http_status: 200,
                    server: "nginx/1.25.3".into(),
                    ..Default::default()
                },
            ],
            mail: SpyMail {
                spf: "v=spf1 +all".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let f = findings(&r, false);
        let titles: Vec<&str> = f.iter().map(|x| x.title.as_str()).collect();
        assert_eq!(f[0].severity, Severity::High);
        for t in [
            "Einträge zeigen auf deinen Anschluss zu Hause",
            "Interne Adressen im öffentlichen DNS",
            "Offene Ports auf öffentlichen Adressen",
            "SPF erlaubt allen das Senden",
            "Kein DMARC",
            "Kein DNSSEC",
            "Kein CAA-Eintrag",
            "Webserver verraten Software und Version",
            "HTTPS ohne HSTS",
            "1 Namen in öffentlichen Zertifikaten",
        ] {
            assert!(titles.contains(&t), "{t} fehlt in {titles:?}");
        }
        let home = f.iter().find(|x| x.title.contains("zu Hause")).unwrap();
        assert_eq!(home.items, ["zweers.ch → 85.1.2.3"]);
        assert!(score(&f) < 30);
        assert_eq!(score(&[]), 100);
    }
}
