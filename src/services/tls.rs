//! HTTPS für eigene Domains: Zertifikat von Let's Encrypt über ACME mit DNS-Nachweis
//! (`dns-01`) bei Cloudflare. Ablauf:
//!
//! 1. ACME-Konto laden oder anlegen (`tls/account.json`).
//! 2. Auftrag für die Namen (z. B. `zweers.ch`, `*.zweers.ch`).
//! 3. Je Name einen TXT-Eintrag `_acme-challenge.<name>` über die Cloudflare-API anlegen und
//!    warten, bis Cloudflares Nameserver ihn ausliefern.
//! 4. Let's Encrypt prüfen lassen, Zertifikat holen, TXT-Einträge wieder löschen.
//! 5. Zertifikat und Schlüssel unter `tls/` speichern und sofort im Proxy benutzen.
//!
//! Das Zertifikat wird erneuert, wenn weniger als ein Drittel der Laufzeit übrig ist.

use crate::config::Config;
use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::proxy::tls::{load_pem, LoadedCert};
use crate::proxy::ProxyState;
use crate::services::settings;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use nrzdns_engine::Engine;
use nrzdns_types::{
    normalize_domain, CertificateInfo, ResolveInput, TlsSettings, TlsSettingsInput, TlsStatus,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

const SETTINGS: &str = "tls";
/// Schalter für den Umbrel-Wächter: `on` = Port 443 an den Proxy geben.
pub const TLS_FLAG: &str = "tls-active";
/// Nach einem Fehlschlag frühestens so viel später automatisch wieder (Let's Encrypt
/// begrenzt fehlgeschlagene Prüfungen).
const RETRY_AFTER: i64 = 6 * 3600;

/// Gespeichert: Einstellungen und Token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Stored {
    #[serde(flatten)]
    settings: TlsSettings,
    /// Früher hier, jetzt bei den Verbindungen (wird dorthin übernommen).
    #[serde(skip_serializing_if = "String::is_empty")]
    cloudflare_token: String,
}

async fn stored(pool: &SqlitePool) -> AppResult<Stored> {
    Ok(settings::get(pool, SETTINGS).await?.unwrap_or_default())
}

pub async fn settings(pool: &SqlitePool) -> AppResult<TlsSettings> {
    Ok(stored(pool).await?.settings)
}

fn dir(data_dir: &Path) -> PathBuf {
    data_dir.join("tls")
}

/// Namen prüfen: `zweers.ch` oder `*.zweers.ch`, klein, ohne Doppelte, höchstens 10.
pub fn normalize_names(input: &[String]) -> AppResult<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for raw in input.iter().flat_map(|d| d.split([',', ' ', '\n'])) {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let (wild, rest) = match raw.strip_prefix("*.") {
            Some(r) => (true, r),
            None => (false, raw),
        };
        let name = Some(rest)
            .filter(|r| !r.contains('*'))
            .and_then(normalize_domain)
            .filter(|n| n.contains('.'))
            .ok_or_else(|| {
                AppError::bad(format!(
                    "„{raw}“ ist kein gültiger Name (z. B. zweers.ch oder *.zweers.ch)."
                ))
            })?;
        let name = if wild { format!("*.{name}") } else { name };
        if !out.contains(&name) {
            out.push(name);
        }
    }
    if out.len() > 10 {
        return Err(AppError::bad("Höchstens 10 Namen pro Zertifikat."));
    }
    Ok(out)
}

pub async fn save(
    pool: &SqlitePool,
    state: &ProxyState,
    data_dir: &Path,
    input: &TlsSettingsInput,
) -> AppResult<TlsSettings> {
    let mut s = stored(pool).await?;
    let domains = normalize_names(&input.settings.domains)?;
    let email = input.settings.email.trim().to_string();
    if !email.is_empty()
        && (!email.contains('@') || email.contains([' ', ',', ';']) || email.len() > 200)
    {
        return Err(AppError::bad("E-Mail: bitte eine gültige Adresse angeben."));
    }
    // Altes Token zu den Verbindungen übernehmen und hier nicht mehr speichern
    crate::services::integrations::cloudflare_token(pool).await?;
    s.cloudflare_token.clear();
    let token = input.cloudflare_token.trim();
    if !token.is_empty() && !input.clear_token {
        crate::services::integrations::set_cloudflare_token(pool, token).await?;
    }
    if input.settings.enabled && domains.is_empty() {
        return Err(AppError::bad(
            "Bitte mindestens einen Namen angeben, z. B. *.zweers.ch.",
        ));
    }
    s.settings = TlsSettings {
        enabled: input.settings.enabled,
        domains,
        email,
        staging: input.settings.staging,
        redirect_http: input.settings.redirect_http,
    };
    settings::set(pool, SETTINGS, &s).await?;
    apply(state, data_dir, &s.settings);
    Ok(s.settings)
}

/// Einstellungen im Proxy übernehmen und den Schalter für den Wächter schreiben.
pub fn apply(state: &ProxyState, data_dir: &Path, settings: &TlsSettings) {
    let tls = state.tls();
    tls.redirect.store(
        settings.enabled && settings.redirect_http,
        Ordering::Relaxed,
    );
    if !settings.enabled {
        tls.set_cert(None);
    } else if tls.cert().is_none() {
        if let Some(c) = read_cert(data_dir) {
            tls.set_cert(Some(c));
        }
    }
    let active = settings.enabled && tls.cert().is_some();
    let value = if active { "on\n" } else { "off\n" };
    if let Err(e) = std::fs::write(data_dir.join(TLS_FLAG), value) {
        tracing::warn!("{TLS_FLAG} schreiben: {e}");
    }
}

fn read_cert(data_dir: &Path) -> Option<LoadedCert> {
    let d = dir(data_dir);
    let cert = std::fs::read_to_string(d.join("cert.pem")).ok()?;
    let key = std::fs::read_to_string(d.join("key.pem")).ok()?;
    match load_pem(&cert, &key) {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!("HTTPS: gespeichertes Zertifikat unbrauchbar: {e}");
            None
        }
    }
}

/// Beim Start: Einstellungen und gespeichertes Zertifikat laden.
pub async fn load(pool: &SqlitePool, state: &ProxyState, data_dir: &Path) -> AppResult<()> {
    let s = settings(pool).await?;
    apply(state, data_dir, &s);
    if let Some(c) = state.tls().cert() {
        tracing::info!(names = ?c.names, "HTTPS-Zertifikat geladen");
    }
    Ok(())
}

pub async fn status(
    pool: &SqlitePool,
    state: &ProxyState,
    config: &Config,
) -> AppResult<TlsStatus> {
    let s = stored(pool).await?;
    let tls = state.tls();
    Ok(TlsStatus {
        settings: s.settings,
        token_set: !crate::services::integrations::cloudflare_token(pool)
            .await?
            .is_empty(),
        certificate: tls.cert().map(|c| CertificateInfo {
            names: c.names,
            issuer: c.issuer,
            not_before: c.not_before,
            not_after: c.not_after,
        }),
        issuing: tls.issuing.load(Ordering::Relaxed),
        progress: tls.progress(),
        last_error: tls.last_error(),
        last_attempt: tls.last_attempt.load(Ordering::Relaxed),
        listen: config
            .proxy_tls_listen
            .iter()
            .map(ToString::to_string)
            .collect(),
        listen_errors: tls.listen_errors(),
    })
}

pub async fn remove_certificate(
    state: &ProxyState,
    data_dir: &Path,
    pool: &SqlitePool,
) -> AppResult<()> {
    let d = dir(data_dir);
    for f in ["cert.pem", "key.pem"] {
        match std::fs::remove_file(d.join(f)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(AppError::Config(format!("{f} löschen: {e}"))),
        }
    }
    state.tls().set_cert(None);
    apply(state, data_dir, &settings(pool).await?);
    Ok(())
}

/// Muss erneuert werden? (Kein Zertifikat, andere Namen oder weniger als ein Drittel übrig.)
fn needs_renewal(cert: Option<&LoadedCert>, wanted: &[String], now: i64) -> bool {
    let Some(c) = cert else { return true };
    let mut have = c.names.clone();
    let mut want = wanted.to_vec();
    have.sort();
    want.sort();
    if have != want {
        return true;
    }
    let lifetime = (c.not_after - c.not_before).max(86_400);
    c.not_after - now < lifetime / 3
}

/// Zertifikat holen, falls nötig (Hintergrund, stündlich).
pub async fn maybe_renew(pool: &SqlitePool, engine: &Engine, state: &ProxyState, config: &Config) {
    let Ok(s) = stored(pool).await else { return };
    let token = crate::services::integrations::cloudflare_token(pool)
        .await
        .unwrap_or_default();
    if !s.settings.enabled || token.is_empty() || s.settings.domains.is_empty() {
        return;
    }
    let tls = state.tls();
    let t = now();
    if !needs_renewal(tls.cert().as_ref(), &s.settings.domains, t) {
        return;
    }
    let failed_recently =
        !tls.last_error().is_empty() && t - tls.last_attempt.load(Ordering::Relaxed) < RETRY_AFTER;
    if failed_recently {
        return;
    }
    tracing::info!("HTTPS: Zertifikat wird erneuert");
    let _ = issue(pool, engine, state, config).await;
}

/// Zertifikat jetzt holen. Läuft schon ein Versuch, kommt sofort ein Fehler.
pub async fn issue(
    pool: &SqlitePool,
    engine: &Engine,
    state: &ProxyState,
    config: &Config,
) -> AppResult<()> {
    let tls = state.tls();
    if tls.issuing.swap(true, Ordering::SeqCst) {
        return Err(AppError::Conflict(
            "Es wird schon ein Zertifikat geholt.".into(),
        ));
    }
    tls.progress.lock().map(|mut p| p.clear()).ok();
    tls.last_attempt.store(now(), Ordering::Relaxed);
    let result = run(pool, engine, state, config).await;
    match &result {
        Ok(()) => {
            *tls.last_error
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = String::new();
        }
        Err(e) => {
            let msg = e.to_string();
            tracing::warn!("HTTPS: {msg}");
            tls.set_progress(format!("Fehlgeschlagen: {msg}"));
            *tls.last_error
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = msg;
        }
    }
    tls.issuing.store(false, Ordering::SeqCst);
    result
}

fn acme_err(step: &str) -> impl Fn(instant_acme::Error) -> AppError + '_ {
    move |e| AppError::BadGateway(format!("{step}: {e}"))
}

async fn account(config: &Config, s: &TlsSettings) -> AppResult<Account> {
    let d = dir(&config.data_dir);
    let directory = config.acme_directory.clone().unwrap_or_else(|| {
        if s.staging {
            LetsEncrypt::Staging.url().to_string()
        } else {
            LetsEncrypt::Production.url().to_string()
        }
    });
    let builder = || acme_http(config.acme_root.as_deref()).map(Account::builder_with_http);
    // Je Server ein eigenes Konto (Staging und Produktion sind getrennt)
    let file = d.join(format!("account-{:016x}.json", fnv(&directory)));
    if let Ok(raw) = std::fs::read_to_string(&file) {
        if let Ok(creds) = serde_json::from_str::<AccountCredentials>(&raw) {
            return builder()
                .map_err(acme_err("ACME"))?
                .from_credentials(creds)
                .await
                .map_err(acme_err("ACME-Konto laden"));
        }
    }
    let contact = (!s.email.is_empty()).then(|| format!("mailto:{}", s.email));
    let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (account, creds) = builder()
        .map_err(acme_err("ACME"))?
        .create(
            &NewAccount {
                contact: &contacts,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory,
            None,
        )
        .await
        .map_err(acme_err("ACME-Konto anlegen"))?;
    let raw = serde_json::to_string(&creds).map_err(|e| AppError::Config(e.to_string()))?;
    write_private(&file, &raw)?;
    Ok(account)
}

/// HTTP-Client für ACME: eingebaute Stammzertifikate (Mozilla, `webpki-roots`) – der
/// Container hat keinen Zertifikatsspeicher –, dazu optional eine eigene Stelle (Tests).
fn acme_http(
    extra_root: Option<&Path>,
) -> Result<Box<dyn instant_acme::HttpClient>, instant_acme::Error> {
    let other = |e: String| instant_acme::Error::Other(e.into());
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = extra_root {
        let pem = std::fs::read(path).map_err(|e| other(format!("{}: {e}", path.display())))?;
        for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
            let cert = cert.map_err(|e| other(e.to_string()))?;
            roots.add(cert).map_err(|e| other(e.to_string()))?;
        }
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| other(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();
    let client: hyper_util::client::legacy::Client<_, instant_acme::BodyWrapper<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector);
    Ok(Box::new(client))
}

fn fnv(s: &str) -> u64 {
    s.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    })
}

/// Datei nur für den Besitzer lesbar schreiben.
fn write_private(path: &Path, content: &str) -> AppResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| AppError::Config(format!("{}: {e}", parent.display())))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content)
        .map_err(|e| AppError::Config(format!("{}: {e}", tmp.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, path).map_err(|e| AppError::Config(format!("{}: {e}", path.display())))
}

async fn run(
    pool: &SqlitePool,
    engine: &Engine,
    state: &ProxyState,
    config: &Config,
) -> AppResult<()> {
    let tls = state.tls();
    let s = stored(pool).await?;
    if s.settings.domains.is_empty() {
        return Err(AppError::bad(
            "Bitte zuerst die Namen eintragen, z. B. *.zweers.ch.",
        ));
    }
    let token = crate::services::integrations::cloudflare_token(pool).await?;
    if token.is_empty() {
        return Err(AppError::bad(
            "Bitte zuerst ein Cloudflare-API-Token eintragen.",
        ));
    }
    let cf = Cloudflare::new(&config.cloudflare_api, &token)?;

    tls.set_progress("Cloudflare: Zone suchen");
    let zone = cf.zone_for(&s.settings.domains[0]).await?;
    tls.set_progress(format!("Cloudflare: Zone {} gefunden", zone.name));
    for d in &s.settings.domains {
        let base = d.trim_start_matches("*.");
        if base != zone.name && !base.ends_with(&format!(".{}", zone.name)) {
            return Err(AppError::bad(format!(
                "„{d}“ gehört nicht zur Cloudflare-Zone {} – ein Zertifikat je Zone.",
                zone.name
            )));
        }
    }

    tls.set_progress(if s.settings.staging {
        "Let's Encrypt (Staging): Konto"
    } else {
        "Let's Encrypt: Konto"
    });
    let account = account(config, &s.settings).await?;
    let ids: Vec<Identifier> = s
        .settings
        .domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();
    let mut order = account
        .new_order(&NewOrder::new(&ids))
        .await
        .map_err(acme_err("Auftrag"))?;

    // TXT-Einträge anlegen (alte von früheren Versuchen vorher weg)
    let mut records: Vec<(String, String)> = Vec::new();
    {
        let mut auths = order.authorizations();
        while let Some(a) = auths.next().await {
            let mut a = a.map_err(acme_err("Prüfungen"))?;
            match a.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                other => {
                    return Err(AppError::BadGateway(format!(
                        "Prüfung in unerwartetem Zustand: {other:?}"
                    )))
                }
            }
            let ch = a.challenge(ChallengeType::Dns01).ok_or_else(|| {
                AppError::BadGateway("Let's Encrypt bietet keine DNS-Prüfung an.".into())
            })?;
            let Identifier::Dns(base) = ch.identifier().identifier.clone() else {
                continue;
            };
            records.push((
                format!("_acme-challenge.{base}"),
                ch.key_authorization().dns_value(),
            ));
        }
    }
    let mut created: Vec<String> = Vec::new();
    let result = async {
        let mut cleaned = std::collections::HashSet::new();
        for (name, _) in &records {
            if cleaned.insert(name.clone()) {
                cf.delete_txt(&zone.id, name, None).await?;
            }
        }
        for (name, value) in &records {
            tls.set_progress(format!("Cloudflare: TXT-Eintrag {name}"));
            created.push(cf.create_txt(&zone.id, name, value).await?);
        }
        if config.acme_dns_check && !records.is_empty() {
            tls.set_progress("Warten, bis Cloudflare den Eintrag ausliefert");
            wait_for_txt(engine, &zone.name_servers, &records).await;
        }

        tls.set_progress("Let's Encrypt prüft");
        {
            let mut auths = order.authorizations();
            while let Some(a) = auths.next().await {
                let mut a = a.map_err(acme_err("Prüfungen"))?;
                if a.status != AuthorizationStatus::Pending {
                    continue;
                }
                if let Some(mut ch) = a.challenge(ChallengeType::Dns01) {
                    ch.set_ready().await.map_err(acme_err("Prüfung starten"))?;
                }
            }
        }
        let retry = RetryPolicy::new().timeout(Duration::from_secs(180));
        let status = order
            .poll_ready(&retry)
            .await
            .map_err(acme_err("Prüfung"))?;
        if status != OrderStatus::Ready {
            let detail = failed_detail(&mut order).await;
            return Err(AppError::BadGateway(format!(
                "Let's Encrypt hat die Prüfung nicht bestanden ({status:?}){detail}"
            )));
        }
        tls.set_progress("Zertifikat ausstellen");
        let key_pem = order
            .finalize()
            .await
            .map_err(acme_err("Zertifikat anfordern"))?;
        let cert_pem = order
            .poll_certificate(&retry)
            .await
            .map_err(acme_err("Zertifikat abholen"))?;
        Ok::<_, AppError>((cert_pem, key_pem))
    }
    .await;

    // Aufräumen – auch nach Fehlern
    for id in &created {
        if let Err(e) = cf.delete_record(&zone.id, id).await {
            tracing::warn!("Cloudflare: TXT-Eintrag löschen: {e}");
        }
    }
    let (cert_pem, key_pem) = result?;

    let loaded = load_pem(&cert_pem, &key_pem).map_err(AppError::BadGateway)?;
    let d = dir(&config.data_dir);
    write_private(&d.join("key.pem"), &key_pem)?;
    write_private(&d.join("cert.pem"), &cert_pem)?;
    let until = time::OffsetDateTime::from_unix_timestamp(loaded.not_after)
        .map(|t| t.date().to_string())
        .unwrap_or_default();
    tls.set_progress(format!("Fertig: gültig bis {until}"));
    tls.set_cert(Some(loaded));
    apply(state, &config.data_dir, &s.settings);
    Ok(())
}

async fn failed_detail(order: &mut instant_acme::Order) -> String {
    let mut out = String::new();
    let mut auths = order.authorizations();
    while let Some(Ok(a)) = auths.next().await {
        for ch in &a.challenges {
            if let Some(err) = &ch.error {
                out.push_str(&format!(": {}", err.detail.clone().unwrap_or_default()));
            }
        }
    }
    out
}

/// Bei Cloudflares Nameservern direkt nachfragen, bis alle Werte da sind (höchstens 2 Min.).
async fn wait_for_txt(engine: &Engine, name_servers: &[String], records: &[(String, String)]) {
    let mut servers = Vec::new();
    for ns in name_servers.iter().take(2) {
        if let Ok(r) = engine
            .resolve(&ResolveInput {
                name: ns.clone(),
                qtype: "A".into(),
                ..ResolveInput::default()
            })
            .await
        {
            if let Some(a) = r.answers.iter().find(|a| a.qtype == "A") {
                servers.push(a.data.clone());
            }
        }
    }
    if servers.is_empty() {
        tokio::time::sleep(Duration::from_secs(20)).await;
        return;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let mut all = true;
        'outer: for server in &servers {
            for (name, value) in records {
                let seen = engine
                    .resolve(&ResolveInput {
                        name: name.clone(),
                        qtype: "TXT".into(),
                        server: server.clone(),
                        ..ResolveInput::default()
                    })
                    .await
                    .map(|r| r.answers.iter().any(|a| a.data.contains(value.as_str())))
                    .unwrap_or(false);
                if !seen {
                    all = false;
                    break 'outer;
                }
            }
        }
        if all || tokio::time::Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// Zone bei Cloudflare.
#[derive(Debug, Clone)]
pub struct Zone {
    pub id: String,
    pub name: String,
    pub name_servers: Vec<String>,
}

/// Kleiner Client für die Cloudflare-API (nur DNS-Einträge).
pub struct Cloudflare {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl Cloudflare {
    pub fn new(base: &str, token: &str) -> AppResult<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("nrzNetwork/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| AppError::Config(e.to_string()))?;
        Ok(Self {
            http,
            base: base.trim_end_matches('/').to_string(),
            token: token.to_string(),
        })
    }

    async fn call(&self, req: reqwest::RequestBuilder) -> AppResult<Value> {
        let resp = req
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| AppError::BadGateway(format!("Cloudflare nicht erreichbar: {e}")))?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if status.is_success() && body["success"].as_bool() != Some(false) {
            return Ok(body);
        }
        let msg = body["errors"]
            .as_array()
            .map(|e| {
                e.iter()
                    .filter_map(|x| x["message"].as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| status.to_string());
        let hint = if status.as_u16() == 401 || status.as_u16() == 403 {
            " – stimmt das Token, und hat es das Recht „Zone → DNS → Bearbeiten“ für diese Zone?"
        } else {
            ""
        };
        Err(AppError::BadGateway(format!("Cloudflare: {msg}{hint}")))
    }

    /// Zone zu einem Namen: `a.b.zweers.ch` → versucht `a.b.zweers.ch`, `b.zweers.ch`, `zweers.ch`.
    pub async fn zone_for(&self, name: &str) -> AppResult<Zone> {
        let name = name.trim_start_matches("*.");
        let labels: Vec<&str> = name.split('.').collect();
        for i in 0..labels.len().saturating_sub(1) {
            let candidate = labels[i..].join(".");
            let body = self
                .call(
                    self.http
                        .get(format!("{}/zones", self.base))
                        .query(&[("name", candidate.as_str())]),
                )
                .await?;
            if let Some(z) = body["result"].as_array().and_then(|r| r.first()) {
                return Ok(Zone {
                    id: z["id"].as_str().unwrap_or_default().to_string(),
                    name: z["name"].as_str().unwrap_or(&candidate).to_string(),
                    name_servers: z["name_servers"]
                        .as_array()
                        .map(|n| {
                            n.iter()
                                .filter_map(|x| x.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default(),
                });
            }
        }
        Err(AppError::bad(format!(
            "Cloudflare: keine Zone für „{name}“ gefunden – liegt die Domain bei Cloudflare, und darf das Token sie sehen?"
        )))
    }

    /// TXT-Eintrag anlegen, liefert seine ID.
    pub async fn create_txt(&self, zone: &str, name: &str, value: &str) -> AppResult<String> {
        let body = self
            .call(self.http.post(format!("{}/zones/{zone}/dns_records", self.base)).json(&json!({
                "type": "TXT",
                "name": name,
                "content": format!("\"{value}\""),
                "ttl": 120,
                "comment": "nrzNetwork: Let's-Encrypt-Prüfung (wird gleich wieder gelöscht)",
            })))
            .await?;
        Ok(body["result"]["id"]
            .as_str()
            .unwrap_or_default()
            .to_string())
    }

    /// TXT-Einträge mit diesem Namen löschen (optional nur mit diesem Wert).
    pub async fn delete_txt(&self, zone: &str, name: &str, value: Option<&str>) -> AppResult<()> {
        let body = self
            .call(
                self.http
                    .get(format!("{}/zones/{zone}/dns_records", self.base))
                    .query(&[("type", "TXT"), ("name", name)]),
            )
            .await?;
        for r in body["result"].as_array().into_iter().flatten() {
            let content = r["content"].as_str().unwrap_or_default();
            if value.is_some_and(|v| !content.contains(v)) {
                continue;
            }
            if let Some(id) = r["id"].as_str() {
                self.delete_record(zone, id).await?;
            }
        }
        Ok(())
    }

    pub async fn delete_record(&self, zone: &str, id: &str) -> AppResult<()> {
        if id.is_empty() {
            return Ok(());
        }
        self.call(
            self.http
                .delete(format!("{}/zones/{zone}/dns_records/{id}", self.base)),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(
            normalize_names(&["Zweers.CH, *.zweers.ch".into(), "zweers.ch".into()]).unwrap(),
            ["zweers.ch", "*.zweers.ch"]
        );
        assert!(normalize_names(&["*.*.zweers.ch".into()]).is_err());
        assert!(normalize_names(&["ch".into()]).is_err());
        assert!(normalize_names(&["a b.ch".into()]).is_err());
    }

    /// Let's Encrypt (Staging) mit den eingebauten Stammzertifikaten erreichen – auch ohne
    /// Zertifikatsspeicher im System (`cargo test -- --ignored`, braucht Internet).
    #[tokio::test]
    #[ignore]
    async fn reaches_lets_encrypt_without_system_roots() {
        let http = acme_http(None).unwrap();
        let request = http::Request::get(LetsEncrypt::Staging.url())
            .body(instant_acme::BodyWrapper::default())
            .unwrap();
        let resp = http.request(request).await.unwrap();
        assert_eq!(resp.parts.status, 200);
    }

    #[test]
    fn renewal() {
        let cert = |nb: i64, na: i64, names: &[&str]| LoadedCert {
            key: std::sync::Arc::new(rustls::sign::CertifiedKey::new(
                vec![],
                rustls::crypto::ring::default_provider()
                    .key_provider
                    .load_private_key(rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rcgen::KeyPair::generate().unwrap().serialize_der().into(),
                    ))
                    .unwrap(),
            )),
            names: names.iter().map(|s| s.to_string()).collect(),
            issuer: String::new(),
            not_before: nb,
            not_after: na,
        };
        let want = vec!["*.zweers.ch".to_string(), "zweers.ch".to_string()];
        let day = 86_400;
        let c = cert(0, 90 * day, &["zweers.ch", "*.zweers.ch"]);
        assert!(!needs_renewal(Some(&c), &want, 10 * day));
        assert!(needs_renewal(Some(&c), &want, 61 * day));
        assert!(needs_renewal(Some(&c), &["zweers.ch".into()], 10 * day));
        assert!(needs_renewal(None, &want, 0));
    }
}
