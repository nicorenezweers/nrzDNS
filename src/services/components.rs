//! Komponenten, die nrzNetwork selbst betreibt:
//!
//! * **Cloudflare Tunnel** (`cloudflared`): macht Einträge des Reverse Proxys öffentlich
//!   erreichbar, ohne Ports zu öffnen. Mit Cloudflare-Verbindung verwaltet nrzNetwork die
//!   öffentlichen Namen des Tunnels selbst (Regel + DNS-Eintrag je freigegebenem Eintrag,
//!   fremde Regeln bleiben).
//! * **NetBird** (`netbird`, rootless im Netstack-Modus ohne Sonderrechte): nrzNetwork wird
//!   selbst ein Gerät im NetBird-Netz; Anfragen an seine NetBird-Adresse landen beim Proxy
//!   bzw. beim DNS-Server.
//!
//! Beide Programme lädt nrzNetwork von GitHub (offizielle Releases, SHA-256 geprüft) nach
//! `data/bin/`, startet sie, startet sie nach Abstürzen neu und spielt täglich zur
//! eingestellten Stunde neue Versionen ein.

use crate::config::Config;
use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::services::{integrations, settings};
use base64::Engine as _;
use nrzdns_types::{ComponentStatus, ComponentsInput, ComponentsSettings, ComponentsStatus};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::watch;

const SETTINGS: &str = "components";
const LOG_LINES: usize = 200;
/// Metrik-Adresse von cloudflared (Zustand der Verbindungen).
const CF_METRICS: &str = "127.0.0.1:20241";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Stored {
    #[serde(flatten)]
    settings: ComponentsSettings,
    tunnel_token: String,
    netbird_setup_key: String,
    /// Letzter Tag (JJJJ-MM-TT, Ortszeit) der automatischen Prüfung.
    last_auto_day: String,
}

async fn stored(pool: &SqlitePool) -> AppResult<Stored> {
    Ok(settings::get(pool, SETTINGS).await?.unwrap_or_default())
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Was gestartet werden soll.
#[derive(Debug, Clone, PartialEq)]
struct RunSpec {
    program: PathBuf,
    args: Vec<String>,
    env: Vec<(String, String)>,
    dir: PathBuf,
}

/// Ein betreuter Prozess.
struct Proc {
    log: Mutex<VecDeque<String>>,
    running: AtomicBool,
    started_at: AtomicI64,
    restarts: AtomicU32,
    last_error: Mutex<String>,
    desired: watch::Sender<Option<RunSpec>>,
    /// Neustart erzwingen (Update).
    generation: AtomicU32,
}

impl Proc {
    fn new() -> Self {
        Proc {
            log: Mutex::default(),
            running: AtomicBool::new(false),
            started_at: AtomicI64::new(0),
            restarts: AtomicU32::new(0),
            last_error: Mutex::default(),
            desired: watch::channel(None).0,
            generation: AtomicU32::new(0),
        }
    }

    fn line(&self, l: &str) {
        let clean: String = strip_ansi(l).chars().take(400).collect();
        if clean.trim().is_empty() {
            return;
        }
        let mut log = lock(&self.log);
        if log.len() >= LOG_LINES {
            log.pop_front();
        }
        log.push_back(clean);
    }

    fn set(&self, spec: Option<RunSpec>) {
        self.desired.send_if_modified(|cur| {
            if *cur == spec {
                false
            } else {
                *cur = spec;
                true
            }
        });
    }

    /// Mit gleicher Konfiguration neu starten (nach Update).
    fn restart(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.desired.send_modify(|_| {});
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for d in chars.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// Laufzeit (Rocket-State).
#[derive(Clone)]
pub struct Components(Arc<Inner>);

struct Inner {
    cloudflared: Proc,
    netbird: Proc,
    checking: AtomicBool,
    last_check: AtomicI64,
    last_result: Mutex<String>,
    latest: Mutex<BTreeMap<String, String>>,
}

impl Default for Components {
    fn default() -> Self {
        Components(Arc::new(Inner {
            cloudflared: Proc::new(),
            netbird: Proc::new(),
            checking: AtomicBool::new(false),
            last_check: AtomicI64::new(0),
            last_result: Mutex::default(),
            latest: Mutex::default(),
        }))
    }
}

// ------------------------------------------------------------------ Dateien und Versionen

fn bin_dir(data: &Path) -> PathBuf {
    data.join("bin")
}

fn netbird_dir(data: &Path) -> PathBuf {
    data.join("netbird")
}

fn versions_file(data: &Path) -> PathBuf {
    bin_dir(data).join("versions.json")
}

fn versions(data: &Path) -> BTreeMap<String, String> {
    std::fs::read_to_string(versions_file(data))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn set_version(data: &Path, name: &str, version: &str) -> AppResult<()> {
    let mut v = versions(data);
    v.insert(name.to_string(), version.to_string());
    let raw = serde_json::to_string_pretty(&v).map_err(|e| AppError::Config(e.to_string()))?;
    std::fs::write(versions_file(data), raw)
        .map_err(|e| AppError::Config(format!("versions.json: {e}")))
}

fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "arm" => "arm",
        _ => "amd64",
    }
}

/// Stammzertifikate als PEM für die Go-Programme (der Container hat keinen Speicher).
fn ca_bundle(data: &Path) -> AppResult<PathBuf> {
    let path = bin_dir(data).join("ca-certificates.pem");
    if path.exists() {
        return Ok(path);
    }
    std::fs::create_dir_all(bin_dir(data)).map_err(|e| AppError::Config(e.to_string()))?;
    let mut pem = String::new();
    for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        let b64 = base64::engine::general_purpose::STANDARD.encode(cert.as_ref());
        pem.push_str("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
    }
    std::fs::write(&path, pem).map_err(|e| AppError::Config(format!("{}: {e}", path.display())))?;
    Ok(path)
}

/// Neueste Version auf GitHub: (Tag, Download-URL, SHA-256 oder leer).
async fn latest_release(config: &Config, name: &str) -> AppResult<(String, String, String)> {
    let (repo, asset) = match name {
        "cloudflared" => (
            "cloudflare/cloudflared",
            format!("cloudflared-linux-{}", arch()),
        ),
        _ => ("netbirdio/netbird", String::new()),
    };
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("nrzNetwork/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AppError::Config(e.to_string()))?;
    let url = format!(
        "{}/repos/{repo}/releases/latest",
        config.github_api.trim_end_matches('/')
    );
    let v: Value = http
        .get(&url)
        .header("accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| AppError::BadGateway(format!("GitHub: {e}")))?
        .error_for_status()
        .map_err(|e| AppError::BadGateway(format!("GitHub: {e}")))?
        .json()
        .await
        .map_err(|e| AppError::BadGateway(format!("GitHub: {e}")))?;
    let tag = v["tag_name"].as_str().unwrap_or_default().to_string();
    if tag.is_empty() {
        return Err(AppError::BadGateway(format!(
            "GitHub: keine Version für {repo}"
        )));
    }
    let want = if asset.is_empty() {
        format!(
            "netbird_{}_linux_{}.tar.gz",
            tag.trim_start_matches('v'),
            arch()
        )
    } else {
        asset
    };
    let a = v["assets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["name"].as_str() == Some(want.as_str()))
        .ok_or_else(|| AppError::BadGateway(format!("GitHub: {want} fehlt in {tag}")))?;
    Ok((
        tag,
        a["browser_download_url"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        a["digest"]
            .as_str()
            .unwrap_or_default()
            .trim_start_matches("sha256:")
            .to_string(),
    ))
}

fn sha256_hex(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Herunterladen, prüfen, entpacken, ersetzen.
async fn install(data: &Path, name: &str, url: &str, sha: &str, version: &str) -> AppResult<()> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .user_agent(concat!("nrzNetwork/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AppError::Config(e.to_string()))?;
    let bytes = http
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| AppError::BadGateway(format!("Download {name}: {e}")))?
        .bytes()
        .await
        .map_err(|e| AppError::BadGateway(format!("Download {name}: {e}")))?;
    if bytes.len() > 300 * 1024 * 1024 {
        return Err(AppError::BadGateway(format!("Download {name}: zu gross")));
    }
    if !sha.is_empty() && !sha256_hex(&bytes).eq_ignore_ascii_case(sha) {
        return Err(AppError::BadGateway(format!(
            "Download {name}: Prüfsumme stimmt nicht – nicht installiert."
        )));
    }
    let program: Vec<u8> = if url.ends_with(".tar.gz") {
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&bytes[..]));
        let mut found = None;
        for entry in archive
            .entries()
            .map_err(|e| AppError::BadGateway(format!("{name}: {e}")))?
        {
            let mut entry = entry.map_err(|e| AppError::BadGateway(format!("{name}: {e}")))?;
            let path = entry.path().map(|p| p.to_path_buf()).unwrap_or_default();
            if path.file_name().and_then(|f| f.to_str()) == Some(name) {
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut entry, &mut buf)
                    .map_err(|e| AppError::BadGateway(format!("{name}: {e}")))?;
                found = Some(buf);
                break;
            }
        }
        found.ok_or_else(|| AppError::BadGateway(format!("{name}: Programm fehlt im Archiv")))?
    } else {
        bytes.to_vec()
    };
    let dir = bin_dir(data);
    std::fs::create_dir_all(&dir).map_err(|e| AppError::Config(e.to_string()))?;
    let tmp = dir.join(format!("{name}.new"));
    std::fs::write(&tmp, &program)
        .map_err(|e| AppError::Config(format!("{}: {e}", tmp.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| AppError::Config(e.to_string()))?;
    }
    std::fs::rename(&tmp, dir.join(name)).map_err(|e| AppError::Config(e.to_string()))?;
    set_version(data, name, version)?;
    tracing::info!(component = name, version, "Komponente installiert");
    Ok(())
}

// ------------------------------------------------------------------ Tunnel-Token

/// Konto und Tunnel aus dem Tunnel-Token (`base64({"a": konto, "t": tunnel, "s": geheimnis})`).
pub fn decode_tunnel_token(token: &str) -> Option<(String, String)> {
    let t = token.trim();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(t)
        .or_else(|_| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(t.trim_end_matches('='))
        })
        .ok()?;
    let v: Value = serde_json::from_slice(&raw).ok()?;
    let a = v["a"].as_str()?.to_string();
    let id = v["t"].as_str()?.to_string();
    (!a.is_empty() && !id.is_empty()).then_some((a, id))
}

// ------------------------------------------------------------------ Einstellungen

impl Components {
    fn proc(&self, name: &str) -> &Proc {
        if name == "cloudflared" {
            &self.0.cloudflared
        } else {
            &self.0.netbird
        }
    }

    /// Gewünschte Prozesse aus den Einstellungen ableiten (startet/stoppt sie).
    pub async fn apply(&self, pool: &SqlitePool, config: &Config) -> AppResult<()> {
        let s = stored(pool).await?;
        let data = &config.data_dir;
        let ca = ca_bundle(data)?;
        let base_env = vec![
            ("SSL_CERT_FILE".to_string(), ca.display().to_string()),
            ("HOME".to_string(), netbird_dir(data).display().to_string()),
        ];
        let cf_bin = bin_dir(data).join("cloudflared");
        let cf = (s.settings.cloudflared_enabled && !s.tunnel_token.is_empty() && cf_bin.exists())
            .then(|| {
                let mut env = base_env.clone();
                env.push(("TUNNEL_TOKEN".into(), s.tunnel_token.clone()));
                RunSpec {
                    program: cf_bin.clone(),
                    args: ["tunnel", "--no-autoupdate", "--metrics", CF_METRICS, "run"]
                        .map(String::from)
                        .to_vec(),
                    env,
                    dir: bin_dir(data),
                }
            });
        self.0.cloudflared.set(cf);

        let nb_bin = bin_dir(data).join("netbird");
        let nb_dir = netbird_dir(data);
        std::fs::create_dir_all(&nb_dir).map_err(|e| AppError::Config(e.to_string()))?;
        let registered = nb_dir.join("config.json").exists();
        let nb = (s.settings.netbird_enabled
            && nb_bin.exists()
            && (registered || !s.netbird_setup_key.is_empty()))
        .then(|| {
            let mut env = base_env.clone();
            for (k, v) in [
                ("NB_USE_NETSTACK_MODE", "true"),
                ("NB_ENABLE_NETSTACK_LOCAL_FORWARDING", "true"),
                ("NB_STATE_DIR", &nb_dir.display().to_string()),
                (
                    "NB_CONFIG",
                    &nb_dir.join("config.json").display().to_string(),
                ),
            ] {
                env.push((k.to_string(), v.to_string()));
            }
            let mut args: Vec<String> = vec![
                "up".into(),
                "--foreground-mode".into(),
                "--log-file".into(),
                "console".into(),
                "--daemon-addr".into(),
                format!("unix://{}", nb_dir.join("netbird.sock").display()),
                "--hostname".into(),
                if s.settings.netbird_hostname.trim().is_empty() {
                    "nrznetwork".into()
                } else {
                    s.settings.netbird_hostname.trim().to_string()
                },
                "--disable-dns".into(),
                "--disable-client-routes".into(),
            ];
            if !s.netbird_setup_key.is_empty() && !registered {
                args.push("--setup-key".into());
                args.push(s.netbird_setup_key.clone());
            }
            RunSpec {
                program: nb_bin.clone(),
                args,
                env,
                dir: nb_dir.clone(),
            }
        });
        self.0.netbird.set(nb);
        Ok(())
    }

    /// Prozesse betreuen (einmal beim Start).
    pub fn spawn_supervisors(&self, shutdown: rocket::Shutdown) {
        for name in ["cloudflared", "netbird"] {
            let me = self.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move { supervise(me, name, shutdown).await });
        }
    }
}

async fn supervise(c: Components, name: &'static str, mut shutdown: rocket::Shutdown) {
    let p = c.proc(name);
    let mut rx = p.desired.subscribe();
    let mut backoff = 5u64;
    loop {
        let spec = rx.borrow_and_update().clone();
        let Some(spec) = spec else {
            tokio::select! {
                r = rx.changed() => if r.is_err() { return },
                _ = &mut shutdown => return,
            }
            continue;
        };
        p.line(&format!(
            "— Start: {} {}",
            spec.program.display(),
            spec.args
                .iter()
                .filter(|a| !a.contains('-') || a.starts_with("--"))
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join(" ")
        ));
        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.args)
            .current_dir(&spec.dir)
            .envs(spec.env.iter().cloned())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = match cmd.spawn() {
            Ok(ch) => ch,
            Err(e) => {
                *lock(&p.last_error) = format!("Start: {e}");
                p.line(&format!("Start fehlgeschlagen: {e}"));
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(backoff)) => {}
                    _ = rx.changed() => {}
                    _ = &mut shutdown => return,
                }
                backoff = (backoff * 2).min(120);
                continue;
            }
        };
        p.running.store(true, Ordering::SeqCst);
        p.started_at.store(now(), Ordering::SeqCst);
        for out in [
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let c2 = c.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(out).lines();
                while let Ok(Some(l)) = lines.next_line().await {
                    c2.proc(name).line(&l);
                }
            });
        }
        let started = std::time::Instant::now();
        let stop = tokio::select! {
            status = child.wait() => {
                let msg = match status {
                    Ok(s) => format!("beendet ({s})"),
                    Err(e) => format!("beendet: {e}"),
                };
                p.line(&format!("— {msg}"));
                *lock(&p.last_error) = msg;
                false
            }
            _ = rx.changed() => true,
            _ = &mut shutdown => {
                let _ = child.kill().await;
                p.running.store(false, Ordering::SeqCst);
                return;
            }
        };
        if stop {
            let _ = child.kill().await;
            p.line("— gestoppt (neue Einstellungen oder Update)");
            backoff = 5;
        }
        p.running.store(false, Ordering::SeqCst);
        if !stop {
            p.restarts.fetch_add(1, Ordering::SeqCst);
            if started.elapsed() > Duration::from_secs(120) {
                backoff = 5;
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(backoff)) => {}
                _ = rx.changed() => {}
                _ = &mut shutdown => return,
            }
            backoff = (backoff * 2).min(120);
        }
    }
}

pub async fn save(
    pool: &SqlitePool,
    config: &Config,
    comps: &Components,
    input: &ComponentsInput,
) -> AppResult<()> {
    let mut s = stored(pool).await?;
    if input.settings.update_hour > 23 {
        return Err(AppError::bad("Update-Uhrzeit: 0 bis 23 Uhr."));
    }
    let host = input.settings.netbird_hostname.trim();
    if host.len() > 60 || !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(AppError::bad(
            "NetBird-Name: Buchstaben, Ziffern und -, höchstens 60 Zeichen.",
        ));
    }
    let token = input.tunnel_token.trim();
    if !token.is_empty() {
        if decode_tunnel_token(token).is_none() {
            return Err(AppError::bad("Tunnel-Token: bitte den ganzen Token aus Cloudflare kopieren (beginnt meist mit „eyJ“)."));
        }
        s.tunnel_token = token.to_string();
    }
    let key = input.netbird_setup_key.trim();
    if !key.is_empty() {
        if key.len() > 100 || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(AppError::bad(
                "Setup-Key: bitte unverändert aus NetBird kopieren.",
            ));
        }
        s.netbird_setup_key = key.to_string();
    }
    s.settings = ComponentsSettings {
        netbird_hostname: if host.is_empty() {
            "nrznetwork".into()
        } else {
            host.to_lowercase()
        },
        ..input.settings.clone()
    };
    settings::set(pool, SETTINGS, &s).await?;
    comps.apply(pool, config).await?;
    // Fehlt ein eingeschaltetes Programm, gleich installieren
    let missing = (s.settings.cloudflared_enabled
        && !bin_dir(&config.data_dir).join("cloudflared").exists())
        || (s.settings.netbird_enabled && !bin_dir(&config.data_dir).join("netbird").exists());
    if missing && config.background {
        let (pool, config, comps) = (pool.clone(), config.clone(), comps.clone());
        tokio::spawn(async move {
            let _ = check_updates(&pool, &config, &comps).await;
        });
    }
    Ok(())
}

pub async fn clear_secret(
    pool: &SqlitePool,
    config: &Config,
    comps: &Components,
    which: &str,
) -> AppResult<()> {
    let mut s = stored(pool).await?;
    match which {
        "tunnel" => s.tunnel_token.clear(),
        "netbird" => {
            s.netbird_setup_key.clear();
            let dir = netbird_dir(&config.data_dir);
            for f in ["config.json", "active_profile.json"] {
                let _ = std::fs::remove_file(dir.join(f));
            }
        }
        _ => return Err(AppError::NotFound),
    }
    settings::set(pool, SETTINGS, &s).await?;
    comps.apply(pool, config).await
}

/// Neueste Versionen holen und einspielen (eingeschaltete Komponenten).
pub async fn check_updates(
    pool: &SqlitePool,
    config: &Config,
    comps: &Components,
) -> AppResult<String> {
    if comps.0.checking.swap(true, Ordering::SeqCst) {
        return Err(AppError::Conflict("Die Prüfung läuft schon.".into()));
    }
    let s = stored(pool).await.unwrap_or_default();
    let mut results = Vec::new();
    for (name, enabled) in [
        ("cloudflared", s.settings.cloudflared_enabled),
        ("netbird", s.settings.netbird_enabled),
    ] {
        let installed = versions(&config.data_dir)
            .get(name)
            .cloned()
            .unwrap_or_default();
        let present = bin_dir(&config.data_dir).join(name).exists();
        match latest_release(config, name).await {
            Ok((tag, url, sha)) => {
                lock(&comps.0.latest).insert(name.to_string(), tag.clone());
                if !enabled {
                    continue;
                }
                if present && installed == tag {
                    results.push(format!("{name} {tag} ist aktuell"));
                    continue;
                }
                match install(&config.data_dir, name, &url, &sha, &tag).await {
                    Ok(()) => {
                        results.push(if installed.is_empty() {
                            format!("{name} {tag} installiert")
                        } else {
                            format!("{name}: {installed} → {tag}")
                        });
                        let _ = comps.apply(pool, config).await;
                        comps.proc(name).restart();
                    }
                    Err(e) => results.push(format!("{name}: {e}")),
                }
            }
            Err(e) => {
                if enabled {
                    results.push(format!("{name}: {e}"));
                }
            }
        }
    }
    let summary = if results.is_empty() {
        "Keine Komponente eingeschaltet.".to_string()
    } else {
        results.join(" · ")
    };
    tracing::info!("Komponenten: {summary}");
    comps.0.last_check.store(now(), Ordering::SeqCst);
    *lock(&comps.0.last_result) = summary.clone();
    comps.0.checking.store(false, Ordering::SeqCst);
    Ok(summary)
}

/// Zeitzone für die Update-Stunde (`TZ`, sonst die des Systems).
pub fn time_zone() -> jiff::tz::TimeZone {
    std::env::var("TZ")
        .ok()
        .and_then(|tz| jiff::tz::TimeZone::get(tz.trim()).ok())
        .unwrap_or_else(jiff::tz::TimeZone::system)
}

/// Jede Minute: zur eingestellten Stunde einmal am Tag nach Updates suchen.
pub async fn scheduler(
    pool: SqlitePool,
    config: Config,
    comps: Components,
    mut shutdown: rocket::Shutdown,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
            _ = &mut shutdown => return,
        }
        let Ok(mut s) = stored(&pool).await else {
            continue;
        };
        if !s.settings.auto_update
            || !(s.settings.cloudflared_enabled || s.settings.netbird_enabled)
        {
            continue;
        }
        let local = jiff::Timestamp::now().to_zoned(time_zone());
        let day = local.date().to_string();
        if local.hour() != i8::try_from(s.settings.update_hour).unwrap_or(3)
            || s.last_auto_day == day
        {
            continue;
        }
        s.last_auto_day = day;
        let _ = settings::set(&pool, SETTINGS, &s).await;
        let _ = check_updates(&pool, &config, &comps).await;
    }
}

// ------------------------------------------------------------------ Zustand

async fn cloudflared_detail(http: &reqwest::Client) -> (bool, String) {
    match http.get(format!("http://{CF_METRICS}/ready")).send().await {
        Ok(r) => {
            let v: Value = r.json().await.unwrap_or(Value::Null);
            let n = v["readyConnections"].as_u64().unwrap_or(0);
            (
                n > 0,
                if n > 0 {
                    format!("{n} Verbindungen zu Cloudflare")
                } else {
                    "keine Verbindung zu Cloudflare".into()
                },
            )
        }
        Err(_) => (false, String::new()),
    }
}

pub async fn status(
    pool: &SqlitePool,
    config: &Config,
    comps: &Components,
) -> AppResult<ComponentsStatus> {
    let s = stored(pool).await?;
    let installed = versions(&config.data_dir);
    let latest = lock(&comps.0.latest).clone();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| AppError::Config(e.to_string()))?;
    let mut list = Vec::new();
    for (name, enabled) in [
        ("cloudflared", s.settings.cloudflared_enabled),
        ("netbird", s.settings.netbird_enabled),
    ] {
        let p = comps.proc(name);
        let running = p.running.load(Ordering::Relaxed);
        let log: Vec<String> = lock(&p.log).iter().rev().take(40).rev().cloned().collect();
        let (connected, detail) = if !running {
            (false, String::new())
        } else if name == "cloudflared" {
            cloudflared_detail(&http).await
        } else {
            netbird_detail(pool, &s, &log).await
        };
        list.push(ComponentStatus {
            name: name.into(),
            enabled,
            installed_version: installed.get(name).cloned().unwrap_or_default(),
            latest_version: latest.get(name).cloned().unwrap_or_default(),
            running,
            connected,
            detail,
            started_at: if running {
                p.started_at.load(Ordering::Relaxed)
            } else {
                0
            },
            restarts: p.restarts.load(Ordering::Relaxed),
            last_error: lock(&p.last_error).clone(),
            log,
        });
    }
    Ok(ComponentsStatus {
        tunnel_token_set: !s.tunnel_token.is_empty(),
        tunnel_id: decode_tunnel_token(&s.tunnel_token)
            .map(|(_, t)| t)
            .unwrap_or_default(),
        netbird_key_set: !s.netbird_setup_key.is_empty()
            || netbird_dir(&config.data_dir).join("config.json").exists(),
        settings: s.settings,
        components: list,
        last_check: comps.0.last_check.load(Ordering::Relaxed),
        last_check_result: lock(&comps.0.last_result).clone(),
        checking: comps.0.checking.load(Ordering::Relaxed),
        time_zone: time_zone().iana_name().unwrap_or("UTC").to_string(),
    })
}

/// NetBird: über die API das eigene Gerät suchen, sonst aus der Ausgabe schliessen.
async fn netbird_detail(pool: &SqlitePool, s: &Stored, log: &[String]) -> (bool, String) {
    let host = s.settings.netbird_hostname.to_lowercase();
    if let Ok(up) = integrations::netbird(pool, Method::GET, &["peers"], None, None).await {
        if let Some(p) = up.body.as_array().into_iter().flatten().find(|p| {
            p["hostname"]
                .as_str()
                .is_some_and(|h| h.eq_ignore_ascii_case(&host))
                || p["name"]
                    .as_str()
                    .is_some_and(|h| h.eq_ignore_ascii_case(&host))
        }) {
            let connected = p["connected"].as_bool().unwrap_or(false);
            let ip = p["ip"].as_str().unwrap_or_default();
            return (
                connected,
                format!(
                    "{ip} ({})",
                    if connected { "verbunden" } else { "getrennt" }
                ),
            );
        }
    }
    let joined = log.iter().rev().take(60).any(|l| {
        l.contains("Netbird IP")
            || l.contains("peer connected")
            || l.contains("connected to the Management")
    });
    (
        joined,
        if joined {
            "angemeldet".into()
        } else {
            "verbindet …".into()
        },
    )
}

// ------------------------------------------------------------------ NetBird: Setup-Key

/// Setup-Key über die NetBird-API erzeugen und speichern.
pub async fn create_netbird_key(
    pool: &SqlitePool,
    config: &Config,
    comps: &Components,
) -> AppResult<()> {
    let up = integrations::netbird(
        pool,
        Method::POST,
        &["setup-keys"],
        None,
        Some(json!({
            "name": "nrzNetwork (eingebaut)",
            "type": "one-off",
            "expires_in": 86_400,
            "auto_groups": [],
            "usage_limit": 1,
            "ephemeral": false,
        })),
    )
    .await?;
    if !(200..300).contains(&up.status) {
        return Err(AppError::bad(integrations::error_message("NetBird", &up)));
    }
    let key = up.body["key"].as_str().unwrap_or_default().to_string();
    if key.is_empty() {
        return Err(AppError::BadGateway(
            "NetBird hat keinen Schlüssel geliefert.".into(),
        ));
    }
    let mut s = stored(pool).await?;
    s.netbird_setup_key = key;
    s.settings.netbird_enabled = true;
    settings::set(pool, SETTINGS, &s).await?;
    comps.apply(pool, config).await
}

// ------------------------------------------------------------------ Cloudflare Tunnel

/// Adresse, unter der cloudflared den Proxy erreicht.
fn origin(config: &Config) -> String {
    let port = config.proxy_listen.first().map_or(80, |a| a.port());
    format!("http://127.0.0.1:{port}")
}

async fn cf(
    pool: &SqlitePool,
    config: &Config,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> AppResult<Value> {
    let up = integrations::cloudflare_raw(pool, config, method, path, None, body).await?;
    if (200..300).contains(&up.status) && up.body["success"].as_bool() != Some(false) {
        Ok(up.body)
    } else {
        Err(AppError::bad(integrations::error_message(
            "Cloudflare",
            &up,
        )))
    }
}

/// Neuen Tunnel „nrznetwork“ anlegen und seinen Token speichern.
pub async fn create_tunnel(
    pool: &SqlitePool,
    config: &Config,
    comps: &Components,
) -> AppResult<()> {
    let zones = cf(pool, config, Method::GET, "zones?per_page=50", None).await?;
    let account = zones["result"][0]["account"]["id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if account.is_empty() {
        return Err(AppError::bad(
            "Cloudflare: kein Konto gefunden – sieht das Token eine Zone?",
        ));
    }
    let created = cf(
        pool,
        config,
        Method::POST,
        &format!("accounts/{account}/cfd_tunnel"),
        Some(json!({ "name": format!("nrznetwork-{}", now() % 100_000), "config_src": "cloudflare" })),
    )
    .await?;
    let id = created["result"]["id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let token = match created["result"]["token"].as_str() {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => cf(
            pool,
            config,
            Method::GET,
            &format!("accounts/{account}/cfd_tunnel/{id}/token"),
            None,
        )
        .await?["result"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    };
    if token.is_empty() {
        return Err(AppError::BadGateway(
            "Cloudflare hat keinen Tunnel-Token geliefert.".into(),
        ));
    }
    let mut s = stored(pool).await?;
    s.tunnel_token = token;
    s.settings.cloudflared_enabled = true;
    settings::set(pool, SETTINGS, &s).await?;
    comps.apply(pool, config).await?;
    tracing::info!(tunnel = %id, "Cloudflare Tunnel angelegt");
    Ok(())
}

/// Öffentliche Einträge mit dem Tunnel abgleichen: Regeln (fremde bleiben) und DNS-Einträge.
pub async fn sync_tunnel(pool: &SqlitePool, config: &Config) -> AppResult<()> {
    let s = stored(pool).await?;
    let Some((account, tunnel)) = decode_tunnel_token(&s.tunnel_token) else {
        return Err(AppError::bad(
            "Zuerst den Cloudflare Tunnel einrichten (Einstellungen → Komponenten).",
        ));
    };
    let want: Vec<String> = sqlx::query_scalar(
        "SELECT host FROM proxy_hosts WHERE public = 1 AND enabled = 1 ORDER BY host",
    )
    .fetch_all(pool)
    .await?;
    let ours = origin(config);
    let path = format!("accounts/{account}/cfd_tunnel/{tunnel}/configurations");
    let current = cf(pool, config, Method::GET, &path, None).await?;
    let mut cfg = current["result"]["config"].clone();
    if !cfg.is_object() {
        cfg = json!({});
    }
    let old: Vec<Value> = cfg["ingress"].as_array().cloned().unwrap_or_default();
    let mut previously_ours = Vec::new();
    let mut rules: Vec<Value> = Vec::new();
    for r in &old {
        let host = r["hostname"].as_str().unwrap_or_default();
        if host.is_empty() {
            continue; // Auffangregel kommt ans Ende
        }
        if r["service"].as_str() == Some(ours.as_str()) {
            previously_ours.push(host.to_string());
            continue;
        }
        if want.iter().any(|w| w == host) {
            return Err(AppError::Conflict(format!(
                "„{host}“ ist im Tunnel schon für ein anderes Ziel eingetragen – dort zuerst entfernen."
            )));
        }
        rules.push(r.clone());
    }
    for h in &want {
        rules.push(json!({ "hostname": h, "service": ours, "originRequest": {} }));
    }
    let fallback = old
        .iter()
        .find(|r| r["hostname"].as_str().unwrap_or_default().is_empty())
        .cloned()
        .unwrap_or_else(|| json!({ "service": "http_status:404" }));
    rules.push(fallback);
    cfg["ingress"] = Value::Array(rules);
    cf(
        pool,
        config,
        Method::PUT,
        &path,
        Some(json!({ "config": cfg })),
    )
    .await?;

    // DNS: CNAME → <tunnel>.cfargotunnel.com (Proxy an)
    let target = format!("{tunnel}.cfargotunnel.com");
    let zones = cf(pool, config, Method::GET, "zones?per_page=50", None).await?;
    let zone_of = |host: &str| -> Option<String> {
        zones["result"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|z| {
                Some((
                    z["id"].as_str()?.to_string(),
                    z["name"].as_str()?.to_string(),
                ))
            })
            .filter(|(_, n)| host == n || host.ends_with(&format!(".{n}")))
            .max_by_key(|(_, n)| n.len())
            .map(|(id, _)| id)
    };
    for h in &want {
        let zone = zone_of(h).ok_or_else(|| {
            AppError::bad(format!(
                "„{h}“ liegt in keiner Cloudflare-Zone dieses Tokens."
            ))
        })?;
        let existing = cf(
            pool,
            config,
            Method::GET,
            &format!("zones/{zone}/dns_records?name={h}"),
            None,
        )
        .await?;
        let records = existing["result"].as_array().cloned().unwrap_or_default();
        if records
            .iter()
            .any(|r| r["type"] == "CNAME" && r["content"].as_str() == Some(target.as_str()))
        {
            continue;
        }
        if let Some(r) = records.first() {
            return Err(AppError::Conflict(format!(
                "Für „{h}“ gibt es bei Cloudflare schon einen {}-Eintrag ({}) – unter Domains zuerst entfernen.",
                r["type"].as_str().unwrap_or("?"),
                r["content"].as_str().unwrap_or_default()
            )));
        }
        cf(
            pool,
            config,
            Method::POST,
            &format!("zones/{zone}/dns_records"),
            Some(json!({ "type": "CNAME", "name": h, "content": target, "proxied": true, "ttl": 1, "comment": "nrzNetwork: Cloudflare Tunnel" })),
        )
        .await?;
    }
    for h in previously_ours.iter().filter(|h| !want.contains(h)) {
        let Some(zone) = zone_of(h) else { continue };
        if let Ok(existing) = cf(
            pool,
            config,
            Method::GET,
            &format!("zones/{zone}/dns_records?name={h}"),
            None,
        )
        .await
        {
            for r in existing["result"].as_array().into_iter().flatten() {
                if r["type"] == "CNAME" && r["content"].as_str() == Some(target.as_str()) {
                    if let Some(id) = r["id"].as_str() {
                        let _ = cf(
                            pool,
                            config,
                            Method::DELETE,
                            &format!("zones/{zone}/dns_records/{id}"),
                            None,
                        )
                        .await;
                    }
                }
            }
        }
    }
    tracing::info!(hosts = ?want, "Cloudflare Tunnel abgeglichen");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_token() {
        let t = base64::engine::general_purpose::STANDARD
            .encode(r#"{"a":"acc123","t":"6ff42ae2-765d-4adf-8112-31c55c1551ef","s":"c2VjcmV0"}"#);
        assert_eq!(
            decode_tunnel_token(&t),
            Some((
                "acc123".into(),
                "6ff42ae2-765d-4adf-8112-31c55c1551ef".into()
            ))
        );
        assert!(decode_tunnel_token("kein-token").is_none());
    }

    #[test]
    fn ansi_and_sha() {
        assert_eq!(
            strip_ansi("\u{1b}[32mINF\u{1b}[0m Registered tunnel connection"),
            "INF Registered tunnel connection"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn ca_pem() {
        let dir = tempfile::tempdir().unwrap();
        let p = ca_bundle(dir.path()).unwrap();
        let pem = std::fs::read_to_string(p).unwrap();
        assert!(pem.matches("BEGIN CERTIFICATE").count() > 100);
        let certs: Vec<_> = rustls_pemfile::certs(&mut pem.as_bytes()).collect();
        assert!(certs.iter().all(Result::is_ok));
    }
}
