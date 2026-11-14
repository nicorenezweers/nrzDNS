//! Docker auf dem Gerät beobachten – nur lesend über den Docker-Socket (wie `docker ps`,
//! `docker network ls`, `docker inspect`, `docker logs`). Es gibt bewusst keine Befehle,
//! die etwas starten, stoppen oder löschen.

use crate::config::Config;
use crate::error::{AppError, AppResult};
use nrzdns_types::{DockerAddress, DockerContainer, DockerNetwork, DockerOverview};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// GET über den Unix-Socket; liefert (Status, Körper).
async fn get(config: &Config, path: &str) -> AppResult<(u16, Vec<u8>)> {
    let fut = async {
        let mut s = tokio::net::UnixStream::connect(&config.docker_socket)
            .await
            .map_err(|e| {
                AppError::BadGateway(format!(
                    "Docker nicht erreichbar ({}): {e}",
                    config.docker_socket.display()
                ))
            })?;
        s.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .map_err(|e| AppError::BadGateway(format!("Docker: {e}")))?;
        let mut raw = Vec::new();
        s.take(64 * 1024 * 1024)
            .read_to_end(&mut raw)
            .await
            .map_err(|e| AppError::BadGateway(format!("Docker: {e}")))?;
        parse_http(&raw)
    };
    tokio::time::timeout(Duration::from_secs(15), fut)
        .await
        .map_err(|_| AppError::BadGateway("Docker: keine Antwort".into()))?
}

/// HTTP-Antwort zerlegen (auch `Transfer-Encoding: chunked`).
pub fn parse_http(raw: &[u8]) -> AppResult<(u16, Vec<u8>)> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| AppError::BadGateway("Docker: unvollständige Antwort".into()))?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let body = &raw[split + 4..];
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let chunked = head.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    if !chunked {
        return Ok((status, body.to_vec()));
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let Some(end) = body[i..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_line = String::from_utf8_lossy(&body[i..i + end]).to_string();
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("0").trim(), 16)
            .unwrap_or(0);
        i += end + 2;
        if size == 0 {
            break;
        }
        let stop = (i + size).min(body.len());
        out.extend_from_slice(&body[i..stop]);
        i = stop + 2;
    }
    Ok((status, out))
}

async fn get_json(config: &Config, path: &str) -> AppResult<Value> {
    let (status, body) = get(config, path).await?;
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        let msg = v["message"].as_str().unwrap_or("unbekannter Fehler");
        return Err(if status == 404 {
            AppError::NotFound
        } else {
            AppError::BadGateway(format!("Docker: {msg}"))
        });
    }
    Ok(v)
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}

/// Container aus `GET /containers/json?all=1`.
pub fn parse_containers(v: &Value) -> Vec<DockerContainer> {
    let mut out: Vec<DockerContainer> = v
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| {
            let labels = &c["Labels"];
            let mut addresses: Vec<DockerAddress> = c["NetworkSettings"]["Networks"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(net, n)| DockerAddress {
                    network: net.clone(),
                    ip: s(&n["IPAddress"]),
                    gateway: s(&n["Gateway"]),
                    mac: s(&n["MacAddress"]),
                })
                .collect();
            addresses.sort_by(|a, b| a.network.cmp(&b.network));
            let mut ports: Vec<String> = c["Ports"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|p| {
                    let private = p["PrivatePort"].as_u64().unwrap_or(0);
                    let typ = s(&p["Type"]);
                    match p["PublicPort"].as_u64() {
                        Some(public) => format!(
                            "{}:{public}→{private}/{typ}",
                            if s(&p["IP"]).is_empty() {
                                "0.0.0.0".into()
                            } else {
                                s(&p["IP"])
                            }
                        ),
                        None => format!("{private}/{typ}"),
                    }
                })
                .collect();
            ports.sort();
            ports.dedup();
            DockerContainer {
                id: s(&c["Id"]).chars().take(12).collect(),
                name: c["Names"][0]
                    .as_str()
                    .unwrap_or_default()
                    .trim_start_matches('/')
                    .to_string(),
                image: s(&c["Image"]),
                state: s(&c["State"]),
                status: s(&c["Status"]),
                created: c["Created"].as_i64().unwrap_or(0),
                app: s(&labels["com.docker.compose.project"]),
                service: s(&labels["com.docker.compose.service"]),
                network_mode: s(&c["HostConfig"]["NetworkMode"]),
                addresses,
                ports,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        (a.state != "running", &a.app, &a.name).cmp(&(b.state != "running", &b.app, &b.name))
    });
    out
}

/// Netze aus `GET /networks`, Container aus der Containerliste zugeordnet.
pub fn parse_networks(v: &Value, containers: &[DockerContainer]) -> Vec<DockerNetwork> {
    let mut out: Vec<DockerNetwork> = v
        .as_array()
        .into_iter()
        .flatten()
        .map(|n| {
            let cfg = n["IPAM"]["Config"][0].clone();
            let name = s(&n["Name"]);
            let mut members: Vec<(String, String)> = containers
                .iter()
                .flat_map(|c| {
                    c.addresses
                        .iter()
                        .filter(|a| a.network == name)
                        .map(|a| (c.name.clone(), a.ip.clone()))
                })
                .collect();
            members.sort_by(|a, b| a.1.cmp(&b.1));
            DockerNetwork {
                id: s(&n["Id"]).chars().take(12).collect(),
                driver: s(&n["Driver"]),
                subnet: s(&cfg["Subnet"]),
                gateway: s(&cfg["Gateway"]),
                internal: n["Internal"].as_bool().unwrap_or(false),
                containers: members,
                name,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.containers
            .len()
            .cmp(&a.containers.len())
            .then(a.name.cmp(&b.name))
    });
    out
}

pub async fn overview(config: &Config) -> DockerOverview {
    let mut o = DockerOverview::default();
    let version = match get_json(config, "/version").await {
        Ok(v) => v,
        Err(e) => {
            o.error = e.to_string();
            return o;
        }
    };
    o.available = true;
    o.version = s(&version["Version"]);
    match get_json(config, "/containers/json?all=1").await {
        Ok(v) => o.containers = parse_containers(&v),
        Err(e) => o.error = e.to_string(),
    }
    match get_json(config, "/networks").await {
        Ok(v) => o.networks = parse_networks(&v, &o.containers),
        Err(e) => o.error = e.to_string(),
    }
    o
}

fn check_name(name: &str) -> AppResult<()> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(AppError::bad("Ungültiger Containername."));
    }
    Ok(())
}

/// `docker inspect` ohne Umgebungsvariablen (dort stehen oft Passwörter).
pub async fn inspect(config: &Config, name: &str) -> AppResult<Value> {
    check_name(name)?;
    let mut v = get_json(config, &format!("/containers/{name}/json")).await?;
    if let Some(cfg) = v.get_mut("Config").and_then(Value::as_object_mut) {
        cfg.remove("Env");
        if let Some(cmd) = cfg.get_mut("Cmd") {
            redact_args(cmd);
        }
    }
    if let Some(args) = v.get_mut("Args") {
        redact_args(args);
    }
    Ok(v)
}

/// Geheimnisse in Befehlszeilen ausblenden (`--token xyz`, `--token=xyz`, `--password …`).
fn redact_args(v: &mut Value) {
    let Some(list) = v.as_array_mut() else { return };
    let mut hide_next = false;
    for a in list.iter_mut() {
        let Some(s) = a.as_str().map(str::to_string) else { continue };
        if hide_next {
            *a = Value::String("***".into());
            hide_next = false;
            continue;
        }
        let lower = s.to_ascii_lowercase();
        let secret = ["--token", "--password", "--secret", "--api-key", "--key"];
        if secret.iter().any(|k| lower == *k) {
            hide_next = true;
        } else if let Some(k) = secret.iter().find(|k| lower.starts_with(&format!("{k}="))) {
            *a = Value::String(format!("{k}=***"));
        }
    }
}

/// Tunnel-IDs, die ein cloudflared-Container benutzt (aus dem Token oder den Argumenten).
/// Der Token selbst verlässt diese Funktion nie.
pub async fn tunnel_ids(config: &Config, name: &str) -> Vec<String> {
    if check_name(name).is_err() {
        return Vec::new();
    }
    let Ok(v) = get_json(config, &format!("/containers/{name}/json")).await else {
        return Vec::new();
    };
    let strs = |x: &Value| -> Vec<String> {
        x.as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s.as_str().map(str::to_string))
            .collect()
    };
    let mut args = strs(&v["Config"]["Entrypoint"]);
    args.extend(strs(&v["Args"]));
    args.extend(strs(&v["Config"]["Cmd"]));
    tunnel_ids_from(&args, &strs(&v["Config"]["Env"]))
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

pub fn tunnel_ids_from(args: &[String], env: &[String]) -> Vec<String> {
    use crate::services::components::decode_tunnel_token;
    let mut out: Vec<String> = Vec::new();
    for (i, a) in args.iter().enumerate() {
        let token = if a == "--token" {
            args.get(i + 1).cloned()
        } else {
            a.strip_prefix("--token=").map(str::to_string)
        };
        if let Some((_, id)) = token.as_deref().and_then(decode_tunnel_token) {
            out.push(id);
        } else if is_uuid(a) {
            out.push(a.to_ascii_lowercase());
        }
    }
    for e in env {
        if let Some((_, id)) = e.strip_prefix("TUNNEL_TOKEN=").and_then(decode_tunnel_token) {
            out.push(id);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Ausgabe-Rahmen von `docker logs` ohne TTY (8 Byte Kopf je Rahmen) zerlegen.
pub fn demux_logs(raw: &[u8]) -> String {
    let multiplexed = raw.len() >= 8 && matches!(raw[0], 0..=2) && raw[1..4] == [0, 0, 0];
    if !multiplexed {
        return String::from_utf8_lossy(raw).into_owned();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i + 8 <= raw.len() {
        let len = u32::from_be_bytes([raw[i + 4], raw[i + 5], raw[i + 6], raw[i + 7]]) as usize;
        let start = i + 8;
        let end = (start + len).min(raw.len());
        out.extend_from_slice(&raw[start..end]);
        i = end;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub async fn logs(config: &Config, name: &str, tail: u32) -> AppResult<Vec<String>> {
    check_name(name)?;
    let tail = tail.clamp(1, 1000);
    let (status, body) = get(
        config,
        &format!("/containers/{name}/logs?stdout=1&stderr=1&timestamps=1&tail={tail}"),
    )
    .await?;
    if status == 404 {
        return Err(AppError::NotFound);
    }
    if !(200..300).contains(&status) {
        return Err(AppError::BadGateway(format!("Docker: HTTP {status}")));
    }
    Ok(demux_logs(&body)
        .lines()
        .map(|l| l.chars().take(1000).collect())
        .collect())
}

fn cache() -> &'static std::sync::Mutex<HashMap<String, String>> {
    static C: std::sync::OnceLock<std::sync::Mutex<HashMap<String, String>>> =
        std::sync::OnceLock::new();
    C.get_or_init(Default::default)
}

/// Zuletzt bekannte Containernamen je IP (aufgefrischt von [`refresh_names`]).
pub fn cached_names() -> HashMap<String, String> {
    cache().lock().map(|c| c.clone()).unwrap_or_default()
}

pub async fn refresh_names(config: &Config) {
    let names = ip_names(config).await;
    if let Ok(mut c) = cache().lock() {
        *c = names;
    }
}

/// IP → Containername (für Geräte und Zugriffe), leer ohne Docker.
pub async fn ip_names(config: &Config) -> HashMap<String, String> {
    let Ok(v) = get_json(config, "/containers/json").await else {
        return HashMap::new();
    };
    parse_containers(&v)
        .into_iter()
        .flat_map(|c| {
            c.addresses
                .into_iter()
                .filter(|a| !a.ip.is_empty())
                .map(move |a| (a.ip, c.name.clone()))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn http_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhallo\r\n6\r\n welt\n\r\n0\r\n\r\n";
        let (st, body) = parse_http(raw).unwrap();
        assert_eq!((st, body.as_slice()), (200, &b"hallo welt\n"[..]));
        let (st, body) =
            parse_http(b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!((st, body.as_slice()), (404, &b"{}"[..]));
    }

    #[test]
    fn containers_and_networks() {
        let c = json!([{
            "Id": "abcdef1234567890", "Names": ["/nrz-bench_app_1"], "Image": "nrz-bench:1.4", "State": "running", "Status": "Up 3 hours",
            "Created": 1700000000, "Labels": { "com.docker.compose.project": "nrz-bench", "com.docker.compose.service": "app" },
            "HostConfig": { "NetworkMode": "umbrel_main_network" },
            "Ports": [{ "IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8550, "Type": "tcp" }, { "PrivatePort": 443, "Type": "tcp" }],
            "NetworkSettings": { "Networks": { "umbrel_main_network": { "IPAddress": "10.21.0.20", "Gateway": "10.21.0.1", "MacAddress": "02:42:0a:15:00:14" } } }
        }]);
        let cs = parse_containers(&c);
        assert_eq!(cs[0].name, "nrz-bench_app_1");
        assert_eq!(cs[0].app, "nrz-bench");
        assert_eq!(cs[0].addresses[0].ip, "10.21.0.20");
        assert_eq!(cs[0].ports, ["0.0.0.0:8550→80/tcp", "443/tcp"]);
        assert_eq!(cs[0].id, "abcdef123456");
        let n = json!([{ "Id": "n1", "Name": "umbrel_main_network", "Driver": "bridge", "IPAM": { "Config": [{ "Subnet": "10.21.0.0/16", "Gateway": "10.21.0.1" }] } }]);
        let ns = parse_networks(&n, &cs);
        assert_eq!(ns[0].subnet, "10.21.0.0/16");
        assert_eq!(
            ns[0].containers,
            [("nrz-bench_app_1".to_string(), "10.21.0.20".to_string())]
        );
    }

    #[test]
    fn log_frames() {
        let mut raw = vec![1, 0, 0, 0, 0, 0, 0, 6];
        raw.extend_from_slice(b"zeile\n");
        raw.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 7]);
        raw.extend_from_slice(b"fehler\n");
        assert_eq!(demux_logs(&raw), "zeile\nfehler\n");
        assert_eq!(demux_logs(b"tty-ausgabe\n"), "tty-ausgabe\n");
        assert!(check_name("../x").is_err());
    }

    #[test]
    fn tunnel_ids_and_redaction() {
        use base64::Engine as _;
        let tok = base64::engine::general_purpose::STANDARD
            .encode(r#"{"a":"acc","t":"9ea7bd12-fcaa-4625-bf3f-cc04fa82faeb","s":"geheim"}"#);
        let args: Vec<String> = ["tunnel", "--no-autoupdate", "run", "--token", &tok].iter().map(|s| s.to_string()).collect();
        assert_eq!(tunnel_ids_from(&args, &[]), ["9ea7bd12-fcaa-4625-bf3f-cc04fa82faeb"]);
        assert_eq!(tunnel_ids_from(&[], &[format!("TUNNEL_TOKEN={tok}")]), ["9ea7bd12-fcaa-4625-bf3f-cc04fa82faeb"]);
        let mut v = serde_json::json!(["run", "--token", tok, "--password=x"]);
        redact_args(&mut v);
        assert_eq!(v, serde_json::json!(["run", "--token", "***", "--password=***"]));
    }
}
