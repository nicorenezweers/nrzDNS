//! Docker beobachten gegen einen nachgebauten Docker-Socket.

mod common;

use common::{get, login_as};
use rocket::http::Status;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn fake_docker(path: std::path::PathBuf) {
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("").to_string();
                let (status, body): (u16, Vec<u8>) = if path == "/version" {
                    (200, json!({ "Version": "27.3.1" }).to_string().into_bytes())
                } else if path.starts_with("/containers/json") {
                    (200, json!([{ "Id": "aaaaaaaaaaaaaaaa", "Names": ["/nrz-bench_app_1"], "Image": "nrz-bench", "State": "running", "Status": "Up 2 hours",
                        "Labels": { "com.docker.compose.project": "nrz-bench" }, "HostConfig": { "NetworkMode": "umbrel_main_network" }, "Ports": [],
                        "NetworkSettings": { "Networks": { "umbrel_main_network": { "IPAddress": "10.21.0.20", "Gateway": "10.21.0.1" } } } }]).to_string().into_bytes())
                } else if path == "/networks" {
                    (200, json!([{ "Id": "n1", "Name": "umbrel_main_network", "Driver": "bridge", "IPAM": { "Config": [{ "Subnet": "10.21.0.0/16", "Gateway": "10.21.0.1" }] } }]).to_string().into_bytes())
                } else if path.starts_with("/containers/nrz-bench_app_1/logs") {
                    let mut b = vec![1, 0, 0, 0, 0, 0, 0, 12];
                    b.extend_from_slice(b"gestartet 1\n");
                    (200, b)
                } else if path.starts_with("/containers/nrz-bench_app_1/json") {
                    (200, json!({ "Name": "/nrz-bench_app_1", "Config": { "Env": ["PASSWORD=geheim"], "Image": "nrz-bench" } }).to_string().into_bytes())
                } else {
                    (
                        404,
                        json!({ "message": "No such container" })
                            .to_string()
                            .into_bytes(),
                    )
                };
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
            });
        }
    });
}

#[rocket::async_test]
async fn docker_overview_logs_inspect() {
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("docker.sock");
    fake_docker(sock.clone()).await;
    let (client, _dir) = common::client_with(|f| f.merge(("docker_socket", sock.clone()))).await;
    login_as(&client, "member", false).await;
    let (s, v) = get(&client, "/api/v1/docker").await;
    assert_eq!(s, Status::Ok);
    assert_eq!(v["available"], true, "{v}");
    assert_eq!(v["version"], "27.3.1");
    assert_eq!(v["containers"][0]["name"], "nrz-bench_app_1");
    assert_eq!(v["containers"][0]["addresses"][0]["ip"], "10.21.0.20");
    assert_eq!(v["networks"][0]["containers"][0][0], "nrz-bench_app_1");
    let (s, v) = get(
        &client,
        "/api/v1/docker/containers/nrz-bench_app_1/logs?tail=10",
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v, json!(["gestartet 1"]));
    let (s, v) = get(&client, "/api/v1/docker/containers/nrz-bench_app_1").await;
    assert_eq!(s, Status::Ok);
    assert!(
        v["Config"].get("Env").is_none(),
        "Umgebungsvariablen nie ausliefern: {v}"
    );
    let (s, _) = get(&client, "/api/v1/docker/containers/gibts-nicht/logs").await;
    assert_eq!(s, Status::NotFound);
    // Ohne Socket: verständliche Meldung statt Fehler
    let (client2, _d2) =
        common::client_with(|f| f.merge(("docker_socket", "/nicht/da.sock"))).await;
    login_as(&client2, "member", false).await;
    let (s, v) = get(&client2, "/api/v1/docker").await;
    assert_eq!(s, Status::Ok);
    assert_eq!(v["available"], false);
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("Docker nicht erreichbar"),
        "{v}"
    );
}
