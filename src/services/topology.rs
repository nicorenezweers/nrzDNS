//! Netzwerkkarte: sammelt, wie Anfragen fliessen – aus dem Internet über Cloudflare
//! Tunnel, NetBird oder den Router zum Reverse Proxy und weiter zu Docker-Containern,
//! Geräten zu Hause und NetBird-Geräten.

use crate::config::Config;
use crate::db::now;
use crate::services::components::{self, Components};
use crate::services::{docker, integrations, proxy, spy, tools};
use nrzdns_types::{DockerContainer, TopoLink, TopoNode, Topology};
use reqwest::Method;
use serde_json::Value;
use sqlx::SqlitePool;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

#[derive(Default)]
struct Map {
    nodes: Vec<TopoNode>,
    ids: HashSet<String>,
    links: Vec<TopoLink>,
    seen: HashSet<(String, String, String)>,
}

impl Map {
    fn node(&mut self, n: TopoNode) {
        if self.ids.insert(n.id.clone()) {
            self.nodes.push(n);
        }
    }
    fn has(&self, id: &str) -> bool {
        self.ids.contains(id)
    }
    #[allow(clippy::too_many_arguments)]
    fn link(&mut self, from: &str, to: &str, kind: &str, label: &str, active: bool, hits: u64, flow: &str) {
        if !self.seen.insert((from.into(), to.into(), label.into())) {
            return;
        }
        self.links.push(TopoLink {
            from: from.into(),
            to: to.into(),
            kind: kind.into(),
            label: label.into(),
            active,
            hits,
            flow: flow.into(),
        });
    }
}

fn n(id: impl Into<String>, area: &str, kind: &str, label: impl Into<String>, sub: impl Into<String>) -> TopoNode {
    TopoNode {
        id: id.into(),
        area: area.into(),
        kind: kind.into(),
        label: label.into(),
        sub: sub.into(),
        ..TopoNode::default()
    }
}

fn st(ok: bool, warn: bool) -> String {
    if ok {
        "ok"
    } else if warn {
        "warn"
    } else {
        "off"
    }
    .into()
}

/// `http://host:port/pfad` → (host, port)
pub fn split_target(target: &str) -> (String, u16) {
    let (scheme, rest) = target.split_once("://").unwrap_or(("http", target));
    let hostport = rest.split('/').next().unwrap_or_default();
    let default = if scheme == "https" { 443 } else { 80 };
    if let Some(v6) = hostport.strip_prefix('[') {
        let (h, p) = v6.split_once(']').unwrap_or((v6, ""));
        return (h.to_string(), p.trim_start_matches(':').parse().unwrap_or(default));
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default)),
        None => (hostport.to_string(), default),
    }
}

/// `a.b.c.d/n` enthält `ip`?
fn in_cidr(cidr: &str, ip: IpAddr) -> bool {
    let Some((net, bits)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(IpAddr::V4(net)), Ok(bits), IpAddr::V4(ip)) = (net.parse::<IpAddr>(), bits.parse::<u32>(), ip) else {
        return false;
    };
    if bits > 32 {
        return false;
    }
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    (u32::from(net) & mask) == (u32::from(ip) & mask)
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_link_local(),
        IpAddr::V6(v) => (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn is_cgnat(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v) if v.octets()[0] == 100 && (64..128).contains(&v.octets()[1]))
}

/// Container, der den Port `port` auf dem Gerät veröffentlicht.
fn container_on_port(cs: &[DockerContainer], port: u16) -> Option<&DockerContainer> {
    let needle = format!(":{port}→");
    cs.iter()
        .filter(|c| c.ports.iter().any(|p| p.contains(&needle)))
        .min_by_key(|c| (c.state != "running", c.name.len()))
}

fn container_node(c: &DockerContainer) -> TopoNode {
    let ips: Vec<String> = c
        .addresses
        .iter()
        .filter(|a| !a.ip.is_empty())
        .map(|a| format!("{} ({})", a.ip, a.network))
        .collect();
    let group = if c.network_mode == "host" {
        "host".to_string()
    } else {
        c.addresses
            .iter()
            .find(|a| !a.ip.is_empty())
            .map(|a| a.network.clone())
            .unwrap_or_else(|| c.network_mode.clone())
    };
    let mut info = vec![format!("Image: {}", c.image), format!("Status: {}", c.status)];
    if !ips.is_empty() {
        info.push(format!("IP: {}", ips.join(", ")));
    }
    if !c.ports.is_empty() {
        info.push(format!("Ports: {}", c.ports.join(", ")));
    }
    TopoNode {
        id: format!("ct:{}", c.name),
        area: "docker".into(),
        kind: "container".into(),
        label: c.name.clone(),
        sub: if c.network_mode == "host" {
            "Host-Netzwerk".into()
        } else {
            c.addresses.iter().find(|a| !a.ip.is_empty()).map(|a| a.ip.clone()).unwrap_or_default()
        },
        status: st(c.state == "running", c.state == "restarting" || c.state == "paused"),
        group,
        info,
    }
}

pub async fn build(pool: &SqlitePool, config: &Config, comps: &Components) -> Topology {
    let mut m = Map::default();
    let mut notes = Vec::new();

    // ---------- Daten holen ----------
    let cstatus = components::status(pool, config, comps).await.ok();
    let comp = |name: &str| {
        cstatus
            .as_ref()
            .and_then(|s| s.components.iter().find(|c| c.name == name).cloned())
    };
    let tunnel = comp("cloudflared");
    let nbclient = comp("netbird");
    let psettings = proxy::settings(pool).await.unwrap_or_default();
    let device = proxy::device_addresses(&psettings, &config.data_dir);
    let hosts = proxy::list(pool, &device).await.unwrap_or_default();
    let dk = docker::overview(config).await;
    let containers: Vec<DockerContainer> = dk.containers.clone();
    let nb_ok = integrations::netbird(pool, Method::GET, &["peers"], None, None).await;
    let peers: Vec<Value> = match &nb_ok {
        Ok(up) if up.status < 300 => up.body.as_array().cloned().unwrap_or_default(),
        _ => Vec::new(),
    };
    let services: Vec<Value> = if peers.is_empty() {
        Vec::new()
    } else {
        match integrations::netbird(pool, Method::GET, &["reverse-proxies", "services"], None, None).await {
            Ok(up) if up.status < 300 => up.body.as_array().cloned().unwrap_or_default(),
            _ => Vec::new(),
        }
    };
    let devices = tools::devices(pool, 7).await.unwrap_or_default();
    let since = (now() - 86_400) * 1000;
    let hits: HashMap<String, u64> = sqlx::query_as::<_, (String, i64)>(
        "SELECT host, count(*) FROM access_log WHERE at_ms >= ? GROUP BY host",
    )
    .bind(since)
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(h, c)| (h, c.max(0) as u64))
    .collect();
    let mut reports = Vec::new();
    for d in spy::own_domains(pool, config).await {
        if let Ok(Some(r)) = spy::latest(pool, &d).await {
            reports.push(r);
        }
    }

    // Adressen → Namen
    let device_set: HashSet<IpAddr> = device.iter().copied().collect();
    let mut ct_by_ip: HashMap<IpAddr, &DockerContainer> = HashMap::new();
    for c in &containers {
        for a in &c.addresses {
            if let Ok(ip) = a.ip.parse::<IpAddr>() {
                ct_by_ip.insert(ip, c);
            }
        }
    }
    let docker_subnets: Vec<String> = dk.networks.iter().map(|n| n.subnet.clone()).filter(|s| !s.is_empty()).collect();
    let mut peer_by_ip: HashMap<IpAddr, &Value> = HashMap::new();
    let mut peer_by_id: HashMap<String, &Value> = HashMap::new();
    for p in &peers {
        if let Some(ip) = p["ip"].as_str().and_then(|s| s.parse().ok()) {
            peer_by_ip.insert(ip, p);
        }
        if let Some(id) = p["id"].as_str() {
            peer_by_id.insert(id.to_string(), p);
        }
    }
    let dev_names: HashMap<String, String> = devices
        .iter()
        .map(|d| (d.ip.clone(), if d.name.is_empty() { d.netbird_name.clone() } else { d.name.clone() }))
        .collect();
    let lan_ip = device.iter().find(|ip| is_private(**ip) && !ip.is_loopback()).copied();

    // ---------- Feste Punkte ----------
    let tunnel_on = tunnel.as_ref().is_some_and(|t| t.enabled)
        || cstatus.as_ref().is_some_and(|s| s.tunnel_token_set)
        || hosts.iter().any(|h| h.enabled && h.public);
    let tunnel_ok = tunnel.as_ref().is_some_and(|t| t.running && t.connected);
    if tunnel_on {
        let t = tunnel.clone().unwrap_or_default();
        let mut node = n("gw:tunnel", "gateway", "tunnel", "Cloudflare Tunnel", if tunnel_ok { "verbunden" } else if t.running { "läuft, nicht verbunden" } else { "aus" });
        node.status = st(tunnel_ok, t.running);
        if !t.installed_version.is_empty() {
            node.info.push(format!("Version {}", t.installed_version));
        }
        if !t.detail.is_empty() {
            node.info.push(t.detail.clone());
        }
        if let Some(id) = cstatus.as_ref().map(|s| s.tunnel_id.clone()).filter(|s| !s.is_empty()) {
            node.info.push(format!("Tunnel-ID {id}"));
        }
        if !t.last_error.is_empty() {
            node.info.push(format!("Fehler: {}", t.last_error));
        }
        m.node(node);
    }
    let nb_ok_client = nbclient.as_ref().is_some_and(|t| t.running && t.connected);
    if nbclient.as_ref().is_some_and(|t| t.enabled) || !peers.is_empty() {
        let t = nbclient.clone().unwrap_or_default();
        let mut node = n("gw:netbird", "gateway", "netbird", "NetBird", if nb_ok_client { "verbunden" } else if t.running { "läuft, nicht verbunden" } else { "Client aus" });
        node.status = st(nb_ok_client, t.running || !peers.is_empty());
        if !t.detail.is_empty() {
            node.info.push(t.detail.clone());
        }
        if components::netbird_kernel_mode() {
            node.info.push("WireGuard-Interface (Kernel-Modus)".into());
        }
        m.node(node);
    }
    let mut hub = n("nrz", "nrz", "hub", "nrzNetwork", lan_ip.map(|i| i.to_string()).unwrap_or_default());
    hub.status = "ok".into();
    hub.info.push(format!("Reverse Proxy: {}", config.proxy_listen.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")));
    hub.info.push(format!("Adressen: {}", device.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")));
    m.node(hub);
    let mut lan = n("gw:lan", "gateway", "lan", "Zuhause (LAN)", "lokales DNS → Proxy");
    lan.status = "ok".into();
    lan.info.push("Geräte zu Hause erreichen alle Einträge über nrzNetwork als DNS-Server.".into());
    m.node(lan);

    // ---------- Docker-Container ----------
    let mut used_ct: HashSet<String> = HashSet::new();
    let target_of = |m: &mut Map, used_ct: &mut HashSet<String>, host: &str, port: u16| -> String {
        let ip = host.parse::<IpAddr>().ok();
        let on_device = ip.is_some_and(|i| i.is_loopback() || device_set.contains(&i))
            || config.host_gateway.as_deref() == Some(host)
            || host == "localhost";
        if on_device {
            if let Some(c) = container_on_port(&containers, port) {
                used_ct.insert(c.name.clone());
                m.node(container_node(c));
                return format!("ct:{}", c.name);
            }
            let mut node = n("lan:self", "lan", "host", "Umbrel (Host)", lan_ip.map(|i| i.to_string()).unwrap_or_default());
            node.status = "ok".into();
            m.node(node);
            return "lan:self".into();
        }
        if let Some(i) = ip {
            if let Some(c) = ct_by_ip.get(&i) {
                used_ct.insert(c.name.clone());
                m.node(container_node(c));
                return format!("ct:{}", c.name);
            }
            if let Some(p) = peer_by_ip.get(&i) {
                let id = format!("nb:{i}");
                m.node(peer_node(p, &device_set));
                return id;
            }
            if is_private(i) {
                let id = format!("lan:{i}");
                let name = dev_names.get(&i.to_string()).filter(|s| !s.is_empty()).cloned().unwrap_or_else(|| i.to_string());
                let mut node = n(&id, "lan", "device", name, i.to_string());
                node.status = "ok".into();
                m.node(node);
                return id;
            }
        } else if let Some(c) = containers.iter().find(|c| c.name == host) {
            used_ct.insert(c.name.clone());
            m.node(container_node(c));
            return format!("ct:{}", c.name);
        }
        let id = format!("ext:{host}");
        m.node(n(&id, "internet", "external", host, "extern"));
        id
    };

    // ---------- Reverse-Proxy-Einträge ----------
    for h in hosts.iter().filter(|h| h.enabled) {
        let (thost, tport) = split_target(&h.target);
        let id = format!("ph:{}", h.id);
        let hcount = hits.get(&h.host).copied().unwrap_or(0);
        let mut node = n(&id, "nrz", "proxy", &h.host, format!("→ {thost}:{tport}"));
        node.status = "ok".into();
        node.info.push(format!("Ziel: {}", h.target));
        if !h.comment.is_empty() {
            node.info.push(h.comment.clone());
        }
        node.info.push(if h.public { "Öffentlich über den Cloudflare Tunnel".into() } else { "Nur zu Hause / über NetBird".into() });
        if hcount > 0 {
            node.info.push(format!("{hcount} Zugriffe in 24 h"));
        }
        m.node(node);
        m.link("gw:lan", &id, "lan", "", true, 0, "");
        if h.public {
            let dom = format!("dom:{}", h.host);
            let mut dn = n(&dom, "internet", "domain", &h.host, "öffentlich");
            dn.status = st(tunnel_ok, tunnel_on);
            m.node(dn);
            m.link(&dom, "gw:tunnel", "tunnel", "", tunnel_ok, hcount, &h.host);
            m.link("gw:tunnel", &id, "tunnel", "", tunnel_ok, hcount, &h.host);
        }
        let to = target_of(&mut m, &mut used_ct, &thost, tport);
        m.link(&id, &to, "proxy", &format!(":{tport}"), true, hcount, &h.host);
    }

    // ---------- NetBird-Freigaben (Reverse Proxy von NetBird) ----------
    if !services.is_empty() {
        let mut gw = n("gw:nbproxy", "gateway", "netbird", "NetBird Reverse Proxy", "öffentliche Freigaben");
        gw.status = "ok".into();
        m.node(gw);
    }
    for svc in &services {
        let domain = svc["domain"].as_str().unwrap_or_default();
        if domain.is_empty() {
            continue;
        }
        let enabled = svc["enabled"].as_bool().unwrap_or(true);
        let dom = format!("dom:{domain}");
        let mut dn = n(&dom, "internet", "domain", domain, "NetBird-Freigabe");
        dn.status = st(enabled, false);
        m.node(dn);
        let hc = hits.get(domain).copied().unwrap_or(0);
        m.link(&dom, "gw:nbproxy", "netbird", "", enabled, hc, domain);
        for t in svc["targets"].as_array().into_iter().flatten() {
            let port = t["port"].as_u64().unwrap_or(0) as u16;
            let peer = t["target_id"].as_str().and_then(|id| peer_by_id.get(id)).copied();
            let host = t["host"].as_str().unwrap_or_default();
            let (to, via) = match peer {
                Some(p) => {
                    let ip = p["ip"].as_str().unwrap_or_default();
                    let name = p["name"].as_str().unwrap_or_default();
                    let mine = ip.parse::<IpAddr>().is_ok_and(|i| device_set.contains(&i));
                    if mine {
                        (target_of(&mut m, &mut used_ct, ip, port), format!("{name}:{port}"))
                    } else {
                        m.node(peer_node(p, &device_set));
                        (format!("nb:{ip}"), format!(":{port}"))
                    }
                }
                None if !host.is_empty() => (target_of(&mut m, &mut used_ct, host, port), format!(":{port}")),
                None => continue,
            };
            m.link("gw:nbproxy", &to, "netbird", &via, enabled && t["enabled"].as_bool().unwrap_or(true), hc, domain);
        }
    }

    // ---------- Was Spy von aussen sieht (Router, Tunnel-CNAMEs) ----------
    let mut router_ports: Vec<u16> = Vec::new();
    let mut home_ip = String::new();
    for r in &reports {
        let homes: HashMap<&str, &Vec<u16>> = r.addresses.iter().filter(|a| a.home).map(|a| (a.ip.as_str(), &a.open_ports)).collect();
        for a in r.addresses.iter().filter(|a| a.home) {
            home_ip = a.ip.clone();
            router_ports.extend(a.open_ports.iter().copied());
        }
        for h in r.hosts.iter().filter(|h| !h.dangling) {
            let dom = format!("dom:{}", h.name);
            let via_home: Vec<u16> = h.addresses.iter().filter_map(|a| homes.get(a.as_str())).flat_map(|p| p.iter().copied()).collect();
            let tunnel_cname = h.cname.contains("cfargotunnel.com");
            if via_home.is_empty() && !tunnel_cname {
                continue;
            }
            if !m.has(&dom) {
                let mut dn = n(&dom, "internet", "domain", &h.name, if h.http_status > 0 { format!("HTTP {}", h.http_status) } else { String::new() });
                dn.status = st(h.http_status > 0 && h.http_status < 500, h.http_status >= 500);
                if !h.server.is_empty() {
                    dn.info.push(format!("Server: {}", h.server));
                }
                m.node(dn);
            }
            let hc = hits.get(&h.name).copied().unwrap_or(0);
            if tunnel_cname && m.has("gw:tunnel") {
                m.link(&dom, "gw:tunnel", "tunnel", "", tunnel_ok, hc, &h.name);
            }
            if !via_home.is_empty() {
                let mut ports = via_home.clone();
                ports.sort_unstable();
                ports.dedup();
                let label = ports.iter().take(4).map(ToString::to_string).collect::<Vec<_>>().join(",");
                m.link(&dom, "gw:router", "router", &label, true, hc, &h.name);
            }
        }
    }
    router_ports.sort_unstable();
    router_ports.dedup();
    if m.links.iter().any(|l| l.to == "gw:router") || !router_ports.is_empty() {
        let mut node = n("gw:router", "gateway", "router", "Router (Heim-IP)", home_ip.clone());
        node.status = if router_ports.is_empty() { "ok".into() } else { "warn".into() };
        if router_ports.is_empty() {
            node.info.push("Keine offenen Ports gefunden.".into());
        } else {
            node.info.push(format!(
                "Offen aus dem Internet: {}",
                router_ports.iter().map(|p| format!("{p} ({})", nrzdns_types::port_service(*p))).collect::<Vec<_>>().join(", ")
            ));
        }
        m.node(node);
        let web: Vec<String> = router_ports.iter().filter(|p| matches!(p, 80 | 443)).map(ToString::to_string).collect();
        if !web.is_empty() {
            m.link("gw:router", "nrz", "router", &web.join("/"), true, 0, "");
        }
        for p in router_ports.iter().filter(|p| !matches!(p, 80 | 443)) {
            let to = target_of(&mut m, &mut used_ct, "127.0.0.1", *p);
            m.link("gw:router", &to, "router", &format!(":{p}"), true, 0, "");
        }
    }
    for h in &hosts {
        if h.enabled && m.has("gw:router") && m.links.iter().any(|l| l.to == "gw:router" && l.from == format!("dom:{}", h.host)) {
            m.link("nrz", &format!("ph:{}", h.id), "proxy", "", true, 0, &h.host);
        }
    }

    // ---------- Docker: Umbrel-App-Proxys zu ihrer App ----------
    for c in containers.iter().filter(|c| used_ct.contains(&c.name) && c.service == "app_proxy" && !c.app.is_empty()) {
        if let Some(app) = containers
            .iter()
            .filter(|o| o.app == c.app && o.service != "app_proxy" && o.service != "tor_server")
            .min_by_key(|o| match o.service.as_str() {
                "web" | "app" | "server" | "frontend" => 0,
                _ => 1,
            })
        {
            m.node(container_node(app));
            m.link(&format!("ct:{}", c.name), &format!("ct:{}", app.name), "docker", "", app.state == "running", 0, "");
        }
    }
    // alle übrigen Container (die Oberfläche blendet sie bei Bedarf ein)
    for c in &containers {
        m.node(container_node(c));
    }
    if !dk.available {
        notes.push(format!("Docker nicht erreichbar: {}", dk.error));
    }

    // ---------- NetBird-Geräte ----------
    for p in &peers {
        let node = peer_node(p, &device_set);
        let id = node.id.clone();
        let online = node.status == "ok";
        m.node(node);
        if m.has("gw:netbird") {
            m.link("gw:netbird", &id, "mesh", "", online && nb_ok_client, 0, "");
        }
    }
    match &nb_ok {
        Err(_) => notes.push("NetBird-API nicht eingerichtet (Token unter Einstellungen → Verbindungen) – NetBird-Geräte fehlen.".into()),
        Ok(up) if up.status >= 300 => notes.push(format!("NetBird-API antwortet mit {}.", up.status)),
        _ => {}
    }

    // ---------- Geräte zu Hause ----------
    let mut count = 0;
    for d in &devices {
        let Ok(ip) = d.ip.parse::<IpAddr>() else { continue };
        if ip.is_loopback() || device_set.contains(&ip) || is_cgnat(ip) || !is_private(ip) || ct_by_ip.contains_key(&ip) || docker_subnets.iter().any(|s| in_cidr(s, ip)) {
            continue;
        }
        if count >= 40 {
            break;
        }
        count += 1;
        let id = format!("lan:{ip}");
        let name = if !d.name.is_empty() { d.name.clone() } else if !d.netbird_name.is_empty() { d.netbird_name.clone() } else { d.ip.clone() };
        let mut node = n(&id, "lan", "device", name, &d.ip);
        node.status = st(now() - d.last_seen < 3600, now() - d.last_seen < 86_400);
        node.info.push(format!("{} DNS-Anfragen in 7 Tagen, {} gesperrt", d.queries, d.blocked));
        m.node(node);
        m.link(&id, "nrz", "dns", "DNS", now() - d.last_seen < 3600, 0, "");
    }
    if let Some(ip) = lan_ip {
        let mut node = n("lan:self", "lan", "host", "Umbrel (Host)", ip.to_string());
        node.status = "ok".into();
        m.node(node);
    }

    if !tunnel_on {
        notes.push("Cloudflare Tunnel ist nicht eingerichtet (Einstellungen → Komponenten).".into());
    }
    if reports.is_empty() {
        notes.push("Noch kein Spy-Bericht – offene Ports und Domains beim Router fehlen.".into());
    }

    Topology {
        nodes: m.nodes,
        links: m.links,
        notes,
        generated_at: now(),
    }
}

fn peer_node(p: &Value, device: &HashSet<IpAddr>) -> TopoNode {
    let ip = p["ip"].as_str().unwrap_or_default();
    let name = p["name"].as_str().unwrap_or_default();
    let online = p["connected"].as_bool().unwrap_or(false);
    let mine = ip.parse::<IpAddr>().is_ok_and(|i| device.contains(&i));
    let mut node = n(
        format!("nb:{ip}"),
        "netbird",
        "peer",
        if mine { format!("{name} (dieses Gerät)") } else { name.to_string() },
        ip,
    );
    node.status = st(online, false);
    for (k, label) in [("os", "System"), ("hostname", "Hostname"), ("version", "NetBird")] {
        if let Some(v) = p[k].as_str().filter(|s| !s.is_empty()) {
            node.info.push(format!("{label}: {v}"));
        }
    }
    if let Some(v) = p["connection_ip"].as_str().filter(|s| !s.is_empty()) {
        node.info.push(format!("Verbindet von {v}"));
    }
    node
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_and_cidr() {
        assert_eq!(split_target("http://10.21.0.5:8550/x"), ("10.21.0.5".into(), 8550));
        assert_eq!(split_target("https://nas.local"), ("nas.local".into(), 443));
        assert_eq!(split_target("http://[fd00::1]:81"), ("fd00::1".into(), 81));
        assert!(in_cidr("172.17.0.0/16", "172.17.3.4".parse().unwrap()));
        assert!(!in_cidr("172.17.0.0/16", "192.168.0.4".parse().unwrap()));
        assert!(is_cgnat("100.78.1.2".parse().unwrap()));
        assert!(!is_cgnat("100.20.1.2".parse().unwrap()));
    }

    #[test]
    fn container_port_match() {
        let c = DockerContainer {
            name: "bench_app_proxy_1".into(),
            state: "running".into(),
            ports: vec!["0.0.0.0:8550→8550/tcp".into()],
            ..DockerContainer::default()
        };
        assert_eq!(container_on_port(std::slice::from_ref(&c), 8550).map(|c| c.name.as_str()), Some("bench_app_proxy_1"));
        assert!(container_on_port(&[c], 855).is_none());
    }
}
