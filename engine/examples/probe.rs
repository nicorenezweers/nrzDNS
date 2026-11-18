//! Kurzer Test gegen echte Server (braucht Internet):
//! `cargo run -p nrzdns-engine --example probe [name] [blocklist-url]`
//!
//! Fragt `name` (Vorgabe `example.com`) über UDP, TCP, DoT und DoH bei Cloudflare und Quad9,
//! einmal über die eigene Pipeline mit DoT-Weiterleitung, und lädt optional eine Sperrliste.
//!
//! `cargo run -p nrzdns-engine --example probe listen 127.0.0.1:5353` startet stattdessen den
//! Server auf dieser Adresse (zum Testen mit `dig -p 5353 @127.0.0.1 example.com`) und gibt
//! das Abfrageprotokoll aus.

use nrzdns_engine::types::{DnsSettings, ResolveInput, Upstream, UpstreamProtocol};
use nrzdns_engine::{blocklist, Engine};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let name = args.next().unwrap_or_else(|| "example.com".into());
    let list = args.next();

    let settings = DnsSettings {
        forwarders: vec![Upstream::new(
            UpstreamProtocol::Tls,
            "1.1.1.1:853",
            "cloudflare-dns.com",
            "Cloudflare DoT",
        )],
        ..DnsSettings::default()
    };
    let (engine, mut log) = Engine::new(settings, "probe");

    if name == "listen" {
        let addr = list.unwrap_or_else(|| "127.0.0.1:5353".into());
        let Ok(addr) = addr.parse() else {
            println!("Ungültige Adresse {addr}");
            return;
        };
        engine.set_custom_blocked(vec!["doubleclick.net".into()]);
        let errors = engine.listen(&[addr]).await;
        println!("{:?} {errors:?}", engine.status().dns_listen);
        while let Some(e) = log.recv().await {
            println!(
                "{} {} {} {} {:?} {} {} ms {}",
                e.client, e.qname, e.qtype, e.rcode, e.kind, e.answer, e.duration_ms, e.upstream
            );
        }
        return;
    }

    let targets = [
        ("1.1.1.1", UpstreamProtocol::Udp),
        ("1.1.1.1", UpstreamProtocol::Tcp),
        ("1.1.1.1:853", UpstreamProtocol::Tls),
        ("https://1.1.1.1/dns-query", UpstreamProtocol::Https),
        ("https://dns.quad9.net/dns-query", UpstreamProtocol::Https),
        ("", UpstreamProtocol::Udp),
        ("", UpstreamProtocol::Udp),
    ];
    for (server, protocol) in targets {
        let input = ResolveInput {
            name: name.clone(),
            qtype: "A".into(),
            server: server.into(),
            protocol,
        };
        match engine.resolve(&input).await {
            Ok(r) => {
                let answers: Vec<String> = r
                    .answers
                    .iter()
                    .map(|a| format!("{} {} {}", a.qtype, a.ttl, a.data))
                    .collect();
                println!(
                    "{:<36} {:<8} {:>4} ms  {:?} [{}]  {}",
                    r.server,
                    r.rcode,
                    r.duration_ms,
                    r.kind,
                    r.flags.join(" "),
                    answers.join(", ")
                );
            }
            Err(e) => println!("{server:<36} Fehler: {e}"),
        }
    }
    println!("{:#?}", engine.status().upstreams);

    if let Some(url) = list {
        match blocklist::download(&url).await {
            Ok(domains) => println!(
                "{url}: {} Domains, z. B. {:?}",
                domains.len(),
                domains.first()
            ),
            Err(e) => println!("{url}: Fehler: {e}"),
        }
    }
}
