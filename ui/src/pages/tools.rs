//! Netzwerk-Tools: Ping, Port-Check, HTTP-Check (über den Server) und Subnetz-Rechner (hier).

use crate::api;
use crate::components::common::*;
use crate::i18n::{tr, trf};
use crate::ui::table::*;
use dioxus::prelude::*;
use nrzdns_types::{
    HttpCheckInput, HttpCheckResult, PingInput, PingResult, PortState, PortsInput, PortsResult,
};
use std::net::Ipv4Addr;

const COMMON_PORTS: &str = "21,22,23,25,53,80,110,143,443,445,465,587,993,995,1883,3000,3306,5432,5900,8080,8096,8123,8443,9000";

#[component]
pub fn Tools() -> Element {
    let mut tab = use_signal(|| "ping".to_string());
    rsx! {
        PageHeader { title: tr("Netzwerk-Tools"), description: tr("Erreichbarkeit, offene Ports und Webseiten prüfen – vom Gerät aus, auf dem nrzNetwork läuft.") }
        div { class: "grid grid-cols-1 gap-6",
            Segmented {
                options: vec![
                    ("ping".to_string(), tr("Ping")),
                    ("ports".to_string(), tr("Ports")),
                    ("http".to_string(), tr("HTTP")),
                    ("subnet".to_string(), tr("Subnetz-Rechner")),
                ],
                value: tab(),
                onchange: move |v| tab.set(v),
            }
            match tab().as_str() {
                "ports" => rsx! { Ports {} },
                "http" => rsx! { Http {} },
                "subnet" => rsx! { Subnet {} },
                _ => rsx! { Ping {} },
            }
        }
    }
}

fn ms(v: Option<f64>) -> String {
    v.map_or_else(|| "–".to_string(), |v| format!("{v:.1} ms"))
}

#[component]
fn Ping() -> Element {
    let mut host = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut result = use_signal(|| None::<Result<PingResult, String>>);
    let run = move |e: FormEvent| {
        e.prevent_default();
        spawn(async move {
            busy.set(true);
            let r = api::post::<PingResult, _>(
                "/tools/ping",
                &PingInput {
                    host: host().trim().to_string(),
                    count: 4,
                },
            )
            .await;
            busy.set(false);
            result.set(Some(r.map_err(|e| e.message)));
        });
    };
    rsx! {
        Section { title: tr("Ping"), description: tr("Antwortet ein Gerät, und wie schnell? Namen werden über nrzNetwork aufgelöst."),
            form { class: "grid grid-cols-1 gap-2 sm:grid-cols-[minmax(0,1fr)_auto]", onsubmit: run,
                input { class: "{INPUT} font-mono text-[13px]", required: true, spellcheck: false, autocapitalize: "none",
                    placeholder: tr("Name oder IP, z. B. 192.168.0.1 oder example.com"), value: "{host}", oninput: move |e| host.set(e.value()) }
                button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy() || host().trim().is_empty(),
                    if busy() { icons::LoaderCircle { class: "size-4 animate-spin" } } else { icons::Activity {} }
                    {tr("Ping")}
                }
            }
            match &*result.read() {
                None => rsx! {},
                Some(Err(e)) => rsx! { div { class: "mt-4", Callout { text: e.clone(), error: true } } },
                Some(Ok(r)) => rsx! {
                    div { class: "mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4",
                        Stat { label: tr("Adresse"), value: r.ip.clone() }
                        Stat { label: tr("Durchschnitt"), value: ms(r.avg_ms) }
                        Stat { label: tr("Min / Max"), value: format!("{} / {}", ms(r.min_ms), ms(r.max_ms)) }
                        Stat { label: tr("Verlust"), value: format!("{:.0} %", r.loss_percent) }
                    }
                    p { class: "mt-3 text-xs text-muted-foreground",
                        if r.method == "tcp" { {tr("ICMP ist hier nicht erlaubt – gemessen wurde der Verbindungsaufbau (TCP).")} } else { {tr("ICMP-Echo")} }
                        " · "
                        {r.probes.iter().map(|p| ms(*p)).collect::<Vec<_>>().join(" · ")}
                    }
                },
            }
        }
    }
}

#[component]
fn Stat(#[props(into)] label: String, #[props(into)] value: String) -> Element {
    rsx! {
        div { class: "rounded-lg border px-3 py-2",
            p { class: "text-xs text-muted-foreground", "{label}" }
            p { class: "mt-0.5 font-mono text-sm break-all", "{value}" }
        }
    }
}

#[component]
fn Ports() -> Element {
    let mut host = use_signal(String::new);
    let mut ports = use_signal(|| COMMON_PORTS.to_string());
    let mut only_open = use_signal(|| true);
    let mut busy = use_signal(|| false);
    let mut result = use_signal(|| None::<Result<PortsResult, String>>);
    let run = move |e: FormEvent| {
        e.prevent_default();
        spawn(async move {
            busy.set(true);
            let r = api::post::<PortsResult, _>(
                "/tools/ports",
                &PortsInput {
                    host: host().trim().to_string(),
                    ports: ports().trim().to_string(),
                },
            )
            .await;
            busy.set(false);
            result.set(Some(r.map_err(|e| e.message)));
        });
    };
    rsx! {
        Section { title: tr("Port-Check"), description: tr("Welche Dienste sind auf einem Gerät erreichbar? Höchstens 200 Ports auf einmal."),
            form { class: "grid grid-cols-1 gap-3", onsubmit: run,
                div { class: "grid grid-cols-1 gap-2 sm:grid-cols-2",
                    input { class: "{INPUT} font-mono text-[13px]", required: true, spellcheck: false, autocapitalize: "none",
                        placeholder: tr("Name oder IP"), value: "{host}", oninput: move |e| host.set(e.value()) }
                    input { class: "{INPUT} font-mono text-[13px]", required: true, spellcheck: false,
                        placeholder: "22,80,443,8000-8010", value: "{ports}", oninput: move |e| ports.set(e.value()) }
                }
                div { class: "flex flex-wrap items-center justify-between gap-2",
                    Toggle { checked: only_open(), onchange: move |v| only_open.set(v), label: tr("Nur offene zeigen") }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy() || host().trim().is_empty(),
                        if busy() { icons::LoaderCircle { class: "size-4 animate-spin" } } else { icons::Radar {} }
                        {tr("Prüfen")}
                    }
                }
            }
            match &*result.read() {
                None => rsx! {},
                Some(Err(e)) => rsx! { div { class: "mt-4", Callout { text: e.clone(), error: true } } },
                Some(Ok(r)) => {
                    let open = r.ports.iter().filter(|p| p.state == PortState::Open).count();
                    let shown: Vec<_> = r.ports.iter().filter(|p| !only_open() || p.state == PortState::Open).cloned().collect();
                    rsx! {
                        p { class: "mt-4 text-sm text-muted-foreground", {trf("{0}: {1} von {2} Ports offen", &[&r.ip, &open.to_string(), &r.ports.len().to_string()])} }
                        if !shown.is_empty() {
                            div { class: "mt-3",
                                TableWrapper {
                                    Table {
                                        TableHeader { tr { TableHead { {tr("Port")} } TableHead { {tr("Zustand")} } TableHead { {tr("Zeit")} } } }
                                        TableBody {
                                            for p in shown {
                                                TableRow { key: "{p.port}",
                                                    TableCell { class: "font-mono", "{p.port}" }
                                                    TableCell {
                                                        match p.state {
                                                            PortState::Open => rsx! { span { class: "text-emerald-500", {tr("offen")} } },
                                                            PortState::Closed => rsx! { span { class: "text-muted-foreground", {tr("geschlossen")} } },
                                                            PortState::Timeout => rsx! { span { class: "text-amber-500", {tr("keine Antwort")} } },
                                                        }
                                                    }
                                                    TableCell { class: "font-mono text-muted-foreground", "{ms(p.ms)}" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn Http() -> Element {
    let mut url = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut result = use_signal(|| None::<Result<HttpCheckResult, String>>);
    let run = move |e: FormEvent| {
        e.prevent_default();
        spawn(async move {
            busy.set(true);
            let r = api::post::<HttpCheckResult, _>(
                "/tools/http",
                &HttpCheckInput {
                    url: url().trim().to_string(),
                },
            )
            .await;
            busy.set(false);
            result.set(Some(r.map_err(|e| e.message)));
        });
    };
    rsx! {
        Section { title: tr("HTTP-Check"), description: tr("Antwortet eine Webseite oder App? Mit Statuscode, Zeit, Weiterleitungen und Headern."),
            form { class: "grid grid-cols-1 gap-2 sm:grid-cols-[minmax(0,1fr)_auto]", onsubmit: run,
                input { class: "{INPUT} font-mono text-[13px]", required: true, spellcheck: false, autocapitalize: "none",
                    placeholder: "http://music.nrz.ch", value: "{url}", oninput: move |e| url.set(e.value()) }
                button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy() || url().trim().is_empty(),
                    if busy() { icons::LoaderCircle { class: "size-4 animate-spin" } } else { icons::Gauge {} }
                    {tr("Prüfen")}
                }
            }
            match &*result.read() {
                None => rsx! {},
                Some(Err(e)) => rsx! { div { class: "mt-4", Callout { text: e.clone(), error: true } } },
                Some(Ok(r)) => rsx! {
                    div { class: "mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4",
                        Stat { label: tr("Status"), value: format!("{} {}", r.status, r.reason) }
                        Stat { label: tr("Zeit"), value: format!("{:.0} ms", r.ms) }
                        Stat { label: tr("Server"), value: if r.remote.is_empty() { "–".to_string() } else { r.remote.clone() } }
                        Stat { label: tr("Verschlüsselt"), value: if r.tls { tr("ja (HTTPS)") } else { tr("nein") } }
                    }
                    if r.final_url != r.url {
                        p { class: "mt-3 text-xs text-muted-foreground break-all", {trf("Weitergeleitet nach {0}", &[&r.final_url])} }
                    }
                    div { class: "mt-3 max-h-80 overflow-auto rounded-lg border bg-muted/30 p-3 font-mono text-xs",
                        for (k, v) in r.headers.iter() {
                            p { class: "break-all", span { class: "text-muted-foreground", "{k}: " } "{v}" }
                        }
                    }
                },
            }
        }
    }
}

/// `192.168.0.10/24` → Kennzahlen des Netzes.
fn subnet(input: &str) -> Option<Vec<(String, String)>> {
    let (ip, prefix) = input.trim().split_once('/').unwrap_or((input.trim(), "24"));
    let ip: Ipv4Addr = ip.trim().parse().ok()?;
    let prefix: u32 = if prefix.contains('.') {
        let m: Ipv4Addr = prefix.trim().parse().ok()?;
        let bits = u32::from(m);
        if bits.leading_ones() + bits.trailing_zeros() != 32 {
            return None;
        }
        bits.leading_ones()
    } else {
        prefix.trim().parse().ok().filter(|p| *p <= 32)?
    };
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let net = u32::from(ip) & mask;
    let bcast = net | !mask;
    let (first, last, hosts) = match prefix {
        32 => (net, net, 1u64),
        31 => (net, bcast, 2),
        _ => (net + 1, bcast - 1, u64::from(bcast - net) - 1),
    };
    let a = |v: u32| Ipv4Addr::from(v).to_string();
    Some(vec![
        (tr("Netz"), format!("{}/{prefix}", a(net))),
        (tr("Netzmaske"), a(mask)),
        (tr("Wildcard"), a(!mask)),
        (tr("Broadcast"), a(bcast)),
        (tr("Erste Adresse"), a(first)),
        (tr("Letzte Adresse"), a(last)),
        (tr("Nutzbare Adressen"), crate::util::num(hosts)),
    ])
}

#[component]
fn Subnet() -> Element {
    let mut input = use_signal(|| "192.168.0.198/24".to_string());
    let rows = subnet(&input());
    rsx! {
        Section { title: tr("Subnetz-Rechner"), description: tr("Netz, Maske, Broadcast und Adressbereich zu einer IPv4-Adresse mit Präfix oder Maske."),
            input { class: "{INPUT} font-mono text-[13px]", spellcheck: false, value: "{input}", oninput: move |e| input.set(e.value()),
                placeholder: "192.168.0.10/24 oder 10.0.0.1/255.255.0.0" }
            match rows {
                None => rsx! { p { class: "mt-3 text-sm text-destructive", {tr("Bitte eine IPv4-Adresse mit Präfix angeben, z. B. 192.168.0.10/24.")} } },
                Some(rows) => rsx! {
                    div { class: "mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2",
                        for (k, v) in rows {
                            Stat { key: "{k}", label: k.clone(), value: v }
                        }
                    }
                },
            }
        }
    }
}
