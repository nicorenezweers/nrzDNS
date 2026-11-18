//! Docker auf dem Gerät: alle Container mit internen Adressen und Ports, Netze, Logs
//! (nur lesend).

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::json::Dot;
use crate::ui::table::*;
use dioxus::prelude::*;
use nrzdns_types::DockerOverview;

#[component]
pub fn Docker() -> Element {
    let mut tick = use_signal(|| 0u64);
    let data = use_resource(move || async move {
        let _ = tick();
        api::get::<DockerOverview>("/docker").await
    });
    let mut q = use_signal(String::new);
    let mut logs_for = use_signal(|| None::<String>);
    let mut logs_open = use_signal(|| false);
    let logs = use_resource(move || async move {
        match logs_for() {
            Some(n) => Some(api::get::<Vec<String>>(&format!("/docker/containers/{}/logs?tail=300", api::enc(&n))).await),
            None => None,
        }
    });
    rsx! {
        PageHeader { title: tr("Docker"), description: tr("Alle Container auf dem Gerät mit ihren internen Adressen, Netzen und Ports – nur zum Ansehen.") }
        match &*data.read() {
            None => rsx! { Loading {} },
            Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
            Some(Ok(d)) if !d.available => rsx! {
                Callout { text: trf("Docker ist nicht erreichbar: {0}", &[&d.error]), error: true }
            },
            Some(Ok(d)) => {
                let f = q().trim().to_lowercase();
                let running = d.containers.iter().filter(|c| c.state == "running").count();
                let shown: Vec<_> = d.containers.iter().filter(|c| {
                    f.is_empty() || c.name.to_lowercase().contains(&f) || c.app.to_lowercase().contains(&f) || c.image.to_lowercase().contains(&f)
                        || c.addresses.iter().any(|a| a.ip.contains(&f)) || c.ports.iter().any(|p| p.contains(&f))
                }).cloned().collect();
                rsx! {
                    div { class: "grid grid-cols-1 gap-6",
                        div { class: "grid grid-cols-2 gap-3 sm:grid-cols-4",
                            StatCard { label: tr("Container"), value: d.containers.len().to_string() }
                            StatCard { label: tr("Laufen"), value: running.to_string() }
                            StatCard { label: tr("Netze"), value: d.networks.len().to_string() }
                            StatCard { label: tr("Docker"), value: d.version.clone() }
                        }
                        Section { title: tr("Container"),
                            actions: rsx! { button { class: btn_sm(BTN_OUTLINE), onclick: move |_| tick += 1, icons::RefreshCw {} {tr("Neu laden")} } },
                            div { class: "mb-3", SearchInput { value: q(), oninput: move |v| q.set(v), placeholder: tr("Name, App, Image, IP, Port …") } }
                            TableWrapper { Table {
                                TableHeader { tr {
                                    TableHead { {tr("Container")} }
                                    TableHead { {tr("Interne Adressen")} }
                                    TableHead { class: "hidden md:table-cell", {tr("Ports")} }
                                    TableHead { class: "hidden lg:table-cell", {tr("Image")} }
                                    TableHead { class: "w-12" }
                                } }
                                TableBody {
                                    for c in shown {
                                        TableRow { key: "{c.id}",
                                            TableCell {
                                                div { class: "flex items-center gap-2",
                                                    Dot { on: c.state == "running" }
                                                    div {
                                                        p { class: "font-mono text-[13px] break-all", "{c.name}" }
                                                        p { class: "text-xs text-muted-foreground", if c.app.is_empty() { "{c.status}" } else { "{c.app} · {c.status}" } }
                                                    }
                                                }
                                            }
                                            TableCell { class: "font-mono text-xs",
                                                if c.network_mode == "host" { span { class: "text-muted-foreground", {tr("Host-Netzwerk")} } }
                                                for a in c.addresses.iter().filter(|a| !a.ip.is_empty()) {
                                                    p { key: "{a.network}", "{a.ip}" span { class: "font-sans text-muted-foreground", " · {a.network}" } }
                                                }
                                            }
                                            TableCell { class: "hidden font-mono text-xs text-muted-foreground md:table-cell",
                                                for p in c.ports.iter() { p { key: "{p}", "{p}" } }
                                            }
                                            TableCell { class: "hidden max-w-xs truncate text-xs text-muted-foreground lg:table-cell", title: "{c.image}", "{c.image}" }
                                            TableCell { class: "px-2 text-right",
                                                button { class: icon_btn(""), title: tr("Logs"), onclick: { let n = c.name.clone(); move |_| { logs_for.set(Some(n.clone())); logs_open.set(true); } }, icons::ScrollText {} }
                                            }
                                        }
                                    }
                                }
                            } }
                        }
                        Section { title: tr("Netze"),
                            div { class: "grid grid-cols-1 gap-3 md:grid-cols-2",
                                for n in d.networks.iter().cloned() {
                                    div { key: "{n.id}", class: "rounded-lg border p-3 text-sm",
                                        p { class: "flex flex-wrap items-center gap-2 font-medium",
                                            icons::Network { class: "size-4" } "{n.name}"
                                            Pill { "{n.driver}" }
                                            if n.internal { Pill { {tr("intern")} } }
                                        }
                                        p { class: "mt-0.5 font-mono text-xs text-muted-foreground", {if n.subnet.is_empty() { "–".to_string() } else { format!("{} · Gateway {}", n.subnet, n.gateway) }} }
                                        if !n.containers.is_empty() {
                                            div { class: "mt-2 grid gap-0.5 font-mono text-xs",
                                                for (name, ip) in n.containers.iter().take(40) { p { key: "{name}", span { class: "inline-block w-28 text-muted-foreground", "{ip}" } "{name}" } }
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
        Modal { open: logs_open, title: logs_for().unwrap_or_default(), description: tr("Letzte 300 Zeilen"), class: "max-w-4xl",
            match &*logs.read() {
                Some(Some(Ok(lines))) => rsx! {
                    div { class: "max-h-[60vh] overflow-auto rounded-lg border bg-muted/30 p-2 font-mono text-[11px] leading-relaxed",
                        if lines.is_empty() { p { class: "text-muted-foreground", {tr("Keine Ausgabe.")} } }
                        for (i, l) in lines.iter().enumerate() { p { key: "{i}", class: "whitespace-pre-wrap break-all", "{l}" } }
                    }
                },
                Some(Some(Err(e))) => rsx! { Callout { text: e.message.clone(), error: true } },
                _ => rsx! { Loading {} },
            }
        }
    }
}
