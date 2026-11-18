//! Monitor: wer auf deine Websites zugreift – über Cloudflare, NetBird, aus dem LAN oder
//! direkt aus dem Internet.

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::state;
use crate::ui::table::*;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{AccessCount, AccessEntry, AccessStats};

fn source_label(s: &str) -> String {
    match s {
        "cloudflare" => tr("Cloudflare"),
        "netbird" => tr("NetBird"),
        "lan" => tr("LAN"),
        "device" => tr("über das Gerät"),
        "local" => tr("lokal"),
        "internet" => tr("Internet direkt"),
        o => o.to_string(),
    }
}

fn source_tone(s: &str) -> Tone {
    match s {
        "cloudflare" => Tone::Warning,
        "netbird" => Tone::Success,
        "internet" => Tone::Danger,
        _ => Tone::Neutral,
    }
}

fn flag(cc: &str) -> String {
    if cc.len() != 2 || !cc.chars().all(|c| c.is_ascii_alphabetic()) {
        return String::new();
    }
    cc.to_uppercase()
        .chars()
        .filter_map(|c| char::from_u32(0x1F1E6 + (c as u32 - 'A' as u32)))
        .collect()
}

fn bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

#[component]
pub fn Monitor() -> Element {
    let admin = state::is_admin();
    let mut period = use_signal(|| "24h".to_string());
    let mut host = use_signal(String::new);
    let mut tick = use_signal(|| 0u64);
    let stats = use_resource(move || async move {
        let _ = tick();
        let h = host();
        let q = if h.is_empty() {
            String::new()
        } else {
            format!("&host={}", api::enc(&h))
        };
        api::get::<AccessStats>(&format!("/access/stats?period={}{q}", period())).await
    });
    let live = use_resource(move || async move {
        let _ = tick();
        let h = host();
        let q = if h.is_empty() {
            String::new()
        } else {
            format!("&host={}", api::enc(&h))
        };
        api::get::<Vec<AccessEntry>>(&format!("/access/log?limit=40{q}")).await
    });
    // Alle 10 s neu laden
    use_future(move || async move {
        loop {
            gloo_timers::future::TimeoutFuture::new(10_000).await;
            tick += 1;
        }
    });
    let hosts: Vec<String> = match &*stats.read() {
        Some(Ok(s)) => s.hosts.iter().map(|h| h.host.clone()).collect(),
        _ => Vec::new(),
    };
    rsx! {
        PageHeader { title: tr("Zugriffe"), description: tr("Wer deine Websites aufruft – über Cloudflare (mit echter Adresse und Land), NetBird, aus dem LAN oder direkt aus dem Internet.") }
        div { class: "grid grid-cols-1 gap-6",
            div { class: "flex flex-wrap items-center gap-2",
                Segmented {
                    options: vec![("24h".to_string(), tr("24 h")), ("7d".to_string(), tr("7 Tage")), ("30d".to_string(), tr("30 Tage"))],
                    value: period(),
                    onchange: move |v| period.set(v),
                }
                select { class: "{SELECT} w-auto min-w-48", value: "{host}", onchange: move |e| host.set(e.value()),
                    option { value: "", {tr("Alle Websites")} }
                    for h in hosts.iter() { option { key: "{h}", value: "{h}", "{h}" } }
                    if !host().is_empty() && !hosts.contains(&host()) { option { value: "{host}", "{host}" } }
                }
                if admin {
                    button { class: "{btn_sm(BTN_GHOST)} ml-auto", title: tr("Protokoll leeren"),
                        onclick: move |_| {
                            spawn(async move {
                                let ask = Ask::new(tr("Zugriffsprotokoll leeren?"), tr("Alle gespeicherten Zugriffe werden gelöscht.")).confirm(tr("Leeren")).destructive();
                                if !confirm(ask).await { return; }
                                match api::delete("/access/log").await {
                                    Ok(()) => tick += 1,
                                    Err(e) => toast_error(e),
                                }
                            });
                        },
                        icons::Trash2 {} {tr("Leeren")}
                    }
                }
            }
            match &*stats.read() {
                None => rsx! { Loading {} },
                Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
                Some(Ok(s)) if s.requests == 0 => rsx! {
                    div { class: "rounded-xl border border-dashed px-6 py-10 text-center text-sm text-muted-foreground",
                        {tr("Noch keine Zugriffe in diesem Zeitraum. Sobald jemand eine Website über den Reverse Proxy aufruft, erscheint sie hier.")}
                    }
                },
                Some(Ok(s)) => rsx! { Overview { stats: s.clone(), select_host: move |h: String| host.set(h) } },
            }
            Section { title: tr("Live"), description: tr("Die neuesten Zugriffe, alle 10 Sekunden aktualisiert."),
                match &*live.read() {
                    Some(Ok(list)) if !list.is_empty() => rsx! {
                        TableWrapper { Table {
                            TableHeader { tr {
                                TableHead { class: "w-24", {tr("Zeit")} }
                                TableHead { {tr("Besucher")} }
                                TableHead { {tr("Anfrage")} }
                                TableHead { class: "w-16", {tr("Status")} }
                                TableHead { class: "hidden lg:table-cell", {tr("Browser")} }
                            } }
                            TableBody {
                                for (i, e) in list.iter().cloned().enumerate() {
                                    TableRow { key: "{i}-{e.at_ms}",
                                        TableCell { class: "whitespace-nowrap text-xs text-muted-foreground", title: util::datetime(e.at_ms / 1000), "{util::relative(e.at_ms / 1000)}" }
                                        TableCell {
                                            div { class: "flex flex-wrap items-center gap-1.5",
                                                Pill { tone: source_tone(&e.source), {source_label(&e.source)} }
                                                if !e.country.is_empty() { span { title: "{e.country}", "{flag(&e.country)}" } }
                                                span { class: "font-mono text-xs", if e.client_name.is_empty() { "{e.client}" } else { "{e.client_name}" } }
                                            }
                                        }
                                        TableCell { class: "max-w-[28rem] break-all text-xs",
                                            span { class: "text-muted-foreground", "{e.method} " }
                                            span { class: "font-mono", "{e.host}{e.path}" }
                                            if e.kind == "blocked" { " " Pill { tone: Tone::Danger, {tr("Sperrseite")} } }
                                            if e.kind == "redirect" { span { class: "text-muted-foreground", " → https" } }
                                            if !e.referer.is_empty() { p { class: "text-muted-foreground", {trf("von {0}", &[&e.referer])} } }
                                        }
                                        TableCell { class: if e.status >= 500 { "text-destructive" } else if e.status >= 400 { "text-amber-500" } else { "" }, "{e.status}" }
                                        TableCell { class: "hidden max-w-xs truncate text-xs text-muted-foreground lg:table-cell", title: "{e.user_agent}", "{e.user_agent}" }
                                    }
                                }
                            }
                        } }
                    },
                    Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
                    _ => rsx! { p { class: "text-sm text-muted-foreground", {tr("Noch nichts.")} } },
                }
            }
        }
    }
}

#[component]
fn Overview(stats: AccessStats, select_host: EventHandler<String>) -> Element {
    let s = stats;
    let max = s
        .timeline
        .iter()
        .map(|b| b.requests)
        .max()
        .unwrap_or(1)
        .max(1);
    let fmt_bucket = |t: i64| {
        if s.period == "24h" {
            util::time(t)
        } else {
            util::day_month(t)
        }
    };
    rsx! {
        div { class: "grid grid-cols-2 gap-3 sm:grid-cols-5",
            StatCard { label: tr("Aufrufe"), value: util::num(s.requests) }
            StatCard { label: tr("Besucher"), value: util::num(s.visitors) }
            StatCard { label: tr("Daten"), value: bytes(s.bytes) }
            StatCard { label: tr("Serverfehler"), value: util::num(s.errors) }
            StatCard { label: tr("Sperrseite"), value: util::num(s.blocked) }
        }
        Section { title: tr("Verlauf"),
            div { class: "flex h-40 items-end gap-[2px]",
                for b in s.timeline.iter() {
                    div { key: "{b.start}", class: "group relative flex h-full flex-1 items-end",
                        title: trf("{0}: {1} Aufrufe, {2} Besucher", &[&fmt_bucket(b.start), &b.requests.to_string(), &b.visitors.to_string()]),
                        div { class: "w-full rounded-t bg-primary/70 group-hover:bg-primary", style: format!("height: {}%", bar_height(b.requests, max)) }
                    }
                }
            }
            div { class: "mt-1 flex justify-between text-[11px] text-muted-foreground",
                span { {s.timeline.first().map(|b| fmt_bucket(b.start)).unwrap_or_default()} }
                span { {s.timeline.last().map(|b| fmt_bucket(b.start)).unwrap_or_default()} }
            }
        }
        Section { title: tr("Websites"),
            TableWrapper { Table {
                TableHeader { tr {
                    TableHead { {tr("Website")} }
                    TableHead { class: "text-right", {tr("Aufrufe")} }
                    TableHead { class: "text-right", {tr("Besucher")} }
                    TableHead { class: "hidden text-right sm:table-cell", {tr("Daten")} }
                    TableHead { class: "hidden md:table-cell", {tr("Zuletzt")} }
                } }
                TableBody {
                    for h in s.hosts.iter().cloned() {
                        TableRow { key: "{h.host}",
                            TableCell {
                                button { class: "font-mono text-[13px] hover:underline", onclick: { let n = h.host.clone(); move |_| select_host.call(n.clone()) }, "{h.host}" }
                                if h.public { " " Pill { tone: Tone::Warning, {tr("öffentlich")} } }
                                if h.errors > 0 { " " Pill { tone: Tone::Danger, {trf("{0} Fehler", &[&h.errors.to_string()])} } }
                            }
                            TableCell { class: "text-right tabular-nums", "{util::num(h.requests)}" }
                            TableCell { class: "text-right tabular-nums", "{util::num(h.visitors)}" }
                            TableCell { class: "hidden text-right tabular-nums text-muted-foreground sm:table-cell", "{bytes(h.bytes)}" }
                            TableCell { class: "hidden text-muted-foreground md:table-cell", "{util::relative(h.last_at_ms / 1000)}" }
                        }
                    }
                }
            } }
        }
        div { class: "grid grid-cols-1 gap-6 lg:grid-cols-2",
            Section { title: tr("Herkunft"), Bars { items: s.sources.iter().map(|c| AccessCount { key: source_label(&c.key), count: c.count }).collect::<Vec<_>>() } }
            Section { title: tr("Länder"), description: tr("Nur über Cloudflare bekannt."),
                if s.countries.is_empty() { p { class: "text-sm text-muted-foreground", "–" } } else {
                    Bars { items: s.countries.iter().map(|c| AccessCount { key: format!("{} {}", flag(&c.key), c.key), count: c.count }).collect::<Vec<_>>() }
                }
            }
            Section { title: tr("Meistbesuchte Seiten"), Bars { items: s.paths.clone(), mono: true } }
            Section { title: tr("Browser und Bots"), Bars { items: s.agents.clone() } }
            Section { title: tr("Statuscodes"), Bars { items: s.statuses.clone(), mono: true } }
            Section { title: tr("Besucher"),
                div { class: "grid gap-1.5 text-sm",
                    for c in s.clients.iter().cloned() {
                        div { key: "{c.client}", class: "flex items-center gap-2",
                            Pill { tone: source_tone(&c.source), {source_label(&c.source)} }
                            if !c.country.is_empty() { span { "{flag(&c.country)}" } }
                            span { class: "min-w-0 flex-1 truncate font-mono text-xs", title: "{c.client}", if c.name.is_empty() { "{c.client}" } else { "{c.name} · {c.client}" } }
                            span { class: "tabular-nums text-muted-foreground", "{util::num(c.requests)}" }
                        }
                    }
                }
            }
        }
    }
}

fn bar_height(n: u64, max: u64) -> f64 {
    let h = n as f64 / max.max(1) as f64 * 100.0;
    if n > 0 { h.max(2.0) } else { 0.0 }
}

#[component]
fn Bars(items: Vec<AccessCount>, #[props(default)] mono: bool) -> Element {
    let max = items.iter().map(|c| c.count).max().unwrap_or(1).max(1);
    rsx! {
        div { class: "grid gap-1.5",
            for c in items.iter().take(12) {
                div { key: "{c.key}", class: "relative overflow-hidden rounded-md border px-2 py-1 text-sm",
                    div { class: "absolute inset-y-0 left-0 bg-primary/10", style: "width: {c.count as f64 / max as f64 * 100.0}%" }
                    div { class: "relative flex justify-between gap-3",
                        span { class: if mono { "truncate font-mono text-xs" } else { "truncate" }, title: "{c.key}", "{c.key}" }
                        span { class: "tabular-nums text-muted-foreground", "{util::num(c.count)}" }
                    }
                }
            }
        }
    }
}
