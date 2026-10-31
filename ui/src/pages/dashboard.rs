//! Dashboard: Zeitraum, Kennzahlen, Verlauf, Aufteilung nach Antwortart, Toplisten (Klick
//! öffnet das gefilterte Abfrageprotokoll) und der Zustand des Servers mit Weiterleitungen.
//! Lädt sich alle `dashboard_refresh_secs` Sekunden neu, solange die Seite sichtbar ist.

use crate::Route;
use crate::api;
use crate::components::chart::TrafficChart;
use crate::components::common::*;
use crate::components::pause::{BlockingState, PauseControl};
use crate::i18n::{tr, trf};
use crate::labels;
use crate::state;
use crate::ui::alert::{Alert, AlertDescription, AlertTitle, AlertVariant};
use crate::ui::card::{Card, CardContent, CardHeader, CardTitle};
use crate::ui::progress::Progress;
use crate::ui::table::*;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{Dashboard as Data, ServerStatus, StatsRange, StatsTotals, TopEntry};

#[component]
pub fn Dashboard(range: Option<String>) -> Element {
    let nav = use_navigator();
    let current = range
        .as_deref()
        .and_then(StatsRange::parse)
        .unwrap_or_else(|| state::prefs().dashboard_range);
    let mut tick = use_signal(|| 0u64);
    let mut data = use_signal(|| None::<Data>);
    let mut error = use_signal(|| None::<String>);
    let res = use_resource(use_reactive!(|current| async move {
        let _ = tick();
        match api::get::<Data>(&format!("/dashboard?range={}", current.as_str())).await {
            Ok(d) => {
                data.set(Some(d));
                error.set(None);
            }
            Err(e) => error.set(Some(e.message)),
        }
    }));
    // Automatisch neu laden (0 = nie); im Hintergrund nicht
    use_future(move || async move {
        loop {
            let secs = state::prefs().dashboard_refresh_secs;
            gloo_timers::future::TimeoutFuture::new(if secs == 0 {
                5_000
            } else {
                secs.clamp(5, 3600) * 1000
            })
            .await;
            if secs > 0 && !util::page_hidden() {
                tick += 1;
            }
        }
    });

    let loading = !res.finished();
    let d = data();
    let period = labels::range_period(current);
    rsx! {
        PageHeader {
            title: tr("Dashboard"),
            description: tr("Was dein DNS-Server gerade tut."),
            actions: rsx! {
                Segmented {
                    options: StatsRange::ALL.iter().map(|r| (r.as_str().to_string(), labels::range(*r))).collect::<Vec<_>>(),
                    value: current.as_str().to_string(),
                    onchange: move |v: String| {
                        nav.replace(Route::Dashboard { range: Some(v) });
                    },
                }
                button { class: icon_btn("size-9"), title: tr("Neu laden"), disabled: loading, onclick: move |_| tick += 1,
                    icons::RefreshCw { class: if loading { "size-4 animate-spin" } else { "size-4" } }
                }
            },
        }
        if let Some(e) = error() {
            div { class: "mb-4",
                Callout { text: e, error: true }
            }
        }
        match d {
            None if error().is_none() => rsx! { Loading {} },
            None => rsx! {},
            Some(d) => rsx! {
                div { class: if loading { "grid grid-cols-1 gap-6 opacity-70 transition-opacity" } else { "grid grid-cols-1 gap-6 transition-opacity" },
                    ListenWarnings { errors: d.server.listen_errors.clone() }
                    Totals { totals: d.totals.clone() }
                    div { class: "grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1fr)_20rem]",
                        Card { class: "gap-4 py-5",
                            CardHeader { class: "px-5",
                                CardTitle { {tr("Verlauf")} }
                            }
                            CardContent { class: "px-5", TrafficChart { points: d.series.clone(), range: current } }
                        }
                        Breakdown { totals: d.totals.clone() }
                    }
                    div { class: "grid grid-cols-1 gap-6 md:grid-cols-2 2xl:grid-cols-4",
                        TopList { title: tr("Top-Clients"), entries: d.top_clients.clone(), empty: tr("Noch keine Clients."), on_pick: move |name: String| { nav.push(Route::logs_filtered(&name, "", "", "", period)); } }
                        TopList { title: tr("Top-Domains"), entries: d.top_domains.clone(), empty: tr("Noch keine Anfragen."), mono: true, on_pick: move |name: String| { nav.push(Route::logs_filtered("", &name, "", "", period)); } }
                        TopList { title: tr("Top gesperrte Domains"), entries: d.top_blocked.clone(), empty: tr("Noch nichts gesperrt."), mono: true, danger: true, on_pick: move |name: String| { nav.push(Route::logs_filtered("", &name, "", "blocked", period)); } }
                        TopList { title: tr("Anfragetypen"), entries: d.query_types.clone(), empty: tr("Noch keine Anfragen."), on_pick: move |name: String| { nav.push(Route::logs_filtered("", "", &name, "", period)); } }
                    }
                    ServerPanel { server: d.server.clone(), on_change: move |_| tick += 1 }
                }
            },
        }
    }
}

/// Deutlicher Hinweis, wenn DNS-Adressen nicht geöffnet werden konnten (z. B. Port 53 belegt).
#[component]
fn ListenWarnings(errors: Vec<String>) -> Element {
    if errors.is_empty() {
        return rsx! {};
    }
    rsx! {
        Alert { variant: AlertVariant::Destructive,
            icons::TriangleAlert {}
            AlertTitle { {tr("DNS läuft nicht auf allen Adressen")} }
            AlertDescription {
                p { {tr("Diese Adressen konnten nicht geöffnet werden – meist ist Port 53 schon von einem anderen Dienst belegt (z. B. systemd-resolved, dnsmasq oder ein anderer DNS-Server).")} }
                ul { class: "mt-1 grid gap-0.5 font-mono text-xs",
                    for e in errors {
                        li { key: "{e}", "{e}" }
                    }
                }
            }
        }
    }
}

#[component]
fn Totals(totals: StatsTotals) -> Element {
    let t = totals;
    rsx! {
        div { class: "grid grid-cols-1 gap-3",
            div { class: "grid grid-cols-2 gap-3 lg:grid-cols-4",
                StatCard { large: true, label: tr("Anfragen"), value: util::num(t.queries), icon: rsx! { icons::Activity {} } }
                StatCard { large: true, label: tr("Gesperrt"), value: util::num(t.blocked), sub: trf("{0} aller Anfragen", &[&util::percent(t.blocked, t.queries)]), icon: rsx! { icons::ShieldBan {} } }
                StatCard { large: true, label: tr("Aus dem Cache"), value: util::num(t.cached), sub: trf("{0} aller Anfragen", &[&util::percent(t.cached, t.queries)]), icon: rsx! { icons::Database {} } }
                StatCard { large: true, label: tr("Weitergeleitet"), value: util::num(t.forwarded), sub: trf("{0} aller Anfragen", &[&util::percent(t.forwarded, t.queries)]), icon: rsx! { icons::Send {} } }
            }
            div { class: "grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5",
                StatCard { label: tr("Verbindlich"), value: util::num(t.authoritative), sub: tr("aus eigenen Zonen") }
                StatCard { label: "NXDOMAIN", value: util::num(t.nx_domain), sub: util::percent(t.nx_domain, t.queries) }
                StatCard { label: "SERVFAIL", value: util::num(t.server_failure), sub: util::percent(t.server_failure, t.queries) }
                StatCard { label: tr("Clients"), value: util::num(t.clients), sub: tr("verschiedene Adressen") }
                StatCard { label: tr("Ø Antwortzeit"), value: util::ms(t.avg_duration_ms), sub: tr("über alle Anfragen") }
            }
        }
    }
}

/// Aufteilung nach Antwortart als gestapelter Balken mit Liste darunter.
#[component]
fn Breakdown(totals: StatsTotals) -> Element {
    let t = totals;
    let rows: Vec<(String, u64, &str)> = vec![
        (tr("Weitergeleitet"), t.forwarded, "oklch(0.52 0 0)"),
        (tr("Aus dem Cache"), t.cached, "oklch(0.66 0 0)"),
        (tr("Verbindlich"), t.authoritative, "oklch(0.8 0 0)"),
        (tr("Gesperrt"), t.blocked, "oklch(0.63 0.13 25)"),
        (tr("Lokal"), t.local, "oklch(0.42 0 0)"),
        (tr("Verworfen"), t.dropped, "oklch(0.36 0 0)"),
        (tr("Fehlgeschlagen"), t.failed, "oklch(0.65 0.1 70)"),
    ];
    let total = t.queries.max(1);
    let codes: Vec<(&str, u64)> = vec![
        ("NOERROR", t.no_error),
        ("NXDOMAIN", t.nx_domain),
        ("SERVFAIL", t.server_failure),
        ("REFUSED", t.refused),
    ];
    rsx! {
        Card { class: "gap-4 py-5",
            CardHeader { class: "px-5",
                CardTitle { {tr("Antwortarten")} }
            }
            CardContent { class: "grid grid-cols-1 gap-5 px-5",
                div { class: "flex h-2.5 w-full gap-[2px] overflow-hidden rounded-full bg-muted",
                    for (label , n , color) in rows.iter().filter(|r| r.1 > 0) {
                        div { key: "{label}", class: "h-full first:rounded-l-full last:rounded-r-full", title: "{label}: {util::num(*n)}", style: "width: {*n as f64 / total as f64 * 100.0}%; background: {color}" }
                    }
                }
                ul { class: "grid grid-cols-1 gap-1.5 text-sm",
                    for (label , n , color) in rows.iter() {
                        li { key: "{label}", class: "flex items-center gap-2",
                            span { class: "size-2.5 shrink-0 rounded-[3px]", style: "background: {color}" }
                            span { class: "flex-1 truncate text-muted-foreground", "{label}" }
                            span { class: "font-medium tabular-nums", {util::num(*n)} }
                            span { class: "w-14 text-right text-xs tabular-nums text-muted-foreground", {util::percent(*n, t.queries)} }
                        }
                    }
                }
                div { class: "border-t pt-4",
                    p { class: "mb-2 text-xs font-medium uppercase tracking-wider text-muted-foreground", {tr("Antwortcodes")} }
                    ul { class: "grid grid-cols-1 gap-1.5 text-sm",
                        for (code , n) in codes {
                            li { key: "{code}", class: "flex items-center gap-2",
                                span { class: "flex-1", Rcode { code } }
                                span { class: "font-medium tabular-nums", {util::num(n)} }
                                span { class: "w-14 text-right text-xs tabular-nums text-muted-foreground", {util::percent(n, t.queries)} }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Topliste mit Balken; ein Klick öffnet das Abfrageprotokoll mit diesem Filter.
#[component]
fn TopList(
    #[props(into)] title: String,
    entries: Vec<TopEntry>,
    #[props(into)] empty: String,
    on_pick: EventHandler<String>,
    #[props(default)] mono: bool,
    #[props(default)] danger: bool,
) -> Element {
    let max = entries.iter().map(|e| e.hits).max().unwrap_or(1).max(1);
    let font = if mono { "font-mono text-[13px]" } else { "" };
    let bar = if danger {
        "bg-destructive/60"
    } else {
        "bg-primary/45"
    };
    rsx! {
        Card { class: "gap-3 py-5",
            CardHeader { class: "px-5",
                CardTitle { "{title}" }
            }
            CardContent { class: "px-3",
                if entries.is_empty() {
                    p { class: "px-2 py-6 text-center text-sm text-muted-foreground", "{empty}" }
                }
                ul { class: "grid grid-cols-1 gap-0.5",
                    for e in entries {
                        li { key: "{e.name}",
                            button {
                                class: "group grid w-full gap-1 rounded-md px-2 py-1.5 text-left hover:bg-accent/50",
                                title: tr("Im Abfrageprotokoll zeigen"),
                                onclick: {
                                    let name = e.name.clone();
                                    move |_| on_pick.call(name.clone())
                                },
                                span { class: "flex items-baseline gap-2 text-sm",
                                    span { class: "min-w-0 flex-1 truncate {font}", "{e.name}" }
                                    span { class: "shrink-0 tabular-nums text-muted-foreground group-hover:text-foreground", {util::num(e.hits)} }
                                }
                                Progress { value: e.hits as f64 / max as f64 * 100.0, class: "h-1 bg-transparent", indicator_class: bar }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Zustand des Servers: Adressen, DoH, Laufzeit, Last, Sperren und die Weiterleitungen.
#[component]
fn ServerPanel(server: ServerStatus, on_change: EventHandler<()>) -> Element {
    let s = server;
    let doh = format!(
        "{}{}",
        util::origin(),
        if s.doh_path.is_empty() {
            "/dns-query"
        } else {
            s.doh_path.as_str()
        }
    );
    rsx! {
        div { class: "grid grid-cols-1 gap-6 xl:grid-cols-[22rem_minmax(0,1fr)]",
            Card { class: "gap-4 py-5",
                CardHeader { class: "px-5",
                    div { class: "flex w-full flex-wrap items-center justify-between gap-2",
                        CardTitle { {tr("Server")} }
                        span { class: "text-xs text-muted-foreground", {trf("Version {0}", &[&s.version])} }
                    }
                }
                CardContent { class: "grid grid-cols-1 gap-4 px-5 text-sm",
                    div { class: "flex flex-wrap items-center justify-between gap-2",
                        BlockingState { enabled: s.blocking_enabled, paused_until: s.blocking_paused_until }
                        PauseControl { enabled: s.blocking_enabled, paused_until: s.blocking_paused_until, on_done: move |_| on_change.call(()) }
                    }
                    dl { class: "grid grid-cols-[auto_1fr] gap-x-4 gap-y-2",
                        dt { class: "text-muted-foreground", {tr("Läuft seit")} }
                        dd { class: "text-right", title: util::datetime(s.started_at), {util::uptime(s.uptime_secs)} }
                        dt { class: "text-muted-foreground", {tr("Anfragen/s")} }
                        dd { class: "text-right tabular-nums", {util::decimal(s.queries_per_second, 1)} }
                        dt { class: "text-muted-foreground", {tr("Seit dem Start")} }
                        dd { class: "text-right tabular-nums", {util::num(s.queries_since_start)} }
                        dt { class: "text-muted-foreground", {tr("Im Cache")} }
                        dd { class: "text-right tabular-nums", {util::num(s.cache_entries)} }
                        dt { class: "text-muted-foreground", {tr("Zonen")} }
                        dd { class: "text-right tabular-nums", {util::num(s.zones as u64)} }
                        dt { class: "text-muted-foreground", {tr("Gesperrte Domains")} }
                        dd { class: "text-right tabular-nums", {util::num(s.blocked_domains)} }
                    }
                    div { class: "grid grid-cols-1 gap-1.5 border-t pt-4",
                        p { class: "text-xs font-medium uppercase tracking-wider text-muted-foreground", {tr("DNS hört auf")} }
                        if s.dns_listen.is_empty() {
                            p { class: "text-muted-foreground", {tr("Keine Adresse offen.")} }
                        }
                        for a in s.dns_listen.iter() {
                            p { key: "{a}", class: "font-mono text-xs", "{a}" }
                        }
                        for e in s.listen_errors.iter() {
                            p { key: "{e}", class: "font-mono text-xs text-destructive", "{e}" }
                        }
                    }
                    div { class: "grid grid-cols-1 gap-1.5 border-t pt-4",
                        p { class: "text-xs font-medium uppercase tracking-wider text-muted-foreground", {tr("DNS über HTTPS")} }
                        if s.doh_enabled {
                            div { class: "flex items-center gap-1 rounded-md border bg-background/40 pl-2.5",
                                code { class: "min-w-0 flex-1 truncate font-mono text-xs", "{doh}" }
                                CopyButton { text: doh.clone(), title: tr("Adresse kopieren") }
                            }
                        } else {
                            p { class: "text-muted-foreground", {tr("Ausgeschaltet (Einstellungen → Allgemein).")} }
                        }
                    }
                }
            }
            Card { class: "gap-4 py-5",
                CardHeader { class: "px-5",
                    CardTitle { {tr("Weiterleitungen")} }
                }
                CardContent { class: "px-5",
                    if s.upstreams.is_empty() {
                        p { class: "py-6 text-center text-sm text-muted-foreground", {tr("Noch keine Anfrage weitergeleitet.")} }
                    } else {
                        TableWrapper { class: "bg-transparent",
                            Table {
                                TableHeader {
                                    tr {
                                        TableHead { {tr("Server")} }
                                        TableHead { class: "text-right", {tr("Erfolgreich")} }
                                        TableHead { class: "text-right", {tr("Fehler")} }
                                        TableHead { class: "text-right", {tr("Ø Zeit")} }
                                        TableHead { class: "hidden md:table-cell", {tr("Letzter Fehler")} }
                                    }
                                }
                                TableBody {
                                    for u in s.upstreams.iter().cloned() {
                                        TableRow { key: "{u.upstream}",
                                            TableCell {
                                                p { class: "font-medium", if u.name.is_empty() { "{u.upstream}" } else { "{u.name}" } }
                                                if !u.name.is_empty() {
                                                    p { class: "font-mono text-xs text-muted-foreground", "{u.upstream}" }
                                                }
                                            }
                                            TableCell { class: "text-right tabular-nums", {util::num(u.ok)} }
                                            TableCell { class: if u.failed > 0 { "text-right tabular-nums text-warning" } else { "text-right tabular-nums text-muted-foreground" }, {util::num(u.failed)} }
                                            TableCell { class: "text-right tabular-nums whitespace-nowrap", {util::ms(u.avg_ms)} }
                                            TableCell { class: "hidden max-w-xs md:table-cell",
                                                if let Some(e) = &u.last_error {
                                                    p { class: "truncate text-xs text-warning", title: "{e}", "{e}" }
                                                    if let Some(at) = u.last_error_at {
                                                        p { class: "text-xs text-muted-foreground", {util::relative(at)} }
                                                    }
                                                } else {
                                                    span { class: "text-xs text-muted-foreground", "–" }
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
