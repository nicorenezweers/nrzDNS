//! Spy: was andere im Internet über deine Domain wissen können – mit Bewertung und
//! Empfehlungen.

use crate::Route;
use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::json::Dot;
use crate::state;
use crate::ui::table::*;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{Severity, SpyHistoryEntry, SpyReport, SpyScanInput, SpySettings, SpyStatus};

#[component]
pub fn Spy() -> Element {
    let admin = state::is_admin();
    let mut tick = use_signal(|| 0u64);
    let status = use_resource(move || async move {
        let _ = tick();
        api::get::<SpyStatus>("/spy").await
    });
    let mut domain = use_signal(String::new);
    let mut active = use_signal(|| true);
    let mut selected = use_signal(String::new);
    // Bericht aus dem Verlauf (Domain, Zeitpunkt)
    let mut viewing = use_signal(|| None::<(String, i64)>);
    let mut busy = use_signal(|| false);

    let running = matches!(&*status.read(), Some(Ok(s)) if s.running);
    use_effect(move || {
        let running = matches!(&*status.read(), Some(Ok(s)) if s.running);
        if running {
            spawn(async move {
                gloo_timers::future::TimeoutFuture::new(1500).await;
                tick += 1;
            });
        }
    });
    use_effect(move || {
        let first = match &*status.read() {
            Some(Ok(s)) => s.own_domains.first().cloned(),
            _ => None,
        };
        let empty = domain.peek().is_empty();
        if let (Some(d), true) = (first, empty) {
            domain.set(d);
        }
    });
    let own: Vec<String> = match &*status.read() {
        Some(Ok(s)) => s.own_domains.clone(),
        _ => Vec::new(),
    };
    let start = move |e: FormEvent| {
        e.prevent_default();
        let input = SpyScanInput {
            domain: domain().trim().to_string(),
            active: active(),
        };
        spawn(async move {
            busy.set(true);
            let res = api::post::<SpyStatus, _>("/spy/scan", &input).await;
            busy.set(false);
            match res {
                Ok(_) => {
                    selected.set(input.domain.to_lowercase());
                    viewing.set(None);
                    tick += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };
    let old_report = use_resource(move || async move {
        match viewing() {
            Some((d, at)) => Some(
                api::get::<SpyReport>(&format!("/spy/report?domain={}&at={at}", api::enc(&d)))
                    .await,
            ),
            None => None,
        }
    });

    rsx! {
        PageHeader { title: tr("Spy"), description: tr("Was andere im Internet über deine Domains wissen können – Subdomains aus Zertifikaten, E-Mails, DNS-Einträge, Mail- und DNS-Anbieter, Hoster, dein Anschluss zu Hause, alle offenen Ports. Mit Bewertung, Anleitungen und täglichem Protokoll.") }
        div { class: "grid grid-cols-1 gap-6",
            Section { title: tr("Domain prüfen"), description: tr("Nur deine eigenen Domains (aus Cloudflare und den HTTPS-Einstellungen). Gesammelt wird, was ein Angreifer sieht: Certificate-Transparency-Logs, DNS von aussen, Registrierungsdaten – dazu aktiv Webserver und Ports."),
                if own.is_empty() {
                    Callout { text: tr("Noch keine eigene Domain bekannt – Cloudflare unter Einstellungen → Verbindungen verbinden oder unter Reverse Proxy → HTTPS die Domain eintragen.") }
                } else {
                    form { class: "grid grid-cols-1 gap-3", onsubmit: start,
                        div { class: "grid grid-cols-1 gap-2 sm:grid-cols-[minmax(0,1fr)_auto]",
                            select { class: "{SELECT} font-mono text-[13px]", disabled: !admin, value: "{domain}", onchange: move |e| domain.set(e.value()),
                                for d in own.iter() { option { key: "{d}", value: "{d}", "{d}" } }
                            }
                            if admin {
                                button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: running || busy() || domain().is_empty(),
                                    if running { icons::LoaderCircle { class: "size-4 animate-spin" } } else { icons::ScanEye {} }
                                    {tr("Scan starten")}
                                }
                            }
                        }
                        if admin {
                            Toggle { checked: active(), onchange: move |v| active.set(v),
                                label: tr("Auch aktiv prüfen (Webserver, alle Ports)"),
                                hint: tr("Fragt deine öffentlichen Server und deinen Anschluss direkt an. Alle 65 535 Ports dauern je Adresse ein paar Minuten. Geprüft wird von innen – dein Router kann von aussen anders aussehen."),
                            }
                        } else {
                            ReadOnlyHint {}
                        }
                    }
                }
                if let Some(Ok(s)) = &*status.read() {
                    if s.running || !s.progress.is_empty() {
                        div { class: "mt-4 rounded-lg border bg-muted/30 p-3 text-sm",
                            for (i, p) in s.progress.iter().enumerate() {
                                p { key: "{i}", class: if p.starts_with("Fehlgeschlagen") { "text-destructive" } else if i + 1 == s.progress.len() && s.running { "flex items-center gap-2" } else { "text-muted-foreground" },
                                    if i + 1 == s.progress.len() && s.running { icons::LoaderCircle { class: "size-3.5 animate-spin" } }
                                    "{p}"
                                }
                            }
                            if s.running && s.port_progress > 0 && s.port_progress < 100 {
                                div { class: "mt-2 h-2 overflow-hidden rounded-full bg-muted",
                                    div { class: "h-full bg-primary transition-all", style: format!("width: {}%", s.port_progress) }
                                }
                                p { class: "mt-1 text-xs text-muted-foreground", {trf("Ports: {0} %", &[&s.port_progress.to_string()])} }
                            }
                        }
                    }
                }
            }
            if let Some(Ok(s)) = &*status.read() {
                Schedule { key: "{s.settings.auto}-{s.settings.hour}-{s.settings.all_ports}-{s.settings.scan_home}", settings: s.settings.clone(), admin, tick }
            }
            match &*status.read() {
                None => rsx! { Loading {} },
                Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
                Some(Ok(s)) if s.reports.is_empty() => rsx! {},
                Some(Ok(s)) => {
                    let current = s.reports.iter().find(|r| r.domain == selected()).or(s.reports.first()).cloned().unwrap_or_default();
                    let history: Vec<SpyHistoryEntry> = s.history.iter().filter(|h| h.domain == current.domain).cloned().collect();
                    let shown = match (viewing(), &*old_report.read()) {
                        (Some(_), Some(Some(Ok(r)))) => r.clone(),
                        _ => current.clone(),
                    };
                    rsx! {
                        if s.reports.len() > 1 {
                            div { class: "flex flex-wrap gap-2",
                                for r in s.reports.iter().cloned() {
                                    button { key: "{r.domain}", class: if r.domain == current.domain { btn_sm(BTN_PRIMARY) } else { btn_sm(BTN_OUTLINE) },
                                        onclick: move |_| { selected.set(r.domain.clone()); viewing.set(None); },
                                        "{r.domain}"
                                        span { class: "ml-1 opacity-70", "{r.score}" }
                                    }
                                }
                            }
                        }
                        if viewing().is_some() {
                            div { class: "flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm",
                                span { {trf("Älterer Bericht vom {0}", &[&util::datetime(shown.scanned_at)])} }
                                button { class: btn_sm(BTN_OUTLINE), onclick: move |_| viewing.set(None), {tr("Zum neuesten")} }
                            }
                        }
                        Report { report: shown, admin, tick }
                        History { entries: history, viewing }
                    }
                }
            }
        }
    }
}

/// Täglicher Scan aller eigenen Domains.
#[component]
fn Schedule(settings: SpySettings, admin: bool, tick: Signal<u64>) -> Element {
    let mut auto = use_signal(|| settings.auto);
    let mut hour = use_signal(|| settings.hour);
    let mut all_ports = use_signal(|| settings.all_ports);
    let mut scan_home = use_signal(|| settings.scan_home);
    let save = move |e: FormEvent| {
        e.prevent_default();
        let body = SpySettings {
            auto: auto(),
            hour: hour(),
            all_ports: all_ports(),
            scan_home: scan_home(),
        };
        spawn(async move {
            match api::put::<SpyStatus, _>("/spy/settings", &body).await {
                Ok(_) => {
                    toast(tr("Gespeichert."));
                    tick += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };
    let hours: Vec<u8> = (0..24).collect();
    rsx! {
        Section { title: tr("Protokoll und Zeitplan"), description: tr("Spy prüft alle eigenen Domains automatisch und vergleicht mit dem letzten Mal – neue Subdomains, neue offene Ports, neue Zertifikate und behobene Punkte stehen im Verlauf."),
            form { class: "grid grid-cols-1 gap-4", onsubmit: save,
                div { class: "grid grid-cols-1 gap-4 sm:grid-cols-[1fr_auto] sm:items-end",
                    Toggle { checked: auto(), disabled: !admin, onchange: move |v| auto.set(v), label: tr("Täglich automatisch prüfen (mit aktiven Prüfungen)") }
                    Field { label: tr("Uhrzeit"),
                        select { class: "{SELECT} w-32", disabled: !admin || !auto(), value: "{hour}", onchange: move |e| hour.set(e.value().parse().unwrap_or(4)),
                            for h in hours { option { key: "{h}", value: "{h}", {format!("{h:02}:00")} } }
                        }
                    }
                }
                Toggle { checked: all_ports(), disabled: !admin, onchange: move |v| all_ports.set(v), label: tr("Alle 65 535 Ports prüfen"), hint: tr("Sonst nur die rund 30 wichtigsten (schneller).") }
                Toggle { checked: scan_home(), disabled: !admin, onchange: move |v| scan_home.set(v), label: tr("Auch deinen Internetanschluss prüfen"), hint: tr("Die öffentliche Adresse dieses Anschlusses – auch wenn kein Eintrag darauf zeigt, Bots finden sie trotzdem.") }
                if admin {
                    div { class: "flex justify-end", button { class: btn(BTN_PRIMARY), r#type: "submit", {tr("Speichern")} } }
                }
            }
        }
    }
}

/// Verlauf einer Domain mit Änderungen.
#[component]
fn History(entries: Vec<SpyHistoryEntry>, viewing: Signal<Option<(String, i64)>>) -> Element {
    if entries.is_empty() {
        return rsx! {};
    }
    rsx! {
        Section { title: tr("Verlauf"), description: tr("Jeder Scan mit Bewertung und dem, was sich seit dem vorigen geändert hat."),
            div { class: "grid gap-2",
                for e in entries.iter().cloned() {
                    {
                        let (g, gcls) = grade(e.score);
                        let key = (e.domain.clone(), e.scanned_at);
                        rsx! {
                            div { key: "{e.scanned_at}", class: "rounded-lg border p-3 text-sm",
                                div { class: "flex flex-wrap items-center gap-3",
                                    span { class: "inline-flex size-8 items-center justify-center rounded-full border-2 text-sm font-bold {gcls}", "{g}" }
                                    div { class: "min-w-0 flex-1",
                                        p { class: "font-medium", {util::datetime(e.scanned_at)} if e.scheduled { span { class: "ml-2 text-xs font-normal text-muted-foreground", {tr("automatisch")} } } }
                                        p { class: "text-xs text-muted-foreground", {trf("Bewertung {0}/100 · {1} Punkte zum Verbessern", &[&e.score.to_string(), &e.problems.to_string()])} }
                                    }
                                    button { class: btn_sm(BTN_GHOST), onclick: move |_| viewing.set(Some(key.clone())), icons::Eye {} {tr("Ansehen")} }
                                }
                                if !e.changes.is_empty() {
                                    ul { class: "mt-2 grid gap-0.5 pl-11 text-xs",
                                        for (i, c) in e.changes.iter().enumerate() {
                                            li { key: "{i}", class: if c.starts_with("Behoben") || c.starts_with("Port geschlossen") || c.starts_with("Nicht mehr") { "text-emerald-500" } else if c.starts_with("Bewertung") { "text-muted-foreground" } else { "text-amber-500" }, "{c}" }
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

/// Wohin der Knopf einer Anleitung führt.
fn link_route(link: &str) -> Option<(Route, String)> {
    match link {
        "dns" => Some((Route::Domains {}, tr("DNS-Einträge öffnen"))),
        "proxy" | "https" => Some((Route::Proxy {}, tr("Reverse Proxy öffnen"))),
        "integrations" => Some((
            Route::Settings {
                section: "integrations".into(),
            },
            tr("Verbindungen öffnen"),
        )),
        "components" => Some((
            Route::Settings {
                section: "components".into(),
            },
            tr("Komponenten öffnen"),
        )),
        "netbird" => Some((Route::Netbird {}, tr("NetBird öffnen"))),
        _ => None,
    }
}

fn grade(score: u8) -> (&'static str, &'static str) {
    match score {
        90..=100 => ("A", "text-emerald-500 border-emerald-500/40"),
        75..=89 => ("B", "text-lime-500 border-lime-500/40"),
        60..=74 => ("C", "text-amber-500 border-amber-500/40"),
        40..=59 => ("D", "text-orange-500 border-orange-500/40"),
        _ => ("E", "text-red-500 border-red-500/40"),
    }
}

fn sev(s: Severity) -> (Tone, String) {
    match s {
        Severity::High => (Tone::Danger, tr("hoch")),
        Severity::Medium => (Tone::Warning, tr("mittel")),
        Severity::Low => (Tone::Neutral, tr("niedrig")),
        Severity::Info => (Tone::Neutral, tr("Info")),
    }
}

#[component]
fn Report(report: SpyReport, admin: bool, tick: Signal<u64>) -> Element {
    let r = report;
    let (g, gcls) = grade(r.score);
    let problems = r
        .findings
        .iter()
        .filter(|f| f.severity > Severity::Info)
        .count();
    let names = r
        .cert_names
        .iter()
        .filter(|c| !c.name.starts_with("*."))
        .count();
    let domain = r.domain.clone();
    let reg = r.registration.clone();
    rsx! {
        div { class: "grid grid-cols-1 gap-6",
            div { class: "flex flex-wrap items-center gap-5 rounded-xl border p-5",
                div { class: "flex size-20 shrink-0 flex-col items-center justify-center rounded-full border-4 {gcls}",
                    span { class: "text-3xl font-bold leading-none", "{g}" }
                    span { class: "text-xs", "{r.score}/100" }
                }
                div { class: "min-w-0 flex-1",
                    p { class: "text-lg font-semibold break-all", "{r.domain}" }
                    p { class: "text-sm text-muted-foreground",
                        {trf("Geprüft {0}", &[&util::relative(r.scanned_at)])}
                        if r.active { " · " {tr("mit aktiven Prüfungen")} } else { " · " {tr("nur öffentliche Quellen")} }
                    }
                    p { class: "mt-1 text-sm", if problems == 0 { {tr("Keine Probleme gefunden.")} } else { {trf("{0} Punkte zum Verbessern.", &[&problems.to_string()])} } }
                }
                if admin {
                    button { class: icon_btn("hover:text-destructive"), title: tr("Bericht löschen"),
                        onclick: move |_| {
                            let d = domain.clone();
                            spawn(async move {
                                match api::delete(&format!("/spy/reports/{}", api::enc(&d))).await {
                                    Ok(()) => tick += 1,
                                    Err(e) => toast_error(e),
                                }
                            });
                        },
                        icons::Trash2 {}
                    }
                }
            }
            div { class: "grid grid-cols-2 gap-3 sm:grid-cols-4",
                StatCard { label: tr("Namen in Zertifikaten"), value: names.to_string() }
                StatCard { label: tr("Zertifikate"), value: r.cert_count.to_string() }
                StatCard { label: tr("Öffentliche Adressen"), value: r.addresses.len().to_string() }
                StatCard { label: tr("E-Mails gefunden"), value: r.cert_emails.len().to_string() }
            }
            for e in r.errors.iter() {
                Callout { key: "{e}", text: trf("Quelle nicht erreichbar: {0}", &[e]) }
            }
            Section { title: tr("Erkenntnisse"), description: tr("Sortiert nach Schwere – mit dem, was ein Angreifer daraus macht, und was du tun kannst."),
                div { class: "grid grid-cols-1 gap-3",
                    for (i, f) in r.findings.iter().cloned().enumerate() {
                        {
                            let (tone, label) = sev(f.severity);
                            rsx! {
                                details { key: "{i}", class: "group rounded-lg border p-3 open:bg-muted/20", open: f.severity >= Severity::Medium,
                                    summary { class: "flex cursor-pointer list-none items-center gap-2",
                                        Pill { tone, "{label}" }
                                        span { class: "font-medium", "{f.title}" }
                                        icons::ChevronDown { class: "ml-auto size-4 text-muted-foreground transition-transform group-open:rotate-180" }
                                    }
                                    div { class: "mt-2 grid gap-2 text-sm",
                                        p { class: "text-muted-foreground", "{f.detail}" }
                                        if !f.advice.is_empty() {
                                            p { span { class: "font-medium", {tr("Empfehlung:")} " " } "{f.advice}" }
                                        }
                                        if !f.items.is_empty() {
                                            div { class: "max-h-56 overflow-auto rounded-md border bg-background p-2 font-mono text-xs",
                                                for (j, it) in f.items.iter().enumerate() { p { key: "{j}", class: "break-all", "{it}" } }
                                            }
                                        }
                                        if !f.steps.is_empty() {
                                            div { class: "rounded-md border bg-background p-3",
                                                p { class: "mb-1.5 flex items-center gap-1.5 font-medium", icons::ListChecks { class: "size-4" } {tr("So behebst du es")} }
                                                ol { class: "grid list-decimal gap-1 pl-5 text-muted-foreground",
                                                    for (j, st) in f.steps.iter().enumerate() { li { key: "{j}", "{st}" } }
                                                }
                                                if let Some((route, label)) = link_route(&f.link) {
                                                    Link { class: "{btn_sm(BTN_OUTLINE)} mt-3", to: route, icons::ArrowRight {} "{label}" }
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
            div { class: "grid grid-cols-1 gap-6 lg:grid-cols-2",
                Section { title: tr("Registrierung"),
                    dl { class: "grid grid-cols-[8rem_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-sm",
                        dt { class: "text-muted-foreground", {tr("Registrar")} } dd { if reg.registrar.is_empty() { "–" } else { "{reg.registrar}" } }
                        dt { class: "text-muted-foreground", {tr("Registriert")} } dd { {if reg.created == 0 { "–".to_string() } else { util::date(reg.created) }} }
                        dt { class: "text-muted-foreground", {tr("Läuft ab")} } dd { {if reg.expires == 0 { "–".to_string() } else { util::date(reg.expires) }} }
                        dt { class: "text-muted-foreground", "DNSSEC" } dd { class: "flex items-center gap-2", Dot { on: reg.dnssec } if reg.dnssec { {tr("an")} } else { {tr("aus")} } }
                        dt { class: "text-muted-foreground", {tr("Kontakte")} } dd { if reg.contacts.is_empty() { {tr("geschwärzt")} } else { for c in reg.contacts.iter() { p { key: "{c}", class: "break-all", "{c}" } } } }
                        dt { class: "text-muted-foreground", {tr("Quelle")} } dd { class: "text-muted-foreground", if reg.source.is_empty() { "–" } else { "{reg.source}" } }
                    }
                }
                Section { title: tr("DNS und Mail"),
                    dl { class: "grid grid-cols-[8rem_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-sm",
                        dt { class: "text-muted-foreground", {tr("DNS-Anbieter")} } dd { if r.dns_provider.is_empty() { "–" } else { "{r.dns_provider}" } }
                        dt { class: "text-muted-foreground", {tr("Nameserver")} } dd { class: "font-mono text-xs break-all", {r.name_servers.join(", ")} }
                        dt { class: "text-muted-foreground", {tr("Mail-Anbieter")} } dd { if r.mail.provider.is_empty() { "–" } else { "{r.mail.provider}" } }
                        dt { class: "text-muted-foreground", "MX" } dd { class: "font-mono text-xs break-all", {if r.mail.mx.is_empty() { "–".to_string() } else { r.mail.mx.join(", ") }} }
                        dt { class: "text-muted-foreground", "SPF" } dd { class: "font-mono text-xs break-all", if r.mail.spf.is_empty() { "–" } else { "{r.mail.spf}" } }
                        dt { class: "text-muted-foreground", "DMARC" } dd { class: "font-mono text-xs break-all", if r.mail.dmarc.is_empty() { "–" } else { "{r.mail.dmarc}" } }
                        dt { class: "text-muted-foreground", "DKIM" } dd { class: "font-mono text-xs", if r.mail.dkim.is_empty() { {tr("nicht gefunden")} } else { {r.mail.dkim.join(", ")} } }
                        dt { class: "text-muted-foreground", {tr("Verratene Dienste")} } dd { {if r.services.is_empty() { "–".to_string() } else { r.services.join(", ") }} }
                    }
                }
            }
            Section { title: tr("Namen und Adressen"), description: tr("Alle bekannten Namen (aus DNS und Zertifikaten) und wohin sie öffentlich zeigen."),
                TableWrapper { Table {
                    TableHeader { tr {
                        TableHead { {tr("Name")} }
                        TableHead { {tr("Adressen")} }
                        TableHead { class: "hidden md:table-cell", {tr("Bekannt aus")} }
                        if r.active { TableHead { class: "hidden lg:table-cell", {tr("Webserver")} } }
                    } }
                    TableBody {
                        for h in r.hosts.iter().cloned() {
                            TableRow { key: "{h.name}",
                                TableCell { class: "font-mono text-[13px] break-all", "{h.name}"
                                    if !h.cname.is_empty() { p { class: "text-xs text-muted-foreground", "→ {h.cname}" } }
                                }
                                TableCell { class: "font-mono text-xs break-all",
                                    if h.dangling { Pill { tone: Tone::Danger, {tr("verwaist – Übernahme möglich")} } }
                                    else if h.addresses.is_empty() { span { class: "text-muted-foreground", {tr("löst nicht auf")} } }
                                    for a in h.addresses.iter() {
                                        {
                                            let info = r.addresses.iter().find(|x| x.ip == *a).cloned().unwrap_or_default();
                                            rsx! {
                                                p { key: "{a}", class: if info.home || info.private { "text-destructive" } else { "" },
                                                    "{a}"
                                                    if info.home { span { class: "ml-1 font-sans", {tr("(zu Hause)")} } }
                                                    else if info.private { span { class: "ml-1 font-sans", {tr("(intern)")} } }
                                                    else if info.cdn { span { class: "ml-1 font-sans text-muted-foreground", "(CDN)" } }
                                                }
                                            }
                                        }
                                    }
                                }
                                TableCell { class: "hidden text-xs text-muted-foreground md:table-cell", {h.sources.join(", ")} }
                                if r.active {
                                    TableCell { class: "hidden text-xs lg:table-cell",
                                        if h.http_status > 0 {
                                            p { "{h.http_status} · " if h.https { "HTTPS" } else { "HTTP" } if h.hsts { " · HSTS" } }
                                            if !h.server.is_empty() { p { class: "text-muted-foreground break-all", "{h.server}" } }
                                            if !h.title.is_empty() { p { class: "text-muted-foreground break-all", "„{h.title}“" } }
                                            if !h.missing_headers.is_empty() { p { class: "text-amber-500 break-all", {trf("fehlt: {0}", &[&h.missing_headers.join(", ")])} } }
                                        } else { span { class: "text-muted-foreground", "–" } }
                                    }
                                }
                            }
                        }
                    }
                } }
            }
            Section { title: tr("Adressen und Hoster"), description: tr("Wem die Netze gehören, in denen deine Namen liegen."),
                TableWrapper { Table {
                    TableHeader { tr {
                        TableHead { {tr("Adresse")} }
                        TableHead { {tr("Anbieter")} }
                        TableHead { class: "hidden md:table-cell", {tr("Netz")} }
                        TableHead { class: "w-16", {tr("Land")} }
                        if r.active { TableHead { {tr("Offene Ports")} } }
                    } }
                    TableBody {
                        for a in r.addresses.iter().cloned() {
                            TableRow { key: "{a.ip}",
                                TableCell { class: "font-mono text-[13px]", "{a.ip}" }
                                TableCell {
                                    if a.home { Pill { tone: Tone::Danger, {tr("dein Anschluss")} } " " }
                                    if a.private { Pill { tone: Tone::Warning, {tr("intern")} } " " }
                                    if a.cdn { Pill { tone: Tone::Success, "CDN" } " " }
                                    "{a.provider}"
                                }
                                TableCell { class: "hidden text-xs text-muted-foreground md:table-cell break-all", "{a.network}" }
                                TableCell { "{a.country}" }
                                if r.active {
                                    TableCell { class: "font-mono text-xs",
                                        if a.cdn || a.private { span { class: "text-muted-foreground", {tr("nicht geprüft")} } }
                                        else if a.open_ports.is_empty() { span { class: "text-emerald-500", {tr("keine")} } }
                                        else {
                                            for p in a.open_ports.iter() {
                                                p { key: "{p}", class: if [80u16, 443].contains(p) { "" } else { "text-destructive" },
                                                    "{p}"
                                                    if !nrzdns_types::port_service(*p).is_empty() { span { class: "font-sans text-muted-foreground", " – {nrzdns_types::port_service(*p)}" } }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } }
            }
            if !r.cert_names.is_empty() {
                Section { title: tr("Zertifikate (Certificate Transparency)"), description: trf("{0} Zertifikate öffentlich protokolliert – jeder Name darin ist für immer sichtbar.", &[&r.cert_count.to_string()]),
                    TableWrapper { Table {
                        TableHeader { tr {
                            TableHead { {tr("Name")} }
                            TableHead { class: "w-24", {tr("Zertifikate")} }
                            TableHead { class: "hidden sm:table-cell", {tr("Zuletzt")} }
                            TableHead { class: "hidden md:table-cell", {tr("Aussteller")} }
                        } }
                        TableBody {
                            for c in r.cert_names.iter().cloned() {
                                TableRow { key: "{c.name}",
                                    TableCell { class: "font-mono text-[13px] break-all", "{c.name}" }
                                    TableCell { "{c.certificates}" }
                                    TableCell { class: "hidden text-muted-foreground sm:table-cell", {if c.last_seen == 0 { "–".to_string() } else { util::date(c.last_seen) }} }
                                    TableCell { class: "hidden text-xs text-muted-foreground md:table-cell", {c.issuers.join(", ")} }
                                }
                            }
                        }
                    } }
                }
            }
        }
    }
}
