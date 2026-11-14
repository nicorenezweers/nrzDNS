//! Spy: was andere im Internet über deine Domain wissen können – mit Bewertung und
//! Empfehlungen.

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::json::Dot;
use crate::state;
use crate::ui::table::*;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{Severity, SpyReport, SpyScanInput, SpyStatus};

#[component]
pub fn Spy() -> Element {
    let admin = state::is_admin();
    let mut tick = use_signal(|| 0u64);
    let status = use_resource(move || async move {
        let _ = tick();
        api::get::<SpyStatus>("/spy").await
    });
    let mut domain = use_signal(String::new);
    let mut active = use_signal(|| false);
    let mut selected = use_signal(String::new);
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
    // Vorbelegen: erste eigene Domain (oder der letzte Bericht)
    use_effect(move || {
        let first = match &*status.read() {
            Some(Ok(s)) => s
                .own_domains
                .first()
                .or(s.reports.first().map(|r| &r.domain))
                .cloned(),
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
    let d_now = domain().trim().to_lowercase();
    let is_own = own
        .iter()
        .any(|o| d_now == *o || d_now.ends_with(&format!(".{o}")));

    let start = move |e: FormEvent| {
        e.prevent_default();
        let input = SpyScanInput {
            domain: domain().trim().to_string(),
            active: active() && is_own,
        };
        spawn(async move {
            busy.set(true);
            let res = api::post::<SpyStatus, _>("/spy/scan", &input).await;
            busy.set(false);
            match res {
                Ok(_) => {
                    selected.set(input.domain.to_lowercase());
                    tick += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };

    rsx! {
        PageHeader { title: tr("Spy"), description: tr("Was andere im Internet über dich wissen können: Namen aus Zertifikaten, E-Mails, DNS, Mail-Anbieter, Hoster, dein Anschluss zu Hause – mit Bewertung und Empfehlungen.") }
        div { class: "grid grid-cols-1 gap-6",
            Section { title: tr("Domain prüfen"), description: tr("Nur öffentliche Quellen, genau wie ein Angreifer: Certificate-Transparency-Logs (crt.sh), DNS von aussen, Registrierungsdaten (RDAP). Aktive Prüfungen (Webserver, offene Ports) gibt es nur für eigene Domains."),
                form { class: "grid grid-cols-1 gap-3", onsubmit: start,
                    div { class: "grid grid-cols-1 gap-2 sm:grid-cols-[minmax(0,1fr)_auto]",
                        input { class: "{INPUT} font-mono text-[13px]", list: "spy-domains", required: true, spellcheck: false, autocapitalize: "none",
                            disabled: !admin, placeholder: "zweers.ch", value: "{domain}", oninput: move |e| domain.set(e.value()) }
                        datalist { id: "spy-domains", for d in own.iter() { option { key: "{d}", value: "{d}" } } }
                        if admin {
                            button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: running || busy() || domain().trim().is_empty(),
                                if running { icons::LoaderCircle { class: "size-4 animate-spin" } } else { icons::ScanEye {} }
                                {tr("Scan starten")}
                            }
                        }
                    }
                    if admin {
                        Toggle { checked: active() && is_own, disabled: !is_own, onchange: move |v| active.set(v),
                            label: tr("Auch aktiv prüfen (Webserver-Kopfzeilen, offene Ports)"),
                            hint: if is_own { tr("Fragt deine öffentlichen Server direkt an. Ports werden von innen geprüft – dein Router kann von aussen anders aussehen.") } else { tr("Nur für eigene Domains (aus Cloudflare oder den HTTPS-Einstellungen).") },
                        }
                    } else {
                        ReadOnlyHint {}
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
                        }
                    }
                }
            }
            match &*status.read() {
                None => rsx! { Loading {} },
                Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
                Some(Ok(s)) if s.reports.is_empty() => rsx! {},
                Some(Ok(s)) => {
                    let current = s.reports.iter().find(|r| r.domain == selected()).or(s.reports.first()).cloned().unwrap_or_default();
                    rsx! {
                        if s.reports.len() > 1 {
                            div { class: "flex flex-wrap gap-2",
                                for r in s.reports.iter().cloned() {
                                    button { key: "{r.domain}", class: if r.domain == current.domain { btn_sm(BTN_PRIMARY) } else { btn_sm(BTN_OUTLINE) },
                                        onclick: move |_| selected.set(r.domain.clone()),
                                        "{r.domain}"
                                        span { class: "ml-1 opacity-70", "{r.score}" }
                                    }
                                }
                            }
                        }
                        Report { report: current, admin, tick }
                    }
                }
            }
        }
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
                                    if h.addresses.is_empty() { span { class: "text-muted-foreground", {tr("löst nicht auf")} } }
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
                                        else { {a.open_ports.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")} }
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
