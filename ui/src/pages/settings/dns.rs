//! Einstellungen des DNS-Servers, je Bereich mit eigenem Speichern. Beim Speichern wird der
//! aktuelle Stand vom Server geholt und nur der Bereich ersetzt – so überschreibt niemand
//! Änderungen eines anderen Bereichs. Mitglieder sehen alles, ändern aber nichts.

use crate::Route;
use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::components::upstreams::UpstreamEditor;
use crate::i18n::tr;
use crate::labels;
use crate::state;
use dioxus::prelude::*;
use nrzdns_types::{BlockMode, DnsSettings};

/// Felder eines Bereichs von `from` nach `into` übernehmen.
fn merge(section: &str, from: &DnsSettings, into: &mut DnsSettings) {
    match section {
        "general" => {
            into.server_domain = from.server_domain.trim().trim_end_matches('.').to_string();
            into.default_ttl = from.default_ttl;
            into.rate_limit_qps = from.rate_limit_qps;
            into.doh_enabled = from.doh_enabled;
            into.local_ptr_no_forward = from.local_ptr_no_forward;
            into.disable_ipv6_answers = from.disable_ipv6_answers;
        }
        "forwarding" => {
            into.forwarders = from
                .forwarders
                .iter()
                .filter(|u| !u.address.trim().is_empty())
                .cloned()
                .collect();
            into.forwarding_strategy = from.forwarding_strategy;
            into.upstream_timeout_ms = from.upstream_timeout_ms;
        }
        "cache" => {
            into.cache_enabled = from.cache_enabled;
            into.cache_max_entries = from.cache_max_entries;
            into.cache_min_ttl = from.cache_min_ttl;
            into.cache_max_ttl = from.cache_max_ttl;
            into.cache_negative_ttl = from.cache_negative_ttl;
            into.serve_stale = from.serve_stale;
            into.serve_stale_secs = from.serve_stale_secs;
            into.prefetch = from.prefetch;
        }
        "blocking" => {
            into.blocking_enabled = from.blocking_enabled;
            into.block_mode = from.block_mode;
            into.block_ipv4 = from.block_ipv4.trim().to_string();
            into.block_ipv6 = from.block_ipv6.trim().to_string();
            into.block_ttl = from.block_ttl;
            into.blocklist_update_hours = from.blocklist_update_hours;
        }
        "logging" => {
            into.log_queries = from.log_queries;
            into.log_retention_days = from.log_retention_days;
        }
        _ => {}
    }
}

#[component]
pub fn Dns(section: String) -> Element {
    let admin = state::is_admin();
    let mut draft = use_signal(|| None::<DnsSettings>);
    let mut saved = use_signal(|| None::<DnsSettings>);
    let mut error = use_signal(|| None::<String>);
    let mut busy = use_signal(|| false);
    let edit = use_callback(move |f: Box<dyn FnOnce(&mut DnsSettings)>| {
        let mut v = draft.peek().clone();
        if let Some(s) = v.as_mut() {
            f(s);
        }
        draft.set(v);
    });
    use_future(move || async move {
        match api::get::<DnsSettings>("/settings/dns").await {
            Ok(s) => {
                draft.set(Some(s.clone()));
                saved.set(Some(s));
            }
            Err(e) => error.set(Some(e.message)),
        }
    });
    if let Some(e) = error() {
        return rsx! { Callout { text: e, error: true } };
    }
    let (Some(d), Some(s)) = (draft(), saved()) else {
        return rsx! { Loading {} };
    };
    let changed = {
        let mut a = s.clone();
        merge(&section, &d, &mut a);
        a != s
    };
    let sec = section.clone();
    let submit = move |e: FormEvent| {
        e.prevent_default();
        let sec = sec.clone();
        spawn(async move {
            busy.set(true);
            // Frischen Stand holen und nur diesen Bereich ersetzen
            let res = match api::get::<DnsSettings>("/settings/dns").await {
                Ok(mut fresh) => {
                    if let Some(d) = draft.peek().as_ref() {
                        merge(&sec, d, &mut fresh);
                    }
                    api::put::<DnsSettings, _>("/settings/dns", &fresh).await
                }
                Err(e) => Err(e),
            };
            busy.set(false);
            match res {
                Ok(new) => {
                    // Andere Bereiche behalten ungespeicherte Eingaben
                    let mut d = draft.peek().clone().unwrap_or_else(|| new.clone());
                    merge(&sec, &new, &mut d);
                    for other in ["general", "forwarding", "cache", "blocking", "logging"] {
                        if other != sec {
                            let unchanged = saved.peek().as_ref().is_some_and(|old| {
                                let mut a = old.clone();
                                merge(other, &d, &mut a);
                                a == *old
                            });
                            if unchanged {
                                merge(other, &new, &mut d);
                            }
                        }
                    }
                    draft.set(Some(d));
                    saved.set(Some(new));
                    toast(tr("Einstellungen gespeichert – gelten sofort."));
                }
                Err(e) => toast_error(e),
            }
        });
    };
    let reset = move |_| draft.set(saved.peek().clone());

    let (title, description) = match section.as_str() {
        "general" => (
            tr("Allgemein"),
            tr("Name des Servers, Vorgaben und Schutz vor zu vielen Anfragen."),
        ),
        "forwarding" => (
            tr("Weiterleitung"),
            tr(
                "Vorgelagerte DNS-Server für alles, was nicht aus einer eigenen Zone oder dem Cache kommt.",
            ),
        ),
        "cache" => (
            tr("Cache"),
            tr("Antworten zwischenspeichern spart Zeit und Anfragen nach draussen."),
        ),
        "blocking" => (
            tr("Sperren"),
            tr(
                "Was gesperrte Domains als Antwort bekommen und wie oft die Listen neu geladen werden.",
            ),
        ),
        _ => (
            tr("Abfrageprotokoll"),
            tr("Das Abfrageprotokoll ist die Grundlage für Dashboard und Statistik."),
        ),
    };
    rsx! {
        if !admin {
            ReadOnlyHint {}
        }
        Section { title, description,
            form { class: "grid grid-cols-1 gap-6", onsubmit: submit,
                match section.as_str() {
                    "general" => rsx! { General { s: d.clone(), admin, edit } },
                    "forwarding" => rsx! { Forwarding { s: d.clone(), admin, edit } },
                    "cache" => rsx! { CacheSection { s: d.clone(), admin, edit } },
                    "blocking" => rsx! { BlockingSection { s: d.clone(), admin, edit } },
                    _ => rsx! { Logging { s: d.clone(), admin, edit } },
                }
                if admin {
                    div { class: "flex flex-wrap items-center gap-2 border-t pt-5",
                        button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy() || !changed,
                            if busy() {
                                icons::LoaderCircle { class: "size-4 animate-spin" }
                            }
                            {tr("Speichern")}
                        }
                        if changed {
                            button { class: btn(BTN_GHOST), r#type: "button", onclick: reset, {tr("Verwerfen")} }
                            span { class: "text-xs text-muted-foreground", {tr("Ungespeicherte Änderungen")} }
                        }
                    }
                }
            }
        }
    }
}

type Edit = Callback<Box<dyn FnOnce(&mut DnsSettings)>>;

#[component]
fn General(s: DnsSettings, admin: bool, edit: Edit) -> Element {
    let ro = !admin;
    rsx! {
        Field { label: tr("Name des Servers"), hint: tr("Vorgabe für SOA und NS neuer Zonen, z. B. ns.nrzdns.local."),
            input {
                class: "{INPUT} max-w-md font-mono text-[13px]",
                disabled: ro,
                required: true,
                spellcheck: false,
                autocapitalize: "none",
                value: "{s.server_domain}",
                oninput: move |e| {
                    let v = e.value();
                    edit.call(Box::new(move |s: &mut DnsSettings| s.server_domain = v));
                },
            }
        }
        div { class: "grid grid-cols-1 gap-5 sm:grid-cols-2",
            NumField {
                label: tr("TTL neuer Einträge"),
                hint: tr("Gilt für Einträge mit TTL 0."),
                unit: tr("Sekunden"),
                value: s.default_ttl,
                min: 1,
                max: 604_800,
                disabled: ro,
                onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.default_ttl = v)),
            }
            NumField {
                label: tr("Anfragen pro Sekunde und Client"),
                hint: tr("Darüber wird verworfen. 0 = unbegrenzt."),
                value: s.rate_limit_qps,
                min: 0,
                max: 100_000,
                disabled: ro,
                onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.rate_limit_qps = v)),
            }
        }
        div { class: "grid grid-cols-1 gap-4",
            Toggle {
                checked: s.doh_enabled,
                disabled: ro,
                label: tr("DNS über HTTPS (DoH) annehmen"),
                hint: tr("Unter /dns-query auf derselben Adresse wie diese Oberfläche – für Browser und Handys mit privatem DNS."),
                onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.doh_enabled = v)),
            }
            Toggle {
                checked: s.local_ptr_no_forward,
                disabled: ro,
                label: tr("Private Rückwärtsanfragen nicht weiterleiten"),
                hint: tr("PTR für 10/8, 172.16/12, 192.168/16, fc00::/7 usw. selbst mit NXDOMAIN beantworten, wenn keine Zone passt."),
                onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.local_ptr_no_forward = v)),
            }
            Toggle {
                checked: s.disable_ipv6_answers,
                disabled: ro,
                label: tr("Keine IPv6-Adressen ausliefern"),
                hint: tr("AAAA-Anfragen leer beantworten – für Netze ohne IPv6."),
                onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.disable_ipv6_answers = v)),
            }
        }
    }
}

#[component]
fn Forwarding(s: DnsSettings, admin: bool, edit: Edit) -> Element {
    let ro = !admin;
    rsx! {
        div { class: "grid grid-cols-1 gap-2",
            span { class: "text-sm font-medium", {tr("Vorgelagerte Server")} }
            UpstreamEditor {
                value: s.forwarders.clone(),
                disabled: ro,
                onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.forwarders = v)),
            }
            p { class: "text-xs text-muted-foreground", {tr("DoT und DoH verschlüsseln die Anfragen nach draussen; UDP ist am schnellsten.")} }
        }
        div { class: "grid grid-cols-1 gap-2",
            span { class: "text-sm font-medium", {tr("Strategie")} }
            div { class: "grid grid-cols-1 gap-2 sm:grid-cols-3",
                for st in labels::STRATEGIES {
                    label {
                        key: "{labels::strategy_key(st)}",
                        class: if s.forwarding_strategy == st { "flex cursor-pointer flex-col gap-1 rounded-lg border border-ring/60 bg-accent/40 p-3" } else { "flex cursor-pointer flex-col gap-1 rounded-lg border p-3 hover:bg-accent/20" },
                        span { class: "flex items-center gap-2 text-sm font-medium",
                            input {
                                r#type: "radio",
                                name: "strategy",
                                class: "accent-foreground",
                                disabled: ro,
                                checked: s.forwarding_strategy == st,
                                onchange: move |_| edit.call(Box::new(move |s: &mut DnsSettings| s.forwarding_strategy = st)),
                            }
                            {labels::strategy(st)}
                        }
                        span { class: "text-xs text-muted-foreground", {labels::strategy_hint(st)} }
                    }
                }
            }
        }
        NumField {
            label: tr("Zeitlimit je Anfrage"),
            hint: tr("200 bis 15 000 Millisekunden; danach kommt der nächste Server dran."),
            unit: tr("Millisekunden"),
            value: s.upstream_timeout_ms,
            min: 200,
            max: 15_000,
            disabled: ro,
            onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.upstream_timeout_ms = v)),
        }
    }
}

#[component]
fn CacheSection(s: DnsSettings, admin: bool, edit: Edit) -> Element {
    let ro = !admin;
    let off = ro || !s.cache_enabled;
    rsx! {
        Toggle {
            checked: s.cache_enabled,
            disabled: ro,
            label: tr("Cache verwenden"),
            hint: tr("Antworten vorgelagerter Server so lange behalten, wie ihre TTL erlaubt."),
            onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.cache_enabled = v)),
        }
        div { class: "grid grid-cols-1 gap-5 sm:grid-cols-2",
            NumField {
                label: tr("Höchstens Einträge"),
                hint: tr("Ältere fliegen zuerst."),
                value: s.cache_max_entries,
                min: 100,
                max: 10_000_000,
                disabled: off,
                onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.cache_max_entries = v)),
            }
            NumField {
                label: tr("Negative Antworten behalten"),
                hint: tr("NXDOMAIN und leere Antworten."),
                unit: tr("Sekunden"),
                value: s.cache_negative_ttl,
                min: 0,
                max: 86_400,
                disabled: off,
                onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.cache_negative_ttl = v)),
            }
            NumField {
                label: tr("TTL mindestens"),
                unit: tr("Sekunden"),
                value: s.cache_min_ttl,
                min: 0,
                max: 86_400,
                disabled: off,
                onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.cache_min_ttl = v)),
            }
            NumField {
                label: tr("TTL höchstens"),
                unit: tr("Sekunden"),
                value: s.cache_max_ttl,
                min: 1,
                max: 604_800,
                disabled: off,
                onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.cache_max_ttl = v)),
            }
        }
        div { class: "grid grid-cols-1 gap-4",
            Toggle {
                checked: s.prefetch,
                disabled: off,
                label: tr("Häufige Einträge vorab erneuern"),
                hint: tr("Kurz vor Ablauf im Hintergrund neu holen – oft gefragte Namen kommen so immer aus dem Cache."),
                onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.prefetch = v)),
            }
            Toggle {
                checked: s.serve_stale,
                disabled: off,
                label: tr("Abgelaufene Einträge ausliefern, wenn kein Server antwortet"),
                hint: tr("Hält das Netz am Laufen, wenn die Internetverbindung kurz weg ist (RFC 8767)."),
                onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.serve_stale = v)),
            }
        }
        if s.serve_stale {
            NumField {
                label: tr("Abgelaufene Einträge höchstens so lange ausliefern"),
                unit: tr("Sekunden"),
                value: s.serve_stale_secs,
                min: 0,
                max: 604_800,
                disabled: off,
                onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.serve_stale_secs = v)),
            }
        }
        p { class: "text-xs text-muted-foreground",
            {tr("Den Inhalt des Caches siehst und leerst du unter ")}
            Link { to: Route::Cache {}, class: "underline underline-offset-4 hover:text-foreground", {tr("Cache")} }
            "."
        }
    }
}

#[component]
fn BlockingSection(s: DnsSettings, admin: bool, edit: Edit) -> Element {
    let ro = !admin;
    let off = ro || !s.blocking_enabled;
    rsx! {
        Toggle {
            checked: s.blocking_enabled,
            disabled: ro,
            label: tr("Sperren einschalten"),
            hint: tr("Domains aus Sperrlisten und eigenen Sperren bekommen keine echte Antwort."),
            onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.blocking_enabled = v)),
        }
        div { class: "grid grid-cols-1 gap-2",
            span { class: "text-sm font-medium", {tr("Antwort für gesperrte Domains")} }
            div { class: "grid grid-cols-1 gap-2 sm:grid-cols-2",
                for m in labels::BLOCK_MODES {
                    label {
                        key: "{labels::block_mode_key(m)}",
                        class: if s.block_mode == m { "flex cursor-pointer items-center gap-2 rounded-lg border border-ring/60 bg-accent/40 p-3 text-sm" } else { "flex cursor-pointer items-center gap-2 rounded-lg border p-3 text-sm hover:bg-accent/20" },
                        input {
                            r#type: "radio",
                            name: "block-mode",
                            class: "accent-foreground",
                            disabled: off,
                            checked: s.block_mode == m,
                            onchange: move |_| edit.call(Box::new(move |s: &mut DnsSettings| s.block_mode = m)),
                        }
                        {labels::block_mode(m)}
                    }
                }
            }
        }
        if s.block_mode == BlockMode::CustomAddress {
            div { class: "grid grid-cols-1 gap-5 sm:grid-cols-2",
                Field { label: tr("IPv4-Adresse"), hint: tr("z. B. die Adresse einer Sperrseite"),
                    input {
                        class: "{INPUT} font-mono text-[13px]",
                        disabled: off,
                        spellcheck: false,
                        placeholder: "0.0.0.0",
                        value: "{s.block_ipv4}",
                        oninput: move |e| {
                            let v = e.value();
                            edit.call(Box::new(move |s: &mut DnsSettings| s.block_ipv4 = v));
                        },
                    }
                }
                Field { label: tr("IPv6-Adresse"), hint: tr("Leer lassen oder :: für keine"),
                    input {
                        class: "{INPUT} font-mono text-[13px]",
                        disabled: off,
                        spellcheck: false,
                        placeholder: "::",
                        value: "{s.block_ipv6}",
                        oninput: move |e| {
                            let v = e.value();
                            edit.call(Box::new(move |s: &mut DnsSettings| s.block_ipv6 = v));
                        },
                    }
                }
            }
        }
        div { class: "grid grid-cols-1 gap-5 sm:grid-cols-2",
            NumField {
                label: tr("TTL gesperrter Antworten"),
                unit: tr("Sekunden"),
                value: s.block_ttl,
                min: 0,
                max: 86_400,
                disabled: off,
                onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.block_ttl = v)),
            }
            NumField {
                label: tr("Sperrlisten neu laden alle"),
                hint: tr("1 bis 168 Stunden (eine Woche)."),
                unit: tr("Stunden"),
                value: s.blocklist_update_hours,
                min: 1,
                max: 168,
                disabled: off,
                onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.blocklist_update_hours = v)),
            }
        }
        p { class: "text-xs text-muted-foreground",
            {tr("Sperrlisten und eigene Sperren pflegst du unter ")}
            Link { to: Route::Blocking {}, class: "underline underline-offset-4 hover:text-foreground", {tr("Sperren")} }
            "."
        }
    }
}

#[component]
fn Logging(s: DnsSettings, admin: bool, edit: Edit) -> Element {
    let ro = !admin;
    rsx! {
        Toggle {
            checked: s.log_queries,
            disabled: ro,
            label: tr("Jede Anfrage protokollieren"),
            hint: tr("Ohne Protokoll bleiben Dashboard, Toplisten und Abfragen leer."),
            onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.log_queries = v)),
        }
        NumField {
            label: tr("Einträge löschen nach"),
            hint: tr("1 bis 365 Tage."),
            unit: tr("Tagen"),
            value: s.log_retention_days,
            min: 1,
            max: 365,
            disabled: ro,
            onchange: move |v| edit.call(Box::new(move |s: &mut DnsSettings| s.log_retention_days = v)),
        }
    }
}
