//! DNS-Client: einen Namen bei diesem Server (mit Zonen, Sperren und Cache) oder bei einem
//! anderen Server auflösen und die ganze Antwort zeigen. Enter schickt ab.

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::labels;
use crate::ui::card::{Card, CardContent, CardHeader, CardTitle};
use crate::ui::table::*;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{RecordView, ResolveInput, ResolveResult, Upstream, UpstreamProtocol};

#[component]
pub fn Resolve(name: Option<String>, qtype: Option<String>) -> Element {
    let mut qname = use_signal(|| name.clone().unwrap_or_default());
    let mut rtype = use_signal(|| {
        qtype
            .clone()
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| "A".into())
    });
    // "" = dieser Server, "p:<i>:<j>" = Vorlage, "custom" = eigene Adresse
    let mut server = use_signal(String::new);
    let mut custom = use_signal(String::new);
    let mut protocol = use_signal(UpstreamProtocol::default);
    let mut busy = use_signal(|| false);
    let mut result = use_signal(|| None::<ResolveResult>);
    let mut error = use_signal(|| None::<String>);
    let presets = use_resource(|| async { crate::state::presets().await.upstreams });

    let pick = move |key: &str| -> Option<Upstream> {
        let mut parts = key.strip_prefix("p:")?.split(':');
        let i: usize = parts.next()?.parse().ok()?;
        let j: usize = parts.next()?.parse().ok()?;
        presets.peek().as_ref()?.get(i)?.upstreams.get(j).cloned()
    };
    // Liest nur mit peek: läuft auch aus einem Effekt, der sonst bei jeder Eingabe neu starten würde
    let run = move || {
        let name = qname.peek().trim().trim_end_matches('.').to_string();
        if name.is_empty() {
            return;
        }
        let key = server.peek().clone();
        let (srv, proto) = if key.is_empty() {
            (String::new(), UpstreamProtocol::Udp)
        } else if key == "custom" {
            (custom.peek().trim().to_string(), *protocol.peek())
        } else {
            match pick(&key) {
                Some(u) => (u.address, u.protocol),
                None => (String::new(), UpstreamProtocol::Udp),
            }
        };
        if key == "custom" && srv.is_empty() {
            toast_error(tr("Bitte die Adresse des Servers angeben."));
            return;
        }
        let body = ResolveInput {
            name,
            qtype: rtype.peek().clone(),
            server: srv,
            protocol: proto,
        };
        spawn(async move {
            busy.set(true);
            error.set(None);
            let res = api::post::<ResolveResult, _>("/resolve", &body).await;
            busy.set(false);
            match res {
                Ok(r) => result.set(Some(r)),
                Err(e) => {
                    result.set(None);
                    error.set(Some(e.message));
                }
            }
        });
    };
    // Mit Name in der Adresse (z. B. aus dem Abfrageprotokoll) gleich auflösen
    let (n0, t0) = (name.clone(), qtype.clone());
    use_effect(use_reactive!(|n0, t0| {
        if let Some(n) = n0.filter(|n| !n.trim().is_empty()) {
            qname.set(n);
            if let Some(t) = t0.filter(|t| !t.is_empty()) {
                rtype.set(t);
            }
            run();
        }
    }));

    let current = rtype();
    rsx! {
        PageHeader { title: tr("DNS-Client"), description: tr("Namen auflösen – bei diesem Server oder einem anderen, mit der ganzen Antwort.") }
        div { class: "grid grid-cols-1 gap-6",
            Card { class: "py-5",
                CardContent { class: "px-5",
                    form {
                        class: "grid grid-cols-1 gap-3 lg:grid-cols-[minmax(0,1fr)_8rem_minmax(0,16rem)_auto] lg:items-end",
                        onsubmit: move |e| {
                            e.prevent_default();
                            run();
                        },
                        Field { label: tr("Name"),
                            input {
                                class: "{INPUT} font-mono text-[13px]",
                                id: "page-search",
                                required: true,
                                autofocus: true,
                                spellcheck: false,
                                autocapitalize: "none",
                                placeholder: tr("example.com oder eine IP-Adresse für PTR"),
                                value: "{qname}",
                                oninput: move |e| qname.set(e.value()),
                            }
                        }
                        Field { label: tr("Typ"),
                            select { class: SELECT, onchange: move |e| rtype.set(e.value()),
                                for t in labels::QUERY_TYPES {
                                    option { value: t, selected: current == t, "{t}" }
                                }
                                if !labels::QUERY_TYPES.contains(&current.as_str()) {
                                    option { value: "{current}", selected: true, "{current}" }
                                }
                            }
                        }
                        Field { label: tr("Server"),
                            select { class: SELECT, onchange: move |e| server.set(e.value()),
                                option { value: "", selected: server().is_empty(), {tr("Dieser Server")} }
                                if let Some(list) = presets.read().as_ref() {
                                    for (i , p) in list.iter().enumerate() {
                                        optgroup { key: "{p.id}", label: "{p.name}",
                                            for (j , u) in p.upstreams.iter().enumerate() {
                                                option { key: "{j}", value: "p:{i}:{j}", selected: server() == format!("p:{i}:{j}"), "{u.label()}" }
                                            }
                                        }
                                    }
                                }
                                option { value: "custom", selected: server() == "custom", {tr("Eigener Server …")} }
                            }
                        }
                        button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy() || qname().trim().is_empty(),
                            if busy() {
                                icons::LoaderCircle { class: "size-4 animate-spin" }
                            } else {
                                icons::Search {}
                            }
                            {tr("Auflösen")}
                        }
                        if server() == "custom" {
                            div { class: "grid grid-cols-1 gap-3 sm:grid-cols-[10rem_minmax(0,1fr)] lg:col-span-3",
                                Field { label: tr("Protokoll"),
                                    select { class: SELECT, onchange: move |e| protocol.set(labels::parse_upstream_protocol(&e.value())),
                                        for p in labels::UPSTREAM_PROTOCOLS {
                                            option { value: labels::upstream_protocol_key(p), selected: protocol() == p, {labels::upstream_protocol(p)} }
                                        }
                                    }
                                }
                                Field { label: tr("Adresse"),
                                    input {
                                        class: "{INPUT} font-mono text-[13px]",
                                        spellcheck: false,
                                        autocapitalize: "none",
                                        placeholder: labels::upstream_placeholder(protocol()),
                                        value: "{custom}",
                                        oninput: move |e| custom.set(e.value()),
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if let Some(e) = error() {
                Callout { text: e, error: true }
            }
            if let Some(r) = result() {
                ResultView { result: r }
            } else if error().is_none() && !busy() {
                div { class: "rounded-xl border border-dashed",
                    EmptyState { title: tr("Noch nichts aufgelöst"), description: tr("Name eingeben und Enter drücken."), icon: rsx! { icons::Terminal {} } }
                }
            }
        }
    }
}

#[component]
fn ResultView(result: ResolveResult) -> Element {
    let r = result;
    let empty = r.answers.is_empty() && r.authority.is_empty() && r.additional.is_empty();
    rsx! {
        Card { class: "gap-4 py-5",
            CardHeader { class: "px-5",
                div { class: "flex w-full flex-wrap items-center gap-2",
                    CardTitle { {tr("Antwort")} }
                    Rcode { code: r.rcode.clone() }
                    if let Some(k) = r.kind {
                        KindBadge { kind: k }
                    }
                    span { class: "ml-auto text-xs text-muted-foreground", {trf("{0} ms · {1}", &[&r.duration_ms, &r.server])} }
                }
            }
            CardContent { class: "grid grid-cols-1 gap-5 px-5",
                if !r.flags.is_empty() {
                    div { class: "flex flex-wrap items-center gap-1.5",
                        span { class: "mr-1 text-xs text-muted-foreground", {tr("Flags")} }
                        for f in r.flags.iter() {
                            Pill { key: "{f}", class: "font-mono", "{f}" }
                        }
                    }
                }
                if empty {
                    p { class: "text-sm text-muted-foreground", {tr("Die Antwort enthält keine Einträge.")} }
                }
                RecordTable { title: tr("Antworten"), records: r.answers.clone() }
                RecordTable { title: tr("Zuständig (Authority)"), records: r.authority.clone() }
                RecordTable { title: tr("Zusätzlich (Additional)"), records: r.additional.clone() }
            }
        }
    }
}

#[component]
fn RecordTable(#[props(into)] title: String, records: Vec<RecordView>) -> Element {
    if records.is_empty() {
        return rsx! {};
    }
    rsx! {
        div { class: "grid grid-cols-1 gap-2",
            p { class: "text-xs font-medium uppercase tracking-wider text-muted-foreground", "{title} ({records.len()})" }
            TableWrapper { class: "bg-transparent",
                Table {
                    TableHeader {
                        tr {
                            TableHead { {tr("Name")} }
                            TableHead { {tr("Typ")} }
                            TableHead { class: "text-right", {tr("TTL")} }
                            TableHead { {tr("Daten")} }
                        }
                    }
                    TableBody {
                        for (i , rec) in records.iter().enumerate() {
                            TableRow { key: "{i}", class: "text-[13px]",
                                TableCell { class: "min-w-32 font-mono text-xs break-all", "{rec.name}" }
                                TableCell { class: "font-mono text-xs text-muted-foreground", "{rec.qtype}" }
                                TableCell { class: "text-right whitespace-nowrap tabular-nums text-muted-foreground", title: "{rec.ttl} s", {util::ttl(rec.ttl)} }
                                TableCell { class: "min-w-40 font-mono text-xs break-all", "{rec.data}" }
                            }
                        }
                    }
                }
            }
        }
    }
}
