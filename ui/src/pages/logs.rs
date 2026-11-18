//! Abfrageprotokoll: Filter (Client, Name, Typ, Antwortart, Antwortcode, Zeitraum) stehen in der
//! Adresse, Tabelle mit Seiten, Details mit Aktionen (sperren, erlauben, filtern, auflösen),
//! CSV-Export mit denselben Filtern und – für Administratoren – Protokoll leeren.

use crate::Route;
use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::labels;
use crate::state;
use crate::ui::table::*;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{DomainEntry, DomainInput, QueryLogEntry, QueryLogPage, ResponseKind};

/// Filter, wie sie in der Adresse stehen.
#[derive(Clone, PartialEq, Default)]
struct Filters {
    client: String,
    qname: String,
    qtype: String,
    kind: String,
    rcode: String,
    period: String,
}

impl Filters {
    fn route(&self, page: u32) -> Route {
        let opt = |s: &str| (!s.trim().is_empty()).then(|| s.trim().to_string());
        Route::Logs {
            client: opt(&self.client),
            qname: opt(&self.qname),
            qtype: opt(&self.qtype),
            kind: opt(&self.kind),
            rcode: opt(&self.rcode),
            period: opt(&self.period),
            page: (page > 1).then_some(page),
        }
    }

    /// Suchteil für `GET /logs` und `/logs/export` (ohne Seite).
    fn query(&self) -> String {
        let mut q = Vec::new();
        for (k, v) in [
            ("client", &self.client),
            ("qname", &self.qname),
            ("qtype", &self.qtype),
            ("kind", &self.kind),
            ("rcode", &self.rcode),
        ] {
            if !v.trim().is_empty() {
                q.push(format!("{k}={}", api::enc(v.trim())));
            }
        }
        if let Some((_, secs, _)) = labels::periods()
            .into_iter()
            .find(|(k, _, _)| *k == self.period)
        {
            q.push(format!("from={}", util::now() - secs));
        }
        q.join("&")
    }

    fn active(&self) -> bool {
        *self != Filters::default()
    }
}

#[component]
pub fn Logs(
    client: Option<String>,
    qname: Option<String>,
    qtype: Option<String>,
    kind: Option<String>,
    rcode: Option<String>,
    period: Option<String>,
    page: Option<u32>,
) -> Element {
    let admin = state::is_admin();
    let nav = use_navigator();
    let filters = Filters {
        client: client.unwrap_or_default(),
        qname: qname.unwrap_or_default(),
        qtype: qtype.unwrap_or_default(),
        kind: kind.unwrap_or_default(),
        rcode: rcode.unwrap_or_default(),
        period: period.unwrap_or_default(),
    };
    let page = page.unwrap_or(1).max(1);
    let per_page = state::prefs().logs_per_page.clamp(10, 500);

    // Textfelder: getippt wird lokal, übernommen mit Enter
    let mut client_text = use_signal(|| filters.client.clone());
    let mut qname_text = use_signal(|| filters.qname.clone());
    let (fc, fq) = (filters.client.clone(), filters.qname.clone());
    use_effect(use_reactive!(|fc, fq| {
        client_text.set(fc);
        qname_text.set(fq);
    }));

    let mut tick = use_signal(|| 0u64);
    let mut data = use_signal(|| None::<QueryLogPage>);
    let mut error = use_signal(|| None::<String>);
    let f = filters.clone();
    let res = use_resource(use_reactive!(|f, page, per_page| async move {
        let _ = tick();
        let mut url = format!("/logs?page={page}&perPage={per_page}");
        let q = f.query();
        if !q.is_empty() {
            url.push('&');
            url.push_str(&q);
        }
        match api::get::<QueryLogPage>(&url).await {
            Ok(p) => {
                data.set(Some(p));
                error.set(None);
            }
            Err(e) => error.set(Some(e.message)),
        }
    }));
    let loading = !res.finished();
    let mut detail = use_signal(|| None::<QueryLogEntry>);
    let mut detail_open = use_signal(|| false);

    let go = move |f: Filters| {
        nav.replace(f.route(1));
    };
    let base = filters.clone();
    let export = {
        let q = filters.query();
        api::href(&if q.is_empty() {
            "/logs/export".to_string()
        } else {
            format!("/logs/export?{q}")
        })
    };
    let clear = move |_| {
        spawn(async move {
            let ask = Ask::new(tr("Ganzes Abfrageprotokoll leeren?"), tr("Alle Einträge werden gelöscht – auch die Grundlage für Dashboard und Statistik. Das lässt sich nicht rückgängig machen."))
                .confirm(tr("Protokoll leeren"))
                .destructive();
            if confirm(ask).await {
                match api::delete("/logs").await {
                    Ok(()) => {
                        toast(tr("Abfrageprotokoll geleert."));
                        tick += 1;
                    }
                    Err(e) => toast_error(e),
                }
            }
        });
    };

    rsx! {
        PageHeader {
            title: tr("Abfragen"),
            description: tr("Jede Anfrage an den Server – neueste zuerst."),
            actions: rsx! {
                button { class: icon_btn("size-9"), title: tr("Neu laden"), disabled: loading, onclick: move |_| tick += 1,
                    icons::RefreshCw { class: if loading { "size-4 animate-spin" } else { "size-4" } }
                }
                a { class: btn(BTN_OUTLINE), href: "{export}", download: "nrzdns-abfragen.csv", title: tr("Als CSV herunterladen (gleiche Filter)"),
                    icons::Download {}
                    "CSV"
                }
                if admin {
                    button { class: "{btn(BTN_OUTLINE)} hover:text-destructive", onclick: clear,
                        icons::Eraser {}
                        {tr("Leeren")}
                    }
                }
            },
        }
        div { class: "grid grid-cols-1 gap-4",
            // Filter in einer Zeile über der Tabelle
            form {
                class: "grid grid-cols-2 gap-2 lg:grid-cols-[minmax(0,10rem)_minmax(0,1fr)_repeat(3,minmax(0,9rem))_minmax(0,11rem)_auto]",
                onsubmit: {
                    let base = base.clone();
                    move |e: FormEvent| {
                        e.prevent_default();
                        go(Filters { client: client_text(), qname: qname_text(), ..base.clone() });
                    }
                },
                input {
                    class: "{INPUT} col-span-2 font-mono text-[13px] sm:col-span-1",
                    "aria-label": tr("Client"),
                    placeholder: tr("Client-IP"),
                    spellcheck: false,
                    value: "{client_text}",
                    oninput: move |e| client_text.set(e.value()),
                }
                input {
                    class: "{INPUT} col-span-2 font-mono text-[13px] sm:col-span-1",
                    id: "page-search",
                    r#type: "search",
                    "aria-label": tr("Name"),
                    placeholder: tr("Name enthält …"),
                    spellcheck: false,
                    autocapitalize: "none",
                    value: "{qname_text}",
                    oninput: move |e| qname_text.set(e.value()),
                }
                select {
                    class: SELECT,
                    "aria-label": tr("Typ"),
                    onchange: {
                        let base = base.clone();
                        move |e: FormEvent| go(Filters { qtype: e.value(), ..base.clone() })
                    },
                    option { value: "", selected: filters.qtype.is_empty(), {tr("Alle Typen")} }
                    for t in labels::LOG_TYPES {
                        option { value: t, selected: filters.qtype == t, "{t}" }
                    }
                    if !filters.qtype.is_empty() && !labels::LOG_TYPES.contains(&filters.qtype.as_str()) {
                        option { value: "{filters.qtype}", selected: true, "{filters.qtype}" }
                    }
                }
                select {
                    class: SELECT,
                    "aria-label": tr("Antwortart"),
                    onchange: {
                        let base = base.clone();
                        move |e: FormEvent| go(Filters { kind: e.value(), ..base.clone() })
                    },
                    option { value: "", selected: filters.kind.is_empty(), {tr("Alle Antworten")} }
                    for k in ResponseKind::ALL {
                        option { value: k.as_str(), selected: filters.kind == k.as_str(), {labels::kind(k)} }
                    }
                }
                select {
                    class: SELECT,
                    "aria-label": tr("Antwortcode"),
                    onchange: {
                        let base = base.clone();
                        move |e: FormEvent| go(Filters { rcode: e.value(), ..base.clone() })
                    },
                    option { value: "", selected: filters.rcode.is_empty(), {tr("Alle Codes")} }
                    for c in labels::RCODES {
                        option { value: c, selected: filters.rcode == c, "{c}" }
                    }
                }
                select {
                    class: SELECT,
                    "aria-label": tr("Zeitraum"),
                    onchange: {
                        let base = base.clone();
                        move |e: FormEvent| go(Filters { period: e.value(), ..base.clone() })
                    },
                    option { value: "", selected: filters.period.is_empty(), {tr("Gesamter Zeitraum")} }
                    for (k , _ , label) in labels::periods() {
                        option { value: k, selected: filters.period == k, "{label}" }
                    }
                }
                div { class: "col-span-2 flex gap-2 lg:col-span-1",
                    button { class: "{btn(BTN_OUTLINE)} flex-1", r#type: "submit", title: tr("Filter anwenden (Enter)"),
                        icons::Funnel {}
                        span { class: "lg:sr-only", {tr("Filtern")} }
                    }
                    if filters.active() {
                        button {
                            class: btn(BTN_GHOST),
                            r#type: "button",
                            title: tr("Filter zurücksetzen"),
                            onclick: move |_| {
                                nav.replace(Route::logs());
                            },
                            icons::X {}
                        }
                    }
                }
            }
            if let Some(e) = error() {
                Callout { text: e, error: true }
            }
            match data() {
                None if error().is_none() => rsx! { Loading {} },
                None => rsx! {},
                Some(p) => rsx! {
                    div { class: if loading { "grid grid-cols-1 gap-3 opacity-70 transition-opacity" } else { "grid grid-cols-1 gap-3 transition-opacity" },
                        TableWrapper {
                            Table {
                                TableHeader {
                                    tr {
                                        TableHead { {tr("Zeit")} }
                                        TableHead { {tr("Client")} }
                                        TableHead { class: "hidden xl:table-cell", {tr("Protokoll")} }
                                        TableHead { {tr("Name")} }
                                        TableHead { {tr("Typ")} }
                                        TableHead { {tr("Antwort")} }
                                        TableHead { class: "hidden md:table-cell", {tr("Code")} }
                                        TableHead { class: "hidden lg:table-cell", {tr("Daten")} }
                                        TableHead { class: "hidden sm:table-cell text-right", "ms" }
                                        TableHead { class: "hidden 2xl:table-cell", {tr("Upstream")} }
                                        TableHead { class: "w-10" }
                                    }
                                }
                                TableBody {
                                    if p.entries.is_empty() {
                                        tr {
                                            td { class: "px-3 py-10 text-center text-muted-foreground", colspan: "11",
                                                if filters.active() { {tr("Keine Anfragen passen zu diesen Filtern.")} } else { {tr("Noch keine Anfragen protokolliert.")} }
                                            }
                                        }
                                    }
                                    for e in p.entries.iter().cloned() {
                                        LogRow {
                                            key: "{e.id}-{e.at_ms}",
                                            entry: e,
                                            on_open: move |e: QueryLogEntry| {
                                                detail.set(Some(e));
                                                detail_open.set(true);
                                            },
                                        }
                                    }
                                }
                            }
                        }
                        Pagination {
                            page: p.page.max(1),
                            per_page: p.per_page.max(1),
                            total: p.total,
                            onchange: {
                                let base = base.clone();
                                move |n: u32| {
                                    nav.replace(base.route(n));
                                }
                            },
                        }
                    }
                },
            }
        }
        LogDetail {
            open: detail_open,
            entry: detail(),
            on_filter: move |f: Filters| {
                detail_open.set(false);
                go(f);
            },
        }
    }
}

#[component]
fn LogRow(entry: QueryLogEntry, on_open: EventHandler<QueryLogEntry>) -> Element {
    let e = entry;
    let opened = e.clone();
    rsx! {
        TableRow { class: "text-[13px]", onclick: move |_| on_open.call(opened.clone()),
            TableCell { class: "whitespace-nowrap tabular-nums text-muted-foreground", title: util::datetime(e.at_ms / 1000), {util::log_time(e.at_ms)} }
            TableCell { class: "whitespace-nowrap font-mono text-xs", "{e.client}" }
            TableCell { class: "hidden text-xs text-muted-foreground xl:table-cell", {labels::protocol(e.protocol)} }
            TableCell { class: "max-w-[18rem] truncate font-mono text-xs", title: "{e.qname}", "{e.qname}" }
            TableCell { class: "font-mono text-xs text-muted-foreground", "{e.qtype}" }
            TableCell { KindBadge { kind: e.kind } }
            TableCell { class: "hidden md:table-cell", Rcode { code: e.rcode.clone() } }
            TableCell { class: "hidden max-w-[16rem] truncate font-mono text-xs text-muted-foreground lg:table-cell", title: "{e.answer}", "{e.answer}" }
            TableCell { class: "hidden text-right tabular-nums text-muted-foreground sm:table-cell", "{e.duration_ms}" }
            TableCell { class: "hidden max-w-[12rem] truncate font-mono text-xs text-muted-foreground 2xl:table-cell", title: "{e.upstream}", "{e.upstream}" }
            TableCell { class: "px-2",
                // Klick geht an die Zeile; der Knopf macht sie mit der Tastatur erreichbar
                button { class: icon_btn("size-7"), r#type: "button", title: tr("Details und Aktionen"),
                    icons::Ellipsis { class: "size-4" }
                }
            }
        }
    }
}

/// Details einer Anfrage mit Aktionen.
#[component]
fn LogDetail(
    open: Signal<bool>,
    entry: Option<QueryLogEntry>,
    on_filter: EventHandler<Filters>,
) -> Element {
    let nav = use_navigator();
    let admin = state::is_admin();
    let Some(e) = entry else { return rsx! {} };
    let add = move |base: &'static str, domain: String| {
        spawn(async move {
            match api::post::<DomainEntry, _>(
                base,
                &DomainInput {
                    domain: domain.clone(),
                    comment: String::new(),
                },
            )
            .await
            {
                Ok(d) => {
                    if base == "/blocked" {
                        toast(trf("„{0}“ wird jetzt gesperrt.", &[&d.domain]));
                    } else {
                        toast(trf("„{0}“ ist jetzt erlaubt.", &[&d.domain]));
                    }
                    open.set(false);
                }
                Err(err) => toast_error(err),
            }
        });
    };
    let rows: Vec<(String, String)> = vec![
        (tr("Zeit"), util::datetime(e.at_ms / 1000)),
        (tr("Client"), e.client.clone()),
        (tr("Protokoll"), labels::protocol(e.protocol).to_string()),
        (tr("Name"), e.qname.clone()),
        (tr("Typ"), e.qtype.clone()),
        (tr("Antwortcode"), e.rcode.clone()),
        (
            tr("Daten"),
            if e.answer.is_empty() {
                "–".into()
            } else {
                e.answer.clone()
            },
        ),
        (tr("Dauer"), format!("{} ms", e.duration_ms)),
        (
            tr("Upstream"),
            if e.upstream.is_empty() {
                "–".into()
            } else {
                e.upstream.clone()
            },
        ),
    ];
    let (client, qname) = (e.client.clone(), e.qname.clone());
    let (q2, t2) = (e.qname.clone(), e.qtype.clone());
    let (q3, q4) = (e.qname.clone(), e.qname.clone());
    rsx! {
        Modal { open, title: e.qname.clone(), description: trf("{0} von {1}", &[&e.qtype, &e.client]), class: "max-w-xl",
            div { class: "grid grid-cols-1 gap-5",
                div { class: "flex items-center gap-2",
                    KindBadge { kind: e.kind }
                    Rcode { code: e.rcode.clone() }
                }
                dl { class: "grid grid-cols-[7rem_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm",
                    for (k , v) in rows {
                        dt { key: "{k}-k", class: "text-muted-foreground", "{k}" }
                        dd { class: "font-mono text-[13px] break-all", "{v}" }
                    }
                }
                div { class: "grid grid-cols-1 gap-2 border-t pt-4",
                    p { class: "text-xs font-medium uppercase tracking-wider text-muted-foreground", {tr("Aktionen")} }
                    div { class: "flex flex-wrap gap-2",
                        button { class: btn_sm(BTN_OUTLINE), onclick: move |_| on_filter.call(Filters { client: client.clone(), ..Default::default() }),
                            icons::Funnel {}
                            {tr("Nach diesem Client filtern")}
                        }
                        button { class: btn_sm(BTN_OUTLINE), onclick: move |_| on_filter.call(Filters { qname: qname.clone(), ..Default::default() }),
                            icons::Funnel {}
                            {tr("Nach diesem Namen filtern")}
                        }
                        button {
                            class: btn_sm(BTN_OUTLINE),
                            onclick: move |_| {
                                open.set(false);
                                nav.push(Route::Resolve { name: Some(q2.clone()), qtype: Some(t2.clone()) });
                            },
                            icons::Terminal {}
                            {tr("Im DNS-Client auflösen")}
                        }
                    }
                    if admin {
                        div { class: "flex flex-wrap gap-2",
                            if e.kind == ResponseKind::Blocked {
                                button { class: btn_sm(BTN_PRIMARY), onclick: move |_| add("/allowed", q3.clone()),
                                    icons::ShieldCheck {}
                                    {tr("Domain erlauben")}
                                }
                            } else {
                                button { class: "{btn_sm(BTN_OUTLINE)} hover:text-destructive", onclick: move |_| add("/blocked", q3.clone()),
                                    icons::ShieldBan {}
                                    {tr("Domain sperren")}
                                }
                                button { class: btn_sm(BTN_GHOST), onclick: move |_| add("/allowed", q4.clone()),
                                    icons::ShieldCheck {}
                                    {tr("Domain erlauben")}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
