//! Sperren: Zustand (aktiv, pausiert, Zahl der Domains, letzte/nächste Aktualisierung),
//! Sperrlisten mit Vorlagen, eigene Sperren und die Prüfung „Wird diese Domain gesperrt?“.

use crate::Route;
use crate::api;
use crate::components::common::*;
use crate::components::domains::DomainList;
use crate::components::overlay::*;
use crate::components::pause::{BlockingState, PauseControl};
use crate::i18n::{tr, trf};
use crate::state;
use crate::ui::card::Card;
use crate::ui::table::*;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{
    BlockList, BlockListInput, BlockListPreset, BlockingStatus, DomainCheck, normalize_domain,
};

#[component]
pub fn Blocking() -> Element {
    let admin = state::is_admin();
    let mut version = use_signal(|| 0u64);
    let mut status = use_signal(|| None::<BlockingStatus>);
    let mut error = use_signal(|| None::<String>);
    let _load = use_resource(move || async move {
        let _ = version();
        match api::get::<BlockingStatus>("/blocking").await {
            Ok(s) => {
                status.set(Some(s));
                error.set(None);
            }
            Err(e) => error.set(Some(e.message)),
        }
    });
    // Solange neu geladen wird, alle 3 s nachsehen
    use_future(move || async move {
        loop {
            gloo_timers::future::TimeoutFuture::new(3000).await;
            if status.peek().as_ref().is_some_and(|s| s.updating) {
                version += 1;
            }
        }
    });
    let mut dialog_open = use_signal(|| false);
    let mut editing = use_signal(|| None::<BlockList>);
    let mut updating = use_signal(|| false);

    let update_now = move |_| {
        spawn(async move {
            updating.set(true);
            let res = api::action::<BlockingStatus>("/blocking/update").await;
            updating.set(false);
            match res {
                Ok(s) => {
                    toast(if s.updating {
                        tr("Sperrlisten werden neu geladen …")
                    } else {
                        tr("Sperrlisten aktualisiert.")
                    });
                    status.set(Some(s));
                }
                Err(e) => toast_error(e),
            }
        });
    };

    let s = status();
    rsx! {
        PageHeader {
            title: tr("Sperren"),
            description: tr("Sperrlisten aus dem Netz und eigene Sperren gegen Werbung, Tracking und Schadsoftware."),
            actions: rsx! {
                if admin {
                    button { class: btn(BTN_OUTLINE), disabled: updating() || s.as_ref().is_some_and(|s| s.updating), onclick: update_now,
                        icons::RefreshCw { class: if updating() || s.as_ref().is_some_and(|s| s.updating) { "size-4 animate-spin" } else { "size-4" } }
                        {tr("Jetzt aktualisieren")}
                    }
                    button {
                        class: btn(BTN_PRIMARY),
                        onclick: move |_| {
                            editing.set(None);
                            dialog_open.set(true);
                        },
                        icons::Plus {}
                        {tr("Liste hinzufügen")}
                    }
                }
            },
        }
        div { class: "grid grid-cols-1 gap-6",
            if !admin {
                ReadOnlyHint {}
            }
            if let Some(e) = error() {
                Callout { text: e, error: true }
            }
            match s {
                None if error().is_none() => rsx! { Loading {} },
                None => rsx! {},
                Some(s) => rsx! {
                    StatusCard { status: s.clone(), on_change: move |_| version += 1 }
                    Lists {
                        lists: s.lists.clone(),
                        admin,
                        on_edit: move |l: BlockList| {
                            editing.set(Some(l));
                            dialog_open.set(true);
                        },
                        on_change: move |_| version += 1,
                    }
                    if admin {
                        Presets { lists: s.lists.clone(), on_change: move |_| version += 1 }
                    }
                },
            }
            DomainList {
                base: "/blocked",
                title: tr("Eigene Sperren"),
                description: tr("Diese Domains sind immer gesperrt – samt allen Subdomains. Ausnahmen haben trotzdem Vorrang."),
                empty: tr("Noch keine eigenen Sperren."),
                add_label: tr("Domain sperren"),
            }
            CheckDomain {}
        }
        ListDialog { open: dialog_open, list: editing(), on_done: move |_| version += 1 }
    }
}

#[component]
fn StatusCard(status: BlockingStatus, on_change: EventHandler<()>) -> Element {
    let s = status;
    let active = s.lists.iter().filter(|l| l.enabled).count();
    rsx! {
        Card { class: "gap-4 px-5 py-5 sm:px-6",
            div { class: "flex flex-wrap items-center justify-between gap-3",
                div { class: "flex flex-wrap items-center gap-2",
                    BlockingState { enabled: s.enabled, paused_until: s.paused_until }
                    if s.updating {
                        Pill { tone: Tone::Neutral,
                            icons::LoaderCircle { class: "mr-1 size-3 animate-spin" }
                            {tr("Listen werden geladen …")}
                        }
                    }
                    if !s.enabled {
                        Link { to: Route::Settings { section: "blocking".into() }, class: "text-xs text-muted-foreground underline-offset-4 hover:text-foreground hover:underline",
                            {tr("In den Einstellungen einschalten")}
                        }
                    }
                }
                PauseControl { enabled: s.enabled, paused_until: s.paused_until, on_done: move |_| on_change.call(()) }
            }
            dl { class: "grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-3 lg:grid-cols-6",
                Stat { label: tr("Gesperrte Domains"), value: util::num(s.total_domains), strong: true }
                Stat { label: tr("Aktive Listen"), value: trf("{0} von {1}", &[&active, &s.lists.len()]) }
                Stat { label: tr("Eigene Sperren"), value: util::num(s.custom_blocked as u64) }
                Stat { label: tr("Ausnahmen"), value: util::num(s.allowed as u64) }
                Stat { label: tr("Zuletzt aktualisiert"), value: s.last_update_at.map(util::relative).unwrap_or_else(|| tr("noch nie")) }
                Stat { label: tr("Nächste Aktualisierung"), value: s.next_update_at.map(util::relative).unwrap_or_else(|| "–".into()) }
            }
        }
    }
}

#[component]
fn Stat(
    #[props(into)] label: String,
    #[props(into)] value: String,
    #[props(default)] strong: bool,
) -> Element {
    rsx! {
        div { class: "min-w-0",
            dt { class: "truncate text-xs text-muted-foreground", "{label}" }
            dd { class: if strong { "mt-0.5 truncate text-lg font-semibold" } else { "mt-0.5 truncate font-medium" }, "{value}" }
        }
    }
}

#[component]
fn Lists(
    lists: Vec<BlockList>,
    admin: bool,
    on_edit: EventHandler<BlockList>,
    on_change: EventHandler<()>,
) -> Element {
    rsx! {
        Section { title: tr("Sperrlisten"), description: tr("Werden regelmässig neu geladen. Schlägt das Laden fehl, bleibt die alte Fassung aktiv."),
            if lists.is_empty() {
                div { class: "rounded-lg border border-dashed px-4 py-8 text-center text-sm text-muted-foreground",
                    {tr("Noch keine Sperrliste. Füge eine Vorlage unten hinzu oder trage eine eigene Adresse ein.")}
                }
            } else {
                TableWrapper { class: "bg-transparent",
                    Table {
                        TableHeader {
                            tr {
                                TableHead { {tr("Liste")} }
                                TableHead { class: "text-right", {tr("Domains")} }
                                TableHead { class: "hidden md:table-cell", {tr("Aktualisiert")} }
                                TableHead { {tr("Aktiv")} }
                                if admin {
                                    TableHead { class: "w-20" }
                                }
                            }
                        }
                        TableBody {
                            for l in lists {
                                ListRow { key: "{l.id}", list: l, admin, on_edit, on_change }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn ListRow(
    list: BlockList,
    admin: bool,
    on_edit: EventHandler<BlockList>,
    on_change: EventHandler<()>,
) -> Element {
    let l = list;
    let id = l.id;
    let (name, url) = (l.name.clone(), l.url.clone());
    let edited = l.clone();
    let deleted = l.name.clone();
    rsx! {
        TableRow {
            TableCell { class: "max-w-[28rem]",
                p { class: if l.enabled { "truncate font-medium" } else { "truncate font-medium text-muted-foreground" }, "{l.name}" }
                a { class: "block truncate font-mono text-xs text-muted-foreground hover:text-foreground hover:underline", href: "{l.url}", target: "_blank", rel: "noopener noreferrer", "{l.url}" }
                if let Some(e) = l.last_error.as_ref().filter(|e| !e.is_empty()) {
                    p { class: "mt-1 flex items-start gap-1 text-xs text-warning",
                        icons::TriangleAlert { class: "mt-0.5 size-3 shrink-0" }
                        span { class: "break-words", "{e}" }
                    }
                }
            }
            TableCell { class: "text-right tabular-nums", {util::num(l.domain_count as u64)} }
            TableCell { class: "hidden whitespace-nowrap text-muted-foreground md:table-cell",
                title: l.last_updated_at.map(util::datetime).unwrap_or_default(),
                {l.last_updated_at.map(util::relative).unwrap_or_else(|| tr("noch nie"))}
            }
            TableCell {
                Toggle {
                    checked: l.enabled,
                    disabled: !admin,
                    onchange: move |on: bool| {
                        let body = BlockListInput { name: name.clone(), url: url.clone(), enabled: on };
                        spawn(async move {
                            match api::put::<BlockList, _>(&format!("/blocking/lists/{id}"), &body).await {
                                Ok(_) => on_change.call(()),
                                Err(e) => toast_error(e),
                            }
                        });
                    },
                }
            }
            if admin {
                TableCell { class: "px-2",
                    div { class: "flex items-center justify-end gap-0.5",
                        button { class: ICON_BTN, title: tr("Bearbeiten"), onclick: move |_| on_edit.call(edited.clone()),
                            icons::Pencil {}
                        }
                        button {
                            class: icon_btn("hover:text-destructive"),
                            title: tr("Liste entfernen"),
                            onclick: move |_| {
                                let name = deleted.clone();
                                spawn(async move {
                                    let ask = Ask::new(trf("Sperrliste „{0}“ entfernen?", &[&name]), tr("Ihre Domains werden nicht mehr gesperrt (ausser sie stehen auch in einer anderen Liste)."))
                                        .confirm(tr("Entfernen"))
                                        .destructive();
                                    if confirm(ask).await {
                                        match api::delete(&format!("/blocking/lists/{id}")).await {
                                            Ok(()) => {
                                                toast(trf("„{0}“ entfernt.", &[&name]));
                                                on_change.call(());
                                            }
                                            Err(e) => toast_error(e),
                                        }
                                    }
                                });
                            },
                            icons::Trash2 {}
                        }
                    }
                }
            }
        }
    }
}

/// Vorlagen mit einem Klick übernehmen (schon vorhandene sind markiert).
#[component]
fn Presets(lists: Vec<BlockList>, on_change: EventHandler<()>) -> Element {
    let presets = use_resource(|| async { crate::state::presets().await.blocklists });
    let mut busy = use_signal(|| None::<String>);
    let Some(all) = presets.read().clone() else {
        return rsx! {};
    };
    if all.is_empty() {
        return rsx! {};
    }
    let add = move |p: BlockListPreset| {
        spawn(async move {
            busy.set(Some(p.url.clone()));
            let res = api::post::<BlockList, _>(
                "/blocking/lists",
                &BlockListInput {
                    name: p.name.clone(),
                    url: p.url.clone(),
                    enabled: true,
                },
            )
            .await;
            busy.set(None);
            match res {
                Ok(l) => {
                    toast(trf(
                        "„{0}“ hinzugefügt – {1} Domains.",
                        &[&l.name, &util::num(l.domain_count as u64)],
                    ));
                    on_change.call(());
                }
                Err(e) => toast_error(e),
            }
        });
    };
    rsx! {
        Section { title: tr("Vorlagen"), description: tr("Bewährte Sperrlisten zum Übernehmen. Eine oder zwei genügen meistens."),
            div { class: "grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3",
                for p in all {
                    {
                        let added = lists.iter().any(|l| l.url == p.url);
                        let loading = busy().as_deref() == Some(p.url.as_str());
                        let preset = p.clone();
                        rsx! {
                            div { key: "{p.url}", class: "flex flex-col gap-3 rounded-lg border bg-background/40 p-4",
                                div { class: "min-w-0 flex-1",
                                    p { class: "font-medium", "{p.name}" }
                                    p { class: "mt-1 text-sm text-muted-foreground", {tr(&p.description)} }
                                }
                                if added {
                                    span { class: "inline-flex items-center gap-1.5 text-sm text-muted-foreground",
                                        icons::Check { class: "size-4" }
                                        {tr("Schon dabei")}
                                    }
                                } else {
                                    button { class: "{btn_sm(BTN_OUTLINE)} w-fit", disabled: busy().is_some(), onclick: move |_| add(preset.clone()),
                                        if loading {
                                            icons::LoaderCircle { class: "size-4 animate-spin" }
                                        } else {
                                            icons::Plus {}
                                        }
                                        {tr("Hinzufügen")}
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

/// Neue Liste oder Liste bearbeiten: Adresse, Name, aktiv.
#[component]
fn ListDialog(open: Signal<bool>, list: Option<BlockList>, on_done: EventHandler<()>) -> Element {
    let mut url = use_signal(String::new);
    let mut name = use_signal(String::new);
    let mut enabled = use_signal(|| true);
    let mut busy = use_signal(|| false);
    let init = list.clone();
    use_effect(use_reactive!(|init| {
        if open() {
            url.set(init.as_ref().map(|l| l.url.clone()).unwrap_or_default());
            name.set(init.as_ref().map(|l| l.name.clone()).unwrap_or_default());
            enabled.set(init.as_ref().is_none_or(|l| l.enabled));
        }
    }));
    let id = list.as_ref().map(|l| l.id);
    let submit = move |e: FormEvent| {
        e.prevent_default();
        let u = url().trim().to_string();
        if !(u.starts_with("http://") || u.starts_with("https://")) {
            toast_error(tr("Die Adresse muss mit http:// oder https:// beginnen."));
            return;
        }
        let body = BlockListInput {
            name: name().trim().to_string(),
            url: u,
            enabled: enabled(),
        };
        spawn(async move {
            busy.set(true);
            let res = match id {
                Some(id) => api::put::<BlockList, _>(&format!("/blocking/lists/{id}"), &body).await,
                None => api::post::<BlockList, _>("/blocking/lists", &body).await,
            };
            busy.set(false);
            match res {
                Ok(l) => {
                    if id.is_some() {
                        toast(tr("Sperrliste gespeichert."));
                    } else {
                        toast(trf(
                            "„{0}“ hinzugefügt – {1} Domains.",
                            &[&l.name, &util::num(l.domain_count as u64)],
                        ));
                    }
                    open.set(false);
                    on_done.call(());
                }
                Err(e) => toast_error(e),
            }
        });
    };
    rsx! {
        Modal {
            open,
            title: if id.is_some() { tr("Sperrliste bearbeiten") } else { tr("Sperrliste hinzufügen") },
            description: tr("hosts-Dateien, reine Domainlisten und einfache Adblock-Regeln (||domain^) werden erkannt."),
            form { class: "grid grid-cols-1 gap-4", onsubmit: submit,
                Field { label: tr("Adresse der Liste"),
                    input {
                        class: "{INPUT} font-mono text-[13px]",
                        r#type: "url",
                        required: true,
                        spellcheck: false,
                        placeholder: "https://…/hosts",
                        value: "{url}",
                        oninput: move |e| url.set(e.value()),
                    }
                }
                Field { label: tr("Name (optional)"), hint: tr("Leer = aus der Adresse"),
                    input { class: INPUT, maxlength: 100, value: "{name}", oninput: move |e| name.set(e.value()) }
                }
                Toggle { checked: enabled(), onchange: move |v| enabled.set(v), label: tr("Aktiv") }
                div { class: "flex justify-end gap-2",
                    button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| open.set(false), {tr("Abbrechen")} }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy() || url().trim().is_empty(),
                        if busy() {
                            icons::LoaderCircle { class: "size-4 animate-spin" }
                        }
                        if id.is_some() { {tr("Speichern")} } else { {tr("Hinzufügen und laden")} }
                    }
                }
            }
        }
    }
}

/// „Wird diese Domain gesperrt?“ – mit allen Treffern (Listen, eigene Sperren, Ausnahmen).
#[component]
fn CheckDomain() -> Element {
    let mut domain = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut result = use_signal(|| None::<DomainCheck>);
    let submit = move |e: FormEvent| {
        e.prevent_default();
        let Some(d) = normalize_domain(&domain()) else {
            toast_error(tr("Das ist keine gültige Domain (z. B. ads.example.com)."));
            return;
        };
        spawn(async move {
            busy.set(true);
            let res =
                api::get::<DomainCheck>(&format!("/blocking/check?domain={}", api::enc(&d))).await;
            busy.set(false);
            match res {
                Ok(r) => result.set(Some(r)),
                Err(e) => toast_error(e),
            }
        });
    };
    rsx! {
        Section { title: tr("Domain prüfen"), description: tr("Zeigt, ob eine Domain gesperrt wird und durch welche Liste oder Regel."),
            div { class: "grid grid-cols-1 gap-4",
                form { class: "flex flex-col gap-2 sm:flex-row", onsubmit: submit,
                    input {
                        class: "{INPUT} font-mono text-[13px] sm:max-w-md",
                        required: true,
                        spellcheck: false,
                        autocapitalize: "none",
                        "aria-label": tr("Domain"),
                        placeholder: "ads.example.com",
                        value: "{domain}",
                        oninput: move |e| domain.set(e.value()),
                    }
                    button { class: btn(BTN_OUTLINE), r#type: "submit", disabled: busy() || domain().trim().is_empty(),
                        icons::SearchCheck {}
                        {tr("Prüfen")}
                    }
                }
                if let Some(r) = result() {
                    div { class: "grid grid-cols-1 gap-3 rounded-lg border bg-background/40 p-4",
                        div { class: "flex flex-wrap items-center gap-2",
                            span { class: "font-mono text-sm", "{r.domain}" }
                            if r.allowed {
                                Pill { tone: Tone::Success, {tr("Erlaubt (Ausnahme)")} }
                            } else if r.blocked {
                                Pill { tone: Tone::Danger, {tr("Gesperrt")} }
                            } else {
                                Pill { tone: Tone::Neutral, {tr("Nicht gesperrt")} }
                            }
                        }
                        if r.matches.is_empty() {
                            p { class: "text-sm text-muted-foreground", {tr("Steht in keiner Liste und keiner eigenen Regel.")} }
                        } else {
                            ul { class: "grid grid-cols-1 gap-1 text-sm",
                                for (i , m) in r.matches.iter().enumerate() {
                                    li { key: "{i}", class: "flex items-start gap-2",
                                        icons::ChevronRight { class: "mt-0.5 size-3.5 shrink-0 text-muted-foreground" }
                                        span { class: "break-all", "{m}" }
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
