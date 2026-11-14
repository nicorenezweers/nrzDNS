//! Zonen: Liste mit Typ, Einträgen und Schalter, neue Zone (primär oder bedingte
//! Weiterleitung) und Import einer Zonendatei im BIND-Format.

use crate::Route;
use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::components::upstreams::UpstreamEditor;
use crate::i18n::{tr, trf};
use crate::labels;
use crate::state;
use crate::ui::table::*;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{
    UpdateZoneInput, Upstream, Zone, ZoneImportInput, ZoneImportResult, ZoneInput, ZoneKind,
    normalize_domain,
};

#[component]
pub fn Zones() -> Element {
    let admin = state::is_admin();
    let nav = use_navigator();
    let mut version = use_signal(|| 0u64);
    let zones = use_resource(move || async move {
        let _ = version();
        api::get::<Vec<Zone>>("/zones").await
    });
    let mut create_open = use_signal(|| false);
    let mut import_open = use_signal(|| false);
    let mut q = use_signal(String::new);
    let filter = q().trim().to_lowercase();
    rsx! {
        PageHeader {
            title: tr("Zonen"),
            description: tr("Eigene Zonen beantwortet nrzNetwork selbst und verbindlich. Weiterleitungszonen schicken Anfragen an bestimmte Server – z. B. fritz.box an den Router."),
            actions: rsx! {
                if admin {
                    button { class: btn(BTN_OUTLINE), onclick: move |_| import_open.set(true),
                        icons::FileUp {}
                        {tr("Importieren")}
                    }
                    button { class: btn(BTN_PRIMARY), onclick: move |_| create_open.set(true),
                        icons::Plus {}
                        {tr("Zone anlegen")}
                    }
                }
            },
        }
        div { class: "grid grid-cols-1 gap-4",
            if !admin {
                ReadOnlyHint {}
            }
            match &*zones.read() {
                None => rsx! { Loading {} },
                Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
                Some(Ok(list)) if list.is_empty() => rsx! {
                    div { class: "rounded-xl border border-dashed",
                        EmptyState {
                            title: tr("Noch keine Zonen"),
                            description: tr("Lege eine Zone für dein Heimnetz an (z. B. home.arpa) oder importiere eine Zonendatei."),
                            icon: rsx! { icons::Globe {} },
                            if admin {
                                button { class: btn(BTN_PRIMARY), onclick: move |_| create_open.set(true),
                                    icons::Plus {}
                                    {tr("Zone anlegen")}
                                }
                            }
                        }
                    }
                },
                Some(Ok(list)) => {
                    let shown: Vec<Zone> = list.iter().filter(|z| filter.is_empty() || z.name.contains(&filter) || z.comment.to_lowercase().contains(&filter)).cloned().collect();
                    rsx! {
                        div { class: "flex flex-wrap items-center justify-between gap-2",
                            SearchInput { id: "page-search", value: q(), oninput: move |v| q.set(v), placeholder: tr("Zonen durchsuchen …") }
                            span { class: "text-xs text-muted-foreground", {trf("{0} Zonen", &[&list.len()])} }
                        }
                        TableWrapper {
                            Table {
                                TableHeader {
                                    tr {
                                        TableHead { {tr("Name")} }
                                        TableHead { {tr("Typ")} }
                                        TableHead { class: "text-right", {tr("Einträge")} }
                                        TableHead { {tr("Aktiv")} }
                                        TableHead { class: "hidden md:table-cell", {tr("Geändert")} }
                                        TableHead { class: "w-20" }
                                    }
                                }
                                TableBody {
                                    if shown.is_empty() {
                                        tr {
                                            td { class: "px-3 py-6 text-center text-muted-foreground", colspan: "6", {tr("Keine Treffer.")} }
                                        }
                                    }
                                    for z in shown {
                                        ZoneRow { key: "{z.id}", zone: z, admin, on_change: move |_| version += 1 }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        CreateZone {
            open: create_open,
            on_done: move |z: Zone| {
                version += 1;
                nav.push(Route::ZoneView { id: z.id });
            },
        }
        ImportZone { open: import_open, on_done: move |_| version += 1 }
    }
}

#[component]
fn ZoneRow(zone: Zone, admin: bool, on_change: EventHandler<()>) -> Element {
    let z = zone;
    let id = z.id;
    let name = z.name.clone();
    rsx! {
        TableRow {
            TableCell {
                Link { to: Route::ZoneView { id }, class: "font-mono text-[13px] font-medium hover:underline", "{z.name}" }
                if !z.comment.is_empty() {
                    p { class: "max-w-md truncate text-xs text-muted-foreground", "{z.comment}" }
                }
            }
            TableCell {
                Pill { tone: if z.kind == ZoneKind::Primary { Tone::Strong } else { Tone::Neutral }, {labels::zone_kind(z.kind)} }
            }
            TableCell { class: "text-right tabular-nums", {util::num(z.record_count as u64)} }
            TableCell {
                Toggle {
                    checked: !z.disabled,
                    disabled: !admin,
                    onchange: move |on: bool| {
                        spawn(async move {
                            match api::put::<Zone, _>(&format!("/zones/{id}"), &UpdateZoneInput { disabled: Some(!on), ..Default::default() }).await {
                                Ok(z) => {
                                    toast(if z.disabled { trf("„{0}“ ausgeschaltet.", &[&z.name]) } else { trf("„{0}“ eingeschaltet.", &[&z.name]) });
                                    on_change.call(());
                                }
                                Err(e) => toast_error(e),
                            }
                        });
                    },
                }
            }
            TableCell { class: "hidden whitespace-nowrap text-muted-foreground md:table-cell", title: util::datetime(z.updated_at), {util::relative(z.updated_at)} }
            TableCell { class: "px-2",
                div { class: "flex items-center justify-end gap-0.5",
                    a { class: ICON_BTN, href: api::href(&format!("/zones/{id}/export")), download: "{z.name}.zone", title: tr("Zonendatei herunterladen"),
                        icons::Download {}
                    }
                    if admin {
                        button {
                            class: icon_btn("hover:text-destructive"),
                            title: tr("Zone löschen"),
                            onclick: move |_| {
                                let name = name.clone();
                                spawn(async move {
                                    let ask = Ask::new(trf("Zone „{0}“ löschen?", &[&name]), tr("Die Zone wird mit allen Einträgen gelöscht. Das lässt sich nicht rückgängig machen."))
                                        .confirm(tr("Zone löschen"))
                                        .destructive();
                                    if confirm(ask).await {
                                        match api::delete(&format!("/zones/{id}")).await {
                                            Ok(()) => {
                                                toast(trf("Zone „{0}“ gelöscht.", &[&name]));
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

/// Neue Zone: Name, Typ, Weiterleitungen (nur bedingte Weiterleitung), Kommentar.
#[component]
fn CreateZone(open: Signal<bool>, on_done: EventHandler<Zone>) -> Element {
    let mut name = use_signal(String::new);
    let mut kind = use_signal(ZoneKind::default);
    let mut forwarders = use_signal(Vec::<Upstream>::new);
    let mut comment = use_signal(String::new);
    let mut busy = use_signal(|| false);
    use_effect(move || {
        if open() {
            name.set(String::new());
            kind.set(ZoneKind::Primary);
            forwarders.set(vec![Upstream::default()]);
            comment.set(String::new());
        }
    });
    let submit = move |e: FormEvent| {
        e.prevent_default();
        let Some(zone) = normalize_domain(&name()) else {
            toast_error(tr(
                "Das ist kein gültiger Zonenname (z. B. home.arpa oder example.com).",
            ));
            return;
        };
        let fw: Vec<Upstream> = forwarders()
            .into_iter()
            .filter(|u| !u.address.trim().is_empty())
            .collect();
        if kind() == ZoneKind::Forwarder && fw.is_empty() {
            toast_error(tr(
                "Eine Weiterleitungszone braucht mindestens einen Server.",
            ));
            return;
        }
        let body = ZoneInput {
            name: zone,
            kind: kind(),
            forwarders: if kind() == ZoneKind::Forwarder {
                fw
            } else {
                Vec::new()
            },
            comment: comment().trim().to_string(),
        };
        spawn(async move {
            busy.set(true);
            let res = api::post::<Zone, _>("/zones", &body).await;
            busy.set(false);
            match res {
                Ok(z) => {
                    toast(trf("Zone „{0}“ angelegt.", &[&z.name]));
                    open.set(false);
                    on_done.call(z);
                }
                Err(e) => toast_error(e),
            }
        });
    };
    rsx! {
        Modal { open, title: tr("Zone anlegen"), class: "max-w-2xl",
            form { class: "grid grid-cols-1 gap-5", onsubmit: submit,
                Field { label: tr("Name der Zone"), hint: tr("Ohne Punkt am Ende, z. B. home.arpa, example.com oder 1.168.192.in-addr.arpa für Rückwärtsanfragen."),
                    input {
                        class: "{INPUT} font-mono",
                        required: true,
                        spellcheck: false,
                        autocapitalize: "none",
                        placeholder: "home.arpa",
                        value: "{name}",
                        oninput: move |e| name.set(e.value()),
                    }
                }
                div { class: "grid grid-cols-1 gap-2",
                    span { class: "text-sm font-medium", {tr("Typ")} }
                    Segmented {
                        options: vec![("primary".to_string(), tr("Primärzone")), ("forwarder".to_string(), tr("Bedingte Weiterleitung"))],
                        value: if kind() == ZoneKind::Primary { "primary".to_string() } else { "forwarder".to_string() },
                        onchange: move |v: String| kind.set(if v == "forwarder" { ZoneKind::Forwarder } else { ZoneKind::Primary }),
                    }
                    p { class: "text-xs text-muted-foreground",
                        if kind() == ZoneKind::Primary {
                            {tr("nrzNetwork legt SOA und NS an; Einträge pflegst du danach in der Zone.")}
                        } else {
                            {tr("Anfragen in dieser Zone gehen an die Server unten. Eigene Einträge in der Zone haben trotzdem Vorrang.")}
                        }
                    }
                }
                if kind() == ZoneKind::Forwarder {
                    div { class: "grid grid-cols-1 gap-2",
                        span { class: "text-sm font-medium", {tr("Weiterleiten an")} }
                        UpstreamEditor { value: forwarders(), onchange: move |v| forwarders.set(v), presets: false }
                    }
                }
                Field { label: tr("Kommentar (optional)"),
                    input { class: INPUT, maxlength: 200, value: "{comment}", oninput: move |e| comment.set(e.value()) }
                }
                div { class: "flex justify-end gap-2",
                    button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| open.set(false), {tr("Abbrechen")} }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy() || name().trim().is_empty(), {tr("Anlegen")} }
                }
            }
        }
    }
}

/// Zonendatei einfügen oder auswählen; zeigt danach, was übernommen und was übersprungen wurde.
#[component]
fn ImportZone(open: Signal<bool>, on_done: EventHandler<()>) -> Element {
    let nav = use_navigator();
    let mut name = use_signal(String::new);
    let mut text = use_signal(String::new);
    let mut replace = use_signal(|| false);
    let mut busy = use_signal(|| false);
    let mut result = use_signal(|| None::<ZoneImportResult>);
    use_effect(move || {
        if open() {
            name.set(String::new());
            text.set(String::new());
            replace.set(false);
            result.set(None);
        }
    });
    let submit = move |e: FormEvent| {
        e.prevent_default();
        let zone = name().trim().to_string();
        if !zone.is_empty() && normalize_domain(&zone).is_none() {
            toast_error(tr(
                "Das ist kein gültiger Zonenname (z. B. home.arpa oder example.com).",
            ));
            return;
        }
        let body = ZoneImportInput {
            name: normalize_domain(&zone).unwrap_or_default(),
            text: text(),
            replace: replace(),
        };
        spawn(async move {
            busy.set(true);
            let res = api::post::<ZoneImportResult, _>("/zones/import", &body).await;
            busy.set(false);
            match res {
                Ok(r) => {
                    toast(trf(
                        "{0} Einträge in „{1}“ übernommen.",
                        &[&r.imported, &r.zone.name],
                    ));
                    result.set(Some(r));
                    on_done.call(());
                }
                Err(e) => toast_error(e),
            }
        });
    };
    rsx! {
        Modal { open, title: tr("Zonendatei importieren"), description: tr("Zonendatei im BIND-Format (RFC 1035), z. B. aus einem anderen DNS-Server exportiert."), class: "max-w-2xl",
            if let Some(r) = result() {
                div { class: "grid grid-cols-1 gap-4",
                    Callout { text: trf("{0} Einträge in „{1}“ übernommen.", &[&r.imported, &r.zone.name]) }
                    if !r.skipped.is_empty() {
                        div { class: "grid grid-cols-1 gap-2",
                            p { class: "text-sm font-medium", {trf("{0} Zeilen übersprungen", &[&r.skipped.len()])} }
                            ul { class: "max-h-60 overflow-y-auto rounded-lg border bg-background/40 p-3 font-mono text-xs leading-relaxed text-muted-foreground",
                                for (i , line) in r.skipped.iter().enumerate() {
                                    li { key: "{i}", class: "break-all", "{line}" }
                                }
                            }
                        }
                    }
                    div { class: "flex justify-end gap-2",
                        button { class: btn(BTN_OUTLINE), onclick: move |_| open.set(false), {tr("Schliessen")} }
                        button {
                            class: btn(BTN_PRIMARY),
                            onclick: move |_| {
                                open.set(false);
                                nav.push(Route::ZoneView { id: r.zone.id });
                            },
                            {tr("Zur Zone")}
                        }
                    }
                }
            } else {
                form { class: "grid grid-cols-1 gap-4", onsubmit: submit,
                    Field { label: tr("Name der Zone (optional)"), hint: tr("Leer = aus $ORIGIN bzw. dem SOA der Datei."),
                        input {
                            class: "{INPUT} font-mono",
                            spellcheck: false,
                            autocapitalize: "none",
                            placeholder: "example.com",
                            value: "{name}",
                            oninput: move |e| name.set(e.value()),
                        }
                    }
                    div { class: "grid grid-cols-1 gap-1.5",
                        div { class: "flex items-center justify-between gap-2",
                            span { class: "text-sm font-medium", {tr("Inhalt")} }
                            label { class: "{btn_sm(BTN_GHOST)} cursor-pointer",
                                icons::FileText {}
                                {tr("Datei wählen …")}
                                input {
                                    class: "sr-only",
                                    r#type: "file",
                                    accept: ".zone,.db,.txt,text/plain",
                                    onchange: move |e| {
                                        if let Some(file) = util::input_file(&e) {
                                            spawn(async move {
                                                match util::file_text(&file).await {
                                                    Some(t) => text.set(t),
                                                    None => toast_error(tr("Die Datei liess sich nicht lesen.")),
                                                }
                                            });
                                        }
                                    },
                                }
                            }
                        }
                        textarea {
                            class: "min-h-48 w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 dark:bg-input/30",
                            spellcheck: false,
                            required: true,
                            placeholder: "$ORIGIN example.com.\n@   3600 IN SOA ns1.example.com. hostmaster.example.com. 1 900 300 604800 900\nwww 3600 IN A   192.168.1.10",
                            value: "{text}",
                            oninput: move |e| text.set(e.value()),
                        }
                    }
                    Checkbox {
                        checked: replace(),
                        onchange: move |v| replace.set(v),
                        label: tr("Bestehende Zone ersetzen"),
                        hint: tr("Gibt es die Zone schon, werden ihre Einträge durch die aus der Datei ersetzt."),
                    }
                    div { class: "flex justify-end gap-2",
                        button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| open.set(false), {tr("Abbrechen")} }
                        button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy() || text().trim().is_empty(),
                            if busy() {
                                icons::LoaderCircle { class: "size-4 animate-spin" }
                            }
                            {tr("Importieren")}
                        }
                    }
                }
            }
        }
    }
}
