//! Reverse Proxy: Namen wie `music.nrz.ch` an ein HTTP-Ziel wie `http://100.78.107.162:8350`
//! weiterreichen. nrzDNS beantwortet den Namen selbst mit der Adresse des Proxys.

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::state;
use crate::ui::alert::{Alert, AlertDescription, AlertTitle};
use crate::ui::table::*;
use dioxus::prelude::*;
use nrzdns_types::{ProxyHost, ProxyHostInput, ProxySettings, ProxyStatus};

/// Adresse, unter der Browser den Namen öffnen.
fn url(host: &str, port: u16) -> String {
    if port == 80 || port == 0 {
        format!("http://{host}/")
    } else {
        format!("http://{host}:{port}/")
    }
}

#[component]
pub fn Proxy() -> Element {
    let admin = state::is_admin();
    let version = use_signal(|| 0u64);
    let status = use_resource(move || async move {
        let _ = version();
        api::get::<ProxyStatus>("/proxy").await
    });

    rsx! {
        PageHeader { title: tr("Reverse Proxy"), description: tr("Eigene Namen statt IP-Adresse und Port, z. B. music.nrz.ch statt 100.78.107.162:8350.") }
        div { class: "grid grid-cols-1 gap-6",
            Alert {
                icons::Waypoints {}
                AlertTitle { {tr("So funktioniert es")} }
                AlertDescription {
                    p { {tr("Trage einen Namen und das Ziel ein. nrzDNS beantwortet den Namen mit der Adresse dieses Geräts, und der Proxy reicht jede HTTP-Anfrage für diesen Namen an das Ziel weiter – Ports spielen für den Browser keine Rolle mehr. Die Domain muss dir nicht gehören: Es klappt auf allen Geräten, die nrzDNS als DNS-Server benutzen. Nur HTTP, kein HTTPS.")} }
                }
            }
            if !admin {
                ReadOnlyHint {}
            }
            match &*status.read() {
                None => rsx! { Loading {} },
                Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
                Some(Ok(s)) => rsx! {
                    if s.listen.is_empty() {
                        Callout { text: tr("Der Proxy ist ausgeschaltet (NRZDNS_PROXY_LISTEN ist leer). Die Namen werden trotzdem beantwortet."), error: true }
                    }
                    for e in s.listen_errors.iter() {
                        Callout { key: "{e}", text: trf("Port konnte nicht geöffnet werden: {0}", &[e]), error: true }
                    }
                    if s.port != 80 && s.port != 0 {
                        Callout { text: trf("Der Proxy läuft auf Port {0} – Namen also mit Port öffnen, z. B. http://music.nrz.ch:{0}/.", &[&s.port.to_string()]) }
                    }
                    Hosts { status: s.clone(), version }
                    AddressSection { settings: s.settings.clone(), version }
                },
            }
        }
    }
}

#[component]
fn Hosts(status: ProxyStatus, version: Signal<u64>) -> Element {
    let admin = state::is_admin();
    let mut host = use_signal(String::new);
    let mut target = use_signal(String::new);
    let mut comment = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let editing = use_signal(|| None::<ProxyHost>);
    let port = status.port;

    let add = move |e: FormEvent| {
        e.prevent_default();
        spawn(async move {
            busy.set(true);
            let res = api::post::<ProxyHost, _>(
                "/proxy/hosts",
                &ProxyHostInput {
                    host: host().trim().to_string(),
                    target: target().trim().to_string(),
                    enabled: true,
                    comment: comment().trim().to_string(),
                },
            )
            .await;
            busy.set(false);
            match res {
                Ok(h) => {
                    toast(trf("„{0}“ hinzugefügt.", &[&h.host]));
                    host.set(String::new());
                    target.set(String::new());
                    comment.set(String::new());
                    version += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };

    rsx! {
        Section { title: tr("Einträge"), description: tr("Gilt sofort, ohne Neustart."),
            div { class: "grid grid-cols-1 gap-4",
                if admin {
                    form { class: "grid grid-cols-1 gap-2 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,0.8fr)_auto]", onsubmit: add,
                        input {
                            class: "{INPUT} font-mono text-[13px]",
                            required: true,
                            spellcheck: false,
                            autocapitalize: "none",
                            "aria-label": tr("Name"),
                            placeholder: tr("Name, z. B. music.nrz.ch"),
                            value: "{host}",
                            oninput: move |e| host.set(e.value()),
                        }
                        input {
                            class: "{INPUT} font-mono text-[13px]",
                            required: true,
                            spellcheck: false,
                            autocapitalize: "none",
                            "aria-label": tr("Ziel"),
                            placeholder: tr("Ziel, z. B. http://100.78.107.162:8350"),
                            value: "{target}",
                            oninput: move |e| target.set(e.value()),
                        }
                        input {
                            class: INPUT,
                            maxlength: 200,
                            "aria-label": tr("Kommentar"),
                            placeholder: tr("Kommentar (optional)"),
                            value: "{comment}",
                            oninput: move |e| comment.set(e.value()),
                        }
                        button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy() || host().trim().is_empty() || target().trim().is_empty(),
                            icons::Plus {}
                            {tr("Hinzufügen")}
                        }
                    }
                }
                if status.hosts.is_empty() {
                    div { class: "rounded-lg border border-dashed px-4 py-8 text-center text-sm text-muted-foreground", {tr("Noch keine Einträge.")} }
                } else {
                    TableWrapper {
                        Table {
                            TableHeader {
                                tr {
                                    TableHead { {tr("Name")} }
                                    TableHead { {tr("Ziel")} }
                                    TableHead { class: "hidden md:table-cell", {tr("DNS-Antwort")} }
                                    TableHead { class: "w-16", {tr("Aktiv")} }
                                    if admin {
                                        TableHead { class: "w-20" }
                                    }
                                }
                            }
                            TableBody {
                                for h in status.hosts.iter().cloned() {
                                    HostRow { key: "{h.id}", host: h, port, version, editing }
                                }
                            }
                        }
                    }
                }
            }
        }
        EditDialog { editing, version }
    }
}

#[component]
fn HostRow(
    host: ProxyHost,
    port: u16,
    version: Signal<u64>,
    editing: Signal<Option<ProxyHost>>,
) -> Element {
    let admin = state::is_admin();
    let h = host.clone();
    let toggle = move |on: bool| {
        let h = h.clone();
        spawn(async move {
            let input = ProxyHostInput {
                host: h.host.clone(),
                target: h.target.clone(),
                enabled: on,
                comment: h.comment.clone(),
            };
            match api::put::<ProxyHost, _>(&format!("/proxy/hosts/{}", h.id), &input).await {
                Ok(_) => version += 1,
                Err(e) => toast_error(e),
            }
        });
    };
    let link = url(&host.host, port);
    rsx! {
        TableRow {
            TableCell { class: "font-mono text-[13px] break-all",
                a { class: "hover:underline", href: "{link}", target: "_blank", rel: "noopener", "{host.host}" }
                if !host.comment.is_empty() {
                    p { class: "font-sans text-xs text-muted-foreground", "{host.comment}" }
                }
            }
            TableCell { class: "font-mono text-[13px] break-all text-muted-foreground",
                a { class: "hover:underline", href: "{host.target}", target: "_blank", rel: "noopener", "{host.target}" }
            }
            TableCell { class: "hidden font-mono text-[13px] md:table-cell",
                if host.dns_address.is_empty() {
                    span { class: "font-sans text-xs text-destructive", title: tr("Unten die Adresse dieses Geräts eintragen."), {tr("keine – Adresse fehlt")} }
                } else {
                    "{host.dns_address}"
                }
            }
            TableCell {
                Toggle { checked: host.enabled, disabled: !admin, onchange: toggle }
            }
            if admin {
                TableCell { class: "px-2 text-right whitespace-nowrap",
                    button {
                        class: icon_btn(""),
                        title: tr("Bearbeiten"),
                        onclick: {
                            let h = host.clone();
                            move |_| editing.set(Some(h.clone()))
                        },
                        icons::Pencil {}
                    }
                    button {
                        class: icon_btn("hover:text-destructive"),
                        title: tr("Entfernen"),
                        onclick: {
                            let h = host.clone();
                            move |_| {
                                let h = h.clone();
                                spawn(async move {
                                    let ask = Ask::new(trf("„{0}“ entfernen?", &[&h.host]), tr("Der Name wird dann nicht mehr weitergereicht und von nrzDNS nicht mehr beantwortet."))
                                        .confirm(tr("Entfernen"))
                                        .destructive();
                                    if confirm(ask).await {
                                        match api::delete(&format!("/proxy/hosts/{}", h.id)).await {
                                            Ok(()) => {
                                                toast(trf("„{0}“ entfernt.", &[&h.host]));
                                                version += 1;
                                            }
                                            Err(e) => toast_error(e),
                                        }
                                    }
                                });
                            }
                        },
                        icons::Trash2 {}
                    }
                }
            }
        }
    }
}

#[component]
fn EditDialog(editing: Signal<Option<ProxyHost>>, version: Signal<u64>) -> Element {
    let mut open = use_signal(|| false);
    let mut host = use_signal(String::new);
    let mut target = use_signal(String::new);
    let mut comment = use_signal(String::new);
    let mut busy = use_signal(|| false);

    use_effect(move || {
        if let Some(h) = editing() {
            host.set(h.host.clone());
            target.set(h.target.clone());
            comment.set(h.comment.clone());
            open.set(true);
        }
    });
    use_effect(move || {
        if !open() && editing.peek().is_some() {
            editing.set(None);
        }
    });

    let save = move |e: FormEvent| {
        e.prevent_default();
        let Some(h) = editing() else { return };
        spawn(async move {
            busy.set(true);
            let input = ProxyHostInput {
                host: host().trim().to_string(),
                target: target().trim().to_string(),
                enabled: h.enabled,
                comment: comment().trim().to_string(),
            };
            let res = api::put::<ProxyHost, _>(&format!("/proxy/hosts/{}", h.id), &input).await;
            busy.set(false);
            match res {
                Ok(h) => {
                    toast(trf("„{0}“ gespeichert.", &[&h.host]));
                    open.set(false);
                    version += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };

    rsx! {
        Modal { open, title: tr("Eintrag bearbeiten"),
            form { class: "grid grid-cols-1 gap-4", onsubmit: save,
                Field { label: tr("Name"),
                    input { class: "{INPUT} font-mono text-[13px]", required: true, spellcheck: false, autocapitalize: "none",
                        value: "{host}", oninput: move |e| host.set(e.value()) }
                }
                Field { label: tr("Ziel"), hint: tr("Nur HTTP, z. B. http://100.78.107.162:8350"),
                    input { class: "{INPUT} font-mono text-[13px]", required: true, spellcheck: false, autocapitalize: "none",
                        value: "{target}", oninput: move |e| target.set(e.value()) }
                }
                Field { label: tr("Kommentar"),
                    input { class: INPUT, maxlength: 200, value: "{comment}", oninput: move |e| comment.set(e.value()) }
                }
                div { class: "flex justify-end gap-2",
                    button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| open.set(false), {tr("Abbrechen")} }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy(), {tr("Speichern")} }
                }
            }
        }
    }
}

#[component]
fn AddressSection(settings: ProxySettings, version: Signal<u64>) -> Element {
    let admin = state::is_admin();
    let mut address = use_signal(|| settings.address.clone());
    let mut busy = use_signal(|| false);
    let save = move |e: FormEvent| {
        e.prevent_default();
        spawn(async move {
            busy.set(true);
            let res = api::put::<ProxyStatus, _>(
                "/proxy/settings",
                &ProxySettings {
                    address: address().trim().to_string(),
                },
            )
            .await;
            busy.set(false);
            match res {
                Ok(_) => {
                    toast(tr("Gespeichert."));
                    version += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };
    rsx! {
        Section { title: tr("DNS-Antwort"), description: tr("Mit dieser Adresse beantwortet nrzDNS die Namen der Einträge – die IP-Adresse des Geräts, auf dem nrzDNS läuft."),
            form { class: "grid grid-cols-1 gap-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end", onsubmit: save,
                Field { label: tr("IP-Adresse dieses Geräts"), hint: tr("Leer = die IP-Adresse aus dem Ziel (passt, wenn das Ziel auf demselben Gerät läuft)."),
                    input {
                        class: "{INPUT} font-mono text-[13px]",
                        disabled: !admin,
                        spellcheck: false,
                        placeholder: "100.78.107.162",
                        value: "{address}",
                        oninput: move |e| address.set(e.value()),
                    }
                }
                if admin {
                    button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy(), {tr("Speichern")} }
                }
            }
        }
    }
}
