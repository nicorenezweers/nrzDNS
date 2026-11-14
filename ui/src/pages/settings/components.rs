//! Komponenten: Cloudflare Tunnel und NetBird laufen in nrzNetwork und aktualisieren sich
//! täglich zur eingestellten Stunde.

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::json::Dot;
use crate::state;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{
    ComponentStatus, ComponentsInput, ComponentsSettings, ComponentsStatus, IntegrationsStatus,
};

#[component]
pub fn ComponentsPage() -> Element {
    let mut version = use_signal(|| 0u64);
    let status = use_resource(move || async move {
        let _ = version();
        api::get::<ComponentsStatus>("/components").await
    });
    let integrations =
        use_resource(|| async { api::get::<IntegrationsStatus>("/integrations").await });
    // Während einer Prüfung oder solange etwas startet: alle 3 s neu laden
    use_future(move || async move {
        loop {
            gloo_timers::future::TimeoutFuture::new(3000).await;
            let busy = matches!(&*status.peek(), Some(Ok(s)) if s.checking || s.components.iter().any(|c| c.enabled && (!c.running || !c.connected)));
            if busy {
                version += 1;
            }
        }
    });
    let (cf_ok, nb_ok) = match &*integrations.read() {
        Some(Ok(i)) => (i.cloudflare.configured, i.netbird.configured),
        _ => (false, false),
    };
    rsx! {
        match &*status.read() {
            None => rsx! { Loading {} },
            Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
            Some(Ok(s)) => rsx! { Form { key: "{s.settings.cloudflared_enabled}-{s.settings.netbird_enabled}-{s.tunnel_token_set}-{s.netbird_key_set}", status: s.clone(), version, cf_ok, nb_ok } },
        }
    }
}

#[component]
fn Card(c: ComponentStatus, title: String, children: Element) -> Element {
    let mut show_log = use_signal(|| false);
    let state_text = if !c.enabled {
        tr("aus")
    } else if c.installed_version.is_empty() {
        tr("wird installiert …")
    } else if !c.running {
        tr("startet …")
    } else if c.connected {
        tr("verbunden")
    } else {
        tr("verbindet …")
    };
    rsx! {
        Section {
            title,
            actions: rsx! {
                div { class: "flex items-center gap-2 text-sm",
                    Dot { on: c.enabled && c.running && c.connected }
                    "{state_text}"
                }
            },
            div { class: "grid grid-cols-1 gap-4",
                div { class: "grid grid-cols-2 gap-3 text-sm sm:grid-cols-4",
                    div { p { class: "text-xs text-muted-foreground", {tr("Version")} } p { class: "font-mono", if c.installed_version.is_empty() { "–" } else { "{c.installed_version}" } } }
                    div { p { class: "text-xs text-muted-foreground", {tr("Neueste")} } p { class: "font-mono", if c.latest_version.is_empty() { "–" } else { "{c.latest_version}" } } }
                    div { p { class: "text-xs text-muted-foreground", {tr("Zustand")} } p { if c.detail.is_empty() { "–" } else { "{c.detail}" } } }
                    div { p { class: "text-xs text-muted-foreground", {tr("Läuft seit")} } p { {if c.started_at == 0 { "–".to_string() } else { util::relative(c.started_at) }} if c.restarts > 0 { span { class: "text-xs text-muted-foreground", " · " {trf("{0} Neustarts", &[&c.restarts.to_string()])} } } } }
                }
                {children}
                if !c.log.is_empty() {
                    div {
                        button { class: btn_sm(BTN_GHOST), r#type: "button", onclick: move |_| show_log.toggle(),
                            icons::ScrollText {} if show_log() { {tr("Ausgabe ausblenden")} } else { {tr("Ausgabe anzeigen")} }
                        }
                        if show_log() {
                            div { class: "mt-2 max-h-72 overflow-auto rounded-lg border bg-muted/30 p-2 font-mono text-[11px] leading-relaxed",
                                for (i, l) in c.log.iter().enumerate() { p { key: "{i}", class: "break-all", "{l}" } }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn Form(status: ComponentsStatus, version: Signal<u64>, cf_ok: bool, nb_ok: bool) -> Element {
    let admin = state::is_admin();
    let s = status.settings.clone();
    let mut hour = use_signal(|| s.update_hour);
    let mut auto = use_signal(|| s.auto_update);
    let mut cf_on = use_signal(|| s.cloudflared_enabled);
    let mut nb_on = use_signal(|| s.netbird_enabled);
    let mut nb_name = use_signal(|| s.netbird_hostname.clone());
    let mut token = use_signal(String::new);
    let mut key = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let input = move || ComponentsInput {
        settings: ComponentsSettings {
            update_hour: hour(),
            auto_update: auto(),
            cloudflared_enabled: cf_on(),
            netbird_enabled: nb_on(),
            netbird_hostname: nb_name().trim().to_string(),
        },
        tunnel_token: token().trim().to_string(),
        netbird_setup_key: key().trim().to_string(),
    };
    let save = move |e: FormEvent| {
        e.prevent_default();
        spawn(async move {
            busy.set(true);
            let res = api::put::<ComponentsStatus, _>("/components", &input()).await;
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
    let action = move |path: &'static str, ok: String| {
        spawn(async move {
            busy.set(true);
            let res = api::action::<ComponentsStatus>(path).await;
            busy.set(false);
            match res {
                Ok(_) => {
                    if !ok.is_empty() {
                        toast(ok);
                    }
                    version += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };
    let forget = move |which: &'static str| {
        spawn(async move {
            let ask = Ask::new(tr("Wirklich entfernen?"), if which == "tunnel" { tr("Der Tunnel-Token wird gelöscht und cloudflared gestoppt.") } else { tr("Die Anmeldung bei NetBird wird gelöscht; zum Wiederverbinden braucht es einen neuen Setup-Key.") })
                .confirm(tr("Entfernen"))
                .destructive();
            if !confirm(ask).await {
                return;
            }
            match api::delete(&format!("/components/{which}")).await {
                Ok(()) => version += 1,
                Err(e) => toast_error(e),
            }
        });
    };
    let cf = status
        .components
        .iter()
        .find(|c| c.name == "cloudflared")
        .cloned()
        .unwrap_or_default();
    let nb = status
        .components
        .iter()
        .find(|c| c.name == "netbird")
        .cloned()
        .unwrap_or_default();
    let hours: Vec<u8> = (0..24).collect();
    rsx! {
        form { class: "grid grid-cols-1 gap-6", onsubmit: save,
            Callout { text: tr("nrzNetwork lädt Cloudflare Tunnel und NetBird selbst (offizielle Versionen von GitHub, Prüfsumme geprüft), startet sie, startet sie nach Abstürzen neu und spielt Updates zur eingestellten Uhrzeit ein. Die separaten Umbrel-Apps „Cloudflare Tunnel“ und „NetBird“ werden danach nicht mehr gebraucht.") }
            Section { title: tr("Automatische Updates"),
                div { class: "grid grid-cols-1 gap-4 sm:grid-cols-[1fr_auto] sm:items-end",
                    Toggle { checked: auto(), disabled: !admin, onchange: move |v| auto.set(v), label: tr("Täglich nach Updates suchen und einspielen"),
                        hint: trf("Zeitzone: {0}. Läuft ein Update, sind Tunnel bzw. NetBird für ein paar Sekunden weg.", &[&status.time_zone]),
                    }
                    Field { label: tr("Uhrzeit"),
                        select { class: "{SELECT} w-32", disabled: !admin || !auto(), value: "{hour}", onchange: move |e| hour.set(e.value().parse().unwrap_or(3)),
                            for h in hours { option { key: "{h}", value: "{h}", {format!("{h:02}:00")} } }
                        }
                    }
                }
                div { class: "mt-4 flex flex-wrap items-center justify-between gap-2 text-sm",
                    span { class: "text-muted-foreground",
                        if status.checking { icons::LoaderCircle { class: "mr-1 inline size-3.5 animate-spin" } {tr("Prüfe …")} }
                        else if status.last_check > 0 { {trf("Zuletzt geprüft {0}: {1}", &[&util::relative(status.last_check), &status.last_check_result])} }
                        else { {tr("Noch nicht geprüft.")} }
                    }
                    if admin {
                        button { class: btn_sm(BTN_OUTLINE), r#type: "button", disabled: busy() || status.checking, onclick: move |_| action("/components/check", String::new()),
                            icons::RefreshCw {} {tr("Jetzt prüfen")}
                        }
                    }
                }
            }
            Card { c: cf.clone(), title: tr("Cloudflare Tunnel"),
                p { class: "text-sm text-muted-foreground", {tr("Macht Einträge des Reverse Proxys öffentlich erreichbar, ohne Ports zu öffnen – freigeben unter Reverse Proxy mit dem Schalter „Öffentlich“. Besucher erscheinen unter Zugriffe mit echter Adresse und Land.")} }
                Toggle { checked: cf_on(), disabled: !admin, onchange: move |v| cf_on.set(v), label: tr("Cloudflare Tunnel in nrzNetwork betreiben") }
                if status.tunnel_token_set {
                    div { class: "flex flex-wrap items-center justify-between gap-2 rounded-lg border px-3 py-2 text-sm",
                        span { {tr("Tunnel:")} " " span { class: "font-mono text-xs", "{status.tunnel_id}" } }
                        if admin { button { class: btn_sm(BTN_GHOST), r#type: "button", onclick: move |_| forget("tunnel"), {tr("Token entfernen")} } }
                    }
                } else {
                    div { class: "grid grid-cols-1 gap-3",
                        if admin && cf_ok {
                            div { class: "flex flex-wrap items-center gap-2",
                                button { class: btn(BTN_PRIMARY), r#type: "button", disabled: busy(), onclick: move |_| action("/components/tunnel", tr("Tunnel angelegt – cloudflared startet.")),
                                    icons::Plus {} {tr("Neuen Tunnel anlegen")}
                                }
                                span { class: "text-xs text-muted-foreground", {tr("über die Cloudflare-Verbindung (Token braucht zusätzlich: Konto → Cloudflare Tunnel → Bearbeiten)")} }
                            }
                        }
                        Field { label: tr("oder vorhandenen Tunnel-Token einfügen"), hint: tr("Cloudflare → Zero Trust → Netzwerke → Tunnel → dein Tunnel → Konfigurieren: der lange Wert nach --token. Damit übernimmt nrzNetwork z. B. den Tunnel der Umbrel-App."),
                            input { class: "{INPUT} font-mono text-[13px]", disabled: !admin, r#type: "password", autocomplete: "off", spellcheck: false, placeholder: "eyJhIjoi…", value: "{token}", oninput: move |e| token.set(e.value()) }
                        }
                    }
                }
            }
            Card { c: nb.clone(), title: tr("NetBird"),
                p { class: "text-sm text-muted-foreground", {tr("nrzNetwork wird selbst ein Gerät im NetBird-Netz (ohne Sonderrechte, im Userspace). Anfragen an seine NetBird-Adresse landen beim Reverse Proxy und beim DNS-Server.")} }
                Toggle { checked: nb_on(), disabled: !admin, onchange: move |v| nb_on.set(v), label: tr("NetBird in nrzNetwork betreiben") }
                Field { label: tr("Name im NetBird-Netz"),
                    input { class: "{INPUT} font-mono text-[13px]", disabled: !admin, maxlength: 60, value: "{nb_name}", oninput: move |e| nb_name.set(e.value()) }
                }
                if status.netbird_key_set {
                    div { class: "flex flex-wrap items-center justify-between gap-2 rounded-lg border px-3 py-2 text-sm",
                        span { {tr("Angemeldet bzw. Setup-Key gespeichert.")} }
                        if admin { button { class: btn_sm(BTN_GHOST), r#type: "button", onclick: move |_| forget("netbird"), {tr("Abmelden")} } }
                    }
                } else {
                    div { class: "grid grid-cols-1 gap-3",
                        if admin && nb_ok {
                            div { class: "flex flex-wrap items-center gap-2",
                                button { class: btn(BTN_PRIMARY), r#type: "button", disabled: busy(), onclick: move |_| action("/components/netbird-key", tr("Setup-Key erzeugt – NetBird verbindet sich.")),
                                    icons::KeyRound {} {tr("Über NetBird anmelden")}
                                }
                                span { class: "text-xs text-muted-foreground", {tr("erzeugt einen einmaligen Setup-Key über die NetBird-Verbindung")} }
                            }
                        }
                        Field { label: tr("oder Setup-Key einfügen"), hint: tr("NetBird → Setup-Keys → Setup-Key erstellen."),
                            input { class: "{INPUT} font-mono text-[13px]", disabled: !admin, r#type: "password", autocomplete: "off", spellcheck: false, value: "{key}", oninput: move |e| key.set(e.value()) }
                        }
                    }
                }
            }
            if admin {
                div { class: "flex justify-end",
                    button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy(), {tr("Speichern")} }
                }
            }
        }
    }
}
