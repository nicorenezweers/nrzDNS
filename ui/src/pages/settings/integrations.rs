//! Verbindungen: Cloudflare (Domains und HTTPS-Zertifikate) und NetBird (das ganze Netz).
//! Die Tokens bleiben auf dem Server und werden nie wieder angezeigt.

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::tr;
use crate::json::Dot;
use crate::state;
use dioxus::prelude::*;
use nrzdns_types::{IntegrationStatus, IntegrationsInput, IntegrationsStatus};

#[component]
pub fn Integrations() -> Element {
    let version = use_signal(|| 0u64);
    let status = use_resource(move || async move {
        let _ = version();
        api::get::<IntegrationsStatus>("/integrations?test=true").await
    });
    rsx! {
        match &*status.read() {
            None => rsx! { Loading {} },
            Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
            Some(Ok(s)) => rsx! { Form { key: "{version}", status: s.clone(), version } },
        }
    }
}

#[component]
fn State(st: IntegrationStatus) -> Element {
    rsx! {
        if st.configured {
            div { class: "flex items-start gap-2 text-sm",
                span { class: "mt-1.5", Dot { on: st.ok } }
                span { class: if st.ok { "" } else { "text-destructive" }, "{st.detail}" }
            }
        } else {
            p { class: "text-sm text-muted-foreground", {tr("Nicht verbunden.")} }
        }
    }
}

#[component]
fn Form(status: IntegrationsStatus, version: Signal<u64>) -> Element {
    let admin = state::is_admin();
    let mut cf = use_signal(String::new);
    let mut nb = use_signal(String::new);
    let mut nb_url = use_signal(|| status.netbird_url.clone());
    let mut busy = use_signal(|| false);
    let send = move |input: IntegrationsInput| {
        spawn(async move {
            busy.set(true);
            let res = api::put::<IntegrationsStatus, _>("/integrations", &input).await;
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
    let save = move |e: FormEvent| {
        e.prevent_default();
        send(IntegrationsInput {
            cloudflare_token: cf().trim().to_string(),
            netbird_url: nb_url().trim().to_string(),
            netbird_token: nb().trim().to_string(),
            ..IntegrationsInput::default()
        });
    };
    let keep = |set: bool| {
        if set {
            tr("gespeichert – leer lassen, um es zu behalten")
        } else {
            tr("Token einfügen")
        }
    };
    rsx! {
        form { class: "grid grid-cols-1 gap-6", onsubmit: save,
            Section { title: tr("Cloudflare"), description: tr("Für die Seite Domains (alle DNS-Einträge deiner Domains) und die HTTPS-Zertifikate."),
                div { class: "grid grid-cols-1 gap-4",
                    State { st: status.cloudflare.clone() }
                    Field { label: tr("API-Token"), hint: tr("Cloudflare → Profil → API-Tokens → Token erstellen → Vorlage „Zone-DNS bearbeiten“ → Zonenressourcen: alle Zonen (oder deine Domain). Rechte: Zone → DNS → Bearbeiten, Zone → Zone → Lesen."),
                        input { class: "{INPUT} font-mono text-[13px]", disabled: !admin, r#type: "password", autocomplete: "off", spellcheck: false,
                            placeholder: keep(status.cloudflare.configured), value: "{cf}", oninput: move |e| cf.set(e.value()) }
                    }
                    if admin && status.cloudflare.configured {
                        div { button { class: btn_sm(BTN_GHOST), r#type: "button",
                            onclick: move |_| send(IntegrationsInput { clear_cloudflare: true, netbird_url: nb_url(), ..IntegrationsInput::default() }),
                            {tr("Verbindung trennen")}
                        } }
                    }
                }
            }
            Section { title: tr("NetBird"), description: tr("Für die Seite NetBird (Geräte, Gruppen, Zugriff, Netzwerke, DNS, Setup-Keys, Benutzer) und die Namen auf der Geräte-Seite."),
                div { class: "grid grid-cols-1 gap-4",
                    State { st: status.netbird.clone() }
                    Field { label: tr("Persönliches Zugangstoken"), hint: tr("NetBird → Einstellungen → Persönliche Zugangstoken → Token erstellen (als Owner oder Admin). Läuft nach der gewählten Zeit ab – dann hier ein neues eintragen."),
                        input { class: "{INPUT} font-mono text-[13px]", disabled: !admin, r#type: "password", autocomplete: "off", spellcheck: false,
                            placeholder: keep(status.netbird.configured), value: "{nb}", oninput: move |e| nb.set(e.value()) }
                    }
                    Field { label: tr("Verwaltung (nur selbst gehostet)"), hint: tr("Leer = NetBird Cloud (https://api.netbird.io)."),
                        input { class: "{INPUT} font-mono text-[13px]", disabled: !admin, spellcheck: false, autocapitalize: "none",
                            placeholder: "https://api.netbird.io", value: "{nb_url}", oninput: move |e| nb_url.set(e.value()) }
                    }
                    if admin && status.netbird.configured {
                        div { button { class: btn_sm(BTN_GHOST), r#type: "button",
                            onclick: move |_| send(IntegrationsInput { clear_netbird: true, netbird_url: nb_url(), ..IntegrationsInput::default() }),
                            {tr("Verbindung trennen")}
                        } }
                    }
                }
            }
            if admin {
                div { class: "flex justify-end gap-2",
                    button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy(),
                        if busy() { icons::LoaderCircle { class: "size-4 animate-spin" } } else { icons::Plug {} }
                        {tr("Speichern und prüfen")}
                    }
                }
            }
        }
    }
}
