//! Liste vorgelagerter DNS-Server bearbeiten (Einstellungen → Weiterleitung und Zonen mit
//! bedingter Weiterleitung): Protokoll, Adresse, TLS-Name, Anzeigename, Reihenfolge, Vorlagen.

use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::tr;
use crate::labels;
use dioxus::prelude::*;
use nrzdns_types::{Upstream, UpstreamProtocol};

/// Kontrollierte Liste: jede Änderung geht als ganze neue Liste an `onchange`.
#[component]
pub fn UpstreamEditor(
    value: Vec<Upstream>,
    onchange: EventHandler<Vec<Upstream>>,
    #[props(default)] disabled: bool,
    #[props(default = true)] presets: bool,
) -> Element {
    let list = use_resource(move || async move {
        if presets {
            crate::state::presets().await.upstreams
        } else {
            Vec::new()
        }
    });
    let count = value.len();
    let edit = {
        let value = value.clone();
        move |i: usize, f: Box<dyn FnOnce(&mut Upstream)>| {
            let mut v = value.clone();
            if let Some(u) = v.get_mut(i) {
                f(u);
            }
            onchange.call(v);
        }
    };
    rsx! {
        div { class: "grid grid-cols-1 gap-2",
            if value.is_empty() {
                div { class: "rounded-lg border border-dashed px-3 py-4 text-center text-sm text-muted-foreground",
                    {tr("Noch kein Server eingetragen.")}
                }
            }
            for (i , u) in value.iter().cloned().enumerate() {
                div { key: "{i}", class: "grid grid-cols-1 gap-2 rounded-lg border bg-background/40 p-2.5 sm:grid-cols-[8.5rem_minmax(0,1fr)_minmax(0,11rem)_auto] sm:items-center",
                    select {
                        class: SELECT,
                        disabled,
                        "aria-label": tr("Protokoll"),
                        onchange: {
                            let edit = edit.clone();
                            move |e: FormEvent| {
                                let p = labels::parse_upstream_protocol(&e.value());
                                edit(i, Box::new(move |u: &mut Upstream| u.protocol = p));
                            }
                        },
                        for p in labels::UPSTREAM_PROTOCOLS {
                            option { value: labels::upstream_protocol_key(p), selected: u.protocol == p, {labels::upstream_protocol(p)} }
                        }
                    }
                    input {
                        class: "{INPUT} font-mono text-[13px]",
                        disabled,
                        required: true,
                        spellcheck: false,
                        autocapitalize: "none",
                        "aria-label": tr("Adresse"),
                        placeholder: labels::upstream_placeholder(u.protocol),
                        value: "{u.address}",
                        oninput: {
                            let edit = edit.clone();
                            move |e: FormEvent| {
                                let v = e.value();
                                edit(i, Box::new(move |u: &mut Upstream| u.address = v.trim().to_string()));
                            }
                        },
                    }
                    input {
                        class: INPUT,
                        disabled,
                        "aria-label": tr("Anzeigename"),
                        placeholder: tr("Name (optional)"),
                        value: "{u.name}",
                        oninput: {
                            let edit = edit.clone();
                            move |e: FormEvent| {
                                let v = e.value();
                                edit(i, Box::new(move |u: &mut Upstream| u.name = v));
                            }
                        },
                    }
                    if !disabled {
                        div { class: "flex items-center justify-end gap-0.5",
                            button {
                                class: ICON_BTN,
                                r#type: "button",
                                title: tr("Nach oben"),
                                disabled: i == 0,
                                onclick: {
                                    let value = value.clone();
                                    move |_| {
                                        let mut v = value.clone();
                                        v.swap(i, i - 1);
                                        onchange.call(v);
                                    }
                                },
                                icons::ChevronUp {}
                            }
                            button {
                                class: ICON_BTN,
                                r#type: "button",
                                title: tr("Nach unten"),
                                disabled: i + 1 >= count,
                                onclick: {
                                    let value = value.clone();
                                    move |_| {
                                        let mut v = value.clone();
                                        v.swap(i, i + 1);
                                        onchange.call(v);
                                    }
                                },
                                icons::ChevronDown {}
                            }
                            button {
                                class: icon_btn("hover:text-destructive"),
                                r#type: "button",
                                title: tr("Entfernen"),
                                onclick: {
                                    let value = value.clone();
                                    move |_| {
                                        let mut v = value.clone();
                                        v.remove(i);
                                        onchange.call(v);
                                    }
                                },
                                icons::X {}
                            }
                        }
                    }
                    if u.protocol == UpstreamProtocol::Tls {
                        input {
                            class: "{INPUT} font-mono text-[13px] sm:col-span-2 sm:col-start-2",
                            disabled,
                            spellcheck: false,
                            autocapitalize: "none",
                            "aria-label": tr("Name im TLS-Zertifikat"),
                            placeholder: tr("Name im TLS-Zertifikat, z. B. cloudflare-dns.com (leer = aus der Adresse)"),
                            value: "{u.tls_name}",
                            oninput: {
                                let edit = edit.clone();
                                move |e: FormEvent| {
                                    let v = e.value();
                                    edit(i, Box::new(move |u: &mut Upstream| u.tls_name = v.trim().to_string()));
                                }
                            },
                        }
                    }
                }
            }
            if !disabled {
                div { class: "flex flex-wrap items-center gap-2 pt-1",
                    button {
                        class: btn_sm(BTN_OUTLINE),
                        r#type: "button",
                        onclick: {
                            let value = value.clone();
                            move |_| {
                                let mut v = value.clone();
                                v.push(Upstream::default());
                                onchange.call(v);
                            }
                        },
                        icons::Plus {}
                        {tr("Server hinzufügen")}
                    }
                    if let Some(items) = list.read().as_ref().filter(|l| !l.is_empty()) {
                        Dropdown {
                            class: "w-72",
                            trigger_class: btn_sm(BTN_GHOST),
                            trigger: rsx! {
                                icons::ListPlus {}
                                {tr("Vorlage übernehmen")}
                                icons::ChevronDown { class: "size-3.5 text-muted-foreground" }
                            },
                            MenuLabel { {tr("Ersetzt die Liste oben")} }
                            for p in items.iter().cloned() {
                                MenuItem {
                                    key: "{p.id}",
                                    onclick: {
                                        let ups = p.upstreams.clone();
                                        move |_| onchange.call(ups.clone())
                                    },
                                    span { class: "grid grid-cols-1 min-w-0 gap-0.5",
                                        span { class: "truncate", "{p.name}" }
                                        span { class: "truncate text-xs text-muted-foreground", {tr(&p.description)} }
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
