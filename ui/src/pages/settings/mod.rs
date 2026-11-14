//! Einstellungen: der DNS-Server (Allgemein, Weiterleitung, Cache, Sperren, Protokoll), das
//! eigene Konto, – für Administratoren – die Benutzer und der MCP-Server – und die Info zu
//! dieser Instanz.

mod account;
mod admin;
mod dns;
mod info;
mod integrations;
mod mcp;

use crate::Route;
use crate::components::common::*;
use crate::i18n::tr;
use crate::state;
use dioxus::prelude::*;

struct Item {
    key: &'static str,
    label: &'static str,
    group: &'static str,
    admin_only: bool,
}

const ITEMS: &[Item] = &[
    Item {
        key: "general",
        label: "Allgemein",
        group: "DNS-Server",
        admin_only: false,
    },
    Item {
        key: "forwarding",
        label: "Weiterleitung",
        group: "DNS-Server",
        admin_only: false,
    },
    Item {
        key: "cache",
        label: "Cache",
        group: "DNS-Server",
        admin_only: false,
    },
    Item {
        key: "blocking",
        label: "Sperren",
        group: "DNS-Server",
        admin_only: false,
    },
    Item {
        key: "logging",
        label: "Abfrageprotokoll",
        group: "DNS-Server",
        admin_only: false,
    },
    Item {
        key: "account",
        label: "Konto",
        group: "Persönlich",
        admin_only: false,
    },
    Item {
        key: "users",
        label: "Benutzer",
        group: "Instanz",
        admin_only: true,
    },
    Item {
        key: "integrations",
        label: "Verbindungen",
        group: "Instanz",
        admin_only: false,
    },
    Item {
        key: "mcp",
        label: "MCP",
        group: "Instanz",
        admin_only: true,
    },
    Item {
        key: "info",
        label: "Info",
        group: "Instanz",
        admin_only: false,
    },
];

/// Übersetzte Namen der Bereiche und Gruppen (die Konstanten oben sind die Schlüssel).
fn label(key: &str) -> String {
    match key {
        "Allgemein" => tr("Allgemein"),
        "Weiterleitung" => tr("Weiterleitung"),
        "Cache" => tr("Cache"),
        "Sperren" => tr("Sperren"),
        "Abfrageprotokoll" => tr("Abfrageprotokoll"),
        "Konto" => tr("Konto"),
        "Benutzer" => tr("Benutzer"),
        "Info" => tr("Info"),
        "DNS-Server" => tr("DNS-Server"),
        "Persönlich" => tr("Persönlich"),
        "Instanz" => tr("Instanz"),
        other => tr(other),
    }
}

fn icon(key: &str) -> Element {
    match key {
        "general" => rsx! { icons::SlidersHorizontal {} },
        "forwarding" => rsx! { icons::Send {} },
        "cache" => rsx! { icons::Database {} },
        "blocking" => rsx! { icons::ShieldBan {} },
        "logging" => rsx! { icons::ScrollText {} },
        "account" => rsx! { icons::User {} },
        "users" => rsx! { icons::Users {} },
        "mcp" => rsx! { icons::Plug {} },
        "integrations" => rsx! { icons::Cable {} },
        _ => rsx! { icons::Info {} },
    }
}

#[component]
pub fn Settings(section: String) -> Element {
    let admin = state::is_admin();
    let visible: Vec<&Item> = ITEMS.iter().filter(|i| !i.admin_only || admin).collect();
    let mut groups: Vec<&str> = Vec::new();
    for i in &visible {
        if !groups.contains(&i.group) {
            groups.push(i.group);
        }
    }
    let title = visible
        .iter()
        .find(|i| i.key == section)
        .map(|i| label(i.label))
        .unwrap_or_else(|| tr("Einstellungen"));
    rsx! {
        PageHeader { title: tr("Einstellungen"), description: title }
        div { class: "grid grid-cols-1 gap-6 lg:grid-cols-[12rem_minmax(0,1fr)]",
            nav { class: "-mx-1 flex gap-1 overflow-x-auto px-1 pb-1 lg:mx-0 lg:flex-col lg:overflow-visible lg:px-0",
                for g in groups.iter().copied() {
                    p { class: "hidden px-2.5 pt-3 pb-1 text-xs font-medium uppercase tracking-wider text-muted-foreground first:pt-0 lg:block", {label(g)} }
                    for i in visible.iter().filter(|i| i.group == g) {
                        Link {
                            key: "{i.key}",
                            to: Route::Settings { section: i.key.to_string() },
                            class: if i.key == section { "flex shrink-0 items-center gap-2.5 rounded-md bg-accent px-2.5 py-1.5 text-sm font-medium [&_svg]:size-4" } else { "flex shrink-0 items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm text-muted-foreground hover:bg-accent/50 hover:text-foreground [&_svg]:size-4" },
                            {icon(i.key)}
                            {label(i.label)}
                        }
                    }
                }
            }
            div { class: "min-w-0 space-y-6",
                match section.as_str() {
                    "general" | "forwarding" | "cache" | "blocking" | "logging" => rsx! { dns::Dns { section: section.clone() } },
                    "account" => rsx! { account::Account {} },
                    "users" if admin => rsx! { admin::Users {} },
                    "mcp" if admin => rsx! { mcp::Mcp {} },
                    "info" => rsx! { info::Info {} },
                    "integrations" => rsx! { integrations::Integrations {} },
                    _ => rsx! { Callout { text: tr("Diesen Bereich gibt es nicht oder er ist nur für Administratoren.") } },
                }
            }
        }
    }
}
