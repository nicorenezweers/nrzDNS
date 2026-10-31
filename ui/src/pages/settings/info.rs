//! Info: Version, Adressen für DNS und DNS über HTTPS, Quelltext.

use crate::api;
use crate::components::common::*;
use crate::i18n::{tr, trf};
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::ServerStatus;

const REPO: &str = "https://github.com/nicorenezweers/nrzDNS";

#[component]
pub fn Info() -> Element {
    let server = use_resource(|| api::get::<ServerStatus>("/server"));
    match &*server.read() {
        None => rsx! { Loading {} },
        Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
        Some(Ok(s)) => {
            let doh = format!(
                "{}{}",
                util::origin(),
                if s.doh_path.is_empty() {
                    "/dns-query"
                } else {
                    s.doh_path.as_str()
                }
            );
            rsx! {
                Section { title: "nrzDNS", description: tr("Eigener DNS-Server mit Zonen, Sperrlisten, Cache und DNS über HTTPS – in Rust."),
                    dl { class: "grid max-w-2xl grid-cols-[6.5rem_minmax(0,1fr)] gap-x-4 gap-y-3 text-sm sm:grid-cols-[10rem_minmax(0,1fr)]",
                        dt { class: "text-muted-foreground", {tr("Version")} }
                        dd { class: "font-medium", "{s.version}" }
                        dt { class: "text-muted-foreground", {tr("Läuft seit")} }
                        dd { {trf("{0} (seit {1})", &[&util::uptime(s.uptime_secs), &util::datetime(s.started_at)])} }
                        dt { class: "text-muted-foreground", {tr("Quelltext")} }
                        dd {
                            a { class: "inline-flex max-w-full items-center gap-1.5 underline-offset-4 hover:underline", href: REPO, target: "_blank", rel: "noopener noreferrer",
                                span { class: "truncate", "github.com/nicorenezweers/nrzDNS" }
                                icons::ExternalLink { class: "size-3.5 text-muted-foreground" }
                            }
                        }
                    }
                }
                Section { title: tr("Geräte einrichten"), description: tr("Trage diese Adressen als DNS-Server ein – im Router (für alle Geräte) oder direkt am Gerät."),
                    div { class: "grid grid-cols-1 max-w-2xl gap-5 text-sm",
                        div { class: "grid grid-cols-1 gap-1.5",
                            p { class: "font-medium", {tr("Klassisches DNS (Port 53)")} }
                            if s.dns_listen.is_empty() {
                                p { class: "text-muted-foreground", {tr("Keine Adresse offen.")} }
                            }
                            for a in s.dns_listen.iter() {
                                p { key: "{a}", class: "font-mono text-xs", "{a}" }
                            }
                            for e in s.listen_errors.iter() {
                                p { key: "{e}", class: "font-mono text-xs text-destructive", "{e}" }
                            }
                            p { class: "text-xs text-muted-foreground", {tr("0.0.0.0 bzw. [::] heisst: auf allen Netzwerkadressen dieses Rechners.")} }
                        }
                        div { class: "grid grid-cols-1 gap-1.5",
                            p { class: "font-medium", {tr("DNS über HTTPS (DoH)")} }
                            if s.doh_enabled {
                                div { class: "flex items-center gap-1 rounded-md border bg-background/40 pl-2.5",
                                    code { class: "min-w-0 flex-1 truncate font-mono text-xs", "{doh}" }
                                    CopyButton { text: doh.clone(), title: tr("Adresse kopieren") }
                                }
                                p { class: "text-xs text-muted-foreground", {tr("Für Browser (sicheres DNS) und Geräte, die DoH-Vorlagen erlauben. Braucht HTTPS mit gültigem Zertifikat, z. B. über einen Reverse Proxy.")} }
                            } else {
                                p { class: "text-muted-foreground", {tr("Ausgeschaltet (Einstellungen → Allgemein).")} }
                            }
                        }
                    }
                }
            }
        }
    }
}
