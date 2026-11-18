//! MCP-Server für nrzDashboard & Co. einrichten (nur Administratoren): Token erzeugen,
//! ersetzen, löschen und Änderungen über MCP erlauben.

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{McpSettingsInput, McpStatus, McpToken};

#[component]
pub fn Mcp() -> Element {
    let mut status = use_signal(|| None::<McpStatus>);
    // Frisch erzeugtes Token – nur bis zum Verlassen der Seite sichtbar
    let mut fresh = use_signal(|| None::<String>);
    let mut busy = use_signal(|| false);
    use_future(move || async move {
        match api::get::<McpStatus>("/settings/mcp").await {
            Ok(s) => status.set(Some(s)),
            Err(e) => toast_error(e),
        }
    });
    let Some(s) = status() else {
        return rsx! { Loading {} };
    };
    let url = format!("{}{}", util::origin(), s.path);

    let create = move |_| {
        spawn(async move {
            if status().is_some_and(|s| s.enabled) {
                let ask = Ask::new(tr("Neues Token erzeugen?"), tr("Das bisherige Token gilt danach nicht mehr; verbundene Clients brauchen das neue.")).confirm(tr("Neues Token"));
                if !confirm(ask).await {
                    return;
                }
            }
            busy.set(true);
            let res = api::action::<McpToken>("/settings/mcp/token").await;
            busy.set(false);
            match res {
                Ok(t) => {
                    fresh.set(Some(t.token));
                    status.set(Some(t.status));
                    toast(tr("Token erzeugt."));
                }
                Err(e) => toast_error(e),
            }
        });
    };
    let revoke = move |_| {
        spawn(async move {
            let ask = Ask::new(
                tr("MCP ausschalten?"),
                tr("Das Token wird gelöscht; kein Client kann sich danach noch verbinden."),
            )
            .confirm(tr("Ausschalten"))
            .destructive();
            if !confirm(ask).await {
                return;
            }
            match api::delete_json::<McpStatus>("/settings/mcp/token").await {
                Ok(s) => {
                    fresh.set(None);
                    status.set(Some(s));
                    toast(tr("MCP ausgeschaltet."));
                }
                Err(e) => toast_error(e),
            }
        });
    };

    rsx! {
        Section {
            title: tr("MCP-Server"),
            description: tr("Model Context Protocol für nrzDashboard und andere Clients: Kennzahlen für die Übersicht, Statistiken, Abfrageprotokoll und – wenn erlaubt – Filter schalten."),
            actions: rsx! {
                if !s.from_env {
                    if s.enabled {
                        button { class: btn(BTN_OUTLINE), disabled: busy(), onclick: revoke, {tr("Ausschalten")} }
                    }
                    button { class: btn(BTN_PRIMARY), disabled: busy(), onclick: create,
                        icons::KeyRound { class: "size-4" }
                        if s.enabled { {tr("Neues Token")} } else { {tr("Token erzeugen")} }
                    }
                }
            },
            div { class: "grid gap-4",
                div { class: "grid gap-1.5",
                    p { class: "text-sm font-medium", {tr("Adresse")} }
                    div { class: "flex items-center gap-2",
                        code { class: "min-w-0 flex-1 truncate rounded-md border bg-muted/50 px-3 py-2 font-mono text-[13px]", "{url}" }
                        CopyButton { text: url.clone() }
                    }
                    p { class: "text-xs text-muted-foreground", {tr("POST mit Authorization: Bearer <Token> (Streamable HTTP, JSON-RPC).")} }
                }
                if let Some(token) = fresh() {
                    Callout { text: tr("Das Token wird nur jetzt angezeigt – kopiere es in den Client (z. B. nrzDashboard)."),
                        div { class: "flex items-center gap-2",
                            code { class: "min-w-0 flex-1 break-all rounded-md border bg-background px-3 py-2 font-mono text-[13px]", "{token}" }
                            CopyButton { text: token.clone() }
                        }
                    }
                }
                div { class: "grid gap-1.5",
                    p { class: "text-sm font-medium", {tr("Token")} }
                    if s.enabled {
                        p { class: "text-sm",
                            code { class: "font-mono text-[13px]", {s.token_hint.clone().unwrap_or_default()} }
                            if s.from_env {
                                span { class: "text-muted-foreground", " · NRZDNS_MCP_TOKEN" }
                            } else if let Some(t) = s.created_at {
                                span { class: "text-muted-foreground", " · " {trf("erzeugt {0}", &[&util::datetime(t)])} }
                            }
                        }
                        p { class: "text-xs text-muted-foreground",
                            match s.last_used_at {
                                Some(t) => trf("zuletzt benutzt {0}", &[&util::relative(t)]),
                                None => tr("seit dem Start noch nicht benutzt"),
                            }
                        }
                    } else {
                        p { class: "text-sm text-muted-foreground", {tr("Kein Token – MCP ist aus.")} }
                    }
                }
                Toggle {
                    checked: s.allow_changes,
                    disabled: busy(),
                    label: tr("Änderungen über MCP erlauben"),
                    hint: tr("Filter ein-/ausschalten und pausieren, Sperrlisten umschalten, eigene Regeln, Cache leeren. Aus = nur lesen."),
                    onchange: move |on: bool| {
                        spawn(async move {
                            busy.set(true);
                            let res = api::put::<McpStatus, _>("/settings/mcp", &McpSettingsInput { allow_changes: on }).await;
                            busy.set(false);
                            match res {
                                Ok(s) => {
                                    status.set(Some(s));
                                    toast(tr("Einstellungen gespeichert."));
                                }
                                Err(e) => toast_error(e),
                            }
                        });
                    },
                }
            }
        }
    }
}
