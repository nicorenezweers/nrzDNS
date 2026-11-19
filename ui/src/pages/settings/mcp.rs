//! MCP-Server für nrzDashboard, Claude & Co. einrichten (nur Administratoren): beliebig viele
//! benannte Tokens, jedes mit eigenem Recht (nur lesen / ändern), umbenennen und löschen.

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{McpSettingsInput, McpStatus, McpToken, McpTokenInfo, McpTokenInput};

#[component]
pub fn Mcp() -> Element {
    let mut status = use_signal(|| None::<McpStatus>);
    // Frisch erzeugtes Token – nur bis zum Verlassen der Seite sichtbar
    let mut fresh = use_signal(|| None::<(String, String)>);
    let mut busy = use_signal(|| false);
    let mut name = use_signal(String::new);
    let mut allow = use_signal(|| false);
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
            busy.set(true);
            let input = McpTokenInput {
                name: name().trim().to_string(),
                allow_changes: allow(),
            };
            let res = api::post::<McpToken, _>("/settings/mcp/tokens", &input).await;
            busy.set(false);
            match res {
                Ok(t) => {
                    fresh.set(Some((t.info.name.clone(), t.token)));
                    status.set(Some(t.status));
                    name.set(String::new());
                    allow.set(false);
                    toast(tr("Token erzeugt."));
                }
                Err(e) => toast_error(e),
            }
        });
    };

    let config = fresh().map(|(_, token)| {
        format!(
            "{{\n  \"mcpServers\": {{\n    \"nrznetwork\": {{\n      \"type\": \"http\",\n      \"url\": \"{url}\",\n      \"headers\": {{ \"Authorization\": \"Bearer {token}\" }}\n    }}\n  }}\n}}"
        )
    });
    let cli = fresh().map(|(_, token)| {
        format!("claude mcp add --transport http nrznetwork {url} --header \"Authorization: Bearer {token}\"")
    });

    rsx! {
        Section {
            title: tr("MCP-Server"),
            description: tr("Model Context Protocol für nrzDashboard, Claude und andere Clients: Kennzahlen, Statistiken, Abfrageprotokoll, DNS, Reverse Proxy, Docker, Netzwerkkarte und die ganze API – und, wenn das Token es darf, Änderungen."),
            div { class: "grid gap-4",
                div { class: "grid gap-1.5",
                    p { class: "text-sm font-medium", {tr("Adresse")} }
                    div { class: "flex items-center gap-2",
                        code { class: "min-w-0 flex-1 truncate rounded-md border bg-muted/50 px-3 py-2 font-mono text-[13px]", "{url}" }
                        CopyButton { text: url.clone() }
                    }
                    p { class: "text-xs text-muted-foreground", {tr("Streamable HTTP (JSON-RPC). Token als Authorization: Bearer <Token>, X-API-Key: <Token> oder – wenn der Client keine Kopfzeilen kann – als ?token=<Token> an der Adresse.")} }
                }
                if let Some((tname, token)) = fresh() {
                    Callout { text: trf("Token „{0}“ – wird nur jetzt angezeigt, gleich in den Client kopieren.", &[&tname]),
                        div { class: "grid gap-2",
                            div { class: "flex items-center gap-2",
                                code { class: "min-w-0 flex-1 break-all rounded-md border bg-background px-3 py-2 font-mono text-[13px]", "{token}" }
                                CopyButton { text: token.clone() }
                            }
                            p { class: "text-xs text-muted-foreground", {tr("Claude Code:")} }
                            div { class: "flex items-start gap-2",
                                code { class: "min-w-0 flex-1 break-all rounded-md border bg-background px-3 py-2 font-mono text-[12px]", {cli.clone().unwrap_or_default()} }
                                CopyButton { text: cli.clone().unwrap_or_default() }
                            }
                            p { class: "text-xs text-muted-foreground", {tr("Konfiguration (Claude Desktop, Cursor, nrzDashboard …):")} }
                            div { class: "flex items-start gap-2",
                                pre { class: "min-w-0 flex-1 overflow-x-auto rounded-md border bg-background px-3 py-2 font-mono text-[12px]", {config.clone().unwrap_or_default()} }
                                CopyButton { text: config.clone().unwrap_or_default() }
                            }
                        }
                    }
                }
            }
        }
        Section {
            title: tr("Tokens"),
            description: tr("Jeder Client bekommt sein eigenes Token – so lässt sich eins löschen, ohne die anderen neu einzurichten."),
            div { class: "grid gap-3",
                if s.tokens.is_empty() {
                    p { class: "text-sm text-muted-foreground", {tr("Kein Token – MCP ist aus.")} }
                }
                for t in s.tokens.clone() {
                    TokenRow { key: "{t.id}", token: t, status, busy }
                }
                div { class: "grid gap-3 rounded-md border border-dashed p-3",
                    p { class: "text-sm font-medium", {tr("Neues Token")} }
                    input { class: INPUT, maxlength: 60, placeholder: tr("Name, z. B. Claude Code oder nrzDashboard"), value: "{name}", oninput: move |e| name.set(e.value()) }
                    Toggle {
                        checked: allow(),
                        disabled: busy(),
                        label: tr("Darf ändern"),
                        hint: tr("Filter schalten und pausieren, Sperrlisten, eigene Regeln, Cache leeren, API mit POST/PUT/DELETE. Aus = nur lesen."),
                        onchange: move |on: bool| allow.set(on),
                    }
                    div {
                        button { class: btn(BTN_PRIMARY), disabled: busy(), onclick: create,
                            icons::KeyRound { class: "size-4" }
                            {tr("Token erzeugen")}
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn TokenRow(token: McpTokenInfo, status: Signal<Option<McpStatus>>, busy: Signal<bool>) -> Element {
    let mut status = status;
    let mut busy = busy;
    let t = token.clone();
    let id = t.id;
    let from_env = t.from_env;
    let mut edit_name = use_signal(|| t.name.clone());

    let save = move |allow_changes: bool| {
        spawn(async move {
            busy.set(true);
            let res = if from_env {
                api::put::<McpStatus, _>("/settings/mcp", &McpSettingsInput { allow_changes }).await
            } else {
                let input = McpTokenInput {
                    name: edit_name().trim().to_string(),
                    allow_changes,
                };
                api::put::<McpStatus, _>(&format!("/settings/mcp/tokens/{id}"), &input).await
            };
            busy.set(false);
            match res {
                Ok(s) => {
                    status.set(Some(s));
                    toast(tr("Einstellungen gespeichert."));
                }
                Err(e) => toast_error(e),
            }
        });
    };
    let allow_now = t.allow_changes;
    let name_changed = edit_name().trim() != t.name && !edit_name().trim().is_empty();
    let revoke = move |_| {
        spawn(async move {
            let ask = Ask::new(
                tr("Token löschen?"),
                tr("Clients mit diesem Token können sich danach nicht mehr verbinden."),
            )
            .confirm(tr("Löschen"))
            .destructive();
            if !confirm(ask).await {
                return;
            }
            match api::delete_json::<McpStatus>(&format!("/settings/mcp/tokens/{id}")).await {
                Ok(s) => {
                    status.set(Some(s));
                    toast(tr("Token gelöscht."));
                }
                Err(e) => toast_error(e),
            }
        });
    };

    rsx! {
        div { class: "grid gap-2 rounded-md border p-3",
            div { class: "flex flex-wrap items-center gap-2",
                if from_env {
                    p { class: "text-sm font-medium", "NRZDNS_MCP_TOKEN" }
                } else {
                    input { class: "{INPUT} h-8 max-w-64", maxlength: 60, value: "{edit_name}", oninput: move |e| edit_name.set(e.value()) }
                    if name_changed {
                        button { class: btn_sm(BTN_OUTLINE), disabled: busy(), onclick: move |_| save(allow_now), {tr("Speichern")} }
                    }
                }
                code { class: "font-mono text-[12px] text-muted-foreground", "{t.hint}" }
                div { class: "flex-1" }
                if !from_env {
                    button { class: ICON_BTN, title: tr("Löschen"), disabled: busy(), onclick: revoke, icons::Trash2 {} }
                }
            }
            p { class: "text-xs text-muted-foreground",
                if let Some(c) = t.created_at {
                    {trf("erzeugt {0}", &[&util::datetime(c)])}
                    " · "
                }
                match t.last_used_at {
                    Some(u) => trf("zuletzt benutzt {0}", &[&util::relative(u)]),
                    None => tr("noch nicht benutzt"),
                }
            }
            Toggle {
                checked: t.allow_changes,
                disabled: busy(),
                label: tr("Darf ändern"),
                onchange: move |on: bool| save(on),
            }
        }
    }
}
