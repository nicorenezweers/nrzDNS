//! Dieter: KI-Assistent als Chat-Fenster unten rechts (auf jeder Seite) und seine
//! Einrichtung unter Einstellungen → Dieter.

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::json::Dot;
use crate::state;
use crate::util;
use crate::Route;
use dioxus::prelude::*;
use nrzdns_types::{
    DieterProvider, DieterSendInput, DieterSettings, DieterSettingsInput, DieterStatus,
    DieterThread,
};

/// Name der aktuellen Seite (geht als Kontext an Dieter).
fn page_name(route: &Route) -> String {
    match route {
        Route::Proxy {} => tr("Reverse Proxy"),
        Route::Domains {} => tr("DNS-Einträge"),
        Route::Netbird {} => tr("NetBird"),
        Route::Spy {} => tr("Spy"),
        Route::Monitor {} => tr("Zugriffe"),
        Route::Docker {} => tr("Docker"),
        Route::Devices {} => tr("Geräte"),
        Route::Settings { section } => format!("{} → {section}", tr("Einstellungen")),
        _ => String::new(),
    }
}

/// Vorschläge passend zur Seite.
fn suggestions(route: &Route) -> Vec<String> {
    match route {
        Route::Proxy {} => vec![tr("Prüfe alle Einträge – welche Ziele antworten nicht?"), tr("Welche Einträge sind öffentlich erreichbar?")],
        Route::Domains {} => vec![tr("Welche DNS-Einträge zeigen ins Leere?"), tr("Fehlen SPF, DMARC oder CAA?")],
        Route::Netbird {} => vec![tr("Welche NetBird-Geräte sind offline?"), tr("Warum antwortet ein NetBird-Dienst nicht?")],
        Route::Spy {} => vec![tr("Erkläre mir den letzten Spy-Bericht."), tr("Behebe die wichtigsten Punkte aus dem Spy-Bericht.")],
        Route::Monitor {} => vec![tr("Wer hat heute am meisten zugegriffen?"), tr("Gibt es auffällige Zugriffe oder Fehler?")],
        Route::Docker {} => vec![tr("Welche Container laufen nicht?"), tr("Welche Container melden Fehler im Log?")],
        _ => vec![tr("Ist im Netzwerk alles in Ordnung?"), tr("Sind alle meine Webseiten erreichbar?"), tr("Was hat die Überwachung zuletzt gefunden?")],
    }
}

/// Einfache Darstellung von Markdown: Absätze, Listen, Überschriften, **fett**, `code`, Codeblöcke.
fn markdown(text: &str) -> Element {
    let mut blocks: Vec<Element> = Vec::new();
    let mut in_code = false;
    let mut code = String::new();
    let mut para: Vec<String> = Vec::new();
    let flush = |para: &mut Vec<String>, blocks: &mut Vec<Element>| {
        if !para.is_empty() {
            let lines = std::mem::take(para);
            blocks.push(rsx! { p { class: "leading-relaxed", for (i, l) in lines.iter().enumerate() { if i > 0 { br {} } {inline(l)} } } });
        }
    };
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            if in_code {
                let c = std::mem::take(&mut code);
                blocks.push(rsx! { pre { class: "overflow-x-auto rounded-md bg-background/80 p-2 font-mono text-[11px] leading-snug", "{c}" } });
            } else {
                flush(&mut para, &mut blocks);
            }
            in_code = !in_code;
            continue;
        }
        if in_code {
            code.push_str(line);
            code.push('\n');
            continue;
        }
        let t = line.trim();
        if t.is_empty() {
            flush(&mut para, &mut blocks);
        } else if let Some(h) = t.strip_prefix("### ").or(t.strip_prefix("## ")).or(t.strip_prefix("# ")) {
            flush(&mut para, &mut blocks);
            let h = h.to_string();
            blocks.push(rsx! { p { class: "mt-1 font-semibold", {inline(&h)} } });
        } else if let Some(item) = t.strip_prefix("- ").or(t.strip_prefix("* ")).or(t.strip_prefix("• ")) {
            flush(&mut para, &mut blocks);
            let item = item.to_string();
            blocks.push(rsx! { div { class: "flex gap-2 pl-1", span { class: "text-muted-foreground", "•" } span { class: "min-w-0", {inline(&item)} } } });
        } else if t.len() > 2 && t.chars().next().is_some_and(|c| c.is_ascii_digit()) && t.contains(". ") && t.split(". ").next().is_some_and(|n| n.chars().all(|c| c.is_ascii_digit())) {
            flush(&mut para, &mut blocks);
            let (n, rest) = t.split_once(". ").unwrap_or(("", t));
            let (n, rest) = (n.to_string(), rest.to_string());
            blocks.push(rsx! { div { class: "flex gap-2 pl-1", span { class: "text-muted-foreground tabular-nums", "{n}." } span { class: "min-w-0", {inline(&rest)} } } });
        } else {
            para.push(t.to_string());
        }
    }
    if in_code && !code.is_empty() {
        blocks.push(rsx! { pre { class: "overflow-x-auto rounded-md bg-background/80 p-2 font-mono text-[11px]", "{code}" } });
    }
    flush(&mut para, &mut blocks);
    rsx! { div { class: "grid gap-1.5", for b in blocks { {b} } } }
}

/// `**fett**` und `` `code` `` innerhalb einer Zeile.
fn inline(s: &str) -> Element {
    let mut parts: Vec<(u8, String)> = Vec::new();
    let mut rest = s;
    while !rest.is_empty() {
        let b = rest.find("**");
        let c = rest.find('`');
        match (b, c) {
            (Some(bi), ci) if ci.is_none_or(|ci| bi < ci) => {
                if let Some(end) = rest[bi + 2..].find("**") {
                    parts.push((0, rest[..bi].to_string()));
                    parts.push((1, rest[bi + 2..bi + 2 + end].to_string()));
                    rest = &rest[bi + 2 + end + 2..];
                } else {
                    parts.push((0, rest.to_string()));
                    rest = "";
                }
            }
            (_, Some(ci)) => {
                if let Some(end) = rest[ci + 1..].find('`') {
                    parts.push((0, rest[..ci].to_string()));
                    parts.push((2, rest[ci + 1..ci + 1 + end].to_string()));
                    rest = &rest[ci + 1 + end + 1..];
                } else {
                    parts.push((0, rest.to_string()));
                    rest = "";
                }
            }
            _ => {
                parts.push((0, rest.to_string()));
                rest = "";
            }
        }
    }
    rsx! {
        for (i, (k, t)) in parts.into_iter().enumerate() {
            match k {
                1 => rsx! { strong { key: "{i}", "{t}" } },
                2 => rsx! { code { key: "{i}", class: "rounded bg-background/70 px-1 font-mono text-[0.9em]", "{t}" } },
                _ => rsx! { span { key: "{i}", "{t}" } },
            }
        }
    }
}

/// Chat-Fenster unten rechts.
#[component]
pub fn DieterWidget() -> Element {
    let admin = state::is_admin();
    let route = use_route::<Route>();
    let mut open = use_signal(|| false);
    let mut big = use_signal(|| false);
    let mut tick = use_signal(|| 0u64);
    let status = use_resource(move || async move {
        let _ = tick();
        api::get::<DieterStatus>("/dieter").await
    });
    // Abzeichen aktuell halten (alle 20 s, während Dieter arbeitet alle 3 s)
    use_future(move || async move {
        loop {
            let busy = matches!(&*status.peek(), Some(Ok(s)) if s.conversations.iter().any(|c| c.running));
            gloo_timers::future::TimeoutFuture::new(if busy { 3000 } else { 20_000 }).await;
            tick += 1;
        }
    });
    let mut current = use_signal(|| None::<i64>);
    let mut show_list = use_signal(|| false);
    let (ready, problems, working) = match &*status.read() {
        Some(Ok(s)) => (s.ready, s.incidents.iter().filter(|i| i.active).count(), s.conversations.iter().any(|c| c.running)),
        _ => (false, 0, false),
    };
    let size = if big() { "inset-x-3 bottom-20 top-16 sm:inset-x-auto sm:right-6 sm:w-[44rem]" } else { "bottom-20 right-3 h-[34rem] w-[calc(100vw-1.5rem)] sm:right-6 sm:w-[26rem]" };
    rsx! {
        if open() {
            div { class: "fixed z-50 flex flex-col overflow-hidden rounded-2xl border bg-popover shadow-2xl {size}",
                div { class: "flex items-center gap-2 border-b px-3 py-2",
                    div { class: "flex size-8 items-center justify-center rounded-full bg-primary text-primary-foreground", icons::Bot { class: "size-4" } }
                    div { class: "min-w-0 flex-1",
                        p { class: "flex items-center gap-1.5 text-sm font-semibold", "Dieter" Dot { on: ready } }
                        p { class: "truncate text-[11px] text-muted-foreground",
                            match &*status.read() {
                                Some(Ok(s)) => s.ready_detail.clone(),
                                _ => String::new(),
                            }
                        }
                    }
                    button { class: icon_btn(""), title: tr("Gespräche"), onclick: move |_| show_list.toggle(), icons::History {} }
                    button { class: icon_btn(""), title: tr("Neues Gespräch"), onclick: move |_| { current.set(None); show_list.set(false); }, icons::SquarePen {} }
                    button { class: icon_btn(""), title: if big() { tr("Verkleinern") } else { tr("Vergrössern") }, onclick: move |_| big.toggle(),
                        if big() { icons::Minimize2 {} } else { icons::Maximize2 {} }
                    }
                    button { class: icon_btn(""), title: tr("Schliessen"), onclick: move |_| open.set(false), icons::X {} }
                }
                if show_list() {
                    div { class: "max-h-56 overflow-y-auto border-b",
                        match &*status.read() {
                            Some(Ok(s)) if s.conversations.is_empty() => rsx! { p { class: "p-3 text-xs text-muted-foreground", {tr("Noch keine Gespräche.")} } },
                            Some(Ok(s)) => rsx! {
                                for c in s.conversations.iter().cloned() {
                                    button { key: "{c.id}", class: if current() == Some(c.id) { "flex w-full items-center gap-2 bg-accent px-3 py-2 text-left text-xs" } else { "flex w-full items-center gap-2 px-3 py-2 text-left text-xs hover:bg-accent" },
                                        onclick: move |_| { current.set(Some(c.id)); show_list.set(false); },
                                        if c.automatic { icons::Zap { class: "size-3.5 shrink-0 text-amber-500" } } else { icons::MessageSquare { class: "size-3.5 shrink-0 text-muted-foreground" } }
                                        span { class: "min-w-0 flex-1 truncate", "{c.title}" }
                                        if c.running { icons::LoaderCircle { class: "size-3.5 animate-spin" } }
                                        span { class: "shrink-0 text-muted-foreground", "{util::relative(c.updated_at)}" }
                                    }
                                }
                            },
                            _ => rsx! {},
                        }
                    }
                }
                if problems > 0 && current().is_none() {
                    if let Some(Ok(s)) = &*status.read() {
                        div { class: "border-b bg-destructive/5 px-3 py-2 text-xs",
                            p { class: "mb-1 font-medium text-destructive", {trf("{0} aktuelle Probleme", &[&problems.to_string()])} }
                            for i in s.incidents.iter().filter(|i| i.active).take(4).cloned() {
                                div { key: "{i.key}", class: "flex items-center gap-2",
                                    span { class: "min-w-0 flex-1 truncate", title: "{i.text}", "{i.text}" }
                                    if i.conversation_id > 0 {
                                        button { class: "shrink-0 underline-offset-2 hover:underline", onclick: move |_| current.set(Some(i.conversation_id)), {tr("Einsatz")} }
                                    }
                                }
                            }
                        }
                    }
                }
                Chat { key: "{current():?}", id: current(), ready, admin, current, tick, context: page_name(&route), suggestions: suggestions(&route) }
            }
        }
        button {
            class: "fixed bottom-4 right-4 z-50 flex size-13 items-center justify-center rounded-full bg-primary text-primary-foreground shadow-xl transition hover:scale-105 sm:right-6",
            title: tr("Dieter – KI-Assistent"),
            onclick: move |_| open.toggle(),
            if open() { icons::X { class: "size-5" } } else if working { icons::LoaderCircle { class: "size-5 animate-spin" } } else { icons::Bot { class: "size-6" } }
            if problems > 0 && !open() {
                span { class: "absolute -right-0.5 -top-0.5 flex size-5 items-center justify-center rounded-full bg-destructive text-[10px] font-bold text-white", "{problems}" }
            }
        }
    }
}

#[component]
fn Chat(id: Option<i64>, ready: bool, admin: bool, current: Signal<Option<i64>>, tick: Signal<u64>, context: String, suggestions: Vec<String>) -> Element {
    let mut local = use_signal(|| 0u64);
    let thread = use_resource(move || async move {
        let _ = local();
        match id {
            Some(i) => Some(api::get::<DieterThread>(&format!("/dieter/conversations/{i}")).await),
            None => None,
        }
    });
    let mut text = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut show_steps = use_signal(|| false);
    let running = matches!(&*thread.read(), Some(Some(Ok(t))) if t.conversation.running);
    let count = match &*thread.read() {
        Some(Some(Ok(t))) => t.messages.len(),
        _ => 0,
    };
    use_effect(move || {
        let running = matches!(&*thread.read(), Some(Some(Ok(t))) if t.conversation.running);
        if running {
            spawn(async move {
                gloo_timers::future::TimeoutFuture::new(1200).await;
                local += 1;
            });
        }
    });
    // Nach neuen Nachrichten nach unten scrollen
    use_effect(use_reactive!(|count, running| {
        let _ = (count, running);
        document::eval("setTimeout(()=>{const e=document.getElementById('dieter-scroll'); if(e) e.scrollTop=e.scrollHeight;},30)");
    }));
    let ctx = context.clone();
    let send = use_callback(move |msg: String| {
        let body = DieterSendInput { text: msg.trim().to_string(), context: ctx.clone() };
        if body.text.is_empty() || busy() {
            return;
        }
        spawn(async move {
            busy.set(true);
            let res = match id {
                Some(i) => api::post::<DieterThread, _>(&format!("/dieter/conversations/{i}/messages"), &body).await,
                None => api::post::<DieterThread, _>("/dieter/conversations", &body).await,
            };
            busy.set(false);
            match res {
                Ok(t) => {
                    text.set(String::new());
                    if id.is_none() {
                        current.set(Some(t.conversation.id));
                    }
                    tick += 1;
                    local += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    });
    rsx! {
        div { id: "dieter-scroll", class: "flex-1 space-y-3 overflow-y-auto px-3 py-3 text-sm",
            match &*thread.read() {
                Some(Some(Ok(t))) => {
                    let steps = t.messages.iter().filter(|m| m.role == "action").count();
                    rsx! {
                        for m in t.messages.iter().cloned() {
                            match m.role.as_str() {
                                "user" => rsx! { div { key: "{m.id}", class: "ml-auto w-fit max-w-[85%] whitespace-pre-wrap rounded-2xl rounded-br-sm bg-primary px-3 py-2 text-primary-foreground", "{m.text}" } },
                                "action" => if show_steps() {
                                    rsx! { div { key: "{m.id}", class: "flex items-center gap-1.5 pl-1 font-mono text-[11px] text-muted-foreground", icons::Wrench { class: "size-3" } "{m.detail}" } }
                                } else { rsx! {} },
                                "error" => rsx! { div { key: "{m.id}", class: "rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive", "{m.text}" } },
                                _ => rsx! { div { key: "{m.id}", class: "w-fit max-w-[92%] rounded-2xl rounded-bl-sm bg-muted px-3 py-2", {markdown(&m.text)} } },
                            }
                        }
                        if steps > 0 {
                            button { class: "flex items-center gap-1 pl-1 text-[11px] text-muted-foreground hover:underline", onclick: move |_| show_steps.toggle(),
                                icons::Wrench { class: "size-3" }
                                if show_steps() { {tr("Schritte ausblenden")} } else { {trf("{0} Schritte anzeigen", &[&steps.to_string()])} }
                            }
                        }
                        if running {
                            div { class: "flex w-fit items-center gap-2 rounded-2xl bg-muted px-3 py-2 text-muted-foreground",
                                span { class: "flex gap-1",
                                    span { class: "size-1.5 animate-bounce rounded-full bg-current [animation-delay:-0.3s]" }
                                    span { class: "size-1.5 animate-bounce rounded-full bg-current [animation-delay:-0.15s]" }
                                    span { class: "size-1.5 animate-bounce rounded-full bg-current" }
                                }
                                if let Some(last) = t.messages.iter().rev().find(|m| m.role == "action") { span { class: "truncate font-mono text-[11px]", "{last.detail}" } }
                            }
                        }
                    }
                },
                Some(Some(Err(e))) => rsx! { Callout { text: e.message.clone(), error: true } },
                _ => rsx! {
                    div { class: "grid gap-3",
                        div { class: "rounded-2xl rounded-bl-sm bg-muted px-3 py-2",
                            p { {tr("Hallo, ich bin Dieter. Ich kenne dein ganzes Netzwerk – DNS, Reverse Proxy, Cloudflare, NetBird, Tunnel, Docker und Zertifikate – und kann Dinge prüfen und einstellen.")} }
                            if !ready {
                                p { class: "mt-2 text-xs text-muted-foreground", {tr("Zuerst unter Einstellungen → Dieter einen Anbieter einrichten.")} }
                                Link { class: "{btn_sm(BTN_OUTLINE)} mt-2", to: Route::Settings { section: "dieter".into() }, icons::Settings {} {tr("Einrichten")} }
                            }
                        }
                        if ready && admin {
                            div { class: "grid gap-1.5",
                                for (i, s) in suggestions.iter().cloned().enumerate() {
                                    button { key: "{i}", class: "rounded-xl border px-3 py-2 text-left text-xs hover:bg-accent", onclick: move |_| send(s.clone()), "{s}" }
                                }
                            }
                        }
                    }
                },
            }
        }
        if admin {
            div { class: "border-t p-2",
                div { class: "flex items-end gap-2 rounded-xl border bg-background px-2 py-1.5 focus-within:ring-2 focus-within:ring-ring/40",
                    textarea { class: "max-h-32 min-h-9 flex-1 resize-none bg-transparent py-1.5 text-sm outline-none", rows: 1, disabled: !ready || running,
                        placeholder: if ready { tr("Frag Dieter …  (Enter senden, Shift+Enter neue Zeile)") } else { tr("Dieter ist noch nicht eingerichtet") },
                        value: "{text}", oninput: move |e| text.set(e.value()),
                        onkeydown: move |e: KeyboardEvent| {
                            if e.key() == Key::Enter && !e.modifiers().shift() {
                                e.prevent_default();
                                send(text());
                            }
                        },
                    }
                    button { class: "flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground disabled:opacity-40", disabled: !ready || running || busy() || text().trim().is_empty(),
                        onclick: move |_| send(text()), icons::ArrowUp { class: "size-4" } }
                }
            }
        }
    }
}

/// Einstellungen → Dieter
#[component]
pub fn DieterSettingsPage() -> Element {
    let tick = use_signal(|| 0u64);
    let status = use_resource(move || async move {
        let _ = tick();
        api::get::<DieterStatus>("/dieter").await
    });
    rsx! {
        match &*status.read() {
            None => rsx! { Loading {} },
            Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
            Some(Ok(s)) => rsx! {
                div { class: "grid gap-6",
                    SettingsForm { key: "{s.openrouter_key_set}-{s.xai_key_set}-{s.claude_token_set}-{s.claude_version}", status: s.clone(), tick }
                    if !s.incidents.is_empty() {
                        Section { title: tr("Vorfälle der Überwachung"),
                            div { class: "grid gap-1.5 text-sm",
                                for i in s.incidents.iter().cloned() {
                                    div { key: "{i.key}", class: "flex flex-wrap items-center gap-2",
                                        if i.active { Pill { tone: Tone::Danger, {tr("offen")} } } else { Pill { tone: Tone::Success, {tr("erledigt")} } }
                                        span { class: "min-w-0 flex-1", "{i.text}" }
                                        span { class: "text-xs text-muted-foreground", "{util::relative(i.last_seen)}" }
                                    }
                                }
                            }
                        }
                    }
                }
            },
        }
    }
}

#[component]
fn SettingsForm(status: DieterStatus, tick: Signal<u64>) -> Element {
    let admin = state::is_admin();
    let s = status.settings.clone();
    let mut provider = use_signal(|| s.provider);
    let mut or_model = use_signal(|| s.openrouter_model.clone());
    let mut xai_model = use_signal(|| s.xai_model.clone());
    let mut claude_model = use_signal(|| s.claude_model.clone());
    let mut allow = use_signal(|| s.allow_changes);
    let mut watch = use_signal(|| s.auto_watch);
    let mut fix = use_signal(|| s.auto_fix);
    let mut minutes = use_signal(|| s.watch_minutes);
    let mut or_key = use_signal(String::new);
    let mut xai_key = use_signal(String::new);
    let mut claude_token = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let save = move |e: FormEvent| {
        e.prevent_default();
        let body = DieterSettingsInput {
            settings: DieterSettings {
                provider: provider(),
                openrouter_model: or_model().trim().to_string(),
                xai_model: xai_model().trim().to_string(),
                claude_model: claude_model().trim().to_string(),
                allow_changes: allow(),
                auto_watch: watch(),
                watch_minutes: minutes(),
                auto_fix: fix(),
            },
            openrouter_key: or_key().trim().to_string(),
            xai_key: xai_key().trim().to_string(),
            claude_token: claude_token().trim().to_string(),
            clear: Vec::new(),
        };
        spawn(async move {
            busy.set(true);
            let res = api::put::<DieterStatus, _>("/dieter/settings", &body).await;
            busy.set(false);
            match res {
                Ok(_) => { toast(tr("Gespeichert.")); tick += 1; }
                Err(e) => toast_error(e),
            }
        });
    };
    let install = move |_| {
        spawn(async move {
            busy.set(true);
            let res = api::action::<DieterStatus>("/dieter/claude/install").await;
            busy.set(false);
            match res {
                Ok(_) => { toast(tr("Claude CLI ist installiert.")); tick += 1; }
                Err(e) => toast_error(e),
            }
        });
    };
    let keep = |set: bool| if set { tr("gespeichert – leer lassen, um es zu behalten") } else { tr("Schlüssel einfügen") };
    let p = provider();
    rsx! {
        Section { title: tr("Dieter einrichten"), description: tr("Dein KI-Assistent für das Netzwerk – unten rechts auf jeder Seite. Er prüft und konfiguriert DNS, Reverse Proxy, Cloudflare, NetBird, Tunnel, Docker und Zertifikate und springt bei Problemen automatisch ein."),
            form { class: "grid grid-cols-1 gap-4", onsubmit: save,
                div { class: "flex items-center gap-2 text-sm", Dot { on: status.ready } if status.ready { {tr("Dieter ist bereit")} } else { {tr("Dieter ist noch nicht bereit")} } span { class: "text-muted-foreground", " · {status.ready_detail}" } }
                Field { label: tr("Anbieter"),
                    Segmented {
                        options: vec![("openrouter".to_string(), "OpenRouter".to_string()), ("xai".to_string(), "Grok (xAI)".to_string()), ("claude-cli".to_string(), "Claude CLI".to_string())],
                        value: match p { DieterProvider::Openrouter => "openrouter".to_string(), DieterProvider::Xai => "xai".to_string(), DieterProvider::ClaudeCli => "claude-cli".to_string() },
                        onchange: move |v: String| provider.set(match v.as_str() { "xai" => DieterProvider::Xai, "claude-cli" => DieterProvider::ClaudeCli, _ => DieterProvider::Openrouter }),
                    }
                }
                match p {
                    DieterProvider::Openrouter => rsx! {
                        div { class: "grid grid-cols-1 gap-3 sm:grid-cols-2",
                            Field { label: tr("OpenRouter-Schlüssel"), hint: tr("openrouter.ai → Keys → Create Key."),
                                input { class: "{INPUT} font-mono text-[13px]", disabled: !admin, r#type: "password", autocomplete: "off", placeholder: keep(status.openrouter_key_set), value: "{or_key}", oninput: move |e| or_key.set(e.value()) }
                            }
                            Field { label: tr("Modell"), hint: tr("Leer = anthropic/claude-sonnet-5.5. Jedes Modell von OpenRouter mit Werkzeugen geht."),
                                input { class: "{INPUT} font-mono text-[13px]", disabled: !admin, placeholder: "anthropic/claude-sonnet-5.5", value: "{or_model}", oninput: move |e| or_model.set(e.value()) }
                            }
                        }
                    },
                    DieterProvider::Xai => rsx! {
                        div { class: "grid grid-cols-1 gap-3 sm:grid-cols-2",
                            Field { label: tr("xAI-Schlüssel"), hint: tr("console.x.ai → API Keys."),
                                input { class: "{INPUT} font-mono text-[13px]", disabled: !admin, r#type: "password", autocomplete: "off", placeholder: keep(status.xai_key_set), value: "{xai_key}", oninput: move |e| xai_key.set(e.value()) }
                            }
                            Field { label: tr("Modell"), hint: tr("Leer = grok-4.7."),
                                input { class: "{INPUT} font-mono text-[13px]", disabled: !admin, placeholder: "grok-4.7", value: "{xai_model}", oninput: move |e| xai_model.set(e.value()) }
                            }
                        }
                    },
                    DieterProvider::ClaudeCli => rsx! {
                        div { class: "grid grid-cols-1 gap-3",
                            div { class: "flex flex-wrap items-center justify-between gap-2 rounded-lg border px-3 py-2 text-sm",
                                span { if status.claude_version.is_empty() { {tr("Claude CLI ist noch nicht installiert.")} } else { {trf("Claude CLI {0} installiert.", &[&status.claude_version])} } }
                                if admin {
                                    button { class: btn_sm(BTN_OUTLINE), r#type: "button", disabled: busy(), onclick: install, icons::Download {} if status.claude_version.is_empty() { {tr("Installieren")} } else { {tr("Aktualisieren")} } }
                                }
                            }
                            div { class: "grid grid-cols-1 gap-3 sm:grid-cols-2",
                                Field { label: tr("Claude-Token"), hint: tr("Mit Claude-Abo: auf einem Rechner „claude setup-token“ ausführen und den Token einfügen. Sonst ein API-Schlüssel von console.anthropic.com."),
                                    input { class: "{INPUT} font-mono text-[13px]", disabled: !admin, r#type: "password", autocomplete: "off", placeholder: keep(status.claude_token_set), value: "{claude_token}", oninput: move |e| claude_token.set(e.value()) }
                                }
                                Field { label: tr("Modell"), hint: tr("Leer = sonnet. Auch opus oder haiku."),
                                    input { class: "{INPUT} font-mono text-[13px]", disabled: !admin, placeholder: "sonnet", value: "{claude_model}", oninput: move |e| claude_model.set(e.value()) }
                                }
                            }
                        }
                    },
                }
                Toggle { checked: allow(), disabled: !admin, onchange: move |v| allow.set(v), label: tr("Dieter darf Einstellungen ändern"), hint: tr("Sonst prüft und erklärt er nur. Konten, Zugangsdaten und seine eigenen Einstellungen darf er nie ändern; jede Änderung steht im Protokoll.") }
                div { class: "grid grid-cols-1 gap-4 sm:grid-cols-[1fr_auto] sm:items-end",
                    Toggle { checked: watch(), disabled: !admin, onchange: move |v| watch.set(v), label: tr("Überwachen und bei Problemen automatisch einspringen"), hint: tr("Prüft DNS, Tunnel, NetBird, Proxy-Ziele, Zertifikat und Spy. Je Problem höchstens alle 6 Stunden ein Einsatz.") }
                    Field { label: tr("alle (Minuten)"),
                        input { class: "{INPUT} w-24", disabled: !admin, r#type: "number", min: 5, max: 240, value: "{minutes}", oninput: move |e| minutes.set(e.value().parse().unwrap_or(10)) }
                    }
                }
                if watch() {
                    Toggle { checked: fix(), disabled: !admin || !allow(), onchange: move |v| fix.set(v), label: tr("Bei automatischen Einsätzen selbst beheben"), hint: tr("Sonst untersucht Dieter nur und berichtet.") }
                }
                if admin {
                    div { class: "flex justify-end", button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy(), {tr("Speichern")} } }
                }
            }
        }
    }
}
