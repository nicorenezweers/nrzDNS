//! Dieter: KI-Assistent für das Netzwerk – Chat, automatische Einsätze, Einstellungen.

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::json::Dot;
use crate::state;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{
    DieterProvider, DieterSendInput, DieterSettings, DieterSettingsInput, DieterStatus,
    DieterThread,
};

#[component]
pub fn Dieter() -> Element {
    let admin = state::is_admin();
    let mut tick = use_signal(|| 0u64);
    let status = use_resource(move || async move {
        let _ = tick();
        api::get::<DieterStatus>("/dieter").await
    });
    let mut current = use_signal(|| None::<i64>);
    let mut show_settings = use_signal(|| false);
    use_future(move || async move {
        loop {
            gloo_timers::future::TimeoutFuture::new(4000).await;
            let busy =
                matches!(&*status.peek(), Some(Ok(s)) if s.conversations.iter().any(|c| c.running));
            if busy {
                tick += 1;
            }
        }
    });
    rsx! {
        PageHeader { title: tr("Dieter"), description: tr("Dein KI-Assistent für das Netzwerk: fragt, prüft und konfiguriert DNS, Reverse Proxy, Cloudflare, NetBird, Tunnel und Zertifikate – und springt automatisch ein, wenn etwas klemmt.") }
        match &*status.read() {
            None => rsx! { Loading {} },
            Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
            Some(Ok(s)) => rsx! {
                div { class: "grid grid-cols-1 gap-6",
                    div { class: "flex flex-wrap items-center justify-between gap-3 rounded-xl border p-4",
                        div { class: "flex items-center gap-3",
                            div { class: "flex size-10 items-center justify-center rounded-full bg-primary text-primary-foreground", icons::Bot { class: "size-5" } }
                            div {
                                p { class: "font-medium flex items-center gap-2", Dot { on: s.ready } if s.ready { {tr("Dieter ist bereit")} } else { {tr("Dieter ist noch nicht bereit")} } }
                                p { class: "text-xs text-muted-foreground",
                                    "{s.ready_detail}"
                                    " · " if s.settings.allow_changes { {tr("darf ändern")} } else { {tr("nur lesen")} }
                                    if s.settings.auto_watch { " · " {trf("Überwachung alle {0} Min.", &[&s.settings.watch_minutes.to_string()])} }
                                    if s.last_watch > 0 { " · " {trf("zuletzt geprüft {0}", &[&util::relative(s.last_watch)])} }
                                }
                            }
                        }
                        if admin {
                            div { class: "flex gap-2",
                                button { class: btn_sm(BTN_OUTLINE), onclick: move |_| {
                                        spawn(async move {
                                            match api::action::<DieterStatus>("/dieter/watch").await {
                                                Ok(_) => { toast(tr("Geprüft.")); tick += 1; }
                                                Err(e) => toast_error(e),
                                            }
                                        });
                                    },
                                    icons::ShieldCheck {} {tr("Jetzt prüfen")}
                                }
                                button { class: btn_sm(BTN_OUTLINE), onclick: move |_| show_settings.toggle(), icons::Settings {} {tr("Einstellungen")} }
                            }
                        }
                    }
                    if show_settings() || (!s.ready && admin) {
                        SettingsForm { key: "{s.openrouter_key_set}-{s.xai_key_set}-{s.claude_token_set}-{s.claude_version}", status: s.clone(), tick }
                    }
                    if s.incidents.iter().any(|i| i.active) {
                        Section { title: tr("Aktuelle Probleme"), description: tr("Gefunden von der Überwachung – Dieter kümmert sich automatisch, wenn es eingeschaltet ist."),
                            div { class: "grid gap-1.5 text-sm",
                                for i in s.incidents.iter().filter(|i| i.active).cloned() {
                                    div { key: "{i.key}", class: "flex flex-wrap items-center gap-2",
                                        Pill { tone: Tone::Danger, {tr("offen")} }
                                        span { class: "min-w-0 flex-1", "{i.text}" }
                                        if i.conversation_id > 0 {
                                            button { class: btn_sm(BTN_GHOST), onclick: move |_| current.set(Some(i.conversation_id)), icons::MessageSquare {} {tr("Einsatz ansehen")} }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    div { class: "grid grid-cols-1 gap-6 lg:grid-cols-[18rem_minmax(0,1fr)]",
                        div { class: "grid content-start gap-2",
                            if admin {
                                button { class: btn(BTN_PRIMARY), onclick: move |_| current.set(None), icons::Plus {} {tr("Neues Gespräch")} }
                            }
                            for c in s.conversations.iter().cloned() {
                                button { key: "{c.id}",
                                    class: if current() == Some(c.id) { "rounded-lg border border-primary bg-primary/5 p-2 text-left text-sm" } else { "rounded-lg border p-2 text-left text-sm hover:bg-accent" },
                                    onclick: move |_| current.set(Some(c.id)),
                                    p { class: "flex items-center gap-1.5 font-medium",
                                        if c.automatic { icons::Zap { class: "size-3.5 text-amber-500" } }
                                        if c.running { icons::LoaderCircle { class: "size-3.5 animate-spin" } }
                                        span { class: "truncate", "{c.title}" }
                                    }
                                    p { class: "text-xs text-muted-foreground", "{util::relative(c.updated_at)}" }
                                }
                            }
                        }
                        Chat { key: "{current():?}", id: current(), ready: s.ready, admin, tick, current }
                    }
                }
            },
        }
    }
}

#[component]
fn Chat(
    id: Option<i64>,
    ready: bool,
    admin: bool,
    tick: Signal<u64>,
    current: Signal<Option<i64>>,
) -> Element {
    let mut local_tick = use_signal(|| 0u64);
    let thread = use_resource(move || async move {
        let _ = (local_tick(), tick());
        match id {
            Some(i) => Some(api::get::<DieterThread>(&format!("/dieter/conversations/{i}")).await),
            None => None,
        }
    });
    let mut text = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let running = matches!(&*thread.read(), Some(Some(Ok(t))) if t.conversation.running);
    use_effect(move || {
        let running = matches!(&*thread.read(), Some(Some(Ok(t))) if t.conversation.running);
        if running {
            spawn(async move {
                gloo_timers::future::TimeoutFuture::new(1500).await;
                local_tick += 1;
            });
        }
    });
    let submit = move |e: FormEvent| {
        e.prevent_default();
        let body = DieterSendInput {
            text: text().trim().to_string(),
        };
        if body.text.is_empty() {
            return;
        }
        spawn(async move {
            busy.set(true);
            let res = match id {
                Some(i) => {
                    api::post::<DieterThread, _>(
                        &format!("/dieter/conversations/{i}/messages"),
                        &body,
                    )
                    .await
                }
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
                    local_tick += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };
    let examples = [
        tr("Warum ist zweers.ch nicht erreichbar?"),
        tr("Prüfe alle Reverse-Proxy-Einträge und sag mir, welche Ziele nicht antworten."),
        tr(
            "Leg bench.zweers.ch als Eintrag auf http://192.168.0.198:8550 an und gib ihn über Cloudflare frei.",
        ),
        tr("Welche DNS-Einträge bei Cloudflare zeigen ins Leere?"),
    ];
    rsx! {
        div { class: "flex min-h-[28rem] flex-col rounded-xl border",
            div { class: "flex items-center justify-between gap-2 border-b px-4 py-2 text-sm",
                match &*thread.read() {
                    Some(Some(Ok(t))) => rsx! { span { class: "truncate font-medium", "{t.conversation.title}" } },
                    _ => rsx! { span { class: "font-medium", {tr("Neues Gespräch")} } },
                }
                if let (Some(i), true) = (id, admin) {
                    button { class: icon_btn("hover:text-destructive"), title: tr("Gespräch löschen"),
                        onclick: move |_| {
                            spawn(async move {
                                match api::delete(&format!("/dieter/conversations/{i}")).await {
                                    Ok(()) => { current.set(None); tick += 1; }
                                    Err(e) => toast_error(e),
                                }
                            });
                        },
                        icons::Trash2 {}
                    }
                }
            }
            div { class: "flex-1 space-y-3 overflow-y-auto p-4",
                match &*thread.read() {
                    Some(Some(Ok(t))) => rsx! {
                        for m in t.messages.iter().cloned() {
                            match m.role.as_str() {
                                "user" => rsx! { div { key: "{m.id}", class: "ml-auto max-w-[85%] whitespace-pre-wrap rounded-2xl rounded-br-sm bg-primary px-3 py-2 text-sm text-primary-foreground", "{m.text}" } },
                                "action" => rsx! { div { key: "{m.id}", class: "flex items-center gap-2 font-mono text-xs text-muted-foreground", icons::Wrench { class: "size-3.5" } "{m.detail}" } },
                                "error" => rsx! { div { key: "{m.id}", Callout { text: m.text.clone(), error: true } } },
                                _ => rsx! { div { key: "{m.id}", class: "max-w-[90%] whitespace-pre-wrap rounded-2xl rounded-bl-sm bg-muted px-3 py-2 text-sm", "{m.text}" } },
                            }
                        }
                        if running {
                            div { class: "flex items-center gap-2 text-sm text-muted-foreground", icons::LoaderCircle { class: "size-4 animate-spin" } {tr("Dieter arbeitet …")} }
                        }
                    },
                    Some(Some(Err(e))) => rsx! { Callout { text: e.message.clone(), error: true } },
                    _ => rsx! {
                        div { class: "grid gap-2 text-sm",
                            p { class: "text-muted-foreground", {tr("Frag Dieter etwas, zum Beispiel:")} }
                            for (i, ex) in examples.iter().cloned().enumerate() {
                                button { key: "{i}", class: "rounded-lg border px-3 py-2 text-left hover:bg-accent", disabled: !admin || !ready, onclick: move |_| text.set(ex.clone()), "{ex}" }
                            }
                        }
                    },
                }
            }
            if admin {
                form { class: "flex gap-2 border-t p-3", onsubmit: submit,
                    textarea { class: "{INPUT} min-h-11 flex-1 resize-none py-2", rows: 2, disabled: !ready || running,
                        placeholder: if ready { tr("Nachricht an Dieter …") } else { tr("Zuerst unter Einstellungen einen Anbieter einrichten.") },
                        value: "{text}", oninput: move |e| text.set(e.value()),
                        onkeydown: move |e: KeyboardEvent| {
                            if e.key() == Key::Enter && !e.modifiers().shift() {
                                e.prevent_default();
                                let body = DieterSendInput { text: text().trim().to_string() };
                                if body.text.is_empty() { return; }
                                spawn(async move {
                                    busy.set(true);
                                    let res = match id {
                                        Some(i) => api::post::<DieterThread, _>(&format!("/dieter/conversations/{i}/messages"), &body).await,
                                        None => api::post::<DieterThread, _>("/dieter/conversations", &body).await,
                                    };
                                    busy.set(false);
                                    match res {
                                        Ok(t) => { text.set(String::new()); if id.is_none() { current.set(Some(t.conversation.id)); } tick += 1; local_tick += 1; }
                                        Err(e) => toast_error(e),
                                    }
                                });
                            }
                        },
                    }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: !ready || running || busy() || text().trim().is_empty(), icons::Send {} }
                }
            }
        }
    }
}

#[component]
fn SettingsForm(status: DieterStatus, tick: Signal<u64>) -> Element {
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
                Ok(_) => {
                    toast(tr("Gespeichert."));
                    tick += 1;
                }
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
                Ok(_) => {
                    toast(tr("Claude CLI ist installiert."));
                    tick += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };
    let keep = |set: bool| {
        if set {
            tr("gespeichert – leer lassen, um es zu behalten")
        } else {
            tr("Schlüssel einfügen")
        }
    };
    let p = provider();
    rsx! {
        Section { title: tr("Dieter einrichten"),
            form { class: "grid grid-cols-1 gap-4", onsubmit: save,
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
                                input { class: "{INPUT} font-mono text-[13px]", r#type: "password", autocomplete: "off", placeholder: keep(status.openrouter_key_set), value: "{or_key}", oninput: move |e| or_key.set(e.value()) }
                            }
                            Field { label: tr("Modell"), hint: tr("Leer = anthropic/claude-sonnet-5.5. Jedes Modell von OpenRouter mit Werkzeugen geht."),
                                input { class: "{INPUT} font-mono text-[13px]", placeholder: "anthropic/claude-sonnet-5.5", value: "{or_model}", oninput: move |e| or_model.set(e.value()) }
                            }
                        }
                    },
                    DieterProvider::Xai => rsx! {
                        div { class: "grid grid-cols-1 gap-3 sm:grid-cols-2",
                            Field { label: tr("xAI-Schlüssel"), hint: tr("console.x.ai → API Keys."),
                                input { class: "{INPUT} font-mono text-[13px]", r#type: "password", autocomplete: "off", placeholder: keep(status.xai_key_set), value: "{xai_key}", oninput: move |e| xai_key.set(e.value()) }
                            }
                            Field { label: tr("Modell"), hint: tr("Leer = grok-4.7."),
                                input { class: "{INPUT} font-mono text-[13px]", placeholder: "grok-4.7", value: "{xai_model}", oninput: move |e| xai_model.set(e.value()) }
                            }
                        }
                    },
                    DieterProvider::ClaudeCli => rsx! {
                        div { class: "grid grid-cols-1 gap-3",
                            div { class: "flex flex-wrap items-center justify-between gap-2 rounded-lg border px-3 py-2 text-sm",
                                span { if status.claude_version.is_empty() { {tr("Claude CLI ist noch nicht installiert.")} } else { {trf("Claude CLI {0} installiert.", &[&status.claude_version])} } }
                                button { class: btn_sm(BTN_OUTLINE), r#type: "button", disabled: busy(), onclick: install, icons::Download {} if status.claude_version.is_empty() { {tr("Installieren")} } else { {tr("Aktualisieren")} } }
                            }
                            div { class: "grid grid-cols-1 gap-3 sm:grid-cols-2",
                                Field { label: tr("Claude-Token"), hint: tr("Mit Claude-Abo: auf einem Rechner „claude setup-token“ ausführen und den Token einfügen. Sonst ein API-Schlüssel von console.anthropic.com."),
                                    input { class: "{INPUT} font-mono text-[13px]", r#type: "password", autocomplete: "off", placeholder: keep(status.claude_token_set), value: "{claude_token}", oninput: move |e| claude_token.set(e.value()) }
                                }
                                Field { label: tr("Modell"), hint: tr("Leer = sonnet. Auch opus oder haiku."),
                                    input { class: "{INPUT} font-mono text-[13px]", placeholder: "sonnet", value: "{claude_model}", oninput: move |e| claude_model.set(e.value()) }
                                }
                            }
                        }
                    },
                }
                Toggle { checked: allow(), onchange: move |v| allow.set(v), label: tr("Dieter darf Einstellungen ändern"), hint: tr("Sonst prüft und erklärt er nur. Konten, Zugangsdaten und seine eigenen Einstellungen darf er nie ändern; jede Änderung steht im Protokoll.") }
                div { class: "grid grid-cols-1 gap-4 sm:grid-cols-[1fr_auto] sm:items-end",
                    Toggle { checked: watch(), onchange: move |v| watch.set(v), label: tr("Überwachen und bei Problemen automatisch einspringen"), hint: tr("Prüft DNS, Tunnel, NetBird, Proxy-Ziele, Zertifikat und Spy. Je Problem höchstens alle 6 Stunden ein Einsatz.") }
                    Field { label: tr("alle (Minuten)"),
                        input { class: "{INPUT} w-24", r#type: "number", min: 5, max: 240, value: "{minutes}", oninput: move |e| minutes.set(e.value().parse().unwrap_or(10)) }
                    }
                }
                if watch() {
                    Toggle { checked: fix(), disabled: !allow(), onchange: move |v| fix.set(v), label: tr("Bei automatischen Einsätzen selbst beheben"), hint: tr("Sonst untersucht Dieter nur und berichtet.") }
                }
                div { class: "flex justify-end", button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy(), {tr("Speichern")} } }
            }
        }
    }
}
