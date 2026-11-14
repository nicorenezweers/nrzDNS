//! Eigenes Konto: Anzeigename, persönliche Einstellungen (Sprache, Dashboard, Abfrageprotokoll)
//! und Passwort. Persönliche Einstellungen werden bei jeder Änderung sofort gespeichert.

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{self, LANGUAGES, tr, trf};
use crate::labels;
use crate::state;
use crate::state::ME;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{
    ChangePasswordInput, MIN_PASSWORD_LEN, Preferences, StatsRange, UpdateMeInput, User,
};

#[component]
pub fn Account() -> Element {
    let me = ME.read().clone();
    let mut name = use_signal(|| {
        me.as_ref()
            .map(|m| m.display_name.clone())
            .unwrap_or_default()
    });
    let mut saving = use_signal(|| false);
    let mut current = use_signal(String::new);
    let mut new = use_signal(String::new);
    let mut repeat = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let Some(me) = me else {
        return rsx! { Loading {} };
    };
    let changed = name().trim() != me.display_name.trim();
    rsx! {
        Section { title: tr("Profil"), description: tr("Dein Konto in dieser nrzNetwork-Instanz."),
            div { class: "grid grid-cols-1 max-w-xl gap-5",
                dl { class: "grid grid-cols-[8rem_1fr] gap-y-2 text-sm",
                    dt { class: "text-muted-foreground", {tr("Benutzername")} }
                    dd { class: "font-medium", "{me.username}" }
                    dt { class: "text-muted-foreground", {tr("Rolle")} }
                    dd { if me.is_admin() { {tr("Administrator")} } else { {tr("Mitglied")} } }
                    dt { class: "text-muted-foreground", {tr("Dabei seit")} }
                    dd { "{util::date(me.created_at)}" }
                }
                form { class: "grid grid-cols-1 gap-3 sm:grid-cols-[1fr_auto] sm:items-end",
                    onsubmit: move |e| {
                        e.prevent_default();
                        spawn(async move {
                            saving.set(true);
                            let res = api::put::<User, _>("/me", &UpdateMeInput { display_name: Some(name().trim().to_string()), preferences: None }).await;
                            saving.set(false);
                            match res {
                                Ok(u) => {
                                    *ME.write() = Some(u);
                                    toast(tr("Anzeigename gespeichert."));
                                }
                                Err(e) => toast_error(e),
                            }
                        });
                    },
                    Field { label: tr("Anzeigename"), hint: tr("Leer = Benutzername"),
                        input { class: INPUT, maxlength: 100, autocomplete: "name", value: "{name}", oninput: move |e| name.set(e.value()) }
                    }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: saving() || !changed, {tr("Speichern")} }
                }
            }
        }
        Prefs {}
        TwoFactor {}
        Section { title: tr("Passwort ändern"), description: tr("Danach sind alle anderen Geräte abgemeldet."),
            form { class: "grid grid-cols-1 max-w-3xl gap-4 sm:grid-cols-3 sm:items-end",
                onsubmit: move |e| {
                    e.prevent_default();
                    if new() != repeat() {
                        toast_error(tr("Die Passwörter stimmen nicht überein."));
                        return;
                    }
                    spawn(async move {
                        busy.set(true);
                        let res = api::put::<serde_json::Value, _>("/me/password", &ChangePasswordInput { current: current(), new: new() }).await;
                        busy.set(false);
                        match res {
                            Ok(_) => {
                                toast(tr("Passwort geändert. Andere Geräte sind abgemeldet."));
                                current.set(String::new());
                                new.set(String::new());
                                repeat.set(String::new());
                            }
                            Err(e) => toast_error(e),
                        }
                    });
                },
                Field { label: tr("Aktuelles Passwort"),
                    input { class: INPUT, r#type: "password", autocomplete: "current-password", required: true, value: "{current}", oninput: move |e| current.set(e.value()) }
                }
                Field { label: tr("Neues Passwort"), hint: trf("Mindestens {0} Zeichen", &[&MIN_PASSWORD_LEN]),
                    input { class: INPUT, r#type: "password", autocomplete: "new-password", minlength: MIN_PASSWORD_LEN as i64, required: true, value: "{new}", oninput: move |e| new.set(e.value()) }
                }
                Field { label: tr("Wiederholen"),
                    input { class: INPUT, r#type: "password", autocomplete: "new-password", required: true, value: "{repeat}", oninput: move |e| repeat.set(e.value()) }
                }
                div { class: "sm:col-span-3",
                    button { class: btn(BTN_PRIMARY), disabled: busy(), r#type: "submit", {tr("Passwort ändern")} }
                }
            }
        }
    }
}

fn save(p: Preferences) {
    spawn(async move {
        match state::save_prefs(p).await {
            Ok(_) => toast(tr("Gespeichert.")),
            Err(e) => toast_error(e),
        }
    });
}

/// Persönliche Einstellungen: jede Änderung wird sofort gespeichert.
#[component]
fn Prefs() -> Element {
    let p = state::prefs();
    let (p1, p2, p3, p4) = (p.clone(), p.clone(), p.clone(), p.clone());
    let refresh: Vec<(u32, String)> = vec![
        (0, tr("Nie")),
        (10, trf("{0} Sekunden", &[&10])),
        (30, trf("{0} Sekunden", &[&30])),
        (60, tr("1 Minute")),
        (300, trf("{0} Minuten", &[&5])),
    ];
    let custom_refresh = !refresh.iter().any(|(v, _)| *v == p.dashboard_refresh_secs);
    rsx! {
        Section { title: tr("Persönliche Einstellungen"), description: tr("Gelten auf allen Geräten, auf denen du angemeldet bist."),
            div { class: "grid grid-cols-1 max-w-2xl gap-6",
                div { class: "grid grid-cols-1 gap-2",
                    span { class: "text-sm font-medium", {tr("Sprache")} }
                    Segmented {
                        options: LANGUAGES.iter().map(|(c, n)| (c.to_string(), n.to_string())).collect::<Vec<_>>(),
                        value: p.language.clone(),
                        onchange: move |code: String| {
                            let mut p = p1.clone();
                            p.language = code.clone();
                            spawn(async move {
                                i18n::set_language(&code, true).await;
                            });
                            save(p);
                        },
                    }
                }
                div { class: "grid grid-cols-1 gap-2",
                    span { class: "text-sm font-medium", {tr("Dashboard öffnet mit")} }
                    Segmented {
                        options: StatsRange::ALL.iter().map(|r| (r.as_str().to_string(), labels::range(*r))).collect::<Vec<_>>(),
                        value: p.dashboard_range.as_str().to_string(),
                        onchange: move |v: String| {
                            let mut p = p2.clone();
                            p.dashboard_range = StatsRange::parse(&v).unwrap_or_default();
                            save(p);
                        },
                    }
                }
                div { class: "grid grid-cols-1 gap-5 sm:grid-cols-2",
                    Field { label: tr("Dashboard neu laden"),
                        select {
                            class: SELECT,
                            onchange: move |e| {
                                let mut p = p3.clone();
                                p.dashboard_refresh_secs = e.value().parse().unwrap_or(30);
                                save(p);
                            },
                            for (v , label) in refresh {
                                option { value: "{v}", selected: p.dashboard_refresh_secs == v, "{label}" }
                            }
                            if custom_refresh {
                                option { value: "{p.dashboard_refresh_secs}", selected: true, {trf("{0} Sekunden", &[&p.dashboard_refresh_secs])} }
                            }
                        }
                    }
                    Field { label: tr("Zeilen je Seite im Abfrageprotokoll"),
                        select {
                            class: SELECT,
                            onchange: move |e| {
                                let mut p = p4.clone();
                                p.logs_per_page = e.value().parse().unwrap_or(50);
                                save(p);
                            },
                            for n in [25u32, 50, 100, 200, 500] {
                                option { value: "{n}", selected: p.logs_per_page == n, "{n}" }
                            }
                            if ![25u32, 50, 100, 200, 500].contains(&p.logs_per_page) {
                                option { value: "{p.logs_per_page}", selected: true, "{p.logs_per_page}" }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Zwei-Faktor-Anmeldung einrichten, Codes, abschalten.
#[component]
fn TwoFactor() -> Element {
    let mut version = use_signal(|| 0u64);
    let status = use_resource(move || async move {
        let _ = version();
        api::get::<nrzdns_types::TwoFactorStatus>("/me/2fa").await
    });
    let mut setup = use_signal(|| None::<nrzdns_types::TwoFactorSetup>);
    let mut codes = use_signal(Vec::<String>::new);
    let mut code = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let start = move |_| {
        spawn(async move {
            busy.set(true);
            let r = api::action::<nrzdns_types::TwoFactorSetup>("/me/2fa/setup").await;
            busy.set(false);
            match r {
                Ok(s) => { setup.set(Some(s)); code.set(String::new()); }
                Err(e) => toast_error(e),
            }
        });
    };
    let enable = move |e: FormEvent| {
        e.prevent_default();
        spawn(async move {
            busy.set(true);
            let r = api::post::<nrzdns_types::TwoFactorCodes, _>("/me/2fa/enable", &nrzdns_types::TwoFactorInput { code: code().trim().to_string(), password: String::new() }).await;
            busy.set(false);
            match r {
                Ok(c) => { codes.set(c.recovery_codes); setup.set(None); code.set(String::new()); toast(tr("Zwei-Faktor-Anmeldung ist an.")); version += 1; }
                Err(e) => toast_error(e),
            }
        });
    };
    let with_password = move |path: &'static str, disable: bool| {
        spawn(async move {
            busy.set(true);
            let body = nrzdns_types::TwoFactorInput { code: code().trim().to_string(), password: password() };
            let r = if disable {
                api::send::<serde_json::Value, _>("POST", path, &body).await.map(|_| Vec::new())
            } else {
                api::post::<nrzdns_types::TwoFactorCodes, _>(path, &body).await.map(|c| c.recovery_codes)
            };
            busy.set(false);
            match r {
                Ok(c) => {
                    codes.set(c);
                    code.set(String::new());
                    password.set(String::new());
                    toast(if disable { tr("Zwei-Faktor-Anmeldung ist aus.") } else { tr("Neue Wiederherstellungscodes erstellt.") });
                    version += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };
    let enabled = matches!(&*status.read(), Some(Ok(s)) if s.enabled);
    let left = match &*status.read() { Some(Ok(s)) => s.recovery_left, _ => 0 };
    rsx! {
        Section { title: tr("Zwei-Faktor-Anmeldung (2FA)"), description: tr("Zusätzlich zum Passwort ein Code aus einer Authenticator-App (Google Authenticator, Aegis, 1Password, Bitwarden …). Schützt dein Konto, auch wenn jemand dein Passwort kennt."),
            div { class: "grid max-w-3xl gap-4",
                if !codes().is_empty() {
                    div { class: "rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 text-sm",
                        p { class: "mb-2 font-medium", {tr("Wiederherstellungscodes – jetzt sicher aufbewahren!")} }
                        p { class: "mb-3 text-muted-foreground", {tr("Jeder Code funktioniert einmal, falls du dein Telefon nicht hast. Sie werden nur jetzt angezeigt.")} }
                        div { class: "grid grid-cols-2 gap-1 font-mono sm:grid-cols-5", for c in codes().iter() { span { key: "{c}", "{c}" } } }
                        div { class: "mt-3 flex gap-2",
                            CopyButton { text: codes().join("\n") }
                            button { class: btn_sm(BTN_GHOST), onclick: move |_| codes.set(Vec::new()), {tr("Ich habe sie gespeichert")} }
                        }
                    }
                }
                if enabled {
                    div { class: "flex flex-wrap items-center gap-2 text-sm",
                        span { class: "inline-flex items-center gap-1.5 font-medium text-emerald-500", icons::ShieldCheck { class: "size-4" } {tr("An")} }
                        span { class: "text-muted-foreground", {trf("{0} Wiederherstellungscodes übrig", &[&left.to_string()])} }
                    }
                    div { class: "grid grid-cols-1 gap-3 sm:grid-cols-2",
                        Field { label: tr("Passwort"), input { class: INPUT, r#type: "password", autocomplete: "current-password", value: "{password}", oninput: move |e| password.set(e.value()) } }
                        Field { label: tr("Code aus der App"), input { class: "{INPUT} font-mono", inputmode: "numeric", autocomplete: "one-time-code", value: "{code}", oninput: move |e| code.set(e.value()) } }
                    }
                    div { class: "flex flex-wrap gap-2",
                        button { class: btn(BTN_OUTLINE), disabled: busy() || password().is_empty() || code().trim().is_empty(), onclick: move |_| with_password("/me/2fa/recovery", false), {tr("Neue Wiederherstellungscodes")} }
                        button { class: btn(BTN_GHOST), disabled: busy() || password().is_empty() || code().trim().is_empty(), onclick: move |_| with_password("/me/2fa/disable", true), {tr("2FA ausschalten")} }
                    }
                } else if let Some(s) = setup() {
                    div { class: "grid gap-4 sm:grid-cols-[auto_minmax(0,1fr)] sm:items-start",
                        div { class: "rounded-lg bg-white p-2", dangerous_inner_html: "{s.qr_svg}" }
                        div { class: "grid gap-3 text-sm",
                            p { {tr("1. Den QR-Code mit deiner Authenticator-App scannen – oder den Schlüssel abtippen:")} }
                            div { class: "flex items-center gap-2 rounded-md border bg-muted/30 px-2 py-1 font-mono text-xs break-all", span { class: "flex-1", "{s.secret}" } CopyButton { text: s.secret.clone() } }
                            p { {tr("2. Den 6-stelligen Code aus der App eingeben:")} }
                            form { class: "flex gap-2", onsubmit: enable,
                                input { class: "{INPUT} w-40 text-center font-mono text-lg tracking-[0.3em]", inputmode: "numeric", autocomplete: "one-time-code", required: true, maxlength: 7, placeholder: "123456", value: "{code}", oninput: move |e| code.set(e.value()) }
                                button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy(), {tr("Einschalten")} }
                            }
                        }
                    }
                } else {
                    div { class: "flex flex-wrap items-center gap-3",
                        span { class: "inline-flex items-center gap-1.5 text-sm text-muted-foreground", icons::ShieldOff { class: "size-4" } {tr("Aus")} }
                        button { class: btn(BTN_PRIMARY), disabled: busy(), onclick: start, icons::ShieldCheck {} {tr("2FA einrichten")} }
                    }
                }
            }
        }
    }
}
