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
        Section { title: tr("Profil"), description: tr("Dein Konto in dieser nrzDNS-Instanz."),
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
