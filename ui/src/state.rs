//! Globaler Zustand: angemeldeter Benutzer, Seitenleiste auf dem Handy, Vorlagen
//! (Weiterleitungen und Sperrlisten) und das Speichern der persönlichen Einstellungen.

use crate::api;
use dioxus::prelude::*;
use nrzdns_types::{Preferences, Presets, UpdateMeInput, User};

/// Angemeldeter Benutzer (None = noch nicht geladen / abgemeldet).
pub static ME: GlobalSignal<Option<User>> = Signal::global(|| None);

/// Seitenleiste auf dem Handy geöffnet.
pub static SIDEBAR_OPEN: GlobalSignal<bool> = Signal::global(|| false);

/// Streamer-Modus: sensible Angaben geschwärzt/unscharf (gespeichert im Browser).
pub static STREAMER: GlobalSignal<bool> = Signal::global(|| {
    web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("nrz-streamer").ok().flatten())
        .is_some_and(|v| v == "1")
});

/// Streamer-Modus ein- oder ausschalten.
pub fn set_streamer(on: bool) {
    *STREAMER.write() = on;
    document::eval(&format!("window.nrzStreamer && window.nrzStreamer.set({on})"));
    crate::components::overlay::toast(if on {
        crate::i18n::tr("Streamer-Modus an – sensible Angaben sind verborgen.")
    } else {
        crate::i18n::tr("Streamer-Modus aus.")
    });
}

/// Vorlagen vom Server (einmal geladen).
static PRESETS: GlobalSignal<Option<Presets>> = Signal::global(|| None);

/// Einstellungen des angemeldeten Benutzers (Vorgaben, solange niemand angemeldet ist).
pub fn prefs() -> Preferences {
    ME.read()
        .as_ref()
        .map(|u| u.preferences.clone())
        .unwrap_or_default()
}

/// Darf ändern (Administrator). Mitglieder sehen alles, ändern aber nur ihr Konto.
pub fn is_admin() -> bool {
    ME.read().as_ref().is_some_and(|u| u.is_admin())
}

/// Nach 401: zur Anmeldung (ausser auf den Anmeldeseiten selbst).
pub fn on_unauthorized() {
    let Some(window) = web_sys::window() else {
        return;
    };
    let path = window.location().pathname().unwrap_or_default();
    if path.starts_with("/login") || path.starts_with("/setup") || path.starts_with("/register") {
        return;
    }
    *ME.write() = None;
    let next = api::enc(&crate::util::current_path());
    let _ = window.location().assign(&format!("/login?next={next}"));
}

/// Persönliche Einstellungen speichern (ganzer Satz) und übernehmen.
pub async fn save_prefs(p: Preferences) -> api::ApiResult<User> {
    let user = api::put::<User, _>(
        "/me",
        &UpdateMeInput {
            display_name: None,
            preferences: Some(p),
        },
    )
    .await?;
    *ME.write() = Some(user.clone());
    Ok(user)
}

/// Vorlagen für Weiterleitungen und Sperrlisten; ohne Server die eingebauten.
pub async fn presets() -> Presets {
    if let Some(p) = PRESETS.peek().clone() {
        return p;
    }
    match api::get::<Presets>("/presets").await {
        Ok(p) => {
            *PRESETS.write() = Some(p.clone());
            p
        }
        Err(_) => Presets::builtin(),
    }
}
