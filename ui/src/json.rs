//! Hilfen für die Antworten von Cloudflare und NetBird (kommen unverändert als JSON durch)
//! und gemeinsame Bausteine der beiden Seiten.

use crate::Route;
use crate::components::common::*;
use crate::i18n::tr;
use dioxus::prelude::*;
use serde_json::Value;

pub fn s(v: &Value, k: &str) -> String {
    match &v[k] {
        Value::String(x) => x.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

pub fn b(v: &Value, k: &str) -> bool {
    v[k].as_bool().unwrap_or(false)
}

pub fn n(v: &Value, k: &str) -> i64 {
    v[k].as_i64().unwrap_or(0)
}

pub fn list(v: &Value) -> Vec<Value> {
    v.as_array().cloned().unwrap_or_default()
}

/// IDs aus einer Liste von Objekten (`[{id, name}]`) oder Zeichenketten.
pub fn ids(v: &Value) -> Vec<String> {
    list(v)
        .iter()
        .filter_map(|x| match x {
            Value::String(s) => Some(s.clone()),
            o => o["id"].as_str().map(str::to_string),
        })
        .collect()
}

/// Namen aus einer Liste von Objekten (`[{id, name}]`).
pub fn names(v: &Value) -> Vec<String> {
    list(v)
        .iter()
        .filter_map(|x| x["name"].as_str().map(str::to_string))
        .collect()
}

/// RFC-3339-Zeit → Unix-Sekunden (0 = keine/ungültig, auch NetBirds „0001-01-01…“).
pub fn ts(v: &Value, k: &str) -> i64 {
    let raw = s(v, k);
    if raw.is_empty() || raw.starts_with("0001") {
        return 0;
    }
    let ms = js_sys::Date::parse(&raw);
    if ms.is_nan() { 0 } else { (ms / 1000.0) as i64 }
}

pub fn relative_or(t: i64, none: &str) -> String {
    if t == 0 {
        none.to_string()
    } else {
        crate::util::relative(t)
    }
}

/// Hinweis, wenn die Verbindung fehlt, mit Link zu den Einstellungen.
#[component]
pub fn ConnectHint(#[props(into)] service: String, #[props(into)] text: String) -> Element {
    rsx! {
        div { class: "rounded-xl border border-dashed px-6 py-10 text-center",
            p { class: "font-medium", {format!("{service} {}", tr("ist nicht verbunden"))} }
            p { class: "mx-auto mt-1 max-w-md text-sm text-muted-foreground", "{text}" }
            Link { class: "{btn(BTN_PRIMARY)} mt-4", to: Route::Settings { section: "integrations".into() },
                icons::Plug {}
                {tr("Verbindung einrichten")}
            }
        }
    }
}

/// Auswahl mehrerer Gruppen (Chips zum An- und Abwählen).
#[component]
pub fn GroupPicker(
    groups: Vec<(String, String)>,
    selected: Signal<Vec<String>>,
    #[props(default)] disabled: bool,
) -> Element {
    rsx! {
        div { class: "flex flex-wrap gap-1.5",
            if groups.is_empty() {
                span { class: "text-sm text-muted-foreground", {tr("Keine Gruppen")} }
            }
            for (id, name) in groups {
                {
                    let on = selected.read().contains(&id);
                    let id2 = id.clone();
                    rsx! {
                        button {
                            key: "{id}",
                            r#type: "button",
                            disabled,
                            class: if on { "rounded-full border border-primary bg-primary px-2.5 py-0.5 text-xs text-primary-foreground" } else { "rounded-full border px-2.5 py-0.5 text-xs text-muted-foreground hover:bg-accent" },
                            onclick: move |_| {
                                let mut sel = selected.write();
                                if let Some(i) = sel.iter().position(|x| *x == id2) {
                                    sel.remove(i);
                                } else {
                                    sel.push(id2.clone());
                                }
                            },
                            "{name}"
                        }
                    }
                }
            }
        }
    }
}

/// Grüner/grauer Punkt.
#[component]
pub fn Dot(on: bool) -> Element {
    rsx! {
        span { class: if on { "inline-block size-2 shrink-0 rounded-full bg-emerald-500" } else { "inline-block size-2 shrink-0 rounded-full bg-muted-foreground/40" } }
    }
}
