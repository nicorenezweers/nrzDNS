//! Tastenkürzel: `g` und ein Buchstabe wechselt die Seite, `/` springt ins Suchfeld der Seite,
//! `?` zeigt die Übersicht (rust-ui Kbd). Der Listener läuft, solange man angemeldet ist.

use crate::Route;
use crate::components::overlay::Modal;
use crate::i18n::tr;
use crate::ui::kbd::{Kbd, KbdGroup};
use dioxus::prelude::*;

/// Hilfe zu den Tastenkürzeln geöffnet.
pub static SHORTCUTS_OPEN: GlobalSignal<bool> = Signal::global(|| false);

/// Ziele für `g` + Buchstabe.
fn target(key: char) -> Option<Route> {
    Some(match key {
        'd' => Route::Dashboard { range: None },
        'z' => Route::Zones {},
        's' => Route::Blocking {},
        'a' => Route::Allowed {},
        'q' => Route::logs(),
        'c' => Route::Cache {},
        'r' => Route::Resolve {
            name: None,
            qtype: None,
        },
        'e' => Route::Settings {
            section: "general".into(),
        },
        _ => return None,
    })
}

const KEYS_JS: &str = r#"
if (window.__nrzdnsKeys) window.removeEventListener('keydown', window.__nrzdnsKeys);
let pending = 0;
window.__nrzdnsKeys = (e) => {
    if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
    const t = e.target;
    if (t && t.closest && t.closest('input, textarea, select, [contenteditable], [role=dialog], [role=alertdialog]')) return;
    const k = e.key;
    if (k === '/') {
        const s = document.getElementById('page-search');
        if (s) { e.preventDefault(); s.focus(); s.select && s.select(); }
        return;
    }
    if (k === '?') { e.preventDefault(); dioxus.send('?'); return; }
    if (k === 'b' && !(pending && Date.now() - pending < 1500)) { e.preventDefault(); dioxus.send('b'); return; }
    if (pending && Date.now() - pending < 1500 && k.length === 1) {
        pending = 0;
        e.preventDefault();
        dioxus.send('g' + k.toLowerCase());
        return;
    }
    pending = k === 'g' ? Date.now() : 0;
};
window.addEventListener('keydown', window.__nrzdnsKeys);
await new Promise(() => {});
"#;

/// Einmal im angemeldeten Rahmen aufrufen.
pub fn use_shortcuts() {
    use_future(|| async {
        let mut eval = document::eval(KEYS_JS);
        while let Ok(k) = eval.recv::<String>().await {
            if k == "?" {
                let open = *SHORTCUTS_OPEN.peek();
                *SHORTCUTS_OPEN.write() = !open;
            } else if k == "b" {
                let on = *crate::state::STREAMER.peek();
                crate::state::set_streamer(!on);
            } else if let Some(route) = k
                .strip_prefix('g')
                .and_then(|c| c.chars().next())
                .and_then(target)
            {
                navigator().push(route);
            }
        }
    });
}

#[component]
pub fn ShortcutsHelp() -> Element {
    let rows: [(&[&str], String); 11] = [
        (&["g", "d"], tr("Dashboard")),
        (&["g", "z"], tr("Zonen")),
        (&["g", "s"], tr("Sperren")),
        (&["g", "a"], tr("Ausnahmen")),
        (&["g", "q"], tr("Abfragen")),
        (&["g", "c"], tr("Cache")),
        (&["g", "r"], tr("DNS-Client")),
        (&["g", "e"], tr("Einstellungen")),
        (&["/"], tr("Ins Suchfeld der Seite")),
        (&["b"], tr("Streamer-Modus ein/aus")),
        (&["?"], tr("Diese Übersicht")),
    ];
    rsx! {
        Modal { open: SHORTCUTS_OPEN.signal(), title: tr("Tastenkürzel"), description: tr("Funktionieren überall, solange kein Eingabefeld aktiv ist."), class: "max-w-md",
            div { class: "divide-y rounded-lg border",
                for (keys , label) in rows {
                    div { class: "flex items-center justify-between gap-4 px-3 py-2 text-sm",
                        span { class: "text-muted-foreground", "{label}" }
                        KbdGroup {
                            for k in keys.iter().copied() {
                                Kbd { class: "min-w-6 px-1.5", "{k}" }
                            }
                        }
                    }
                }
            }
        }
    }
}
