//! Streamer-Modus: schwärzt IPs, Domains, E-Mails, UUIDs, MACs und Schlüssel im ganzen Dokument
//! (CSS Custom Highlight API, Stil `::highlight(nrz-redact)` in `ui/tailwind.rs`) und blendet
//! Tooltips aus; die Klasse `streamer` am `<html>` macht Eingabefelder, Namen und technische
//! Angaben unscharf. [`init`] läuft vor dem ersten Rendern, danach hält ein `MutationObserver`
//! alles aktuell. Texte in `[data-public]` bleiben sichtbar.

use std::cell::RefCell;

use js_sys::{Array, Function, JsString, Reflect, RegExp};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{Document, Element, MutationObserver, MutationObserverInit, MutationRecord, Node};

/// Schlüssel im localStorage ("1" = an).
const STORAGE_KEY: &str = "nrz-streamer";
/// Name der Hervorhebung (CSS: `::highlight(nrz-redact)`).
const HIGHLIGHT: &str = "nrz-redact";
/// Wartezeit nach Änderungen im DOM, bevor neu geschwärzt wird.
const SCAN_DELAY_MS: i32 = 120;
/// `NodeFilter.SHOW_TEXT`
const SHOW_TEXT: u32 = 0x4;

/// Muster mit Flags – JavaScript-RegExp, damit die Positionen (UTF-16) zu `Range` passen.
const PATTERNS: [(&str, &str); 7] = [
    // IPv4, auch mit Port oder Präfix
    (
        r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:/\d{1,2})?\b",
        "g",
    ),
    // E-Mail
    (r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", "g"),
    // UUID
    (
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        "gi",
    ),
    // MAC
    (r"\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b", "gi"),
    // Domain
    (
        r"\b(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b\.?",
        "gi",
    ),
    // IPv6 (siehe `sensitive`)
    (r"(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}", "gi"),
    // Schlüssel und Tokens (siehe `sensitive`)
    (r"[A-Za-z0-9_+/=-]{24,}", "g"),
];
const IPV6: usize = 5;
const TOKEN: usize = 6;

#[derive(Default)]
struct State {
    on: bool,
    /// Ein Durchlauf ist schon geplant.
    pending: bool,
    observer: Option<MutationObserver>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
    static REGEXES: Vec<RegExp> = PATTERNS.iter().map(|(p, f)| RegExp::new(p, f)).collect();
}

/// Im Browser gespeichert: an?
pub fn stored() -> bool {
    web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item(STORAGE_KEY).ok().flatten())
        .is_some_and(|v| v == "1")
}

/// Beim Start (vor dem ersten Rendern): gespeicherten Zustand übernehmen.
pub fn init() {
    if stored() {
        set(true);
    }
}

/// Ein- oder ausschalten und im Browser merken.
pub fn set(on: bool) {
    let Some(window) = web_sys::window() else {
        return;
    };
    if let Ok(Some(storage)) = window.local_storage() {
        let _ = storage.set_item(STORAGE_KEY, if on { "1" } else { "0" });
    }
    let Some(document) = window.document() else {
        return;
    };
    if let Some(html) = document.document_element() {
        let _ = html.class_list().toggle_with_force("streamer", on);
    }
    STATE.with_borrow_mut(|s| s.on = on);
    if !on {
        stop(&document);
    } else if let Some(body) = document.body() {
        start(&body);
    } else {
        // <body> noch nicht da (bei WebAssembly praktisch nie): nach dem Parsen starten
        let later = Closure::once_into_js(|| {
            let body = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.body());
            if let Some(body) = body.filter(|_| is_on()) {
                start(&body);
            }
        });
        let _ =
            document.add_event_listener_with_callback("DOMContentLoaded", later.unchecked_ref());
    }
}

fn is_on() -> bool {
    STATE.with_borrow(|s| s.on)
}

fn start(body: &Element) {
    hide_titles(body);
    if let Some(observer) = observer() {
        let options = MutationObserverInit::new();
        options.set_subtree(true);
        options.set_child_list(true);
        options.set_character_data(true);
        options.set_attributes(true);
        options.set_attribute_filter(&Array::of1(&"title".into()));
        let _ = observer.observe_with_options(body, &options);
    }
    scan();
}

fn stop(document: &Document) {
    if let Some(observer) = STATE.with_borrow(|s| s.observer.clone()) {
        observer.disconnect();
    }
    if let Some(registry) = highlights() {
        let _ = call(&registry, "delete", &[HIGHLIGHT.into()]);
    }
    for el in elements(document.query_selector_all("[data-nrz-title]")) {
        if let Some(title) = el.get_attribute("data-nrz-title") {
            let _ = el.set_attribute("title", &title);
            let _ = el.remove_attribute("data-nrz-title");
        }
    }
}

/// Der eine `MutationObserver` (beim ersten Einschalten angelegt, lebt so lange wie die Seite):
/// neue Tooltips gleich ausblenden, danach neu schwärzen.
fn observer() -> Option<MutationObserver> {
    if let Some(observer) = STATE.with_borrow(|s| s.observer.clone()) {
        return Some(observer);
    }
    let callback = Closure::<dyn FnMut(Array)>::new(|records: Array| {
        for record in records.iter() {
            let record: MutationRecord = record.unchecked_into();
            if record.type_() == "attributes"
                && let Some(el) = record.target().and_then(|t| t.dyn_into::<Element>().ok())
            {
                hide_title(&el);
            }
            let added = record.added_nodes();
            for i in 0..added.length() {
                if let Some(el) = added.item(i).and_then(|n| n.dyn_into::<Element>().ok()) {
                    hide_titles(&el);
                }
            }
        }
        later();
    });
    let observer = MutationObserver::new(callback.as_ref().unchecked_ref()).ok()?;
    callback.forget();
    STATE.with_borrow_mut(|s| s.observer = Some(observer.clone()));
    Some(observer)
}

/// Tooltip (`title`) von `root` und allen Elementen darin nach `data-nrz-title` verschieben.
fn hide_titles(root: &Element) {
    hide_title(root);
    for el in elements(root.query_selector_all("[title]")) {
        hide_title(&el);
    }
}

fn hide_title(el: &Element) {
    if let Some(title) = el.get_attribute("title") {
        let _ = el.set_attribute("data-nrz-title", &title);
        let _ = el.remove_attribute("title");
    }
}

fn elements(list: Result<web_sys::NodeList, JsValue>) -> Vec<Element> {
    let Ok(list) = list else {
        return Vec::new();
    };
    (0..list.length())
        .filter_map(|i| list.item(i)?.dyn_into::<Element>().ok())
        .collect()
}

/// Neues Schwärzen planen (mehrere Änderungen kurz hintereinander ergeben einen Durchlauf).
fn later() {
    if STATE.with_borrow_mut(|s| std::mem::replace(&mut s.pending, true)) {
        return;
    }
    let scheduled = web_sys::window().is_some_and(|w| {
        w.set_timeout_with_callback_and_timeout_and_arguments_0(
            Closure::once_into_js(scan).unchecked_ref(),
            SCAN_DELAY_MS,
        )
        .is_ok()
    });
    if !scheduled {
        STATE.with_borrow_mut(|s| s.pending = false);
    }
}

/// Alle Texte durchsuchen und die Treffer als Hervorhebung `nrz-redact` setzen.
fn scan() {
    let on = STATE.with_borrow_mut(|s| {
        s.pending = false;
        s.on
    });
    if !on {
        return;
    }
    let (Some(registry), Some(constructor)) = (highlights(), highlight_constructor()) else {
        return;
    };
    let Some(document) = web_sys::window().and_then(|w| w.document()) else {
        return;
    };
    let Some(body) = document.body() else {
        return;
    };
    let Ok(walker) = document.create_tree_walker_with_what_to_show(&body, SHOW_TEXT) else {
        return;
    };
    let Ok(highlight) = Reflect::construct(&constructor, &Array::new()) else {
        return;
    };
    let Ok(add) = Reflect::get(&highlight, &"add".into()).and_then(|f| f.dyn_into::<Function>())
    else {
        return;
    };
    REGEXES.with(|regexes| {
        while let Ok(Some(node)) = walker.next_node() {
            if !redactable(&node) {
                continue;
            }
            let Ok(text) = Reflect::get(&node, &"nodeValue".into()) else {
                continue;
            };
            let Some(text) = text.dyn_ref::<JsString>().filter(|t| t.length() > 3) else {
                continue;
            };
            for (pattern, re) in regexes.iter().enumerate() {
                for found in text.match_all(re) {
                    let Ok(found) = found else {
                        break;
                    };
                    let Some((start, len)) = position(&found, pattern) else {
                        continue;
                    };
                    let Ok(range) = document.create_range() else {
                        continue;
                    };
                    if range.set_start(&node, start).is_ok()
                        && range.set_end(&node, start + len).is_ok()
                    {
                        let _ = add.call1(&highlight, &range);
                    }
                }
            }
        }
    });
    let _ = call(&registry, "set", &[HIGHLIGHT.into(), highlight]);
}

/// Texte in Skripten, Stilen und `[data-public]` bleiben, wie sie sind.
fn redactable(node: &Node) -> bool {
    let Some(parent) = node.parent_element() else {
        return false;
    };
    !matches!(parent.tag_name().as_str(), "SCRIPT" | "STYLE" | "NOSCRIPT")
        && parent.closest("[data-public]").ok().flatten().is_none()
}

/// Anfang und Länge (UTF-16) eines Treffers von `matchAll`, falls er geschwärzt wird.
fn position(found: &JsValue, pattern: usize) -> Option<(u32, u32)> {
    let text = Reflect::get_u32(found, 0).ok()?;
    let len = text.dyn_ref::<JsString>()?.length();
    if len == 0 || (matches!(pattern, IPV6 | TOKEN) && !sensitive(pattern, &text.as_string()?)) {
        return None;
    }
    let start = Reflect::get(found, &"index".into()).ok()?.as_f64()?;
    Some((start as u32, len))
}

/// IPv6 nur mit „::“ oder mindestens 5 Gruppen (keine Uhrzeiten wie 12:30:45), Tokens nur mit
/// Ziffern und Buchstaben (keine langen Wörter).
fn sensitive(pattern: usize, found: &str) -> bool {
    match pattern {
        IPV6 => {
            found.bytes().filter(|&b| b != b':').count() >= 3
                && (found.contains("::") || found.split(':').count() >= 5)
        }
        TOKEN => {
            found.bytes().any(|b| b.is_ascii_digit())
                && found.bytes().any(|b| b.is_ascii_alphabetic())
        }
        _ => true,
    }
}

/// `CSS.highlights`, falls der Browser die CSS Custom Highlight API kennt.
fn highlights() -> Option<JsValue> {
    let css = Reflect::get(&js_sys::global(), &"CSS".into()).ok()?;
    let registry = Reflect::get(&css, &"highlights".into()).ok()?;
    (!registry.is_undefined() && !registry.is_null()).then_some(registry)
}

/// Der Konstruktor `Highlight`.
fn highlight_constructor() -> Option<Function> {
    Reflect::get(&js_sys::global(), &"Highlight".into())
        .ok()?
        .dyn_into()
        .ok()
}

/// Methode `name` von `target` aufrufen.
fn call(target: &JsValue, name: &str, args: &[JsValue]) -> Result<JsValue, JsValue> {
    let method: Function = Reflect::get(target, &name.into())?.dyn_into()?;
    method.apply(target, &args.iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_needs_double_colon_or_five_groups() {
        assert!(sensitive(IPV6, "fd00::1"));
        assert!(sensitive(IPV6, "2001:db8:0:0:1:0:0:1"));
        assert!(!sensitive(IPV6, "12:30:45"));
        assert!(!sensitive(IPV6, "a::"));
    }

    #[test]
    fn tokens_need_digits_and_letters() {
        assert!(sensitive(TOKEN, "Zm9vYmFyMTIzNDU2Nzg5MGFiY2Rl"));
        assert!(!sensitive(TOKEN, "Donaudampfschifffahrtsgesellschaft"));
        assert!(sensitive(0, "192.168.1.1"));
    }
}
