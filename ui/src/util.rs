//! Kleine Helfer: Datum und Uhrzeit, Zahlen, Dauer, Browser-Speicher, Fokus, Zwischenablage.

use crate::i18n::{tr, trf};
use wasm_bindgen::{JsCast, JsValue};

fn js_date_ms(ms: f64) -> js_sys::Date {
    js_sys::Date::new(&JsValue::from_f64(ms))
}

fn js_date(ts: i64) -> js_sys::Date {
    js_date_ms(ts as f64 * 1000.0)
}

/// Optionen für `Intl` aus Schlüssel-Wert-Paaren.
fn opts(pairs: &[(&str, &str)]) -> js_sys::Object {
    let o = js_sys::Object::new();
    for (k, v) in pairs {
        let _ = js_sys::Reflect::set(&o, &(*k).into(), &(*v).into());
    }
    o
}

fn format_date(d: &js_sys::Date, pairs: &[(&str, &str)]) -> String {
    d.to_locale_string(crate::i18n::locale(), &opts(pairs))
        .into()
}

/// Unix-Sekunden → "31.10.2026, 14:05" in der Zeitzone des Browsers.
pub fn datetime(ts: i64) -> String {
    format_date(
        &js_date(ts),
        &[("dateStyle", "medium"), ("timeStyle", "short")],
    )
}

/// Unix-Sekunden → "31.10.2026".
pub fn date(ts: i64) -> String {
    let d = js_date(ts);
    d.to_locale_date_string(crate::i18n::locale(), &opts(&[("dateStyle", "medium")]))
        .into()
}

/// Unix-Sekunden → "14:05".
pub fn time(ts: i64) -> String {
    format_date(&js_date(ts), &[("hour", "2-digit"), ("minute", "2-digit")])
}

/// Unix-Sekunden → "31.10." (Achse im Monatsdiagramm).
pub fn day_month(ts: i64) -> String {
    format_date(&js_date(ts), &[("day", "2-digit"), ("month", "2-digit")])
}

/// Unix-Sekunden → "Fr 14:00" (Achse im Wochendiagramm).
pub fn weekday_time(ts: i64) -> String {
    format_date(
        &js_date(ts),
        &[
            ("weekday", "short"),
            ("hour", "2-digit"),
            ("minute", "2-digit"),
        ],
    )
}

/// Unix-Sekunden → "Fr., 31.10., 14:00" (Kopf des Tooltips im Diagramm).
pub fn weekday_datetime(ts: i64) -> String {
    format_date(
        &js_date(ts),
        &[
            ("weekday", "short"),
            ("day", "2-digit"),
            ("month", "2-digit"),
            ("hour", "2-digit"),
            ("minute", "2-digit"),
        ],
    )
}

/// Unix-Millisekunden → "14:05:23", an einem anderen Tag "30.10. 14:05:23".
pub fn log_time(ms: i64) -> String {
    let d = js_date_ms(ms as f64);
    let today = js_date_ms(js_sys::Date::now());
    let same_day = d.get_full_year() == today.get_full_year()
        && d.get_month() == today.get_month()
        && d.get_date() == today.get_date();
    let t = format_date(
        &d,
        &[
            ("hour", "2-digit"),
            ("minute", "2-digit"),
            ("second", "2-digit"),
        ],
    );
    if same_day {
        t
    } else {
        format!("{} {t}", day_month(ms / 1000))
    }
}

pub fn now() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

/// Wie lange her bzw. wie lange noch: "gerade eben", "vor 5 Min.", "in 3 Std.", sonst das Datum.
pub fn relative(ts: i64) -> String {
    let diff = now() - ts;
    if diff < 0 {
        let d = -diff;
        return if d < 60 {
            tr("gleich")
        } else if d < 3600 {
            trf("in {0} Min.", &[&(d / 60)])
        } else if d < 86_400 {
            trf("in {0} Std.", &[&(d / 3600)])
        } else {
            datetime(ts)
        };
    }
    if diff < 60 {
        tr("gerade eben")
    } else if diff < 3600 {
        trf("vor {0} Min.", &[&(diff / 60)])
    } else if diff < 86_400 {
        trf("vor {0} Std.", &[&(diff / 3600)])
    } else if diff < 2 * 86_400 {
        tr("gestern")
    } else if diff < 7 * 86_400 {
        trf("vor {0} Tagen", &[&(diff / 86_400)])
    } else {
        date(ts)
    }
}

/// Zahl mit Tausendertrennzeichen der gewählten Sprache: "12’345" bzw. "12,345".
pub fn num(n: u64) -> String {
    js_sys::Number::from(n as f64)
        .to_locale_string(crate::i18n::locale())
        .into()
}

fn number_with(v: f64, pairs: &[(&str, &str)]) -> String {
    let locales = js_sys::Array::of1(&JsValue::from_str(crate::i18n::locale()));
    let format = js_sys::Intl::NumberFormat::new(&locales, &opts(pairs)).format();
    format
        .call1(&JsValue::NULL, &JsValue::from_f64(v))
        .ok()
        .and_then(|s| s.as_string())
        .unwrap_or_else(|| format!("{v}"))
}

/// Kurze Zahl für Achsen: "950", "1,2K", "3,4 Mio." (je nach Sprache).
pub fn compact(n: f64) -> String {
    number_with(
        n,
        &[("notation", "compact"), ("maximumFractionDigits", "1")],
    )
}

/// Dezimalzahl mit höchstens `digits` Nachkommastellen.
pub fn decimal(v: f64, digits: u8) -> String {
    let d = digits.to_string();
    number_with(v, &[("maximumFractionDigits", d.as_str())])
}

/// Anteil in Prozent: "12,3 %".
pub fn percent(part: u64, total: u64) -> String {
    if total == 0 {
        return "0 %".into();
    }
    let p = part as f64 / total as f64;
    number_with(p, &[("style", "percent"), ("maximumFractionDigits", "1")])
}

/// Millisekunden: "12 ms", "0,8 ms".
pub fn ms(v: f64) -> String {
    let digits = if v < 10.0 { 1 } else { 0 };
    format!("{} ms", decimal(v, digits))
}

/// Laufzeit: "3 T. 4 Std.", "2 Std. 5 Min.", "7 Min.".
pub fn uptime(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs % 86_400 / 3600, secs % 3600 / 60);
    if d > 0 {
        trf("{0} T. {1} Std.", &[&d, &h])
    } else if h > 0 {
        trf("{0} Std. {1} Min.", &[&h, &m])
    } else if m > 0 {
        trf("{0} Min.", &[&m])
    } else {
        trf("{0} s", &[&secs])
    }
}

/// TTL in Sekunden, gut lesbar: "45 s", "5 Min.", "2 Std.", "3 T.".
pub fn ttl(secs: u32) -> String {
    let s = secs as u64;
    if s < 120 {
        trf("{0} s", &[&s])
    } else if s.is_multiple_of(86_400) {
        trf("{0} T.", &[&(s / 86_400)])
    } else if s.is_multiple_of(3600) {
        trf("{0} Std.", &[&(s / 3600)])
    } else if s < 2 * 3600 {
        trf("{0} Min.", &[&(s / 60)])
    } else if s < 2 * 86_400 {
        trf("{0} Std.", &[&(s / 3600)])
    } else {
        trf("{0} T.", &[&(s / 86_400)])
    }
}

pub fn storage_get(key: &str) -> Option<String> {
    web_sys::window()?
        .local_storage()
        .ok()??
        .get_item(key)
        .ok()?
}

pub fn storage_set(key: &str, value: &str) {
    if let Some(s) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = s.set_item(key, value);
    }
}

/// Aktuelle Adresse samt Suchteil (für `?next=` bei der Anmeldung).
pub fn current_path() -> String {
    let Some(w) = web_sys::window() else {
        return "/".into();
    };
    let loc = w.location();
    format!(
        "{}{}",
        loc.pathname().unwrap_or_default(),
        loc.search().unwrap_or_default()
    )
}

/// Herkunft der Seite: "https://dns.example.com".
pub fn origin() -> String {
    web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .unwrap_or_default()
}

/// Seite gerade im Hintergrund (dann nicht automatisch neu laden).
pub fn page_hidden() -> bool {
    web_sys::window()
        .and_then(|w| w.document())
        .is_some_and(|d| d.hidden())
}

/// Erste Datei aus einem <input type=file> (onchange); leert das Feld danach.
pub fn input_file(e: &dioxus::prelude::FormEvent) -> Option<web_sys::File> {
    let input = e
        .data()
        .downcast::<web_sys::Event>()
        .and_then(|ev| ev.target())
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())?;
    let file = input.files().and_then(|l| l.get(0));
    input.set_value("");
    file
}

/// Inhalt einer Datei als Text (UTF-8).
pub async fn file_text(file: &web_sys::File) -> Option<String> {
    wasm_bindgen_futures::JsFuture::from(file.text())
        .await
        .ok()?
        .as_string()
}

/// Anfangsbuchstabe für Platzhalter-Icons.
pub fn initial(name: &str) -> String {
    name.trim()
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "·".into())
}

/// Text in die Zwischenablage (mit Rückfall für Seiten ohne HTTPS). `true` bei Erfolg.
pub async fn copy(text: &str) -> bool {
    let js = format!(
        r#"const t = {};
        try {{ await navigator.clipboard.writeText(t); return true; }} catch (_) {{}}
        const a = document.createElement('textarea');
        a.value = t; a.setAttribute('readonly', ''); a.style.position = 'fixed'; a.style.opacity = '0';
        document.body.appendChild(a); a.select();
        let ok = false;
        try {{ ok = document.execCommand('copy'); }} catch (_) {{}}
        a.remove();
        return ok;"#,
        serde_json::to_string(text).unwrap_or_default()
    );
    matches!(
        dioxus::prelude::document::eval(&js).await,
        Ok(serde_json::Value::Bool(true))
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn initial() {
        assert_eq!(super::initial("  ärger"), "Ä");
        assert_eq!(super::initial("…"), "·");
    }
}
