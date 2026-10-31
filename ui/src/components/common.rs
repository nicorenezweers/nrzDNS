//! Gemeinsame Bausteine im Stil von rust-ui: Feld mit Beschriftung, Knöpfe, Seitenkopf,
//! leerer Zustand, Ladeanzeige, Hinweis, Abschnitt, Schalter, Auswahl in Segmenten, Abzeichen,
//! Kennzahl, Seitenwahl, Kopieren, Zahlenfeld und Suchfeld.

use crate::components::overlay::{toast, toast_error};
use crate::i18n::{tr, trf};
use crate::ui::badge::{Badge, BadgeVariant};
use crate::ui::card::Card;
use dioxus::prelude::*;
use nrzdns_types::ResponseKind;
use tw_merge::tw_merge;

pub const INPUT: &str = "flex h-9 w-full min-w-0 rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-xs outline-none transition-[color,box-shadow] placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50 md:text-sm dark:bg-input/30";
pub const SELECT: &str = "flex h-9 w-full items-center rounded-md border border-input bg-transparent px-3 text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:opacity-50 dark:bg-input/30 [&>option]:bg-popover";
pub const BTN: &str = "inline-flex shrink-0 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-all outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4";
pub const BTN_PRIMARY: &str =
    "bg-primary text-primary-foreground shadow-xs hover:bg-primary/90 h-9 px-4 py-2";
pub const BTN_OUTLINE: &str = "border bg-background shadow-xs hover:bg-accent hover:text-accent-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50 h-9 px-4 py-2";
pub const BTN_GHOST: &str =
    "hover:bg-accent hover:text-accent-foreground dark:hover:bg-accent/50 h-9 px-3";
pub const BTN_SM: &str = "h-8 px-3 text-[13px]";
/// Kleiner Symbolknopf (Werkzeugleisten und Tabellenzeilen).
/// Die Symbole selbst nehmen keine Maus an – sonst zeigt der Browser ihren SVG-Titel statt `title`.
pub const ICON_BTN: &str = "inline-grid size-8 shrink-0 cursor-pointer place-items-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4";

/// Klassen für einen Knopf, z. B. `btn(BTN_PRIMARY)`.
pub fn btn(variant: &str) -> String {
    format!("{BTN} {variant}")
}

/// Kleiner Knopf (Höhe 8), z. B. `btn_sm(BTN_OUTLINE)`.
pub fn btn_sm(variant: &str) -> String {
    tw_merge!(BTN, variant, BTN_SM)
}

/// Auswahlfeld mit eigenen Klassen.
pub fn select_class(extra: &str) -> String {
    tw_merge!(SELECT, extra)
}

/// Symbolknopf mit eigenen Klassen.
pub fn icon_btn(extra: &str) -> String {
    tw_merge!(ICON_BTN, extra)
}

#[component]
pub fn Field(
    #[props(into)] label: String,
    #[props(into, optional)] hint: Option<String>,
    #[props(into, optional)] class: Option<String>,
    children: Element,
) -> Element {
    let c = tw_merge!("grid grid-cols-1 gap-1.5", class.as_deref().unwrap_or(""));
    rsx! {
        label { class: "{c}",
            span { class: "text-sm font-medium leading-none", "{label}" }
            {children}
            if let Some(h) = hint {
                span { class: "text-xs text-muted-foreground", "{h}" }
            }
        }
    }
}

#[component]
pub fn PageHeader(
    #[props(into)] title: String,
    #[props(into, optional)] description: Option<String>,
    #[props(optional)] actions: Option<Element>,
    #[props(optional)] eyebrow: Option<String>,
) -> Element {
    rsx! {
        document::Title { "{title} · nrzDNS" }
        div { class: "mb-6 flex flex-wrap items-end justify-between gap-4",
            div { class: "flex min-w-0 items-center gap-2",
                MenuButton {}
                div { class: "min-w-0",
                    if let Some(e) = eyebrow {
                        p { class: "text-xs font-medium uppercase tracking-wider text-muted-foreground", "{e}" }
                    }
                    h1 { class: "truncate text-2xl font-semibold tracking-tight", "{title}" }
                    if let Some(d) = description {
                        p { class: "mt-1 text-sm text-muted-foreground", "{d}" }
                    }
                }
            }
            if let Some(a) = actions {
                div { class: "flex flex-wrap items-center gap-2", {a} }
            }
        }
    }
}

/// Öffnet auf schmalen Bildschirmen die Seitenleiste.
#[component]
pub fn MenuButton() -> Element {
    rsx! {
        button { class: "{ICON_BTN} -ml-1 lg:hidden", title: tr("Menü"), "aria-label": tr("Menü"),
            onclick: move |_| *crate::state::SIDEBAR_OPEN.write() = true,
            icons::Menu { class: "size-5" }
        }
    }
}

#[component]
pub fn EmptyState(
    #[props(into)] title: String,
    #[props(into, optional)] description: Option<String>,
    #[props(optional)] icon: Option<Element>,
    #[props(optional)] children: Option<Element>,
    #[props(into, optional)] class: Option<String>,
) -> Element {
    let c = tw_merge!(
        "flex flex-col items-center justify-center gap-3 p-10 text-center animate-fade-in",
        class.as_deref().unwrap_or("")
    );
    rsx! {
        div { class: "{c}",
            if let Some(i) = icon {
                div { class: "grid size-12 place-items-center rounded-xl bg-muted text-muted-foreground [&_svg]:size-6", {i} }
            }
            div {
                p { class: "font-medium", "{title}" }
                if let Some(d) = description {
                    p { class: "mx-auto mt-1 max-w-sm text-sm text-muted-foreground", "{d}" }
                }
            }
            if let Some(c) = children {
                {c}
            }
        }
    }
}

#[component]
pub fn Loading(#[props(into, optional)] text: Option<String>) -> Element {
    let text = text.unwrap_or_else(|| tr("Lade …"));
    rsx! {
        div { class: "flex items-center justify-center gap-2 py-10 text-sm text-muted-foreground",
            icons::LoaderCircle { class: "size-4 animate-spin" }
            "{text}"
        }
    }
}

#[component]
pub fn Callout(
    #[props(into)] text: String,
    #[props(default)] error: bool,
    #[props(optional)] children: Option<Element>,
) -> Element {
    let c = if error {
        "border-destructive/40 bg-destructive/10"
    } else {
        "bg-muted/50"
    };
    rsx! {
        div { class: "flex items-start gap-2 rounded-lg border px-3 py-2.5 text-sm {c}",
            if error {
                icons::CircleAlert { class: "mt-0.5 size-4 shrink-0 text-destructive" }
            } else {
                icons::Info { class: "mt-0.5 size-4 shrink-0 text-muted-foreground" }
            }
            div { class: "grid grid-cols-1 gap-2",
                span { "{text}" }
                if let Some(c) = children {
                    {c}
                }
            }
        }
    }
}

/// Abschnitt einer Einstellungsseite (rust-ui Card).
#[component]
pub fn Section(
    #[props(into)] title: String,
    #[props(into, optional)] description: Option<String>,
    #[props(optional)] actions: Option<Element>,
    children: Element,
) -> Element {
    rsx! {
        section { class: "rounded-xl border bg-card text-card-foreground shadow-sm animate-fade-in",
            div { class: "flex flex-wrap items-start justify-between gap-3 border-b px-5 py-4 sm:px-6",
                div { class: "min-w-0",
                    h2 { class: "font-semibold leading-none", "{title}" }
                    if let Some(d) = description {
                        p { class: "mt-1.5 text-sm text-muted-foreground", "{d}" }
                    }
                }
                if let Some(a) = actions {
                    div { class: "flex flex-wrap items-center gap-2", {a} }
                }
            }
            div { class: "px-5 py-5 sm:px-6", {children} }
        }
    }
}

/// rust-ui Switch als kontrollierte Komponente.
#[component]
pub fn Toggle(
    checked: bool,
    onchange: EventHandler<bool>,
    #[props(into, optional)] label: Option<String>,
    #[props(into, optional)] hint: Option<String>,
    #[props(default)] disabled: bool,
) -> Element {
    let state = if checked {
        "bg-primary"
    } else {
        "bg-input dark:bg-input/80"
    };
    let thumb = if checked {
        "translate-x-[calc(100%-2px)] dark:bg-primary-foreground"
    } else {
        "translate-x-0 dark:bg-foreground"
    };
    rsx! {
        label { class: "inline-flex cursor-pointer items-start gap-3 text-sm",
            button {
                r#type: "button",
                role: "switch",
                disabled,
                "aria-checked": "{checked}",
                class: "peer mt-0.5 inline-flex h-[1.15rem] w-8 shrink-0 items-center rounded-full border border-transparent shadow-xs transition-all outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:opacity-50 {state}",
                onclick: move |_| onchange.call(!checked),
                span { class: "pointer-events-none block size-4 rounded-full bg-background ring-0 transition-transform {thumb}" }
            }
            if label.is_some() || hint.is_some() {
                span { class: "grid grid-cols-1 gap-0.5",
                    if let Some(l) = label {
                        span { "{l}" }
                    }
                    if let Some(h) = hint {
                        span { class: "text-xs text-muted-foreground", "{h}" }
                    }
                }
            }
        }
    }
}

#[component]
pub fn Checkbox(
    checked: bool,
    onchange: EventHandler<bool>,
    #[props(into)] label: String,
    #[props(into, optional)] hint: Option<String>,
) -> Element {
    let state = if checked {
        "bg-primary text-primary-foreground border-primary"
    } else {
        "dark:bg-input/30"
    };
    rsx! {
        label { class: "flex cursor-pointer items-start gap-2.5 text-sm",
            button {
                r#type: "button",
                role: "checkbox",
                "aria-checked": "{checked}",
                class: "mt-0.5 grid size-4 shrink-0 place-items-center rounded-[4px] border border-input shadow-xs outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50 {state}",
                onclick: move |_| onchange.call(!checked),
                if checked {
                    icons::Check { class: "size-3.5" }
                }
            }
            span { class: "grid grid-cols-1 gap-0.5",
                span { "{label}" }
                if let Some(h) = hint {
                    span { class: "text-xs text-muted-foreground", "{h}" }
                }
            }
        }
    }
}

/// Auswahl in Segmenten (rust-ui Tabs-Optik), z. B. Schriftgrösse oder Zeitraum.
#[component]
pub fn Segmented(
    options: Vec<(String, String)>,
    value: String,
    onchange: EventHandler<String>,
    #[props(into, optional)] class: Option<String>,
    #[props(default)] disabled: bool,
) -> Element {
    let c = tw_merge!(
        "inline-flex h-9 w-fit max-w-full items-center overflow-x-auto rounded-lg bg-muted p-[3px] text-muted-foreground",
        class.as_deref().unwrap_or("")
    );
    rsx! {
        div { class: "{c}", role: "radiogroup",
            for (v , label) in options {
                button {
                    key: "{v}",
                    r#type: "button",
                    role: "radio",
                    disabled,
                    "aria-checked": "{v == value}",
                    class: if v == value { "inline-flex h-full items-center justify-center rounded-md border border-input bg-input/30 px-3 text-sm font-medium text-foreground shadow-sm transition-all" } else { "inline-flex h-full items-center justify-center rounded-md border border-transparent px-3 text-sm font-medium text-foreground/60 transition-all hover:text-foreground" },
                    onclick: {
                        let v = v.clone();
                        move |_| onchange.call(v.clone())
                    },
                    "{label}"
                }
            }
        }
    }
}

// ------------------------------------------------------------------ Abzeichen

/// Ton eines Abzeichens: grau, betont, und nur für Zustände gedämpfte Farben.
#[derive(Clone, Copy, PartialEq, Default)]
pub enum Tone {
    #[default]
    Neutral,
    Strong,
    Danger,
    Warning,
    Success,
}

/// Kleines Abzeichen (rust-ui Badge, Variante Outline).
#[component]
pub fn Pill(
    #[props(default)] tone: Tone,
    #[props(into, optional)] class: Option<String>,
    children: Element,
) -> Element {
    let t = match tone {
        Tone::Neutral => "border-border text-muted-foreground",
        Tone::Strong => "border-transparent bg-secondary text-foreground",
        Tone::Danger => "border-destructive/30 bg-destructive/10 text-destructive",
        Tone::Warning => "border-warning/30 bg-warning/10 text-warning",
        Tone::Success => "border-success/30 bg-success/10 text-success",
    };
    let c = tw_merge!(
        "whitespace-nowrap px-2 py-0 text-[11px] leading-5 font-medium",
        t,
        class.as_deref().unwrap_or("")
    );
    rsx! {
        Badge { variant: BadgeVariant::Outline, class: c, {children} }
    }
}

/// Woher die Antwort kam, als Abzeichen (gesperrt = gedämpftes Rot).
#[component]
pub fn KindBadge(kind: ResponseKind) -> Element {
    let tone = match kind {
        ResponseKind::Blocked => Tone::Danger,
        ResponseKind::Failed | ResponseKind::Dropped => Tone::Warning,
        ResponseKind::Authoritative => Tone::Strong,
        _ => Tone::Neutral,
    };
    rsx! {
        Pill { tone, {crate::labels::kind(kind)} }
    }
}

/// Antwortcode; Fehler leicht hervorgehoben.
#[component]
pub fn Rcode(#[props(into)] code: String) -> Element {
    let c = match code.as_str() {
        "NOERROR" => "text-muted-foreground",
        "SERVFAIL" | "REFUSED" | "FORMERR" | "NOTIMP" => "text-warning",
        _ => "text-foreground",
    };
    rsx! {
        span { class: "font-mono text-xs {c}", "{code}" }
    }
}

// ------------------------------------------------------------------ Kennzahl

/// Kennzahl (rust-ui Card): Beschriftung, Wert, optional eine Zeile darunter.
#[component]
pub fn StatCard(
    #[props(into)] label: String,
    #[props(into)] value: String,
    #[props(into, optional)] sub: Option<String>,
    #[props(optional)] icon: Option<Element>,
    #[props(default)] large: bool,
) -> Element {
    let size = if large { "text-2xl" } else { "text-xl" };
    rsx! {
        Card { class: "gap-1 px-4 py-4",
            div { class: "flex items-center justify-between gap-2",
                p { class: "truncate text-[13px] text-muted-foreground", "{label}" }
                if let Some(i) = icon {
                    span { class: "text-muted-foreground/70 [&_svg]:size-4", {i} }
                }
            }
            p { class: "{size} font-semibold tracking-tight", "{value}" }
            if let Some(s) = sub {
                p { class: "truncate text-xs text-muted-foreground", "{s}" }
            }
        }
    }
}

// ------------------------------------------------------------------ Seitenwahl

/// „1–50 von 1’234“ mit Knöpfen für vorige und nächste Seite (Seiten ab 1).
#[component]
pub fn Pagination(page: u32, per_page: u32, total: u64, onchange: EventHandler<u32>) -> Element {
    let per = per_page.max(1) as u64;
    let pages = total.div_ceil(per).max(1) as u32;
    let page = page.clamp(1, pages);
    let from = if total == 0 {
        0
    } else {
        (page as u64 - 1) * per + 1
    };
    let to = (page as u64 * per).min(total);
    rsx! {
        div { class: "flex flex-wrap items-center justify-between gap-3 text-sm text-muted-foreground",
            span { {trf("{0}–{1} von {2}", &[&crate::util::num(from), &crate::util::num(to), &crate::util::num(total)])} }
            div { class: "flex items-center gap-2",
                span { class: "tabular-nums", {trf("Seite {0} von {1}", &[&page, &pages])} }
                button { class: btn_sm(BTN_OUTLINE), disabled: page <= 1, title: tr("Vorige Seite"), onclick: move |_| onchange.call(page - 1),
                    icons::ChevronLeft { class: "size-4" }
                }
                button { class: btn_sm(BTN_OUTLINE), disabled: page >= pages, title: tr("Nächste Seite"), onclick: move |_| onchange.call(page + 1),
                    icons::ChevronRight { class: "size-4" }
                }
            }
        }
    }
}

// ------------------------------------------------------------------ Kopieren

/// Symbolknopf, der einen Text in die Zwischenablage legt.
#[component]
pub fn CopyButton(
    #[props(into)] text: String,
    #[props(into, optional)] title: Option<String>,
) -> Element {
    let mut done = use_signal(|| false);
    rsx! {
        button {
            class: ICON_BTN,
            r#type: "button",
            title: title.unwrap_or_else(|| tr("Kopieren")),
            onclick: move |_| {
                let text = text.clone();
                spawn(async move {
                    if crate::util::copy(&text).await {
                        done.set(true);
                        toast(tr("In die Zwischenablage kopiert."));
                        gloo_timers::future::TimeoutFuture::new(1500).await;
                        done.set(false);
                    } else {
                        toast_error(tr("Kopieren ist hier nicht möglich – bitte von Hand markieren."));
                    }
                });
            },
            if done() {
                icons::Check {}
            } else {
                icons::Copy {}
            }
        }
    }
}

// ------------------------------------------------------------------ Eingaben

/// Zahlenfeld für ganze Zahlen; meldet nur gültige Werte, behält aber den getippten Text.
#[component]
pub fn NumField(
    #[props(into)] label: String,
    #[props(into, optional)] hint: Option<String>,
    value: u32,
    min: u32,
    max: u32,
    onchange: EventHandler<u32>,
    #[props(default)] disabled: bool,
    #[props(into, optional)] unit: Option<String>,
) -> Element {
    let mut text = use_signal(|| value.to_string());
    use_effect(use_reactive!(|value| {
        if text.peek().trim().parse::<u32>().ok() != Some(value) {
            text.set(value.to_string());
        }
    }));
    rsx! {
        Field { label, hint,
            div { class: "flex items-center gap-2",
                input {
                    class: "{INPUT} max-w-40",
                    r#type: "number",
                    inputmode: "numeric",
                    min: min as i64,
                    max: max as i64,
                    step: 1,
                    required: true,
                    disabled,
                    value: "{text}",
                    oninput: move |e| {
                        let v = e.value();
                        if let Ok(n) = v.trim().parse::<u32>() {
                            onchange.call(n);
                        }
                        text.set(v);
                    },
                }
                if let Some(u) = unit {
                    span { class: "text-sm text-muted-foreground", "{u}" }
                }
            }
        }
    }
}

/// Suchfeld mit Lupe. Mit `id: "page-search"` springt `/` hinein.
#[component]
pub fn SearchInput(
    #[props(into)] value: String,
    oninput: EventHandler<String>,
    #[props(into, optional)] placeholder: Option<String>,
    #[props(into, optional)] id: Option<String>,
    #[props(into, optional)] class: Option<String>,
) -> Element {
    let c = tw_merge!(
        "relative w-full sm:max-w-xs",
        class.as_deref().unwrap_or("")
    );
    rsx! {
        div { class: "{c}",
            icons::Search { class: "pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" }
            input {
                class: "{INPUT} pl-8",
                r#type: "search",
                id: id.unwrap_or_default(),
                autocomplete: "off",
                spellcheck: false,
                placeholder: placeholder.unwrap_or_else(|| tr("Suchen …")),
                value: "{value}",
                oninput: move |e| oninput.call(e.value()),
            }
        }
    }
}

/// Hinweis für Mitglieder: nur Administratoren ändern hier etwas.
#[component]
pub fn ReadOnlyHint() -> Element {
    rsx! {
        div { class: "flex items-center gap-2 rounded-lg border border-dashed px-3 py-2 text-xs text-muted-foreground",
            icons::Eye { class: "size-3.5 shrink-0" }
            {tr("Nur ansehen – Änderungen sind Administratoren vorbehalten.")}
        }
    }
}
