//! Zustand der Sperren (aktiv, pausiert bis …, ausgeschaltet) und für Administratoren:
//! 5, 15 oder 60 Minuten pausieren bzw. sofort fortsetzen.

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::state;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{BlockingStatus, PauseInput};

/// Abzeichen mit dem Zustand der Sperren.
#[component]
pub fn BlockingState(enabled: bool, paused_until: Option<i64>) -> Element {
    let paused = paused_until.filter(|t| *t > util::now());
    rsx! {
        if !enabled {
            Pill { tone: Tone::Neutral, {tr("Sperren ausgeschaltet")} }
        } else if let Some(t) = paused {
            Pill { tone: Tone::Warning, {trf("Pausiert bis {0}", &[&util::time(t)])} }
        } else {
            Pill { tone: Tone::Success, {tr("Sperren aktiv")} }
        }
    }
}

/// Knöpfe zum Pausieren und Fortsetzen (nur Administratoren, nur wenn Sperren eingeschaltet).
#[component]
pub fn PauseControl(
    enabled: bool,
    paused_until: Option<i64>,
    on_done: EventHandler<()>,
) -> Element {
    let mut busy = use_signal(|| false);
    if !state::is_admin() || !enabled {
        return rsx! {};
    }
    let paused = paused_until.is_some_and(|t| t > util::now());
    let run = move |minutes: u32| {
        spawn(async move {
            busy.set(true);
            let res =
                api::post::<BlockingStatus, _>("/blocking/pause", &PauseInput { minutes }).await;
            busy.set(false);
            match res {
                Ok(s) => {
                    match s.paused_until {
                        Some(t) if minutes > 0 => {
                            toast(trf("Sperren pausiert bis {0}.", &[&util::time(t)]))
                        }
                        _ => toast(tr("Sperren laufen wieder.")),
                    }
                    on_done.call(());
                }
                Err(e) => toast_error(e),
            }
        });
    };
    rsx! {
        div { class: "flex flex-wrap items-center gap-2",
            if paused {
                button { class: btn_sm(BTN_OUTLINE), disabled: busy(), onclick: move |_| run(0),
                    icons::Play {}
                    {tr("Fortsetzen")}
                }
            }
            Dropdown {
                align: Align::End,
                class: "w-48",
                trigger_class: btn_sm(BTN_OUTLINE),
                trigger: rsx! {
                    icons::Pause {}
                    if paused { {tr("Länger pausieren")} } else { {tr("Pausieren")} }
                    icons::ChevronDown { class: "size-3.5 text-muted-foreground" }
                },
                MenuLabel { {tr("Sperren pausieren für")} }
                for m in [5u32, 15, 60] {
                    MenuItem { key: "{m}", onclick: move |_| run(m),
                        icons::Timer {}
                        {trf("{0} Minuten", &[&m])}
                    }
                }
            }
        }
    }
}
