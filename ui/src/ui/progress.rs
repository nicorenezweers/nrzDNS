//! Progress von rust-ui (Dioxus-Fassung). Angepasst: Farbe des Balkens über `indicator_class`.

use dioxus::prelude::*;
use tw_merge::tw_merge;

#[component]
pub fn Progress(
    /// 0–100
    value: f64,
    #[props(into, optional)] class: Option<String>,
    #[props(into, optional)] indicator_class: Option<String>,
) -> Element {
    let v = value.clamp(0.0, 100.0);
    let merged = tw_merge!(
        "relative h-1.5 w-full overflow-hidden rounded-full bg-primary/10",
        class.as_deref().unwrap_or("")
    );
    let indicator = tw_merge!(
        "h-full w-full flex-1 rounded-full bg-primary/60 transition-all",
        indicator_class.as_deref().unwrap_or("")
    );
    let offset = 100.0 - v;
    rsx! {
        div {
            "data-name": "Progress",
            role: "progressbar",
            "aria-valuemin": "0",
            "aria-valuemax": "100",
            "aria-valuenow": "{v:.0}",
            class: "{merged}",
            div { class: "{indicator}", style: "transform: translateX(-{offset}%)" }
        }
    }
}
