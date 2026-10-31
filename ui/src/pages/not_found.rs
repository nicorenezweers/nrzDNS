//! Unbekannte Adresse.

use crate::Route;
use crate::components::common::*;
use crate::i18n::tr;
use dioxus::prelude::*;

#[component]
pub fn NotFound(segments: Vec<String>) -> Element {
    let _ = segments;
    rsx! {
        div { class: "grid min-h-dvh place-items-center p-6",
            EmptyState { title: tr("Seite nicht gefunden"), description: tr("Diese Adresse gibt es in nrzDNS nicht."), icon: rsx! { icons::Globe {} },
                Link { class: btn(BTN_OUTLINE), to: Route::Dashboard { range: None }, {tr("Zum Dashboard")} }
            }
        }
    }
}
