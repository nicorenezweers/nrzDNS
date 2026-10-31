//! Ausnahmen: Domains, die nie gesperrt werden – sie schlagen jede Sperrliste und eigene Sperre.

use crate::components::common::*;
use crate::components::domains::DomainList;
use crate::i18n::tr;
use crate::state;
use crate::ui::alert::{Alert, AlertDescription, AlertTitle};
use dioxus::prelude::*;

#[component]
pub fn Allowed() -> Element {
    let admin = state::is_admin();
    rsx! {
        PageHeader { title: tr("Ausnahmen"), description: tr("Domains, die nie gesperrt werden.") }
        div { class: "grid grid-cols-1 gap-6",
            Alert {
                icons::ShieldCheck {}
                AlertTitle { {tr("Ausnahmen haben immer Vorrang")} }
                AlertDescription {
                    p { {tr("Eine Ausnahme schlägt jede Sperrliste und jede eigene Sperre – für die Domain und alle ihre Subdomains. Praktisch, wenn eine Liste zu viel sperrt (z. B. Links in Newslettern oder eine App, die sonst nicht startet).")} }
                }
            }
            if !admin {
                ReadOnlyHint {}
            }
            DomainList {
                base: "/allowed",
                title: tr("Erlaubte Domains"),
                description: tr("Gilt sofort, ohne Neustart."),
                empty: tr("Noch keine Ausnahmen."),
                add_label: tr("Domain erlauben"),
            }
        }
    }
}
