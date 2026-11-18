//! Alert von rust-ui (Dioxus-Fassung). Angepasst: Variante „Warnung“ mit gedämpftem Bernstein.

use dioxus::prelude::*;
use tw_merge::tw_merge;

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub enum AlertVariant {
    #[default]
    Default,
    Destructive,
    Warning,
}

#[component]
pub fn Alert(
    #[props(into, optional)] class: Option<String>,
    #[props(default)] variant: AlertVariant,
    children: Element,
) -> Element {
    let variant_class = match variant {
        AlertVariant::Default => "bg-card text-card-foreground",
        AlertVariant::Destructive => {
            "border-destructive/40 bg-destructive/10 text-destructive [&>svg]:text-current *:data-[name=AlertDescription]:text-destructive/90"
        }
        AlertVariant::Warning => {
            "border-warning/40 bg-warning/10 text-foreground [&>svg]:text-warning *:data-[name=AlertDescription]:text-foreground/80"
        }
    };
    let merged = tw_merge!(
        "relative grid w-full grid-cols-[0_1fr] items-start gap-y-0.5 rounded-lg border px-4 py-3 text-sm has-[>svg]:grid-cols-[calc(var(--spacing)*4)_1fr] has-[>svg]:gap-x-3 [&>svg]:size-4 [&>svg]:translate-y-0.5 [&>svg]:text-current",
        variant_class,
        class.as_deref().unwrap_or("")
    );
    rsx! { div { "data-name": "Alert", role: "alert", class: "{merged}", {children} } }
}

#[component]
pub fn AlertTitle(#[props(into, optional)] class: Option<String>, children: Element) -> Element {
    let merged = tw_merge!(
        "col-start-2 min-h-4 font-medium tracking-tight",
        class.as_deref().unwrap_or("")
    );
    rsx! { div { "data-name": "AlertTitle", class: "{merged}", {children} } }
}

#[component]
pub fn AlertDescription(
    #[props(into, optional)] class: Option<String>,
    children: Element,
) -> Element {
    let merged = tw_merge!(
        "col-start-2 grid justify-items-start gap-1 text-sm text-muted-foreground [&_p]:leading-relaxed",
        class.as_deref().unwrap_or("")
    );
    rsx! { div { "data-name": "AlertDescription", class: "{merged}", {children} } }
}
