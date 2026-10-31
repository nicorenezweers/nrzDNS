//! Table von rust-ui (Dioxus-Fassung). Angepasst: Kopfzeile im Stil von nrzPaper (klein,
//! Grossbuchstaben, gedämpft), kompaktere Zellen und ein Rahmen mit waagrechtem Scrollen.

use dioxus::prelude::*;
use tw_merge::tw_merge;

/// Rahmen um die Tabelle; scrollt auf schmalen Bildschirmen waagrecht.
#[component]
pub fn TableWrapper(#[props(into, optional)] class: Option<String>, children: Element) -> Element {
    let merged = tw_merge!(
        "w-full overflow-x-auto rounded-xl border bg-card",
        class.as_deref().unwrap_or("")
    );
    rsx! { div { "data-name": "TableWrapper", class: "{merged}", {children} } }
}

#[component]
pub fn Table(#[props(into, optional)] class: Option<String>, children: Element) -> Element {
    let merged = tw_merge!(
        "w-full caption-bottom text-sm",
        class.as_deref().unwrap_or("")
    );
    rsx! { table { "data-name": "Table", class: "{merged}", {children} } }
}

#[component]
pub fn TableCaption(#[props(into, optional)] class: Option<String>, children: Element) -> Element {
    let merged = tw_merge!(
        "mt-4 text-sm text-muted-foreground",
        class.as_deref().unwrap_or("")
    );
    rsx! { caption { "data-name": "TableCaption", class: "{merged}", {children} } }
}

#[component]
pub fn TableHeader(#[props(into, optional)] class: Option<String>, children: Element) -> Element {
    let merged = tw_merge!(
        "bg-muted/40 text-left text-xs uppercase tracking-wider text-muted-foreground [&_tr]:border-b",
        class.as_deref().unwrap_or("")
    );
    rsx! { thead { "data-name": "TableHeader", class: "{merged}", {children} } }
}

#[component]
pub fn TableBody(#[props(into, optional)] class: Option<String>, children: Element) -> Element {
    let merged = tw_merge!("[&_tr:last-child]:border-0", class.as_deref().unwrap_or(""));
    rsx! { tbody { "data-name": "TableBody", class: "{merged}", {children} } }
}

#[component]
pub fn TableFooter(#[props(into, optional)] class: Option<String>, children: Element) -> Element {
    let merged = tw_merge!(
        "border-t bg-muted/50 font-medium [&>tr]:last:border-b-0",
        class.as_deref().unwrap_or("")
    );
    rsx! { tfoot { "data-name": "TableFooter", class: "{merged}", {children} } }
}

#[component]
pub fn TableRow(
    #[props(into, optional)] class: Option<String>,
    #[props(optional)] onclick: Option<EventHandler<MouseEvent>>,
    children: Element,
) -> Element {
    let merged = tw_merge!(
        "border-b transition-colors hover:bg-muted/30 data-[state=selected]:bg-muted",
        if onclick.is_some() {
            "cursor-pointer"
        } else {
            ""
        },
        class.as_deref().unwrap_or("")
    );
    rsx! {
        tr {
            "data-name": "TableRow",
            class: "{merged}",
            onclick: move |e| {
                if let Some(h) = &onclick {
                    h.call(e);
                }
            },
            {children}
        }
    }
}

#[component]
pub fn TableHead(#[props(into, optional)] class: Option<String>, children: Element) -> Element {
    let merged = tw_merge!(
        "h-9 px-3 text-left align-middle font-medium whitespace-nowrap [&:has([role=checkbox])]:pr-0",
        class.as_deref().unwrap_or("")
    );
    rsx! { th { "data-name": "TableHead", class: "{merged}", {children} } }
}

#[component]
pub fn TableCell(
    #[props(into, optional)] class: Option<String>,
    #[props(into, optional)] title: Option<String>,
    children: Element,
) -> Element {
    let merged = tw_merge!(
        "px-3 py-2 align-middle [&:has([role=checkbox])]:pr-0",
        class.as_deref().unwrap_or("")
    );
    rsx! {
        td { "data-name": "TableCell", class: "{merged}", title: title.unwrap_or_default(), {children} }
    }
}
