//! Cache: Einträge durchsuchen (Name, Typ, Antwortcode, Rest-TTL, abgelaufen, Antworten, Treffer),
//! einen Namen entfernen oder – für Administratoren – den ganzen Cache leeren.

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::state;
use crate::ui::table::*;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{CacheEntry, CacheFlushResult, CacheList};

const LIMIT: u32 = 500;

#[component]
pub fn Cache() -> Element {
    let admin = state::is_admin();
    let mut q = use_signal(String::new);
    let mut search = use_signal(String::new);
    let mut tick = use_signal(|| 0u64);
    let mut data = use_signal(|| None::<CacheList>);
    let mut error = use_signal(|| None::<String>);
    let res = use_resource(move || async move {
        let _ = tick();
        let s = search();
        match api::get::<CacheList>(&format!("/cache?q={}&limit={LIMIT}", api::enc(s.trim()))).await
        {
            Ok(l) => {
                data.set(Some(l));
                error.set(None);
            }
            Err(e) => error.set(Some(e.message)),
        }
    });
    // Suche kurz nach dem Tippen auslösen
    use_effect(move || {
        let v = q();
        spawn(async move {
            gloo_timers::future::TimeoutFuture::new(300).await;
            if *q.peek() == v && *search.peek() != v {
                search.set(v);
            }
        });
    });
    let loading = !res.finished();

    let flush = move |_| {
        spawn(async move {
            let ask = Ask::new(tr("Ganzen Cache leeren?"), tr("Alle zwischengespeicherten Antworten werden verworfen; die nächsten Anfragen gehen wieder an die vorgelagerten Server.")).confirm(tr("Cache leeren")).destructive();
            if confirm(ask).await {
                match api::delete_json::<CacheFlushResult>("/cache").await {
                    Ok(r) => {
                        toast(trf("{0} Einträge entfernt.", &[&util::num(r.removed)]));
                        tick += 1;
                    }
                    Err(e) => toast_error(e),
                }
            }
        });
    };

    rsx! {
        PageHeader {
            title: tr("Cache"),
            description: tr("Zwischengespeicherte Antworten vorgelagerter Server."),
            actions: rsx! {
                button { class: icon_btn("size-9"), title: tr("Neu laden"), disabled: loading, onclick: move |_| tick += 1,
                    icons::RefreshCw { class: if loading { "size-4 animate-spin" } else { "size-4" } }
                }
                if admin {
                    button { class: "{btn(BTN_OUTLINE)} hover:text-destructive", onclick: flush,
                        icons::Eraser {}
                        {tr("Cache leeren")}
                    }
                }
            },
        }
        div { class: "grid grid-cols-1 gap-4",
            div { class: "flex flex-wrap items-center justify-between gap-2",
                SearchInput { id: "page-search", value: q(), oninput: move |v| q.set(v), placeholder: tr("Name enthält …"), class: "sm:max-w-sm" }
                if let Some(l) = data() {
                    span { class: "text-xs text-muted-foreground",
                        if (l.entries.len() as u64) < l.total {
                            {trf("{0} von {1} Einträgen", &[&util::num(l.entries.len() as u64), &util::num(l.total)])}
                        } else {
                            {trf("{0} Einträge", &[&util::num(l.total)])}
                        }
                    }
                }
            }
            if let Some(e) = error() {
                Callout { text: e, error: true }
            }
            match data() {
                None if error().is_none() => rsx! { Loading {} },
                None => rsx! {},
                Some(l) => rsx! {
                    div { class: if loading { "opacity-70 transition-opacity" } else { "transition-opacity" },
                        TableWrapper {
                            Table {
                                TableHeader {
                                    tr {
                                        TableHead { {tr("Name")} }
                                        TableHead { {tr("Typ")} }
                                        TableHead { class: "hidden sm:table-cell", {tr("Code")} }
                                        TableHead { class: "text-right", {tr("TTL")} }
                                        TableHead { class: "hidden md:table-cell", {tr("Antworten")} }
                                        TableHead { class: "hidden sm:table-cell text-right", {tr("Treffer")} }
                                        if admin {
                                            TableHead { class: "w-10" }
                                        }
                                    }
                                }
                                TableBody {
                                    if l.entries.is_empty() {
                                        tr {
                                            td { class: "px-3 py-10 text-center text-muted-foreground", colspan: "7",
                                                if search().trim().is_empty() { {tr("Der Cache ist leer.")} } else { {tr("Keine Treffer.")} }
                                            }
                                        }
                                    }
                                    for (i , e) in l.entries.iter().cloned().enumerate() {
                                        CacheRow { key: "{i}-{e.name}-{e.qtype}", entry: e, admin, on_change: move |_| tick += 1 }
                                    }
                                }
                            }
                        }
                    }
                },
            }
        }
    }
}

#[component]
fn CacheRow(entry: CacheEntry, admin: bool, on_change: EventHandler<()>) -> Element {
    let e = entry;
    let name = e.name.clone();
    let answers = e.answers.join("\n");
    rsx! {
        TableRow { class: "text-[13px]",
            TableCell { class: "min-w-40 max-w-[20rem] font-mono text-xs break-all", "{e.name}" }
            TableCell { class: "font-mono text-xs text-muted-foreground", "{e.qtype}" }
            TableCell { class: "hidden sm:table-cell", Rcode { code: e.rcode.clone() } }
            TableCell { class: "text-right whitespace-nowrap tabular-nums",
                if e.stale {
                    Pill { tone: Tone::Warning, {tr("abgelaufen")} }
                } else {
                    {util::ttl(e.ttl)}
                }
            }
            TableCell { class: "hidden max-w-md md:table-cell", title: "{answers}",
                if e.answers.is_empty() {
                    span { class: "text-muted-foreground", "–" }
                }
                for (i , a) in e.answers.iter().take(3).enumerate() {
                    p { key: "{i}", class: "truncate font-mono text-xs text-muted-foreground", "{a}" }
                }
                if e.answers.len() > 3 {
                    p { class: "text-xs text-muted-foreground", {trf("und {0} weitere", &[&(e.answers.len() - 3)])} }
                }
            }
            TableCell { class: "hidden text-right tabular-nums text-muted-foreground sm:table-cell", {util::num(e.hits)} }
            if admin {
                TableCell { class: "px-2",
                    button {
                        class: icon_btn("hover:text-destructive"),
                        title: tr("Diesen Namen aus dem Cache entfernen"),
                        onclick: move |_| {
                            let name = name.clone();
                            spawn(async move {
                                match api::delete_json::<CacheFlushResult>(&format!("/cache/{}", api::enc(&name))).await {
                                    Ok(r) => {
                                        toast(trf("„{0}“ entfernt ({1} Einträge).", &[&name, &r.removed]));
                                        on_change.call(());
                                    }
                                    Err(e) => toast_error(e),
                                }
                            });
                        },
                        icons::Trash2 {}
                    }
                }
            }
        }
    }
}
