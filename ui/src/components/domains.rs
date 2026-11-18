//! Eigene Domainliste (eigene Sperren unter Sperren, Ausnahmen): hinzufügen mit Kommentar,
//! durchsuchen, löschen. Jeder Eintrag gilt für die Domain und alle Subdomains.

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::state;
use crate::ui::table::*;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{DomainEntry, DomainInput, normalize_domain};

/// `base` ist der API-Pfad (`/blocked` oder `/allowed`).
#[component]
pub fn DomainList(
    base: &'static str,
    #[props(into)] title: String,
    #[props(into)] description: String,
    #[props(into)] empty: String,
    #[props(into)] add_label: String,
) -> Element {
    let admin = state::is_admin();
    let mut version = use_signal(|| 0u64);
    let list = use_resource(move || async move {
        let _ = version();
        api::get::<Vec<DomainEntry>>(base).await
    });
    let mut q = use_signal(String::new);
    let mut domain = use_signal(String::new);
    let mut comment = use_signal(String::new);
    let mut busy = use_signal(|| false);

    let add = move |e: FormEvent| {
        e.prevent_default();
        let Some(d) = normalize_domain(&domain()) else {
            toast_error(tr("Das ist keine gültige Domain (z. B. ads.example.com)."));
            return;
        };
        spawn(async move {
            busy.set(true);
            let res = api::post::<DomainEntry, _>(
                base,
                &DomainInput {
                    domain: d,
                    comment: comment().trim().to_string(),
                },
            )
            .await;
            busy.set(false);
            match res {
                Ok(entry) => {
                    toast(trf("„{0}“ hinzugefügt.", &[&entry.domain]));
                    domain.set(String::new());
                    comment.set(String::new());
                    version += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };

    let filter = q().trim().to_lowercase();
    rsx! {
        Section { title, description,
            div { class: "grid grid-cols-1 gap-4",
                if admin {
                    form { class: "grid grid-cols-1 gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]", onsubmit: add,
                        input {
                            class: "{INPUT} font-mono text-[13px]",
                            required: true,
                            spellcheck: false,
                            autocapitalize: "none",
                            "aria-label": tr("Domain"),
                            placeholder: tr("Domain, z. B. ads.example.com"),
                            value: "{domain}",
                            oninput: move |e| domain.set(e.value()),
                        }
                        input {
                            class: INPUT,
                            maxlength: 200,
                            "aria-label": tr("Kommentar"),
                            placeholder: tr("Kommentar (optional)"),
                            value: "{comment}",
                            oninput: move |e| comment.set(e.value()),
                        }
                        button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy() || domain().trim().is_empty(),
                            icons::Plus {}
                            "{add_label}"
                        }
                    }
                }
                match &*list.read() {
                    None => rsx! { Loading {} },
                    Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
                    Some(Ok(items)) if items.is_empty() => rsx! {
                        div { class: "rounded-lg border border-dashed px-4 py-8 text-center text-sm text-muted-foreground", "{empty}" }
                    },
                    Some(Ok(items)) => {
                        let shown: Vec<DomainEntry> = items
                            .iter()
                            .filter(|d| filter.is_empty() || d.domain.contains(&filter) || d.comment.to_lowercase().contains(&filter))
                            .cloned()
                            .collect();
                        let total = items.len();
                        rsx! {
                            div { class: "flex flex-wrap items-center justify-between gap-2",
                                SearchInput { value: q(), oninput: move |v| q.set(v), placeholder: tr("Domains durchsuchen …") }
                                span { class: "text-xs text-muted-foreground",
                                    if shown.len() == total {
                                        {trf("{0} Einträge", &[&util::num(total as u64)])}
                                    } else {
                                        {trf("{0} von {1} Einträgen", &[&util::num(shown.len() as u64), &util::num(total as u64)])}
                                    }
                                }
                            }
                            TableWrapper {
                                Table {
                                    TableHeader {
                                        tr {
                                            TableHead { {tr("Domain")} }
                                            TableHead { class: "hidden sm:table-cell", {tr("Kommentar")} }
                                            TableHead { class: "hidden md:table-cell", {tr("Hinzugefügt")} }
                                            if admin {
                                                TableHead { class: "w-10" }
                                            }
                                        }
                                    }
                                    TableBody {
                                        if shown.is_empty() {
                                            tr {
                                                td { class: "px-3 py-6 text-center text-muted-foreground", colspan: "4", {tr("Keine Treffer.")} }
                                            }
                                        }
                                        for d in shown {
                                            TableRow { key: "{d.domain}",
                                                TableCell { class: "font-mono text-[13px] break-all",
                                                    "{d.domain}"
                                                    if !d.comment.is_empty() {
                                                        p { class: "font-sans text-xs text-muted-foreground sm:hidden", "{d.comment}" }
                                                    }
                                                }
                                                TableCell { class: "hidden text-muted-foreground sm:table-cell", "{d.comment}" }
                                                TableCell { class: "hidden whitespace-nowrap text-muted-foreground md:table-cell", title: util::datetime(d.created_at), "{util::relative(d.created_at)}" }
                                                if admin {
                                                    TableCell { class: "px-2 text-right",
                                                        button {
                                                            class: icon_btn("hover:text-destructive"),
                                                            title: tr("Entfernen"),
                                                            onclick: {
                                                                let name = d.domain.clone();
                                                                move |_| {
                                                                    let name = name.clone();
                                                                    spawn(async move {
                                                                        let ask = Ask::new(trf("„{0}“ entfernen?", &[&name]), tr("Der Eintrag gilt dann nicht mehr – auch nicht für Subdomains."))
                                                                            .confirm(tr("Entfernen"))
                                                                            .destructive();
                                                                        if confirm(ask).await {
                                                                            match api::delete(&format!("{base}/{}", api::enc(&name))).await {
                                                                                Ok(()) => {
                                                                                    toast(trf("„{0}“ entfernt.", &[&name]));
                                                                                    version += 1;
                                                                                }
                                                                                Err(e) => toast_error(e),
                                                                            }
                                                                        }
                                                                    });
                                                                }
                                                            },
                                                            icons::Trash2 {}
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
