//! Geräte im Netzwerk: wer nrzNetwork in den letzten Tagen gefragt hat, mit eigenen Namen.

use crate::Route;
use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::state;
use crate::ui::table::*;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{Device, DeviceNameInput};

#[component]
pub fn Devices() -> Element {
    let admin = state::is_admin();
    let mut days = use_signal(|| "7".to_string());
    let mut version = use_signal(|| 0u64);
    let mut q = use_signal(String::new);
    let list = use_resource(move || async move {
        let _ = version();
        api::get::<Vec<Device>>(&format!("/devices?days={}", days())).await
    });
    let mut editing = use_signal(|| None::<Device>);
    let mut name = use_signal(String::new);
    let mut open = use_signal(|| false);
    let save = move |e: FormEvent| {
        e.prevent_default();
        let Some(d) = editing() else { return };
        spawn(async move {
            let res = api::put::<Device, _>(
                &format!("/devices/{}", api::enc(&d.ip)),
                &DeviceNameInput {
                    name: name().trim().to_string(),
                },
            )
            .await;
            match res {
                Ok(_) => {
                    open.set(false);
                    version += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };
    let filter = q().trim().to_lowercase();
    rsx! {
        PageHeader { title: tr("Geräte"), description: tr("Alle Geräte, die nrzNetwork als DNS-Server benutzen – gib ihnen Namen, damit du sie wiedererkennst.") }
        Section {
            title: tr("Geräte im Netzwerk"),
            actions: rsx! {
                Segmented {
                    options: vec![("1".to_string(), tr("24 h")), ("7".to_string(), tr("7 Tage")), ("30".to_string(), tr("30 Tage"))],
                    value: days(),
                    onchange: move |v| days.set(v),
                }
            },
            match &*list.read() {
                None => rsx! { Loading {} },
                Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
                Some(Ok(items)) if items.is_empty() => rsx! {
                    div { class: "rounded-lg border border-dashed px-4 py-8 text-center text-sm text-muted-foreground",
                        {tr("Noch keine Geräte. Sobald Geräte nrzNetwork als DNS-Server benutzen, erscheinen sie hier.")}
                    }
                },
                Some(Ok(items)) => {
                    let shown: Vec<Device> = items
                        .iter()
                        .filter(|d| filter.is_empty() || d.ip.contains(&filter) || d.name.to_lowercase().contains(&filter) || d.netbird_name.to_lowercase().contains(&filter))
                        .cloned()
                        .collect();
                    rsx! {
                        div { class: "mb-3 flex flex-wrap items-center justify-between gap-2",
                            SearchInput { value: q(), oninput: move |v| q.set(v), placeholder: tr("Name oder IP …") }
                            span { class: "text-xs text-muted-foreground", {trf("{0} Geräte", &[&items.len().to_string()])} }
                        }
                        TableWrapper {
                            Table {
                                TableHeader {
                                    tr {
                                        TableHead { {tr("Gerät")} }
                                        TableHead { class: "text-right", {tr("Anfragen")} }
                                        TableHead { class: "hidden text-right sm:table-cell", {tr("Gesperrt")} }
                                        TableHead { class: "hidden md:table-cell", {tr("Zuletzt")} }
                                        TableHead { class: "w-20" }
                                    }
                                }
                                TableBody {
                                    for d in shown {
                                        TableRow { key: "{d.ip}",
                                            TableCell {
                                                if d.name.is_empty() && d.netbird_name.is_empty() {
                                                    span { class: "font-mono text-[13px]", "{d.ip}" }
                                                } else {
                                                    p { class: "font-medium",
                                                        if d.name.is_empty() { "{d.netbird_name}" } else { "{d.name}" }
                                                        if !d.netbird_name.is_empty() {
                                                            span { class: "ml-1.5 inline-flex items-center gap-1 rounded-full border px-1.5 text-[11px] font-normal text-muted-foreground", title: tr("Name in NetBird"),
                                                                icons::Waypoints { class: "size-3" }
                                                                if d.name.is_empty() { "NetBird" } else { "{d.netbird_name}" }
                                                            }
                                                        }
                                                    }
                                                    p { class: "font-mono text-xs text-muted-foreground", "{d.ip}" }
                                                }
                                            }
                                            TableCell { class: "text-right tabular-nums", "{util::num(d.queries)}" }
                                            TableCell { class: "hidden text-right tabular-nums text-muted-foreground sm:table-cell",
                                                {format!("{} ({:.0} %)", util::num(d.blocked), if d.queries == 0 { 0.0 } else { d.blocked as f64 * 100.0 / d.queries as f64 })}
                                            }
                                            TableCell { class: "hidden whitespace-nowrap text-muted-foreground md:table-cell", title: util::datetime(d.last_seen), "{util::relative(d.last_seen)}" }
                                            TableCell { class: "px-2 text-right whitespace-nowrap",
                                                Link { class: icon_btn(""), title: tr("Abfragen dieses Geräts"),
                                                    to: Route::logs_filtered(&d.ip, "", "", "", ""),
                                                    icons::ScrollText {}
                                                }
                                                if admin {
                                                    button { class: icon_btn(""), title: tr("Name ändern"),
                                                        onclick: {
                                                            let d = d.clone();
                                                            move |_| {
                                                                name.set(d.name.clone());
                                                                editing.set(Some(d.clone()));
                                                                open.set(true);
                                                            }
                                                        },
                                                        icons::Pencil {}
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
        Modal { open, title: tr("Gerätename"), description: editing().map(|d| d.ip).unwrap_or_default(),
            form { class: "grid grid-cols-1 gap-4", onsubmit: save,
                Field { label: tr("Name"), hint: tr("Leer = Name entfernen."),
                    input { class: INPUT, maxlength: 60, value: "{name}", placeholder: tr("z. B. Laptop Nico"), oninput: move |e| name.set(e.value()) }
                }
                div { class: "flex justify-end gap-2",
                    button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| open.set(false), {tr("Abbrechen")} }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", {tr("Speichern")} }
                }
            }
        }
    }
}
