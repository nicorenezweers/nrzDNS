//! Ausnahmen: Domains, die nie gesperrt werden – sie schlagen jede Sperrliste und eigene Sperre.

use crate::api;
use crate::components::common::*;
use crate::components::domains::DomainList;
use crate::components::overlay::*;
use crate::i18n::tr;
use crate::i18n::trf;
use crate::state;
use crate::ui::alert::{Alert, AlertDescription, AlertTitle};
use crate::ui::table::*;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{AllowRequest, RequestStatus, TempUnlock};

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
            Requests {}
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

/// Anträge von der Sperrseite (offene zuerst) und gerade freigeschaltete Domains.
#[component]
fn Requests() -> Element {
    let admin = state::is_admin();
    let mut version = use_signal(|| 0u64);
    let requests = use_resource(move || async move {
        let _ = version();
        api::get::<Vec<AllowRequest>>("/requests").await
    });
    let unlocks = use_resource(move || async move {
        let _ = version();
        api::get::<Vec<TempUnlock>>("/unlocks").await
    });
    let decide = move |id: i64, action: &'static str| {
        spawn(async move {
            match api::action::<AllowRequest>(&format!("/requests/{id}/{action}")).await {
                Ok(r) => {
                    if r.status == RequestStatus::Approved {
                        toast(trf("„{0}“ ist jetzt eine Ausnahme.", &[&r.domain]));
                    } else {
                        toast(trf("Antrag für „{0}“ abgelehnt.", &[&r.domain]));
                    }
                    version += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };
    let reqs = match &*requests.read() {
        Some(Ok(r)) => r.clone(),
        _ => Vec::new(),
    };
    let active = match &*unlocks.read() {
        Some(Ok(u)) => u.clone(),
        _ => Vec::new(),
    };
    let pending = reqs
        .iter()
        .filter(|r| r.status == RequestStatus::Pending)
        .count();
    rsx! {
        Section {
            title: tr("Anträge von der Sperrseite"),
            description: if pending == 0 { tr("Keine offenen Anträge.") } else { trf("{0} offene Anträge – genehmigen macht die Domain zur Ausnahme.", &[&pending.to_string()]) },
            if reqs.is_empty() {
                div { class: "rounded-lg border border-dashed px-4 py-6 text-center text-sm text-muted-foreground", {tr("Noch keine Anträge. Wer auf der Sperrseite landet, kann hier eine Freigabe beantragen.")} }
            } else {
                TableWrapper {
                    Table {
                        TableHeader {
                            tr {
                                TableHead { {tr("Domain")} }
                                TableHead { class: "hidden sm:table-cell", {tr("Begründung")} }
                                TableHead { class: "hidden md:table-cell", {tr("Von")} }
                                TableHead { {tr("Status")} }
                                if admin { TableHead { class: "w-40" } }
                            }
                        }
                        TableBody {
                            for r in reqs.into_iter().take(50) {
                                TableRow { key: "{r.id}",
                                    TableCell { class: "font-mono text-[13px] break-all",
                                        "{r.domain}"
                                        p { class: "font-sans text-xs text-muted-foreground", title: util::datetime(r.created_at), "{util::relative(r.created_at)}" }
                                    }
                                    TableCell { class: "hidden whitespace-pre-line text-muted-foreground sm:table-cell", "{r.reason}" }
                                    TableCell { class: "hidden font-mono text-[13px] text-muted-foreground md:table-cell", "{r.client}" }
                                    TableCell {
                                        match r.status {
                                            RequestStatus::Pending => rsx! { span { class: "text-amber-500", {tr("offen")} } },
                                            RequestStatus::Approved => rsx! { span { class: "text-emerald-500", title: "{r.decided_by}", {tr("genehmigt")} } },
                                            RequestStatus::Rejected => rsx! { span { class: "text-muted-foreground", title: "{r.decided_by}", {tr("abgelehnt")} } },
                                        }
                                    }
                                    if admin {
                                        TableCell { class: "px-2 text-right whitespace-nowrap",
                                            if r.status == RequestStatus::Pending {
                                                button { class: btn_sm(BTN_PRIMARY), onclick: { let id = r.id; move |_| decide(id, "approve") }, {tr("Genehmigen")} }
                                                button { class: "{btn_sm(BTN_GHOST)} ml-1", onclick: { let id = r.id; move |_| decide(id, "reject") }, {tr("Ablehnen")} }
                                            } else {
                                                button {
                                                    class: icon_btn("hover:text-destructive"),
                                                    title: tr("Entfernen"),
                                                    onclick: {
                                                        let id = r.id;
                                                        move |_| {
                                                            spawn(async move {
                                                                match api::delete(&format!("/requests/{id}")).await {
                                                                    Ok(()) => version += 1,
                                                                    Err(e) => toast_error(e),
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
        if !active.is_empty() {
            Section { title: tr("Gerade freigeschaltet"), description: tr("Über die Sperrseite auf Zeit freigeschaltet; endet von selbst."),
                TableWrapper {
                    Table {
                        TableHeader {
                            tr {
                                TableHead { {tr("Domain")} }
                                TableHead { {tr("Bis")} }
                                TableHead { class: "hidden md:table-cell", {tr("Von")} }
                                if admin { TableHead { class: "w-10" } }
                            }
                        }
                        TableBody {
                            for u in active {
                                TableRow { key: "{u.domain}",
                                    TableCell { class: "font-mono text-[13px] break-all", "{u.domain}" }
                                    TableCell { class: "whitespace-nowrap text-muted-foreground", "{util::datetime(u.until)}" }
                                    TableCell { class: "hidden font-mono text-[13px] text-muted-foreground md:table-cell", "{u.client}" }
                                    if admin {
                                        TableCell { class: "px-2 text-right",
                                            button {
                                                class: icon_btn("hover:text-destructive"),
                                                title: tr("Freischaltung beenden"),
                                                onclick: {
                                                    let d = u.domain.clone();
                                                    move |_| {
                                                        let d = d.clone();
                                                        spawn(async move {
                                                            match api::delete(&format!("/unlocks/{}", api::enc(&d))).await {
                                                                Ok(()) => {
                                                                    toast(trf("„{0}“ ist wieder gesperrt.", &[&d]));
                                                                    version += 1;
                                                                }
                                                                Err(e) => toast_error(e),
                                                            }
                                                        });
                                                    }
                                                },
                                                icons::X {}
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
