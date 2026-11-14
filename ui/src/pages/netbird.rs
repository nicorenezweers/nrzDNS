//! Das ganze NetBird-Netzwerk: Geräte, Gruppen, Zugriffsregeln, Netzwerke, DNS, Setup-Keys
//! und Benutzer – über `/api/v1/netbird/…` (Token bleibt auf dem Server).

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::json::{ConnectHint, Dot, GroupPicker, b, ids, list, n, names, relative_or, s, ts};
use crate::state;
use crate::ui::table::*;
use dioxus::prelude::*;
use nrzdns_types::{IntegrationsStatus, ProxyStatus};
use serde_json::{Value, json};

type Groups = Vec<(String, String)>;

#[component]
pub fn Netbird() -> Element {
    let status = use_resource(|| async { api::get::<IntegrationsStatus>("/integrations").await });
    rsx! {
        PageHeader { title: tr("NetBird"), description: tr("Dein ganzes NetBird-Netzwerk: Geräte, Gruppen, wer worauf zugreifen darf, Netzwerke, DNS, Setup-Keys und Benutzer.") }
        match &*status.read() {
            None => rsx! { Loading {} },
            Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
            Some(Ok(st)) if !st.netbird.configured => rsx! {
                ConnectHint { service: "NetBird", text: tr("Erstelle in NetBird unter Einstellungen → Persönliche Zugangstoken ein Token und trage es unter Einstellungen → Verbindungen ein.") }
            },
            Some(Ok(st)) => rsx! { Main { url: st.netbird_url.clone() } },
        }
    }
}

#[component]
fn Main(url: String) -> Element {
    let mut tab = use_signal(|| "peers".to_string());
    let version = use_signal(|| 0u64);
    let groups_res = use_resource(move || async move {
        let _ = version();
        api::get::<Value>("/netbird/groups").await
    });
    let peers_res = use_resource(move || async move {
        let _ = version();
        api::get::<Value>("/netbird/peers").await
    });
    let groups_v = match &*groups_res.read() {
        Some(Ok(v)) => v.clone(),
        _ => Value::Null,
    };
    let peers_v = match &*peers_res.read() {
        Some(Ok(v)) => v.clone(),
        _ => Value::Null,
    };
    let groups: Groups = {
        let mut g: Groups = list(&groups_v)
            .iter()
            .map(|g| (s(g, "id"), s(g, "name")))
            .collect();
        g.sort_by_key(|x| (x.1 != "All", x.1.to_lowercase()));
        g
    };
    let peers: Groups = list(&peers_v)
        .iter()
        .map(|p| (s(p, "id"), s(p, "name")))
        .collect();
    let online = list(&peers_v).iter().filter(|p| b(p, "connected")).count();
    let err = match (&*groups_res.read(), &*peers_res.read()) {
        (Some(Err(e)), _) | (_, Some(Err(e))) => Some(e.message.clone()),
        _ => None,
    };
    rsx! {
        div { class: "grid grid-cols-1 gap-6",
            if let Some(e) = err {
                Callout { text: e, error: true }
            }
            div { class: "grid grid-cols-2 gap-3 sm:grid-cols-4",
                StatCard { label: tr("Geräte"), value: list(&peers_v).len().to_string() }
                StatCard { label: tr("Online"), value: online.to_string() }
                StatCard { label: tr("Gruppen"), value: groups.len().to_string() }
                StatCard { label: tr("Verwaltung"), value: if url.is_empty() { "NetBird Cloud".to_string() } else { url.clone() } }
            }
            div { class: "overflow-x-auto",
                Segmented {
                    options: vec![
                        ("peers".to_string(), tr("Geräte")),
                        ("groups".to_string(), tr("Gruppen")),
                        ("access".to_string(), tr("Zugriff")),
                        ("networks".to_string(), tr("Netzwerke")),
                        ("dns".to_string(), tr("DNS")),
                        ("services".to_string(), tr("Freigaben")),
                        ("keys".to_string(), tr("Setup-Keys")),
                        ("users".to_string(), tr("Benutzer")),
                    ],
                    value: tab(),
                    onchange: move |v| tab.set(v),
                }
            }
            match tab().as_str() {
                "groups" => rsx! { GroupsTab { groups_v: groups_v.clone(), peers: peers.clone(), version } },
                "access" => rsx! { AccessTab { groups: groups.clone(), version } },
                "networks" => rsx! { NetworksTab { groups: groups.clone(), peers: peers.clone(), version } },
                "dns" => rsx! { DnsTab { groups: groups.clone(), version } },
                "services" => rsx! { ServicesTab { groups: groups.clone(), peers: peers.clone(), version } },
                "keys" => rsx! { KeysTab { groups: groups.clone(), url: url.clone(), version } },
                "users" => rsx! { UsersTab { groups: groups.clone(), version } },
                _ => rsx! { PeersTab { peers_v: peers_v.clone(), groups_v: groups_v.clone(), loading: peers_res.read().is_none(), version } },
            }
        }
    }
}

fn group_names(v: &Value) -> Vec<String> {
    let mut n = names(v);
    n.retain(|x| x != "All");
    n
}

fn name_of(groups: &Groups, id: &str) -> String {
    groups
        .iter()
        .find(|g| g.0 == id)
        .map(|g| g.1.clone())
        .unwrap_or_else(|| id.to_string())
}

async fn run(
    method: &'static str,
    path: String,
    body: Value,
    ok: String,
    mut version: Signal<u64>,
) -> bool {
    let res = if method == "DELETE" {
        api::delete(&path).await.map(|_| Value::Null)
    } else {
        api::send::<Value, _>(method, &path, &body).await
    };
    match res {
        Ok(_) => {
            if !ok.is_empty() {
                toast(ok);
            }
            version += 1;
            true
        }
        Err(e) => {
            toast_error(e);
            false
        }
    }
}

async fn ask_delete(what: String, detail: String) -> bool {
    confirm(
        Ask::new(trf("„{0}“ löschen?", &[&what]), detail)
            .confirm(tr("Löschen"))
            .destructive(),
    )
    .await
}

// ------------------------------------------------------------------ Geräte

#[component]
fn PeersTab(peers_v: Value, groups_v: Value, loading: bool, version: Signal<u64>) -> Element {
    let admin = state::is_admin();
    let mut q = use_signal(String::new);
    let mut open = use_signal(|| false);
    let mut edit = use_signal(|| Value::Null);
    let mut name = use_signal(String::new);
    let mut ssh = use_signal(|| false);
    let mut login_exp = use_signal(|| false);
    let mut inactivity = use_signal(|| false);
    let mut sel = use_signal(Vec::<String>::new);
    let groups: Groups = list(&groups_v)
        .iter()
        .filter(|g| s(g, "name") != "All")
        .map(|g| (s(g, "id"), s(g, "name")))
        .collect();
    let gv = groups_v.clone();
    let save = move |e: FormEvent| {
        e.prevent_default();
        let p = edit();
        let gv = gv.clone();
        spawn(async move {
            let id = s(&p, "id");
            let body = json!({
                "name": name().trim(),
                "ssh_enabled": ssh(),
                "login_expiration_enabled": login_exp(),
                "inactivity_expiration_enabled": inactivity(),
            });
            if !run(
                "PUT",
                format!("/netbird/peers/{id}"),
                body,
                String::new(),
                version,
            )
            .await
            {
                return;
            }
            // Gruppen: nur die geänderten Gruppen neu schreiben
            let before = ids(&p["groups"]);
            let after = sel();
            for g in list(&gv) {
                let gid = s(&g, "id");
                if s(&g, "name") == "All" {
                    continue;
                }
                let was = before.contains(&gid);
                let is = after.contains(&gid);
                if was == is {
                    continue;
                }
                let mut members = ids(&g["peers"]);
                if is {
                    members.push(id.clone());
                } else {
                    members.retain(|x| *x != id);
                }
                let resources: Vec<Value> = list(&g["resources"])
                    .iter()
                    .map(|r| json!({ "id": s(r, "id"), "type": s(r, "type") }))
                    .collect();
                let body =
                    json!({ "name": s(&g, "name"), "peers": members, "resources": resources });
                run(
                    "PUT",
                    format!("/netbird/groups/{gid}"),
                    body,
                    String::new(),
                    version,
                )
                .await;
            }
            toast(tr("Gespeichert."));
            open.set(false);
        });
    };
    let filter = q().trim().to_lowercase();
    let mut rows = list(&peers_v);
    rows.sort_by_key(|p| (!b(p, "connected"), s(p, "name").to_lowercase()));
    let rows: Vec<Value> = rows
        .into_iter()
        .filter(|p| {
            filter.is_empty()
                || [
                    s(p, "name"),
                    s(p, "ip"),
                    s(p, "dns_label"),
                    s(p, "hostname"),
                    s(p, "os"),
                ]
                .iter()
                .any(|x| x.to_lowercase().contains(&filter))
        })
        .collect();
    rsx! {
        Section { title: tr("Geräte"), description: tr("Alle Geräte im NetBird-Netz, online zuerst."),
            div { class: "mb-3", SearchInput { value: q(), oninput: move |v| q.set(v), placeholder: tr("Name, IP, System …") } }
            if loading { Loading {} } else {
                TableWrapper {
                    Table {
                        TableHeader { tr {
                            TableHead { {tr("Gerät")} }
                            TableHead { {tr("NetBird-IP")} }
                            TableHead { class: "hidden md:table-cell", {tr("System")} }
                            TableHead { class: "hidden lg:table-cell", {tr("Gruppen")} }
                            TableHead { class: "hidden sm:table-cell", {tr("Zuletzt")} }
                            if admin { TableHead { class: "w-20" } }
                        } }
                        TableBody {
                            for p in rows {
                                {
                                    let id = s(&p, "id");
                                    let pe = p.clone();
                                    let pname = s(&p, "name");
                                    let seen = ts(&p, "last_seen");
                                    let gn = group_names(&p["groups"]);
                                    rsx! {
                                        TableRow { key: "{id}",
                                            TableCell {
                                                div { class: "flex items-center gap-2",
                                                    Dot { on: b(&p, "connected") }
                                                    div {
                                                        p { class: "font-medium", "{pname}" }
                                                        p { class: "font-mono text-xs text-muted-foreground break-all", {s(&p, "dns_label").to_string()} }
                                                    }
                                                }
                                            }
                                            TableCell { class: "font-mono text-[13px]", {s(&p, "ip").to_string()} }
                                            TableCell { class: "hidden text-muted-foreground md:table-cell",
                                                {s(&p, "os").to_string()}
                                                p { class: "text-xs", {s(&p, "version").to_string()} }
                                            }
                                            TableCell { class: "hidden lg:table-cell",
                                                div { class: "flex flex-wrap gap-1", for g in gn { Pill { key: "{g}", "{g}" } } }
                                            }
                                            TableCell { class: "hidden whitespace-nowrap text-muted-foreground sm:table-cell",
                                                if b(&p, "connected") { {tr("jetzt")} } else { {relative_or(seen, "–")} }
                                            }
                                            if admin {
                                                TableCell { class: "px-2 text-right whitespace-nowrap",
                                                    button { class: icon_btn(""), title: tr("Bearbeiten"),
                                                        onclick: move |_| {
                                                            name.set(s(&pe, "name"));
                                                            ssh.set(b(&pe, "ssh_enabled"));
                                                            login_exp.set(b(&pe, "login_expiration_enabled"));
                                                            inactivity.set(b(&pe, "inactivity_expiration_enabled"));
                                                            sel.set(ids(&pe["groups"]));
                                                            edit.set(pe.clone());
                                                            open.set(true);
                                                        },
                                                        icons::Pencil {}
                                                    }
                                                    button { class: icon_btn("hover:text-destructive"), title: tr("Entfernen"),
                                                        onclick: move |_| {
                                                            let (id, pname) = (id.clone(), pname.clone());
                                                            spawn(async move {
                                                                if ask_delete(pname, tr("Das Gerät fliegt aus dem Netz und muss sich neu anmelden.")).await {
                                                                    run("DELETE", format!("/netbird/peers/{id}"), Value::Null, tr("Entfernt."), version).await;
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
                            }
                        }
                    }
                }
            }
        }
        Modal { open, title: tr("Gerät bearbeiten"), description: s(&edit(), "ip"),
            form { class: "grid grid-cols-1 gap-4", onsubmit: save,
                Field { label: tr("Name"),
                    input { class: INPUT, required: true, value: "{name}", oninput: move |e| name.set(e.value()) }
                }
                Field { label: tr("Gruppen"), GroupPicker { groups: groups.clone(), selected: sel } }
                Toggle { checked: ssh(), onchange: move |v| ssh.set(v), label: tr("SSH über NetBird erlauben") }
                Toggle { checked: login_exp(), onchange: move |v| login_exp.set(v), label: tr("Anmeldung läuft ab"), hint: tr("Das Gerät muss sich regelmässig neu anmelden.") }
                Toggle { checked: inactivity(), onchange: move |v| inactivity.set(v), label: tr("Bei Inaktivität abmelden") }
                div { class: "flex justify-end gap-2",
                    button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| open.set(false), {tr("Abbrechen")} }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", {tr("Speichern")} }
                }
            }
        }
    }
}

// ------------------------------------------------------------------ Gruppen

#[component]
fn GroupsTab(groups_v: Value, peers: Groups, version: Signal<u64>) -> Element {
    let admin = state::is_admin();
    let mut open = use_signal(|| false);
    let mut edit = use_signal(|| Value::Null);
    let mut name = use_signal(String::new);
    let mut sel = use_signal(Vec::<String>::new);
    let save = move |e: FormEvent| {
        e.prevent_default();
        let g = edit();
        spawn(async move {
            let resources: Vec<Value> = list(&g["resources"])
                .iter()
                .map(|r| json!({ "id": s(r, "id"), "type": s(r, "type") }))
                .collect();
            let body = json!({ "name": name().trim(), "peers": sel(), "resources": resources });
            let id = s(&g, "id");
            let ok = if id.is_empty() {
                run(
                    "POST",
                    "/netbird/groups".into(),
                    body,
                    tr("Gruppe angelegt."),
                    version,
                )
                .await
            } else {
                run(
                    "PUT",
                    format!("/netbird/groups/{id}"),
                    body,
                    tr("Gespeichert."),
                    version,
                )
                .await
            };
            if ok {
                open.set(false);
            }
        });
    };
    let mut rows = list(&groups_v);
    rows.sort_by_key(|g| (s(g, "name") != "All", s(g, "name").to_lowercase()));
    rsx! {
        Section { title: tr("Gruppen"), description: tr("Gruppen fassen Geräte zusammen – Zugriffsregeln, DNS und Netzwerke beziehen sich auf sie."),
            actions: rsx! {
                if admin {
                    button { class: btn_sm(BTN_PRIMARY), onclick: move |_| { edit.set(Value::Null); name.set(String::new()); sel.set(Vec::new()); open.set(true); },
                        icons::Plus {} {tr("Gruppe")}
                    }
                }
            },
            TableWrapper { Table {
                TableHeader { tr {
                    TableHead { {tr("Name")} }
                    TableHead { {tr("Geräte")} }
                    TableHead { class: "hidden sm:table-cell", {tr("Ressourcen")} }
                    TableHead { class: "hidden md:table-cell", {tr("Herkunft")} }
                    if admin { TableHead { class: "w-20" } }
                } }
                TableBody {
                    for g in rows {
                        {
                            let id = s(&g, "id");
                            let gname = s(&g, "name");
                            let all = gname == "All";
                            let ge = g.clone();
                            let members = names(&g["peers"]).join(", ");
                            rsx! {
                                TableRow { key: "{id}",
                                    TableCell { class: "font-medium", "{gname}" }
                                    TableCell { title: "{members}", {n(&g, "peers_count").to_string()} }
                                    TableCell { class: "hidden sm:table-cell", {n(&g, "resources_count").to_string()} }
                                    TableCell { class: "hidden text-muted-foreground md:table-cell", {s(&g, "issued").to_string()} }
                                    if admin {
                                        TableCell { class: "px-2 text-right whitespace-nowrap",
                                            if !all {
                                                button { class: icon_btn(""), title: tr("Bearbeiten"),
                                                    onclick: move |_| { name.set(s(&ge, "name")); sel.set(ids(&ge["peers"])); edit.set(ge.clone()); open.set(true); },
                                                    icons::Pencil {}
                                                }
                                                button { class: icon_btn("hover:text-destructive"), title: tr("Löschen"),
                                                    onclick: move |_| {
                                                        let (id, gname) = (id.clone(), gname.clone());
                                                        spawn(async move {
                                                            if ask_delete(gname, tr("Regeln und Einstellungen, die diese Gruppe benutzen, verlieren sie.")).await {
                                                                run("DELETE", format!("/netbird/groups/{id}"), Value::Null, tr("Gelöscht."), version).await;
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
                        }
                    }
                }
            } }
        }
        Modal { open, title: if s(&edit(), "id").is_empty() { tr("Neue Gruppe") } else { tr("Gruppe bearbeiten") },
            form { class: "grid grid-cols-1 gap-4", onsubmit: save,
                Field { label: tr("Name"), input { class: INPUT, required: true, maxlength: 60, value: "{name}", oninput: move |e| name.set(e.value()) } }
                Field { label: tr("Geräte"), GroupPicker { groups: peers.clone(), selected: sel } }
                div { class: "flex justify-end gap-2",
                    button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| open.set(false), {tr("Abbrechen")} }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", {tr("Speichern")} }
                }
            }
        }
    }
}

// ------------------------------------------------------------------ Zugriff (Policies)

/// Policy für PUT/POST aufbereiten (Antworten enthalten Gruppen als Objekte, Anfragen IDs).
fn policy_body(p: &Value, enabled: bool) -> Value {
    let rules: Vec<Value> = list(&p["rules"])
        .iter()
        .map(|r| {
            let mut out = json!({
                "id": s(r, "id"),
                "name": s(r, "name"),
                "description": s(r, "description"),
                "enabled": b(r, "enabled"),
                "action": if s(r, "action").is_empty() { "accept".to_string() } else { s(r, "action") },
                "bidirectional": b(r, "bidirectional"),
                "protocol": s(r, "protocol"),
            });
            if !r["sources"].is_null() { out["sources"] = json!(ids(&r["sources"])); }
            if !r["destinations"].is_null() { out["destinations"] = json!(ids(&r["destinations"])); }
            for k in ["ports", "port_ranges", "sourceResource", "destinationResource"] {
                if !r[k].is_null() { out[k] = r[k].clone(); }
            }
            out
        })
        .collect();
    json!({
        "name": s(p, "name"),
        "description": s(p, "description"),
        "enabled": enabled,
        "source_posture_checks": p["source_posture_checks"].as_array().cloned().unwrap_or_default(),
        "rules": rules,
    })
}

#[component]
fn AccessTab(groups: Groups, version: Signal<u64>) -> Element {
    let admin = state::is_admin();
    let res = use_resource(move || async move {
        let _ = version();
        api::get::<Value>("/netbird/policies").await
    });
    let mut open = use_signal(|| false);
    let mut edit = use_signal(|| Value::Null);
    let mut name = use_signal(String::new);
    let mut src = use_signal(Vec::<String>::new);
    let mut dst = use_signal(Vec::<String>::new);
    let mut proto = use_signal(|| "all".to_string());
    let mut ports = use_signal(String::new);
    let mut bidi = use_signal(|| true);
    let save = move |e: FormEvent| {
        e.prevent_default();
        let p = edit();
        spawn(async move {
            let mut rule = json!({
                "name": name().trim(),
                "enabled": true,
                "action": "accept",
                "bidirectional": bidi(),
                "protocol": proto(),
                "sources": src(),
                "destinations": dst(),
            });
            let first = list(&p["rules"]).into_iter().next().unwrap_or(Value::Null);
            if !s(&first, "id").is_empty() {
                rule["id"] = json!(s(&first, "id"));
            }
            let pl: Vec<String> = ports()
                .split([',', ' '])
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .collect();
            if matches!(proto().as_str(), "tcp" | "udp") && !pl.is_empty() {
                rule["ports"] = json!(pl);
            }
            let body = json!({ "name": name().trim(), "description": s(&p, "description"), "enabled": if p.is_null() { true } else { b(&p, "enabled") }, "rules": [rule] });
            let id = s(&p, "id");
            let ok = if id.is_empty() {
                run(
                    "POST",
                    "/netbird/policies".into(),
                    body,
                    tr("Regel angelegt."),
                    version,
                )
                .await
            } else {
                run(
                    "PUT",
                    format!("/netbird/policies/{id}"),
                    body,
                    tr("Gespeichert."),
                    version,
                )
                .await
            };
            if ok {
                open.set(false);
            }
        });
    };
    let gs = groups.clone();
    rsx! {
        Section { title: tr("Zugriff"), description: tr("Wer darf mit wem sprechen? Ohne passende Regel erreichen sich Geräte nicht."),
            actions: rsx! {
                if admin {
                    button { class: btn_sm(BTN_PRIMARY),
                        onclick: move |_| { edit.set(Value::Null); name.set(String::new()); src.set(Vec::new()); dst.set(Vec::new()); proto.set("all".into()); ports.set(String::new()); bidi.set(true); open.set(true); },
                        icons::Plus {} {tr("Regel")}
                    }
                }
            },
            match &*res.read() {
                None => rsx! { Loading {} },
                Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
                Some(Ok(v)) => rsx! {
                    TableWrapper { Table {
                        TableHeader { tr {
                            TableHead { class: "w-14", {tr("An")} }
                            TableHead { {tr("Regel")} }
                            TableHead { {tr("Von → Nach")} }
                            TableHead { class: "hidden md:table-cell", {tr("Protokoll")} }
                            if admin { TableHead { class: "w-20" } }
                        } }
                        TableBody {
                            for p in list(v) {
                                {
                                    let id = s(&p, "id");
                                    let pname = s(&p, "name");
                                    let r = list(&p["rules"]).into_iter().next().unwrap_or(Value::Null);
                                    let from = names(&r["sources"]).join(", ");
                                    let to = names(&r["destinations"]).join(", ");
                                    let to = if to.is_empty() { s(&r["destinationResource"], "id") } else { to };
                                    let arrow = if b(&r, "bidirectional") { "↔" } else { "→" };
                                    let portsl: Vec<String> = r["ports"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
                                    let pt = if portsl.is_empty() { s(&r, "protocol").to_uppercase() } else { format!("{} {}", s(&r, "protocol").to_uppercase(), portsl.join(", ")) };
                                    let enabled = b(&p, "enabled");
                                    let (pt_toggle, pe) = (p.clone(), p.clone());
                                    rsx! {
                                        TableRow { key: "{id}",
                                            TableCell {
                                                Toggle { checked: enabled, disabled: !admin, label: "",
                                                    onchange: move |on: bool| {
                                                        let p = pt_toggle.clone();
                                                        spawn(async move {
                                                            let id = s(&p, "id");
                                                            run("PUT", format!("/netbird/policies/{id}"), policy_body(&p, on), String::new(), version).await;
                                                        });
                                                    },
                                                }
                                            }
                                            TableCell { class: "font-medium", "{pname}"
                                                if !s(&p, "description").is_empty() { p { class: "text-xs font-normal text-muted-foreground", {s(&p, "description").to_string()} } }
                                            }
                                            TableCell { class: "text-sm", span { "{from}" } span { class: "mx-1.5 text-muted-foreground", "{arrow}" } span { "{to}" } }
                                            TableCell { class: "hidden text-muted-foreground md:table-cell", "{pt}" }
                                            if admin {
                                                TableCell { class: "px-2 text-right whitespace-nowrap",
                                                    button { class: icon_btn(""), title: tr("Bearbeiten"),
                                                        onclick: move |_| {
                                                            let r = list(&pe["rules"]).into_iter().next().unwrap_or(Value::Null);
                                                            name.set(s(&pe, "name"));
                                                            src.set(ids(&r["sources"]));
                                                            dst.set(ids(&r["destinations"]));
                                                            proto.set(if s(&r, "protocol").is_empty() { "all".into() } else { s(&r, "protocol") });
                                                            ports.set(r["ports"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default());
                                                            bidi.set(b(&r, "bidirectional"));
                                                            edit.set(pe.clone());
                                                            open.set(true);
                                                        },
                                                        icons::Pencil {}
                                                    }
                                                    button { class: icon_btn("hover:text-destructive"), title: tr("Löschen"),
                                                        onclick: move |_| {
                                                            let (id, pname) = (id.clone(), pname.clone());
                                                            spawn(async move {
                                                                if ask_delete(pname, tr("Geräte, die nur über diese Regel verbunden sind, erreichen sich dann nicht mehr.")).await {
                                                                    run("DELETE", format!("/netbird/policies/{id}"), Value::Null, tr("Gelöscht."), version).await;
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
                            }
                        }
                    } }
                },
            }
        }
        Modal { open, title: if s(&edit(), "id").is_empty() { tr("Neue Regel") } else { tr("Regel bearbeiten") },
            form { class: "grid grid-cols-1 gap-4", onsubmit: save,
                Field { label: tr("Name"), input { class: INPUT, required: true, maxlength: 100, value: "{name}", oninput: move |e| name.set(e.value()) } }
                Field { label: tr("Von (Gruppen)"), GroupPicker { groups: gs.clone(), selected: src } }
                Field { label: tr("Nach (Gruppen)"), GroupPicker { groups: gs.clone(), selected: dst } }
                div { class: "grid grid-cols-2 gap-3",
                    Field { label: tr("Protokoll"),
                        select { class: SELECT, value: "{proto}", onchange: move |e| proto.set(e.value()),
                            option { value: "all", {tr("Alle")} }
                            option { value: "tcp", "TCP" }
                            option { value: "udp", "UDP" }
                            option { value: "icmp", "ICMP" }
                        }
                    }
                    if matches!(proto().as_str(), "tcp" | "udp") {
                        Field { label: tr("Ports (leer = alle)"),
                            input { class: "{INPUT} font-mono text-[13px]", placeholder: "80, 443", value: "{ports}", oninput: move |e| ports.set(e.value()) }
                        }
                    }
                }
                Toggle { checked: bidi(), onchange: move |v| bidi.set(v), label: tr("In beide Richtungen") }
                div { class: "flex justify-end gap-2",
                    button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| open.set(false), {tr("Abbrechen")} }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: src().is_empty() || dst().is_empty(), {tr("Speichern")} }
                }
            }
        }
    }
}

// ------------------------------------------------------------------ Netzwerke

#[component]
fn NetworksTab(groups: Groups, peers: Groups, version: Signal<u64>) -> Element {
    let admin = state::is_admin();
    let res = use_resource(move || async move {
        let _ = version();
        api::get::<Value>("/netbird/networks").await
    });
    let mut open = use_signal(|| false);
    let mut name = use_signal(String::new);
    let mut desc = use_signal(String::new);
    let create = move |e: FormEvent| {
        e.prevent_default();
        spawn(async move {
            if run(
                "POST",
                "/netbird/networks".into(),
                json!({ "name": name().trim(), "description": desc().trim() }),
                tr("Netzwerk angelegt."),
                version,
            )
            .await
            {
                open.set(false);
            }
        });
    };
    rsx! {
        Section { title: tr("Netzwerke"), description: tr("Netze hinter einem Gerät (z. B. dein LAN 192.168.0.0/24) im NetBird-Netz erreichbar machen: Ressource eintragen, ein Gerät als Router wählen und den Zugriff unter „Zugriff“ freigeben."),
            actions: rsx! {
                if admin {
                    button { class: btn_sm(BTN_PRIMARY), onclick: move |_| { name.set(String::new()); desc.set(String::new()); open.set(true); },
                        icons::Plus {} {tr("Netzwerk")}
                    }
                }
            },
            match &*res.read() {
                None => rsx! { Loading {} },
                Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
                Some(Ok(v)) if list(v).is_empty() => rsx! { p { class: "text-sm text-muted-foreground", {tr("Noch keine Netzwerke.")} } },
                Some(Ok(v)) => rsx! {
                    div { class: "grid grid-cols-1 gap-4",
                        for (nid, net) in list(v).into_iter().map(|x| (s(&x, "id"), x)) {
                            NetworkCard { key: "{nid}", net: net.clone(), groups: groups.clone(), peers: peers.clone(), version }
                        }
                    }
                },
            }
        }
        Modal { open, title: tr("Neues Netzwerk"),
            form { class: "grid grid-cols-1 gap-4", onsubmit: create,
                Field { label: tr("Name"), input { class: INPUT, required: true, placeholder: "Zuhause", value: "{name}", oninput: move |e| name.set(e.value()) } }
                Field { label: tr("Beschreibung (optional)"), input { class: INPUT, value: "{desc}", oninput: move |e| desc.set(e.value()) } }
                div { class: "flex justify-end gap-2",
                    button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| open.set(false), {tr("Abbrechen")} }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", {tr("Anlegen")} }
                }
            }
        }
    }
}

#[component]
fn NetworkCard(net: Value, groups: Groups, peers: Groups, version: Signal<u64>) -> Element {
    let admin = state::is_admin();
    let id = s(&net, "id");
    let (id_r, id_t) = (id.clone(), id.clone());
    let resources = use_resource(move || {
        let id = id_r.clone();
        async move {
            let _ = version();
            api::get::<Value>(&format!("/netbird/networks/{id}/resources")).await
        }
    });
    let routers = use_resource(move || {
        let id = id_t.clone();
        async move {
            let _ = version();
            api::get::<Value>(&format!("/netbird/networks/{id}/routers")).await
        }
    });
    let mut res_open = use_signal(|| false);
    let mut r_name = use_signal(String::new);
    let mut r_addr = use_signal(String::new);
    let mut r_groups = use_signal(Vec::<String>::new);
    let mut rt_open = use_signal(|| false);
    let mut rt_peer = use_signal(String::new);
    let mut rt_masq = use_signal(|| true);
    let id_add = id.clone();
    let add_resource = move |e: FormEvent| {
        e.prevent_default();
        let id = id_add.clone();
        spawn(async move {
            let body = json!({ "name": r_name().trim(), "address": r_addr().trim(), "enabled": true, "groups": r_groups(), "description": "" });
            if run(
                "POST",
                format!("/netbird/networks/{id}/resources"),
                body,
                tr("Ressource angelegt."),
                version,
            )
            .await
            {
                res_open.set(false);
            }
        });
    };
    let id_rt = id.clone();
    let add_router = move |e: FormEvent| {
        e.prevent_default();
        let id = id_rt.clone();
        spawn(async move {
            let body = json!({ "peer": rt_peer(), "metric": 9999, "masquerade": rt_masq(), "enabled": true });
            if run(
                "POST",
                format!("/netbird/networks/{id}/routers"),
                body,
                tr("Router angelegt."),
                version,
            )
            .await
            {
                rt_open.set(false);
            }
        });
    };
    let net_name = s(&net, "name");
    let id_del = id.clone();
    let gs = groups.clone();
    rsx! {
        div { class: "rounded-xl border p-4",
            div { class: "mb-3 flex flex-wrap items-start justify-between gap-2",
                div {
                    p { class: "font-medium", icons::Network { class: "mr-1.5 inline size-4" } "{net_name}" }
                    if !s(&net, "description").is_empty() { p { class: "text-sm text-muted-foreground", {s(&net, "description").to_string()} } }
                }
                if admin {
                    div { class: "flex gap-1",
                        button { class: btn_sm(BTN_OUTLINE), onclick: move |_| { r_name.set(String::new()); r_addr.set(String::new()); r_groups.set(Vec::new()); res_open.set(true); }, icons::Plus {} {tr("Ressource")} }
                        button { class: btn_sm(BTN_OUTLINE), onclick: move |_| { rt_peer.set(String::new()); rt_masq.set(true); rt_open.set(true); }, icons::Plus {} {tr("Router")} }
                        button { class: icon_btn("hover:text-destructive"), title: tr("Netzwerk löschen"),
                            onclick: move |_| {
                                let (id, nn) = (id_del.clone(), net_name.clone());
                                spawn(async move {
                                    if ask_delete(nn, tr("Mit allen Ressourcen und Routern.")).await {
                                        run("DELETE", format!("/netbird/networks/{id}"), Value::Null, tr("Gelöscht."), version).await;
                                    }
                                });
                            },
                            icons::Trash2 {}
                        }
                    }
                }
            }
            p { class: "mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground", {tr("Ressourcen")} }
            match &*resources.read() {
                Some(Ok(v)) if !list(v).is_empty() => rsx! {
                    div { class: "mb-3 divide-y rounded-lg border",
                        for r in list(v) {
                            {
                                let rid = s(&r, "id");
                                let rr = r.clone();
                                let rname = s(&r, "name");
                                let nid = id.clone();
                                let nid2 = id.clone();
                                rsx! {
                                    div { key: "{rid}", class: "flex flex-wrap items-center gap-3 px-3 py-2 text-sm",
                                        Toggle { checked: b(&r, "enabled"), disabled: !admin, label: "",
                                            onchange: move |on: bool| {
                                                let (r, nid) = (rr.clone(), nid.clone());
                                                spawn(async move {
                                                    let body = json!({ "name": s(&r, "name"), "description": s(&r, "description"), "address": s(&r, "address"), "enabled": on, "groups": ids(&r["groups"]) });
                                                    run("PUT", format!("/netbird/networks/{nid}/resources/{}", s(&r, "id")), body, String::new(), version).await;
                                                });
                                            },
                                        }
                                        span { class: "font-medium", "{rname}" }
                                        span { class: "font-mono text-[13px] text-muted-foreground", {s(&r, "address").to_string()} }
                                        div { class: "flex flex-wrap gap-1", for g in names(&r["groups"]) { Pill { key: "{g}", "{g}" } } }
                                        if admin {
                                            button { class: format!("{} ml-auto", icon_btn("hover:text-destructive")), title: tr("Löschen"),
                                                onclick: move |_| {
                                                    let (nid, rid, rname) = (nid2.clone(), rid.clone(), rname.clone());
                                                    spawn(async move {
                                                        if ask_delete(rname, String::new()).await {
                                                            run("DELETE", format!("/netbird/networks/{nid}/resources/{rid}"), Value::Null, tr("Gelöscht."), version).await;
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
                    }
                },
                Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
                _ => rsx! { p { class: "mb-3 text-sm text-muted-foreground", {tr("Keine Ressourcen.")} } },
            }
            p { class: "mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground", {tr("Router")} }
            match &*routers.read() {
                Some(Ok(v)) if !list(v).is_empty() => rsx! {
                    div { class: "divide-y rounded-lg border",
                        for r in list(v) {
                            {
                                let rid = s(&r, "id");
                                let who = if s(&r, "peer").is_empty() {
                                    ids(&r["peer_groups"]).iter().map(|g| name_of(&groups, g)).collect::<Vec<_>>().join(", ")
                                } else {
                                    name_of(&peers, &s(&r, "peer"))
                                };
                                let nid = id.clone();
                                rsx! {
                                    div { key: "{rid}", class: "flex flex-wrap items-center gap-3 px-3 py-2 text-sm",
                                        Dot { on: b(&r, "enabled") }
                                        span { class: "font-medium", "{who}" }
                                        span { class: "text-muted-foreground", if b(&r, "masquerade") { {tr("Masquerade")} } else { {tr("ohne Masquerade")} } }
                                        if admin {
                                            button { class: format!("{} ml-auto", icon_btn("hover:text-destructive")), title: tr("Löschen"),
                                                onclick: move |_| {
                                                    let (nid, rid) = (nid.clone(), rid.clone());
                                                    spawn(async move {
                                                        if ask_delete(tr("Router"), String::new()).await {
                                                            run("DELETE", format!("/netbird/networks/{nid}/routers/{rid}"), Value::Null, tr("Gelöscht."), version).await;
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
                    }
                },
                Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
                _ => rsx! { p { class: "text-sm text-muted-foreground", {tr("Kein Router – ohne Router ist das Netz nicht erreichbar.")} } },
            }
        }
        Modal { open: res_open, title: tr("Neue Ressource"), description: s(&net, "name"),
            form { class: "grid grid-cols-1 gap-4", onsubmit: add_resource,
                Field { label: tr("Name"), input { class: INPUT, required: true, placeholder: "LAN", value: "{r_name}", oninput: move |e| r_name.set(e.value()) } }
                Field { label: tr("Adresse"), hint: tr("IP, Netz (192.168.0.0/24) oder Domain (*.zweers.ch)."),
                    input { class: "{INPUT} font-mono text-[13px]", required: true, placeholder: "192.168.0.0/24", value: "{r_addr}", oninput: move |e| r_addr.set(e.value()) }
                }
                Field { label: tr("Gruppen der Ressource"), hint: tr("Für die Zugriffsregel (Ziel)."), GroupPicker { groups: gs.clone(), selected: r_groups } }
                div { class: "flex justify-end gap-2",
                    button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| res_open.set(false), {tr("Abbrechen")} }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", {tr("Anlegen")} }
                }
            }
        }
        Modal { open: rt_open, title: tr("Neuer Router"), description: tr("Das Gerät, über das das Netz erreichbar ist (es muss im Netz stehen)."),
            form { class: "grid grid-cols-1 gap-4", onsubmit: add_router,
                Field { label: tr("Gerät"),
                    select { class: SELECT, required: true, value: "{rt_peer}", onchange: move |e| rt_peer.set(e.value()),
                        option { value: "", {tr("Gerät wählen …")} }
                        for (pid, pname) in peers.clone() { option { key: "{pid}", value: "{pid}", "{pname}" } }
                    }
                }
                Toggle { checked: rt_masq(), onchange: move |v| rt_masq.set(v), label: tr("Masquerade"), hint: tr("Empfohlen: das Ziel sieht die Adresse des Routers, keine Route im LAN nötig.") }
                div { class: "flex justify-end gap-2",
                    button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| rt_open.set(false), {tr("Abbrechen")} }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: rt_peer().is_empty(), {tr("Anlegen")} }
                }
            }
        }
    }
}

// ------------------------------------------------------------------ DNS

/// NetBird-Adresse dieses Geräts (100.64.0.0/10) aus den erkannten Adressen.
fn netbird_ip(addrs: &[String]) -> Option<String> {
    addrs
        .iter()
        .find(|a| {
            a.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| {
                let o = ip.octets();
                o[0] == 100 && (64..128).contains(&o[1])
            })
        })
        .cloned()
}

#[component]
fn DnsTab(groups: Groups, version: Signal<u64>) -> Element {
    let admin = state::is_admin();
    let res = use_resource(move || async move {
        let _ = version();
        api::get::<Value>("/netbird/dns/nameservers").await
    });
    let proxy = use_resource(|| async { api::get::<ProxyStatus>("/proxy").await });
    let mut open = use_signal(|| false);
    let mut name = use_signal(String::new);
    let mut servers = use_signal(String::new);
    let mut domains = use_signal(String::new);
    let mut sel = use_signal(Vec::<String>::new);
    let all_id = groups
        .iter()
        .find(|g| g.1 == "All")
        .map(|g| g.0.clone())
        .unwrap_or_default();
    let own_ip = match &*proxy.read() {
        Some(Ok(p)) => netbird_ip(&p.device_addresses),
        _ => None,
    };
    let create = move |e: FormEvent| {
        e.prevent_default();
        spawn(async move {
            let ns: Vec<Value> = servers()
                .split([',', ' '])
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .take(3)
                .map(|ip| json!({ "ip": ip, "ns_type": "udp", "port": 53 }))
                .collect();
            let dl: Vec<String> = domains()
                .split([',', ' '])
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .collect();
            let body = json!({ "name": name().trim(), "description": "", "nameservers": ns, "enabled": true, "groups": sel(), "primary": dl.is_empty(), "domains": dl, "search_domains_enabled": false });
            if run(
                "POST",
                "/netbird/dns/nameservers".into(),
                body,
                tr("Nameserver angelegt."),
                version,
            )
            .await
            {
                open.set(false);
            }
        });
    };
    let list_v = match &*res.read() {
        Some(Ok(v)) => list(v),
        _ => Vec::new(),
    };
    let has_own = own_ip.as_ref().is_some_and(|ip| {
        list_v
            .iter()
            .any(|g| list(&g["nameservers"]).iter().any(|x| s(x, "ip") == *ip))
    });
    let gs = groups.clone();
    let oip = own_ip.clone();
    let aid = all_id.clone();
    rsx! {
        Section { title: tr("nrzNetwork als DNS für NetBird"), description: tr("Alle NetBird-Geräte fragen dann nrzNetwork: Sperrlisten, eigene Zonen und die Namen aus dem Reverse Proxy gelten auch unterwegs."),
            match (own_ip.clone(), has_own) {
                (None, _) => rsx! { Callout { text: tr("Die NetBird-Adresse dieses Geräts ist (noch) nicht bekannt – unter Reverse Proxy → Gerät und Sperrseite eintragen.") } },
                (Some(ip), true) => rsx! { div { class: "flex items-center gap-2 text-sm", Dot { on: true } {trf("Aktiv: alle NetBird-Geräte benutzen nrzNetwork ({0}).", &[&ip])} } },
                (Some(ip), false) => rsx! {
                    div { class: "flex flex-wrap items-center justify-between gap-3",
                        p { class: "text-sm text-muted-foreground", {trf("Legt in NetBird einen Nameserver {0} für die Gruppe „All“ an.", &[&ip])} }
                        if admin {
                            button { class: btn(BTN_PRIMARY), disabled: aid.is_empty(),
                                onclick: move |_| {
                                    let (ip, aid) = (oip.clone().unwrap_or_default(), aid.clone());
                                    spawn(async move {
                                        let body = json!({ "name": "nrzNetwork", "description": "DNS mit Sperrlisten und eigenen Namen", "nameservers": [{ "ip": ip, "ns_type": "udp", "port": 53 }], "enabled": true, "groups": [aid], "primary": true, "domains": [], "search_domains_enabled": false });
                                        run("POST", "/netbird/dns/nameservers".into(), body, tr("nrzNetwork ist jetzt DNS für alle NetBird-Geräte."), version).await;
                                    });
                                },
                                icons::Zap {} {tr("Jetzt einrichten")}
                            }
                        }
                    }
                },
            }
        }
        Section { title: tr("Nameserver"), description: tr("Welche DNS-Server NetBird-Geräte benutzen – für alle Domains (primär) oder nur für bestimmte."),
            actions: rsx! {
                if admin {
                    button { class: btn_sm(BTN_PRIMARY), onclick: move |_| { name.set(String::new()); servers.set(String::new()); domains.set(String::new()); sel.set(if all_id.is_empty() { Vec::new() } else { vec![all_id.clone()] }); open.set(true); },
                        icons::Plus {} {tr("Nameserver")}
                    }
                }
            },
            match &*res.read() {
                None => rsx! { Loading {} },
                Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
                Some(Ok(_)) => rsx! {
                    TableWrapper { Table {
                        TableHeader { tr {
                            TableHead { class: "w-14", {tr("An")} }
                            TableHead { {tr("Name")} }
                            TableHead { {tr("Server")} }
                            TableHead { class: "hidden md:table-cell", {tr("Domains")} }
                            TableHead { class: "hidden lg:table-cell", {tr("Gruppen")} }
                            if admin { TableHead { class: "w-12" } }
                        } }
                        TableBody {
                            for g in list_v.clone() {
                                {
                                    let id = s(&g, "id");
                                    let gname = s(&g, "name");
                                    let gt = g.clone();
                                    let srv = list(&g["nameservers"]).iter().map(|x| { let p = n(x, "port"); if p == 53 || p == 0 { s(x, "ip") } else { format!("{}:{p}", s(x, "ip")) } }).collect::<Vec<_>>().join(", ");
                                    let doms = g["domains"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
                                    let gn = ids(&g["groups"]).iter().map(|x| name_of(&groups, x)).collect::<Vec<_>>();
                                    rsx! {
                                        TableRow { key: "{id}",
                                            TableCell {
                                                Toggle { checked: b(&g, "enabled"), disabled: !admin, label: "",
                                                    onchange: move |on: bool| {
                                                        let mut body = gt.clone();
                                                        spawn(async move {
                                                            let id = s(&body, "id");
                                                            body["enabled"] = json!(on);
                                                            if let Some(o) = body.as_object_mut() { o.remove("id"); }
                                                            run("PUT", format!("/netbird/dns/nameservers/{id}"), body, String::new(), version).await;
                                                        });
                                                    },
                                                }
                                            }
                                            TableCell { class: "font-medium", "{gname}" }
                                            TableCell { class: "font-mono text-[13px]", "{srv}" }
                                            TableCell { class: "hidden text-muted-foreground md:table-cell", if doms.is_empty() { {tr("alle (primär)")} } else { "{doms}" } }
                                            TableCell { class: "hidden lg:table-cell", div { class: "flex flex-wrap gap-1", for x in gn { Pill { key: "{x}", "{x}" } } } }
                                            if admin {
                                                TableCell { class: "px-2 text-right",
                                                    button { class: icon_btn("hover:text-destructive"), title: tr("Löschen"),
                                                        onclick: move |_| {
                                                            let (id, gname) = (id.clone(), gname.clone());
                                                            spawn(async move {
                                                                if ask_delete(gname, String::new()).await {
                                                                    run("DELETE", format!("/netbird/dns/nameservers/{id}"), Value::Null, tr("Gelöscht."), version).await;
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
                            }
                        }
                    } }
                },
            }
        }
        Modal { open, title: tr("Neuer Nameserver"),
            form { class: "grid grid-cols-1 gap-4", onsubmit: create,
                Field { label: tr("Name"), input { class: INPUT, required: true, maxlength: 40, value: "{name}", oninput: move |e| name.set(e.value()) } }
                Field { label: tr("Server (bis zu 3 IPs)"), input { class: "{INPUT} font-mono text-[13px]", required: true, placeholder: "100.78.107.162", value: "{servers}", oninput: move |e| servers.set(e.value()) } }
                Field { label: tr("Nur für Domains (leer = alle)"), input { class: "{INPUT} font-mono text-[13px]", placeholder: "zweers.ch, fritz.box", value: "{domains}", oninput: move |e| domains.set(e.value()) } }
                Field { label: tr("Für Gruppen"), GroupPicker { groups: gs.clone(), selected: sel } }
                div { class: "flex justify-end gap-2",
                    button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| open.set(false), {tr("Abbrechen")} }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: sel().is_empty(), {tr("Anlegen")} }
                }
            }
        }
    }
}

// ------------------------------------------------------------------ Setup-Keys

#[component]
fn KeysTab(groups: Groups, url: String, version: Signal<u64>) -> Element {
    let admin = state::is_admin();
    let res = use_resource(move || async move {
        let _ = version();
        api::get::<Value>("/netbird/setup-keys").await
    });
    let mut open = use_signal(|| false);
    let mut name = use_signal(String::new);
    let mut reusable = use_signal(|| true);
    let mut days = use_signal(|| 30i64);
    let mut limit = use_signal(|| 0i64);
    let mut ephemeral = use_signal(|| false);
    let mut sel = use_signal(Vec::<String>::new);
    let mut created = use_signal(String::new);
    let create = move |e: FormEvent| {
        e.prevent_default();
        spawn(async move {
            let body = json!({
                "name": name().trim(),
                "type": if reusable() { "reusable" } else { "one-off" },
                "expires_in": days().clamp(1, 365) * 86_400,
                "auto_groups": sel(),
                "usage_limit": if reusable() { limit().max(0) } else { 1 },
                "ephemeral": ephemeral(),
            });
            match api::post::<Value, _>("/netbird/setup-keys", &body).await {
                Ok(v) => {
                    created.set(s(&v, "key"));
                    version += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };
    let gs = groups.clone();
    let cmd = if url.is_empty() {
        format!("netbird up --setup-key {}", created())
    } else {
        format!(
            "netbird up --management-url {url} --setup-key {}",
            created()
        )
    };
    rsx! {
        Section { title: tr("Setup-Keys"), description: tr("Damit melden sich neue Geräte (Server, Router, Geräte ohne Browser) im Netz an."),
            actions: rsx! {
                if admin {
                    button { class: btn_sm(BTN_PRIMARY), onclick: move |_| { name.set(String::new()); reusable.set(true); days.set(30); limit.set(0); ephemeral.set(false); sel.set(Vec::new()); created.set(String::new()); open.set(true); },
                        icons::Plus {} {tr("Setup-Key")}
                    }
                }
            },
            match &*res.read() {
                None => rsx! { Loading {} },
                Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
                Some(Ok(v)) => rsx! {
                    TableWrapper { Table {
                        TableHeader { tr {
                            TableHead { {tr("Name")} }
                            TableHead { {tr("Status")} }
                            TableHead { class: "hidden sm:table-cell", {tr("Benutzt")} }
                            TableHead { class: "hidden md:table-cell", {tr("Läuft ab")} }
                            TableHead { class: "hidden lg:table-cell", {tr("Gruppen")} }
                            if admin { TableHead { class: "w-20" } }
                        } }
                        TableBody {
                            for k in list(v) {
                                {
                                    let id = s(&k, "id");
                                    let kname = s(&k, "name");
                                    let valid = b(&k, "valid") && !b(&k, "revoked");
                                    let state = s(&k, "state");
                                    let lim = n(&k, "usage_limit");
                                    let used = if lim == 0 { format!("{} / ∞", n(&k, "used_times")) } else { format!("{} / {lim}", n(&k, "used_times")) };
                                    let exp = ts(&k, "expires");
                                    let gn = ids(&k["auto_groups"]).iter().map(|x| name_of(&groups, x)).collect::<Vec<_>>();
                                    let kr = k.clone();
                                    rsx! {
                                        TableRow { key: "{id}",
                                            TableCell { class: "font-medium", "{kname}"
                                                p { class: "text-xs font-normal text-muted-foreground", if s(&k, "type") == "reusable" { {tr("mehrfach")} } else { {tr("einmalig")} } if b(&k, "ephemeral") { " · " {tr("flüchtig")} } }
                                            }
                                            TableCell { div { class: "flex items-center gap-2", Dot { on: valid } "{state}" } }
                                            TableCell { class: "hidden sm:table-cell", "{used}" }
                                            TableCell { class: "hidden text-muted-foreground md:table-cell", if exp == 0 { "–" } else { "{crate::util::date(exp)}" } }
                                            TableCell { class: "hidden lg:table-cell", div { class: "flex flex-wrap gap-1", for x in gn { Pill { key: "{x}", "{x}" } } } }
                                            if admin {
                                                TableCell { class: "px-2 text-right whitespace-nowrap",
                                                    if valid {
                                                        button { class: icon_btn(""), title: tr("Sperren"),
                                                            onclick: move |_| {
                                                                let k = kr.clone();
                                                                spawn(async move {
                                                                    let body = json!({ "revoked": true, "auto_groups": ids(&k["auto_groups"]) });
                                                                    run("PUT", format!("/netbird/setup-keys/{}", s(&k, "id")), body, tr("Gesperrt."), version).await;
                                                                });
                                                            },
                                                            icons::Ban {}
                                                        }
                                                    }
                                                    button { class: icon_btn("hover:text-destructive"), title: tr("Löschen"),
                                                        onclick: move |_| {
                                                            let (id, kname) = (id.clone(), kname.clone());
                                                            spawn(async move {
                                                                if ask_delete(kname, tr("Schon angemeldete Geräte bleiben im Netz.")).await {
                                                                    run("DELETE", format!("/netbird/setup-keys/{id}"), Value::Null, tr("Gelöscht."), version).await;
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
                            }
                        }
                    } }
                },
            }
        }
        Modal { open, title: tr("Neuer Setup-Key"),
            if created().is_empty() {
                form { class: "grid grid-cols-1 gap-4", onsubmit: create,
                    Field { label: tr("Name"), input { class: INPUT, required: true, placeholder: "NAS", value: "{name}", oninput: move |e| name.set(e.value()) } }
                    Toggle { checked: reusable(), onchange: move |v| reusable.set(v), label: tr("Mehrfach verwendbar") }
                    div { class: "grid grid-cols-2 gap-3",
                        Field { label: tr("Gültig (Tage)"), input { class: INPUT, r#type: "number", min: 1, max: 365, value: "{days}", oninput: move |e| days.set(e.value().parse().unwrap_or(30)) } }
                        if reusable() {
                            Field { label: tr("Höchstens (0 = unbegrenzt)"), input { class: INPUT, r#type: "number", min: 0, value: "{limit}", oninput: move |e| limit.set(e.value().parse().unwrap_or(0)) } }
                        }
                    }
                    Field { label: tr("Gruppen für neue Geräte"), GroupPicker { groups: gs.clone(), selected: sel } }
                    Toggle { checked: ephemeral(), onchange: move |v| ephemeral.set(v), label: tr("Flüchtig"), hint: tr("Geräte verschwinden nach 10 Minuten offline von selbst (für Container).") }
                    div { class: "flex justify-end gap-2",
                        button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| open.set(false), {tr("Abbrechen")} }
                        button { class: btn(BTN_PRIMARY), r#type: "submit", {tr("Erstellen")} }
                    }
                }
            } else {
                div { class: "grid grid-cols-1 gap-4",
                    Callout { text: tr("Jetzt kopieren – der Schlüssel wird nur dieses eine Mal angezeigt.") }
                    div { class: "flex items-center gap-2 rounded-lg border bg-muted/30 p-3 font-mono text-[13px] break-all", span { class: "flex-1", "{created}" } CopyButton { text: created() } }
                    p { class: "text-sm text-muted-foreground", {tr("Auf dem neuen Gerät:")} }
                    div { class: "flex items-center gap-2 rounded-lg border bg-muted/30 p-3 font-mono text-xs break-all", span { class: "flex-1", "{cmd}" } CopyButton { text: cmd.clone() } }
                    div { class: "flex justify-end", button { class: btn(BTN_PRIMARY), onclick: move |_| open.set(false), {tr("Fertig")} } }
                }
            }
        }
    }
}

// ------------------------------------------------------------------ Benutzer

#[component]
fn UsersTab(groups: Groups, version: Signal<u64>) -> Element {
    let admin = state::is_admin();
    let res = use_resource(move || async move {
        let _ = version();
        api::get::<Value>("/netbird/users?service_user=false").await
    });
    let mut open = use_signal(|| false);
    let mut edit = use_signal(|| Value::Null);
    let mut role = use_signal(|| "user".to_string());
    let mut blocked = use_signal(|| false);
    let mut sel = use_signal(Vec::<String>::new);
    let mut email = use_signal(String::new);
    let mut uname = use_signal(String::new);
    let save = move |e: FormEvent| {
        e.prevent_default();
        let u = edit();
        spawn(async move {
            let id = s(&u, "id");
            let ok = if id.is_empty() {
                let body = json!({ "email": email().trim(), "name": uname().trim(), "role": role(), "auto_groups": sel(), "is_service_user": false });
                run(
                    "POST",
                    "/netbird/users".into(),
                    body,
                    tr("Einladung gesendet."),
                    version,
                )
                .await
            } else {
                let body = json!({ "role": role(), "auto_groups": sel(), "is_blocked": blocked() });
                run(
                    "PUT",
                    format!("/netbird/users/{id}"),
                    body,
                    tr("Gespeichert."),
                    version,
                )
                .await
            };
            if ok {
                open.set(false);
            }
        });
    };
    let gs = groups.clone();
    let is_new = s(&edit(), "id").is_empty();
    rsx! {
        Section { title: tr("Benutzer"), description: tr("Wer sich im NetBird-Netz anmelden darf, mit Rolle und Gruppen für seine Geräte."),
            actions: rsx! {
                if admin {
                    button { class: btn_sm(BTN_PRIMARY), onclick: move |_| { edit.set(Value::Null); email.set(String::new()); uname.set(String::new()); role.set("user".into()); sel.set(Vec::new()); blocked.set(false); open.set(true); },
                        icons::UserPlus {} {tr("Einladen")}
                    }
                }
            },
            match &*res.read() {
                None => rsx! { Loading {} },
                Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
                Some(Ok(v)) => rsx! {
                    TableWrapper { Table {
                        TableHeader { tr {
                            TableHead { {tr("Benutzer")} }
                            TableHead { {tr("Rolle")} }
                            TableHead { class: "hidden sm:table-cell", {tr("Status")} }
                            TableHead { class: "hidden md:table-cell", {tr("Zuletzt")} }
                            if admin { TableHead { class: "w-20" } }
                        } }
                        TableBody {
                            for u in list(v) {
                                {
                                    let id = s(&u, "id");
                                    let label = if s(&u, "name").is_empty() { s(&u, "email") } else { s(&u, "name") };
                                    let me = b(&u, "is_current");
                                    let owner = s(&u, "role") == "owner";
                                    let ue = u.clone();
                                    let last = ts(&u, "last_login");
                                    rsx! {
                                        TableRow { key: "{id}",
                                            TableCell {
                                                p { class: "font-medium", "{label}" if me { span { class: "ml-1.5 text-xs text-muted-foreground", {tr("(du)")} } } }
                                                p { class: "text-xs text-muted-foreground", {s(&u, "email").to_string()} }
                                            }
                                            TableCell { Pill { tone: if owner { Tone::Strong } else { Tone::Neutral }, {s(&u, "role").to_string()} } }
                                            TableCell { class: "hidden sm:table-cell",
                                                if b(&u, "is_blocked") { Pill { tone: Tone::Danger, {tr("gesperrt")} } } else { span { class: "text-muted-foreground", {s(&u, "status").to_string()} } }
                                            }
                                            TableCell { class: "hidden text-muted-foreground md:table-cell", {relative_or(last, "–")} }
                                            if admin {
                                                TableCell { class: "px-2 text-right whitespace-nowrap",
                                                    if !owner && !me {
                                                        button { class: icon_btn(""), title: tr("Bearbeiten"),
                                                            onclick: move |_| { role.set(s(&ue, "role")); blocked.set(b(&ue, "is_blocked")); sel.set(ids(&ue["auto_groups"])); edit.set(ue.clone()); open.set(true); },
                                                            icons::Pencil {}
                                                        }
                                                        button { class: icon_btn("hover:text-destructive"), title: tr("Entfernen"),
                                                            onclick: move |_| {
                                                                let (id, label) = (id.clone(), label.clone());
                                                                spawn(async move {
                                                                    if ask_delete(label, tr("Der Zugang wird entfernt; seine Geräte bleiben, bis du sie löschst.")).await {
                                                                        run("DELETE", format!("/netbird/users/{id}"), Value::Null, tr("Entfernt."), version).await;
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
                                }
                            }
                        }
                    } }
                },
            }
        }
        Modal { open, title: if is_new { tr("Benutzer einladen") } else { tr("Benutzer bearbeiten") }, description: s(&edit(), "email"),
            form { class: "grid grid-cols-1 gap-4", onsubmit: save,
                if is_new {
                    Field { label: tr("E-Mail"), input { class: INPUT, r#type: "email", required: true, value: "{email}", oninput: move |e| email.set(e.value()) } }
                    Field { label: tr("Name"), input { class: INPUT, required: true, value: "{uname}", oninput: move |e| uname.set(e.value()) } }
                }
                Field { label: tr("Rolle"),
                    select { class: SELECT, value: "{role}", onchange: move |e| role.set(e.value()),
                        option { value: "user", {tr("Benutzer")} }
                        option { value: "admin", {tr("Admin")} }
                        option { value: "auditor", {tr("Prüfer (nur lesen)")} }
                    }
                }
                Field { label: tr("Gruppen für seine Geräte"), GroupPicker { groups: gs.clone(), selected: sel } }
                if !is_new {
                    Toggle { checked: blocked(), onchange: move |v| blocked.set(v), label: tr("Gesperrt") }
                }
                div { class: "flex justify-end gap-2",
                    button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| open.set(false), {tr("Abbrechen")} }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", if is_new { {tr("Einladen")} } else { {tr("Speichern")} } }
                }
            }
        }
    }
}

// ------------------------------------------------------------------ Freigaben (NetBird Reverse Proxy)

/// Dienst für PUT aufbereiten (Felder, die nur gelesen werden, entfernen).
fn service_body(v: &Value, enabled: bool) -> Value {
    let mut b = v.clone();
    if let Some(o) = b.as_object_mut() {
        for k in [
            "id",
            "meta",
            "port_auto_assigned",
            "proxy_cluster",
            "terminated",
        ] {
            o.remove(k);
        }
        o.insert("enabled".into(), json!(enabled));
    }
    b
}

#[component]
fn ServicesTab(groups: Groups, peers: Groups, version: Signal<u64>) -> Element {
    let admin = state::is_admin();
    let res = use_resource(move || async move {
        let _ = version();
        api::get::<Value>("/netbird/reverse-proxies/services").await
    });
    let domains =
        use_resource(|| async { api::get::<Value>("/netbird/reverse-proxies/domains").await });
    let mut open = use_signal(|| false);
    let mut sub = use_signal(String::new);
    let mut base = use_signal(String::new);
    let mut peer = use_signal(String::new);
    let mut port = use_signal(|| 80i64);
    let mut proto = use_signal(|| "http".to_string());
    let mut private = use_signal(|| false);
    let mut sel = use_signal(Vec::<String>::new);
    let mut password = use_signal(String::new);
    let doms: Vec<(String, bool)> = match &*domains.read() {
        Some(Ok(v)) => list(v)
            .iter()
            .map(|d| (s(d, "domain"), b(d, "require_subdomain")))
            .collect(),
        _ => Vec::new(),
    };
    let doms2 = doms.clone();
    let doms3 = doms.clone();
    let create = move |e: FormEvent| {
        e.prevent_default();
        let need_sub =
            doms2.iter().find(|d| d.0 == base()).is_some_and(|d| d.1) || base().is_empty();
        let domain = if need_sub || !sub().trim().is_empty() {
            format!("{}.{}", sub().trim(), base())
        } else {
            base()
        };
        spawn(async move {
            let mut body = json!({
                "name": domain,
                "domain": domain,
                "mode": "http",
                "enabled": true,
                "pass_host_header": false,
                "rewrite_redirects": true,
                "private": private(),
                "targets": [{ "target_id": peer(), "target_type": "peer", "path": "/", "access_action": "inherit", "protocol": proto(), "port": port(), "enabled": true }],
            });
            if private() {
                body["access_groups"] = json!(sel());
            }
            if !password().trim().is_empty() {
                body["auth"] =
                    json!({ "password_auth": { "enabled": true, "password": password().trim() } });
            }
            if run(
                "POST",
                "/netbird/reverse-proxies/services".into(),
                body,
                tr("Freigabe angelegt."),
                version,
            )
            .await
            {
                open.set(false);
            }
        });
    };
    let gs = groups.clone();
    rsx! {
        Section { title: tr("Freigaben (NetBird Reverse Proxy)"), description: tr("Dienste im NetBird-Netz unter einer Adresse von NetBird im Internet erreichbar machen – auf Wunsch nur für NetBird-Benutzer, mit Passwort oder Zugriffsregeln. Ergänzt den Cloudflare Tunnel."),
            actions: rsx! {
                if admin {
                    button { class: btn_sm(BTN_PRIMARY), onclick: move |_| { sub.set(String::new()); base.set(doms3.first().map(|d| d.0.clone()).unwrap_or_default()); peer.set(String::new()); port.set(80); proto.set("http".into()); private.set(false); sel.set(Vec::new()); password.set(String::new()); open.set(true); },
                        icons::Plus {} {tr("Freigabe")}
                    }
                }
            },
            match &*res.read() {
                None => rsx! { Loading {} },
                Some(Err(e)) => rsx! { Callout { text: trf("NetBird Reverse Proxy nicht verfügbar: {0}", &[&e.message]) } },
                Some(Ok(v)) if list(v).is_empty() => rsx! { p { class: "text-sm text-muted-foreground", {tr("Noch keine Freigaben.")} } },
                Some(Ok(v)) => rsx! {
                    TableWrapper { Table {
                        TableHeader { tr {
                            TableHead { class: "w-14", {tr("An")} }
                            TableHead { {tr("Adresse")} }
                            TableHead { class: "hidden md:table-cell", {tr("Ziel")} }
                            TableHead { {tr("Zugang")} }
                            if admin { TableHead { class: "w-12" } }
                        } }
                        TableBody {
                            for svc in list(v) {
                                {
                                    let id = s(&svc, "id");
                                    let domain = s(&svc, "domain");
                                    let st = svc.clone();
                                    let targets = list(&svc["targets"]).iter().map(|t| {
                                        let who = name_of(&peers, &s(t, "target_id"));
                                        let host = s(t, "host");
                                        format!("{}{}:{}", if host.is_empty() { who } else { host }, if s(t, "path").is_empty() || s(t, "path") == "/" { String::new() } else { s(t, "path") }, n(t, "port"))
                                    }).collect::<Vec<_>>().join(", ");
                                    let auth = &svc["auth"];
                                    let mut access: Vec<String> = Vec::new();
                                    if b(&svc, "private") { access.push(tr("nur NetBird")); }
                                    if b(&auth["password_auth"], "enabled") { access.push(tr("Passwort")); }
                                    if b(&auth["pin_auth"], "enabled") { access.push("PIN".into()); }
                                    if b(&auth["bearer_auth"], "enabled") { access.push(tr("Anmeldung")); }
                                    if access.is_empty() { access.push(tr("öffentlich")); }
                                    rsx! {
                                        TableRow { key: "{id}",
                                            TableCell {
                                                Toggle { checked: b(&svc, "enabled"), disabled: !admin, label: "",
                                                    onchange: move |on: bool| {
                                                        let svc = st.clone();
                                                        spawn(async move {
                                                            run("PUT", format!("/netbird/reverse-proxies/services/{}", s(&svc, "id")), service_body(&svc, on), String::new(), version).await;
                                                        });
                                                    },
                                                }
                                            }
                                            TableCell { class: "font-mono text-[13px] break-all",
                                                a { class: "hover:underline", href: "https://{domain}/", target: "_blank", rel: "noopener", "{domain}" }
                                                p { class: "font-sans text-xs text-muted-foreground", {s(&svc["meta"], "status")} }
                                            }
                                            TableCell { class: "hidden font-mono text-xs text-muted-foreground md:table-cell", "{targets}" }
                                            TableCell { div { class: "flex flex-wrap gap-1", for a in access { Pill { key: "{a}", "{a}" } } } }
                                            if admin {
                                                TableCell { class: "px-2 text-right",
                                                    button { class: icon_btn("hover:text-destructive"), title: tr("Löschen"),
                                                        onclick: move |_| {
                                                            let (id, domain) = (id.clone(), domain.clone());
                                                            spawn(async move {
                                                                if ask_delete(domain, tr("Die Adresse ist danach nicht mehr erreichbar.")).await {
                                                                    run("DELETE", format!("/netbird/reverse-proxies/services/{id}"), Value::Null, tr("Gelöscht."), version).await;
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
                            }
                        }
                    } }
                },
            }
        }
        Modal { open, title: tr("Neue Freigabe"),
            form { class: "grid grid-cols-1 gap-4", onsubmit: create,
                div { class: "grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1.4fr)] items-end gap-2",
                    Field { label: tr("Name"), input { class: "{INPUT} font-mono text-[13px]", placeholder: "music", value: "{sub}", oninput: move |e| sub.set(e.value()) } }
                    span { class: "pb-2 text-muted-foreground", "." }
                    Field { label: tr("Domain"),
                        select { class: SELECT, required: true, value: "{base}", onchange: move |e| base.set(e.value()),
                            for (d, _) in doms.clone() { option { key: "{d}", value: "{d}", "{d}" } }
                        }
                    }
                }
                div { class: "grid grid-cols-[minmax(0,1fr)_6rem_6rem] gap-2",
                    Field { label: tr("Gerät"),
                        select { class: SELECT, required: true, value: "{peer}", onchange: move |e| peer.set(e.value()),
                            option { value: "", {tr("Gerät wählen …")} }
                            for (pid, pname) in peers.clone() { option { key: "{pid}", value: "{pid}", "{pname}" } }
                        }
                    }
                    Field { label: tr("Port"), input { class: INPUT, r#type: "number", min: 1, max: 65535, value: "{port}", oninput: move |e| port.set(e.value().parse().unwrap_or(80)) } }
                    Field { label: tr("Protokoll"),
                        select { class: SELECT, value: "{proto}", onchange: move |e| proto.set(e.value()),
                            option { value: "http", "HTTP" }
                            option { value: "https", "HTTPS" }
                        }
                    }
                }
                Toggle { checked: private(), onchange: move |v| private.set(v), label: tr("Nur für NetBird-Benutzer"), hint: tr("Zugriff nur nach Anmeldung bei NetBird, optional auf Gruppen beschränkt.") }
                if private() { Field { label: tr("Gruppen"), GroupPicker { groups: gs.clone(), selected: sel } } }
                Field { label: tr("Passwort (optional)"), input { class: INPUT, r#type: "password", autocomplete: "new-password", value: "{password}", oninput: move |e| password.set(e.value()) } }
                div { class: "flex justify-end gap-2",
                    button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| open.set(false), {tr("Abbrechen")} }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: peer().is_empty() || base().is_empty(), {tr("Anlegen")} }
                }
            }
        }
    }
}
