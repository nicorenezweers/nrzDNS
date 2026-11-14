//! Domains bei Cloudflare: alle Zonen, alle DNS-Einträge anlegen, ändern, löschen, mit
//! Proxy-Schalter (orange Wolke). Läuft über `/api/v1/cloudflare/…` (Token bleibt auf dem
//! Server).

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::json::{ConnectHint, b, list, n, s};
use crate::state;
use crate::ui::table::*;
use dioxus::prelude::*;
use nrzdns_types::IntegrationsStatus;
use serde_json::{Value, json};

const TYPES: &[&str] = &["A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA"];
const TTLS: &[(i64, &str)] = &[
    (1, "Auto"),
    (60, "1 min"),
    (300, "5 min"),
    (3600, "1 h"),
    (86400, "1 d"),
];

fn proxiable(t: &str) -> bool {
    matches!(t, "A" | "AAAA" | "CNAME")
}

/// `music.zweers.ch` → `music`, `zweers.ch` → `@`.
fn short(name: &str, zone: &str) -> String {
    if name == zone {
        "@".into()
    } else {
        name.strip_suffix(&format!(".{zone}"))
            .unwrap_or(name)
            .to_string()
    }
}

/// Inhalt zur Anzeige (SRV/CAA aus `data`).
fn content_of(r: &Value) -> String {
    match s(r, "type").as_str() {
        "SRV" => {
            let d = &r["data"];
            format!(
                "{} {} {} {}",
                n(d, "priority"),
                n(d, "weight"),
                n(d, "port"),
                s(d, "target")
            )
        }
        "CAA" => {
            let d = &r["data"];
            format!("{} {} \"{}\"", n(d, "flags"), s(d, "tag"), s(d, "value"))
        }
        "MX" => format!("{} {}", n(r, "priority"), s(r, "content")),
        _ => s(r, "content"),
    }
}

#[component]
pub fn Domains() -> Element {
    let status = use_resource(|| async { api::get::<IntegrationsStatus>("/integrations").await });
    rsx! {
        PageHeader { title: tr("DNS-Einträge"), description: tr("Alle DNS-Einträge deiner Domains bei Cloudflare an einem Ort – anlegen, ändern, löschen, Proxy ein und aus.") }
        match &*status.read() {
            None => rsx! { Loading {} },
            Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
            Some(Ok(st)) if !st.cloudflare.configured => rsx! {
                ConnectHint { service: "Cloudflare", text: tr("Trage unter Einstellungen → Verbindungen ein Cloudflare-API-Token ein (Vorlage „Zone-DNS bearbeiten“, alle Zonen). Dasselbe Token holt auch die HTTPS-Zertifikate.") }
            },
            Some(Ok(_)) => rsx! { Zones {} },
        }
    }
}

#[component]
fn Zones() -> Element {
    let zones = use_resource(|| async { api::get::<Value>("/cloudflare/zones?per_page=50").await });
    let mut zone = use_signal(|| None::<(String, String)>);
    match &*zones.read() {
        None => rsx! { Loading {} },
        Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
        Some(Ok(v)) => {
            let all: Vec<(String, String, String)> = list(&v["result"])
                .iter()
                .map(|z| (s(z, "id"), s(z, "name"), s(z, "status")))
                .collect();
            if all.is_empty() {
                return rsx! { Callout { text: tr("Das Token sieht keine Zone – in Cloudflare beim Token die Zone freigeben."), error: true } };
            }
            if zone.peek().is_none() {
                zone.set(Some((all[0].0.clone(), all[0].1.clone())));
            }
            let current = zone().unwrap_or_default();
            rsx! {
                div { class: "grid grid-cols-1 gap-6",
                    if all.len() > 1 {
                        div { class: "flex flex-wrap gap-2",
                            for (id, name, _) in all.iter().cloned() {
                                button {
                                    key: "{id}",
                                    class: if current.0 == id { btn(BTN_PRIMARY) } else { btn(BTN_OUTLINE) },
                                    onclick: move |_| zone.set(Some((id.clone(), name.clone()))),
                                    icons::Globe {}
                                    "{name}"
                                }
                            }
                        }
                    }
                    Records { key: "{current.0}", zone_id: current.0.clone(), zone_name: current.1.clone() }
                }
            }
        }
    }
}

#[derive(Clone, PartialEq, Default)]
struct Draft {
    id: String,
    kind: String,
    name: String,
    content: String,
    ttl: i64,
    proxied: bool,
    priority: i64,
    comment: String,
    // SRV
    weight: i64,
    port: i64,
    // CAA
    flags: i64,
    tag: String,
}

impl Draft {
    fn from(r: &Value, zone: &str) -> Self {
        let d = &r["data"];
        let kind = s(r, "type");
        Draft {
            id: s(r, "id"),
            name: short(&s(r, "name"), zone),
            content: match kind.as_str() {
                "SRV" => s(d, "target"),
                "CAA" => s(d, "value"),
                _ => s(r, "content"),
            },
            ttl: n(r, "ttl").max(1),
            proxied: b(r, "proxied"),
            priority: if kind == "SRV" {
                n(d, "priority")
            } else {
                n(r, "priority")
            },
            comment: s(r, "comment"),
            weight: n(d, "weight"),
            port: n(d, "port"),
            flags: n(d, "flags"),
            tag: if s(d, "tag").is_empty() {
                "issue".into()
            } else {
                s(d, "tag")
            },
            kind,
        }
    }

    fn body(&self, zone: &str) -> Value {
        let name = if self.name.trim() == "@" || self.name.trim().is_empty() {
            zone.to_string()
        } else {
            self.name.trim().to_string()
        };
        let mut v = json!({ "type": self.kind, "name": name, "ttl": self.ttl, "comment": self.comment.trim() });
        match self.kind.as_str() {
            "SRV" => {
                v["data"] = json!({ "priority": self.priority, "weight": self.weight, "port": self.port, "target": self.content.trim() });
            }
            "CAA" => {
                v["data"] =
                    json!({ "flags": self.flags, "tag": self.tag, "value": self.content.trim() });
            }
            "MX" => {
                v["content"] = json!(self.content.trim());
                v["priority"] = json!(self.priority);
            }
            _ => v["content"] = json!(self.content.trim()),
        }
        if proxiable(&self.kind) {
            v["proxied"] = json!(self.proxied);
        }
        v
    }
}

#[component]
fn Records(zone_id: String, zone_name: String) -> Element {
    let admin = state::is_admin();
    let mut version = use_signal(|| 0u64);
    let zid = zone_id.clone();
    let records = use_resource(move || {
        let zid = zid.clone();
        async move {
            let _ = version();
            api::get::<Value>(&format!(
                "/cloudflare/zones/{zid}/dns_records?per_page=5000"
            ))
            .await
        }
    });
    let mut q = use_signal(String::new);
    let mut kind = use_signal(String::new);
    let mut open = use_signal(|| false);
    let mut draft = use_signal(Draft::default);
    let mut busy = use_signal(|| false);

    let zid = zone_id.clone();
    let zname = zone_name.clone();
    let save = move |e: FormEvent| {
        e.prevent_default();
        let d = draft();
        let (zid, zname) = (zid.clone(), zname.clone());
        spawn(async move {
            busy.set(true);
            let body = d.body(&zname);
            let res = if d.id.is_empty() {
                api::post::<Value, _>(&format!("/cloudflare/zones/{zid}/dns_records"), &body).await
            } else {
                api::send::<Value, _>(
                    "PUT",
                    &format!("/cloudflare/zones/{zid}/dns_records/{}", d.id),
                    &body,
                )
                .await
            };
            busy.set(false);
            match res {
                Ok(_) => {
                    open.set(false);
                    toast(tr("Gespeichert."));
                    version += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };

    let filter = q().trim().to_lowercase();
    let rows: Vec<Value> = match &*records.read() {
        Some(Ok(v)) => {
            let mut r = list(&v["result"]);
            r.sort_by_key(|x| (s(x, "name"), s(x, "type")));
            r.into_iter()
                .filter(|x| kind().is_empty() || s(x, "type") == kind())
                .filter(|x| {
                    filter.is_empty()
                        || s(x, "name").to_lowercase().contains(&filter)
                        || content_of(x).to_lowercase().contains(&filter)
                        || s(x, "comment").to_lowercase().contains(&filter)
                })
                .collect()
        }
        _ => Vec::new(),
    };
    let total = match &*records.read() {
        Some(Ok(v)) => list(&v["result"]).len(),
        _ => 0,
    };
    let d = draft();
    let zn = zone_name.clone();

    rsx! {
        Section {
            title: zone_name.clone(),
            description: trf("{0} DNS-Einträge bei Cloudflare. Änderungen gelten sofort weltweit.", &[&total.to_string()]),
            actions: rsx! {
                if admin {
                    button { class: btn_sm(BTN_PRIMARY),
                        onclick: move |_| {
                            draft.set(Draft { kind: "A".into(), ttl: 1, tag: "issue".into(), ..Draft::default() });
                            open.set(true);
                        },
                        icons::Plus {}
                        {tr("Eintrag")}
                    }
                }
            },
            div { class: "mb-3 flex flex-wrap items-center gap-2",
                SearchInput { value: q(), oninput: move |v| q.set(v), placeholder: tr("Name, Inhalt, Kommentar …") }
                select { class: "{SELECT} w-auto", value: "{kind}", onchange: move |e| kind.set(e.value()),
                    option { value: "", {tr("Alle Typen")} }
                    for t in TYPES { option { value: "{t}", "{t}" } }
                }
            }
            match &*records.read() {
                None => rsx! { Loading {} },
                Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
                Some(Ok(_)) => rsx! {
                    TableWrapper {
                        Table {
                            TableHeader {
                                tr {
                                    TableHead { class: "w-20", {tr("Typ")} }
                                    TableHead { {tr("Name")} }
                                    TableHead { {tr("Inhalt")} }
                                    TableHead { class: "w-24", {tr("Proxy")} }
                                    TableHead { class: "hidden w-20 md:table-cell", {tr("TTL")} }
                                    if admin { TableHead { class: "w-20" } }
                                }
                            }
                            TableBody {
                                for r in rows {
                                    {
                                        let rid = s(&r, "id");
                                        let t = s(&r, "type");
                                        let proxied = b(&r, "proxied");
                                        let name = short(&s(&r, "name"), &zn);
                                        let ttl = n(&r, "ttl");
                                        let comment = s(&r, "comment");
                                        let r_edit = r.clone();
                                        let r_toggle = r.clone();
                                        let zid_t = zone_id.clone();
                                        let zid_d = zone_id.clone();
                                        let zn_e = zn.clone();
                                        let full = s(&r, "name");
                                        rsx! {
                                            TableRow { key: "{rid}",
                                                TableCell { Pill { tone: Tone::Strong, "{t}" } }
                                                TableCell { class: "font-mono text-[13px] break-all",
                                                    "{name}"
                                                    if !comment.is_empty() { p { class: "font-sans text-xs text-muted-foreground", "{comment}" } }
                                                }
                                                TableCell { class: "max-w-[28rem] font-mono text-[13px] break-all text-muted-foreground", "{content_of(&r)}" }
                                                TableCell {
                                                    if proxiable(&t) {
                                                        button {
                                                            class: if proxied { "inline-flex items-center gap-1 text-xs font-medium text-orange-500" } else { "inline-flex items-center gap-1 text-xs text-muted-foreground" },
                                                            disabled: !admin,
                                                            title: if proxied { tr("Über Cloudflare (Proxy an) – klicken zum Ausschalten") } else { tr("Nur DNS – klicken, um über Cloudflare zu leiten") },
                                                            onclick: move |_| {
                                                                let zid = zid_t.clone();
                                                                let id = s(&r_toggle, "id");
                                                                let on = !b(&r_toggle, "proxied");
                                                                spawn(async move {
                                                                    match api::send::<Value, _>("PATCH", &format!("/cloudflare/zones/{zid}/dns_records/{id}"), &json!({ "proxied": on })).await {
                                                                        Ok(_) => version += 1,
                                                                        Err(e) => toast_error(e),
                                                                    }
                                                                });
                                                            },
                                                            icons::Cloud { class: "size-4" }
                                                            if proxied { {tr("Proxy")} } else { {tr("Nur DNS")} }
                                                        }
                                                    } else {
                                                        span { class: "text-xs text-muted-foreground", "–" }
                                                    }
                                                }
                                                TableCell { class: "hidden text-muted-foreground md:table-cell", if ttl <= 1 { "Auto" } else { "{crate::util::ttl(ttl as u32)}" } }
                                                if admin {
                                                    TableCell { class: "px-2 text-right whitespace-nowrap",
                                                        button { class: icon_btn(""), title: tr("Bearbeiten"),
                                                            onclick: move |_| { draft.set(Draft::from(&r_edit, &zn_e)); open.set(true); },
                                                            icons::Pencil {}
                                                        }
                                                        button { class: icon_btn("hover:text-destructive"), title: tr("Löschen"),
                                                            onclick: move |_| {
                                                                let zid = zid_d.clone();
                                                                let id = rid.clone();
                                                                let label = format!("{t} {full}");
                                                                spawn(async move {
                                                                    let ask = Ask::new(trf("„{0}“ löschen?", &[&label]), tr("Der Eintrag wird bei Cloudflare sofort gelöscht."))
                                                                        .confirm(tr("Löschen"))
                                                                        .destructive();
                                                                    if !confirm(ask).await { return; }
                                                                    match api::delete(&format!("/cloudflare/zones/{zid}/dns_records/{id}")).await {
                                                                        Ok(()) => version += 1,
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
                                }
                            }
                        }
                    }
                },
            }
        }
        Modal { open, title: if d.id.is_empty() { tr("Neuer DNS-Eintrag") } else { tr("DNS-Eintrag bearbeiten") }, description: zone_name.clone(),
            form { class: "grid grid-cols-1 gap-4", onsubmit: save,
                div { class: "grid grid-cols-[7rem_minmax(0,1fr)] gap-3",
                    Field { label: tr("Typ"),
                        select { class: SELECT, disabled: !d.id.is_empty(), value: "{d.kind}",
                            onchange: move |e| draft.write().kind = e.value(),
                            for t in TYPES { option { value: "{t}", "{t}" } }
                        }
                    }
                    Field { label: tr("Name"), hint: trf("@ = {0} selbst, sonst z. B. music", &[&zone_name]),
                        input { class: "{INPUT} font-mono text-[13px]", required: true, spellcheck: false, autocapitalize: "none",
                            value: "{d.name}", oninput: move |e| draft.write().name = e.value() }
                    }
                }
                Field {
                    label: match d.kind.as_str() { "A" => tr("IPv4-Adresse"), "AAAA" => tr("IPv6-Adresse"), "CNAME" | "NS" | "MX" | "SRV" => tr("Ziel (Name)"), "CAA" => tr("Wert (z. B. letsencrypt.org)"), _ => tr("Inhalt") },
                    if d.kind == "TXT" {
                        textarea { class: "{INPUT} min-h-20 py-2 font-mono text-[13px]", required: true, value: "{d.content}", oninput: move |e| draft.write().content = e.value() }
                    } else {
                        input { class: "{INPUT} font-mono text-[13px]", required: true, spellcheck: false, autocapitalize: "none",
                            placeholder: match d.kind.as_str() { "A" => "192.0.2.1", "AAAA" => "2001:db8::1", "CAA" => "letsencrypt.org", _ => "ziel.zweers.ch" },
                            value: "{d.content}", oninput: move |e| draft.write().content = e.value() }
                    }
                }
                if matches!(d.kind.as_str(), "MX" | "SRV") {
                    div { class: "grid grid-cols-3 gap-3",
                        Field { label: tr("Priorität"),
                            input { class: INPUT, r#type: "number", min: 0, max: 65535, value: "{d.priority}", oninput: move |e| draft.write().priority = e.value().parse().unwrap_or(0) }
                        }
                        if d.kind == "SRV" {
                            Field { label: tr("Gewicht"),
                                input { class: INPUT, r#type: "number", min: 0, max: 65535, value: "{d.weight}", oninput: move |e| draft.write().weight = e.value().parse().unwrap_or(0) }
                            }
                            Field { label: tr("Port"),
                                input { class: INPUT, r#type: "number", min: 0, max: 65535, value: "{d.port}", oninput: move |e| draft.write().port = e.value().parse().unwrap_or(0) }
                            }
                        }
                    }
                }
                if d.kind == "CAA" {
                    div { class: "grid grid-cols-2 gap-3",
                        Field { label: tr("Tag"),
                            select { class: SELECT, value: "{d.tag}", onchange: move |e| draft.write().tag = e.value(),
                                option { value: "issue", "issue" }
                                option { value: "issuewild", "issuewild" }
                                option { value: "iodef", "iodef" }
                            }
                        }
                        Field { label: tr("Flags"),
                            input { class: INPUT, r#type: "number", min: 0, max: 255, value: "{d.flags}", oninput: move |e| draft.write().flags = e.value().parse().unwrap_or(0) }
                        }
                    }
                }
                div { class: "grid grid-cols-2 gap-3",
                    Field { label: tr("TTL"),
                        select { class: SELECT, disabled: d.proxied && proxiable(&d.kind), value: "{d.ttl}",
                            onchange: move |e| draft.write().ttl = e.value().parse().unwrap_or(1),
                            for (v, l) in TTLS { option { value: "{v}", "{l}" } }
                        }
                    }
                    if proxiable(&d.kind) {
                        div { class: "flex items-end pb-1",
                            Toggle { checked: d.proxied, onchange: move |v| { let mut w = draft.write(); w.proxied = v; if v { w.ttl = 1; } },
                                label: tr("Über Cloudflare (Proxy)"),
                            }
                        }
                    }
                }
                Field { label: tr("Kommentar (optional)"),
                    input { class: INPUT, maxlength: 100, value: "{d.comment}", oninput: move |e| draft.write().comment = e.value() }
                }
                if proxiable(&d.kind) && d.proxied {
                    p { class: "text-xs text-muted-foreground", {tr("Mit Proxy zeigt der Name öffentlich auf Cloudflare. Im eigenen Netz beantwortet nrzNetwork Namen aus dem Reverse Proxy trotzdem mit der Adresse dieses Geräts.")} }
                }
                div { class: "flex justify-end gap-2",
                    button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| open.set(false), {tr("Abbrechen")} }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy(), {tr("Speichern")} }
                }
            }
        }
    }
}
