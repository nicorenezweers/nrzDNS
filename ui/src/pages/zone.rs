//! Eine Zone: Einstellungen (SOA bzw. Weiterleitungen, Kommentar), Einträge mit Filter nach
//! Name und Typ, Dialog mit eigenen Feldern für jeden Typ, Ein/Aus, Löschen, Export.

use crate::Route;
use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::components::upstreams::UpstreamEditor;
use crate::i18n::{tr, trf};
use crate::labels;
use crate::state;
use crate::ui::table::*;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{
    RecordData, RecordInput, RecordType, Soa, UpdateZoneInput, Upstream, Zone, ZoneDetail,
    ZoneKind, ZoneRecord, record_fqdn,
};

#[component]
pub fn ZoneView(id: i64) -> Element {
    let admin = state::is_admin();
    let nav = use_navigator();
    let mut version = use_signal(|| 0u64);
    let detail = use_resource(use_reactive!(|id| async move {
        let _ = version();
        api::get::<ZoneDetail>(&format!("/zones/{id}")).await
    }));
    let back = rsx! {
        Link { to: Route::Zones {}, class: "mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground",
            icons::ChevronLeft { class: "size-4" }
            {tr("Zonen")}
        }
    };
    let d = match &*detail.read() {
        None => return rsx! { {back} Loading {} },
        Some(Err(e)) => {
            return rsx! {
                {back}
                Callout { text: e.message.clone(), error: true }
            };
        }
        Some(Ok(d)) => d.clone(),
    };
    let zone = d.zone.clone();
    let zone_name = zone.name.clone();
    rsx! {
        {back}
        PageHeader {
            title: zone.name.clone(),
            description: if zone.comment.is_empty() { None } else { Some(zone.comment.clone()) },
            actions: rsx! {
                Pill { tone: if zone.kind == ZoneKind::Primary { Tone::Strong } else { Tone::Neutral }, {labels::zone_kind(zone.kind)} }
                if zone.disabled {
                    Pill { tone: Tone::Warning, {tr("ausgeschaltet")} }
                }
                a { class: btn(BTN_OUTLINE), href: api::href(&format!("/zones/{id}/export")), download: "{zone.name}.zone",
                    icons::Download {}
                    {tr("Exportieren")}
                }
                if admin {
                    button {
                        class: btn(BTN_OUTLINE),
                        onclick: {
                            let on = zone.disabled;
                            move |_| {
                                spawn(async move {
                                    match api::put::<Zone, _>(&format!("/zones/{id}"), &UpdateZoneInput { disabled: Some(!on), ..Default::default() }).await {
                                        Ok(_) => version += 1,
                                        Err(e) => toast_error(e),
                                    }
                                });
                            }
                        },
                        if zone.disabled {
                            icons::Play {}
                            {tr("Einschalten")}
                        } else {
                            icons::Pause {}
                            {tr("Ausschalten")}
                        }
                    }
                    button {
                        class: "{btn(BTN_OUTLINE)} hover:text-destructive",
                        title: tr("Zone löschen"),
                        onclick: move |_| {
                            let name = zone_name.clone();
                            spawn(async move {
                                let ask = Ask::new(trf("Zone „{0}“ löschen?", &[&name]), tr("Die Zone wird mit allen Einträgen gelöscht. Das lässt sich nicht rückgängig machen."))
                                    .confirm(tr("Zone löschen"))
                                    .destructive();
                                if confirm(ask).await {
                                    match api::delete(&format!("/zones/{id}")).await {
                                        Ok(()) => {
                                            toast(trf("Zone „{0}“ gelöscht.", &[&name]));
                                            nav.push(Route::Zones {});
                                        }
                                        Err(e) => toast_error(e),
                                    }
                                }
                            });
                        },
                        icons::Trash2 {}
                    }
                }
            },
        }
        div { class: "grid grid-cols-1 gap-6",
            if !admin {
                ReadOnlyHint {}
            }
            ZoneSettings { zone: zone.clone(), admin, on_saved: move |_| version += 1 }
            Records { zone: zone.clone(), records: d.records.clone(), admin, on_change: move |_| version += 1 }
        }
    }
}

// ------------------------------------------------------------------ Einstellungen der Zone

/// SOA (Primärzone) bzw. Weiterleitungen (bedingte Weiterleitung) und Kommentar, aufklappbar.
#[component]
fn ZoneSettings(zone: Zone, admin: bool, on_saved: EventHandler<()>) -> Element {
    let primary = zone.kind == ZoneKind::Primary;
    let mut open = use_signal(|| !primary);
    let mut soa = use_signal(|| zone.soa.clone());
    let mut forwarders = use_signal(|| zone.forwarders.clone());
    let mut comment = use_signal(|| zone.comment.clone());
    let mut busy = use_signal(|| false);
    // Neuer Stand vom Server (z. B. höhere Seriennummer nach einem neuen Eintrag) → übernehmen
    let fresh = zone.clone();
    use_effect(use_reactive!(|fresh| {
        soa.set(fresh.soa.clone());
        forwarders.set(fresh.forwarders.clone());
        comment.set(fresh.comment.clone());
    }));
    let id = zone.id;
    let changed = soa() != zone.soa
        || forwarders() != zone.forwarders
        || comment().trim() != zone.comment.trim();
    let summary = if primary {
        trf(
            "Seriennummer {0} · Primärer Server {1}",
            &[&zone.soa.serial, &zone.soa.primary_ns],
        )
    } else {
        let names: Vec<String> = zone.forwarders.iter().map(|u| u.label()).collect();
        if names.is_empty() {
            tr("Noch kein Server eingetragen.")
        } else {
            names.join(", ")
        }
    };
    let submit = move |e: FormEvent| {
        e.prevent_default();
        let fw: Vec<Upstream> = forwarders()
            .into_iter()
            .filter(|u| !u.address.trim().is_empty())
            .collect();
        if !primary && fw.is_empty() {
            toast_error(tr(
                "Eine Weiterleitungszone braucht mindestens einen Server.",
            ));
            return;
        }
        let body = UpdateZoneInput {
            disabled: None,
            soa: primary.then(|| soa.cloned()),
            forwarders: (!primary).then_some(fw),
            comment: Some(comment().trim().to_string()),
        };
        spawn(async move {
            busy.set(true);
            let res = api::put::<Zone, _>(&format!("/zones/{id}"), &body).await;
            busy.set(false);
            match res {
                Ok(_) => {
                    toast(tr("Zone gespeichert."));
                    on_saved.call(());
                }
                Err(e) => toast_error(e),
            }
        });
    };
    let num = move |label: String, hint: String, value: u32, set: fn(&mut Soa, u32)| {
        rsx! {
            NumField {
                label,
                hint,
                value,
                min: 0,
                max: u32::MAX,
                disabled: !admin,
                onchange: move |v| {
                    let mut s = soa();
                    set(&mut s, v);
                    soa.set(s);
                },
            }
        }
    };
    let s = soa();
    rsx! {
        section { class: "rounded-xl border bg-card shadow-sm",
            button {
                class: "flex w-full items-center gap-3 px-5 py-4 text-left sm:px-6",
                r#type: "button",
                "aria-expanded": "{open}",
                onclick: move |_| open.toggle(),
                span { class: if open() { "grid rotate-90 text-muted-foreground transition-transform" } else { "grid text-muted-foreground transition-transform" },
                    icons::ChevronRight { class: "size-4" }
                }
                span { class: "min-w-0 flex-1",
                    span { class: "block font-semibold leading-none",
                        if primary { {tr("SOA und Kommentar")} } else { {tr("Weiterleitung und Kommentar")} }
                    }
                    span { class: "mt-1.5 block truncate text-sm text-muted-foreground", "{summary}" }
                }
            }
            if open() {
                form { class: "grid grid-cols-1 gap-5 border-t px-5 py-5 sm:px-6", onsubmit: submit,
                    if primary {
                        div { class: "grid grid-cols-1 gap-4 sm:grid-cols-2",
                            Field { label: tr("Primärer Nameserver"), hint: tr("Voller Name, z. B. ns.nrzdns.local"),
                                input {
                                    class: "{INPUT} font-mono text-[13px]",
                                    disabled: !admin,
                                    spellcheck: false,
                                    value: "{s.primary_ns}",
                                    oninput: move |e| {
                                        let mut s = soa();
                                        s.primary_ns = e.value().trim().trim_end_matches('.').to_string();
                                        soa.set(s);
                                    },
                                }
                            }
                            Field { label: tr("Verantwortlich"), hint: tr("Adresse in DNS-Schreibweise, z. B. hostmaster.example.com"),
                                input {
                                    class: "{INPUT} font-mono text-[13px]",
                                    disabled: !admin,
                                    spellcheck: false,
                                    value: "{s.responsible}",
                                    oninput: move |e| {
                                        let mut s = soa();
                                        s.responsible = e.value().trim().trim_end_matches('.').to_string();
                                        soa.set(s);
                                    },
                                }
                            }
                        }
                        div { class: "grid grid-cols-1 gap-4 sm:grid-cols-3 lg:grid-cols-5",
                            {num(tr("Seriennummer"), tr("Steigt bei jeder Änderung."), s.serial, |s, v| s.serial = v)}
                            {num(tr("Refresh (s)"), tr("Abgleich sekundärer Server"), s.refresh, |s, v| s.refresh = v)}
                            {num(tr("Retry (s)"), tr("Nach fehlgeschlagenem Abgleich"), s.retry, |s, v| s.retry = v)}
                            {num(tr("Expire (s)"), tr("Danach gilt die Kopie nicht mehr"), s.expire, |s, v| s.expire = v)}
                            {num(tr("Minimum (s)"), tr("TTL negativer Antworten"), s.minimum, |s, v| s.minimum = v)}
                        }
                    } else {
                        div { class: "grid grid-cols-1 gap-2",
                            span { class: "text-sm font-medium", {tr("Weiterleiten an")} }
                            UpstreamEditor { value: forwarders(), onchange: move |v| forwarders.set(v), disabled: !admin, presets: false }
                        }
                    }
                    Field { label: tr("Kommentar"),
                        input { class: INPUT, disabled: !admin, maxlength: 200, value: "{comment}", oninput: move |e| comment.set(e.value()) }
                    }
                    if admin {
                        div {
                            button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy() || !changed, {tr("Speichern")} }
                        }
                    }
                }
            }
        }
    }
}

// ------------------------------------------------------------------ Einträge

#[component]
fn Records(
    zone: Zone,
    records: Vec<ZoneRecord>,
    admin: bool,
    on_change: EventHandler<()>,
) -> Element {
    let mut q = use_signal(String::new);
    let mut type_filter = use_signal(String::new);
    let mut dialog_open = use_signal(|| false);
    let mut editing = use_signal(|| None::<ZoneRecord>);
    let filter = q().trim().to_lowercase();
    let tf = type_filter();
    let zone_name = zone.name.clone();
    let shown: Vec<ZoneRecord> = records
        .iter()
        .filter(|r| {
            filter.is_empty()
                || r.name.to_lowercase().contains(&filter)
                || r.fqdn(&zone_name).contains(&filter)
                || r.data.summary().to_lowercase().contains(&filter)
        })
        .filter(|r| tf.is_empty() || r.data.record_type().as_str() == tf)
        .cloned()
        .collect();
    let id = zone.id;
    rsx! {
        Section {
            title: tr("Einträge"),
            description: trf("{0} Einträge in dieser Zone", &[&records.len()]),
            actions: rsx! {
                if admin {
                    button {
                        class: btn(BTN_PRIMARY),
                        onclick: move |_| {
                            editing.set(None);
                            dialog_open.set(true);
                        },
                        icons::Plus {}
                        {tr("Eintrag hinzufügen")}
                    }
                }
            },
            div { class: "grid grid-cols-1 gap-4",
                div { class: "flex flex-wrap items-center gap-2",
                    SearchInput { id: "page-search", value: q(), oninput: move |v| q.set(v), placeholder: tr("Name oder Daten filtern …") }
                    select { class: select_class("w-auto min-w-32"), "aria-label": tr("Typ"), onchange: move |e| type_filter.set(e.value()),
                        option { value: "", selected: tf.is_empty(), {tr("Alle Typen")} }
                        for t in RecordType::ALL {
                            option { value: t.as_str(), selected: tf == t.as_str(), "{t.as_str()}" }
                        }
                    }
                }
                if records.is_empty() {
                    div { class: "rounded-lg border border-dashed px-4 py-8 text-center text-sm text-muted-foreground", {tr("Noch keine Einträge.")} }
                } else {
                    TableWrapper { class: "bg-transparent",
                        Table {
                            TableHeader {
                                tr {
                                    TableHead { {tr("Name")} }
                                    TableHead { {tr("Typ")} }
                                    TableHead { class: "hidden sm:table-cell", {tr("TTL")} }
                                    TableHead { {tr("Daten")} }
                                    TableHead { class: "hidden lg:table-cell", {tr("Kommentar")} }
                                    TableHead { {tr("Aktiv")} }
                                    if admin {
                                        TableHead { class: "w-20" }
                                    }
                                }
                            }
                            TableBody {
                                if shown.is_empty() {
                                    tr {
                                        td { class: "px-3 py-6 text-center text-muted-foreground", colspan: "7", {tr("Keine Treffer.")} }
                                    }
                                }
                                for r in shown {
                                    RecordRow {
                                        key: "{r.id}",
                                        record: r.clone(),
                                        zone: zone_name.clone(),
                                        admin,
                                        on_edit: move |r: ZoneRecord| {
                                            editing.set(Some(r));
                                            dialog_open.set(true);
                                        },
                                        on_change: move |_| on_change.call(()),
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        RecordDialog { open: dialog_open, zone_id: id, zone: zone.name.clone(), record: editing(), on_done: move |_| on_change.call(()) }
    }
}

fn record_input(r: &ZoneRecord) -> RecordInput {
    RecordInput {
        name: r.name.clone(),
        ttl: r.ttl,
        data: r.data.clone(),
        disabled: r.disabled,
        comment: r.comment.clone(),
    }
}

#[component]
fn RecordRow(
    record: ZoneRecord,
    zone: String,
    admin: bool,
    on_edit: EventHandler<ZoneRecord>,
    on_change: EventHandler<()>,
) -> Element {
    let r = record;
    let (zid, rid) = (r.zone_id, r.id);
    let fqdn = r.fqdn(&zone);
    let summary = r.data.summary();
    let muted = if r.disabled { "opacity-50" } else { "" };
    let toggled = r.clone();
    let deleted = r.clone();
    let edited = r.clone();
    rsx! {
        TableRow {
            TableCell { class: "font-mono text-[13px] {muted}", title: "{fqdn}", "{r.name}" }
            TableCell { class: muted,
                Pill { "{r.data.record_type().as_str()}" }
            }
            TableCell { class: "hidden whitespace-nowrap text-muted-foreground sm:table-cell {muted}",
                if r.ttl == 0 { {tr("Standard")} } else { {util::ttl(r.ttl)} }
            }
            TableCell { class: "min-w-40 max-w-md font-mono text-[13px] break-all {muted}", "{summary}" }
            TableCell { class: "hidden max-w-xs truncate text-muted-foreground lg:table-cell {muted}", title: "{r.comment}", "{r.comment}" }
            TableCell {
                Toggle {
                    checked: !r.disabled,
                    disabled: !admin,
                    onchange: move |on: bool| {
                        let mut input = record_input(&toggled);
                        input.disabled = !on;
                        spawn(async move {
                            match api::put::<ZoneRecord, _>(&format!("/zones/{zid}/records/{rid}"), &input).await {
                                Ok(_) => on_change.call(()),
                                Err(e) => toast_error(e),
                            }
                        });
                    },
                }
            }
            if admin {
                TableCell { class: "px-2",
                    div { class: "flex items-center justify-end gap-0.5",
                        button { class: ICON_BTN, title: tr("Bearbeiten"), onclick: move |_| on_edit.call(edited.clone()),
                            icons::Pencil {}
                        }
                        button {
                            class: icon_btn("hover:text-destructive"),
                            title: tr("Eintrag löschen"),
                            onclick: move |_| {
                                let r = deleted.clone();
                                spawn(async move {
                                    let ask = Ask::new(trf("Eintrag „{0} {1}“ löschen?", &[&r.name, &r.data.record_type().as_str()]), r.data.summary())
                                        .confirm(tr("Löschen"))
                                        .destructive();
                                    if confirm(ask).await {
                                        match api::delete(&format!("/zones/{zid}/records/{rid}")).await {
                                            Ok(()) => {
                                                toast(tr("Eintrag gelöscht."));
                                                on_change.call(());
                                            }
                                            Err(e) => toast_error(e),
                                        }
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

// ------------------------------------------------------------------ Dialog für einen Eintrag

/// Alle Felder als Text, damit halbe Eingaben stehen bleiben; erst beim Speichern geprüft.
#[derive(Clone, PartialEq)]
struct Form {
    name: String,
    rtype: RecordType,
    ttl: String,
    comment: String,
    disabled: bool,
    address: String,
    target: String,
    preference: String,
    text: String,
    priority: String,
    weight: String,
    port: String,
    flags: String,
    tag: String,
    value: String,
}

impl Default for Form {
    fn default() -> Self {
        Form {
            name: String::new(),
            rtype: RecordType::A,
            ttl: "0".into(),
            comment: String::new(),
            disabled: false,
            address: String::new(),
            target: String::new(),
            preference: "10".into(),
            text: String::new(),
            priority: "0".into(),
            weight: "0".into(),
            port: String::new(),
            flags: "0".into(),
            tag: "issue".into(),
            value: String::new(),
        }
    }
}

impl Form {
    fn from_record(r: &ZoneRecord) -> Self {
        let mut f = Form {
            name: r.name.clone(),
            rtype: r.data.record_type(),
            ttl: r.ttl.to_string(),
            comment: r.comment.clone(),
            disabled: r.disabled,
            ..Default::default()
        };
        match &r.data {
            RecordData::A { address } | RecordData::AAAA { address } => f.address = address.clone(),
            RecordData::CNAME { target } | RecordData::PTR { target } => f.target = target.clone(),
            RecordData::NS { host } => f.target = host.clone(),
            RecordData::MX {
                preference,
                exchange,
            } => {
                f.preference = preference.to_string();
                f.target = exchange.clone();
            }
            RecordData::TXT { text } => f.text = text.clone(),
            RecordData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                f.priority = priority.to_string();
                f.weight = weight.to_string();
                f.port = port.to_string();
                f.target = target.clone();
            }
            RecordData::CAA { flags, tag, value } => {
                f.flags = flags.to_string();
                f.tag = tag.clone();
                f.value = value.clone();
            }
        }
        f
    }

    fn to_input(&self) -> Result<RecordInput, String> {
        let host = |s: &str| -> Result<String, String> {
            let h = s.trim().trim_end_matches('.').to_ascii_lowercase();
            if h.is_empty() {
                Err(tr("Bitte einen Zielnamen angeben."))
            } else {
                Ok(h)
            }
        };
        let u16f = |s: &str, label: &str| {
            s.trim()
                .parse::<u16>()
                .map_err(|_| trf("„{0}“ muss eine Zahl von 0 bis 65535 sein.", &[&label]))
        };
        let addr = self.address.trim().to_string();
        let data = match self.rtype {
            RecordType::A => {
                if addr.parse::<std::net::Ipv4Addr>().is_err() {
                    return Err(tr(
                        "Das ist keine gültige IPv4-Adresse (z. B. 192.168.1.10).",
                    ));
                }
                RecordData::A { address: addr }
            }
            RecordType::AAAA => {
                if addr.parse::<std::net::Ipv6Addr>().is_err() {
                    return Err(tr("Das ist keine gültige IPv6-Adresse (z. B. fd00::10)."));
                }
                RecordData::AAAA { address: addr }
            }
            RecordType::CNAME => RecordData::CNAME {
                target: host(&self.target)?,
            },
            RecordType::PTR => RecordData::PTR {
                target: host(&self.target)?,
            },
            RecordType::NS => RecordData::NS {
                host: host(&self.target)?,
            },
            RecordType::MX => RecordData::MX {
                preference: u16f(&self.preference, &tr("Priorität"))?,
                exchange: host(&self.target)?,
            },
            RecordType::TXT => {
                if self.text.is_empty() {
                    return Err(tr("Bitte einen Text angeben."));
                }
                RecordData::TXT {
                    text: self.text.clone(),
                }
            }
            RecordType::SRV => RecordData::SRV {
                priority: u16f(&self.priority, &tr("Priorität"))?,
                weight: u16f(&self.weight, &tr("Gewicht"))?,
                port: u16f(&self.port, &tr("Port"))?,
                target: host(&self.target)?,
            },
            RecordType::CAA => {
                let flags = self
                    .flags
                    .trim()
                    .parse::<u8>()
                    .map_err(|_| tr("Flags müssen eine Zahl von 0 bis 255 sein."))?;
                if self.value.trim().is_empty() {
                    return Err(tr("Bitte einen Wert angeben, z. B. letsencrypt.org."));
                }
                RecordData::CAA {
                    flags,
                    tag: self.tag.trim().to_string(),
                    value: self.value.trim().to_string(),
                }
            }
        };
        let ttl = self
            .ttl
            .trim()
            .parse::<u32>()
            .map_err(|_| tr("Die TTL muss eine ganze Zahl sein (0 = Standard)."))?;
        let name = if self.name.trim().is_empty() {
            "@".to_string()
        } else {
            self.name.trim().to_ascii_lowercase()
        };
        Ok(RecordInput {
            name,
            ttl,
            data,
            disabled: self.disabled,
            comment: self.comment.trim().to_string(),
        })
    }
}

#[component]
fn RecordDialog(
    open: Signal<bool>,
    zone_id: i64,
    zone: String,
    record: Option<ZoneRecord>,
    on_done: EventHandler<()>,
) -> Element {
    let mut form = use_signal(Form::default);
    let mut busy = use_signal(|| false);
    let init = record.clone();
    use_effect(use_reactive!(|init| {
        if open() {
            form.set(init.as_ref().map(Form::from_record).unwrap_or_default());
        }
    }));
    let rid = record.as_ref().map(|r| r.id);
    let f = form();
    let submit = move |e: FormEvent| {
        e.prevent_default();
        let input = match form().to_input() {
            Ok(i) => i,
            Err(msg) => {
                toast_error(msg);
                return;
            }
        };
        spawn(async move {
            busy.set(true);
            let res = match rid {
                Some(rid) => {
                    api::put::<ZoneRecord, _>(&format!("/zones/{zone_id}/records/{rid}"), &input)
                        .await
                }
                None => {
                    api::post::<ZoneRecord, _>(&format!("/zones/{zone_id}/records"), &input).await
                }
            };
            busy.set(false);
            match res {
                Ok(_) => {
                    toast(if rid.is_some() {
                        tr("Eintrag gespeichert.")
                    } else {
                        tr("Eintrag hinzugefügt.")
                    });
                    open.set(false);
                    on_done.call(());
                }
                Err(e) => toast_error(e),
            }
        });
    };
    let mut set = move |change: fn(&mut Form, String), v: String| {
        let mut f = form();
        change(&mut f, v);
        form.set(f);
    };
    let preview = record_fqdn(&f.name, &zone);
    let target_hint = match f.rtype {
        RecordType::PTR => tr("Voller Name des Geräts, z. B. nas.home.arpa"),
        RecordType::NS => tr("Voller Name des Nameservers, z. B. ns1.example.com"),
        RecordType::MX => tr("Voller Name des Mailservers, z. B. mail.example.com"),
        RecordType::SRV => tr("Voller Name des Servers, z. B. sip.example.com"),
        _ => tr("Voller Name, z. B. www.example.com (ohne Punkt am Ende)"),
    };
    rsx! {
        Modal { open, title: if rid.is_some() { tr("Eintrag bearbeiten") } else { tr("Eintrag hinzufügen") }, description: trf("in der Zone {0}", &[&zone]), class: "max-w-xl",
            form { class: "grid grid-cols-1 gap-4", onsubmit: submit,
                div { class: "grid grid-cols-1 gap-4 sm:grid-cols-[minmax(0,1fr)_8rem]",
                    Field { label: tr("Name"), hint: trf("@ = die Zone selbst, * = Platzhalter · ergibt {0}", &[&preview]),
                        div { class: "flex items-center",
                            input {
                                class: "{INPUT} rounded-r-none font-mono text-[13px]",
                                spellcheck: false,
                                autocapitalize: "none",
                                placeholder: "@",
                                value: "{f.name}",
                                oninput: move |e| set(|f, v| f.name = v, e.value()),
                            }
                            span { class: "flex h-9 max-w-[60%] shrink-0 items-center rounded-r-md border border-l-0 border-input bg-muted/50 px-2.5 font-mono text-xs text-muted-foreground", title: ".{zone}",
                                span { class: "truncate", ".{zone}" }
                            }
                        }
                    }
                    Field { label: tr("Typ"),
                        select {
                            class: SELECT,
                            onchange: move |e| {
                                if let Some(t) = RecordType::parse(&e.value()) {
                                    let mut f = form();
                                    f.rtype = t;
                                    form.set(f);
                                }
                            },
                            for t in RecordType::ALL {
                                option { value: t.as_str(), selected: f.rtype == t, "{t.as_str()}" }
                            }
                        }
                    }
                }
                match f.rtype {
                    RecordType::A | RecordType::AAAA => rsx! {
                        Field { label: if f.rtype == RecordType::A { tr("IPv4-Adresse") } else { tr("IPv6-Adresse") },
                            input {
                                class: "{INPUT} font-mono text-[13px]",
                                required: true,
                                spellcheck: false,
                                placeholder: if f.rtype == RecordType::A { "192.168.1.10" } else { "fd00::10" },
                                value: "{f.address}",
                                oninput: move |e| set(|f, v| f.address = v, e.value()),
                            }
                        }
                    },
                    RecordType::TXT => rsx! {
                        Field { label: tr("Text"), hint: tr("Längere Texte als 255 Zeichen werden automatisch geteilt."),
                            textarea {
                                class: "min-h-24 w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-[13px] shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 dark:bg-input/30",
                                required: true,
                                spellcheck: false,
                                placeholder: "v=spf1 mx -all",
                                value: "{f.text}",
                                oninput: move |e| set(|f, v| f.text = v, e.value()),
                            }
                        }
                    },
                    RecordType::CAA => rsx! {
                        div { class: "grid grid-cols-1 gap-4 sm:grid-cols-[6rem_10rem_minmax(0,1fr)]",
                            Field { label: tr("Flags"),
                                input { class: INPUT, r#type: "number", min: 0, max: 255, required: true, value: "{f.flags}", oninput: move |e| set(|f, v| f.flags = v, e.value()) }
                            }
                            Field { label: tr("CAA-Tag"),
                                select { class: SELECT, onchange: move |e| set(|f, v| f.tag = v, e.value()),
                                    for t in ["issue", "issuewild", "iodef"] {
                                        option { value: t, selected: f.tag == t, "{t}" }
                                    }
                                }
                            }
                            Field { label: tr("Wert"),
                                input {
                                    class: "{INPUT} font-mono text-[13px]",
                                    required: true,
                                    spellcheck: false,
                                    placeholder: "letsencrypt.org",
                                    value: "{f.value}",
                                    oninput: move |e| set(|f, v| f.value = v, e.value()),
                                }
                            }
                        }
                    },
                    _ => rsx! {
                        if f.rtype == RecordType::MX {
                            Field { label: tr("Priorität"), hint: tr("Kleinere Zahl = bevorzugt"),
                                input { class: "{INPUT} max-w-32", r#type: "number", min: 0, max: 65535, required: true, value: "{f.preference}", oninput: move |e| set(|f, v| f.preference = v, e.value()) }
                            }
                        }
                        if f.rtype == RecordType::SRV {
                            div { class: "grid grid-cols-3 gap-4",
                                Field { label: tr("Priorität"),
                                    input { class: INPUT, r#type: "number", min: 0, max: 65535, required: true, value: "{f.priority}", oninput: move |e| set(|f, v| f.priority = v, e.value()) }
                                }
                                Field { label: tr("Gewicht"),
                                    input { class: INPUT, r#type: "number", min: 0, max: 65535, required: true, value: "{f.weight}", oninput: move |e| set(|f, v| f.weight = v, e.value()) }
                                }
                                Field { label: tr("Port"),
                                    input { class: INPUT, r#type: "number", min: 0, max: 65535, required: true, placeholder: "5060", value: "{f.port}", oninput: move |e| set(|f, v| f.port = v, e.value()) }
                                }
                            }
                        }
                        Field { label: if f.rtype == RecordType::NS { tr("Nameserver") } else { tr("Ziel") }, hint: target_hint.clone(),
                            input {
                                class: "{INPUT} font-mono text-[13px]",
                                required: true,
                                spellcheck: false,
                                autocapitalize: "none",
                                value: "{f.target}",
                                oninput: move |e| set(|f, v| f.target = v, e.value()),
                            }
                        }
                    },
                }
                div { class: "grid grid-cols-1 gap-4 sm:grid-cols-[8rem_minmax(0,1fr)]",
                    Field { label: tr("TTL (s)"), hint: tr("0 = Standard"),
                        input { class: INPUT, r#type: "number", min: 0, required: true, value: "{f.ttl}", oninput: move |e| set(|f, v| f.ttl = v, e.value()) }
                    }
                    Field { label: tr("Kommentar (optional)"),
                        input { class: INPUT, maxlength: 200, value: "{f.comment}", oninput: move |e| set(|f, v| f.comment = v, e.value()) }
                    }
                }
                Toggle {
                    checked: !f.disabled,
                    onchange: move |on: bool| {
                        let mut f = form();
                        f.disabled = !on;
                        form.set(f);
                    },
                    label: tr("Aktiv"),
                    hint: tr("Ausgeschaltete Einträge bleiben gespeichert, werden aber nicht beantwortet."),
                }
                div { class: "flex justify-end gap-2",
                    button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| open.set(false), {tr("Abbrechen")} }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy(),
                        if rid.is_some() { {tr("Speichern")} } else { {tr("Hinzufügen")} }
                    }
                }
            }
        }
    }
}
