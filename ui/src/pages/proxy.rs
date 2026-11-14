//! Reverse Proxy: Namen wie `music.nrz.ch` an ein HTTP-Ziel wie `http://100.78.107.162:8350`
//! weiterreichen. nrzNetwork beantwortet den Namen selbst mit der Adresse des Proxys.

use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::i18n::{tr, trf};
use crate::state;
use crate::ui::alert::{Alert, AlertDescription, AlertTitle};
use crate::ui::table::*;
use dioxus::prelude::*;
use nrzdns_types::{
    GatewayStatus, ProxyHost, ProxyHostInput, ProxySettings, ProxyStatus, TlsSettings,
    TlsSettingsInput, TlsStatus,
};

/// Passt `host` zu einem Namen im Zertifikat (`*.zweers.ch` = genau eine Ebene)?
pub fn https_covers(names: &[String], host: &str) -> bool {
    names.iter().any(|n| match n.strip_prefix("*.") {
        Some(base) => host
            .strip_suffix(base)
            .and_then(|l| l.strip_suffix('.'))
            .is_some_and(|l| !l.is_empty() && !l.contains('.')),
        None => n == host,
    })
}

/// Adresse, unter der Browser den Namen öffnen.
fn url(host: &str, port: u16, https: &[String]) -> String {
    if https_covers(https, host) {
        format!("https://{host}/")
    } else if port == 80 || port == 0 {
        format!("http://{host}/")
    } else {
        format!("http://{host}:{port}/")
    }
}

#[component]
pub fn Proxy() -> Element {
    let admin = state::is_admin();
    let version = use_signal(|| 0u64);
    let status = use_resource(move || async move {
        let _ = version();
        api::get::<ProxyStatus>("/proxy").await
    });

    rsx! {
        PageHeader { title: tr("Reverse Proxy"), description: tr("Eigene Namen statt IP-Adresse und Port, z. B. music.nrz.ch statt 100.78.107.162:8350.") }
        div { class: "grid grid-cols-1 gap-6",
            Alert {
                icons::Waypoints {}
                AlertTitle { {tr("So funktioniert es")} }
                AlertDescription {
                    p { {tr("Trage einen Namen und das Ziel ein. nrzNetwork beantwortet den Namen mit der Adresse dieses Geräts, und der Proxy reicht jede HTTP-Anfrage für diesen Namen an das Ziel weiter – Ports spielen für den Browser keine Rolle mehr. Die Domain muss dir nicht gehören: Es klappt auf allen Geräten, die nrzNetwork als DNS-Server benutzen. HTTPS gibt es für eigene Domains bei Cloudflare (unten).")} }
                }
            }
            if !admin {
                ReadOnlyHint {}
            }
            match &*status.read() {
                None => rsx! { Loading {} },
                Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
                Some(Ok(s)) => rsx! {
                    if s.listen.is_empty() {
                        Callout { text: tr("Der Proxy ist ausgeschaltet (NRZDNS_PROXY_LISTEN ist leer). Die Namen werden trotzdem beantwortet."), error: true }
                    }
                    for e in s.listen_errors.iter() {
                        Callout { key: "{e}", text: trf("Port konnte nicht geöffnet werden: {0}", &[e]), error: true }
                    }
                    if s.port != 80 && s.port != 0 && !s.gateway.as_ref().is_some_and(|g| g.active) {
                        Callout { text: trf("Der Proxy läuft auf Port {0} – Namen also mit Port öffnen, z. B. http://music.nrz.ch:{0}/.", &[&s.port.to_string()]) }
                    }
                    Hosts { status: s.clone(), version }
                    HttpsSection { version }
                    AddressSection { settings: s.settings.clone(), device: s.device_addresses.clone(), gateway: s.gateway.clone(), version }
                },
            }
        }
    }
}

#[component]
fn Hosts(status: ProxyStatus, version: Signal<u64>) -> Element {
    let admin = state::is_admin();
    let mut host = use_signal(String::new);
    let mut target = use_signal(String::new);
    let mut comment = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let editing = use_signal(|| None::<ProxyHost>);
    let port = status.port;

    let add = move |e: FormEvent| {
        e.prevent_default();
        spawn(async move {
            busy.set(true);
            let res = api::post::<ProxyHost, _>(
                "/proxy/hosts",
                &ProxyHostInput {
                    host: host().trim().to_string(),
                    target: target().trim().to_string(),
                    enabled: true,
                    comment: comment().trim().to_string(),
                },
            )
            .await;
            busy.set(false);
            match res {
                Ok(h) => {
                    toast(trf("„{0}“ hinzugefügt.", &[&h.host]));
                    host.set(String::new());
                    target.set(String::new());
                    comment.set(String::new());
                    version += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };

    rsx! {
        Section { title: tr("Einträge"), description: tr("Gilt sofort, ohne Neustart."),
            div { class: "grid grid-cols-1 gap-4",
                if admin {
                    form { class: "grid grid-cols-1 gap-2 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,0.8fr)_auto]", onsubmit: add,
                        input {
                            class: "{INPUT} font-mono text-[13px]",
                            required: true,
                            spellcheck: false,
                            autocapitalize: "none",
                            "aria-label": tr("Name"),
                            placeholder: tr("Name, z. B. music.nrz.ch"),
                            value: "{host}",
                            oninput: move |e| host.set(e.value()),
                        }
                        input {
                            class: "{INPUT} font-mono text-[13px]",
                            required: true,
                            spellcheck: false,
                            autocapitalize: "none",
                            "aria-label": tr("Ziel"),
                            placeholder: tr("Ziel, z. B. http://100.78.107.162:8350"),
                            value: "{target}",
                            oninput: move |e| target.set(e.value()),
                        }
                        input {
                            class: INPUT,
                            maxlength: 200,
                            "aria-label": tr("Kommentar"),
                            placeholder: tr("Kommentar (optional)"),
                            value: "{comment}",
                            oninput: move |e| comment.set(e.value()),
                        }
                        button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy() || host().trim().is_empty() || target().trim().is_empty(),
                            icons::Plus {}
                            {tr("Hinzufügen")}
                        }
                    }
                }
                if status.hosts.is_empty() {
                    div { class: "rounded-lg border border-dashed px-4 py-8 text-center text-sm text-muted-foreground", {tr("Noch keine Einträge.")} }
                } else {
                    TableWrapper {
                        Table {
                            TableHeader {
                                tr {
                                    TableHead { {tr("Name")} }
                                    TableHead { {tr("Ziel")} }
                                    TableHead { class: "hidden md:table-cell", {tr("DNS-Antwort")} }
                                    TableHead { class: "w-16", {tr("Aktiv")} }
                                    if admin {
                                        TableHead { class: "w-20" }
                                    }
                                }
                            }
                            TableBody {
                                for h in status.hosts.iter().cloned() {
                                    HostRow { key: "{h.id}", host: h, port, https: status.https_names.clone(), version, editing }
                                }
                            }
                        }
                    }
                }
            }
        }
        EditDialog { editing, version }
    }
}

#[component]
fn HostRow(
    host: ProxyHost,
    port: u16,
    https: Vec<String>,
    version: Signal<u64>,
    editing: Signal<Option<ProxyHost>>,
) -> Element {
    let admin = state::is_admin();
    let h = host.clone();
    let toggle = move |on: bool| {
        let h = h.clone();
        spawn(async move {
            let input = ProxyHostInput {
                host: h.host.clone(),
                target: h.target.clone(),
                enabled: on,
                comment: h.comment.clone(),
            };
            match api::put::<ProxyHost, _>(&format!("/proxy/hosts/{}", h.id), &input).await {
                Ok(_) => version += 1,
                Err(e) => toast_error(e),
            }
        });
    };
    let link = url(&host.host, port, &https);
    rsx! {
        TableRow {
            TableCell { class: "font-mono text-[13px] break-all",
                a { class: "hover:underline", href: "{link}", target: "_blank", rel: "noopener", "{host.host}" }
                if !host.comment.is_empty() {
                    p { class: "font-sans text-xs text-muted-foreground", "{host.comment}" }
                }
            }
            TableCell { class: "font-mono text-[13px] break-all text-muted-foreground",
                a { class: "hover:underline", href: "{host.target}", target: "_blank", rel: "noopener", "{host.target}" }
            }
            TableCell { class: "hidden font-mono text-[13px] md:table-cell",
                if host.dns_address.is_empty() {
                    span { class: "font-sans text-xs text-destructive", title: tr("Unten die Adresse dieses Geräts eintragen."), {tr("keine – Adresse fehlt")} }
                } else {
                    "{host.dns_address}"
                }
            }
            TableCell {
                Toggle { checked: host.enabled, disabled: !admin, onchange: toggle }
            }
            if admin {
                TableCell { class: "px-2 text-right whitespace-nowrap",
                    button {
                        class: icon_btn(""),
                        title: tr("Bearbeiten"),
                        onclick: {
                            let h = host.clone();
                            move |_| editing.set(Some(h.clone()))
                        },
                        icons::Pencil {}
                    }
                    button {
                        class: icon_btn("hover:text-destructive"),
                        title: tr("Entfernen"),
                        onclick: {
                            let h = host.clone();
                            move |_| {
                                let h = h.clone();
                                spawn(async move {
                                    let ask = Ask::new(trf("„{0}“ entfernen?", &[&h.host]), tr("Der Name wird dann nicht mehr weitergereicht und von nrzNetwork nicht mehr beantwortet."))
                                        .confirm(tr("Entfernen"))
                                        .destructive();
                                    if confirm(ask).await {
                                        match api::delete(&format!("/proxy/hosts/{}", h.id)).await {
                                            Ok(()) => {
                                                toast(trf("„{0}“ entfernt.", &[&h.host]));
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

#[component]
fn EditDialog(editing: Signal<Option<ProxyHost>>, version: Signal<u64>) -> Element {
    let mut open = use_signal(|| false);
    let mut host = use_signal(String::new);
    let mut target = use_signal(String::new);
    let mut comment = use_signal(String::new);
    let mut busy = use_signal(|| false);

    use_effect(move || {
        if let Some(h) = editing() {
            host.set(h.host.clone());
            target.set(h.target.clone());
            comment.set(h.comment.clone());
            open.set(true);
        }
    });
    use_effect(move || {
        if !open() && editing.peek().is_some() {
            editing.set(None);
        }
    });

    let save = move |e: FormEvent| {
        e.prevent_default();
        let Some(h) = editing() else { return };
        spawn(async move {
            busy.set(true);
            let input = ProxyHostInput {
                host: host().trim().to_string(),
                target: target().trim().to_string(),
                enabled: h.enabled,
                comment: comment().trim().to_string(),
            };
            let res = api::put::<ProxyHost, _>(&format!("/proxy/hosts/{}", h.id), &input).await;
            busy.set(false);
            match res {
                Ok(h) => {
                    toast(trf("„{0}“ gespeichert.", &[&h.host]));
                    open.set(false);
                    version += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };

    rsx! {
        Modal { open, title: tr("Eintrag bearbeiten"),
            form { class: "grid grid-cols-1 gap-4", onsubmit: save,
                Field { label: tr("Name"),
                    input { class: "{INPUT} font-mono text-[13px]", required: true, spellcheck: false, autocapitalize: "none",
                        value: "{host}", oninput: move |e| host.set(e.value()) }
                }
                Field { label: tr("Ziel"), hint: tr("Nur HTTP, z. B. http://100.78.107.162:8350"),
                    input { class: "{INPUT} font-mono text-[13px]", required: true, spellcheck: false, autocapitalize: "none",
                        value: "{target}", oninput: move |e| target.set(e.value()) }
                }
                Field { label: tr("Kommentar"),
                    input { class: INPUT, maxlength: 200, value: "{comment}", oninput: move |e| comment.set(e.value()) }
                }
                div { class: "flex justify-end gap-2",
                    button { class: btn(BTN_OUTLINE), r#type: "button", onclick: move |_| open.set(false), {tr("Abbrechen")} }
                    button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy(), {tr("Speichern")} }
                }
            }
        }
    }
}

#[component]
fn AddressSection(
    settings: ProxySettings,
    device: Vec<String>,
    gateway: Option<GatewayStatus>,
    version: Signal<u64>,
) -> Element {
    let admin = state::is_admin();
    let mut address = use_signal(|| settings.address.clone());
    let mut allow_unlock = use_signal(|| settings.allow_unlock);
    let mut minutes = use_signal(|| {
        settings
            .unlock_minutes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    });
    let mut allow_requests = use_signal(|| settings.allow_requests);
    let mut port80 = use_signal(|| settings.port80);
    let mut busy = use_signal(|| false);
    let save = move |e: FormEvent| {
        e.prevent_default();
        let unlock_minutes: Vec<u32> = minutes()
            .split([',', ' ', ';'])
            .filter_map(|m| m.trim().parse().ok())
            .collect();
        spawn(async move {
            busy.set(true);
            let res = api::put::<ProxyStatus, _>(
                "/proxy/settings",
                &ProxySettings {
                    address: address().trim().to_string(),
                    allow_unlock: allow_unlock(),
                    unlock_minutes,
                    allow_requests: allow_requests(),
                    port80: port80(),
                },
            )
            .await;
            busy.set(false);
            match res {
                Ok(_) => {
                    toast(tr("Gespeichert."));
                    version += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };
    let detected = if device.is_empty() {
        tr("keine erkannt")
    } else {
        device.join(", ")
    };
    rsx! {
        Section { title: tr("Gerät und Sperrseite"), description: tr("Mit diesen Adressen beantwortet nrzNetwork die Namen der Einträge und – im Sperrmodus „Sperrseite“ – gesperrte Domains. Jeder Client bekommt die passende (LAN oder VPN)."),
            form { class: "grid grid-cols-1 gap-5", onsubmit: save,
                Field { label: tr("IP-Adressen dieses Geräts"), hint: trf("Durch Kommas getrennt. Leer = automatisch erkannt: {0}", &[&detected]),
                    input {
                        class: "{INPUT} font-mono text-[13px]",
                        disabled: !admin,
                        spellcheck: false,
                        placeholder: "192.168.0.198, 100.78.107.162",
                        value: "{address}",
                        oninput: move |e| address.set(e.value()),
                    }
                }
                if let Some(g) = gateway.as_ref() {
                    div { class: "grid grid-cols-1 gap-2",
                        Toggle { checked: port80(), disabled: !admin, onchange: move |v| port80.set(v),
                            label: tr("Port 80 des Umbrel an den Proxy geben (Namen ohne Port)"),
                            hint: tr("Alles ohne Eintrag – auch die umbrelOS-Oberfläche – reicht der Proxy unverändert an umbrelOS weiter. Antwortet der Proxy nicht, bekommt umbrelOS Port 80 sofort zurück."),
                        }
                        Callout { text: if g.active { trf("Aktiv: {0}", &[&g.message]) } else { trf("Nicht aktiv: {0}", &[&g.message]) }, error: !g.active && port80() }
                    }
                }
                Toggle { checked: allow_unlock(), disabled: !admin, onchange: move |v| allow_unlock.set(v),
                    label: tr("Auf der Sperrseite für eine Weile freischalten lassen"),
                    hint: tr("Jeder im Netzwerk kann eine gesperrte Seite selbst freischalten; die Freischaltung endet von selbst."),
                }
                if allow_unlock() {
                    Field { label: tr("Zeiträume in Minuten"), hint: tr("Durch Kommas getrennt, 1 bis 1440, z. B. 15, 60, 240."),
                        input { class: "{INPUT} font-mono text-[13px]", disabled: !admin, value: "{minutes}", oninput: move |e| minutes.set(e.value()) }
                    }
                }
                Toggle { checked: allow_requests(), disabled: !admin, onchange: move |v| allow_requests.set(v),
                    label: tr("Dauerhafte Freigabe beantragen lassen"),
                    hint: tr("Anträge erscheinen unter Ausnahmen; ein Admin genehmigt oder lehnt ab."),
                }
                if admin {
                    div { class: "flex justify-end",
                        button { class: btn(BTN_PRIMARY), r#type: "submit", disabled: busy(), {tr("Speichern")} }
                    }
                }
            }
        }
    }
}

/// HTTPS für eigene Domains: Let's Encrypt, Nachweis über Cloudflare.
#[component]
fn HttpsSection(version: Signal<u64>) -> Element {
    let admin = state::is_admin();
    let mut tick = use_signal(|| 0u64);
    let status = use_resource(move || async move {
        let _ = (tick(), version());
        api::get::<TlsStatus>("/tls").await
    });
    let mut was_issuing = use_signal(|| false);
    // Solange ein Zertifikat geholt wird, alle 2 s nachfragen; danach die Liste neu laden
    // (Links werden zu https://)
    use_effect(move || {
        let issuing = matches!(&*status.read(), Some(Ok(s)) if s.issuing);
        if issuing {
            spawn(async move {
                gloo_timers::future::TimeoutFuture::new(2000).await;
                tick += 1;
            });
        } else if *was_issuing.peek() {
            was_issuing.set(false);
            version += 1;
        }
    });
    match &*status.read() {
        None => rsx! {},
        Some(Err(e)) => rsx! { Callout { text: e.message.clone(), error: true } },
        Some(Ok(s)) => rsx! {
            HttpsForm { key: "{s.settings.domains.join(\",\")}-{s.token_set}", status: s.clone(), admin, tick, was_issuing }
        },
    }
}

#[component]
fn HttpsForm(
    status: TlsStatus,
    admin: bool,
    tick: Signal<u64>,
    was_issuing: Signal<bool>,
) -> Element {
    let s = status.settings.clone();
    let mut enabled = use_signal(|| s.enabled);
    let mut domains = use_signal(|| {
        if s.domains.is_empty() {
            String::new()
        } else {
            s.domains.join(", ")
        }
    });
    let mut email = use_signal(|| s.email.clone());
    let mut token = use_signal(String::new);
    let mut staging = use_signal(|| s.staging);
    let mut redirect = use_signal(|| s.redirect_http);
    let mut busy = use_signal(|| false);

    let input = move || TlsSettingsInput {
        settings: TlsSettings {
            enabled: enabled(),
            domains: domains()
                .split([',', ' ', '\n'])
                .map(str::trim)
                .filter(|d| !d.is_empty())
                .map(str::to_string)
                .collect(),
            email: email().trim().to_string(),
            staging: staging(),
            redirect_http: redirect(),
        },
        cloudflare_token: token().trim().to_string(),
        clear_token: false,
    };
    let save = move |e: FormEvent| {
        e.prevent_default();
        spawn(async move {
            busy.set(true);
            let res = api::put::<TlsStatus, _>("/tls", &input()).await;
            busy.set(false);
            match res {
                Ok(_) => {
                    token.set(String::new());
                    toast(tr("Gespeichert."));
                    tick += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };
    let issue = move |_| {
        spawn(async move {
            busy.set(true);
            // Erst speichern (falls etwas geändert wurde), dann holen
            let saved = api::put::<TlsStatus, _>("/tls", &input()).await;
            let res = match saved {
                Ok(_) => api::action::<TlsStatus>("/tls/issue").await,
                Err(e) => Err(e),
            };
            busy.set(false);
            match res {
                Ok(_) => {
                    token.set(String::new());
                    was_issuing.set(true);
                    tick += 1;
                }
                Err(e) => toast_error(e),
            }
        });
    };
    let remove = move |_| {
        spawn(async move {
            let ask = Ask::new(
                tr("Zertifikat entfernen?"),
                tr("HTTPS für diese Namen ist dann aus, bis ein neues Zertifikat geholt wird."),
            )
            .confirm(tr("Entfernen"))
            .destructive();
            if !confirm(ask).await {
                return;
            }
            match api::delete("/tls/certificate").await {
                Ok(()) => tick += 1,
                Err(e) => toast_error(e),
            }
        });
    };
    let cert = status.certificate.clone();
    let days_left = cert
        .as_ref()
        .map(|c| (c.not_after - crate::util::now()) / 86_400);
    rsx! {
        Section {
            title: tr("HTTPS für eigene Domains"),
            description: tr("Echtes Zertifikat von Let's Encrypt für deine Domain bei Cloudflare, z. B. *.zweers.ch – dann öffnen sich die Einträge als https://music.zweers.ch ohne Warnung. Der Nachweis läuft über einen kurzen TXT-Eintrag bei Cloudflare, von aussen muss nichts erreichbar sein. Erneuert sich von selbst."),
            form { class: "grid grid-cols-1 gap-5", onsubmit: save,
                for e in status.listen_errors.iter() {
                    Callout { key: "{e}", text: trf("HTTPS-Port konnte nicht geöffnet werden: {0}", &[e]), error: true }
                }
                match &cert {
                    Some(c) => rsx! {
                        div { class: "grid grid-cols-1 gap-3 rounded-lg border p-3 sm:grid-cols-3",
                            div {
                                p { class: "text-xs text-muted-foreground", {tr("Zertifikat für")} }
                                p { class: "mt-0.5 font-mono text-[13px] break-all", "{c.names.join(\", \")}" }
                            }
                            div {
                                p { class: "text-xs text-muted-foreground", {tr("Gültig bis")} }
                                p { class: if days_left.unwrap_or(0) < 14 { "mt-0.5 text-sm text-amber-500" } else { "mt-0.5 text-sm" },
                                    {format!("{} ({})", crate::util::datetime(c.not_after), trf("noch {0} Tage", &[&days_left.unwrap_or(0).max(0).to_string()]))}
                                }
                            }
                            div {
                                p { class: "text-xs text-muted-foreground", {tr("Ausgestellt von")} }
                                p { class: "mt-0.5 text-sm break-all", "{c.issuer}" }
                            }
                        }
                    },
                    None => rsx! {},
                }
                if status.issuing || !status.progress.is_empty() {
                    div { class: "rounded-lg border bg-muted/30 p-3 text-sm",
                        p { class: "mb-1 flex items-center gap-2 font-medium",
                            if status.issuing { icons::LoaderCircle { class: "size-4 animate-spin" } {tr("Zertifikat wird geholt …")} } else { {tr("Letzter Versuch")} }
                        }
                        for (i, step) in status.progress.iter().enumerate() {
                            p { key: "{i}", class: if step.starts_with("Fehlgeschlagen") { "text-destructive break-words" } else { "text-muted-foreground break-words" }, "{step}" }
                        }
                    }
                }
                Toggle { checked: enabled(), disabled: !admin, onchange: move |v| enabled.set(v),
                    label: tr("HTTPS einschalten"),
                    hint: tr("Der Proxy nimmt dann auch https:// an. Andere HTTPS-Seiten auf diesem Gerät (z. B. umbrelOS) reicht er unverändert weiter."),
                }
                div { class: "grid grid-cols-1 gap-4 sm:grid-cols-2",
                    Field { label: tr("Namen im Zertifikat"), hint: tr("Durch Kommas getrennt. *.zweers.ch deckt music.zweers.ch, dns.zweers.ch … ab, zweers.ch selbst extra angeben."),
                        input { class: "{INPUT} font-mono text-[13px]", disabled: !admin, spellcheck: false, autocapitalize: "none",
                            placeholder: "zweers.ch, *.zweers.ch", value: "{domains}", oninput: move |e| domains.set(e.value()) }
                    }
                    Field { label: tr("E-Mail für Let's Encrypt (optional)"), hint: tr("Für Hinweise, falls die Erneuerung einmal nicht klappt."),
                        input { class: INPUT, disabled: !admin, r#type: "email", autocomplete: "email", placeholder: "admin@zweers.ch", value: "{email}", oninput: move |e| email.set(e.value()) }
                    }
                }
                Field {
                    label: tr("Cloudflare-API-Token"),
                    hint: tr("In Cloudflare: Profil → API-Tokens → Token erstellen → Vorlage „Zone-DNS bearbeiten“ → Zone zweers.ch. Wird nur auf diesem Gerät gespeichert und nie wieder angezeigt."),
                    input {
                        class: "{INPUT} font-mono text-[13px]",
                        disabled: !admin,
                        r#type: "password",
                        autocomplete: "off",
                        spellcheck: false,
                        placeholder: if status.token_set { tr("gespeichert – leer lassen, um es zu behalten") } else { tr("Token einfügen") },
                        value: "{token}",
                        oninput: move |e| token.set(e.value()),
                    }
                }
                Toggle { checked: redirect(), disabled: !admin, onchange: move |v| redirect.set(v),
                    label: tr("http:// auf https:// umleiten"),
                    hint: tr("Nur für Einträge, deren Name im Zertifikat steht."),
                }
                Toggle { checked: staging(), disabled: !admin, onchange: move |v| staging.set(v),
                    label: tr("Testzertifikat (Let's Encrypt Staging)"),
                    hint: tr("Zum Ausprobieren ohne Limits – Browser zeigen dafür eine Warnung."),
                }
                if !status.last_error.is_empty() && !status.issuing {
                    Callout { text: status.last_error.clone(), error: true }
                }
                if admin {
                    div { class: "flex flex-wrap justify-end gap-2",
                        if cert.is_some() {
                            button { class: btn(BTN_GHOST), r#type: "button", onclick: remove, {tr("Zertifikat entfernen")} }
                        }
                        button { class: btn(BTN_OUTLINE), r#type: "submit", disabled: busy() || status.issuing, {tr("Speichern")} }
                        button { class: btn(BTN_PRIMARY), r#type: "button", disabled: busy() || status.issuing || !enabled(), onclick: issue,
                            icons::ShieldCheck {}
                            if cert.is_some() { {tr("Jetzt erneuern")} } else { {tr("Zertifikat holen")} }
                        }
                    }
                }
            }
        }
    }
}
