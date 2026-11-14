//! nrzNetwork – Oberfläche (Dioxus 0.7, WebAssembly) mit Komponenten von rust-ui.
//! Spricht nur mit der JSON-API unter `/api/v1` (Sitzungs-Cookie); die Typen kommen aus
//! `nrzdns-types`, damit Server und Oberfläche nie auseinanderlaufen.

mod api;
mod components;
mod i18n;
mod json;
mod labels;
mod pages;
mod state;
mod ui;
mod util;

use components::overlay::{ConfirmHost, Toaster};
use dioxus::prelude::*;
use pages::allowed::Allowed;
use pages::auth::{Login, Register, Setup};
use pages::blocking::Blocking;
use pages::cache::Cache;
use pages::dashboard::Dashboard;
use pages::devices::Devices;
use pages::domains::Domains;
use pages::layout::AppLayout;
use pages::logs::Logs;
use pages::netbird::Netbird;
use pages::not_found::NotFound;
use pages::proxy::Proxy;
use pages::resolve::Resolve;
use pages::settings::Settings;
use pages::tools::Tools;
use pages::zone::ZoneView;
use pages::zones::Zones;

static CSS: Asset = asset!("/assets/tailwind.css");
static ICON: Asset = asset!("/assets/icon.png");
static FAVICON: Asset = asset!("/assets/favicon-32.png");

/// Adressen der App. Filter des Abfrageprotokolls und der Zeitraum des Dashboards stehen im
/// Suchteil der Adresse, damit Links vom Dashboard, Neuladen und Zurück funktionieren.
#[derive(Routable, Clone, PartialEq, Debug)]
#[rustfmt::skip]
pub enum Route {
    #[route("/login?:next")]
    Login { next: String },
    #[route("/setup")]
    Setup {},
    #[route("/register")]
    Register {},
    #[layout(AppLayout)]
        #[route("/?:range")]
        Dashboard { range: Option<String> },
        #[route("/zones")]
        Zones {},
        #[route("/zones/:id")]
        ZoneView { id: i64 },
        #[route("/blocking")]
        Blocking {},
        #[route("/allowed")]
        Allowed {},
        #[route("/logs?:client&:qname&:qtype&:kind&:rcode&:period&:page")]
        Logs {
            client: Option<String>,
            qname: Option<String>,
            qtype: Option<String>,
            kind: Option<String>,
            rcode: Option<String>,
            period: Option<String>,
            page: Option<u32>,
        },
        #[route("/cache")]
        Cache {},
        #[route("/proxy")]
        Proxy {},
        #[route("/devices")]
        Devices {},
        #[route("/domains")]
        Domains {},
        #[route("/netbird")]
        Netbird {},
        #[route("/tools")]
        Tools {},
        #[route("/resolve?:name&:qtype")]
        Resolve { name: Option<String>, qtype: Option<String> },
        #[redirect("/settings", || Route::Settings { section: "general".into() })]
        #[route("/settings/:section")]
        Settings { section: String },
    #[end_layout]
    #[route("/:..segments")]
    NotFound { segments: Vec<String> },
}

impl Route {
    /// Abfrageprotokoll mit Filtern (leere Werte fallen weg).
    pub fn logs_filtered(
        client: &str,
        qname: &str,
        qtype: &str,
        kind: &str,
        period: &str,
    ) -> Route {
        let opt = |s: &str| (!s.trim().is_empty()).then(|| s.trim().to_string());
        Route::Logs {
            client: opt(client),
            qname: opt(qname),
            qtype: opt(qtype),
            kind: opt(kind),
            rcode: None,
            period: opt(period),
            page: None,
        }
    }

    /// Abfrageprotokoll ohne Filter.
    pub fn logs() -> Route {
        Route::logs_filtered("", "", "", "", "")
    }
}

fn main() {
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    let mut ready = use_signal(|| false);
    use_future(move || async move {
        i18n::init().await;
        ready.set(true);
    });
    rsx! {
        document::Stylesheet { href: CSS }
        document::Link { rel: "icon", r#type: "image/png", href: FAVICON }
        document::Link { rel: "apple-touch-icon", href: ICON }
        document::Meta { name: "theme-color", content: "#1f1f1f" }
        if ready() {
            Router::<Route> {}
        }
        ConfirmHost {}
        Toaster {}
    }
}
