//! Rahmen: Anmeldung prüfen (AppLayout), dann Seitenleiste mit den Bereichen wie in der
//! Konsole von Technitium (Dashboard, Zonen, Sperren, Ausnahmen, Abfragen, Cache, DNS-Client,
//! Einstellungen) und unten das Profilmenü. Auf schmalen Bildschirmen ist die Seitenleiste ein Sheet.

use crate::Route;
use crate::api;
use crate::components::common::*;
use crate::components::overlay::*;
use crate::components::shortcuts::{SHORTCUTS_OPEN, ShortcutsHelp, use_shortcuts};
use crate::i18n::{self, tr};
use crate::state::{ME, SIDEBAR_OPEN};
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::AuthStatus;

/// Prüft die Anmeldung; ohne Konto zur Ersteinrichtung, ohne Anmeldung zur Anmeldeseite.
#[component]
pub fn AppLayout() -> Element {
    let nav = use_navigator();
    let mut status = use_resource(|| async move {
        let s = api::get::<AuthStatus>("/auth/status").await?;
        if let Some(user) = s.user.clone() {
            i18n::set_language(&user.preferences.language, true).await;
            *ME.write() = Some(user);
        }
        Ok::<AuthStatus, api::ApiError>(s)
    });
    match &*status.read() {
        None => rsx! { Splash {} },
        Some(Err(e)) => rsx! {
            div { class: "grid min-h-dvh place-items-center p-6",
                EmptyState { title: tr("Server nicht erreichbar"), description: e.message.clone(), icon: rsx! { icons::CircleAlert {} },
                    button { class: btn(BTN_OUTLINE), onclick: move |_| status.restart(), icons::RotateCw { class: "size-4" } {tr("Nochmals versuchen")} }
                }
            }
        },
        Some(Ok(s)) if s.setup_required => {
            nav.replace(Route::Setup {});
            rsx! { Splash {} }
        }
        Some(Ok(s)) if !s.authenticated || s.user.is_none() => {
            nav.replace(Route::Login {
                next: util::current_path(),
            });
            rsx! { Splash {} }
        }
        Some(Ok(_)) => rsx! { Shell {} },
    }
}

#[component]
fn Splash() -> Element {
    rsx! {
        div { class: "grid min-h-dvh place-items-center",
            img { src: asset!("/assets/icon.png"), class: "size-10 animate-pulse rounded-xl opacity-80", alt: "" }
        }
    }
}

/// Angemeldet: Seitenleiste, Inhalt, Tastenkürzel.
#[component]
fn Shell() -> Element {
    let route = use_route::<Route>();
    // Seitenwechsel schliesst die Seitenleiste auf dem Handy. Leere Filter hinterlassen ein „?“
    // oder „&“ am Ende der Adresse – das kommt weg.
    use_effect(use_reactive!(|route| {
        let _ = route;
        *SIDEBAR_OPEN.write() = false;
        document::eval(
            "if (/[?&]$/.test(location.href)) history.replaceState(history.state, '', location.href.replace(/[?&]+$/, ''))",
        );
    }));
    use_shortcuts();
    rsx! {
        div { class: "flex h-dvh overflow-hidden",
            // Seitenleiste (Desktop)
            aside { class: "hidden w-60 shrink-0 border-r border-sidenav-border bg-sidenav lg:flex lg:flex-col",
                Sidebar {}
            }
            // Seitenleiste (Handy/Tablet) als Sheet
            if SIDEBAR_OPEN() {
                div { class: "fixed inset-0 z-50 bg-black/60 backdrop-blur-[2px] lg:hidden", onclick: move |_| *SIDEBAR_OPEN.write() = false }
                aside { class: "fixed inset-y-0 left-0 z-50 flex w-[16rem] max-w-[85vw] flex-col border-r border-sidenav-border bg-sidenav shadow-xl animate-slide-in lg:hidden",
                    Sidebar {}
                }
            }
            main { class: "min-h-0 min-w-0 flex-1 overflow-y-auto",
                div { class: "mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 md:py-8", Outlet::<Route> {} }
            }
        }
        ShortcutsHelp {}
        crate::pages::dieter::DieterWidget {}
    }
}

#[component]
fn NavItem(to: Route, #[props(into)] label: String, icon: Element, active: bool) -> Element {
    let c = if active {
        "bg-sidenav-accent font-medium text-sidenav-accent-foreground"
    } else {
        "text-muted-foreground hover:bg-sidenav-accent/60 hover:text-sidenav-accent-foreground"
    };
    rsx! {
        Link { to, class: "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors [&_svg]:size-4 [&_svg]:shrink-0 {c}",
            {icon}
            span { class: "flex-1 truncate", "{label}" }
        }
    }
}

#[component]
fn Sidebar() -> Element {
    let route = use_route::<Route>();
    let me = ME.read().clone();
    rsx! {
        // Logo
        div { class: "flex h-14 shrink-0 items-center gap-2.5 px-4",
            Link { to: Route::Dashboard { range: None }, class: "flex items-center gap-2.5",
                img { src: asset!("/assets/icon.png"), class: "size-7 rounded-lg", alt: "" }
                span { class: "text-[15px] font-semibold tracking-tight", "nrzNetwork" }
            }
        }

        nav { class: "flex min-h-0 flex-1 flex-col gap-0.5 overflow-y-auto px-3 pb-3",
            NavItem { to: Route::Dashboard { range: None }, label: tr("Dashboard"), active: matches!(route, Route::Dashboard { .. }), icon: rsx! { icons::LayoutDashboard {} } }
            NavItem { to: Route::Map {}, label: tr("Netzwerkkarte"), active: matches!(route, Route::Map {}), icon: rsx! { icons::Network {} } }
            NavItem { to: Route::Zones {}, label: tr("Zonen"), active: matches!(route, Route::Zones {} | Route::ZoneView { .. }), icon: rsx! { icons::Globe {} } }
            NavItem { to: Route::Blocking {}, label: tr("Sperren"), active: matches!(route, Route::Blocking {}), icon: rsx! { icons::ShieldBan {} } }
            NavItem { to: Route::Allowed {}, label: tr("Ausnahmen"), active: matches!(route, Route::Allowed {}), icon: rsx! { icons::ShieldCheck {} } }
            NavItem { to: Route::logs(), label: tr("Abfragen"), active: matches!(route, Route::Logs { .. }), icon: rsx! { icons::ScrollText {} } }
            NavItem { to: Route::Proxy {}, label: tr("Reverse Proxy"), active: matches!(route, Route::Proxy {}), icon: rsx! { icons::Waypoints {} } }
            NavItem { to: Route::Monitor {}, label: tr("Zugriffe"), active: matches!(route, Route::Monitor {}), icon: rsx! { icons::Activity {} } }
            NavItem { to: Route::Cache {}, label: tr("Cache"), active: matches!(route, Route::Cache {}), icon: rsx! { icons::Database {} } }
            NavItem { to: Route::Resolve { name: None, qtype: None }, label: tr("DNS-Client"), active: matches!(route, Route::Resolve { .. }), icon: rsx! { icons::Terminal {} } }
            NavItem { to: Route::Devices {}, label: tr("Geräte"), active: matches!(route, Route::Devices {}), icon: rsx! { icons::MonitorSmartphone {} } }
            NavItem { to: Route::Netbird {}, label: tr("NetBird"), active: matches!(route, Route::Netbird {}), icon: rsx! { icons::Waypoints {} } }
            NavItem { to: Route::Domains {}, label: tr("DNS-Einträge"), active: matches!(route, Route::Domains {}), icon: rsx! { icons::Globe {} } }
            NavItem { to: Route::Docker {}, label: tr("Docker"), active: matches!(route, Route::Docker {}), icon: rsx! { icons::Container {} } }
            NavItem { to: Route::Spy {}, label: tr("Spy"), active: matches!(route, Route::Spy {}), icon: rsx! { icons::ScanEye {} } }
            NavItem { to: Route::Tools {}, label: tr("Netzwerk-Tools"), active: matches!(route, Route::Tools {}), icon: rsx! { icons::Wrench {} } }
            div { class: "my-2 h-px bg-sidenav-border" }
            NavItem { to: Route::Settings { section: "general".into() }, label: tr("Einstellungen"), active: matches!(route, Route::Settings { .. }), icon: rsx! { icons::Settings {} } }
        }

        // Unten: Profil
        div { class: "border-t border-sidenav-border p-3",
            if let Some(u) = me {
                ProfileMenu { name: u.name().to_string(), admin: u.is_admin() }
            }
        }
    }
}

#[component]
fn ProfileMenu(name: String, admin: bool) -> Element {
    let nav = use_navigator();
    rsx! {
        Dropdown { side: Side::Top, class: "w-56",
            trigger_class: "flex w-full items-center gap-2.5 rounded-lg px-2 py-1.5 text-left hover:bg-sidenav-accent",
            trigger: rsx! {
                span { class: "grid size-8 shrink-0 place-items-center rounded-full bg-secondary text-sm font-semibold", "{util::initial(&name)}" }
                span { class: "min-w-0 flex-1",
                    span { class: "block truncate text-sm font-medium", "{name}" }
                    span { class: "block text-xs text-muted-foreground",
                        if admin { {tr("Administrator")} } else { {tr("Mitglied")} }
                    }
                }
                icons::ChevronsUpDown { class: "size-4 shrink-0 text-muted-foreground" }
            },
            MenuItem { onclick: move |_| { nav.push(Route::Settings { section: "account".into() }); }, icons::User {} {tr("Konto")} }
            if admin {
                MenuItem { onclick: move |_| { nav.push(Route::Settings { section: "users".into() }); }, icons::Users {} {tr("Benutzer")} }
            }
            MenuItem { onclick: move |_| { nav.push(Route::Settings { section: "info".into() }); }, icons::Info {} {tr("Info")} }
            MenuSeparator {}
            MenuItem { onclick: move |_| *SHORTCUTS_OPEN.write() = true, icons::Keyboard {} {tr("Tastenkürzel")} }
            MenuItem {
                onclick: move |_| {
                    spawn(async move {
                        let _: api::ApiResult<serde_json::Value> = api::action("/auth/logout").await;
                        *ME.write() = None;
                        if let Some(w) = web_sys::window() {
                            let _ = w.location().assign("/login");
                        }
                    });
                },
                icons::LogOut {}
                {tr("Abmelden")}
            }
        }
    }
}
