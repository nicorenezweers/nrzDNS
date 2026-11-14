//! Netzwerkkarte: ein Canvas mit allen Bereichen (Internet, Zugänge, nrzNetwork,
//! Docker, Zuhause, NetBird) und den Verbindungen als Linien.

use crate::api;
use crate::components::common::*;
use crate::i18n::{tr, trf};
use crate::ui::card::Card;
use crate::Route;
use dioxus::prelude::*;
use nrzdns_types::{TopoLink, TopoNode, Topology};
use std::collections::{HashMap, HashSet};

const NODE_H: f64 = 40.0;
const GAP: f64 = 8.0;
const PAD: f64 = 12.0;
const TITLE: f64 = 32.0;
const GROUP_H: f64 = 22.0;
const MORE_H: f64 = 24.0;
const COLS: [(f64, f64); 4] = [(20.0, 240.0), (330.0, 210.0), (610.0, 260.0), (950.0, 280.0)];
const WIDTH: f64 = 1250.0;

fn area_info(key: &str) -> (String, &'static str, usize) {
    match key {
        "internet" => (tr("Internet"), "#0ea5e9", 0),
        "gateway" => (tr("Zugänge"), "#f59e0b", 1),
        "nrz" => (tr("nrzNetwork · Reverse Proxy"), "#8b5cf6", 2),
        "docker" => (tr("Docker"), "#2496ed", 3),
        "lan" => (tr("Zuhause (LAN)"), "#10b981", 3),
        _ => (tr("NetBird-Netz"), "#6366f1", 3),
    }
}

fn link_color(kind: &str) -> &'static str {
    match kind {
        "tunnel" => "#f38020",
        "cfproxy" => "#fbad41",
        "direct" => "#94a3b8",
        "netbird" | "mesh" => "#6366f1",
        "router" => "#ef4444",
        "lan" | "dns" => "#10b981",
        "docker" => "#2496ed",
        _ => "#8b5cf6",
    }
}

fn status_color(n: &TopoNode) -> &'static str {
    match n.status.as_str() {
        "ok" => "#22c55e",
        "warn" => "#f59e0b",
        "off" if matches!(n.kind.as_str(), "peer" | "device" | "container") => "#9ca3af",
        "off" => "#ef4444",
        _ => "#9ca3af",
    }
}

fn cut(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n.saturating_sub(1)).collect::<String>())
    }
}

#[derive(Clone, PartialEq)]
struct AreaBox {
    key: String,
    title: String,
    color: &'static str,
    x: f64,
    y: f64,
    w: f64,
    h: f64,
    groups: Vec<(String, f64)>,
    more: Option<(usize, f64)>,
}

#[derive(Clone, PartialEq, Default)]
struct Layout {
    pos: HashMap<String, (f64, f64, f64, usize)>, // x, y, w, Spalte
    areas: Vec<AreaBox>,
    height: f64,
}

fn order(n: &TopoNode, linked_to: &HashMap<&str, &str>) -> (u8, String) {
    let rank = match (n.area.as_str(), n.kind.as_str()) {
        ("internet", "external") => 9,
        ("internet", _) => match linked_to.get(n.id.as_str()).copied().unwrap_or("") {
            "gw:cloudflare" => 0,
            t if t.starts_with("gw:cft:") => 1,
            "gw:tunnel" => 2,
            "gw:nbproxy" => 3,
            "gw:router" => 4,
            t if t.starts_with("dom:") => 5,
            _ => 6,
        },
        ("gateway", "cloudflare") => 0,
        ("gateway", "tunnel") if n.id != "gw:tunnel" => 1,
        ("gateway", "tunnel") => 2,
        ("gateway", "netbird") if n.id == "gw:nbproxy" => 3,
        ("gateway", "router") => 4,
        ("gateway", "netbird") => 5,
        ("gateway", _) => 6,
        ("nrz", "hub") => 0,
        ("lan", "host") => 0,
        ("netbird", _) if n.status != "ok" => 2,
        ("netbird", _) if n.label.contains('(') => 0,
        _ => 1,
    };
    (rank, n.label.to_lowercase())
}

fn layout(t: &Topology, show_all: bool) -> Layout {
    let linked: HashSet<&str> = t.links.iter().flat_map(|l| [l.from.as_str(), l.to.as_str()]).collect();
    let linked_to: HashMap<&str, &str> = t.links.iter().map(|l| (l.from.as_str(), l.to.as_str())).collect();
    let public: HashSet<&str> = t.links.iter().filter(|l| l.kind == "tunnel").map(|l| l.to.as_str()).collect();
    let mut by_area: HashMap<&str, Vec<&TopoNode>> = HashMap::new();
    let mut hidden = 0usize;
    for n in &t.nodes {
        if n.area == "docker" && !show_all && !linked.contains(n.id.as_str()) {
            hidden += 1;
            continue;
        }
        by_area.entry(n.area.as_str()).or_default().push(n);
    }
    for (area, list) in by_area.iter_mut() {
        if *area == "docker" {
            list.sort_by_key(|n| (n.group.to_lowercase(), n.label.to_lowercase()));
        } else if *area == "nrz" {
            list.sort_by_key(|n| (n.kind != "hub", !public.contains(n.id.as_str()), n.label.to_lowercase()));
        } else {
            list.sort_by_key(|n| order(n, &linked_to));
        }
    }
    let mut out = Layout::default();
    // Spalten 0–2 je ein Bereich, Spalte 3 drei Bereiche untereinander
    let mut col_boxes: Vec<Vec<(String, Vec<&TopoNode>)>> = vec![Vec::new(); 4];
    for key in ["internet", "gateway", "nrz", "docker", "lan", "netbird"] {
        let list = by_area.remove(key).unwrap_or_default();
        if list.is_empty() && !(key == "docker" && hidden > 0) {
            continue;
        }
        let (_, _, col) = area_info(key);
        col_boxes[col].push((key.to_string(), list));
    }
    let area_h = |key: &str, list: &[&TopoNode]| {
        let mut h = TITLE + PAD;
        if !list.is_empty() {
            h += list.len() as f64 * (NODE_H + GAP) - GAP;
        }
        if key == "docker" {
            let groups: HashSet<&str> = list.iter().map(|n| n.group.as_str()).collect();
            h += groups.len() as f64 * GROUP_H;
            if hidden > 0 {
                h += MORE_H;
            }
        }
        h
    };
    let heights: Vec<f64> = col_boxes
        .iter()
        .map(|c| c.iter().map(|(k, l)| area_h(k, l)).sum::<f64>() + (c.len().saturating_sub(1)) as f64 * 24.0)
        .collect();
    let total = heights.iter().copied().fold(0.0, f64::max).max(200.0);
    for (col, boxes) in col_boxes.iter().enumerate() {
        let (x, w) = COLS[col];
        let mut y = 20.0 + ((total - heights[col]) / 2.0).max(0.0);
        for (key, list) in boxes {
            let (title, color, _) = area_info(key);
            let h = area_h(key, list);
            let mut ab = AreaBox { key: key.clone(), title, color, x, y, w, h, groups: Vec::new(), more: None };
            let mut cy = y + TITLE;
            let mut last_group: Option<&str> = None;
            for n in list {
                if key == "docker" && last_group != Some(n.group.as_str()) {
                    ab.groups.push((n.group.clone(), cy + 14.0));
                    cy += GROUP_H;
                    last_group = Some(n.group.as_str());
                }
                out.pos.insert(n.id.clone(), (x + PAD, cy, w - 2.0 * PAD, col));
                cy += NODE_H + GAP;
            }
            if key == "docker" && hidden > 0 {
                ab.more = Some((hidden, cy + 12.0));
            }
            out.areas.push(ab);
            y += h + 24.0;
        }
    }
    out.height = total + 40.0;
    out
}

struct Drawn {
    d: String,
    mid: (f64, f64),
}

fn curve(a: (f64, f64, f64, usize), b: (f64, f64, f64, usize)) -> Drawn {
    let (ay, by) = (a.1 + NODE_H / 2.0, b.1 + NODE_H / 2.0);
    let (sx, tx, c1, c2) = if a.3 < b.3 {
        let (sx, tx) = (a.0 + a.2, b.0);
        let dx = ((tx - sx) / 2.0).max(40.0);
        (sx, tx, sx + dx, tx - dx)
    } else if a.3 > b.3 {
        let (sx, tx) = (a.0, b.0 + b.2);
        let dx = ((sx - tx) / 2.0).max(40.0);
        (sx, tx, sx - dx, tx + dx)
    } else {
        let (sx, tx) = (a.0 + a.2, b.0 + b.2);
        let dx = 40.0 + (by - ay).abs().min(300.0) / 6.0;
        (sx, tx, sx + dx, tx + dx)
    };
    let mid_x = (sx + 3.0 * c1 + 3.0 * c2 + tx) / 8.0;
    let mid_y = (ay + by) / 2.0;
    Drawn { d: format!("M{sx:.1},{ay:.1} C{c1:.1},{ay:.1} {c2:.1},{by:.1} {tx:.1},{by:.1}"), mid: (mid_x, mid_y) }
}

/// Welche Verbindungen und Punkte zum gewählten Punkt gehören.
fn highlight(t: &Topology, focus: &str) -> (HashSet<usize>, HashSet<String>) {
    let mut links = HashSet::new();
    let mut flows = HashSet::new();
    for (i, l) in t.links.iter().enumerate() {
        if l.from == focus || l.to == focus {
            links.insert(i);
            if !l.flow.is_empty() {
                flows.insert(l.flow.clone());
            }
        }
    }
    for (i, l) in t.links.iter().enumerate() {
        if flows.contains(&l.flow) {
            links.insert(i);
        }
    }
    let mut nodes: HashSet<String> = links.iter().flat_map(|i| [t.links[*i].from.clone(), t.links[*i].to.clone()]).collect();
    // Docker-intern weiter (App-Proxy → App)
    for (i, l) in t.links.iter().enumerate() {
        if l.kind == "docker" && nodes.contains(&l.from) {
            links.insert(i);
            nodes.insert(l.to.clone());
        }
    }
    nodes.insert(focus.to_string());
    (links, nodes)
}

/// Netzwerkkarte als eigene Seite.
#[component]
pub fn NetworkMapPage() -> Element {
    rsx! {
        PageHeader { title: tr("Netzwerkkarte"), description: tr("Wie Anfragen fliessen: aus dem Internet über Cloudflare Tunnel, NetBird oder den Router zum Reverse Proxy und weiter zu Docker, Geräten zu Hause und im NetBird-Netz.") }
        NetworkMap { compact: false }
    }
}

#[component]
pub fn NetworkMap(compact: bool) -> Element {
    let mut tick = use_signal(|| 0u64);
    let data = use_resource(move || async move {
        let _ = tick();
        api::get::<Topology>("/topology").await
    });
    use_future(move || async move {
        loop {
            gloo_timers::future::TimeoutFuture::new(30_000).await;
            tick += 1;
        }
    });
    let mut show_all = use_signal(|| false);
    let mut zoom = use_signal(|| 0.0f64); // 0 = an die Breite anpassen
    let mut full = use_signal(|| false);
    let mut hover = use_signal(|| None::<String>);
    let mut selected = use_signal(|| None::<String>);
    let streamer = crate::state::STREAMER();

    let read = data.read();
    let t = match &*read {
        None => return rsx! { Card { class: "p-6", Loading {} } },
        Some(Err(e)) => return rsx! { Callout { text: e.message.clone(), error: true } },
        Some(Ok(t)) => t.clone(),
    };
    drop(read);
    let lay = layout(&t, show_all());
    let focus = selected().or(hover());
    let (hl_links, hl_nodes) = focus.as_deref().map(|f| highlight(&t, f)).unwrap_or_default();
    let dim = focus.is_some();
    let nodes_by_id: HashMap<String, TopoNode> = t.nodes.iter().map(|n| (n.id.clone(), n.clone())).collect();
    let h = lay.height;
    let svg_style = if zoom() == 0.0 { "width: 100%; min-width: 900px; height: auto".to_string() } else { format!("width: {:.0}px; height: auto", WIDTH * zoom()) };
    let wrap = if full() {
        "fixed inset-0 z-40 flex flex-col gap-3 overflow-hidden bg-background p-4"
    } else {
        "flex flex-col gap-3"
    };
    let canvas = if full() {
        "min-h-0 flex-1 overflow-auto rounded-xl border bg-card"
    } else if compact {
        "max-h-[34rem] overflow-auto rounded-xl border bg-card"
    } else {
        "overflow-auto rounded-xl border bg-card"
    };
    let links: Vec<(usize, TopoLink, Drawn)> = t
        .links
        .iter()
        .enumerate()
        .filter_map(|(i, l)| Some((i, l.clone(), curve(*lay.pos.get(&l.from)?, *lay.pos.get(&l.to)?))))
        .collect();
    let public_count = t.nodes.iter().filter(|n| n.area == "internet" && n.kind == "domain").count();
    let ct_count = t.nodes.iter().filter(|n| n.kind == "container").count();
    let peer_count = t.nodes.iter().filter(|n| n.kind == "peer").count();
    let lan_count = t.nodes.iter().filter(|n| n.kind == "device").count();

    rsx! {
        div { class: wrap,
            div { class: "flex flex-wrap items-center gap-2",
                div { class: "flex min-w-0 flex-1 flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground",
                    for (label , color) in [(tr("Cloudflare Tunnel"), "#f38020"), (tr("Cloudflare Proxy"), "#fbad41"), (tr("Direkt (DNS)"), "#94a3b8"), (tr("NetBird"), "#6366f1"), (tr("Router / offene Ports"), "#ef4444"), (tr("Reverse Proxy"), "#8b5cf6"), (tr("Zuhause / DNS"), "#10b981"), (tr("Docker"), "#2496ed")] {
                        span { key: "{label}", class: "flex items-center gap-1.5",
                            span { class: "inline-block h-0.5 w-5 rounded", style: "background: {color}" }
                            "{label}"
                        }
                    }
                    span { class: "hidden sm:inline", "· " {trf("{0} öffentlich · {1} Container · {2} zu Hause · {3} NetBird", &[&public_count.to_string(), &ct_count.to_string(), &lan_count.to_string(), &peer_count.to_string()])} }
                }
                button { class: btn_sm(BTN_OUTLINE), onclick: move |_| show_all.toggle(),
                    icons::Container {}
                    if show_all() { {tr("Nur verbundene Container")} } else { {tr("Alle Container")} }
                }
                div { class: "flex items-center",
                    button { class: icon_btn(""), title: tr("Verkleinern"), onclick: move |_| { let z = if zoom() == 0.0 { 1.0 } else { zoom() }; zoom.set((z - 0.2).max(0.4)); }, icons::ZoomOut {} }
                    button { class: "px-1.5 text-xs tabular-nums text-muted-foreground hover:text-foreground", title: tr("An die Breite anpassen"), onclick: move |_| zoom.set(0.0),
                        if zoom() == 0.0 { {tr("Passend")} } else { "{(zoom() * 100.0).round()} %" }
                    }
                    button { class: icon_btn(""), title: tr("Vergrössern"), onclick: move |_| { let z = if zoom() == 0.0 { 1.0 } else { zoom() }; zoom.set((z + 0.2).min(2.4)); }, icons::ZoomIn {} }
                }
                button { class: icon_btn(""), title: tr("Neu laden"), onclick: move |_| tick += 1, icons::RefreshCw {} }
                if compact && !full() {
                    Link { class: icon_btn(""), title: tr("Netzwerkkarte öffnen"), to: Route::Map {}, icons::ExternalLink {} }
                }
                button { class: icon_btn(""), title: if full() { tr("Vollbild beenden") } else { tr("Vollbild") }, onclick: move |_| full.toggle(),
                    if full() { icons::Minimize2 {} } else { icons::Maximize2 {} }
                }
            }
            if !t.notes.is_empty() && !compact {
                div { class: "grid gap-1",
                    for n in t.notes.iter() {
                        p { key: "{n}", class: "flex items-center gap-2 text-xs text-muted-foreground", icons::Info { class: "size-3.5 shrink-0" } "{n}" }
                    }
                }
            }
            div { class: canvas,
                svg {
                    view_box: "0 0 {WIDTH} {h}",
                    style: "{svg_style}",
                    onclick: move |_| selected.set(None),
                    // Bereiche
                    for a in lay.areas.iter().cloned() {
                        g { key: "{a.key}",
                            rect { x: "{a.x}", y: "{a.y}", width: "{a.w}", height: "{a.h}", rx: "14",
                                style: "fill: {a.color}; fill-opacity: 0.06; stroke: {a.color}; stroke-opacity: 0.35; stroke-width: 1; stroke-dasharray: 5 4" }
                            text { x: "{a.x + 14.0}", y: "{a.y + 21.0}", style: "fill: {a.color}; font-size: 12px; font-weight: 600; letter-spacing: 0.04em", "{a.title.to_uppercase()}" }
                            for (g , gy) in a.groups.iter().cloned() {
                                text { key: "{g}", x: "{a.x + 16.0}", y: "{gy}", class: "sensitive fill-muted-foreground", style: "font-size: 10.5px; font-family: ui-monospace, monospace", "{g}" }
                            }
                            if let Some((n , my)) = a.more {
                                text { x: "{a.x + 16.0}", y: "{my}", style: "fill: {a.color}; font-size: 11px; cursor: pointer; text-decoration: underline",
                                    onclick: move |e| { e.stop_propagation(); show_all.set(true); },
                                    {trf("+ {0} weitere Container", &[&n.to_string()])}
                                }
                            }
                        }
                    }
                    // Linien
                    for (i , l , dr) in links.iter() {
                        {
                            let on = hl_links.contains(i);
                            let color = link_color(&l.kind);
                            let faint = matches!(l.kind.as_str(), "lan" | "dns" | "mesh");
                            let width = if l.hits > 0 { (1.6 + ((l.hits + 1) as f64).log2() * 0.45).min(6.0) } else if faint { 1.0 } else { 1.6 };
                            let opacity = if dim { if on { 0.95 } else { 0.06 } } else if faint { 0.28 } else if l.active { 0.8 } else { 0.45 };
                            let dash = if !l.active { "4 4" } else if l.hits > 0 || on { "8 4" } else { "none" };
                            let anim = if l.active && (l.hits > 0 || on) { "flow-line" } else { "" };
                            let show_label = !l.label.is_empty() && (on || (!dim && !faint));
                            let (mx, my) = dr.mid;
                            let tip = format!("{} → {}{}{}", nodes_by_id.get(&l.from).map(|n| n.label.clone()).unwrap_or_default(), nodes_by_id.get(&l.to).map(|n| n.label.clone()).unwrap_or_default(), if l.label.is_empty() { String::new() } else { format!(" ({})", l.label) }, if l.hits > 0 { format!(" · {} Zugriffe/24 h", l.hits) } else { String::new() });
                            rsx! {
                                g { key: "{i}",
                                    path { d: "{dr.d}", class: anim, style: "fill: none; stroke: {color}; stroke-width: {width}; stroke-opacity: {opacity}; stroke-dasharray: {dash}; stroke-linecap: round",
                                        if !streamer { title { "{tip}" } }
                                    }
                                    if show_label {
                                        text { x: "{mx}", y: "{my - 4.0}", class: "sensitive fill-foreground", style: "font-size: 10px; text-anchor: middle; paint-order: stroke; stroke: var(--card); stroke-width: 3px; font-family: ui-monospace, monospace", "{l.label}" }
                                    }
                                }
                            }
                        }
                    }
                    // Punkte
                    for n in t.nodes.iter().filter(|n| lay.pos.contains_key(&n.id)).cloned() {
                        {
                            let (x, y, w, _) = lay.pos[&n.id];
                            let (_, color, _) = area_info(&n.area);
                            let on = hl_nodes.contains(&n.id);
                            let sel = selected().as_deref() == Some(n.id.as_str());
                            let opacity = if dim && !on { 0.3 } else { 1.0 };
                            let max = ((w - 34.0) / 6.6) as usize;
                            let label = cut(&n.label, max);
                            let sub = cut(&n.sub, max + 6);
                            let id = n.id.clone();
                            let id2 = n.id.clone();
                            let stroke = if sel { 2.2 } else if on && dim { 1.6 } else { 1.0 };
                            let big = n.kind == "hub" || n.area == "gateway";
                            let sop = if on || sel { 1.0 } else { 0.45 };
                            let weight = if big { 600 } else { 500 };
                            rsx! {
                                g { key: "{n.id}", style: "cursor: pointer; opacity: {opacity}",
                                    onmouseenter: move |_| hover.set(Some(id.clone())),
                                    onmouseleave: move |_| hover.set(None),
                                    onclick: move |e| { e.stop_propagation(); selected.set(Some(id2.clone())); },
                                    rect { x: "{x}", y: "{y}", width: "{w}", height: "{NODE_H}", rx: "9", class: "fill-card",
                                        style: "stroke: {color}; stroke-opacity: {sop}; stroke-width: {stroke}" }
                                    if big {
                                        rect { x: "{x}", y: "{y}", width: "4", height: "{NODE_H}", rx: "2", style: "fill: {color}" }
                                    }
                                    circle { cx: "{x + 14.0}", cy: "{y + NODE_H / 2.0}", r: "4", style: "fill: {status_color(&n)}" }
                                    text { x: "{x + 26.0}", y: "{y + 17.0}", class: "sensitive fill-foreground", style: "font-size: 12px; font-weight: {weight}", "{label}" }
                                    text { x: "{x + 26.0}", y: "{y + 31.0}", class: "sensitive fill-muted-foreground", style: "font-size: 10.5px; font-family: ui-monospace, monospace", "{sub}" }
                                    if !streamer { title { "{n.label}\n{n.sub}" } }
                                }
                            }
                        }
                    }
                }
            }
            if let Some(id) = selected() {
                if let Some(n) = nodes_by_id.get(&id).cloned() {
                    Details { node: n, topo: t.clone(), on_close: move |_| selected.set(None), on_pick: move |id: String| selected.set(Some(id)) }
                }
            }
        }
    }
}

#[component]
fn Details(node: TopoNode, topo: Topology, on_close: EventHandler<()>, on_pick: EventHandler<String>) -> Element {
    let (area, color, _) = area_info(&node.area);
    let names: HashMap<&str, &str> = topo.nodes.iter().map(|n| (n.id.as_str(), n.label.as_str())).collect();
    let incoming: Vec<TopoLink> = topo.links.iter().filter(|l| l.to == node.id).cloned().collect();
    let outgoing: Vec<TopoLink> = topo.links.iter().filter(|l| l.from == node.id).cloned().collect();
    let goto: Option<(Route, String)> = match node.kind.as_str() {
        "container" => Some((Route::Docker {}, tr("Zu Docker"))),
        "peer" | "netbird" => Some((Route::Netbird {}, tr("Zu NetBird"))),
        "proxy" | "hub" => Some((Route::Proxy {}, tr("Zum Reverse Proxy"))),
        "domain" | "cloudflare" => Some((Route::Domains {}, tr("Zu den DNS-Einträgen"))),
        "device" => Some((Route::Devices {}, tr("Zu den Geräten"))),
        "tunnel" => Some((Route::Settings { section: "components".into() }, tr("Zu den Komponenten"))),
        "router" => Some((Route::Spy {}, tr("Zum Spy"))),
        _ => None,
    };
    let row = |l: &TopoLink, other: &str, arrow: &'static str| {
        let other_id = other.to_string();
        let name = names.get(other).copied().unwrap_or(other).to_string();
        let label = l.label.clone();
        let hits = l.hits;
        let col = link_color(&l.kind);
        let lop = if l.active { 1.0 } else { 0.4 };
        rsx! {
            button { class: "flex w-full items-center gap-2 rounded-md px-2 py-1 text-left text-xs hover:bg-accent",
                onclick: move |_| on_pick.call(other_id.clone()),
                span { class: "inline-block h-0.5 w-4 shrink-0 rounded", style: "background: {col}; opacity: {lop}" }
                span { class: "text-muted-foreground", "{arrow}" }
                span { class: "sensitive min-w-0 flex-1 truncate font-medium", "{name}" }
                if !label.is_empty() { span { class: "font-mono text-muted-foreground", "{label}" } }
                if hits > 0 { span { class: "text-muted-foreground", {trf("{0}/24 h", &[&hits.to_string()])} } }
            }
        }
    };
    rsx! {
        Card { class: "gap-3 p-4",
            div { class: "flex items-start gap-3",
                span { class: "mt-1 inline-block size-2.5 shrink-0 rounded-full", style: "background: {status_color(&node)}" }
                div { class: "min-w-0 flex-1",
                    p { class: "sensitive font-semibold break-all", "{node.label}" }
                    p { class: "text-xs text-muted-foreground",
                        span { style: "color: {color}", "{area}" }
                        if !node.sub.is_empty() { " · " span { class: "font-mono", "{node.sub}" } }
                    }
                }
                if let Some((to, label)) = goto {
                    Link { class: btn_sm(BTN_OUTLINE), to, icons::ArrowRight {} "{label}" }
                }
                button { class: icon_btn(""), title: tr("Schliessen"), onclick: move |_| on_close.call(()), icons::X {} }
            }
            if !node.info.is_empty() {
                div { class: "grid gap-0.5 text-xs",
                    for (i , line) in node.info.iter().enumerate() { p { key: "{i}", class: "sensitive break-all text-muted-foreground", "{line}" } }
                }
            }
            div { class: "grid grid-cols-1 gap-3 md:grid-cols-2",
                div {
                    p { class: "mb-1 text-xs font-medium", {trf("Kommt von ({0})", &[&incoming.len().to_string()])} }
                    if incoming.is_empty() { p { class: "px-2 text-xs text-muted-foreground", "–" } }
                    for (i , l) in incoming.iter().enumerate() { div { key: "{i}", {row(l, &l.from, "←")} } }
                }
                div {
                    p { class: "mb-1 text-xs font-medium", {trf("Geht zu ({0})", &[&outgoing.len().to_string()])} }
                    if outgoing.is_empty() { p { class: "px-2 text-xs text-muted-foreground", "–" } }
                    for (i , l) in outgoing.iter().enumerate() { div { key: "{i}", {row(l, &l.to, "→")} } }
                }
            }
        }
    }
}
