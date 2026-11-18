//! Verlaufsdiagramm des Dashboards als SVG direkt in rsx: gestapelte Flächen für
//! weitergeleitet, aus dem Cache, verbindlich und gesperrt, darüber die Linie aller Anfragen.
//! Achsenbeschriftung und Tooltip sind HTML über dem SVG (das SVG wird gestreckt, Text nicht).
//! Fadenkreuz rastet am nächsten Punkt ein; auf dem Handy genügt Antippen.

use crate::i18n::tr;
use crate::util;
use dioxus::prelude::*;
use nrzdns_types::{StatsPoint, StatsRange};

const W: f64 = 1000.0;
const H: f64 = 300.0;

/// Gesamt-Linie (fast weiss).
pub const TOTAL_COLOR: &str = "oklch(0.93 0 0)";

/// Gestapelte Reihen von unten nach oben: Schlüssel, Farbe. Grautöne in klar getrennten
/// Helligkeitsstufen, nur „gesperrt“ in gedämpftem Rot.
pub const SERIES: [(&str, &str); 4] = [
    ("forwarded", "oklch(0.52 0 0)"),
    ("cached", "oklch(0.66 0 0)"),
    ("authoritative", "oklch(0.8 0 0)"),
    ("blocked", "oklch(0.63 0.13 25)"),
];

pub fn series_label(key: &str) -> String {
    match key {
        "forwarded" => tr("Weitergeleitet"),
        "cached" => tr("Aus dem Cache"),
        "authoritative" => tr("Verbindlich"),
        "blocked" => tr("Gesperrt"),
        _ => tr("Anfragen"),
    }
}

fn value(p: &StatsPoint, key: &str) -> u64 {
    match key {
        "forwarded" => p.forwarded,
        "cached" => p.cached,
        "authoritative" => p.authoritative,
        "blocked" => p.blocked,
        _ => p.total,
    }
}

/// Runder Schritt für die y-Achse (1, 2, 5 × 10ⁿ), mindestens 1.
fn nice_step(max: f64, ticks: f64) -> f64 {
    let raw = (max / ticks).max(1.0);
    let mag = 10f64.powf(raw.log10().floor());
    let norm = raw / mag;
    let step = if norm <= 1.0 {
        1.0
    } else if norm <= 2.0 {
        2.0
    } else if norm <= 5.0 {
        5.0
    } else {
        10.0
    };
    (step * mag).max(1.0)
}

/// Beschriftung der x-Achse je nach Zeitraum.
fn axis_label(range: StatsRange, at: i64) -> String {
    match range {
        StatsRange::Hour | StatsRange::Day => util::time(at),
        StatsRange::Week => util::weekday_time(at),
        StatsRange::Month => util::day_month(at),
    }
}

/// Kopf des Tooltips: der Abschnitt, den der Punkt zusammenfasst.
fn bucket_label(range: StatsRange, at: i64) -> String {
    let (_, bucket) = range.span_and_bucket();
    match range {
        StatsRange::Hour => util::time(at),
        StatsRange::Day => format!("{} – {}", util::time(at), util::time(at + bucket)),
        StatsRange::Week => format!(
            "{} – {}",
            util::weekday_datetime(at),
            util::time(at + bucket)
        ),
        StatsRange::Month => util::date(at),
    }
}

fn fmt(v: f64) -> String {
    format!("{v:.1}")
}

#[component]
pub fn TrafficChart(points: Vec<StatsPoint>, range: StatsRange) -> Element {
    let mut hover = use_signal(|| None::<usize>);
    let n = points.len();
    if n == 0 {
        return rsx! {
            div { class: "grid h-56 place-items-center text-sm text-muted-foreground", {tr("Noch keine Daten.")} }
        };
    }
    let max = points
        .iter()
        .map(|p| {
            p.total
                .max(p.forwarded + p.cached + p.authoritative + p.blocked)
        })
        .max()
        .unwrap_or(0) as f64;
    let step = nice_step(max, 4.0);
    let ymax = (step * (max / step).ceil()).max(step * 2.0);
    let ticks: Vec<f64> = (0..=((ymax / step).round() as usize))
        .map(|i| i as f64 * step)
        .collect();
    let x = |i: usize| {
        if n == 1 {
            W / 2.0
        } else {
            i as f64 * W / (n - 1) as f64
        }
    };
    let y = |v: f64| H - v / ymax * H;

    // Gestapelte Flächen
    let mut lower = vec![0f64; n];
    let mut bands: Vec<(String, String, &str)> = Vec::new();
    for (key, color) in SERIES {
        let upper: Vec<f64> = points
            .iter()
            .zip(&lower)
            .map(|(p, l)| l + value(p, key) as f64)
            .collect();
        let mut area = String::new();
        let mut edge = String::new();
        for (i, u) in upper.iter().enumerate() {
            let cmd = if i == 0 { 'M' } else { 'L' };
            area.push_str(&format!("{cmd}{} {} ", fmt(x(i)), fmt(y(*u))));
            edge.push_str(&format!("{cmd}{} {} ", fmt(x(i)), fmt(y(*u))));
        }
        for i in (0..n).rev() {
            area.push_str(&format!("L{} {} ", fmt(x(i)), fmt(y(lower[i]))));
        }
        area.push('Z');
        bands.push((area, edge, color));
        lower = upper;
    }
    let total_line: String = points
        .iter()
        .enumerate()
        .map(|(i, p)| {
            format!(
                "{}{} {} ",
                if i == 0 { 'M' } else { 'L' },
                fmt(x(i)),
                fmt(y(p.total as f64))
            )
        })
        .collect();
    let empty = points.iter().all(|p| p.total == 0);

    // Etwa sechs Beschriftungen auf der x-Achse
    let every = n.div_ceil(6).max(1);
    let labels: Vec<(f64, String, &str)> = (0..n)
        .filter(|i| i % every == 0)
        .map(|i| {
            let pct = x(i) / W * 100.0;
            let align = if i == 0 && n > 1 {
                "translate-x-0"
            } else if i + 1 == n && n > 1 {
                "-translate-x-full"
            } else {
                "-translate-x-1/2"
            };
            (pct, axis_label(range, points[i].at), align)
        })
        .collect();
    let col_w = if n == 1 {
        100.0
    } else {
        100.0 / (n - 1) as f64
    };
    let hovered = hover().filter(|i| *i < n);

    rsx! {
        div { class: "select-none",
            // Legende
            div { class: "mb-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-muted-foreground",
                span { class: "inline-flex items-center gap-1.5",
                    span { class: "h-0.5 w-3.5 rounded-full", style: "background: {TOTAL_COLOR}" }
                    {tr("Anfragen")}
                }
                for (key , color) in SERIES.iter().rev() {
                    span { key: "{key}", class: "inline-flex items-center gap-1.5",
                        span { class: "size-2.5 rounded-[3px]", style: "background: {color}" }
                        {series_label(key)}
                    }
                }
            }
            div { class: "flex pt-2",
                // y-Achse
                div { class: "relative h-56 w-11 shrink-0 text-[11px] tabular-nums text-muted-foreground",
                    for t in ticks.iter().copied() {
                        span { key: "{t}", class: "absolute right-2 -translate-y-1/2 leading-none", style: "top: {(1.0 - t / ymax) * 100.0}%",
                            {util::compact(t)}
                        }
                    }
                }
                div { class: "relative h-56 min-w-0 flex-1",
                    svg {
                        class: "absolute inset-0 h-full w-full overflow-visible",
                        view_box: "0 0 {W} {H}",
                        preserve_aspect_ratio: "none",
                        "aria-hidden": "true",
                        for t in ticks.iter().copied() {
                            line {
                                key: "{t}",
                                x1: "0",
                                x2: "{W}",
                                y1: "{fmt(y(t))}",
                                y2: "{fmt(y(t))}",
                                style: "stroke: oklch(1 0 0 / 8%); stroke-width: 1",
                                vector_effect: "non-scaling-stroke",
                            }
                        }
                        for (i , (area , edge , color)) in bands.iter().enumerate() {
                            g { key: "{i}",
                                path { d: "{area}", style: "fill: {color}; fill-opacity: 0.42; stroke: none" }
                                path {
                                    d: "{edge}",
                                    style: "fill: none; stroke: {color}; stroke-width: 1.25; stroke-linejoin: round; stroke-linecap: round",
                                    vector_effect: "non-scaling-stroke",
                                }
                            }
                        }
                        path {
                            d: "{total_line}",
                            style: "fill: none; stroke: {TOTAL_COLOR}; stroke-width: 2; stroke-linejoin: round; stroke-linecap: round",
                            vector_effect: "non-scaling-stroke",
                        }
                        if let Some(i) = hovered {
                            line {
                                x1: "{fmt(x(i))}",
                                x2: "{fmt(x(i))}",
                                y1: "0",
                                y2: "{H}",
                                style: "stroke: oklch(1 0 0 / 35%); stroke-width: 1",
                                vector_effect: "non-scaling-stroke",
                            }
                        }
                    }
                    // Punkt auf der Gesamt-Linie (HTML, damit er rund bleibt)
                    if let Some(i) = hovered {
                        span {
                            class: "pointer-events-none absolute size-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full ring-2 ring-card",
                            style: "left: {x(i) / W * 100.0}%; top: {y(points[i].total as f64) / H * 100.0}%; background: {TOTAL_COLOR}",
                        }
                    }
                    if empty {
                        div { class: "pointer-events-none absolute inset-0 grid place-items-center text-sm text-muted-foreground",
                            {tr("Keine Anfragen in diesem Zeitraum.")}
                        }
                    }
                    // Trefferflächen je Punkt
                    div { class: "absolute inset-0 overflow-hidden", onmouseleave: move |_| hover.set(None),
                        for i in 0..n {
                            div {
                                key: "{i}",
                                class: "absolute inset-y-0",
                                style: "left: {(x(i) / W * 100.0) - col_w / 2.0}%; width: {col_w}%",
                                onmouseenter: move |_| hover.set(Some(i)),
                                onmousemove: move |_| {
                                    if *hover.peek() != Some(i) {
                                        hover.set(Some(i));
                                    }
                                },
                                onclick: move |_| hover.set(Some(i)),
                            }
                        }
                    }
                    if let Some(i) = hovered {
                        Tooltip { point: points[i].clone(), title: bucket_label(range, points[i].at), left: x(i) / W * 100.0 }
                    }
                }
            }
            // x-Achse
            div { class: "relative ml-11 h-6 text-[11px] tabular-nums text-muted-foreground",
                for (pct , text , align) in labels {
                    span { key: "{pct}", class: "absolute top-1.5 whitespace-nowrap {align}", style: "left: {pct}%", "{text}" }
                }
            }
        }
    }
}

#[component]
fn Tooltip(point: StatsPoint, title: String, left: f64) -> Element {
    // Rechts vom Fadenkreuz, in der rechten Hälfte links davon
    let pos = if left > 55.0 {
        format!("right: {}%; margin-right: 12px", 100.0 - left)
    } else {
        format!("left: {left}%; margin-left: 12px")
    };
    let other = point
        .total
        .saturating_sub(point.forwarded + point.cached + point.authoritative + point.blocked);
    rsx! {
        div { class: "pointer-events-none absolute top-2 z-10 min-w-44 rounded-lg border bg-popover/95 px-3 py-2 text-xs shadow-lg backdrop-blur-sm", style: "{pos}",
            p { class: "mb-1.5 font-medium text-muted-foreground", "{title}" }
            div { class: "grid grid-cols-[auto_1fr_auto] items-center gap-x-2 gap-y-1",
                span { class: "h-0.5 w-3 rounded-full", style: "background: {TOTAL_COLOR}" }
                span { class: "text-muted-foreground", {tr("Anfragen")} }
                span { class: "text-right font-semibold tabular-nums text-foreground", {util::num(point.total)} }
                for (key , color) in SERIES.iter().rev() {
                    span { key: "{key}-k", class: "h-0.5 w-3 rounded-full", style: "background: {color}" }
                    span { class: "text-muted-foreground", {series_label(key)} }
                    span { class: "text-right font-semibold tabular-nums text-foreground", {util::num(value(&point, key))} }
                }
                if other > 0 {
                    span { class: "h-0.5 w-3 rounded-full bg-muted-foreground/40" }
                    span { class: "text-muted-foreground", {tr("Sonstige")} }
                    span { class: "text-right font-semibold tabular-nums text-foreground", {util::num(other)} }
                }
            }
        }
    }
}
