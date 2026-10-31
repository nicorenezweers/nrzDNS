//! Anzeigenamen für die Aufzählungen der API (übersetzt) und gemeinsame Auswahllisten.

use crate::i18n::tr;
use nrzdns_types::{
    BlockMode, ForwardingStrategy, Protocol, ResponseKind, StatsRange, UpstreamProtocol, ZoneKind,
};

/// Woher die Antwort kam.
pub fn kind(k: ResponseKind) -> String {
    match k {
        ResponseKind::Authoritative => tr("Verbindlich"),
        ResponseKind::Forwarded => tr("Weitergeleitet"),
        ResponseKind::Cached => tr("Aus dem Cache"),
        ResponseKind::Blocked => tr("Gesperrt"),
        ResponseKind::Local => tr("Lokal"),
        ResponseKind::Dropped => tr("Verworfen"),
        ResponseKind::Failed => tr("Fehlgeschlagen"),
    }
}

/// Wie die Anfrage hereinkam.
pub fn protocol(p: Protocol) -> &'static str {
    match p {
        Protocol::Udp => "UDP",
        Protocol::Tcp => "TCP",
        Protocol::Https => "DoH",
    }
}

/// Protokoll zu einem vorgelagerten Server.
pub fn upstream_protocol(p: UpstreamProtocol) -> &'static str {
    match p {
        UpstreamProtocol::Udp => "UDP",
        UpstreamProtocol::Tcp => "TCP",
        UpstreamProtocol::Tls => "DoT (TLS)",
        UpstreamProtocol::Https => "DoH (HTTPS)",
    }
}

pub const UPSTREAM_PROTOCOLS: [UpstreamProtocol; 4] = [
    UpstreamProtocol::Udp,
    UpstreamProtocol::Tcp,
    UpstreamProtocol::Tls,
    UpstreamProtocol::Https,
];

pub fn upstream_protocol_key(p: UpstreamProtocol) -> &'static str {
    match p {
        UpstreamProtocol::Udp => "udp",
        UpstreamProtocol::Tcp => "tcp",
        UpstreamProtocol::Tls => "tls",
        UpstreamProtocol::Https => "https",
    }
}

pub fn parse_upstream_protocol(s: &str) -> UpstreamProtocol {
    UPSTREAM_PROTOCOLS
        .into_iter()
        .find(|p| upstream_protocol_key(*p) == s)
        .unwrap_or_default()
}

/// Beispieladresse je Protokoll (Platzhalter im Eingabefeld).
pub fn upstream_placeholder(p: UpstreamProtocol) -> &'static str {
    match p {
        UpstreamProtocol::Udp | UpstreamProtocol::Tcp => "1.1.1.1",
        UpstreamProtocol::Tls => "1.1.1.1:853",
        UpstreamProtocol::Https => "https://1.1.1.1/dns-query",
    }
}

pub fn zone_kind(k: ZoneKind) -> String {
    match k {
        ZoneKind::Primary => tr("Primär"),
        ZoneKind::Forwarder => tr("Weiterleitung"),
    }
}

/// Zeitraum des Dashboards.
pub fn range(r: StatsRange) -> String {
    match r {
        StatsRange::Hour => tr("Stunde"),
        StatsRange::Day => tr("Tag"),
        StatsRange::Week => tr("Woche"),
        StatsRange::Month => tr("Monat"),
    }
}

/// Zeitraum des Dashboards als Filter des Abfrageprotokolls (`period`).
pub fn range_period(r: StatsRange) -> &'static str {
    match r {
        StatsRange::Hour => "1h",
        StatsRange::Day => "24h",
        StatsRange::Week => "7d",
        StatsRange::Month => "30d",
    }
}

/// Zeiträume im Abfrageprotokoll: Schlüssel, Sekunden, Anzeigename.
pub fn periods() -> Vec<(&'static str, i64, String)> {
    vec![
        ("15m", 15 * 60, tr("Letzte 15 Minuten")),
        ("1h", 3600, tr("Letzte Stunde")),
        ("24h", 86_400, tr("Letzte 24 Stunden")),
        ("7d", 7 * 86_400, tr("Letzte 7 Tage")),
        ("30d", 30 * 86_400, tr("Letzte 30 Tage")),
    ]
}

pub fn strategy(s: ForwardingStrategy) -> String {
    match s {
        ForwardingStrategy::Sequential => tr("Der Reihe nach"),
        ForwardingStrategy::Random => tr("Zufällig"),
        ForwardingStrategy::Parallel => tr("Alle gleichzeitig"),
    }
}

pub fn strategy_hint(s: ForwardingStrategy) -> String {
    match s {
        ForwardingStrategy::Sequential => {
            tr("Der erste Server antwortet; die nächsten nur bei Fehler oder Zeitüberschreitung.")
        }
        ForwardingStrategy::Random => {
            tr("Ein zufälliger Server, bei Fehler der nächste – verteilt die Last.")
        }
        ForwardingStrategy::Parallel => tr(
            "Alle gleichzeitig fragen, die schnellste Antwort gewinnt – am schnellsten, aber mehr Verkehr.",
        ),
    }
}

pub const STRATEGIES: [ForwardingStrategy; 3] = [
    ForwardingStrategy::Sequential,
    ForwardingStrategy::Random,
    ForwardingStrategy::Parallel,
];

pub fn strategy_key(s: ForwardingStrategy) -> &'static str {
    match s {
        ForwardingStrategy::Sequential => "sequential",
        ForwardingStrategy::Random => "random",
        ForwardingStrategy::Parallel => "parallel",
    }
}

pub fn block_mode(m: BlockMode) -> String {
    match m {
        BlockMode::NullAddress => tr("Nulladresse (0.0.0.0 / ::)"),
        BlockMode::NxDomain => tr("NXDOMAIN (Domain gibt es nicht)"),
        BlockMode::CustomAddress => tr("Eigene Adressen (z. B. Sperrseite)"),
        BlockMode::Refused => tr("REFUSED (abgelehnt)"),
    }
}

pub const BLOCK_MODES: [BlockMode; 4] = [
    BlockMode::NullAddress,
    BlockMode::NxDomain,
    BlockMode::CustomAddress,
    BlockMode::Refused,
];

pub fn block_mode_key(m: BlockMode) -> &'static str {
    match m {
        BlockMode::NullAddress => "nullAddress",
        BlockMode::NxDomain => "nxDomain",
        BlockMode::CustomAddress => "customAddress",
        BlockMode::Refused => "refused",
    }
}

/// Typen für den DNS-Client.
pub const QUERY_TYPES: [&str; 12] = [
    "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV", "CAA", "HTTPS", "ANY",
];

/// Typen für den Filter im Abfrageprotokoll.
pub const LOG_TYPES: [&str; 12] = [
    "A", "AAAA", "HTTPS", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV", "SVCB", "ANY",
];

/// Antwortcodes für den Filter im Abfrageprotokoll.
pub const RCODES: [&str; 6] = [
    "NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR", "NOTIMP",
];
