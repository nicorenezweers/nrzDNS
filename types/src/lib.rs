//! nrzDNS – Typen der JSON-API unter `/api/v1`. Server (Rocket), DNS-Engine (`engine/`) und
//! Oberfläche (Dioxus, WebAssembly) benutzen dieselben Structs, damit nie etwas auseinanderläuft.
//!
//! Konventionen:
//! * JSON-Felder in camelCase, Zeitpunkte als Unix-Sekunden (UTC, `i64`), IDs als `i64`.
//! * Domains immer klein, ohne Punkt am Ende (`example.com`), siehe [`normalize_domain`].
//! * Anmeldung per Sitzungs-Cookie (`nrzdns_session`, HttpOnly, SameSite=Lax).
//! * Fehler: HTTP-Status plus [`ApiError`] als Körper.
//! * Rollen: **Admin** darf alles; **Mitglied** sieht alles (Dashboard, Zonen, Listen, Cache,
//!   Abfragen, DNS-Client), ändert aber nichts ausser dem eigenen Konto.
//!
//! Endpunkte (alle unter `/api/v1`):
//!
//! | Methode & Pfad | Körper → Antwort | Wer |
//! |---|---|---|
//! | `GET /health` | → `{status, name, version}` | alle |
//! | `GET /auth/status` | → [`AuthStatus`] | alle |
//! | `POST /auth/register` | [`RegisterInput`] → [`User`] (setzt Cookie; erstes Konto = Admin) | alle, solange Registrierung offen oder noch kein Konto |
//! | `POST /auth/login` | [`LoginInput`] → [`User`] (setzt Cookie) | alle |
//! | `POST /auth/logout` | → `204` | angemeldet |
//! | `GET /me` | → [`User`] | angemeldet |
//! | `PUT /me` | [`UpdateMeInput`] → [`User`] | angemeldet |
//! | `PUT /me/password` | [`ChangePasswordInput`] → `204` | angemeldet |
//! | `GET /admin/users` | → `Vec<`[`User`]`>` | Admin |
//! | `POST /admin/users` | [`CreateUserInput`] → [`User`] | Admin |
//! | `PUT /admin/users/<id>` | [`UpdateUserInput`] → [`User`] | Admin |
//! | `DELETE /admin/users/<id>` | → `204` | Admin (nicht sich selbst, nicht den letzten Admin) |
//! | `GET /settings/instance` | → [`InstanceSettings`] | Admin |
//! | `PUT /settings/instance` | [`InstanceSettings`] → [`InstanceSettings`] | Admin |
//! | `GET /settings/dns` | → [`DnsSettings`] | angemeldet |
//! | `PUT /settings/dns` | [`DnsSettings`] → [`DnsSettings`] (sofort aktiv, ohne Neustart) | Admin |
//! | `GET /presets` | → [`Presets`] (Weiterleitungen und Sperrlisten zum Übernehmen) | angemeldet |
//! | `GET /server` | → [`ServerStatus`] | angemeldet |
//! | `GET /dashboard?range=` | → [`Dashboard`] (`range` = [`StatsRange`], Vorgabe `day`) | angemeldet |
//! | `GET /zones` | → `Vec<`[`Zone`]`>` | angemeldet |
//! | `POST /zones` | [`ZoneInput`] → [`Zone`] (Primärzone mit SOA und NS) | Admin |
//! | `POST /zones/import` | [`ZoneImportInput`] → [`ZoneImportResult`] (Zonendatei im BIND-Format) | Admin |
//! | `GET /zones/<id>` | → [`ZoneDetail`] | angemeldet |
//! | `PUT /zones/<id>` | [`UpdateZoneInput`] → [`Zone`] | Admin |
//! | `DELETE /zones/<id>` | → `204` (mit allen Einträgen) | Admin |
//! | `GET /zones/<id>/export` | → Zonendatei (`text/plain`, Download `<zone>.zone`) | angemeldet |
//! | `POST /zones/<id>/records` | [`RecordInput`] → [`ZoneRecord`] (erhöht die SOA-Seriennummer) | Admin |
//! | `PUT /zones/<id>/records/<rid>` | [`RecordInput`] → [`ZoneRecord`] | Admin |
//! | `DELETE /zones/<id>/records/<rid>` | → `204` | Admin |
//! | `GET /blocking` | → [`BlockingStatus`] | angemeldet |
//! | `POST /blocking/lists` | [`BlockListInput`] → [`BlockList`] (lädt die Liste sofort) | Admin |
//! | `PUT /blocking/lists/<id>` | [`BlockListInput`] → [`BlockList`] | Admin |
//! | `DELETE /blocking/lists/<id>` | → `204` | Admin |
//! | `POST /blocking/update` | → [`BlockingStatus`] (alle aktiven Listen jetzt neu laden) | Admin |
//! | `POST /blocking/pause` | [`PauseInput`] → [`BlockingStatus`] (`minutes = 0` setzt fort) | Admin |
//! | `GET /blocking/check?domain=` | → [`DomainCheck`] | angemeldet |
//! | `GET /blocked` | → `Vec<`[`DomainEntry`]`>` (eigene Sperren) | angemeldet |
//! | `POST /blocked` | [`DomainInput`] → [`DomainEntry`] | Admin |
//! | `DELETE /blocked/<domain>` | → `204` | Admin |
//! | `GET /allowed` | → `Vec<`[`DomainEntry`]`>` (Ausnahmen, schlagen jede Sperre) | angemeldet |
//! | `POST /allowed` | [`DomainInput`] → [`DomainEntry`] | Admin |
//! | `DELETE /allowed/<domain>` | → `204` | Admin |
//! | `GET /logs?page=&perPage=&client=&qname=&qtype=&kind=&rcode=&from=&to=` | → [`QueryLogPage`] (Filter = [`QueryLogFilter`]) | angemeldet |
//! | `GET /logs/export?…` | → CSV (`text/csv`, gleiche Filter, höchstens 100 000 Zeilen) | angemeldet |
//! | `DELETE /logs` | → `204` (ganzes Abfrageprotokoll leeren) | Admin |
//! | `GET /cache?q=&limit=` | → [`CacheList`] | angemeldet |
//! | `DELETE /cache` | → [`CacheFlushResult`] (alles leeren) | Admin |
//! | `DELETE /cache/<name>` | → [`CacheFlushResult`] (alle Typen dieses Namens) | Admin |
//! | `POST /resolve` | [`ResolveInput`] → [`ResolveResult`] (DNS-Client) | angemeldet |
//! | `GET /settings/mcp` | → [`McpStatus`] | Admin |
//! | `PUT /settings/mcp` | [`McpSettingsInput`] → [`McpStatus`] | Admin |
//! | `POST /settings/mcp/token` | → [`McpToken`] (neues Token, nur jetzt im Klartext; das alte gilt nicht mehr) | Admin |
//! | `DELETE /settings/mcp/token` | → [`McpStatus`] (MCP aus) | Admin |
//! | `GET /proxy` | → [`ProxyStatus`] (Reverse Proxy: Einträge, Ports, Adresse) | angemeldet |
//! | `PUT /proxy/settings` | [`ProxySettings`] → [`ProxyStatus`] | Admin |
//! | `POST /proxy/hosts` | [`ProxyHostInput`] → [`ProxyHost`] | Admin |
//! | `PUT /proxy/hosts/<id>` | [`ProxyHostInput`] → [`ProxyHost`] | Admin |
//! | `DELETE /proxy/hosts/<id>` | → `204` | Admin |
//! | `GET /unlocks` | → `Vec<`[`TempUnlock`]`>` (auf Zeit freigeschaltet, über die Sperrseite) | angemeldet |
//! | `DELETE /unlocks/<domain>` | → `204` (Freischaltung beenden) | Admin |
//! | `GET /requests` | → `Vec<`[`AllowRequest`]`>` (Anträge auf Ausnahmen, offene zuerst) | angemeldet |
//! | `POST /requests/<id>/approve` | → [`AllowRequest`] (Domain kommt in die Ausnahmen) | Admin |
//! | `POST /requests/<id>/reject` | → [`AllowRequest`] | Admin |
//! | `DELETE /requests/<id>` | → `204` | Admin |
//! | `GET /tls` | → [`TlsStatus`] (HTTPS: Einstellungen ohne Token, Zertifikat, letzter Versuch) | angemeldet |
//! | `PUT /tls` | [`TlsSettingsInput`] → [`TlsStatus`] | Admin |
//! | `POST /tls/issue` | → [`TlsStatus`] (Zertifikat jetzt holen, läuft im Hintergrund) | Admin |
//! | `DELETE /tls/certificate` | → `204` (Zertifikat entfernen) | Admin |
//! | `GET /integrations[?test=true]` | → [`IntegrationsStatus`] (Cloudflare, NetBird; mit `test` werden beide APIs gefragt) | angemeldet |
//! | `PUT /integrations` | [`IntegrationsInput`] → [`IntegrationsStatus`] | Admin |
//! | `GET\|POST\|PUT\|PATCH\|DELETE /cloudflare/<pfad>` | Cloudflare-API (`/client/v4/<pfad>`): Zonen lesen, DNS-Einträge verwalten; Antwort unverändert | lesen: angemeldet, ändern: Admin |
//! | `GET\|POST\|PUT\|DELETE /netbird/<pfad>` | NetBird-API (`/api/<pfad>`): Geräte, Gruppen, Policies, Netzwerke, DNS, Setup-Keys, Benutzer; Antwort unverändert | lesen: angemeldet, ändern: Admin |
//! | `GET /spy` | → [`SpyStatus`] (laufender Scan, eigene Domains, letzte Berichte) | angemeldet |
//! | `POST /spy/scan` | [`SpyScanInput`] → [`SpyStatus`] (Scan im Hintergrund; aktiv nur für eigene Domains) | Admin |
//! | `DELETE /spy/reports/<domain>` | → `204` | Admin |
//! | `POST /tools/ping` | [`PingInput`] → [`PingResult`] (ICMP, sonst TCP) | angemeldet |
//! | `POST /tools/ports` | [`PortsInput`] → [`PortsResult`] | angemeldet |
//! | `POST /tools/http` | [`HttpCheckInput`] → [`HttpCheckResult`] | angemeldet |
//! | `GET /devices?days=` | → `Vec<`[`Device`]`>` (Geräte aus dem Abfrageprotokoll, 1–30 Tage) | angemeldet |
//! | `PUT /devices/<ip>` | [`DeviceNameInput`] → [`Device`] (Name, leer = löschen) | Admin |
//!
//! **MCP-Server** (Model Context Protocol, Streamable HTTP, JSON-RPC 2.0) unter `POST /mcp`, mit
//! `Authorization: Bearer <Token>` – für nrzDashboard und andere MCP-Clients: Übersicht,
//! Statistiken, Abfrageprotokoll und (wenn erlaubt) Sperren ein-/ausschalten, pausieren usw.
//!
//! Ausserhalb von `/api/v1`: **DNS über HTTPS** (RFC 8484) unter `GET /dns-query?dns=<base64url>`
//! und `POST /dns-query` (`application/dns-message`), ohne Anmeldung, abschaltbar mit
//! [`DnsSettings::doh_enabled`].

use serde::{Deserialize, Serialize};

mod spy;
mod tls;
mod tools;
pub use spy::*;
pub use tls::*;
pub use tools::*;

// ------------------------------------------------------------------ Fehler

/// Fehlerkörper jeder Antwort mit Status ≥ 400.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiError {
    pub error: ApiErrorBody,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiErrorBody {
    /// Maschinenlesbar: `bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`, …
    pub code: String,
    /// Deutsche Meldung für den Benutzer (die Oberfläche übersetzt sie über den Katalog).
    pub message: String,
}

// ------------------------------------------------------------------ Konten

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    #[default]
    Member,
}

/// Persönliche Einstellungen, gespeichert beim Benutzer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Preferences {
    /// Sprache der Oberfläche: "de" oder "en".
    pub language: String,
    /// Zeitraum, mit dem das Dashboard öffnet.
    pub dashboard_range: StatsRange,
    /// Dashboard alle N Sekunden neu laden (0 = nie).
    pub dashboard_refresh_secs: u32,
    /// Zeilen je Seite im Abfrageprotokoll.
    pub logs_per_page: u32,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            language: "de".into(),
            dashboard_range: StatsRange::Day,
            dashboard_refresh_secs: 30,
            logs_per_page: 50,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: i64,
    pub username: String,
    /// Anzeigename; leer = Benutzername anzeigen.
    pub display_name: String,
    pub role: Role,
    pub disabled: bool,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
    pub preferences: Preferences,
}

impl User {
    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }

    pub fn name(&self) -> &str {
        if self.display_name.trim().is_empty() {
            &self.username
        } else {
            &self.display_name
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthStatus {
    pub authenticated: bool,
    /// Noch kein Konto: die Oberfläche zeigt die Ersteinrichtung (erstes Konto = Admin).
    pub setup_required: bool,
    /// Selbst registrieren erlaubt (Einstellung des Admins).
    pub registration_open: bool,
    pub user: Option<User>,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginInput {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterInput {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateMeInput {
    pub display_name: Option<String>,
    pub preferences: Option<Preferences>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordInput {
    pub current: String,
    pub new: String,
}

/// Mindestlänge für Passwörter (Server prüft, Oberfläche zeigt sie an).
pub const MIN_PASSWORD_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserInput {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub role: Role,
}

/// Nur gesetzte Felder werden geändert.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateUserInput {
    pub display_name: Option<String>,
    pub role: Option<Role>,
    /// Neues Passwort setzen (meldet alle Sitzungen des Benutzers ab).
    pub password: Option<String>,
    /// Gesperrte Konten können sich nicht anmelden.
    pub disabled: Option<bool>,
}

/// Einstellungen der Instanz (Admin).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct InstanceSettings {
    /// Jeder darf sich selbst ein Konto anlegen (neue Konten sind Mitglieder).
    pub registration_open: bool,
}

// ------------------------------------------------------------------ DNS: Weiterleitung

/// Protokoll zu einem vorgelagerten DNS-Server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    /// Klassisch über UDP (fällt bei abgeschnittenen Antworten auf TCP zurück), Port 53.
    #[default]
    Udp,
    /// Klassisch über TCP, Port 53.
    Tcp,
    /// DNS über TLS (RFC 7858), Port 853.
    Tls,
    /// DNS über HTTPS (RFC 8484).
    Https,
}

/// Ein vorgelagerter DNS-Server.
///
/// `address` je nach Protokoll:
/// * `udp`/`tcp`: `1.1.1.1`, `1.1.1.1:53` oder `[2606:4700:4700::1111]:53` (ohne Port = 53)
/// * `tls`: `1.1.1.1:853` oder `1.1.1.1` (ohne Port = 853); Zertifikatsname in `tls_name`
/// * `https`: ganze URL, z. B. `https://1.1.1.1/dns-query` oder `https://dns.quad9.net/dns-query`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Upstream {
    pub protocol: UpstreamProtocol,
    pub address: String,
    /// Name im TLS-Zertifikat (DoT); leer = aus `address`.
    pub tls_name: String,
    /// Anzeigename, z. B. „Cloudflare“; leer = `address`.
    pub name: String,
}

impl Upstream {
    pub fn new(protocol: UpstreamProtocol, address: &str, tls_name: &str, name: &str) -> Self {
        Self {
            protocol,
            address: address.into(),
            tls_name: tls_name.into(),
            name: name.into(),
        }
    }

    /// Kurzform für Anzeige und Protokoll: `udp://1.1.1.1`, `tls://1.1.1.1:853`, `https://…`.
    pub fn label(&self) -> String {
        match self.protocol {
            UpstreamProtocol::Https => self.address.clone(),
            UpstreamProtocol::Udp => format!("udp://{}", self.address),
            UpstreamProtocol::Tcp => format!("tcp://{}", self.address),
            UpstreamProtocol::Tls => format!("tls://{}", self.address),
        }
    }
}

/// Wie mehrere Weiterleitungen benutzt werden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ForwardingStrategy {
    /// Der Reihe nach: der erste, der antwortet, gewinnt; die nächsten nur bei Fehler/Zeitlimit.
    #[default]
    Sequential,
    /// Zufällig einer, bei Fehler der nächste.
    Random,
    /// Alle gleichzeitig fragen, die schnellste Antwort gewinnt.
    Parallel,
}

/// Fertige Auswahl an Weiterleitungen für die Einstellungen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamPreset {
    pub id: String,
    pub name: String,
    pub description: String,
    pub upstreams: Vec<Upstream>,
}

/// Fertige Sperrliste zum Übernehmen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockListPreset {
    pub name: String,
    pub url: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Presets {
    pub upstreams: Vec<UpstreamPreset>,
    pub blocklists: Vec<BlockListPreset>,
}

impl Presets {
    /// Die eingebauten Vorlagen (Server liefert sie unter `GET /presets` aus).
    pub fn builtin() -> Self {
        use UpstreamProtocol::*;
        let p =
            |id: &str, name: &str, description: &str, upstreams: Vec<Upstream>| UpstreamPreset {
                id: id.into(),
                name: name.into(),
                description: description.into(),
                upstreams,
            };
        let b = |name: &str, url: &str, description: &str| BlockListPreset {
            name: name.into(),
            url: url.into(),
            description: description.into(),
        };
        Self {
            upstreams: vec![
                p("cloudflare", "Cloudflare", "Schnell, ohne Filter (1.1.1.1)", vec![
                    Upstream::new(Udp, "1.1.1.1", "", "Cloudflare"),
                    Upstream::new(Udp, "1.0.0.1", "", "Cloudflare"),
                ]),
                p("cloudflare-doh", "Cloudflare (DoH)", "Verschlüsselt über HTTPS", vec![
                    Upstream::new(Https, "https://1.1.1.1/dns-query", "", "Cloudflare DoH"),
                    Upstream::new(Https, "https://1.0.0.1/dns-query", "", "Cloudflare DoH"),
                ]),
                p("cloudflare-dot", "Cloudflare (DoT)", "Verschlüsselt über TLS", vec![
                    Upstream::new(Tls, "1.1.1.1:853", "cloudflare-dns.com", "Cloudflare DoT"),
                    Upstream::new(Tls, "1.0.0.1:853", "cloudflare-dns.com", "Cloudflare DoT"),
                ]),
                p("quad9", "Quad9", "Sperrt bekannte Schad-Domains (9.9.9.9)", vec![
                    Upstream::new(Udp, "9.9.9.9", "", "Quad9"),
                    Upstream::new(Udp, "149.112.112.112", "", "Quad9"),
                ]),
                p("quad9-doh", "Quad9 (DoH)", "Quad9 verschlüsselt über HTTPS", vec![
                    Upstream::new(Https, "https://9.9.9.9/dns-query", "", "Quad9 DoH"),
                    Upstream::new(Https, "https://149.112.112.112/dns-query", "", "Quad9 DoH"),
                ]),
                p("google", "Google", "Google Public DNS (8.8.8.8)", vec![
                    Upstream::new(Udp, "8.8.8.8", "", "Google"),
                    Upstream::new(Udp, "8.8.4.4", "", "Google"),
                ]),
                p("google-doh", "Google (DoH)", "Google verschlüsselt über HTTPS", vec![
                    Upstream::new(Https, "https://8.8.8.8/dns-query", "", "Google DoH"),
                    Upstream::new(Https, "https://8.8.4.4/dns-query", "", "Google DoH"),
                ]),
                p("adguard", "AdGuard DNS", "Sperrt Werbung und Tracker schon beim Anbieter", vec![
                    Upstream::new(Udp, "94.140.14.14", "", "AdGuard"),
                    Upstream::new(Udp, "94.140.15.15", "", "AdGuard"),
                ]),
                p("mullvad-doh", "Mullvad (DoH)", "Ohne Protokoll, verschlüsselt", vec![
                    Upstream::new(Https, "https://dns.mullvad.net/dns-query", "", "Mullvad DoH"),
                ]),
            ],
            blocklists: vec![
                b(
                    "StevenBlack Unified",
                    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
                    "Werbung und Schadsoftware, hosts-Format (rund 80 000 Domains)",
                ),
                b(
                    "HaGeZi Multi Normal",
                    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt",
                    "Werbung, Tracking, Schadsoftware – ausgewogen",
                ),
                b(
                    "HaGeZi Multi Light",
                    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt",
                    "Wie Normal, aber zurückhaltender",
                ),
                b(
                    "OISD Small",
                    "https://small.oisd.nl/domainswild2",
                    "Werbung und Tracking, sehr wenige Fehlalarme",
                ),
                b(
                    "AdGuard DNS Filter",
                    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
                    "Adblock-Format, Werbung und Tracking",
                ),
                b(
                    "HaGeZi Threat Intelligence",
                    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt",
                    "Phishing, Malware, Kryptomining",
                ),
            ],
        }
    }
}

// ------------------------------------------------------------------ DNS: Einstellungen

/// Was eine gesperrte Domain als Antwort bekommt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum BlockMode {
    /// `NXDOMAIN` – die Domain gibt es nicht.
    NxDomain,
    /// `0.0.0.0` bzw. `::` (andere Typen: leere Antwort).
    NullAddress,
    /// Eigene Adressen aus [`DnsSettings::block_ipv4`] / [`DnsSettings::block_ipv6`], z. B. eine Sperrseite.
    CustomAddress,
    /// `REFUSED`.
    Refused,
    /// Adresse dieses Geräts: Browser landen bei `http://` auf der Sperrseite von nrzNetwork
    /// (freischalten auf Zeit, Ausnahme beantragen). Ohne bekannte Adresse wie `0.0.0.0`.
    #[default]
    BlockPage,
}

/// Alle Einstellungen des DNS-Servers. Gespeichert als JSON, die Engine übernimmt sie sofort.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DnsSettings {
    // --- Allgemein
    /// Name dieses Servers, Vorgabe für SOA/NS neuer Zonen (z. B. `ns.nrzdns.local`).
    pub server_domain: String,
    /// TTL neuer Einträge in Sekunden.
    pub default_ttl: u32,
    /// Höchstens N Anfragen pro Sekunde und Client (0 = unbegrenzt); darüber wird verworfen.
    pub rate_limit_qps: u32,
    /// DNS über HTTPS unter `/dns-query` annehmen.
    pub doh_enabled: bool,
    /// Rückwärtsanfragen (PTR) für private Netze (10/8, 172.16/12, 192.168/16, fc00::/7, …)
    /// nicht weiterleiten, sondern selbst mit NXDOMAIN beantworten, wenn keine Zone passt.
    pub local_ptr_no_forward: bool,
    /// Bei AAAA-Anfragen leer antworten (für Netze ohne IPv6).
    pub disable_ipv6_answers: bool,

    // --- Weiterleitung
    pub forwarders: Vec<Upstream>,
    pub forwarding_strategy: ForwardingStrategy,
    /// Zeitlimit je Anfrage an einen vorgelagerten Server (Millisekunden, 200–15 000).
    pub upstream_timeout_ms: u32,

    // --- Cache
    pub cache_enabled: bool,
    /// Höchstens so viele Einträge (ältere fliegen zuerst).
    pub cache_max_entries: u32,
    /// TTL mindestens so lange behalten (Sekunden).
    pub cache_min_ttl: u32,
    /// TTL höchstens so lange behalten (Sekunden).
    pub cache_max_ttl: u32,
    /// Negative Antworten (NXDOMAIN, leer) so lange behalten (Sekunden).
    pub cache_negative_ttl: u32,
    /// Abgelaufene Einträge ausliefern, wenn kein vorgelagerter Server antwortet (RFC 8767).
    pub serve_stale: bool,
    /// So lange nach Ablauf darf ein Eintrag noch ausgeliefert werden (Sekunden).
    pub serve_stale_secs: u32,
    /// Häufig gefragte Einträge kurz vor Ablauf im Hintergrund erneuern.
    pub prefetch: bool,

    // --- Sperren
    pub blocking_enabled: bool,
    pub block_mode: BlockMode,
    /// Für [`BlockMode::CustomAddress`].
    pub block_ipv4: String,
    pub block_ipv6: String,
    /// TTL gesperrter Antworten (Sekunden).
    pub block_ttl: u32,
    /// Sperrlisten alle N Stunden neu laden (1–168).
    pub blocklist_update_hours: u32,

    // --- Protokoll
    /// Jede Anfrage ins Abfrageprotokoll schreiben (Dashboard und Statistik brauchen es).
    pub log_queries: bool,
    /// Einträge nach N Tagen löschen (1–365).
    pub log_retention_days: u32,
}

impl Default for DnsSettings {
    fn default() -> Self {
        use UpstreamProtocol::Udp;
        Self {
            server_domain: "ns.nrzdns.local".into(),
            default_ttl: 3600,
            rate_limit_qps: 0,
            doh_enabled: true,
            local_ptr_no_forward: true,
            disable_ipv6_answers: false,
            forwarders: vec![
                Upstream::new(Udp, "1.1.1.1", "", "Cloudflare"),
                Upstream::new(Udp, "9.9.9.9", "", "Quad9"),
            ],
            forwarding_strategy: ForwardingStrategy::Sequential,
            upstream_timeout_ms: 2000,
            cache_enabled: true,
            cache_max_entries: 50_000,
            cache_min_ttl: 10,
            cache_max_ttl: 86_400,
            cache_negative_ttl: 300,
            serve_stale: true,
            serve_stale_secs: 86_400,
            prefetch: true,
            blocking_enabled: true,
            block_mode: BlockMode::BlockPage,
            block_ipv4: "0.0.0.0".into(),
            block_ipv6: "::".into(),
            block_ttl: 60,
            blocklist_update_hours: 24,
            log_queries: true,
            log_retention_days: 30,
        }
    }
}

// ------------------------------------------------------------------ DNS: Zonen

/// Typen, die sich in einer Zone pflegen lassen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SRV,
    PTR,
    CAA,
}

impl RecordType {
    pub const ALL: [RecordType; 9] = [
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::TXT,
        RecordType::NS,
        RecordType::SRV,
        RecordType::PTR,
        RecordType::CAA,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::NS => "NS",
            RecordType::SRV => "SRV",
            RecordType::PTR => "PTR",
            RecordType::CAA => "CAA",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|t| t.as_str().eq_ignore_ascii_case(s.trim()))
    }
}

/// Daten eines Eintrags. JSON: `{"type": "A", "address": "192.168.1.10"}`,
/// `{"type": "MX", "preference": 10, "exchange": "mail.example.com"}` usw.
/// Namen (Ziele) sind voll qualifiziert, ohne Punkt am Ende.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RecordData {
    A {
        address: String,
    },
    AAAA {
        address: String,
    },
    CNAME {
        target: String,
    },
    MX {
        preference: u16,
        exchange: String,
    },
    /// Längere Texte als 255 Zeichen werden in mehrere Zeichenketten geteilt.
    TXT {
        text: String,
    },
    NS {
        host: String,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    PTR {
        target: String,
    },
    CAA {
        flags: u8,
        tag: String,
        value: String,
    },
}

impl RecordData {
    pub fn record_type(&self) -> RecordType {
        match self {
            RecordData::A { .. } => RecordType::A,
            RecordData::AAAA { .. } => RecordType::AAAA,
            RecordData::CNAME { .. } => RecordType::CNAME,
            RecordData::MX { .. } => RecordType::MX,
            RecordData::TXT { .. } => RecordType::TXT,
            RecordData::NS { .. } => RecordType::NS,
            RecordData::SRV { .. } => RecordType::SRV,
            RecordData::PTR { .. } => RecordType::PTR,
            RecordData::CAA { .. } => RecordType::CAA,
        }
    }

    /// Daten in Zonendatei-Schreibweise ohne Typ, z. B. `10 mail.example.com.`.
    pub fn summary(&self) -> String {
        match self {
            RecordData::A { address } | RecordData::AAAA { address } => address.clone(),
            RecordData::CNAME { target } | RecordData::PTR { target } => format!("{target}."),
            RecordData::NS { host } => format!("{host}."),
            RecordData::MX {
                preference,
                exchange,
            } => format!("{preference} {exchange}."),
            RecordData::TXT { text } => format!("{text:?}"),
            RecordData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                format!("{priority} {weight} {port} {target}.")
            }
            RecordData::CAA { flags, tag, value } => format!("{flags} {tag} {value:?}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ZoneKind {
    /// Eigene Zone: nrzDNS antwortet verbindlich (AA) aus den Einträgen.
    #[default]
    Primary,
    /// Bedingte Weiterleitung: Anfragen in dieser Zone gehen an [`Zone::forwarders`]
    /// (z. B. `fritz.box` an den Router). Eigene Einträge haben trotzdem Vorrang.
    Forwarder,
}

/// SOA einer Primärzone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Soa {
    pub primary_ns: String,
    /// Verantwortliche Adresse in DNS-Schreibweise (`hostmaster.example.com`).
    pub responsible: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    /// Negativ-TTL (RFC 2308).
    pub minimum: u32,
}

impl Default for Soa {
    fn default() -> Self {
        Self {
            primary_ns: String::new(),
            responsible: String::new(),
            serial: 1,
            refresh: 900,
            retry: 300,
            expire: 604_800,
            minimum: 900,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Zone {
    pub id: i64,
    /// `example.com`, `home.arpa`, `1.168.192.in-addr.arpa`
    pub name: String,
    pub kind: ZoneKind,
    pub disabled: bool,
    pub soa: Soa,
    /// Nur für [`ZoneKind::Forwarder`].
    pub forwarders: Vec<Upstream>,
    pub comment: String,
    pub record_count: u32,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZoneRecord {
    pub id: i64,
    pub zone_id: i64,
    /// Relativ zur Zone: `@` = Zone selbst, `www`, `*` oder `*.dev` (Platzhalter).
    pub name: String,
    pub ttl: u32,
    pub data: RecordData,
    pub disabled: bool,
    pub comment: String,
    pub updated_at: i64,
}

impl ZoneRecord {
    /// Voller Name (`www.example.com`), `@` = Zonenname.
    pub fn fqdn(&self, zone: &str) -> String {
        record_fqdn(&self.name, zone)
    }
}

/// `@` → `zone`, `www` → `www.zone`; ein schon voller Name mit Punkt am Ende bleibt (ohne Punkt).
pub fn record_fqdn(name: &str, zone: &str) -> String {
    let name = name.trim();
    if name.is_empty() || name == "@" {
        zone.to_string()
    } else if let Some(full) = name.strip_suffix('.') {
        full.to_ascii_lowercase()
    } else {
        format!("{}.{zone}", name.to_ascii_lowercase())
    }
}

/// Zone mit allen Einträgen – so bekommt sie auch die Engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZoneDetail {
    pub zone: Zone,
    pub records: Vec<ZoneRecord>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ZoneInput {
    pub name: String,
    pub kind: ZoneKind,
    pub forwarders: Vec<Upstream>,
    pub comment: String,
}

/// Nur gesetzte Felder werden geändert.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateZoneInput {
    pub disabled: Option<bool>,
    pub soa: Option<Soa>,
    pub forwarders: Option<Vec<Upstream>>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordInput {
    pub name: String,
    /// 0 = [`DnsSettings::default_ttl`].
    #[serde(default)]
    pub ttl: u32,
    pub data: RecordData,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ZoneImportInput {
    /// Zonenname; leer = aus `$ORIGIN` bzw. dem SOA der Datei.
    pub name: String,
    /// Zonendatei im BIND-Format (RFC 1035).
    pub text: String,
    /// Gibt es die Zone schon, ihre Einträge ersetzen (sonst Fehler `conflict`).
    pub replace: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZoneImportResult {
    pub zone: Zone,
    pub imported: u32,
    /// Zeilen, die nicht übernommen wurden, mit Grund.
    pub skipped: Vec<String>,
}

// ------------------------------------------------------------------ DNS: Sperren

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockList {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub domain_count: u32,
    pub last_updated_at: Option<i64>,
    /// Letzter Fehler beim Laden (die alte Fassung bleibt dann aktiv).
    pub last_error: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct BlockListInput {
    /// Leer = aus der URL.
    pub name: String,
    pub url: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockingStatus {
    pub enabled: bool,
    /// Sperren pausiert bis (Unix-Sekunden); `None` = nicht pausiert.
    pub paused_until: Option<i64>,
    /// Verschiedene gesperrte Domains aus allen aktiven Listen und eigenen Sperren.
    pub total_domains: u64,
    pub lists: Vec<BlockList>,
    pub custom_blocked: u32,
    pub allowed: u32,
    pub last_update_at: Option<i64>,
    pub next_update_at: Option<i64>,
    /// Gerade läuft ein Neuladen.
    pub updating: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PauseInput {
    /// 0 = Sperren sofort fortsetzen.
    pub minutes: u32,
}

/// Eigene Sperre oder Ausnahme. Gilt für die Domain **und alle Subdomains**.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainEntry {
    pub domain: String,
    pub comment: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DomainInput {
    pub domain: String,
    pub comment: String,
}

/// Antwort auf „Wird diese Domain gesperrt?“
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainCheck {
    pub domain: String,
    pub blocked: bool,
    /// Steht (auch über eine Elterndomain) in den Ausnahmen.
    pub allowed: bool,
    /// Treffer, z. B. `Liste „StevenBlack Unified“: ads.example.com`, `Eigene Sperre: example.com`,
    /// `Ausnahme: example.com`.
    pub matches: Vec<String>,
}

// ------------------------------------------------------------------ DNS: Abfrageprotokoll

/// Wie die Anfrage hereinkam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Udp,
    Tcp,
    /// DNS über HTTPS (`/dns-query`)
    Https,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Udp => "udp",
            Protocol::Tcp => "tcp",
            Protocol::Https => "https",
        }
    }
}

/// Woher die Antwort kam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ResponseKind {
    /// Aus einer eigenen Zone.
    Authoritative,
    /// Von einem vorgelagerten Server (auch bedingte Weiterleitung).
    #[default]
    Forwarded,
    /// Aus dem Cache (auch abgelaufen ausgeliefert).
    Cached,
    /// Gesperrt (Liste oder eigene Sperre).
    Blocked,
    /// Ohne Weiterleitung selbst beantwortet (private PTR, IPv6 aus, `localhost` …).
    Local,
    /// Verworfen (Rate-Limit) oder abgelehnt.
    Dropped,
    /// Kein vorgelagerter Server hat geantwortet (SERVFAIL).
    Failed,
}

impl ResponseKind {
    pub const ALL: [ResponseKind; 7] = [
        ResponseKind::Authoritative,
        ResponseKind::Forwarded,
        ResponseKind::Cached,
        ResponseKind::Blocked,
        ResponseKind::Local,
        ResponseKind::Dropped,
        ResponseKind::Failed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ResponseKind::Authoritative => "authoritative",
            ResponseKind::Forwarded => "forwarded",
            ResponseKind::Cached => "cached",
            ResponseKind::Blocked => "blocked",
            ResponseKind::Local => "local",
            ResponseKind::Dropped => "dropped",
            ResponseKind::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// Eine beantwortete Anfrage. Die Engine erzeugt sie, der Server speichert sie.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryLogEntry {
    /// 0, solange noch nicht gespeichert.
    pub id: i64,
    /// Unix-Millisekunden.
    pub at_ms: i64,
    /// IP-Adresse des Clients.
    pub client: String,
    pub protocol: Protocol,
    /// Gefragter Name, klein, ohne Punkt am Ende.
    pub qname: String,
    /// `A`, `AAAA`, `HTTPS`, `TYPE65534` …
    pub qtype: String,
    /// `NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED` …
    pub rcode: String,
    pub kind: ResponseKind,
    /// Kurzfassung der Antwort, z. B. `93.184.215.14, 93.184.215.15` oder `CNAME a.b → 1.2.3.4`.
    pub answer: String,
    pub duration_ms: u32,
    /// Vorgelagerter Server, der geantwortet hat ([`Upstream::label`]); sonst leer.
    pub upstream: String,
}

/// Filter für `GET /logs` (Query-Parameter, alle optional).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct QueryLogFilter {
    /// Ab 1.
    pub page: u32,
    /// 10–500
    pub per_page: u32,
    /// Genau diese Client-IP.
    pub client: String,
    /// Teil des Namens.
    pub qname: String,
    /// Genau dieser Typ (`A`, `AAAA` …).
    pub qtype: String,
    pub kind: Option<ResponseKind>,
    /// Genau dieser Antwortcode.
    pub rcode: String,
    /// Ab / bis (Unix-Sekunden).
    pub from: Option<i64>,
    pub to: Option<i64>,
}

impl Default for QueryLogFilter {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: 50,
            client: String::new(),
            qname: String::new(),
            qtype: String::new(),
            kind: None,
            rcode: String::new(),
            from: None,
            to: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryLogPage {
    /// Neueste zuerst.
    pub entries: Vec<QueryLogEntry>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

// ------------------------------------------------------------------ DNS: Dashboard

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum StatsRange {
    /// Letzte Stunde, Punkte je Minute.
    Hour,
    /// Letzte 24 Stunden, Punkte je Stunde.
    #[default]
    Day,
    /// Letzte 7 Tage, Punkte je 6 Stunden.
    Week,
    /// Letzte 30 Tage, Punkte je Tag.
    Month,
}

impl StatsRange {
    pub const ALL: [StatsRange; 4] = [
        StatsRange::Hour,
        StatsRange::Day,
        StatsRange::Week,
        StatsRange::Month,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            StatsRange::Hour => "hour",
            StatsRange::Day => "day",
            StatsRange::Week => "week",
            StatsRange::Month => "month",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }

    /// (Länge des Zeitraums, Länge eines Punktes) in Sekunden.
    pub fn span_and_bucket(self) -> (i64, i64) {
        match self {
            StatsRange::Hour => (3600, 60),
            StatsRange::Day => (86_400, 3600),
            StatsRange::Week => (7 * 86_400, 6 * 3600),
            StatsRange::Month => (30 * 86_400, 86_400),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct StatsTotals {
    pub queries: u64,
    pub no_error: u64,
    pub nx_domain: u64,
    pub server_failure: u64,
    pub refused: u64,
    pub authoritative: u64,
    pub forwarded: u64,
    pub cached: u64,
    pub blocked: u64,
    pub local: u64,
    pub dropped: u64,
    /// Kein vorgelagerter Server hat geantwortet ([`ResponseKind::Failed`]).
    pub failed: u64,
    /// Verschiedene Clients.
    pub clients: u64,
    /// Mittlere Antwortzeit (Millisekunden).
    pub avg_duration_ms: f64,
}

/// Ein Punkt im Verlaufsdiagramm.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct StatsPoint {
    /// Beginn des Abschnitts (Unix-Sekunden).
    pub at: i64,
    pub total: u64,
    pub blocked: u64,
    pub cached: u64,
    pub forwarded: u64,
    pub authoritative: u64,
    /// NXDOMAIN + SERVFAIL + verworfen.
    pub failed: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopEntry {
    pub name: String,
    pub hits: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dashboard {
    pub range: StatsRange,
    pub totals: StatsTotals,
    /// Lückenlos vom Beginn des Zeitraums bis jetzt (leere Abschnitte mit 0).
    pub series: Vec<StatsPoint>,
    /// Je höchstens 10.
    pub top_clients: Vec<TopEntry>,
    pub top_domains: Vec<TopEntry>,
    pub top_blocked: Vec<TopEntry>,
    pub query_types: Vec<TopEntry>,
    pub server: ServerStatus,
}

/// Zustand eines vorgelagerten Servers seit dem Start.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct UpstreamHealth {
    /// [`Upstream::label`]
    pub upstream: String,
    pub name: String,
    pub ok: u64,
    pub failed: u64,
    /// Mittlere Antwortzeit der letzten Anfragen (Millisekunden).
    pub avg_ms: f64,
    pub last_error: Option<String>,
    pub last_error_at: Option<i64>,
}

/// Laufender Zustand des Servers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ServerStatus {
    pub version: String,
    pub started_at: i64,
    pub uptime_secs: u64,
    /// Adressen, auf denen DNS läuft (`0.0.0.0:53/udp`, `0.0.0.0:53/tcp`).
    pub dns_listen: Vec<String>,
    /// Adressen, die nicht geöffnet werden konnten, mit Grund (z. B. Port 53 belegt).
    pub listen_errors: Vec<String>,
    pub doh_enabled: bool,
    /// `/dns-query`
    pub doh_path: String,
    /// Anfragen seit dem Start (auch ohne Protokoll).
    pub queries_since_start: u64,
    /// Anfragen je Sekunde, Mittel der letzten Minute.
    pub queries_per_second: f64,
    pub cache_entries: u64,
    pub zones: u32,
    pub blocked_domains: u64,
    pub blocking_enabled: bool,
    pub blocking_paused_until: Option<i64>,
    pub upstreams: Vec<UpstreamHealth>,
}

// ------------------------------------------------------------------ MCP

/// Zustand des MCP-Servers (`/mcp`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct McpStatus {
    /// Es gibt ein Token (aus der Datenbank oder `NRZDNS_MCP_TOKEN`), `/mcp` nimmt Anfragen an.
    pub enabled: bool,
    /// Das Token kommt aus der Umgebung (`NRZDNS_MCP_TOKEN`) und lässt sich hier nicht ändern.
    pub from_env: bool,
    /// Anfang und Ende des Tokens (`nrzdns_mcp_Ab3d…x9Z1`).
    pub token_hint: Option<String>,
    pub created_at: Option<i64>,
    /// Werkzeuge, die etwas ändern (Sperren, Pause, Listen, Regeln, Cache), sind erlaubt.
    pub allow_changes: bool,
    /// Zuletzt benutzt (Unix-Sekunden, seit dem Start des Servers).
    pub last_used_at: Option<i64>,
    /// `/mcp`
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct McpSettingsInput {
    pub allow_changes: bool,
}

/// Neues Token – nur in dieser Antwort im Klartext.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToken {
    pub token: String,
    pub status: McpStatus,
}

// ------------------------------------------------------------------ DNS: Cache

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheEntry {
    pub name: String,
    pub qtype: String,
    pub rcode: String,
    /// Verbleibende TTL in Sekunden (0 bei abgelaufenen, noch ausgelieferten Einträgen).
    pub ttl: u32,
    pub stale: bool,
    /// Antworten in Zonendatei-Schreibweise (`A 93.184.215.14`).
    pub answers: Vec<String>,
    pub hits: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheList {
    pub entries: Vec<CacheEntry>,
    /// Alle Einträge im Cache (nicht nur die gelieferten).
    pub total: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheFlushResult {
    pub removed: u64,
}

// ------------------------------------------------------------------ DNS: Client

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ResolveInput {
    pub name: String,
    /// `A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME`, `SOA`, `PTR`, `SRV`, `CAA`, `HTTPS`, `ANY` …;
    /// leer = `A`. Bei `PTR` darf `name` eine IP-Adresse sein.
    pub qtype: String,
    /// Leer = dieser Server (mit Zonen, Sperren und Cache, ohne Protokolleintrag);
    /// sonst Adresse eines anderen Servers wie bei [`Upstream::address`].
    pub server: String,
    pub protocol: UpstreamProtocol,
}

/// Ein Eintrag einer Antwort.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordView {
    pub name: String,
    pub qtype: String,
    pub ttl: u32,
    /// Daten in Zonendatei-Schreibweise.
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveResult {
    /// „Dieser Server“ oder [`Upstream::label`].
    pub server: String,
    pub rcode: String,
    /// Gesetzte Bits: `qr`, `aa`, `tc`, `rd`, `ra`, `ad`, `cd`.
    pub flags: Vec<String>,
    pub answers: Vec<RecordView>,
    pub authority: Vec<RecordView>,
    pub additional: Vec<RecordView>,
    pub duration_ms: u32,
    /// Nur bei „dieser Server“: woher die Antwort kam.
    pub kind: Option<ResponseKind>,
}

// ------------------------------------------------------------------ Hilfen

/// Domain prüfen und vereinheitlichen: klein, ohne Punkt am Ende, ohne `*.` vorne,
/// Labels 1–63 Zeichen aus `a-z 0-9 - _`, gesamt höchstens 253. IDN (Umlaute) bitte vorher
/// als Punycode (`xn--…`). `None` = ungültig.
pub fn normalize_domain(input: &str) -> Option<String> {
    let mut d = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = d.strip_prefix("*.") {
        d = rest.to_string();
    }
    if d.is_empty() || d.len() > 253 {
        return None;
    }
    let ok = d.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
            && !label.starts_with('-')
            && !label.ends_with('-')
    });
    ok.then_some(d)
}

// ------------------------------------------------------------------ Reverse Proxy

/// Ein Name, den der eingebaute Reverse Proxy (HTTP) an ein Ziel weiterreicht, z. B.
/// `music.nrz.ch` → `http://100.78.107.162:8350`. nrzDNS beantwortet den Namen selbst mit
/// der Adresse des Proxys (A bzw. AAAA), damit Geräte, die nrzDNS fragen, beim Proxy landen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyHost {
    pub id: i64,
    /// Name wie `music.nrz.ch` (klein, ohne Punkt am Ende).
    pub host: String,
    /// Ziel wie `http://100.78.107.162:8350` (nur HTTP), optional mit Pfad.
    pub target: String,
    pub enabled: bool,
    pub comment: String,
    /// Adresse, mit der nrzDNS den Namen beantwortet (leer = keine DNS-Antwort möglich).
    pub dns_address: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProxyHostInput {
    pub host: String,
    /// `http://adresse:port[/pfad]`; ohne `http://` wird es ergänzt.
    pub target: String,
    pub enabled: bool,
    pub comment: String,
}

impl Default for ProxyHostInput {
    fn default() -> Self {
        Self {
            host: String::new(),
            target: String::new(),
            enabled: true,
            comment: String::new(),
        }
    }
}

/// Einstellungen des Reverse Proxys und der Sperrseite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProxySettings {
    /// IP-Adressen dieses Geräts, durch Kommas getrennt (z. B. `192.168.0.198, 100.78.107.162`)
    /// – damit beantwortet nrzNetwork die Namen der Proxy-Einträge und gesperrte Domains im
    /// Modus Sperrseite, je Client die passende. Leer = automatisch erkannte Adressen, sonst
    /// die IP aus dem Ziel.
    pub address: String,
    /// Auf der Sperrseite darf jeder eine Domain für eine Weile freischalten.
    pub allow_unlock: bool,
    /// Wählbare Zeiträume in Minuten (1–1440).
    pub unlock_minutes: Vec<u32>,
    /// Auf der Sperrseite darf jeder eine dauerhafte Ausnahme beantragen (der Admin entscheidet).
    pub allow_requests: bool,
    /// Umbrel: Port 80 des Geräts an den Proxy geben (Namen ohne Port); alles Unbekannte geht
    /// weiter an umbrelOS.
    pub port80: bool,
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            address: String::new(),
            allow_unlock: true,
            unlock_minutes: vec![15, 60, 240],
            allow_requests: true,
            port80: true,
        }
    }
}

/// Zustand der Port-80-Weiterleitung auf dem Gerät (Umbrel-Wächter).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct GatewayStatus {
    /// Port 80 zeigt gerade auf den Proxy.
    pub active: bool,
    pub message: String,
    /// Letzte Meldung des Wächters (Unix-Sekunden).
    pub updated_at: i64,
}

/// Für eine Weile freigeschaltete Domain (von der Sperrseite).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TempUnlock {
    pub domain: String,
    /// Gilt bis (Unix-Sekunden).
    pub until: i64,
    /// Wer freigeschaltet hat (IP-Adresse).
    pub client: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RequestStatus {
    #[default]
    Pending,
    Approved,
    Rejected,
}

/// Antrag auf eine dauerhafte Ausnahme (von der Sperrseite).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowRequest {
    pub id: i64,
    pub domain: String,
    pub client: String,
    pub reason: String,
    pub status: RequestStatus,
    pub created_at: i64,
    pub decided_at: Option<i64>,
    pub decided_by: String,
}

/// `GET /proxy`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ProxyStatus {
    /// Adressen, auf denen der Proxy HTTP annimmt (`NRZDNS_PROXY_LISTEN`), z. B. `0.0.0.0:80`.
    pub listen: Vec<String>,
    /// Port, den Browser nach dem Namen brauchen (80 = keiner, sonst `http://name:port`).
    pub port: u16,
    /// Adressen, die nicht geöffnet werden konnten, mit Grund.
    pub listen_errors: Vec<String>,
    pub settings: ProxySettings,
    pub hosts: Vec<ProxyHost>,
    /// Adressen dieses Geräts, mit denen nrzNetwork antwortet (eingetragen oder erkannt).
    pub device_addresses: Vec<String>,
    /// Port-80-Weiterleitung (nur auf Umbrel, sonst `None`).
    pub gateway: Option<GatewayStatus>,
    /// Namen mit HTTPS-Zertifikat (z. B. `*.zweers.ch`), leer = kein HTTPS.
    pub https_names: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains() {
        assert_eq!(
            normalize_domain(" Ads.Example.COM. ").as_deref(),
            Some("ads.example.com")
        );
        assert_eq!(
            normalize_domain("*.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_domain("_dmarc.example.com").as_deref(),
            Some("_dmarc.example.com")
        );
        assert_eq!(normalize_domain("localhost").as_deref(), Some("localhost"));
        assert!(normalize_domain("").is_none());
        assert!(normalize_domain("a..b").is_none());
        assert!(normalize_domain("-a.com").is_none());
        assert!(normalize_domain("exa mple.com").is_none());
    }

    #[test]
    fn record_json() {
        let r = RecordData::MX {
            preference: 10,
            exchange: "mail.example.com".into(),
        };
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(
            j,
            r#"{"type":"MX","preference":10,"exchange":"mail.example.com"}"#
        );
        assert_eq!(serde_json::from_str::<RecordData>(&j).unwrap(), r);
        assert_eq!(record_fqdn("@", "example.com"), "example.com");
        assert_eq!(record_fqdn("WWW", "example.com"), "www.example.com");
        assert_eq!(
            record_fqdn("host.other.org.", "example.com"),
            "host.other.org"
        );
    }

    #[test]
    fn settings_roundtrip() {
        let s = DnsSettings::default();
        let j = serde_json::to_string(&s).unwrap();
        assert!(j.contains("\"blockMode\":\"blockPage\""));
        assert_eq!(serde_json::from_str::<DnsSettings>(&j).unwrap(), s);
        // Fehlende Felder bekommen Vorgaben (ältere gespeicherte Einstellungen)
        let partial: DnsSettings = serde_json::from_str(r#"{"cacheEnabled":false}"#).unwrap();
        assert!(!partial.cache_enabled);
        assert_eq!(partial.default_ttl, 3600);
    }
}
