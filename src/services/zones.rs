//! Zonen und ihre Einträge.
//!
//! * Primärzonen bekommen beim Anlegen ein SOA (`primary_ns` = Servername aus den
//!   DNS-Einstellungen, `responsible` = `hostmaster.<zone>`) und einen NS-Eintrag bei `@`.
//! * Jede Änderung an der Zone oder ihren Einträgen erhöht die Seriennummer im Stil
//!   `JJJJMMTTnn` ([`next_serial`]).
//! * Namen der Einträge sind relativ zur Zone (`@`, `www`, `*`, `*.dev`); Ziele (CNAME, MX, NS,
//!   SRV, PTR) voll qualifiziert ohne Punkt am Ende.
//! * Kein CNAME bei `@` und keiner neben anderen Einträgen desselben Namens; doppelte
//!   Einträge sind ein Konflikt.
//!
//! Die Engine bekommt nach jeder Änderung den ganzen Bestand (siehe `services::sync`).

use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::services::settings;
use nrzdns_engine::zonefile;
use nrzdns_types::{
    normalize_domain, record_fqdn, DnsSettings, RecordData, RecordInput, RecordType, Soa,
    UpdateZoneInput, Zone, ZoneDetail, ZoneImportInput, ZoneImportResult, ZoneInput, ZoneKind,
    ZoneRecord,
};
use sqlx::{Sqlite, SqlitePool, Transaction};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Höchstlänge von Kommentaren.
pub const MAX_COMMENT: usize = 200;
/// Höchstlänge eines TXT-Eintrags (wird in Zeichenketten zu 255 Byte geteilt).
pub const MAX_TXT: usize = 4000;
/// Grösste TTL laut RFC 2181.
const MAX_TTL: u32 = i32::MAX as u32;

/// `SELECT … FROM zones z <rest>` mit Anzahl der Einträge.
macro_rules! select_zones {
    ($rest:literal) => {
        concat!(
            "SELECT z.id, z.name, z.kind, z.disabled, z.soa_primary_ns, z.soa_responsible, \
             z.soa_serial, z.soa_refresh, z.soa_retry, z.soa_expire, z.soa_minimum, z.forwarders, \
             z.comment, z.created_at, z.updated_at, \
             (SELECT count(*) FROM zone_records r WHERE r.zone_id = z.id) AS record_count \
             FROM zones z ",
            $rest
        )
    };
}

macro_rules! select_records {
    ($rest:literal) => {
        concat!(
            "SELECT id, zone_id, name, data, ttl, disabled, comment, updated_at FROM zone_records ",
            $rest
        )
    };
}

#[derive(sqlx::FromRow)]
struct ZoneRow {
    id: i64,
    name: String,
    kind: String,
    disabled: bool,
    soa_primary_ns: String,
    soa_responsible: String,
    soa_serial: i64,
    soa_refresh: i64,
    soa_retry: i64,
    soa_expire: i64,
    soa_minimum: i64,
    forwarders: String,
    comment: String,
    created_at: i64,
    updated_at: i64,
    record_count: i64,
}

impl ZoneRow {
    fn into_zone(self) -> Zone {
        let u = |v: i64| u32::try_from(v).unwrap_or_default();
        Zone {
            id: self.id,
            name: self.name,
            kind: parse_kind(&self.kind),
            disabled: self.disabled,
            soa: Soa {
                primary_ns: self.soa_primary_ns,
                responsible: self.soa_responsible,
                serial: u(self.soa_serial),
                refresh: u(self.soa_refresh),
                retry: u(self.soa_retry),
                expire: u(self.soa_expire),
                minimum: u(self.soa_minimum),
            },
            forwarders: serde_json::from_str(&self.forwarders).unwrap_or_default(),
            comment: self.comment,
            record_count: u(self.record_count),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct RecordRow {
    id: i64,
    zone_id: i64,
    name: String,
    data: String,
    ttl: i64,
    disabled: bool,
    comment: String,
    updated_at: i64,
}

impl RecordRow {
    /// `None`, wenn die gespeicherten Daten nicht mehr lesbar sind (dann fehlt der Eintrag).
    fn into_record(self) -> Option<ZoneRecord> {
        let data = match serde_json::from_str::<RecordData>(&self.data) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(id = self.id, "Eintrag nicht lesbar: {e}");
                return None;
            }
        };
        Some(ZoneRecord {
            id: self.id,
            zone_id: self.zone_id,
            name: self.name,
            ttl: u32::try_from(self.ttl).unwrap_or_default(),
            data,
            disabled: self.disabled,
            comment: self.comment,
            updated_at: self.updated_at,
        })
    }
}

fn parse_kind(s: &str) -> ZoneKind {
    if s == "forwarder" {
        ZoneKind::Forwarder
    } else {
        ZoneKind::Primary
    }
}

fn kind_str(kind: ZoneKind) -> &'static str {
    match kind {
        ZoneKind::Primary => "primary",
        ZoneKind::Forwarder => "forwarder",
    }
}

// ------------------------------------------------------------------ Lesen

pub async fn list(pool: &SqlitePool) -> AppResult<Vec<Zone>> {
    let rows: Vec<ZoneRow> = sqlx::query_as(select_zones!("ORDER BY z.name"))
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(ZoneRow::into_zone).collect())
}

pub async fn get(pool: &SqlitePool, id: i64) -> AppResult<Zone> {
    let row: Option<ZoneRow> = sqlx::query_as(select_zones!("WHERE z.id = ?"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    row.map(ZoneRow::into_zone).ok_or(AppError::NotFound)
}

/// Zone mit allen Einträgen (`@` zuerst, dann nach Name und Typ).
pub async fn detail(pool: &SqlitePool, id: i64) -> AppResult<ZoneDetail> {
    let zone = get(pool, id).await?;
    let rows: Vec<RecordRow> = sqlx::query_as(select_records!(
        "WHERE zone_id = ? ORDER BY name <> '@', name, type, id"
    ))
    .bind(id)
    .fetch_all(pool)
    .await?;
    Ok(ZoneDetail {
        zone,
        records: rows
            .into_iter()
            .filter_map(RecordRow::into_record)
            .collect(),
    })
}

/// Alle Zonen mit allen Einträgen – so bekommt sie die Engine.
pub async fn all_details(pool: &SqlitePool) -> AppResult<Vec<ZoneDetail>> {
    let zones = list(pool).await?;
    let rows: Vec<RecordRow> = sqlx::query_as(select_records!(
        "ORDER BY zone_id, name <> '@', name, type, id"
    ))
    .fetch_all(pool)
    .await?;
    let mut by_zone: HashMap<i64, Vec<ZoneRecord>> = HashMap::new();
    for record in rows.into_iter().filter_map(RecordRow::into_record) {
        by_zone.entry(record.zone_id).or_default().push(record);
    }
    Ok(zones
        .into_iter()
        .map(|zone| ZoneDetail {
            records: by_zone.remove(&zone.id).unwrap_or_default(),
            zone,
        })
        .collect())
}

async fn record(pool: &SqlitePool, zone_id: i64, id: i64) -> AppResult<ZoneRecord> {
    let row: Option<RecordRow> = sqlx::query_as(select_records!("WHERE id = ? AND zone_id = ?"))
        .bind(id)
        .bind(zone_id)
        .fetch_optional(pool)
        .await?;
    row.and_then(RecordRow::into_record)
        .ok_or(AppError::NotFound)
}

/// Zonendatei (BIND-Format) und Dateiname `<zone>.zone`.
pub async fn export(pool: &SqlitePool, id: i64) -> AppResult<(String, String)> {
    let detail = detail(pool, id).await?;
    let file = format!("{}.zone", detail.zone.name);
    Ok((file, zonefile::export(&detail)))
}

// ------------------------------------------------------------------ Zonen ändern

/// Neue Zone. Primärzonen bekommen SOA und NS, Weiterleitungszonen brauchen mindestens
/// einen vorgelagerten Server.
pub async fn create(pool: &SqlitePool, dns: &DnsSettings, input: &ZoneInput) -> AppResult<Zone> {
    let name = zone_name(&input.name)?;
    let comment = validate_comment(&input.comment)?;
    let forwarders = match input.kind {
        ZoneKind::Primary => Vec::new(),
        ZoneKind::Forwarder => forwarder_list(&input.forwarders)?,
    };
    let soa = default_soa(dns, &name);
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let id = insert_zone(&mut tx, &name, input.kind, &soa, &forwarders, &comment).await?;
    if input.kind == ZoneKind::Primary {
        insert_default_ns(&mut tx, id, dns).await?;
    }
    tx.commit().await?;
    get(pool, id).await
}

/// Nur gesetzte Felder; jede Änderung erhöht die Seriennummer (ein ausdrücklich höher
/// gesetzter Wert gilt so, wie er ist).
pub async fn update(pool: &SqlitePool, id: i64, input: &UpdateZoneInput) -> AppResult<Zone> {
    let zone = get(pool, id).await?;
    let comment = input
        .comment
        .as_deref()
        .map(validate_comment)
        .transpose()?
        .unwrap_or(zone.comment.clone());
    let forwarders = match (zone.kind, &input.forwarders) {
        (ZoneKind::Forwarder, Some(list)) => forwarder_list(list)?,
        _ => zone.forwarders.clone(),
    };
    let mut soa = match &input.soa {
        Some(s) => validate_soa(s)?,
        None => zone.soa.clone(),
    };
    soa.serial = if input
        .soa
        .as_ref()
        .is_some_and(|s| s.serial > zone.soa.serial)
    {
        soa.serial
    } else {
        next_serial(zone.soa.serial, today())
    };
    let disabled = input.disabled.unwrap_or(zone.disabled);
    sqlx::query(
        "UPDATE zones SET disabled = ?, soa_primary_ns = ?, soa_responsible = ?, soa_serial = ?,
            soa_refresh = ?, soa_retry = ?, soa_expire = ?, soa_minimum = ?, forwarders = ?,
            comment = ?, updated_at = ?
         WHERE id = ?",
    )
    .bind(disabled)
    .bind(&soa.primary_ns)
    .bind(&soa.responsible)
    .bind(soa.serial)
    .bind(soa.refresh)
    .bind(soa.retry)
    .bind(soa.expire)
    .bind(soa.minimum)
    .bind(json(&forwarders))
    .bind(&comment)
    .bind(now())
    .bind(id)
    .execute(pool)
    .await?;
    get(pool, id).await
}

/// Zone mit allen Einträgen löschen.
pub async fn delete(pool: &SqlitePool, id: i64) -> AppResult<()> {
    let done = sqlx::query("DELETE FROM zones WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

// ------------------------------------------------------------------ Einträge ändern

pub async fn add_record(
    pool: &SqlitePool,
    dns: &DnsSettings,
    zone_id: i64,
    input: &RecordInput,
) -> AppResult<ZoneRecord> {
    let zone = get(pool, zone_id).await?;
    let rec = validate_record(&zone.name, dns, input)?;
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    check_cname_rules(&mut tx, zone_id, &rec, None).await?;
    let id = insert_record(&mut tx, zone_id, &rec)
        .await
        .map_err(|e| AppError::unique(e, DUPLICATE))?;
    bump_serial(&mut tx, zone_id).await?;
    tx.commit().await?;
    record(pool, zone_id, id).await
}

pub async fn update_record(
    pool: &SqlitePool,
    dns: &DnsSettings,
    zone_id: i64,
    id: i64,
    input: &RecordInput,
) -> AppResult<ZoneRecord> {
    let zone = get(pool, zone_id).await?;
    record(pool, zone_id, id).await?;
    let rec = validate_record(&zone.name, dns, input)?;
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    check_cname_rules(&mut tx, zone_id, &rec, Some(id)).await?;
    sqlx::query(
        "UPDATE zone_records SET name = ?, type = ?, data = ?, ttl = ?, disabled = ?, comment = ?,
            updated_at = ?
         WHERE id = ? AND zone_id = ?",
    )
    .bind(&rec.name)
    .bind(rec.data.record_type().as_str())
    .bind(json(&rec.data))
    .bind(rec.ttl)
    .bind(rec.disabled)
    .bind(&rec.comment)
    .bind(now())
    .bind(id)
    .bind(zone_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::unique(e, DUPLICATE))?;
    bump_serial(&mut tx, zone_id).await?;
    tx.commit().await?;
    record(pool, zone_id, id).await
}

pub async fn delete_record(pool: &SqlitePool, zone_id: i64, id: i64) -> AppResult<()> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let done = sqlx::query("DELETE FROM zone_records WHERE id = ? AND zone_id = ?")
        .bind(id)
        .bind(zone_id)
        .execute(&mut *tx)
        .await?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    bump_serial(&mut tx, zone_id).await?;
    tx.commit().await?;
    Ok(())
}

// ------------------------------------------------------------------ Import

/// Zonendatei übernehmen. Gibt es die Zone schon, ersetzt `replace` ihre Einträge (sonst
/// Konflikt). Ungültige Einträge landen mit Grund in `skipped`.
pub async fn import(
    pool: &SqlitePool,
    dns: &DnsSettings,
    input: &ZoneImportInput,
) -> AppResult<ZoneImportResult> {
    if input.text.trim().is_empty() {
        return Err(AppError::bad("Die Zonendatei ist leer."));
    }
    let given = if input.name.trim().is_empty() {
        String::new()
    } else {
        zone_name(&input.name)?
    };
    let parsed = zonefile::parse(&input.text, &given, dns.default_ttl)?;
    let name = normalize_domain(&parsed.origin).ok_or_else(|| {
        AppError::bad("Zonenname fehlt – weder angegeben noch in der Datei ($ORIGIN oder SOA).")
    })?;
    let file_soa = parsed.soa.as_ref().map(|s| {
        let mut soa = validate_soa(s).unwrap_or_else(|_| default_soa(dns, &name));
        soa.serial = s.serial;
        soa
    });

    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let existing: Option<(i64, i64)> =
        sqlx::query_as("SELECT id, soa_serial FROM zones WHERE name = ?")
            .bind(&name)
            .fetch_optional(&mut *tx)
            .await?;
    let zone_id = match existing {
        Some(_) if !input.replace => return Err(AppError::Conflict(ZONE_EXISTS.into())),
        Some((id, serial)) => {
            sqlx::query("DELETE FROM zone_records WHERE zone_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            let next = next_serial(u32::try_from(serial).unwrap_or_default(), today());
            if let Some(soa) = &file_soa {
                sqlx::query(
                    "UPDATE zones SET soa_primary_ns = ?, soa_responsible = ?, soa_refresh = ?,
                        soa_retry = ?, soa_expire = ?, soa_minimum = ? WHERE id = ?",
                )
                .bind(&soa.primary_ns)
                .bind(&soa.responsible)
                .bind(soa.refresh)
                .bind(soa.retry)
                .bind(soa.expire)
                .bind(soa.minimum)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            }
            let serial = file_soa.as_ref().map_or(next, |s| s.serial.max(next));
            sqlx::query("UPDATE zones SET soa_serial = ?, updated_at = ? WHERE id = ?")
                .bind(serial)
                .bind(now())
                .bind(id)
                .execute(&mut *tx)
                .await?;
            id
        }
        None => {
            let soa = file_soa.clone().unwrap_or_else(|| default_soa(dns, &name));
            insert_zone(&mut tx, &name, ZoneKind::Primary, &soa, &[], "").await?
        }
    };

    let mut skipped = parsed.skipped.clone();
    let mut types_by_name: HashMap<String, Vec<RecordType>> = HashMap::new();
    let mut imported = 0u32;
    for input in &parsed.records {
        let label = format!("{} {}", input.name, input.data.record_type().as_str());
        let rec = match validate_record(&name, dns, input) {
            Ok(r) => r,
            Err(e) => {
                skipped.push(format!("{label}: {}", e.public_message()));
                continue;
            }
        };
        let types = types_by_name.entry(rec.name.clone()).or_default();
        let is_cname = rec.data.record_type() == RecordType::CNAME;
        if !types.is_empty() && (is_cname || types.contains(&RecordType::CNAME)) {
            skipped.push(format!("{label}: {CNAME_ALONE}"));
            continue;
        }
        let done = sqlx::query(
            "INSERT INTO zone_records (zone_id, name, type, data, ttl, disabled, comment,
                created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
        )
        .bind(zone_id)
        .bind(&rec.name)
        .bind(rec.data.record_type().as_str())
        .bind(json(&rec.data))
        .bind(rec.ttl)
        .bind(rec.disabled)
        .bind(&rec.comment)
        .bind(now())
        .bind(now())
        .execute(&mut *tx)
        .await?;
        if done.rows_affected() == 0 {
            skipped.push(format!("{label}: {DUPLICATE}"));
            continue;
        }
        types.push(rec.data.record_type());
        imported += 1;
    }
    let has_apex_ns = types_by_name
        .get("@")
        .is_some_and(|t| t.contains(&RecordType::NS));
    if !has_apex_ns {
        insert_default_ns(&mut tx, zone_id, dns).await?;
    }
    tx.commit().await?;
    Ok(ZoneImportResult {
        zone: get(pool, zone_id).await?,
        imported,
        skipped,
    })
}

// ------------------------------------------------------------------ Prüfen

const DUPLICATE: &str = "Diesen Eintrag gibt es schon.";
const ZONE_EXISTS: &str = "Diese Zone gibt es schon.";
const CNAME_ALONE: &str =
    "Neben einem CNAME darf es unter demselben Namen keine weiteren Einträge geben.";

/// Zonenname prüfen und vereinheitlichen.
pub fn zone_name(input: &str) -> AppResult<String> {
    normalize_domain(input).ok_or_else(|| {
        AppError::bad("Zonenname: bitte eine gültige Domain angeben, z. B. home.arpa.")
    })
}

fn validate_comment(input: &str) -> AppResult<String> {
    let c = input.trim();
    if c.chars().count() > MAX_COMMENT || c.chars().any(char::is_control) {
        return Err(AppError::bad(format!(
            "Kommentar: höchstens {MAX_COMMENT} Zeichen, ohne Steuerzeichen."
        )));
    }
    Ok(c.to_string())
}

fn forwarder_list(list: &[nrzdns_types::Upstream]) -> AppResult<Vec<nrzdns_types::Upstream>> {
    let list = settings::validate_upstreams(list)?;
    if list.is_empty() {
        return Err(AppError::bad(
            "Eine Weiterleitungszone braucht mindestens einen Server.",
        ));
    }
    Ok(list)
}

/// SOA einer neuen Primärzone.
pub fn default_soa(dns: &DnsSettings, zone: &str) -> Soa {
    Soa {
        primary_ns: dns.server_domain.clone(),
        responsible: format!("hostmaster.{zone}"),
        serial: next_serial(0, today()),
        ..Soa::default()
    }
}

/// Namen prüfen (`hostmaster@example.com` wird zu `hostmaster.example.com`), Zeiten in
/// sinnvolle Grenzen setzen. Die Seriennummer bleibt, wie sie ist.
fn validate_soa(s: &Soa) -> AppResult<Soa> {
    let primary_ns = normalize_domain(&s.primary_ns)
        .ok_or_else(|| AppError::bad("SOA: ungültiger primärer Nameserver."))?;
    let responsible = normalize_domain(&s.responsible.replacen('@', ".", 1))
        .ok_or_else(|| AppError::bad("SOA: ungültige verantwortliche Adresse."))?;
    Ok(Soa {
        primary_ns,
        responsible,
        serial: s.serial,
        refresh: s.refresh.clamp(60, 2_419_200),
        retry: s.retry.clamp(60, 2_419_200),
        expire: s.expire.clamp(3600, 31_536_000),
        minimum: s.minimum.min(86_400),
    })
}

/// Nächste Seriennummer im Stil `JJJJMMTTnn`: am selben Tag hochzählen, sonst `JJJJMMTT01`.
/// Ist die bisherige schon grösser (eigene Zählweise), einfach plus eins.
pub fn next_serial(current: u32, today: time::Date) -> u32 {
    let day = today.year() as u32 * 10_000
        + u32::from(u8::from(today.month())) * 100
        + u32::from(today.day());
    let base = day.saturating_mul(100);
    if current < base {
        base + 1
    } else {
        current.wrapping_add(1).max(1)
    }
}

fn today() -> time::Date {
    time::OffsetDateTime::now_utc().date()
}

/// Geprüfter Eintrag, bereit zum Speichern.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidRecord {
    pub name: String,
    pub ttl: u32,
    pub data: RecordData,
    pub disabled: bool,
    pub comment: String,
}

pub fn validate_record(
    zone: &str,
    dns: &DnsSettings,
    input: &RecordInput,
) -> AppResult<ValidRecord> {
    let name = relative_name(&input.name, zone)?;
    let data = validate_data(&input.data)?;
    if name == "@" && data.record_type() == RecordType::CNAME {
        return Err(AppError::bad(
            "Ein CNAME ist an der Zonenspitze (@) nicht erlaubt.",
        ));
    }
    let ttl = if input.ttl == 0 {
        dns.default_ttl
    } else {
        input.ttl
    }
    .clamp(1, MAX_TTL);
    Ok(ValidRecord {
        name,
        ttl,
        data,
        disabled: input.disabled,
        comment: validate_comment(&input.comment)?,
    })
}

/// Name relativ zur Zone: `""`/`@` → `@`; `www.example.com.` und `www.example.com` (in der
/// Zone `example.com`) → `www`; Platzhalter nur ganz links (`*`, `*.dev`).
pub fn relative_name(input: &str, zone: &str) -> AppResult<String> {
    let n = input.trim().to_ascii_lowercase();
    let n = n.strip_suffix('.').map(str::to_string).map_or_else(
        || Ok(n.clone()),
        |full| {
            if full == zone || full.ends_with(&format!(".{zone}")) {
                Ok(full)
            } else {
                Err(AppError::bad("Der Name liegt nicht in der Zone."))
            }
        },
    )?;
    if n.is_empty() || n == "@" || n == zone {
        return Ok("@".into());
    }
    let rel = n
        .strip_suffix(&format!(".{zone}"))
        .unwrap_or(&n)
        .to_string();
    let rest = match rel.as_str() {
        "*" => "",
        r => r.strip_prefix("*.").unwrap_or(r),
    };
    let labels_ok = rest.is_empty() || normalize_domain(rest).as_deref() == Some(rest);
    if !labels_ok || record_fqdn(&rel, zone).len() > 253 {
        return Err(AppError::bad(
            "Name: nur Buchstaben, Ziffern, Minus und Unterstrich, Platzhalter * nur ganz links.",
        ));
    }
    Ok(rel)
}

/// Daten eines Eintrags prüfen und vereinheitlichen (Adressen kanonisch, Namen klein ohne
/// Punkt am Ende).
pub fn validate_data(data: &RecordData) -> AppResult<RecordData> {
    let target = |name: &str, msg: &'static str| normalize_domain(name).ok_or(AppError::bad(msg));
    Ok(match data {
        RecordData::A { address } => RecordData::A {
            address: address
                .trim()
                .parse::<Ipv4Addr>()
                .map_err(|_| AppError::bad("A: ungültige IPv4-Adresse."))?
                .to_string(),
        },
        RecordData::AAAA { address } => RecordData::AAAA {
            address: address
                .trim()
                .parse::<Ipv6Addr>()
                .map_err(|_| AppError::bad("AAAA: ungültige IPv6-Adresse."))?
                .to_string(),
        },
        RecordData::CNAME { target: t } => RecordData::CNAME {
            target: target(t, "CNAME: ungültiges Ziel.")?,
        },
        RecordData::MX {
            preference,
            exchange,
        } => RecordData::MX {
            preference: *preference,
            exchange: target(exchange, "MX: ungültiger Mailserver.")?,
        },
        RecordData::TXT { text } => {
            if text.is_empty() {
                return Err(AppError::bad("TXT: Text fehlt."));
            }
            if text.len() > MAX_TXT {
                return Err(AppError::bad(format!("TXT: höchstens {MAX_TXT} Zeichen.")));
            }
            RecordData::TXT { text: text.clone() }
        }
        RecordData::NS { host } => RecordData::NS {
            host: target(host, "NS: ungültiger Nameserver.")?,
        },
        RecordData::SRV {
            priority,
            weight,
            port,
            target: t,
        } => RecordData::SRV {
            priority: *priority,
            weight: *weight,
            port: *port,
            target: target(t, "SRV: ungültiges Ziel.")?,
        },
        RecordData::PTR { target: t } => RecordData::PTR {
            target: target(t, "PTR: ungültiges Ziel.")?,
        },
        RecordData::CAA { flags, tag, value } => {
            let tag = tag.trim().to_ascii_lowercase();
            if tag.is_empty() || tag.len() > 15 || !tag.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return Err(AppError::bad(
                    "CAA: Tag aus 1–15 Buchstaben und Ziffern, z. B. issue, issuewild oder iodef.",
                ));
            }
            if value.trim().is_empty() {
                return Err(AppError::bad("CAA: Wert fehlt."));
            }
            RecordData::CAA {
                flags: *flags,
                tag,
                value: value.trim().to_string(),
            }
        }
    })
}

// ------------------------------------------------------------------ SQL-Hilfen

fn json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "null".into())
}

async fn insert_zone(
    tx: &mut Transaction<'_, Sqlite>,
    name: &str,
    kind: ZoneKind,
    soa: &Soa,
    forwarders: &[nrzdns_types::Upstream],
    comment: &str,
) -> AppResult<i64> {
    let ts = now();
    sqlx::query_scalar(
        "INSERT INTO zones (name, kind, soa_primary_ns, soa_responsible, soa_serial, soa_refresh,
            soa_retry, soa_expire, soa_minimum, forwarders, comment, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(name)
    .bind(kind_str(kind))
    .bind(&soa.primary_ns)
    .bind(&soa.responsible)
    .bind(soa.serial)
    .bind(soa.refresh)
    .bind(soa.retry)
    .bind(soa.expire)
    .bind(soa.minimum)
    .bind(json(&forwarders))
    .bind(comment)
    .bind(ts)
    .bind(ts)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| AppError::unique(e, ZONE_EXISTS))
}

async fn insert_record(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: i64,
    rec: &ValidRecord,
) -> Result<i64, sqlx::Error> {
    let ts = now();
    sqlx::query_scalar(
        "INSERT INTO zone_records (zone_id, name, type, data, ttl, disabled, comment, created_at,
            updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(zone_id)
    .bind(&rec.name)
    .bind(rec.data.record_type().as_str())
    .bind(json(&rec.data))
    .bind(rec.ttl)
    .bind(rec.disabled)
    .bind(&rec.comment)
    .bind(ts)
    .bind(ts)
    .fetch_one(&mut **tx)
    .await
}

/// NS-Eintrag bei `@` auf den Servernamen.
async fn insert_default_ns(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: i64,
    dns: &DnsSettings,
) -> AppResult<()> {
    let rec = ValidRecord {
        name: "@".into(),
        ttl: dns.default_ttl.clamp(1, MAX_TTL),
        data: RecordData::NS {
            host: dns.server_domain.clone(),
        },
        disabled: false,
        comment: String::new(),
    };
    insert_record(tx, zone_id, &rec).await?;
    Ok(())
}

/// Kein CNAME neben anderen Einträgen desselben Namens (auch kein zweiter CNAME).
async fn check_cname_rules(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: i64,
    rec: &ValidRecord,
    exclude: Option<i64>,
) -> AppResult<()> {
    let others: Vec<String> = sqlx::query_scalar(
        "SELECT type FROM zone_records WHERE zone_id = ? AND name = ? AND id <> ?",
    )
    .bind(zone_id)
    .bind(&rec.name)
    .bind(exclude.unwrap_or(0))
    .fetch_all(&mut **tx)
    .await?;
    let is_cname = rec.data.record_type() == RecordType::CNAME;
    if !others.is_empty() && (is_cname || others.iter().any(|t| t == "CNAME")) {
        return Err(AppError::Conflict(CNAME_ALONE.into()));
    }
    Ok(())
}

async fn bump_serial(tx: &mut Transaction<'_, Sqlite>, zone_id: i64) -> AppResult<()> {
    let current: i64 = sqlx::query_scalar("SELECT soa_serial FROM zones WHERE id = ?")
        .bind(zone_id)
        .fetch_one(&mut **tx)
        .await?;
    sqlx::query("UPDATE zones SET soa_serial = ?, updated_at = ? WHERE id = ?")
        .bind(next_serial(
            u32::try_from(current).unwrap_or_default(),
            today(),
        ))
        .bind(now())
        .bind(zone_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::date;

    #[test]
    fn serials() {
        let d = date!(2026 - 10 - 31);
        assert_eq!(next_serial(0, d), 2026103101);
        assert_eq!(next_serial(1, d), 2026103101);
        assert_eq!(next_serial(2026103101, d), 2026103102);
        assert_eq!(next_serial(2026103099, d), 2026103101);
        assert_eq!(next_serial(2026103005, d), 2026103101);
        // Eigene, grössere Zählweise läuft einfach weiter
        assert_eq!(next_serial(4_000_000_000, d), 4_000_000_001);
    }

    #[test]
    fn names() {
        let z = "example.com";
        assert_eq!(relative_name("", z).unwrap(), "@");
        assert_eq!(relative_name(" @ ", z).unwrap(), "@");
        assert_eq!(relative_name("WWW", z).unwrap(), "www");
        assert_eq!(relative_name("www.example.com.", z).unwrap(), "www");
        assert_eq!(relative_name("www.example.com", z).unwrap(), "www");
        assert_eq!(relative_name("example.com.", z).unwrap(), "@");
        assert_eq!(relative_name("*", z).unwrap(), "*");
        assert_eq!(relative_name("*.dev", z).unwrap(), "*.dev");
        assert_eq!(relative_name("_dmarc", z).unwrap(), "_dmarc");
        assert!(relative_name("a.*.b", z).is_err());
        assert!(relative_name("**", z).is_err());
        assert!(relative_name("mit leer", z).is_err());
        assert!(relative_name("www.other.org.", z).is_err());
        assert!(relative_name(&"a".repeat(64), z).is_err());
    }

    #[test]
    fn data() {
        let ok = |d: RecordData| validate_data(&d).unwrap();
        assert_eq!(
            ok(RecordData::AAAA {
                address: "2001:DB8:0::1".into()
            }),
            RecordData::AAAA {
                address: "2001:db8::1".into()
            }
        );
        assert_eq!(
            ok(RecordData::CNAME {
                target: "Host.Example.ORG.".into()
            }),
            RecordData::CNAME {
                target: "host.example.org".into()
            }
        );
        assert_eq!(
            ok(RecordData::CAA {
                flags: 0,
                tag: "ISSUE".into(),
                value: " letsencrypt.org ".into()
            }),
            RecordData::CAA {
                flags: 0,
                tag: "issue".into(),
                value: "letsencrypt.org".into()
            }
        );
        for bad in [
            RecordData::A {
                address: "1.2.3".into(),
            },
            RecordData::A {
                address: "::1".into(),
            },
            RecordData::AAAA {
                address: "1.2.3.4".into(),
            },
            RecordData::MX {
                preference: 10,
                exchange: "kein name".into(),
            },
            RecordData::TXT {
                text: String::new(),
            },
            RecordData::TXT {
                text: "x".repeat(MAX_TXT + 1),
            },
            RecordData::CAA {
                flags: 0,
                tag: "is-sue".into(),
                value: "x".into(),
            },
            RecordData::CAA {
                flags: 0,
                tag: "issue".into(),
                value: " ".into(),
            },
        ] {
            assert!(validate_data(&bad).is_err(), "{bad:?}");
        }
    }
}
