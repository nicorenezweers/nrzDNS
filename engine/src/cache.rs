//! Antwort-Cache: Schlüssel (Name, Typ, Klasse), TTL-Grenzen, negative Antworten (RFC 2308),
//! abgelaufene Einträge für den Notfall (RFC 8767), Vorabladen beliebter Einträge.

use crate::wire::{name_str, qtype_str, rcode_str, record_line};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{RData, Record, RecordType};
use nrzdns_types::{CacheEntry, CacheList, DnsSettings};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// TTL abgelaufener Einträge, wenn sie im Notfall ausgeliefert werden (RFC 8767).
pub(crate) const STALE_TTL: u32 = 30;

/// Ab so vielen Treffern gilt ein Eintrag als beliebt (Vorabladen).
const PREFETCH_MIN_HITS: u64 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CacheKey {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Antwort aus dem Cache mit schon angepassten TTLs.
#[derive(Debug, Clone)]
pub(crate) struct Cached {
    pub rcode: ResponseCode,
    pub ad: bool,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

pub(crate) enum CacheLookup {
    /// Gültig; `prefetch` = jetzt im Hintergrund erneuern.
    Fresh(Cached, bool),
    /// Abgelaufen, aber noch im Fenster für den Notfall.
    Stale(Cached),
    Miss,
}

struct Item {
    rcode: ResponseCode,
    ad: bool,
    /// Mit DO-Bit geholt (enthält ggf. RRSIG).
    dnssec: bool,
    answers: Vec<Record>,
    authority: Vec<Record>,
    additional: Vec<Record>,
    stored: Instant,
    ttl: u32,
    hits: u64,
    last_used: Instant,
    prefetching: bool,
}

impl Item {
    fn age(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.stored).as_secs()
    }

    fn view(&self, elapsed: u32, fixed_ttl: Option<u32>) -> Cached {
        let adjust = |recs: &[Record]| {
            recs.iter()
                .map(|r| {
                    let mut r = r.clone();
                    r.ttl = fixed_ttl.unwrap_or_else(|| r.ttl.saturating_sub(elapsed));
                    r
                })
                .collect()
        };
        Cached {
            rcode: self.rcode,
            ad: self.ad,
            answers: adjust(&self.answers),
            authority: adjust(&self.authority),
            additional: adjust(&self.additional),
        }
    }
}

struct Inner {
    map: HashMap<CacheKey, Item>,
    last_purge: Instant,
}

pub(crate) struct Cache {
    inner: Mutex<Inner>,
}

impl Default for Cache {
    fn default() -> Self {
        Cache {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                last_purge: Instant::now(),
            }),
        }
    }
}

/// Grenzen aus den Einstellungen.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub max_entries: usize,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub negative_ttl: u32,
    /// 0 = keine abgelaufenen Einträge ausliefern.
    pub stale_secs: u32,
    pub prefetch: bool,
}

impl Limits {
    pub fn from_settings(s: &DnsSettings) -> Limits {
        Limits {
            max_entries: s.cache_max_entries as usize,
            min_ttl: s.cache_min_ttl,
            max_ttl: s.cache_max_ttl.max(1),
            negative_ttl: s.cache_negative_ttl,
            stale_secs: if s.serve_stale { s.serve_stale_secs } else { 0 },
            prefetch: s.prefetch,
        }
    }

    fn clamp(&self, ttl: u32) -> u32 {
        ttl.max(self.min_ttl).min(self.max_ttl)
    }
}

impl Cache {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn get(
        &self,
        key: &CacheKey,
        dnssec_ok: bool,
        limits: &Limits,
        now: Instant,
    ) -> CacheLookup {
        let mut inner = self.lock();
        let Some(item) = inner.map.get_mut(key) else {
            return CacheLookup::Miss;
        };
        let age = item.age(now);
        let ttl = item.ttl as u64;
        if age < ttl {
            let view = item.view(age as u32, None);
            // Ohne RRSIG geholt, Client will DNSSEC: neu holen, notfalls aber diesen nehmen
            if dnssec_ok && !item.dnssec {
                return CacheLookup::Stale(view);
            }
            item.hits += 1;
            item.last_used = now;
            let remaining = ttl - age;
            let prefetch = limits.prefetch
                && !item.prefetching
                && item.hits >= PREFETCH_MIN_HITS
                && ttl >= 10
                && (remaining * 10 <= ttl || remaining <= 5);
            if prefetch {
                item.prefetching = true;
            }
            return CacheLookup::Fresh(view, prefetch);
        }
        if age < ttl + limits.stale_secs as u64 {
            return CacheLookup::Stale(item.view(0, Some(STALE_TTL)));
        }
        inner.map.remove(key);
        CacheLookup::Miss
    }

    /// Abgelaufenen Eintrag ausgeliefert: Treffer zählen.
    pub fn touch(&self, key: &CacheKey, now: Instant) {
        if let Some(item) = self.lock().map.get_mut(key) {
            item.hits += 1;
            item.last_used = now;
        }
    }

    /// Vorabladen fehlgeschlagen: wieder freigeben.
    pub fn prefetch_done(&self, key: &CacheKey) {
        if let Some(item) = self.lock().map.get_mut(key) {
            item.prefetching = false;
        }
    }

    /// Antwort eines vorgelagerten Servers speichern (nur NOERROR und NXDOMAIN).
    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &self,
        key: CacheKey,
        rcode: ResponseCode,
        ad: bool,
        dnssec: bool,
        mut answers: Vec<Record>,
        mut authority: Vec<Record>,
        mut additional: Vec<Record>,
        limits: &Limits,
        now: Instant,
    ) {
        if limits.max_entries == 0 {
            return;
        }
        let negative = rcode == ResponseCode::NXDomain || answers.is_empty();
        if rcode != ResponseCode::NoError && rcode != ResponseCode::NXDomain {
            return;
        }
        let ttl = if negative {
            let soa_ttl = authority.iter().find_map(|r| match &r.data {
                RData::SOA(soa) => Some(r.ttl.min(soa.minimum)),
                _ => None,
            });
            let neg = soa_ttl
                .unwrap_or(limits.negative_ttl)
                .min(limits.negative_ttl);
            for r in answers.iter_mut().chain(authority.iter_mut()) {
                r.ttl = limits.clamp(r.ttl).min(neg.max(limits.min_ttl));
            }
            if neg == 0 {
                return;
            }
            neg.max(limits.min_ttl).min(limits.max_ttl)
        } else {
            for r in answers.iter_mut().chain(authority.iter_mut()) {
                r.ttl = limits.clamp(r.ttl);
            }
            answers
                .iter()
                .map(|r| r.ttl)
                .min()
                .unwrap_or(limits.min_ttl)
        };
        if ttl == 0 {
            return;
        }
        for r in additional.iter_mut() {
            r.ttl = limits.clamp(r.ttl).min(ttl);
        }

        let mut inner = self.lock();
        let hits = inner.map.get(&key).map_or(0, |old| old.hits);
        if !inner.map.contains_key(&key) && inner.map.len() >= limits.max_entries {
            evict(&mut inner, limits, now);
        }
        inner.map.insert(
            key,
            Item {
                rcode,
                ad,
                dnssec,
                answers,
                authority,
                additional,
                stored: now,
                ttl,
                hits,
                last_used: now,
                prefetching: false,
            },
        );
        if now.saturating_duration_since(inner.last_purge) > Duration::from_secs(60) {
            purge(&mut inner, limits, now);
        }
    }

    /// Lebende Einträge (räumt Abgelaufene ausserhalb des Notfall-Fensters weg).
    pub fn len(&self, limits: &Limits, now: Instant) -> u64 {
        let mut inner = self.lock();
        purge(&mut inner, limits, now);
        inner.map.len() as u64
    }

    /// Neue Grenzen sofort anwenden.
    pub fn apply_limits(&self, limits: &Limits, now: Instant) {
        let mut inner = self.lock();
        purge(&mut inner, limits, now);
        while inner.map.len() > limits.max_entries {
            evict(&mut inner, limits, now);
        }
    }

    pub fn flush(&self) -> u64 {
        let mut inner = self.lock();
        let n = inner.map.len() as u64;
        inner.map.clear();
        inner.map.shrink_to_fit();
        n
    }

    pub fn remove_name(&self, name: &str) -> u64 {
        let mut inner = self.lock();
        let before = inner.map.len();
        inner.map.retain(|k, _| k.name != name);
        (before - inner.map.len()) as u64
    }

    pub fn list(&self, query: &str, limit: usize, limits: &Limits, now: Instant) -> CacheList {
        let mut inner = self.lock();
        purge(&mut inner, limits, now);
        let q = query.trim().trim_end_matches('.').to_ascii_lowercase();
        let mut rows: Vec<(&CacheKey, &Item)> = inner
            .map
            .iter()
            .filter(|(k, _)| q.is_empty() || k.name.contains(&q))
            .collect();
        rows.sort_by(|a, b| {
            b.1.hits
                .cmp(&a.1.hits)
                .then_with(|| a.0.name.cmp(&b.0.name))
        });
        let limit = if limit == 0 { 100 } else { limit };
        let entries = rows
            .into_iter()
            .take(limit)
            .map(|(k, item)| {
                let age = item.age(now);
                let remaining = (item.ttl as u64).saturating_sub(age) as u32;
                CacheEntry {
                    name: k.name.clone(),
                    qtype: qtype_str(RecordType::from(k.qtype)),
                    rcode: rcode_str(item.rcode),
                    ttl: remaining,
                    stale: age >= item.ttl as u64,
                    answers: item
                        .answers
                        .iter()
                        .filter(|r| r.record_type() != RecordType::RRSIG)
                        .map(record_line)
                        .collect(),
                    hits: item.hits,
                }
            })
            .collect();
        CacheList {
            entries,
            total: inner.map.len() as u64,
        }
    }
}

/// Einträge entfernen, die auch im Notfall nicht mehr ausgeliefert würden.
fn purge(inner: &mut Inner, limits: &Limits, now: Instant) {
    inner
        .map
        .retain(|_, item| item.age(now) < item.ttl as u64 + limits.stale_secs as u64);
    inner.last_purge = now;
}

/// Platz schaffen: erst Totes, dann das am längsten unbenutzte Zehntel.
fn evict(inner: &mut Inner, limits: &Limits, now: Instant) {
    purge(inner, limits, now);
    if inner.map.len() < limits.max_entries {
        return;
    }
    let mut ages: Vec<Instant> = inner.map.values().map(|i| i.last_used).collect();
    let n = (ages.len() / 10).max(1).min(ages.len());
    let (_, cutoff, _) = ages.select_nth_unstable(n - 1);
    let cutoff = *cutoff;
    let mut removed = 0;
    inner.map.retain(|_, item| {
        if removed < n && item.last_used <= cutoff {
            removed += 1;
            false
        } else {
            true
        }
    });
}

/// Name für den Cache-Schlüssel.
pub(crate) fn key_for(name: &hickory_proto::rr::Name, qtype: RecordType, qclass: u16) -> CacheKey {
    CacheKey {
        name: name_str(name),
        qtype: qtype.into(),
        qclass,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::parse_name;
    use hickory_proto::rr::rdata;

    fn limits() -> Limits {
        Limits {
            max_entries: 100,
            min_ttl: 10,
            max_ttl: 3600,
            negative_ttl: 300,
            stale_secs: 600,
            prefetch: true,
        }
    }

    fn key(name: &str) -> CacheKey {
        CacheKey {
            name: name.into(),
            qtype: 1,
            qclass: 1,
        }
    }

    fn a(name: &str, ttl: u32) -> Record {
        Record::from_rdata(
            parse_name(name).unwrap(),
            ttl,
            RData::A(rdata::A([1, 2, 3, 4].into())),
        )
    }

    fn soa(zone: &str, ttl: u32, minimum: u32) -> Record {
        let n = parse_name(zone).unwrap();
        Record::from_rdata(
            n.clone(),
            ttl,
            RData::SOA(rdata::SOA::new(n.clone(), n, 1, 1, 1, 1, minimum)),
        )
    }

    #[test]
    fn ttl_clamped_and_decremented() {
        let c = Cache::default();
        let l = limits();
        let t0 = Instant::now();
        c.insert(
            key("a.test"),
            ResponseCode::NoError,
            false,
            false,
            vec![a("a.test", 5)],
            vec![],
            vec![],
            &l,
            t0,
        );
        // min_ttl 10
        match c.get(&key("a.test"), false, &l, t0 + Duration::from_secs(3)) {
            CacheLookup::Fresh(v, _) => assert_eq!(v.answers[0].ttl, 7),
            _ => panic!("erwartet: frisch"),
        }
        c.insert(
            key("b.test"),
            ResponseCode::NoError,
            false,
            false,
            vec![a("b.test", 99999)],
            vec![],
            vec![],
            &l,
            t0,
        );
        match c.get(&key("b.test"), false, &l, t0) {
            CacheLookup::Fresh(v, _) => assert_eq!(v.answers[0].ttl, 3600),
            _ => panic!("erwartet: frisch"),
        }
    }

    #[test]
    fn negative_answers() {
        let c = Cache::default();
        let l = limits();
        let t0 = Instant::now();
        // SOA minimum 60 < negative_ttl 300
        c.insert(
            key("nx.test"),
            ResponseCode::NXDomain,
            false,
            false,
            vec![],
            vec![soa("test", 3600, 60)],
            vec![],
            &l,
            t0,
        );
        match c.get(&key("nx.test"), false, &l, t0 + Duration::from_secs(59)) {
            CacheLookup::Fresh(v, _) => assert_eq!(v.rcode, ResponseCode::NXDomain),
            _ => panic!("erwartet: frisch"),
        }
        assert!(matches!(
            c.get(&key("nx.test"), false, &l, t0 + Duration::from_secs(61)),
            CacheLookup::Stale(_)
        ));
        // ohne SOA: negative_ttl
        c.insert(
            key("nodata.test"),
            ResponseCode::NoError,
            false,
            false,
            vec![],
            vec![],
            vec![],
            &l,
            t0,
        );
        assert!(matches!(
            c.get(
                &key("nodata.test"),
                false,
                &l,
                t0 + Duration::from_secs(299)
            ),
            CacheLookup::Fresh(..)
        ));
        assert!(matches!(
            c.get(
                &key("nodata.test"),
                false,
                &l,
                t0 + Duration::from_secs(301)
            ),
            CacheLookup::Stale(_)
        ));
        // SERVFAIL wird nicht gespeichert
        c.insert(
            key("sf.test"),
            ResponseCode::ServFail,
            false,
            false,
            vec![],
            vec![],
            vec![],
            &l,
            t0,
        );
        assert!(matches!(
            c.get(&key("sf.test"), false, &l, t0),
            CacheLookup::Miss
        ));
    }

    #[test]
    fn serve_stale_window() {
        let c = Cache::default();
        let mut l = limits();
        let t0 = Instant::now();
        c.insert(
            key("s.test"),
            ResponseCode::NoError,
            false,
            false,
            vec![a("s.test", 60)],
            vec![],
            vec![],
            &l,
            t0,
        );
        match c.get(&key("s.test"), false, &l, t0 + Duration::from_secs(100)) {
            CacheLookup::Stale(v) => assert_eq!(v.answers[0].ttl, STALE_TTL),
            _ => panic!("erwartet: abgelaufen"),
        }
        assert!(matches!(
            c.get(&key("s.test"), false, &l, t0 + Duration::from_secs(700)),
            CacheLookup::Miss
        ));
        // ohne serve-stale sofort weg
        l.stale_secs = 0;
        c.insert(
            key("s.test"),
            ResponseCode::NoError,
            false,
            false,
            vec![a("s.test", 60)],
            vec![],
            vec![],
            &l,
            t0,
        );
        assert!(matches!(
            c.get(&key("s.test"), false, &l, t0 + Duration::from_secs(61)),
            CacheLookup::Miss
        ));
    }

    #[test]
    fn prefetch_and_hits() {
        let c = Cache::default();
        let l = limits();
        let t0 = Instant::now();
        c.insert(
            key("p.test"),
            ResponseCode::NoError,
            false,
            false,
            vec![a("p.test", 100)],
            vec![],
            vec![],
            &l,
            t0,
        );
        assert!(matches!(
            c.get(&key("p.test"), false, &l, t0),
            CacheLookup::Fresh(_, false)
        ));
        assert!(matches!(
            c.get(&key("p.test"), false, &l, t0 + Duration::from_secs(50)),
            CacheLookup::Fresh(_, false)
        ));
        assert!(matches!(
            c.get(&key("p.test"), false, &l, t0 + Duration::from_secs(95)),
            CacheLookup::Fresh(_, true)
        ));
        // nur einmal
        assert!(matches!(
            c.get(&key("p.test"), false, &l, t0 + Duration::from_secs(96)),
            CacheLookup::Fresh(_, false)
        ));
        let list = c.list("p.te", 10, &l, t0 + Duration::from_secs(96));
        assert_eq!(list.total, 1);
        assert_eq!(list.entries[0].hits, 4);
        assert_eq!(list.entries[0].answers, ["A 1.2.3.4"]);
        assert_eq!(list.entries[0].ttl, 4);
    }

    #[test]
    fn eviction_and_removal() {
        let c = Cache::default();
        let mut l = limits();
        l.max_entries = 20;
        let t0 = Instant::now();
        for i in 0..50 {
            let n = format!("h{i}.test");
            c.insert(
                key(&n),
                ResponseCode::NoError,
                false,
                false,
                vec![a(&n, 300)],
                vec![],
                vec![],
                &l,
                t0 + Duration::from_millis(i),
            );
        }
        assert!(c.len(&l, t0) <= 20);
        // der neueste ist noch da
        assert!(matches!(
            c.get(&key("h49.test"), false, &l, t0 + Duration::from_secs(1)),
            CacheLookup::Fresh(..)
        ));
        let n = c.len(&l, t0);
        l.max_entries = 5;
        c.apply_limits(&l, t0);
        assert!(c.len(&l, t0) <= 5);
        assert!(n >= 5);
        assert_eq!(c.remove_name("h49.test"), 1);
        assert!(c.flush() <= 5);
        assert_eq!(c.len(&l, t0), 0);
    }

    #[test]
    fn dnssec_needs_refetch() {
        let c = Cache::default();
        let l = limits();
        let t0 = Instant::now();
        c.insert(
            key("d.test"),
            ResponseCode::NoError,
            false,
            false,
            vec![a("d.test", 300)],
            vec![],
            vec![],
            &l,
            t0,
        );
        assert!(matches!(
            c.get(&key("d.test"), true, &l, t0),
            CacheLookup::Stale(_)
        ));
        assert!(matches!(
            c.get(&key("d.test"), false, &l, t0),
            CacheLookup::Fresh(..)
        ));
    }
}
