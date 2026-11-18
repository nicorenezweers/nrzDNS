//! Sperrdaten im Speicher: Listen, eigene Sperren, Ausnahmen, Pause.
//!
//! Jede Domain wird als 64-Bit-Hash in einem sortierten `Vec<u64>` gehalten (8 Bytes je
//! Domain, also rund 16 MB für zwei Millionen). Eine Abfrage prüft den Namen und alle
//! Elterndomains per Binärsuche – O(Labels · log n). Kollisionen sind bei 64 Bit praktisch
//! ausgeschlossen (≈ n / 2⁶⁴ je Abfrage).

use crate::wire::suffixes;
use nrzdns_types::DomainCheck;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;

/// Domain → Hash. `DefaultHasher::new()` hat feste Schlüssel: innerhalb eines Prozesses stabil.
pub(crate) fn domain_hash(domain: &str) -> u64 {
    let mut h = DefaultHasher::new();
    domain.hash(&mut h);
    h.finish()
}

/// Klein, ohne Punkt am Ende, ohne `*.` (nur kopieren, wenn nötig).
fn canonical(d: &str) -> Cow<'_, str> {
    let t = d.trim().trim_end_matches('.');
    let t = t.strip_prefix("*.").unwrap_or(t);
    if t.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(t.to_ascii_lowercase())
    } else {
        Cow::Borrowed(t)
    }
}

/// Menge von Domains als sortierte Hashes.
#[derive(Debug, Default)]
pub(crate) struct DomainSet(Vec<u64>);

impl DomainSet {
    pub fn new<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut v: Vec<u64> = domains
            .into_iter()
            .filter_map(|d| {
                let c = canonical(d.as_ref());
                (!c.is_empty()).then(|| domain_hash(&c))
            })
            .collect();
        v.sort_unstable();
        v.dedup();
        v.shrink_to_fit();
        DomainSet(v)
    }

    fn contains(&self, hash: u64) -> bool {
        self.0.binary_search(&hash).is_ok()
    }
}

/// Verschiedene Hashes über mehrere sortierte Mengen (k-Wege-Mischen ohne Kopie).
fn count_distinct(sets: &[&[u64]]) -> u64 {
    let mut pos = vec![0usize; sets.len()];
    let mut count = 0u64;
    loop {
        let mut min: Option<u64> = None;
        for (i, s) in sets.iter().enumerate() {
            if let Some(&v) = s.get(pos[i]) {
                min = Some(min.map_or(v, |m| m.min(v)));
            }
        }
        let Some(m) = min else { return count };
        count += 1;
        for (i, s) in sets.iter().enumerate() {
            if s.get(pos[i]) == Some(&m) {
                pos[i] += 1;
            }
        }
    }
}

struct List {
    name: String,
    set: Arc<DomainSet>,
}

/// Alle Sperrdaten der Engine.
#[derive(Default)]
pub(crate) struct BlockData {
    lists: BTreeMap<i64, List>,
    custom: Arc<DomainSet>,
    allowed: Arc<DomainSet>,
    paused_until: Option<i64>,
    total: u64,
}

impl BlockData {
    pub fn set_list(&mut self, id: i64, name: &str, set: DomainSet) {
        self.lists.insert(
            id,
            List {
                name: name.to_string(),
                set: Arc::new(set),
            },
        );
    }

    pub fn remove_list(&mut self, id: i64) -> bool {
        self.lists.remove(&id).is_some()
    }

    pub fn set_custom(&mut self, set: DomainSet) {
        self.custom = Arc::new(set);
    }

    pub fn set_allowed(&mut self, set: DomainSet) {
        self.allowed = Arc::new(set);
    }

    /// Alle gesperrten Mengen (für die Zählung ausserhalb der Sperre).
    pub fn block_sets(&self) -> Vec<Arc<DomainSet>> {
        let mut v: Vec<Arc<DomainSet>> = self.lists.values().map(|l| l.set.clone()).collect();
        v.push(self.custom.clone());
        v
    }

    pub fn set_total(&mut self, total: u64) {
        self.total = total;
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn pause(&mut self, until: Option<i64>) {
        self.paused_until = until;
    }

    /// Pause bis (läuft von selbst ab).
    pub fn paused_until(&self, now: i64) -> Option<i64> {
        self.paused_until.filter(|&t| t > now)
    }

    /// Gesperrt? Liefert die Domain, die getroffen hat (Name oder Elterndomain).
    /// Ausnahmen schlagen jede Sperre.
    pub fn blocked_by<'a>(&self, name: &'a str) -> Option<&'a str> {
        let hashes: Vec<(&str, u64)> = suffixes(name).map(|s| (s, domain_hash(s))).collect();
        if hashes.iter().any(|&(_, h)| self.allowed.contains(h)) {
            return None;
        }
        hashes
            .iter()
            .find(|&&(_, h)| {
                self.custom.contains(h) || self.lists.values().any(|l| l.set.contains(h))
            })
            .map(|&(s, _)| s)
    }

    /// Steht der Name (oder eine Elterndomain) in den Ausnahmen?
    pub fn is_allowed(&self, name: &str) -> bool {
        suffixes(name).any(|s| self.allowed.contains(domain_hash(s)))
    }

    /// Erklärung für „Wird diese Domain gesperrt?“ (unabhängig von Pause und Schalter).
    pub fn check(&self, domain: &str) -> DomainCheck {
        let Some(name) = nrzdns_types::normalize_domain(domain) else {
            return DomainCheck {
                domain: domain.trim().to_string(),
                blocked: false,
                allowed: false,
                matches: Vec::new(),
            };
        };
        let mut matches = Vec::new();
        let mut allowed = false;
        let mut hit = false;
        for s in suffixes(&name) {
            let h = domain_hash(s);
            if self.allowed.contains(h) {
                allowed = true;
                matches.push(format!("Ausnahme: {s}"));
            }
            if self.custom.contains(h) {
                hit = true;
                matches.push(format!("Eigene Sperre: {s}"));
            }
            for list in self.lists.values() {
                if list.set.contains(h) {
                    hit = true;
                    matches.push(format!("Liste „{}“: {s}", list.name));
                }
            }
        }
        DomainCheck {
            domain: name,
            blocked: hit && !allowed,
            allowed,
            matches,
        }
    }
}

/// Verschiedene Domains über alle gesperrten Mengen.
pub(crate) fn distinct_total(sets: &[Arc<DomainSet>]) -> u64 {
    let slices: Vec<&[u64]> = sets.iter().map(|s| s.0.as_slice()).collect();
    count_distinct(&slices)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data() -> BlockData {
        let mut b = BlockData::default();
        b.set_list(
            1,
            "StevenBlack Unified",
            DomainSet::new(["ads.example.com", "tracker.net"]),
        );
        b.set_list(2, "HaGeZi", DomainSet::new(["tracker.net", "bad.org"]));
        b.set_custom(DomainSet::new(["Custom.Example."]));
        b.set_allowed(DomainSet::new(["good.tracker.net"]));
        let total = distinct_total(&b.block_sets());
        b.set_total(total);
        b
    }

    #[test]
    fn subdomains_and_allowed() {
        let b = data();
        assert_eq!(b.total(), 4);
        assert_eq!(b.blocked_by("ads.example.com"), Some("ads.example.com"));
        assert_eq!(b.blocked_by("x.y.ads.example.com"), Some("ads.example.com"));
        assert_eq!(b.blocked_by("example.com"), None);
        assert_eq!(b.blocked_by("www.custom.example"), Some("custom.example"));
        assert_eq!(b.blocked_by("tracker.net"), Some("tracker.net"));
        // Ausnahme schlägt Sperre, auch für Subdomains
        assert_eq!(b.blocked_by("good.tracker.net"), None);
        assert_eq!(b.blocked_by("cdn.good.tracker.net"), None);
        assert!(b.is_allowed("cdn.good.tracker.net"));
    }

    #[test]
    fn check_explains() {
        let b = data();
        let c = b.check("www.ads.example.com");
        assert!(c.blocked && !c.allowed);
        assert_eq!(c.matches, ["Liste „StevenBlack Unified“: ads.example.com"]);
        let c = b.check("tracker.net");
        assert_eq!(
            c.matches,
            [
                "Liste „StevenBlack Unified“: tracker.net",
                "Liste „HaGeZi“: tracker.net"
            ]
        );
        let c = b.check("good.tracker.net");
        assert!(!c.blocked && c.allowed);
        assert!(c
            .matches
            .contains(&"Ausnahme: good.tracker.net".to_string()));
        let c = b.check("a.custom.example");
        assert_eq!(c.matches, ["Eigene Sperre: custom.example"]);
        assert!(!b.check("kein domain").blocked);
    }

    #[test]
    fn pause_expires() {
        let mut b = data();
        b.pause(Some(1000));
        assert_eq!(b.paused_until(999), Some(1000));
        assert_eq!(b.paused_until(1000), None);
        b.pause(None);
        assert_eq!(b.paused_until(0), None);
    }

    #[test]
    fn distinct_counting() {
        assert_eq!(count_distinct(&[&[1, 3, 5], &[2, 3, 6], &[], &[5]]), 5);
        assert_eq!(count_distinct(&[]), 0);
        let mut b = data();
        assert!(b.remove_list(2));
        assert_eq!(distinct_total(&b.block_sets()), 3);
    }
}
