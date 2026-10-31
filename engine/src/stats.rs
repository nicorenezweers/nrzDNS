//! Zähler und Zustände: Rate-Limit je Client, Anfragen je Sekunde, Zustand der
//! vorgelagerten Server, geöffnete Adressen.

use nrzdns_types::{Upstream, UpstreamHealth};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ------------------------------------------------------------------ Rate-Limit

/// Token-Bucket je Client-IP: höchstens `qps` Anfragen je Sekunde, Vorrat = `qps`.
#[derive(Default)]
pub(crate) struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

impl RateLimiter {
    /// `true` = Anfrage erlaubt. `qps == 0` = unbegrenzt.
    pub fn allow(&self, ip: IpAddr, qps: u32, now: Instant) -> bool {
        if qps == 0 {
            return true;
        }
        let rate = qps as f64;
        let mut map = lock(&self.buckets);
        if map.len() > 100_000 {
            // Alte Clients vergessen (nach 10 s ist ihr Vorrat sowieso wieder voll)
            map.retain(|_, (_, t)| now.saturating_duration_since(*t).as_secs() < 10);
        }
        let (tokens, last) = map.entry(ip).or_insert((rate, now));
        let elapsed = now.saturating_duration_since(*last).as_secs_f64();
        *tokens = (*tokens + elapsed * rate).min(rate);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn clear(&self) {
        lock(&self.buckets).clear();
    }
}

// ------------------------------------------------------------------ Anfragen

/// Anfragen seit dem Start und je Sekunde (Ring über die letzte Minute).
pub(crate) struct QueryStats {
    total: AtomicU64,
    started: Instant,
    ring: Mutex<[(u64, u64); 60]>,
}

impl QueryStats {
    pub fn new(started: Instant) -> Self {
        QueryStats {
            total: AtomicU64::new(0),
            started,
            ring: Mutex::new([(u64::MAX, 0); 60]),
        }
    }

    pub fn count(&self, now: Instant) {
        self.total.fetch_add(1, Ordering::Relaxed);
        let sec = now.saturating_duration_since(self.started).as_secs();
        let mut ring = lock(&self.ring);
        let slot = &mut ring[(sec % 60) as usize];
        if slot.0 != sec {
            *slot = (sec, 0);
        }
        slot.1 += 1;
    }

    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Mittel der letzten (vollen) 60 Sekunden, kürzer direkt nach dem Start.
    pub fn per_second(&self, now: Instant) -> f64 {
        let up = now.saturating_duration_since(self.started).as_secs();
        if up == 0 {
            return 0.0;
        }
        let ring = lock(&self.ring);
        let from = up.saturating_sub(60);
        let sum: u64 = ring
            .iter()
            .filter(|(sec, _)| *sec != u64::MAX && *sec >= from && *sec < up)
            .map(|(_, n)| n)
            .sum();
        sum as f64 / (up - from) as f64
    }
}

// ------------------------------------------------------------------ Vorgelagerte Server

#[derive(Default, Clone)]
struct Health {
    ok: u64,
    failed: u64,
    avg_ms: f64,
    last_error: Option<String>,
    last_error_at: Option<i64>,
}

/// Zustand je vorgelagertem Server ([`Upstream::label`]).
#[derive(Default)]
pub(crate) struct HealthMap {
    map: Mutex<HashMap<String, Health>>,
}

impl HealthMap {
    pub fn ok(&self, label: &str, ms: f64) {
        let mut map = lock(&self.map);
        let h = map.entry(label.to_string()).or_default();
        h.avg_ms = if h.ok == 0 {
            ms
        } else {
            h.avg_ms * 0.8 + ms * 0.2
        };
        h.ok += 1;
    }

    pub fn failed(&self, label: &str, error: &str, now_unix: i64) {
        let mut map = lock(&self.map);
        let h = map.entry(label.to_string()).or_default();
        h.failed += 1;
        h.last_error = Some(error.to_string());
        h.last_error_at = Some(now_unix);
    }

    pub fn snapshot(&self, upstreams: &[Upstream]) -> Vec<UpstreamHealth> {
        let map = lock(&self.map);
        upstreams
            .iter()
            .map(|u| {
                let label = u.label();
                let h = map.get(&label).cloned().unwrap_or_default();
                UpstreamHealth {
                    name: if u.name.trim().is_empty() {
                        u.address.clone()
                    } else {
                        u.name.clone()
                    },
                    upstream: label,
                    ok: h.ok,
                    failed: h.failed,
                    avg_ms: (h.avg_ms * 10.0).round() / 10.0,
                    last_error: h.last_error,
                    last_error_at: h.last_error_at,
                }
            })
            .collect()
    }
}

/// Geöffnete Adressen und Fehler beim Öffnen.
#[derive(Default)]
pub(crate) struct Listeners {
    pub listen: Vec<String>,
    pub errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rate_limit_per_client() {
        let r = RateLimiter::default();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let t0 = Instant::now();
        assert!(r.allow(a, 2, t0));
        assert!(r.allow(a, 2, t0));
        assert!(!r.allow(a, 2, t0));
        // anderer Client unabhängig
        assert!(r.allow(b, 2, t0));
        // nach einer halben Sekunde ein neuer Token
        assert!(r.allow(a, 2, t0 + Duration::from_millis(500)));
        assert!(!r.allow(a, 2, t0 + Duration::from_millis(500)));
        // 0 = aus
        for _ in 0..100 {
            assert!(r.allow(a, 0, t0));
        }
    }

    #[test]
    fn queries_per_second() {
        let t0 = Instant::now();
        let s = QueryStats::new(t0);
        for i in 0..120 {
            s.count(t0 + Duration::from_millis(i * 500));
        }
        assert_eq!(s.total(), 120);
        let qps = s.per_second(t0 + Duration::from_secs(60));
        assert!((qps - 2.0).abs() < 0.01, "{qps}");
    }

    #[test]
    fn health_snapshot() {
        use nrzdns_types::UpstreamProtocol;
        let h = HealthMap::default();
        let u = Upstream::new(UpstreamProtocol::Udp, "1.1.1.1", "", "Cloudflare");
        h.ok(&u.label(), 10.0);
        h.ok(&u.label(), 20.0);
        h.failed(&u.label(), "Zeitlimit", 42);
        let s = h.snapshot(&[u]);
        assert_eq!(s[0].ok, 2);
        assert_eq!(s[0].failed, 1);
        assert_eq!(s[0].avg_ms, 12.0);
        assert_eq!(s[0].last_error.as_deref(), Some("Zeitlimit"));
        assert_eq!(s[0].name, "Cloudflare");
        assert_eq!(s[0].upstream, "udp://1.1.1.1");
    }
}
