//! Eigene Zonen im Speicher: Suche nach der längsten passenden Zone, Antworten nach
//! RFC 1034 4.3.2 (vereinfacht) mit Platzhaltern (RFC 4592), CNAME, Delegationen und
//! NODATA/NXDOMAIN.

use crate::wire::{name_str, parse_name, record_from_data, suffixes};
use hickory_proto::rr::rdata;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use nrzdns_types::{record_fqdn, Upstream, ZoneDetail, ZoneKind};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Alle aktiven Zonen, nach Namen.
#[derive(Default)]
pub(crate) struct ZoneSet {
    zones: HashMap<String, Arc<Zone>>,
    /// Alle übergebenen Zonen (auch deaktivierte) – für den Status.
    pub total: usize,
}

impl ZoneSet {
    pub fn build(details: &[ZoneDetail], server_domain: &str) -> ZoneSet {
        let mut zones = HashMap::new();
        for d in details.iter().filter(|d| !d.zone.disabled) {
            if let Some(z) = Zone::build(d, server_domain) {
                zones.insert(z.name.clone(), Arc::new(z));
            }
        }
        ZoneSet {
            zones,
            total: details.len(),
        }
    }

    /// Längste Zone, in der `name` liegt.
    pub fn find(&self, name: &str) -> Option<&Arc<Zone>> {
        if self.zones.is_empty() {
            return None;
        }
        suffixes(name).find_map(|s| self.zones.get(s))
    }
}

/// Ergebnis einer Suche in einer Zone.
#[derive(Debug)]
pub(crate) enum Lookup {
    /// Passende Einträge (plus Adressen der Ziele für den Additional-Teil).
    Records {
        answers: Vec<Record>,
        additional: Vec<Record>,
    },
    /// CNAME statt des gefragten Typs; Ziel klein, ohne Punkt.
    Cname(Box<Record>, String),
    /// Name existiert, Typ nicht.
    NoData,
    NxDomain,
    /// Delegation an andere Nameserver.
    Referral {
        ns: Vec<Record>,
        glue: Vec<Record>,
    },
}

pub(crate) struct Zone {
    pub name: String,
    pub kind: ZoneKind,
    pub forwarders: Vec<Upstream>,
    soa: Record,
    /// Einträge je Name (klein, ohne Punkt), inklusive SOA und NS der Zone.
    nodes: HashMap<String, Vec<Record>>,
    /// Alle Namen mit Einträgen und ihre Elternnamen bis zur Zone (leere Zwischenknoten).
    names: HashSet<String>,
    /// Delegationen (NS unterhalb der Zone).
    cuts: HashSet<String>,
}

impl Zone {
    fn build(d: &ZoneDetail, server_domain: &str) -> Option<Zone> {
        let name = d
            .zone
            .name
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let origin = parse_name(&name).filter(|n| !n.is_root())?;
        let soa_cfg = &d.zone.soa;
        let mname = Some(soa_cfg.primary_ns.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or(server_domain);
        let mname = parse_name(mname).unwrap_or_else(|| origin.clone());
        let rname = Some(soa_cfg.responsible.trim())
            .filter(|s| !s.is_empty())
            .and_then(parse_name)
            .or_else(|| parse_name(&format!("hostmaster.{name}")))
            .unwrap_or_else(|| origin.clone());
        let soa = Record::from_rdata(
            origin.clone(),
            soa_cfg.minimum,
            RData::SOA(rdata::SOA::new(
                mname.clone(),
                rname,
                soa_cfg.serial,
                clamp_i32(soa_cfg.refresh),
                clamp_i32(soa_cfg.retry),
                clamp_i32(soa_cfg.expire),
                soa_cfg.minimum,
            )),
        );

        let mut nodes: HashMap<String, Vec<Record>> = HashMap::new();
        let mut cuts = HashSet::new();
        let suffix = format!(".{name}");
        for r in d.records.iter().filter(|r| !r.disabled) {
            let fqdn = record_fqdn(&r.name, &name);
            if fqdn != name && !fqdn.ends_with(&suffix) {
                continue;
            }
            let Some(owner) = parse_name(&fqdn) else {
                continue;
            };
            let Some(record) = record_from_data(owner, r.ttl, &r.data) else {
                tracing::warn!(zone = %name, record = %fqdn, "Eintrag mit ungültigen Daten übersprungen");
                continue;
            };
            if record.record_type() == RecordType::NS && fqdn != name {
                cuts.insert(fqdn.clone());
            }
            nodes.entry(fqdn).or_default().push(record);
        }

        let apex = nodes.entry(name.clone()).or_default();
        if d.zone.kind == ZoneKind::Primary {
            apex.push(soa.clone());
            if !apex.iter().any(|r| r.record_type() == RecordType::NS) {
                apex.push(Record::from_rdata(
                    origin.clone(),
                    soa_cfg.minimum.max(300),
                    RData::NS(rdata::NS(mname)),
                ));
            }
        }

        let mut names = HashSet::new();
        for key in nodes.keys() {
            for s in suffixes(key) {
                if !names.insert(s.to_string()) || s == name {
                    break;
                }
            }
        }
        names.insert(name.clone());

        Some(Zone {
            name,
            kind: d.zone.kind,
            forwarders: d.zone.forwarders.clone(),
            soa,
            nodes,
            names,
            cuts,
        })
    }

    /// SOA für negative Antworten: TTL = min(TTL, minimum) (RFC 2308).
    pub fn negative_soa(&self) -> Record {
        let mut soa = self.soa.clone();
        if let RData::SOA(s) = &soa.data {
            soa.ttl = soa.ttl.min(s.minimum);
        }
        soa
    }

    /// Suche in einer Primärzone (`lname` liegt in der Zone).
    pub fn lookup(&self, lname: &str, qname: &Name, qtype: RecordType) -> Lookup {
        if let Some(cut) = self.delegation(lname) {
            return self.referral(cut);
        }
        if let Some(recs) = self.nodes.get(lname) {
            return self.answer_node(recs, None, qtype);
        }
        if self.names.contains(lname) {
            return Lookup::NoData;
        }
        match self.wildcard(lname) {
            Some(recs) => self.answer_node(recs, Some(qname), qtype),
            None => Lookup::NxDomain,
        }
    }

    /// Eigene Einträge einer Weiterleitungszone: nur echte Treffer (Typ oder CNAME), sonst
    /// `None` = weiterleiten.
    pub fn lookup_own(&self, lname: &str, qname: &Name, qtype: RecordType) -> Option<Lookup> {
        let found = match self.nodes.get(lname) {
            Some(recs) => self.answer_node(recs, None, qtype),
            None if self.names.contains(lname) => return None,
            None => self.answer_node(self.wildcard(lname)?, Some(qname), qtype),
        };
        matches!(found, Lookup::Records { .. } | Lookup::Cname(..)).then_some(found)
    }

    /// Oberste Delegation zwischen Zone (ausschliesslich) und `lname` (einschliesslich).
    fn delegation<'a>(&self, lname: &'a str) -> Option<&'a str> {
        if self.cuts.is_empty() || lname == self.name {
            return None;
        }
        suffixes(lname)
            .take_while(|s| s.len() > self.name.len())
            .filter(|s| self.cuts.contains(*s))
            .last()
    }

    fn referral(&self, cut: &str) -> Lookup {
        let ns: Vec<Record> = self
            .nodes
            .get(cut)
            .map(|recs| {
                recs.iter()
                    .filter(|r| r.record_type() == RecordType::NS)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let glue = self.addresses_for(ns.iter().filter_map(|r| match &r.data {
            RData::NS(n) => Some(&n.0),
            _ => None,
        }));
        Lookup::Referral { ns, glue }
    }

    /// Platzhalter über dem nächsten existierenden Vorfahren (closest encloser).
    fn wildcard(&self, lname: &str) -> Option<&Vec<Record>> {
        let encloser = suffixes(lname)
            .skip(1)
            .find(|s| s.len() <= self.name.len() || self.names.contains(*s))?;
        self.nodes.get(&format!("*.{encloser}"))
    }

    fn answer_node(&self, recs: &[Record], rename: Option<&Name>, qtype: RecordType) -> Lookup {
        let owned = |r: &Record| {
            let mut r = r.clone();
            if let Some(n) = rename {
                r.name = n.clone();
            }
            r
        };
        let answers: Vec<Record> = recs
            .iter()
            .filter(|r| qtype == RecordType::ANY || r.record_type() == qtype)
            .map(owned)
            .collect();
        if !answers.is_empty() {
            let additional = self.addresses_for(answers.iter().filter_map(|r| match &r.data {
                RData::MX(mx) => Some(&mx.exchange),
                RData::SRV(srv) => Some(&srv.target),
                RData::NS(ns) => Some(&ns.0),
                _ => None,
            }));
            return Lookup::Records {
                answers,
                additional,
            };
        }
        if qtype != RecordType::CNAME {
            if let Some(c) = recs.iter().find(|r| r.record_type() == RecordType::CNAME) {
                if let RData::CNAME(target) = &c.data {
                    return Lookup::Cname(Box::new(owned(c)), name_str(&target.0));
                }
            }
        }
        Lookup::NoData
    }

    /// A/AAAA der Ziele, soweit sie in dieser Zone liegen.
    fn addresses_for<'a>(&self, targets: impl Iterator<Item = &'a Name>) -> Vec<Record> {
        let mut out = Vec::new();
        for t in targets {
            if let Some(recs) = self.nodes.get(&name_str(t)) {
                out.extend(
                    recs.iter()
                        .filter(|r| matches!(r.record_type(), RecordType::A | RecordType::AAAA))
                        .cloned(),
                );
            }
        }
        out
    }
}

fn clamp_i32(v: u32) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrzdns_types::{RecordData, Soa, Zone as ApiZone, ZoneRecord};

    pub(crate) fn detail(
        name: &str,
        kind: ZoneKind,
        records: Vec<(&str, RecordData)>,
    ) -> ZoneDetail {
        ZoneDetail {
            zone: ApiZone {
                id: 1,
                name: name.into(),
                kind,
                disabled: false,
                soa: Soa {
                    primary_ns: format!("ns1.{name}"),
                    responsible: format!("hostmaster.{name}"),
                    minimum: 300,
                    ..Soa::default()
                },
                forwarders: vec![],
                comment: String::new(),
                record_count: records.len() as u32,
                created_at: 0,
                updated_at: 0,
            },
            records: records
                .into_iter()
                .enumerate()
                .map(|(i, (n, data))| ZoneRecord {
                    id: i as i64,
                    zone_id: 1,
                    name: n.into(),
                    ttl: 3600,
                    data,
                    disabled: false,
                    comment: String::new(),
                    updated_at: 0,
                })
                .collect(),
        }
    }

    fn a(ip: &str) -> RecordData {
        RecordData::A { address: ip.into() }
    }

    fn set() -> ZoneSet {
        let mut disabled = detail("off.test", ZoneKind::Primary, vec![("www", a("10.9.9.9"))]);
        disabled.zone.disabled = true;
        let mut example = detail(
            "example.test",
            ZoneKind::Primary,
            vec![
                ("@", a("10.0.0.1")),
                ("www", a("10.0.0.2")),
                (
                    "www",
                    RecordData::AAAA {
                        address: "fd00::2".into(),
                    },
                ),
                (
                    "alias",
                    RecordData::CNAME {
                        target: "www.example.test".into(),
                    },
                ),
                (
                    "out",
                    RecordData::CNAME {
                        target: "elsewhere.org".into(),
                    },
                ),
                ("*", a("10.0.0.99")),
                ("*.dev", a("10.0.0.100")),
                ("a.b.deep", a("10.0.0.3")),
                (
                    "@",
                    RecordData::MX {
                        preference: 10,
                        exchange: "mail.example.test".into(),
                    },
                ),
                ("mail", a("10.0.0.25")),
                (
                    "sub",
                    RecordData::NS {
                        host: "ns.sub.example.test".into(),
                    },
                ),
                ("ns.sub", a("10.0.0.53")),
                ("gone", a("10.0.0.7")),
            ],
        );
        example.records.last_mut().unwrap().disabled = true;
        let fwd = detail(
            "fritz.box",
            ZoneKind::Forwarder,
            vec![("nas", a("192.168.178.5"))],
        );
        ZoneSet::build(&[example, disabled, fwd], "ns.nrzdns.local")
    }

    fn look(set: &ZoneSet, name: &str, t: RecordType) -> Lookup {
        let z = set.find(name).unwrap();
        z.lookup(name, &parse_name(name).unwrap(), t)
    }

    fn ips(l: &Lookup) -> Vec<String> {
        match l {
            Lookup::Records { answers, .. } => answers
                .iter()
                .filter_map(|r| r.data.ip_addr().map(|i| i.to_string()))
                .collect(),
            other => panic!("keine Einträge: {other:?}"),
        }
    }

    #[test]
    fn finds_longest_zone() {
        let s = set();
        assert_eq!(s.total, 3);
        assert_eq!(s.find("www.example.test").unwrap().name, "example.test");
        assert_eq!(s.find("example.test").unwrap().name, "example.test");
        assert!(s.find("www.off.test").is_none());
        assert!(s.find("other.test").is_none());
        assert!(s.find("test").is_none());
    }

    #[test]
    fn exact_wildcard_and_negative() {
        let s = set();
        assert_eq!(
            ips(&look(&s, "www.example.test", RecordType::A)),
            ["10.0.0.2"]
        );
        assert_eq!(ips(&look(&s, "example.test", RecordType::A)), ["10.0.0.1"]);
        // Platzhalter
        let l = look(&s, "random.example.test", RecordType::A);
        match &l {
            Lookup::Records { answers, .. } => {
                assert_eq!(name_str(&answers[0].name), "random.example.test")
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            ips(&look(&s, "x.y.example.test", RecordType::A)),
            ["10.0.0.99"]
        );
        assert_eq!(
            ips(&look(&s, "foo.dev.example.test", RecordType::A)),
            ["10.0.0.100"]
        );
        assert_eq!(
            ips(&look(&s, "a.foo.dev.example.test", RecordType::A)),
            ["10.0.0.100"]
        );
        // leerer Zwischenknoten: NODATA, kein Platzhalter
        assert!(matches!(
            look(&s, "deep.example.test", RecordType::A),
            Lookup::NoData
        ));
        assert!(matches!(
            look(&s, "dev.example.test", RecordType::A),
            Lookup::NoData
        ));
        // unter einem existierenden Namen greift kein höherer Platzhalter
        assert!(matches!(
            look(&s, "x.b.deep.example.test", RecordType::A),
            Lookup::NxDomain
        ));
        // Name da, Typ nicht
        assert!(matches!(
            look(&s, "mail.example.test", RecordType::AAAA),
            Lookup::NoData
        ));
        // deaktivierter Eintrag zählt nicht – aber der Platzhalter greift
        assert_eq!(
            ips(&look(&s, "gone.example.test", RecordType::A)),
            ["10.0.0.99"]
        );
    }

    #[test]
    fn cname_mx_soa_ns() {
        let s = set();
        match look(&s, "alias.example.test", RecordType::A) {
            Lookup::Cname(r, target) => {
                assert_eq!(target, "www.example.test");
                assert_eq!(r.record_type(), RecordType::CNAME);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            look(&s, "alias.example.test", RecordType::CNAME),
            Lookup::Records { .. }
        ));
        match look(&s, "example.test", RecordType::MX) {
            Lookup::Records { additional, .. } => assert_eq!(additional.len(), 1),
            other => panic!("{other:?}"),
        }
        match look(&s, "example.test", RecordType::SOA) {
            Lookup::Records { answers, .. } => {
                assert_eq!(answers[0].record_type(), RecordType::SOA)
            }
            other => panic!("{other:?}"),
        }
        match look(&s, "example.test", RecordType::NS) {
            Lookup::Records { answers, .. } => assert_eq!(answers.len(), 1),
            other => panic!("{other:?}"),
        }
        let neg = s.find("example.test").unwrap().negative_soa();
        assert_eq!(neg.ttl, 300);
    }

    #[test]
    fn delegation() {
        let s = set();
        match look(&s, "host.sub.example.test", RecordType::A) {
            Lookup::Referral { ns, glue } => {
                assert_eq!(ns.len(), 1);
                assert_eq!(glue.len(), 1);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn forwarder_zone_own_records() {
        let s = set();
        let z = s.find("nas.fritz.box").unwrap();
        assert_eq!(z.kind, ZoneKind::Forwarder);
        let n = parse_name("nas.fritz.box").unwrap();
        assert!(z.lookup_own("nas.fritz.box", &n, RecordType::A).is_some());
        assert!(z
            .lookup_own("nas.fritz.box", &n, RecordType::AAAA)
            .is_none());
        let n = parse_name("router.fritz.box").unwrap();
        assert!(z
            .lookup_own("router.fritz.box", &n, RecordType::A)
            .is_none());
    }
}
