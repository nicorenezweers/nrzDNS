//! Namen, die nrzNetwork selbst mit einer Adresse dieses Geräts beantwortet (Reverse Proxy,
//! Sperrseite). Welche Adresse, hängt vom fragenden Client ab: ein Gerät im LAN bekommt die
//! LAN-Adresse, ein Gerät im VPN (NetBird, Tailscale: 100.64.0.0/10) die VPN-Adresse.

use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Default)]
pub(crate) struct LocalHosts {
    /// Name (klein, ohne Punkt) → Adressen nur für diesen Namen (leer = Adressen des Geräts).
    pub names: HashMap<String, Vec<IpAddr>>,
    /// Adressen dieses Geräts.
    pub device: Vec<IpAddr>,
}

impl LocalHosts {
    /// Kandidaten für einen Namen (`None` = kein lokaler Name).
    pub fn candidates(&self, name: &str) -> Option<&[IpAddr]> {
        let own = self.names.get(name)?;
        Some(if own.is_empty() { &self.device } else { own })
    }
}

fn is_cgnat(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(a) if a.octets()[0] == 100 && (a.octets()[1] & 0xc0) == 64)
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_link_local(),
        IpAddr::V6(a) => {
            (a.segments()[0] & 0xfe00) == 0xfc00 || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Wie gut `addr` zu `client` passt (höher = besser).
fn score(client: Option<IpAddr>, addr: IpAddr) -> u8 {
    let Some(client) = client else {
        return u8::from(is_private(addr));
    };
    match (client, addr) {
        (IpAddr::V4(c), IpAddr::V4(a)) if c.octets()[..3] == a.octets()[..3] => 5,
        (c, a) if is_cgnat(c) && is_cgnat(a) => 5,
        (IpAddr::V4(c), IpAddr::V4(a))
            if c.octets()[..2] == a.octets()[..2] && is_private(addr) =>
        {
            4
        }
        (c, a) if is_private(c) && is_private(a) => 3,
        (c, a) if c.is_loopback() && is_private(a) => 2,
        (_, a) if is_private(a) => 1,
        _ => 0,
    }
}

/// Beste Adresse der gewünschten Familie für diesen Client.
pub(crate) fn pick(candidates: &[IpAddr], client: Option<IpAddr>, v4: bool) -> Option<IpAddr> {
    candidates
        .iter()
        .copied()
        .filter(|a| a.is_ipv4() == v4)
        .enumerate()
        .max_by_key(|(i, a)| (score(client, *a), usize::MAX - i))
        .map(|(_, a)| a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn picks_by_client_network() {
        let c = [ip("192.168.0.198"), ip("100.78.107.162"), ip("fd00::1")];
        assert_eq!(
            pick(&c, Some(ip("192.168.0.50")), true),
            Some(ip("192.168.0.198"))
        );
        assert_eq!(
            pick(&c, Some(ip("100.78.1.2")), true),
            Some(ip("100.78.107.162"))
        );
        assert_eq!(
            pick(&c, Some(ip("172.17.0.3")), true),
            Some(ip("192.168.0.198"))
        );
        assert_eq!(pick(&c, None, true), Some(ip("192.168.0.198")));
        assert_eq!(
            pick(&c, Some(ip("192.168.0.50")), false),
            Some(ip("fd00::1"))
        );
        assert_eq!(
            pick(&[ip("100.78.107.162")], Some(ip("192.168.0.5")), true),
            Some(ip("100.78.107.162"))
        );
        assert_eq!(pick(&[], None, true), None);
    }
}
