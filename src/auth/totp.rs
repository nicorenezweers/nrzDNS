//! Zwei-Faktor-Anmeldung mit TOTP (RFC 6238: HMAC-SHA1, 6 Ziffern, 30 s) – passt zu jeder
//! Authenticator-App (Google Authenticator, Aegis, 1Password, Bitwarden …).

use ring::hmac;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
pub const STEP: i64 = 30;

/// Base32 (RFC 4648, ohne Auffüllung).
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s
        .trim()
        .trim_end_matches('=')
        .chars()
        .filter(|c| !c.is_whitespace())
    {
        let v = ALPHABET
            .iter()
            .position(|&a| a as char == c.to_ascii_uppercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push(((buf >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

/// Code für einen Zeitschritt (RFC 4226).
pub fn hotp(secret: &[u8], counter: u64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let h = tag.as_ref();
    let o = usize::from(h[h.len() - 1] & 0x0f);
    let bin = (u32::from(h[o] & 0x7f) << 24)
        | (u32::from(h[o + 1]) << 16)
        | (u32::from(h[o + 2]) << 8)
        | u32::from(h[o + 3]);
    bin % 1_000_000
}

/// Code prüfen (±1 Zeitschritt). Liefert den Schritt, damit ein Code nicht zweimal gilt.
pub fn verify(secret_b32: &str, code: &str, unix: i64, last_step: i64) -> Option<i64> {
    let code: String = code.chars().filter(char::is_ascii_digit).collect();
    if code.len() != 6 {
        return None;
    }
    let want: u32 = code.parse().ok()?;
    let secret = base32_decode(secret_b32)?;
    let now = unix / STEP;
    (now - 1..=now + 1)
        .filter(|s| *s > last_step && *s >= 0)
        .find(|s| hotp(&secret, *s as u64) == want)
}

/// Neues Geheimnis (20 Byte, Base32).
pub fn new_secret() -> String {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 20];
    let _ = ring::rand::SystemRandom::new().fill(&mut b);
    base32_encode(&b)
}

/// Zehn Wiederherstellungscodes wie `k7m2p-xq4rt`.
pub fn recovery_codes() -> Vec<String> {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    (0..10)
        .map(|_| {
            let mut b = [0u8; 7];
            let _ = rng.fill(&mut b);
            let s = base32_encode(&b).to_lowercase();
            format!("{}-{}", &s[..5], &s[5..10])
        })
        .collect()
}

pub fn hash_code(code: &str) -> String {
    let norm: String = code
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    ring::digest::digest(&ring::digest::SHA256, norm.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vectors() {
        // RFC 6238 Anhang B (SHA1, Geheimnis "12345678901234567890"), letzte 6 Ziffern
        let secret = b"12345678901234567890";
        assert_eq!(hotp(secret, 59 / 30), 287_082);
        assert_eq!(hotp(secret, 1_111_111_109 / 30), 81_804);
        assert_eq!(hotp(secret, 1_234_567_890 / 30), 5_924);
        let b32 = base32_encode(secret);
        assert_eq!(b32, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(base32_decode(&b32).unwrap(), secret);
        assert_eq!(verify(&b32, "287082", 59, 0), Some(1));
        assert_eq!(verify(&b32, "287 082", 59 + 30, 0), Some(1), "±1 Schritt");
        assert_eq!(verify(&b32, "287082", 59, 1), None, "nicht zweimal");
        assert_eq!(verify(&b32, "000000", 59, 0), None);
        assert_eq!(hash_code("K7M2P-XQ4RT"), hash_code("k7m2pxq4rt"));
        assert_eq!(recovery_codes().len(), 10);
    }
}
