//! Production crypto and encoding helpers shared across the `did` submodules.

use std::time::{SystemTime, UNIX_EPOCH};

use super::error::DidError;

pub(super) fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

/// Domain-separated SHA-256: `SHA-256(domain || 0x00 || data)`.
pub(super) fn sha256_tagged(domain: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(domain);
    hasher.update([0u8]);
    hasher.update(data);
    hasher.finalize().into()
}

/// A fresh random 12-byte AEAD nonce from the OS RNG.
pub(super) fn random_nonce() -> Result<[u8; 12], DidError> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| DidError::KeyGen(e.to_string()))?;
    Ok(nonce)
}

pub(super) fn contains(values: &[String], needle: &str) -> bool {
    values.iter().any(|value| value == needle)
}

pub(super) fn intersects(left: &[String], right: &[String]) -> bool {
    left.iter().any(|value| right.contains(value))
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(super) fn hex_decode(value: &str) -> Result<Vec<u8>, DidError> {
    if !value.len().is_multiple_of(2) {
        return Err(DidError::InvalidHex);
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = HEX_VALUES[chunk[0] as usize];
        let low = HEX_VALUES[chunk[1] as usize];
        if high | low > 0x0f {
            return Err(DidError::InvalidHex);
        }
        out.push((high << 4) | low);
    }
    Ok(out)
}

const HEX_VALUES: [u8; 256] = {
    let mut values = [u8::MAX; 256];
    let mut digit = 0;
    while digit < 10 {
        values[b'0' as usize + digit] = digit as u8;
        digit += 1;
    }
    let mut letter = 0;
    while letter < 6 {
        values[b'a' as usize + letter] = letter as u8 + 10;
        values[b'A' as usize + letter] = letter as u8 + 10;
        letter += 1;
    }
    values
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hexadecimal_round_trip_uses_canonical_lowercase() {
        let bytes = [0x00, 0x01, 0x09, 0x0a, 0x10, 0xab, 0xcd, 0xef, 0xff];
        let encoded = hex_encode(&bytes);
        assert_eq!(encoded, "0001090a10abcdefff");
        assert_eq!(hex_decode(&encoded).unwrap(), bytes);
        assert_eq!(hex_decode("0001090A10AbCdEfFf").unwrap(), bytes);
    }

    #[test]
    fn hexadecimal_decode_rejects_odd_and_invalid_inputs() {
        assert!(matches!(hex_decode("0"), Err(DidError::InvalidHex)));
        assert!(matches!(hex_decode("0g"), Err(DidError::InvalidHex)));
        assert!(matches!(hex_decode("💩"), Err(DidError::InvalidHex)));
    }
}
