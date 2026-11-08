//! Lowercase hexadecimal encoding and decoding.
//!
//! Every hash in the container format (manifest, directory entries, payload
//! tree) is stored as a hex string, so this is the canonical text
//! representation of 32-byte SHA-256 digests throughout the crate.

use anyhow::{Result, bail};

const TABLE: &[u8; 16] = b"0123456789abcdef";

/// Hex-encode `bytes` (lowercase, no separators or `0x` prefix).
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode a hex string, rejecting odd lengths and non-hex digits.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        bail!("hex string has odd length");
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.as_chunks::<2>().0 {
        let hi = hex_val(chunk[0]).ok_or_else(|| anyhow::anyhow!("invalid hex digit"))?;
        let lo = hex_val(chunk[1]).ok_or_else(|| anyhow::anyhow!("invalid hex digit"))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
