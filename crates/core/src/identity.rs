//! Content identity for CAF artifacts.
//!
//! The artifact identity is a single domain-separated root hash:
//!
//! ```text
//! RootHash = SHA256("CAF1"
//!                   || u64le(len) || ManifestHash
//!                   || u64le(len) || InterfaceHash
//!                   || u64le(n)   || (u64le(len) || WasmHash)*
//!                   || u64le(m)   || (u64le(len) || PayloadRootHash)*)
//! ```
//!
//! The domain separator, length prefixes, and explicit component count make the
//! hash input unambiguous to parse and leave room for multiple payloads or a
//! future hash-algorithm migration. The manifest hash transitively covers the
//! policy, execution profile, interface ref, component refs, access scopes, and
//! payload tree, so binding strength is equivalent to hashing those fields
//! directly — without redundant fields in the header.

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::hex;

/// Domain separator for the artifact root hash (CAF identity, version 1).
pub const ROOT_DOMAIN: &[u8] = b"CAF1";

fn write_prefixed(h: &mut Sha256, hex_hash: &str) -> Result<()> {
    let raw = hex::decode(hex_hash)?;
    h.update((raw.len() as u64).to_le_bytes());
    h.update(raw);
    Ok(())
}

/// Compute the domain-separated artifact root hash from the section hashes.
pub fn root_hash(
    manifest_hash: &str,
    interface_hash: &str,
    wasm_hashes: &[String],
    payload_root_hashes: &[String],
) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(ROOT_DOMAIN);
    write_prefixed(&mut h, manifest_hash)?;
    write_prefixed(&mut h, interface_hash)?;
    h.update((wasm_hashes.len() as u64).to_le_bytes());
    for w in wasm_hashes {
        write_prefixed(&mut h, w)?;
    }
    h.update((payload_root_hashes.len() as u64).to_le_bytes());
    for p in payload_root_hashes {
        write_prefixed(&mut h, p)?;
    }
    let digest = h.finalize();
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&digest);
    Ok(raw)
}
