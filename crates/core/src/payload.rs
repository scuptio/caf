//! Payload tree construction and verification: files and directories form a
//! Merkle tree of content hashes, with files chunked for range reads and
//! per-chunk verification (see `doc/spec/en/container-format.md` §5).

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::hex;
use crate::manifest::{CHUNK_SIZE, EntryKind, PayloadLayout, PayloadNode, PayloadRef};

/// Build the payload directory tree from a filesystem root. Every file is
/// content-hashed as a Merkle tree over fixed-size chunks; the tree root is the
/// file's identity.
pub fn build_tree(root: &Path) -> Result<PayloadNode> {
    let mut node = build_node(root)?;
    node.name = String::new();
    Ok(node)
}

fn build_node(path: &Path) -> Result<PayloadNode> {
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if meta.is_dir() {
        let mut children = Vec::new();
        for entry in
            std::fs::read_dir(path).with_context(|| format!("readdir {}", path.display()))?
        {
            children.push(entry.with_context(|| format!("readdir entry {}", path.display()))?);
        }
        children.sort_by_key(|e| e.file_name());
        let mut entries = Vec::with_capacity(children.len());
        for child in children {
            entries.push(build_node(&child.path())?);
        }
        let hash = dir_hash(&entries)?;
        Ok(PayloadNode {
            kind: EntryKind::Dir,
            name: name_of(path)?,
            hash,
            length: 0,
            layout: None,
            chunks: Vec::new(),
            entries,
        })
    } else if meta.is_file() {
        let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let (hash, chunks) = file_hash(&data)?;
        let layout = if chunks.len() > 1 {
            Some(PayloadLayout::Range)
        } else {
            Some(PayloadLayout::Opaque)
        };
        Ok(PayloadNode {
            kind: EntryKind::File,
            name: name_of(path)?,
            hash,
            length: data.len() as u64,
            layout,
            chunks,
            entries: Vec::new(),
        })
    } else {
        anyhow::bail!("unsupported entry type at {}", path.display())
    }
}

fn name_of(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("invalid file name for {}", path.display()))
}

/// Split `data` into fixed-size chunks and return `(root_hash, chunk_hashes)`.
/// A single-chunk (or empty) file's root hash equals the plain SHA-256 of the
/// file, preserving the previous whole-file digest.
pub fn file_hash(data: &[u8]) -> Result<(String, Vec<String>)> {
    let mut chunks = Vec::new();
    for chunk in data.chunks(CHUNK_SIZE) {
        chunks.push(sha256_hex(chunk));
    }
    let root = merkle_root(&chunks)?;
    Ok((root, chunks))
}

/// Recompute a file's chunk hashes and Merkle root from its raw bytes. Used by
/// the verifier; mirrors `file_hash`.
pub fn verify_file(data: &[u8]) -> Result<String> {
    let (root, _) = file_hash(data)?;
    Ok(root)
}

/// SHA-256 of `data`, hex-encoded — the same digest used for chunk hashes.
pub fn chunk_hash(data: &[u8]) -> String {
    sha256_hex(data)
}

/// Number of fixed-size chunks a `length`-byte file is split into.
pub fn chunk_count(length: u64) -> u64 {
    length.div_ceil(CHUNK_SIZE as u64)
}

/// Byte range `[start, end)` of chunk `index` within a `length`-byte file.
pub fn chunk_range(length: u64, index: u64) -> (u64, u64) {
    let start = index * CHUNK_SIZE as u64;
    let end = (start + CHUNK_SIZE as u64).min(length);
    (start, end)
}

/// Merkle root over chunk hashes (hex-encoded 32-byte digests). Odd levels pad
/// by duplicating the last element; parents are `SHA256(left || right)`.
pub fn merkle_root(hex_hashes: &[String]) -> Result<String> {
    if hex_hashes.is_empty() {
        return Ok(sha256_hex(b""));
    }
    let mut level: Vec<Vec<u8>> = hex_hashes
        .iter()
        .map(|h| hex::decode(h))
        .collect::<Result<_>>()?;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let mut h = Sha256::new();
            h.update(&pair[0]);
            h.update(pair.get(1).unwrap_or(&pair[0]));
            next.push(h.finalize().to_vec());
        }
        level = next;
    }
    Ok(hex::encode(&level[0]))
}

fn dir_hash(entries: &[PayloadNode]) -> Result<String> {
    let mut h = Sha256::new();
    for e in entries {
        h.update(e.kind.as_str().as_bytes());
        h.update([0x00]);
        h.update((e.name.len() as u64).to_le_bytes());
        h.update(e.name.as_bytes());
        h.update(hex::decode(&e.hash)?);
    }
    Ok(hex::encode(&h.finalize()))
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(&h.finalize())
}

/// Look up a payload tree node by `/`-separated path.
pub fn find<'a>(root: &'a PayloadNode, path: &str) -> Option<&'a PayloadNode> {
    if path == "/" || path.is_empty() {
        return Some(root);
    }
    let mut node = root;
    for part in path.split('/').filter(|s| !s.is_empty()) {
        node = node.entries.iter().find(|e| e.name == part)?;
    }
    Some(node)
}

/// Validate the multi-payload mount rules: names are unique, safe path
/// segments, and no named payload collides with a top-level entry of the
/// default (first) payload, whose tree is mounted at `/`.
pub fn validate_payloads(payloads: &[PayloadRef]) -> Result<()> {
    let pairs: Vec<(&str, &PayloadNode)> = payloads
        .iter()
        .map(|p| (p.name.as_str(), &p.root))
        .collect();
    validate_mounts(&pairs)
}

/// [`validate_payloads`] over `(name, tree)` pairs.
pub fn validate_mounts(pairs: &[(&str, &PayloadNode)]) -> Result<()> {
    let mut names = std::collections::HashSet::with_capacity(pairs.len());
    for (name, _) in pairs {
        let name = *name;
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\']) {
            bail!("invalid payload name '{name}'");
        }
        if !names.insert(name) {
            bail!("duplicate payload name '{name}'");
        }
    }
    if let Some((_, default_root)) = pairs.first() {
        for entry in &default_root.entries {
            if pairs[1..].iter().any(|(name, _)| *name == entry.name) {
                bail!(
                    "payload name '{}' collides with a top-level entry of the default payload",
                    entry.name
                );
            }
        }
    }
    Ok(())
}

/// Resolve a payload by name; "" selects the default (first) payload.
pub fn resolve_payload<'a>(payloads: &'a [PayloadRef], name: &str) -> Result<&'a PayloadRef> {
    if name.is_empty() {
        return payloads
            .first()
            .context("access scope on an artifact without payloads");
    }
    payloads
        .iter()
        .find(|p| p.name == name)
        .with_context(|| format!("unknown payload '{name}'"))
}

/// Recompute every directory hash in the tree bottom-up. Structural
/// consistency only — no payload bytes are involved.
pub fn verify_tree(node: &PayloadNode) -> Result<()> {
    if node.kind == EntryKind::File {
        return Ok(());
    }
    for child in &node.entries {
        verify_tree(child)?;
    }
    let recomputed = dir_hash(&node.entries)?;
    if recomputed != node.hash {
        bail!("directory '{}' hash mismatch", node.name);
    }
    Ok(())
}

/// Verify an ed25519 `signature` over `msg` with the embedded `pubkey`.
pub fn verify_signature(pubkey: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pubkey_arr: Result<[u8; 32], _> = pubkey.try_into();
    let sig_arr: Result<[u8; 64], _> = sig.try_into();
    let (Ok(pubkey_arr), Ok(sig_arr)) = (pubkey_arr, sig_arr) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pubkey_arr) else {
        return false;
    };
    verifying_key
        .verify(msg, &Signature::from_bytes(&sig_arr))
        .is_ok()
}

/// SHA-256 of the embedded ed25519 public key — the signer's fingerprint.
pub fn signer_fingerprint(pubkey: &[u8]) -> String {
    sha256_hex(pubkey)
}

/// Depth-first listing of `(path, hash, length)` for every file, in the same
/// deterministic order the build uses for directory entries and layout.
pub fn collect_files(node: &PayloadNode, parent: &str, out: &mut Vec<(String, String, u64)>) {
    let path = if node.name.is_empty() {
        parent.to_string()
    } else {
        format!("{}/{}", parent, node.name)
    };
    if node.kind == EntryKind::File {
        out.push((path, node.hash.clone(), node.length));
    } else {
        for c in &node.entries {
            collect_files(c, &path, out);
        }
    }
}
