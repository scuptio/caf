use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::hex;
use crate::manifest::{EntryKind, PayloadLayout, PayloadNode, CHUNK_SIZE};

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
        let data =
            std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
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
