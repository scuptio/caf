use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::hex;
use crate::manifest::PayloadNode;

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
            let entry = entry.with_context(|| format!("readdir entry {}", path.display()))?;
            children.push(entry);
        }
        children.sort_by_key(|e| e.file_name());
        let mut entries = Vec::with_capacity(children.len());
        for child in children {
            entries.push(build_node(&child.path())?);
        }
        let hash = dir_hash(&entries)?;
        Ok(PayloadNode {
            kind: "dir".to_string(),
            name: name_of(path)?,
            hash,
            offset: 0,
            length: 0,
            layout: None,
            entries,
        })
    } else if meta.is_file() {
        let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let hash = sha256_hex(&data);
        Ok(PayloadNode {
            kind: "file".to_string(),
            name: name_of(path)?,
            hash,
            offset: 0,
            length: data.len() as u64,
            layout: Some("opaque".to_string()),
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

fn dir_hash(entries: &[PayloadNode]) -> Result<String> {
    let mut h = Sha256::new();
    for e in entries {
        h.update(e.kind.as_bytes());
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

pub fn collect_files(node: &PayloadNode, parent: &str, out: &mut Vec<(String, String)>) {
    let path = if node.name.is_empty() {
        parent.to_string()
    } else {
        format!("{}/{}", parent, node.name)
    };
    if node.kind == "file" {
        out.push((path, node.hash.clone()));
    } else {
        for c in &node.entries {
            collect_files(c, &path, out);
        }
    }
}

pub fn collect_file_lengths(node: &PayloadNode, out: &mut Vec<u64>) {
    if node.kind == "file" {
        out.push(node.length);
    } else {
        for c in &node.entries {
            collect_file_lengths(c, out);
        }
    }
}

pub fn assign_file_offsets(node: &mut PayloadNode, offsets: &[u64], idx: &mut usize) {
    if node.kind == "file" {
        node.offset = offsets[*idx];
        *idx += 1;
    } else {
        for c in node.entries.iter_mut() {
            assign_file_offsets(c, offsets, idx);
        }
    }
}
