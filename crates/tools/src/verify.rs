use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::hex;
use crate::layout::{self, TAG_COMPONENT, TAG_MANIFEST, TAG_PAYLOAD, TAG_SIGNATURE};
use crate::manifest::*;
use crate::payload;

pub struct VerifyReport {
    pub name: String,
    pub version: String,
    pub root_hash: String,
    pub manifest_hash: String,
    pub components: usize,
    pub payload_files: usize,
    pub capabilities: Vec<CapabilityId>,
    pub signed: bool,
    pub signature_valid: Option<bool>,
}

/// Open-time verification: recompute every section hash, the manifest hash, the
/// root hash, access-scope bindings, and (if present) the ed25519 signature.
pub fn verify(path: &Path) -> Result<VerifyReport> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    verify_bytes(&bytes)
}

pub fn verify_bytes(bytes: &[u8]) -> Result<VerifyReport> {
    let header = layout::read_header(bytes)?;

    let manifest_bytes = layout::slice(bytes, header.manifest_offset, header.manifest_len)?;
    let interface_bytes = layout::slice(bytes, header.interface_offset, header.interface_len)?;
    let directory_bytes = layout::slice(bytes, header.directory_offset, header.directory_len)?;

    let manifest: Manifest =
        ciborium::de::from_reader(manifest_bytes).context("decode manifest")?;
    let entries = layout::decode_directory(directory_bytes)?;

    // 0. Header/manifest version consistency.
    if header.format_version != manifest.format_version {
        bail!(
            "format version mismatch: header {}, manifest {}",
            header.format_version,
            manifest.format_version
        );
    }

    // 1. Manifest hash (over the exact manifest bytes in the file).
    let manifest_hash = sha256_hex(manifest_bytes);
    let manifest_entry = entries
        .iter()
        .find(|e| e.tag == TAG_MANIFEST)
        .context("directory has no manifest entry")?;
    if manifest_entry.hash != decode_hash(&manifest_hash)? {
        bail!("manifest hash mismatch");
    }

    // 2. Interface.
    let interface_hash = sha256_hex(interface_bytes);
    if interface_hash != manifest.hashes.interface {
        bail!("interface hash mismatch");
    }
    if interface_hash != manifest.interface.hash {
        bail!("interface hash mismatch (manifest ref)");
    }

    // 3. Components.
    let component_entries: Vec<_> = entries
        .iter()
        .filter(|e| e.tag == TAG_COMPONENT)
        .collect();
    if component_entries.len() != manifest.components.len() {
        bail!(
            "component count mismatch: directory {}, manifest {}",
            component_entries.len(),
            manifest.components.len()
        );
    }
    if manifest.hashes.wasm.len() != manifest.components.len() {
        bail!("wasm hash count mismatch");
    }
    let mut wasm_hashes = Vec::with_capacity(manifest.components.len());
    for (i, comp) in manifest.components.iter().enumerate() {
        let e = component_entries[i];
        let data = layout::slice(bytes, e.offset, e.length)?;
        let h = sha256_hex(data);
        if h != comp.hash {
            bail!("component '{}' hash mismatch", comp.name);
        }
        if h != manifest.hashes.wasm[i] {
            bail!("component '{}' hash mismatch (section hashes)", comp.name);
        }
        if e.hash != decode_hash(&h)? {
            bail!("component '{}' directory hash mismatch", comp.name);
        }
        wasm_hashes.push(h);
    }

    // 4. Payload: file chunk-Merkle hashes + tree structure + access scopes.
    let payload_root = &manifest.payloads[0].root;
    let mut file_list: Vec<(String, String, u64)> = Vec::new();
    payload::collect_files(payload_root, "", &mut file_list);

    let payload_entries: Vec<_> = entries.iter().filter(|e| e.tag == TAG_PAYLOAD).collect();
    if payload_entries.len() != file_list.len() {
        bail!(
            "payload file count mismatch: directory {}, tree {}",
            payload_entries.len(),
            file_list.len()
        );
    }
    for (i, (path, expected_hash, _len)) in file_list.iter().enumerate() {
        let e = payload_entries[i];
        let data = layout::slice(bytes, e.offset, e.length)?;
        let h = payload::verify_file(data)?;
        if &h != expected_hash {
            bail!("payload '{path}' hash mismatch");
        }
        if e.hash != decode_hash(&h)? {
            bail!("payload '{path}' directory hash mismatch");
        }
    }
    verify_tree(payload_root)?;
    if manifest.hashes.payload.len() != 1 || manifest.hashes.payload[0] != payload_root.hash {
        bail!("payload root hash mismatch");
    }

    // 5. Access scopes must resolve to real, hash-matching nodes.
    for comp in &manifest.components {
        for scope in &comp.access {
            let node = payload::find(payload_root, &scope.path)
                .with_context(|| format!("access scope '{}' not found", scope.path))?;
            if node.hash != scope.hash {
                bail!("access scope '{}' hash mismatch", scope.path);
            }
        }
    }

    // 6. Root hash.
    let root_hash = compute_root_hash(&manifest_hash, &interface_hash, &wasm_hashes, &payload_root.hash)?;
    if root_hash != header.root_hash {
        bail!("root hash mismatch");
    }

    // 7. Signature (optional).
    let signed = header.flags & layout::FLAG_SIGNED != 0;
    let mut signature_valid = None;
    if signed {
        let sig_entry = entries
            .iter()
            .find(|e| e.tag == TAG_SIGNATURE)
            .context("signed artifact has no signature directory entry")?;
        let sig_bytes = layout::slice(bytes, sig_entry.offset, sig_entry.length)?;
        if sig_bytes.len() != 96 {
            bail!("signature section has unexpected length {}", sig_bytes.len());
        }
        signature_valid = Some(verify_signature(&sig_bytes[..32], &sig_bytes[32..], manifest_bytes));
    }

    Ok(VerifyReport {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        root_hash: hex::encode(&root_hash),
        manifest_hash,
        components: manifest.components.len(),
        payload_files: file_list.len(),
        capabilities: manifest.capabilities.clone(),
        signed,
        signature_valid,
    })
}

fn verify_tree(node: &PayloadNode) -> Result<()> {
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

fn compute_root_hash(
    manifest_hash: &str,
    interface_hash: &str,
    wasm_hashes: &[String],
    payload_root_hash: &str,
) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(hex::decode(manifest_hash)?);
    h.update(hex::decode(interface_hash)?);
    for w in wasm_hashes {
        h.update(hex::decode(w)?);
    }
    h.update(hex::decode(payload_root_hash)?);
    let digest = h.finalize();
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&digest);
    Ok(raw)
}

fn verify_signature(pubkey: &[u8], sig: &[u8], msg: &[u8]) -> bool {
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

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(&h.finalize())
}

fn decode_hash(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("hash is not 32 bytes"))
}
