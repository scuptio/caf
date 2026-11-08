//! Full open-time verification of a `.caf` artifact: every section hash, the
//! manifest hash, the domain-separated root hash, access-scope bindings, and
//! the optional ed25519 signature (see `doc/spec/container-format.md`).

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::hex;
use crate::identity;
use crate::layout::{self, TAG_COMPONENT, TAG_MANIFEST, TAG_PAYLOAD, TAG_SIGNATURE};
use crate::manifest::*;
use crate::payload;

/// Summary of a successful verification, for display by `caf-tool verify`.
pub struct VerifyReport {
    /// Artifact name from the manifest.
    pub name: String,
    /// Artifact version from the manifest.
    pub version: String,
    /// Domain-separated root hash (hex) — the artifact's content identity.
    pub root_hash: String,
    /// SHA-256 (hex) of the manifest bytes.
    pub manifest_hash: String,
    /// Number of embedded WASM components.
    pub components: usize,
    /// Number of payload files.
    pub payload_files: usize,
    /// Capabilities the artifact exposes.
    pub capabilities: Vec<CapabilityId>,
    /// Whether the artifact carries a signature section.
    pub signed: bool,
    /// Signature validity (`None` when the artifact is unsigned).
    pub signature_valid: Option<bool>,
    /// SHA-256 of the embedded ed25519 public key — the signer's fingerprint,
    /// for comparison against an external trust store.
    pub signer_fingerprint: Option<String>,
}

/// Open-time verification: recompute every section hash, the manifest hash, the
/// root hash, access-scope bindings, and (if present) the ed25519 signature.
pub fn verify(path: &Path) -> Result<VerifyReport> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    verify_bytes(&bytes)
}

/// In-memory equivalent of [`verify`]: verify artifact bytes already loaded
/// (or received) by the caller.
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
    let component_entries: Vec<_> = entries.iter().filter(|e| e.tag == TAG_COMPONENT).collect();
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
    //    This format version carries exactly one payload tree.
    if manifest.payloads.len() != 1 {
        bail!(
            "expected exactly one payload tree, got {}",
            manifest.payloads.len()
        );
    }
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
    payload::verify_tree(payload_root)?;
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

    // 6. Root hash (domain-separated, shared with the builder).
    let root_hash = identity::root_hash(
        &manifest_hash,
        &interface_hash,
        &wasm_hashes,
        &payload_root.hash,
    )?;
    if root_hash != header.root_hash {
        bail!("root hash mismatch");
    }

    // 7. Signature (optional).
    let signed = header.flags & layout::FLAG_SIGNED != 0;
    let mut signature_valid = None;
    let mut signer_fingerprint = None;
    if signed {
        let sig_entry = entries
            .iter()
            .find(|e| e.tag == TAG_SIGNATURE)
            .context("signed artifact has no signature directory entry")?;
        let sig_bytes = layout::slice(bytes, sig_entry.offset, sig_entry.length)?;
        if sig_bytes.len() != 96 {
            bail!(
                "signature section has unexpected length {}",
                sig_bytes.len()
            );
        }
        signer_fingerprint = Some(payload::signer_fingerprint(&sig_bytes[..32]));
        signature_valid = Some(payload::verify_signature(
            &sig_bytes[..32],
            &sig_bytes[32..],
            manifest_bytes,
        ));
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
        signer_fingerprint,
    })
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
