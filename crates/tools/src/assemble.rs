use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::exports;
use crate::hex;
use crate::layout::{
    self, DirectoryEntry, FLAG_SIGNED, TAG_COMPONENT, TAG_MANIFEST, TAG_PAYLOAD, TAG_SIGNATURE,
};
use crate::manifest::*;
use crate::payload;

pub struct BuildOutput {
    pub bytes: Vec<u8>,
    pub manifest: Manifest,
}

pub fn assemble(cfg: &Config, base: &Path) -> Result<BuildOutput> {
    // 1. Interface (WIT text) and its hash.
    let interface_bytes = load_interface(cfg, base)?;
    let interface_hash = sha256_hex(&interface_bytes);

    // 2. WASM component blobs, hashes, and extracted exports.
    let (wasm_blobs, wasm_hashes) = load_components(cfg, base)?;

    // 3. Payload tree (chunked Merkle hashing).
    let payload_root = payload::build_tree(&base.join(&cfg.payload.root))?;
    let payload_root_hash = payload_root.hash.clone();

    // 4. Component refs: access scopes (path + content hash) and exports.
    let components = build_components(cfg, &payload_root, &wasm_hashes, &wasm_blobs)?;

    // 5. Capabilities (parsed and deduplicated).
    let capabilities = collect_capabilities(cfg)?;

    // 6. Manifest — no absolute offsets (those live in the directory).
    let manifest = Manifest {
        name: cfg.name.clone(),
        version: cfg.version.clone(),
        format_version: cfg.format_version,
        interface: InterfaceRef {
            inline: false,
            length: interface_bytes.len() as u64,
            hash: interface_hash.clone(),
        },
        components,
        capabilities,
        execution: ExecutionProfile {
            profile: cfg.execution.profile.clone(),
            deterministic: cfg.execution.deterministic,
        },
        resources: ResourceLimits {
            memory_max: cfg.resources.memory_max,
            cpu_fuel: cfg.resources.cpu_fuel,
            output_max: cfg.resources.output_max,
        },
        policy: CapabilityPolicy {
            self_read: cfg.policy.self_read,
            network: cfg.policy.network,
            filesystem: cfg.policy.filesystem,
            clock: cfg.policy.clock,
            random: cfg.policy.random,
        },
        provenance: Provenance {
            data: Publisher::empty(),
            algorithm: Publisher::empty(),
            artifact: Publisher {
                publisher: cfg.name.clone(),
                signature: None,
            },
        },
        payloads: vec![PayloadRef {
            root: payload_root,
            media_type: cfg.payload.media_type.clone(),
            length: 0,
            hash: payload_root_hash.clone(),
            compressed: None,
        }],
        hashes: SectionHashes {
            interface: interface_hash.clone(),
            wasm: wasm_hashes.clone(),
            payload: vec![payload_root_hash.clone()],
        },
    };

    // 7. Manifest bytes and manifest hash (over the *final* manifest bytes).
    let manifest_bytes = cbor_bytes(&manifest)?;
    let manifest_hash = sha256_hex(&manifest_bytes);

    // 8. Section inventory for layout + directory (deterministic DFS order).
    let component_lens: Vec<u64> = wasm_blobs.iter().map(|b| b.len() as u64).collect();
    let mut file_list: Vec<(String, String, u64)> = Vec::new();
    payload::collect_files(&manifest.payloads[0].root, "", &mut file_list);
    let file_lens: Vec<u64> = file_list.iter().map(|(_, _, len)| *len).collect();

    let signed = cfg.sign.is_some();
    let entry_count = 1 + component_lens.len() + file_lens.len() + usize::from(signed);
    let directory_len = 4 + (entry_count * layout::DIRECTORY_ENTRY_SIZE) as u64;

    // 9. Layout in a single pass (no self-referential offsets).
    let layout = layout::compute(
        manifest_bytes.len() as u64,
        interface_bytes.len() as u64,
        directory_len,
        &component_lens,
        &file_lens,
        signed,
    );

    // 10. Directory (TOC): manifest, components, payload files, signature.
    let mut entries: Vec<DirectoryEntry> = Vec::with_capacity(entry_count);
    entries.push(DirectoryEntry {
        tag: TAG_MANIFEST,
        offset: layout.manifest_offset,
        length: manifest_bytes.len() as u64,
        hash: decode_hash(&manifest_hash)?,
    });
    for (i, blob) in wasm_blobs.iter().enumerate() {
        entries.push(DirectoryEntry {
            tag: TAG_COMPONENT,
            offset: layout.component_offsets[i],
            length: blob.len() as u64,
            hash: decode_hash(&wasm_hashes[i])?,
        });
    }
    for (i, (_, hash, len)) in file_list.iter().enumerate() {
        entries.push(DirectoryEntry {
            tag: TAG_PAYLOAD,
            offset: layout.file_offsets[i],
            length: *len,
            hash: decode_hash(hash)?,
        });
    }
    if signed {
        entries.push(DirectoryEntry {
            tag: TAG_SIGNATURE,
            offset: layout.signature_offset,
            length: 96,
            hash: [0u8; 32],
        });
    }
    let directory_bytes = layout::encode_directory(&entries);

    // 11. Root hash = SHA256(ManifestHash || InterfaceHash || WasmHash* || PayloadHash*).
    let root_hash = compute_root_hash(&manifest_hash, &interface_hash, &wasm_hashes, &payload_root_hash)?;

    // 12. Write the file.
    let mut out = Vec::new();
    let flags = if signed { FLAG_SIGNED } else { 0 };
    layout::write_header(&mut out, &layout, cfg.format_version, &root_hash, flags);
    pad_to(&mut out, layout.manifest_offset);
    out.extend_from_slice(&manifest_bytes);
    pad_to(&mut out, layout.interface_offset);
    out.extend_from_slice(&interface_bytes);
    pad_to(&mut out, layout.directory_offset);
    out.extend_from_slice(&directory_bytes);

    for (i, blob) in wasm_blobs.iter().enumerate() {
        pad_to(&mut out, layout.component_offsets[i]);
        out.extend_from_slice(blob);
    }

    let mut blobs: Vec<Vec<u8>> = Vec::new();
    collect_payload_blobs(
        &manifest.payloads[0].root,
        &base.join(&cfg.payload.root),
        Path::new(""),
        &mut blobs,
    )?;
    for (i, data) in blobs.iter().enumerate() {
        pad_to(&mut out, layout.file_offsets[i]);
        out.extend_from_slice(data);
    }

    if signed {
        pad_to(&mut out, layout.signature_offset);
        let seed = cfg
            .sign
            .as_ref()
            .map(|s| s.seed.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing sign.seed"))?;
        let (pubkey, sig) = sign_manifest(seed, &manifest_bytes)?;
        out.extend_from_slice(&pubkey);
        out.extend_from_slice(&sig);
    }

    Ok(BuildOutput {
        bytes: out,
        manifest,
    })
}

fn collect_capabilities(cfg: &Config) -> Result<Vec<CapabilityId>> {
    let mut out: Vec<CapabilityId> = Vec::new();
    for cap in &cfg.capabilities {
        out.push(CapabilityId::parse(cap).map_err(anyhow::Error::msg)?);
    }
    for c in &cfg.components {
        for cap in &c.capabilities {
            let parsed = CapabilityId::parse(cap).map_err(anyhow::Error::msg)?;
            if !out.contains(&parsed) {
                out.push(parsed);
            }
        }
    }
    Ok(out)
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

fn load_interface(cfg: &Config, base: &Path) -> Result<Vec<u8>> {
    let mut text = String::new();
    for (i, p) in cfg.interfaces.iter().enumerate() {
        if i > 0 {
            text.push('\n');
        }
        let s = std::fs::read_to_string(base.join(p)).with_context(|| format!("read wit {p}"))?;
        text.push_str(&s);
    }
    Ok(text.into_bytes())
}

fn load_components(cfg: &Config, base: &Path) -> Result<(Vec<Vec<u8>>, Vec<String>)> {
    let mut blobs = Vec::new();
    let mut hashes = Vec::new();
    for c in &cfg.components {
        let b =
            std::fs::read(base.join(&c.path)).with_context(|| format!("read wasm {}", c.path))?;
        hashes.push(sha256_hex(&b));
        blobs.push(b);
    }
    Ok((blobs, hashes))
}

fn build_components(
    cfg: &Config,
    payload_root: &PayloadNode,
    wasm_hashes: &[String],
    wasm_blobs: &[Vec<u8>],
) -> Result<Vec<ComponentRef>> {
    let mut out = Vec::with_capacity(cfg.components.len());
    for (i, c) in cfg.components.iter().enumerate() {
        let mut access = Vec::with_capacity(c.access.len());
        for a in &c.access {
            let node = payload::find(payload_root, a)
                .with_context(|| format!("access path '{a}' not found in payload"))?;
            access.push(AccessScope {
                path: a.clone(),
                hash: node.hash.clone(),
                mode: AccessMode::Read,
            });
        }
        out.push(ComponentRef {
            name: c.name.clone(),
            world: c.world.clone(),
            length: wasm_blobs[i].len() as u64,
            hash: wasm_hashes[i].clone(),
            exports: exports::extract_exports(&wasm_blobs[i]),
            access,
        });
    }
    Ok(out)
}

fn collect_payload_blobs(
    node: &PayloadNode,
    base: &Path,
    rel: &Path,
    out: &mut Vec<Vec<u8>>,
) -> Result<()> {
    if node.kind == EntryKind::File {
        let data = std::fs::read(base.join(rel))
            .with_context(|| format!("read payload {}", base.join(rel).display()))?;
        out.push(data);
    } else {
        for c in &node.entries {
            let child_rel = if rel.as_os_str().is_empty() {
                PathBuf::from(&c.name)
            } else {
                rel.join(&c.name)
            };
            collect_payload_blobs(c, base, &child_rel, out)?;
        }
    }
    Ok(())
}

fn sign_manifest(seed_hex: &str, msg: &[u8]) -> Result<([u8; 32], [u8; 64])> {
    use ed25519_dalek::{Signer, SigningKey};

    let seed_bytes = hex::decode(seed_hex).map_err(|e| anyhow::anyhow!("invalid sign.seed: {e}"))?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("sign.seed must be 32 bytes (64 hex chars)"))?;
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey = signing_key.verifying_key().to_bytes();
    let sig = signing_key.sign(msg);
    Ok((pubkey, sig.to_bytes()))
}

fn cbor_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)
        .map_err(|e| anyhow::anyhow!("cbor encode failed: {e}"))?;
    Ok(buf)
}

fn pad_to(out: &mut Vec<u8>, offset: u64) {
    let cur = out.len() as u64;
    if cur < offset {
        out.resize(offset as usize, 0);
    }
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
