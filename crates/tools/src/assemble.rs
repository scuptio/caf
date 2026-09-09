use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::hex;
use crate::layout::{self, Layout, FLAG_SIGNED};
use crate::manifest::*;
use crate::payload;

const LAYOUT_MAX_ITERS: usize = 16;

pub struct BuildOutput {
    pub bytes: Vec<u8>,
    pub manifest: Manifest,
}

pub fn assemble(cfg: &Config, base: &Path) -> Result<BuildOutput> {
    let interface_bytes = load_interface(cfg, base)?;
    let interface_hash = sha256_hex(&interface_bytes);

    let (wasm_blobs, wasm_hashes) = load_components(cfg, base)?;

    let payload_root = payload::build_tree(&base.join(&cfg.payload.root))?;
    let payload_root_hash = payload_root.hash.clone();

    let components = build_components(cfg, &payload_root, &wasm_hashes, &wasm_blobs)?;

    let mut capabilities = cfg.capabilities.clone();
    for c in &cfg.components {
        for cap in &c.capabilities {
            if !capabilities.contains(cap) {
                capabilities.push(cap.clone());
            }
        }
    }

    let mut manifest = Manifest {
        name: cfg.name.clone(),
        version: cfg.version.clone(),
        format_version: cfg.format_version,
        interface: InterfaceRef {
            inline: false,
            offset: 0,
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
            offset: 0,
            length: 0,
            hash: payload_root_hash.clone(),
            compressed: None,
        }],
        hashes: SectionHashes {
            interface: interface_hash.clone(),
            wasm: wasm_hashes.clone(),
            payload: vec![payload_root_hash.clone()],
            manifest: ZERO_HASH.to_string(),
            root: ZERO_HASH.to_string(),
        },
    };

    let directory = build_directory(&manifest);
    let directory_bytes = cbor_bytes(&directory)?;

    let component_lens: Vec<u64> = wasm_blobs.iter().map(|b| b.len() as u64).collect();
    let mut file_lens = Vec::new();
    payload::collect_file_lengths(&manifest.payloads[0].root, &mut file_lens);

    let signed = cfg.sign.is_some();
    let layout = resolve_layout(
        &mut manifest,
        &component_lens,
        &file_lens,
        interface_bytes.len() as u64,
        directory_bytes.len() as u64,
        signed,
    )?;

    let manifest_bytes = cbor_bytes(&manifest)?;
    let manifest_hash = sha256_hex(&manifest_bytes);

    let mut root_hasher = Sha256::new();
    root_hasher.update(hex::decode(&manifest_hash)?);
    root_hasher.update(hex::decode(&interface_hash)?);
    for w in &wasm_hashes {
        root_hasher.update(hex::decode(w)?);
    }
    root_hasher.update(hex::decode(&payload_root_hash)?);
    let digest = root_hasher.finalize();
    let mut root_hash_raw = [0u8; 32];
    root_hash_raw.copy_from_slice(&digest);
    let root_hash = hex::encode(&root_hash_raw);

    manifest.hashes.manifest = manifest_hash;
    manifest.hashes.root = root_hash;
    let final_manifest_bytes = cbor_bytes(&manifest)?;

    let mut out = Vec::new();
    let flags = if signed { FLAG_SIGNED } else { 0 };
    layout::write_header(&mut out, &layout, cfg.format_version, &root_hash_raw, flags);
    pad_to(&mut out, layout.manifest_offset);
    out.extend_from_slice(&final_manifest_bytes);
    pad_to(&mut out, layout.interface_offset);
    out.extend_from_slice(&interface_bytes);
    pad_to(&mut out, layout.directory_offset);
    out.extend_from_slice(&directory_bytes);

    for (i, blob) in wasm_blobs.iter().enumerate() {
        pad_to(&mut out, layout.component_offsets[i]);
        out.extend_from_slice(blob);
    }

    let mut blobs: Vec<(u64, Vec<u8>)> = Vec::new();
    collect_payload_blobs(
        &manifest.payloads[0].root,
        &base.join(&cfg.payload.root),
        Path::new(""),
        &mut blobs,
    )?;
    for (offset, data) in &blobs {
        pad_to(&mut out, *offset);
        out.extend_from_slice(data);
    }

    if signed {
        pad_to(&mut out, layout.signature_offset);
        let seed = cfg
            .sign
            .as_ref()
            .map(|s| s.seed.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing sign.seed"))?;
        let (pubkey, sig) = sign_manifest(seed, &final_manifest_bytes)?;
        out.extend_from_slice(&pubkey);
        out.extend_from_slice(&sig);
    }

    Ok(BuildOutput {
        bytes: out,
        manifest,
    })
}

fn resolve_layout(
    manifest: &mut Manifest,
    component_lens: &[u64],
    file_lens: &[u64],
    interface_len: u64,
    directory_len: u64,
    signed: bool,
) -> Result<Layout> {
    let mut len = 0u64;
    for _ in 0..LAYOUT_MAX_ITERS {
        let l = layout::compute(len, interface_len, directory_len, component_lens, file_lens, signed);
        apply_layout(manifest, &l);
        let new_len = cbor_bytes(manifest)?.len() as u64;
        if new_len == len {
            return Ok(l);
        }
        len = new_len;
    }
    bail!("layout did not converge");
}

fn apply_layout(manifest: &mut Manifest, l: &Layout) {
    manifest.interface.offset = l.interface_offset;
    manifest.interface.length = l.interface_len;
    for (i, c) in manifest.components.iter_mut().enumerate() {
        c.offset = l.component_offsets[i];
    }
    if let Some(p) = manifest.payloads.first_mut() {
        p.offset = l.payload_offset;
        p.length = l.payload_len;
        let mut idx = 0usize;
        payload::assign_file_offsets(&mut p.root, &l.file_offsets, &mut idx);
    }
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
                mode: "read".to_string(),
            });
        }
        out.push(ComponentRef {
            name: c.name.clone(),
            world: c.world.clone(),
            offset: 0,
            length: wasm_blobs[i].len() as u64,
            hash: wasm_hashes[i].clone(),
            exports: Vec::new(),
            access,
        });
    }
    Ok(out)
}

#[derive(Serialize)]
struct SectionEntry {
    kind: String,
    name: String,
    hash: String,
}

fn build_directory(manifest: &Manifest) -> Vec<SectionEntry> {
    let mut out = Vec::new();
    for c in &manifest.components {
        out.push(SectionEntry {
            kind: "wasm".to_string(),
            name: c.name.clone(),
            hash: c.hash.clone(),
        });
    }
    let mut files = Vec::new();
    payload::collect_files(&manifest.payloads[0].root, "", &mut files);
    for (path, hash) in files {
        out.push(SectionEntry {
            kind: "payload".to_string(),
            name: path,
            hash,
        });
    }
    out
}

fn collect_payload_blobs(node: &PayloadNode, base: &Path, rel: &Path, out: &mut Vec<(u64, Vec<u8>)>) -> Result<()> {
    if node.kind == "file" {
        let data = std::fs::read(base.join(rel))
            .with_context(|| format!("read payload {}", base.join(rel).display()))?;
        out.push((node.offset, data));
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
