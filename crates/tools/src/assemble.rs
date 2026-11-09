//! Assemble a `.caf` artifact from a build [`Config`]: hash the interface, build
//! the payload Merkle tree, bind components (access scopes + capability-bound
//! exports), compute layout and directory, derive the root hash, and optionally
//! sign the root hash (Encrypt-then-Sign: the signature always covers the
//! stored-bytes identity).
//!
//! With `[encrypt]` in the config the artifact is **sealed**: components,
//! payload, and the private manifest are AES-256-GCM encrypted under a content
//! key wrapped per recipient in the keybox section, the payload becomes a
//! single pow2-padded ciphertext blob, and the manifest section carries only
//! the public envelope (see `doc/spec/container-format.md` §7).

use anyhow::{Context, Result, bail};
use rand_core::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use caf_core::crypto;
use caf_core::hex;
use caf_core::layout::{
    self, DirectoryEntry, FLAG_ENCRYPTED, FLAG_SIGNED, TAG_COMPONENT, TAG_KEYBOX, TAG_MANIFEST,
    TAG_PAYLOAD, TAG_PRIVATE, TAG_SIGNATURE,
};
use caf_core::manifest::*;
use caf_core::payload;

use crate::config::{Config, EncryptConfig};
use crate::exports;
use crate::wit;

pub struct BuildOutput {
    pub bytes: Vec<u8>,
    pub manifest: Manifest,
    /// Sealed builds only: the public envelope manifest section.
    pub envelope: Option<Envelope>,
    /// Sealed builds only: the private manifest (plaintext form; the artifact
    /// stores only its ciphertext).
    pub private: Option<PrivateManifest>,
    /// Sealed builds only: the content key. Printed by `caf-tool build` only
    /// for convergent builds (`[encrypt] key_seed` set), where the key is a
    /// deterministic function of the seed and the plaintext identity.
    pub content_key: Option<[u8; 32]>,
}

pub fn assemble(cfg: &Config, base: &Path) -> Result<BuildOutput> {
    let prepared = prepare(cfg, base)?;
    if let Some(encrypt) = &cfg.encrypt {
        assemble_sealed(cfg, &prepared, encrypt)
    } else {
        assemble_plaintext(cfg, &prepared)
    }
}

/// Everything both assembly paths share: interface bytes, payload tree and
/// blobs, component blobs/refs, capabilities.
struct Prepared {
    interface_bytes: Vec<u8>,
    interface_hash: String,
    payload_root: PayloadNode,
    payload_blobs: Vec<Vec<u8>>,
    file_list: Vec<(String, String, u64)>,
    components: Components,
    capabilities: Vec<CapabilityId>,
}

fn prepare(cfg: &Config, base: &Path) -> Result<Prepared> {
    // 1. Interface (WIT text) and its hash.
    let interface_sources = load_interfaces(cfg, base)?;
    let interface_bytes = interface_sources.join("\n").into_bytes();
    let interface_hash = sha256_hex(&interface_bytes);

    // 2. Parse/validate the WIT once (when any interface file is declared).
    let wit = if interface_sources.is_empty() {
        None
    } else {
        Some(wit::parse(&interface_sources)?)
    };

    // 3. Payload tree (chunked Merkle hashing, over plaintext).
    let payload_root = payload::build_tree(&base.join(&cfg.payload.root))?;
    let mut file_list: Vec<(String, String, u64)> = Vec::new();
    payload::collect_files(&payload_root, "", &mut file_list);

    // 4. WASM components: load, optionally embed world metadata, hash, and
    //    build refs with access scopes + capability-bound exports.
    let components = build_components(cfg, base, &payload_root, &wit)?;

    // 5. Payload blobs in the same deterministic DFS order.
    let mut payload_blobs: Vec<Vec<u8>> = Vec::new();
    collect_payload_blobs(
        &payload_root,
        &base.join(&cfg.payload.root),
        Path::new(""),
        &mut payload_blobs,
    )?;

    // 6. Capabilities (parsed and deduplicated).
    let capabilities = collect_capabilities(cfg)?;

    Ok(Prepared {
        interface_bytes,
        interface_hash,
        payload_root,
        payload_blobs,
        file_list,
        components,
        capabilities,
    })
}

fn assemble_plaintext(cfg: &Config, p: &Prepared) -> Result<BuildOutput> {
    let payload_root_hash = p.payload_root.hash.clone();

    // Manifest — no absolute offsets (those live in the directory).
    let manifest = Manifest {
        name: cfg.name.clone(),
        version: cfg.version.clone(),
        format_version: cfg.format_version,
        interface: InterfaceRef {
            inline: false,
            length: p.interface_bytes.len() as u64,
            hash: p.interface_hash.clone(),
        },
        components: p.components.refs.clone(),
        capabilities: p.capabilities.clone(),
        execution: execution(cfg),
        resources: resources(cfg),
        policy: policy(cfg),
        provenance: provenance(cfg),
        payloads: vec![PayloadRef {
            root: p.payload_root.clone(),
            media_type: cfg.payload.media_type.clone(),
            length: 0,
            hash: payload_root_hash.clone(),
            compressed: None,
            padded_length: None,
            chunks: Vec::new(),
        }],
        hashes: SectionHashes {
            interface: p.interface_hash.clone(),
            wasm: p.components.hashes.clone(),
            payload: vec![payload_root_hash.clone()],
        },
    };

    let manifest_bytes = cbor_bytes(&manifest)?;
    let manifest_hash = sha256_hex(&manifest_bytes);

    // Section inventory for layout + directory (deterministic DFS order).
    let component_lens: Vec<u64> = p.components.blobs.iter().map(|b| b.len() as u64).collect();
    let file_lens: Vec<u64> = p.file_list.iter().map(|(_, _, len)| *len).collect();

    let signed = cfg.sign.is_some();
    let entry_count = 1 + component_lens.len() + file_lens.len() + usize::from(signed);
    let directory_len = 4 + (entry_count * layout::DIRECTORY_ENTRY_SIZE) as u64;

    // Layout in a single pass (no self-referential offsets).
    let layout = layout::compute(
        manifest_bytes.len() as u64,
        p.interface_bytes.len() as u64,
        directory_len,
        &component_lens,
        &file_lens,
        signed,
        None,
    );

    // Directory (TOC): manifest, components, payload files, signature.
    let mut entries: Vec<DirectoryEntry> = Vec::with_capacity(entry_count);
    entries.push(DirectoryEntry {
        tag: TAG_MANIFEST,
        offset: layout.manifest_offset,
        length: manifest_bytes.len() as u64,
        hash: decode_hash(&manifest_hash)?,
    });
    for (i, blob) in p.components.blobs.iter().enumerate() {
        entries.push(DirectoryEntry {
            tag: TAG_COMPONENT,
            offset: layout.component_offsets[i],
            length: blob.len() as u64,
            hash: decode_hash(&p.components.hashes[i])?,
        });
    }
    for (i, (_, hash, len)) in p.file_list.iter().enumerate() {
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

    // Root hash (domain-separated; shared with the verifier).
    let root_hash = caf_core::identity::root_hash(
        &manifest_hash,
        &p.interface_hash,
        &p.components.hashes,
        &payload_root_hash,
    )?;

    // Write the file.
    let mut out = Vec::new();
    let flags = if signed { FLAG_SIGNED } else { 0 };
    layout::write_header(&mut out, &layout, cfg.format_version, &root_hash, flags);
    pad_to(&mut out, layout.manifest_offset);
    out.extend_from_slice(&manifest_bytes);
    pad_to(&mut out, layout.interface_offset);
    out.extend_from_slice(&p.interface_bytes);
    pad_to(&mut out, layout.directory_offset);
    out.extend_from_slice(&directory_bytes);

    for (i, blob) in p.components.blobs.iter().enumerate() {
        pad_to(&mut out, layout.component_offsets[i]);
        out.extend_from_slice(blob);
    }
    for (i, data) in p.payload_blobs.iter().enumerate() {
        pad_to(&mut out, layout.file_offsets[i]);
        out.extend_from_slice(data);
    }

    if signed {
        pad_to(&mut out, layout.signature_offset);
        let (pubkey, sig) = sign_root_hash(cfg, &root_hash)?;
        out.extend_from_slice(&pubkey);
        out.extend_from_slice(&sig);
    }

    Ok(BuildOutput {
        bytes: out,
        manifest,
        envelope: None,
        private: None,
        content_key: None,
    })
}

fn assemble_sealed(cfg: &Config, p: &Prepared, encrypt: &EncryptConfig) -> Result<BuildOutput> {
    if encrypt.recipients.is_empty() {
        bail!("[encrypt] needs at least one recipient public key");
    }
    let recipients = encrypt
        .recipients
        .iter()
        .map(|r| crypto::parse_recipient(r))
        .collect::<Result<Vec<_>>>()?;
    let seed = match &encrypt.key_seed {
        Some(s) => Some(decode_seed("encrypt.key_seed", s)?),
        None => None,
    };

    // Payload blob: files concatenated in DFS order, pow2-padded with zeros.
    let mut blob_plain = Vec::new();
    for data in &p.payload_blobs {
        blob_plain.extend_from_slice(data);
    }
    let real_len = blob_plain.len() as u64;
    let padded = crypto::padded_len(real_len);
    blob_plain.resize(padded as usize, 0);

    // Content key: convergent (reproducible) when key_seed is set, else random.
    let content_key: [u8; 32] = match seed {
        Some(seed) => {
            let mut identity_input = Vec::new();
            identity_input.extend_from_slice(&decode_hash(&p.interface_hash)?);
            for h in &p.components.hashes {
                identity_input.extend_from_slice(&decode_hash(h)?);
            }
            identity_input.extend_from_slice(&decode_hash(&p.payload_root.hash)?);
            crypto::convergent_content_key(&seed, &sha256_raw(&identity_input))
        }
        None => {
            let mut key = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut key);
            key
        }
    };

    // Encrypt the payload blob per chunk; record ciphertext chunk hashes.
    let payload_key = crypto::section_key(&content_key, "payload");
    let chunk_total = payload::chunk_count(padded);
    let mut blob_ct = Vec::new();
    let mut blob_chunk_hashes = Vec::with_capacity(chunk_total as usize);
    for index in 0..chunk_total {
        let (cs, ce) = payload::chunk_range(padded, index);
        let ct = crypto::seal_chunk(&payload_key, index, &blob_plain[cs as usize..ce as usize])?;
        blob_chunk_hashes.push(sha256_hex(&ct));
        blob_ct.extend_from_slice(&ct);
    }
    let blob_hash = sha256_hex(&blob_ct);

    // Encrypt each component (single chunk per component section).
    let mut component_cts = Vec::with_capacity(p.components.blobs.len());
    let mut component_ct_hashes = Vec::with_capacity(p.components.blobs.len());
    for (i, blob) in p.components.blobs.iter().enumerate() {
        let key = crypto::section_key(&content_key, &format!("component/{i}"));
        let ct = crypto::seal_chunk(&key, 0, blob)?;
        component_ct_hashes.push(sha256_hex(&ct));
        component_cts.push(ct);
    }

    // Private manifest: everything the envelope hides.
    let private = PrivateManifest {
        name: cfg.name.clone(),
        version: cfg.version.clone(),
        components: p
            .components
            .refs
            .iter()
            .map(|c| PrivateComponent {
                name: c.name.clone(),
                world: c.world.clone(),
                hash: c.hash.clone(),
                exports: c.exports.clone(),
                access: c.access.clone(),
            })
            .collect(),
        provenance: provenance(cfg),
        payloads: vec![PayloadRef {
            root: p.payload_root.clone(),
            media_type: cfg.payload.media_type.clone(),
            length: real_len,
            hash: blob_hash.clone(),
            compressed: None,
            padded_length: Some(padded),
            chunks: blob_chunk_hashes,
        }],
    };
    let private_bytes = cbor_bytes(&private)?;
    let private_key = crypto::section_key(&content_key, "private");
    let private_ct = crypto::seal_chunk(&private_key, 0, &private_bytes)?;
    let private_ct_hash = sha256_hex(&private_ct);

    // Keybox: one anonymous stanza per recipient (deterministic ephemerals in
    // convergent builds).
    let mut stanzas = Vec::with_capacity(recipients.len());
    for recipient in &recipients {
        let ephemeral = match seed {
            Some(seed) => crypto::convergent_ephemeral(&seed, recipient)?,
            None => p256::SecretKey::random(&mut rand_core::OsRng),
        };
        stanzas.push(crypto::wrap_content_key(
            &content_key,
            recipient,
            &ephemeral,
        )?);
    }
    let keybox_bytes = crypto::encode_keybox(&stanzas);
    let keybox_hash = sha256_hex(&keybox_bytes);

    // Envelope: the public manifest of a sealed artifact.
    let envelope = Envelope {
        format_version: cfg.format_version,
        interface: InterfaceRef {
            inline: false,
            length: p.interface_bytes.len() as u64,
            hash: p.interface_hash.clone(),
        },
        components: component_cts
            .iter()
            .zip(&component_ct_hashes)
            .map(|(ct, hash)| SectionRef {
                length: ct.len() as u64,
                hash: hash.clone(),
            })
            .collect(),
        capabilities: p.capabilities.clone(),
        execution: execution(cfg),
        resources: resources(cfg),
        policy: policy(cfg),
        encryption: EncryptionInfo {
            aead: AeadAlgorithm::Aes256Gcm,
            wrap: KeyWrapAlgorithm::P256EcdhSha256,
            padding: PaddingProfile::Pow2,
        },
        private: SectionRef {
            length: private_ct.len() as u64,
            hash: private_ct_hash,
        },
        keybox: SectionRef {
            length: keybox_bytes.len() as u64,
            hash: keybox_hash.clone(),
        },
        payload: PayloadBlobRef {
            length: blob_ct.len() as u64,
            padded_length: padded,
            chunks: chunk_total,
            hash: blob_hash.clone(),
        },
    };
    let envelope_bytes = cbor_bytes(&envelope)?;
    let envelope_hash = sha256_hex(&envelope_bytes);

    // Layout + directory: manifest(envelope), interface, directory, keybox,
    // private, components, payload blob, signature.
    let signed = cfg.sign.is_some();
    let component_lens: Vec<u64> = component_cts.iter().map(|c| c.len() as u64).collect();
    let entry_count = 3 + component_lens.len() + 1 + usize::from(signed);
    let directory_len = 4 + (entry_count * layout::DIRECTORY_ENTRY_SIZE) as u64;
    let layout = layout::compute(
        envelope_bytes.len() as u64,
        p.interface_bytes.len() as u64,
        directory_len,
        &component_lens,
        &[blob_ct.len() as u64],
        signed,
        Some((keybox_bytes.len() as u64, private_ct.len() as u64)),
    );

    let mut entries: Vec<DirectoryEntry> = Vec::with_capacity(entry_count);
    entries.push(DirectoryEntry {
        tag: TAG_MANIFEST,
        offset: layout.manifest_offset,
        length: envelope_bytes.len() as u64,
        hash: decode_hash(&envelope_hash)?,
    });
    entries.push(DirectoryEntry {
        tag: TAG_KEYBOX,
        offset: layout.keybox_offset,
        length: keybox_bytes.len() as u64,
        hash: decode_hash(&keybox_hash)?,
    });
    entries.push(DirectoryEntry {
        tag: TAG_PRIVATE,
        offset: layout.private_offset,
        length: private_ct.len() as u64,
        hash: decode_hash(&sha256_hex(&private_ct))?,
    });
    for (i, ct) in component_cts.iter().enumerate() {
        entries.push(DirectoryEntry {
            tag: TAG_COMPONENT,
            offset: layout.component_offsets[i],
            length: ct.len() as u64,
            hash: decode_hash(&component_ct_hashes[i])?,
        });
    }
    entries.push(DirectoryEntry {
        tag: TAG_PAYLOAD,
        offset: layout.file_offsets[0],
        length: blob_ct.len() as u64,
        hash: decode_hash(&blob_hash)?,
    });
    if signed {
        entries.push(DirectoryEntry {
            tag: TAG_SIGNATURE,
            offset: layout.signature_offset,
            length: 96,
            hash: [0u8; 32],
        });
    }
    let directory_bytes = layout::encode_directory(&entries);

    // Root hash over the stored (ciphertext) sections; the envelope hash
    // transitively covers keybox and private manifest.
    let root_hash = caf_core::identity::root_hash(
        &envelope_hash,
        &p.interface_hash,
        &component_ct_hashes,
        &blob_hash,
    )?;

    let mut out = Vec::new();
    let mut flags = FLAG_ENCRYPTED;
    if signed {
        flags |= FLAG_SIGNED;
    }
    layout::write_header(&mut out, &layout, cfg.format_version, &root_hash, flags);
    pad_to(&mut out, layout.manifest_offset);
    out.extend_from_slice(&envelope_bytes);
    pad_to(&mut out, layout.interface_offset);
    out.extend_from_slice(&p.interface_bytes);
    pad_to(&mut out, layout.directory_offset);
    out.extend_from_slice(&directory_bytes);
    pad_to(&mut out, layout.keybox_offset);
    out.extend_from_slice(&keybox_bytes);
    pad_to(&mut out, layout.private_offset);
    out.extend_from_slice(&private_ct);
    for (i, ct) in component_cts.iter().enumerate() {
        pad_to(&mut out, layout.component_offsets[i]);
        out.extend_from_slice(ct);
    }
    pad_to(&mut out, layout.file_offsets[0]);
    out.extend_from_slice(&blob_ct);

    if signed {
        pad_to(&mut out, layout.signature_offset);
        let (pubkey, sig) = sign_root_hash(cfg, &root_hash)?;
        out.extend_from_slice(&pubkey);
        out.extend_from_slice(&sig);
    }

    // The plaintext-shaped full manifest, for `--dump-manifest` records.
    let manifest = Manifest {
        name: cfg.name.clone(),
        version: cfg.version.clone(),
        format_version: cfg.format_version,
        interface: envelope.interface.clone(),
        components: p.components.refs.clone(),
        capabilities: p.capabilities.clone(),
        execution: execution(cfg),
        resources: resources(cfg),
        policy: policy(cfg),
        provenance: provenance(cfg),
        payloads: private.payloads.clone(),
        hashes: SectionHashes {
            interface: p.interface_hash.clone(),
            wasm: p.components.hashes.clone(),
            payload: vec![blob_hash],
        },
    };

    Ok(BuildOutput {
        bytes: out,
        manifest,
        envelope: Some(envelope),
        private: Some(private),
        content_key: Some(content_key),
    })
}

fn execution(cfg: &Config) -> ExecutionProfile {
    ExecutionProfile {
        profile: cfg.execution.profile.clone(),
        deterministic: cfg.execution.deterministic,
    }
}

fn resources(cfg: &Config) -> ResourceLimits {
    ResourceLimits {
        memory_max: cfg.resources.memory_max,
        cpu_fuel: cfg.resources.cpu_fuel,
        read_max: cfg.resources.read_max,
        output_max: cfg.resources.output_max,
    }
}

fn policy(cfg: &Config) -> CapabilityPolicy {
    CapabilityPolicy {
        self_read: cfg.policy.self_read,
        network: cfg.policy.network,
        filesystem: cfg.policy.filesystem,
        clock: cfg.policy.clock,
        random: cfg.policy.random,
    }
}

fn provenance(cfg: &Config) -> Provenance {
    Provenance {
        data: Publisher::empty(),
        algorithm: Publisher::empty(),
        artifact: Publisher {
            publisher: cfg.name.clone(),
            signature: None,
        },
    }
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

fn load_interfaces(cfg: &Config, base: &Path) -> Result<Vec<String>> {
    cfg.interfaces
        .iter()
        .map(|p| std::fs::read_to_string(base.join(p)).with_context(|| format!("read wit {p}")))
        .collect()
}

struct Components {
    blobs: Vec<Vec<u8>>,
    hashes: Vec<String>,
    refs: Vec<ComponentRef>,
}

fn build_components(
    cfg: &Config,
    base: &Path,
    payload_root: &PayloadNode,
    wit: &Option<wit::Wit>,
) -> Result<Components> {
    let mut out = Components {
        blobs: Vec::with_capacity(cfg.components.len()),
        hashes: Vec::with_capacity(cfg.components.len()),
        refs: Vec::with_capacity(cfg.components.len()),
    };

    for c in &cfg.components {
        let mut blob =
            std::fs::read(base.join(&c.path)).with_context(|| format!("read wasm {}", c.path))?;

        // Resolve this component's world in the parsed WIT (if any).
        let world = match wit {
            Some(w) => {
                let name = if c.world.is_empty() {
                    None
                } else {
                    Some(c.world.as_str())
                };
                Some(wit::world(w, name)?)
            }
            None => None,
        };

        // Optionally embed the world metadata into the module (real components).
        if let (Some(w), Some(world)) = (wit.as_ref(), world)
            && c.embed
        {
            blob = wit::embed_metadata(w, world, &blob)?;
        }

        let hash = sha256_hex(&blob);
        let len = blob.len() as u64;

        // Exports: bind declared capabilities to the world's exports; without a
        // WIT world, fall back to raw WASM export names.
        let exports = match (wit.as_ref(), world) {
            (Some(w), Some(world)) => {
                let world_exports = wit::exports(w, world);
                check_abi_bridge(&c.name, &blob, &world_exports)?;
                bind_capabilities(&c.capabilities, &world_exports)?
            }
            _ => exports::extract_exports(&blob),
        };

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

        out.hashes.push(hash.clone());
        out.blobs.push(blob);
        out.refs.push(ComponentRef {
            name: c.name.clone(),
            world: c.world.clone(),
            length: len,
            hash,
            exports,
            access,
        });
    }

    Ok(out)
}

fn bind_capabilities(
    capabilities: &[String],
    world_exports: &[wit::WorldExport],
) -> Result<Vec<ExportEntry>> {
    let mut out = Vec::with_capacity(capabilities.len());
    for cap_str in capabilities {
        let cap = CapabilityId::parse(cap_str).map_err(anyhow::Error::msg)?;
        let we = world_exports
            .iter()
            .find(|w| w.name == cap.name)
            .with_context(|| format!("capability '{cap_str}' has no matching world export"))?;
        for f in &we.functions {
            out.push(ExportEntry {
                capability: cap.to_string(),
                export: f.name.clone(),
                signature: f.signature.clone(),
            });
        }
    }
    Ok(out)
}

/// caf-abi v1 enforcement: a component that actually exports a WIT function
/// needing the memory bridge (complex params/results) must export `alloc` and
/// `dealloc`. Binding is by convention in v1, so matching is name-based
/// (kebab-case WIT ↔ snake_case wasm); complex WIT functions without a
/// matching wasm export only warn — they may be intentionally unbound.
fn check_abi_bridge(
    component_name: &str,
    wasm: &[u8],
    world_exports: &[wit::WorldExport],
) -> Result<()> {
    let complex: Vec<&str> = world_exports
        .iter()
        .flat_map(|we| we.functions.iter())
        .filter(|f| f.needs_bridge)
        .map(|f| f.name.as_str())
        .collect();
    if complex.is_empty() {
        return Ok(());
    }
    let wasm_exports: Vec<String> = exports::extract_exports(wasm)
        .into_iter()
        .map(|e| e.export.replace('_', "-"))
        .collect();
    let bound: Vec<&str> = complex
        .into_iter()
        .filter(|f| wasm_exports.iter().any(|e| e == f))
        .collect();
    if bound.is_empty() {
        eprintln!(
            "warning: component '{component_name}' has complex WIT exports but none match wasm \
             export names; caf-abi memory-bridge check skipped"
        );
        return Ok(());
    }
    let has_alloc = wasm_exports.iter().any(|e| e == "alloc");
    let has_dealloc = wasm_exports.iter().any(|e| e == "dealloc");
    if !has_alloc || !has_dealloc {
        let missing = match (has_alloc, has_dealloc) {
            (false, false) => "alloc and dealloc",
            (false, true) => "alloc",
            (true, false) => "dealloc",
            (true, true) => unreachable!(),
        };
        anyhow::bail!(
            "component '{component_name}' exports complex-typed function(s) [{}] via the caf-abi \
             memory bridge but is missing {missing} — see doc/spec/caf-abi.md §3",
            bound.join(", ")
        );
    }
    Ok(())
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

/// Sign the artifact root hash (Encrypt-then-Sign: the signature covers the
/// stored-bytes identity — ciphertext for sealed artifacts).
fn sign_root_hash(cfg: &Config, root_hash: &[u8; 32]) -> Result<([u8; 32], [u8; 64])> {
    use ed25519_dalek::{Signer, SigningKey};

    let seed_hex = cfg
        .sign
        .as_ref()
        .map(|s| s.seed.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing sign.seed"))?;
    let seed = decode_seed("sign.seed", seed_hex)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey = signing_key.verifying_key().to_bytes();
    let sig = signing_key.sign(root_hash);
    Ok((pubkey, sig.to_bytes()))
}

fn decode_seed(what: &str, seed_hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(seed_hex).map_err(|e| anyhow::anyhow!("invalid {what}: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} must be 32 bytes (64 hex chars)"))
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
    hex::encode(&sha256_raw(data))
}

fn sha256_raw(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn decode_hash(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("hash is not 32 bytes"))
}
