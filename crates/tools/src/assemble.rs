//! Assemble a `.caf` artifact from a build [`Config`]: hash the interface, build
//! the payload Merkle trees, bind components (access scopes + capability-bound
//! exports), compute layout and directory, derive the root hash, and optionally
//! sign the root hash (Encrypt-then-Sign: the signature always covers the
//! stored-bytes identity).
//!
//! With `[encrypt]` in the config the artifact is **sealed**: components,
//! payloads, and the private manifest are AES-256-GCM encrypted under a content
//! key wrapped per recipient in the keybox section, each payload becomes a
//! pow2-padded ciphertext blob, and the manifest section carries only the
//! public envelope (see `doc/spec/en/container-format.md` §7).

use anyhow::{Context, Result, bail};
use rand_core::RngCore;
use serde::Serialize;
use serde_bytes::ByteBuf;
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

/// The result of assembling an artifact.
pub struct BuildOutput {
    /// The complete `.caf` bytes.
    pub bytes: Vec<u8>,
    /// The plaintext-shaped manifest view (for `--dump-manifest` records).
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

/// Assemble a `.caf` artifact from a validated build config. The build is
/// deterministic (`doc/spec/en/round-trip.md` §2); only supported
/// `format_version`s are accepted (fail-closed).
pub fn assemble(cfg: &Config, base: &Path) -> Result<BuildOutput> {
    // Only write format versions this build can also read (fail-closed).
    caf_core::version::spec(cfg.format_version)
        .with_context(|| format!("unsupported format_version {}", cfg.format_version))?;
    let prepared = prepare(cfg, base)?;
    if let Some(encrypt) = &cfg.encrypt {
        assemble_sealed(cfg, &prepared, encrypt)
    } else {
        assemble_plaintext(cfg, &prepared)
    }
}

/// Everything both assembly paths share: interface bytes, payload trees and
/// blobs, component blobs/refs, capabilities.
struct Prepared {
    interface_bytes: Vec<u8>,
    interface_hash: String,
    payloads: Vec<PreparedPayload>,
    components: Components,
    capabilities: Vec<CapabilityId>,
}

/// One payload tree with its file blobs in deterministic DFS order.
struct PreparedPayload {
    name: String,
    media_type: String,
    root_node: PayloadNode,
    blobs: Vec<Vec<u8>>,
    file_list: Vec<(String, String, u64)>,
}

fn prepare(cfg: &Config, base: &Path) -> Result<Prepared> {
    // 1. Interface section: the WIT sources as a name-preserving CBOR list,
    //    plus a flat parse for validation.
    let mut interface_files = Vec::new();
    for path in &cfg.interfaces {
        let text =
            std::fs::read_to_string(base.join(path)).with_context(|| format!("read wit {path}"))?;
        let name = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .with_context(|| format!("invalid interface file name for {path}"))?
            .to_string();
        interface_files.push(InterfaceFile { name, text });
    }
    let interface_bytes = if interface_files.is_empty() {
        Vec::new()
    } else {
        cbor_bytes(&interface_files)?
    };
    let interface_hash = sha256_hex(&interface_bytes);

    // 2. Parse/validate the WIT once (when any interface file is declared).
    let wit = if interface_files.is_empty() {
        None
    } else {
        let sources: Vec<String> = interface_files.iter().map(|f| f.text.clone()).collect();
        Some(wit::parse(&sources)?)
    };

    // 3. Payload trees (chunked Merkle hashing, over plaintext) and blobs in
    //    the same deterministic DFS order.
    let mut payloads = Vec::with_capacity(cfg.payloads.len());
    for p in &cfg.payloads {
        let root_node = payload::build_tree(&base.join(&p.root))?;
        let mut file_list: Vec<(String, String, u64)> = Vec::new();
        payload::collect_files(&root_node, "", &mut file_list);
        let mut blobs: Vec<Vec<u8>> = Vec::new();
        collect_payload_blobs(&root_node, &base.join(&p.root), Path::new(""), &mut blobs)?;
        payloads.push(PreparedPayload {
            name: p.name.clone(),
            media_type: p.media_type.clone(),
            root_node,
            blobs,
            file_list,
        });
    }
    // Mount rules are build-time fail-closed (unique names, no shadowing of
    // the default payload's top-level entries).
    let mount_pairs: Vec<(&str, &PayloadNode)> = payloads
        .iter()
        .map(|p| (p.name.as_str(), &p.root_node))
        .collect();
    payload::validate_mounts(&mount_pairs)?;

    // 4. WASM components: load, optionally embed world metadata, hash, and
    //    build refs with access scopes + capability-bound exports.
    let components = build_components(cfg, base, &payloads, &wit)?;

    // 5. Capabilities (parsed and deduplicated).
    let capabilities = collect_capabilities(cfg)?;

    Ok(Prepared {
        interface_bytes,
        interface_hash,
        payloads,
        components,
        capabilities,
    })
}

fn assemble_plaintext(cfg: &Config, p: &Prepared) -> Result<BuildOutput> {
    let payload_root_hashes: Vec<String> = p
        .payloads
        .iter()
        .map(|x| x.root_node.hash.clone())
        .collect();

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
        payloads: p
            .payloads
            .iter()
            .map(|x| PayloadRef {
                name: x.name.clone(),
                root: x.root_node.clone(),
                media_type: x.media_type.clone(),
                length: 0,
                hash: x.root_node.hash.clone(),
                compressed: None,
                padded_length: None,
                chunks: Vec::new(),
            })
            .collect(),
        hashes: SectionHashes {
            interface: p.interface_hash.clone(),
            wasm: p.components.hashes.clone(),
            payload: payload_root_hashes.clone(),
        },
    };

    let manifest_bytes = cbor_bytes(&manifest)?;
    let manifest_hash = sha256_hex(&manifest_bytes);

    // Section inventory for layout + directory (deterministic DFS order,
    // payload by payload).
    let component_lens: Vec<u64> = p.components.blobs.iter().map(|b| b.len() as u64).collect();
    let file_lens: Vec<u64> = p
        .payloads
        .iter()
        .flat_map(|x| x.file_list.iter().map(|(_, _, len)| *len))
        .collect();

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
    entries.push(dir_entry(
        TAG_MANIFEST,
        layout.manifest_offset,
        manifest_bytes.len() as u64,
        decode_hash(&manifest_hash)?,
    ));
    for (i, blob) in p.components.blobs.iter().enumerate() {
        entries.push(dir_entry(
            TAG_COMPONENT,
            layout.component_offsets[i],
            blob.len() as u64,
            decode_hash(&p.components.hashes[i])?,
        ));
    }
    let mut file_index = 0;
    for payload in &p.payloads {
        for (_, hash, len) in &payload.file_list {
            entries.push(dir_entry(
                TAG_PAYLOAD,
                layout.file_offsets[file_index],
                *len,
                decode_hash(hash)?,
            ));
            file_index += 1;
        }
    }
    if signed {
        entries.push(dir_entry(
            TAG_SIGNATURE,
            layout.signature_offset,
            0, // length filled in after the signature is produced
            [0u8; 32],
        ));
    }

    // Root hash (domain-separated; shared with the verifier).
    let root_hash = caf_core::identity::root_hash(
        &manifest_hash,
        &p.interface_hash,
        &p.components.hashes,
        &payload_root_hashes,
    )?;

    // Signature section: a CBOR list of signature entries over the root hash.
    let signature_bytes = match &cfg.sign {
        Some(_) => Some(sign_root_hash(cfg, &root_hash)?),
        None => None,
    };
    if let Some(bytes) = &signature_bytes {
        let last = entries.last_mut().context("signature entry")?;
        last.length = bytes.len() as u64;
    }
    let directory_bytes = layout::encode_directory(&entries);

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
    let mut file_index = 0;
    for payload in &p.payloads {
        for data in &payload.blobs {
            pad_to(&mut out, layout.file_offsets[file_index]);
            out.extend_from_slice(data);
            file_index += 1;
        }
    }

    if let Some(bytes) = &signature_bytes {
        pad_to(&mut out, layout.signature_offset);
        out.extend_from_slice(bytes);
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

    // Per payload: files concatenated in DFS order, pow2-padded with zeros.
    struct Sealing {
        blob_plain: Vec<u8>,
        real_len: u64,
        padded: u64,
    }
    let mut sealings = Vec::with_capacity(p.payloads.len());
    for payload in &p.payloads {
        let mut blob_plain = Vec::new();
        for data in &payload.blobs {
            blob_plain.extend_from_slice(data);
        }
        let real_len = blob_plain.len() as u64;
        let padded = crypto::padded_len(real_len);
        blob_plain.resize(padded as usize, 0);
        sealings.push(Sealing {
            blob_plain,
            real_len,
            padded,
        });
    }

    // Private manifest: everything the envelope hides. Payload hash/chunks are
    // plaintext placeholders here; they are replaced with ciphertext refs
    // after encryption.
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
        payloads: p
            .payloads
            .iter()
            .zip(&sealings)
            .map(|(x, s)| PayloadRef {
                name: x.name.clone(),
                root: x.root_node.clone(),
                media_type: x.media_type.clone(),
                length: s.real_len,
                hash: sha256_hex(&s.blob_plain),
                compressed: None,
                padded_length: Some(s.padded),
                chunks: Vec::new(),
            })
            .collect(),
    };

    // Content key: convergent (reproducible) when key_seed is set, else random.
    let content_key: [u8; 32] = match seed {
        Some(seed) => {
            // Bind every private metadata field and every encrypted plaintext
            // before encryption. Ciphertext refs above are placeholders here,
            // avoiding a circular dependency on the derived content key.
            let identity_input = cbor_bytes(&(&p.interface_hash, &private))?;
            crypto::convergent_content_key(&seed, &sha256_raw(&identity_input))
        }
        None => {
            let mut key = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut key);
            key
        }
    };

    // Encrypt each payload blob per chunk; record ciphertext chunk hashes.
    let mut private = private;
    let mut blob_cts = Vec::with_capacity(sealings.len());
    let mut blob_hashes = Vec::with_capacity(sealings.len());
    for (i, s) in sealings.iter().enumerate() {
        let payload_key = crypto::section_key(&content_key, &format!("payload/{i}"));
        let chunk_total = payload::chunk_count(s.padded);
        let mut blob_ct = Vec::new();
        let mut blob_chunk_hashes = Vec::with_capacity(chunk_total as usize);
        for index in 0..chunk_total {
            let (cs, ce) = payload::chunk_range(s.padded, index);
            let ct =
                crypto::seal_chunk(&payload_key, index, &s.blob_plain[cs as usize..ce as usize])?;
            blob_chunk_hashes.push(sha256_hex(&ct));
            blob_ct.extend_from_slice(&ct);
        }
        private.payloads[i].chunks = blob_chunk_hashes;
        blob_hashes.push(sha256_hex(&blob_ct));
        blob_cts.push(blob_ct);
    }
    for (i, hash) in blob_hashes.iter().enumerate() {
        private.payloads[i].hash = hash.clone();
    }

    // Encrypt each component (single chunk per component section).
    let mut component_cts = Vec::with_capacity(p.components.blobs.len());
    let mut component_ct_hashes = Vec::with_capacity(p.components.blobs.len());
    for (i, blob) in p.components.blobs.iter().enumerate() {
        let key = crypto::section_key(&content_key, &format!("component/{i}"));
        let ct = crypto::seal_chunk(&key, 0, blob)?;
        component_ct_hashes.push(sha256_hex(&ct));
        component_cts.push(ct);
    }

    let private_bytes = cbor_bytes(&private)?;
    let private_key = crypto::section_key(&content_key, "private");
    let private_ct = crypto::seal_chunk(&private_key, 0, &private_bytes)?;
    let private_ct_hash = sha256_hex(&private_ct);

    // Keybox: one anonymous stanza per recipient (deterministic ephemerals in
    // convergent builds).
    let mut stanzas = Vec::with_capacity(recipients.len());
    for recipient in &recipients {
        let ephemeral = match seed {
            Some(seed) => crypto::convergent_ephemeral(&seed, recipient, &content_key)?,
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
        payloads: blob_cts
            .iter()
            .enumerate()
            .map(|(i, ct)| PayloadBlobRef {
                name: p.payloads[i].name.clone(),
                length: ct.len() as u64,
                padded_length: sealings[i].padded,
                chunks: payload::chunk_count(sealings[i].padded),
                hash: blob_hashes[i].clone(),
            })
            .collect(),
    };

    // Layout + directory: manifest(envelope), interface, directory, keybox,
    // private, components, payload blobs, signature.
    let envelope_bytes = cbor_bytes(&envelope)?;
    let envelope_hash = sha256_hex(&envelope_bytes);
    let signed = cfg.sign.is_some();
    let component_lens: Vec<u64> = component_cts.iter().map(|c| c.len() as u64).collect();
    let blob_lens: Vec<u64> = blob_cts.iter().map(|b| b.len() as u64).collect();
    let entry_count = 3 + component_lens.len() + blob_lens.len() + usize::from(signed);
    let directory_len = 4 + (entry_count * layout::DIRECTORY_ENTRY_SIZE) as u64;
    let layout = layout::compute(
        envelope_bytes.len() as u64,
        p.interface_bytes.len() as u64,
        directory_len,
        &component_lens,
        &blob_lens,
        signed,
        Some((keybox_bytes.len() as u64, private_ct.len() as u64)),
    );

    let mut entries: Vec<DirectoryEntry> = Vec::with_capacity(entry_count);
    entries.push(dir_entry(
        TAG_MANIFEST,
        layout.manifest_offset,
        envelope_bytes.len() as u64,
        decode_hash(&envelope_hash)?,
    ));
    entries.push(dir_entry(
        TAG_KEYBOX,
        layout.keybox_offset,
        keybox_bytes.len() as u64,
        decode_hash(&keybox_hash)?,
    ));
    entries.push(dir_entry(
        TAG_PRIVATE,
        layout.private_offset,
        private_ct.len() as u64,
        decode_hash(&sha256_hex(&private_ct))?,
    ));
    for (i, ct) in component_cts.iter().enumerate() {
        entries.push(dir_entry(
            TAG_COMPONENT,
            layout.component_offsets[i],
            ct.len() as u64,
            decode_hash(&component_ct_hashes[i])?,
        ));
    }
    for (i, ct) in blob_cts.iter().enumerate() {
        entries.push(dir_entry(
            TAG_PAYLOAD,
            layout.file_offsets[i],
            ct.len() as u64,
            decode_hash(&blob_hashes[i])?,
        ));
    }
    if signed {
        entries.push(dir_entry(
            TAG_SIGNATURE,
            layout.signature_offset,
            0,
            [0u8; 32],
        ));
    }

    // Root hash over the stored (ciphertext) sections; the envelope hash
    // transitively covers keybox and private manifest.
    let root_hash = caf_core::identity::root_hash(
        &envelope_hash,
        &p.interface_hash,
        &component_ct_hashes,
        &blob_hashes,
    )?;

    let signature_bytes = match &cfg.sign {
        Some(_) => Some(sign_root_hash(cfg, &root_hash)?),
        None => None,
    };
    if let Some(bytes) = &signature_bytes {
        let last = entries.last_mut().context("signature entry")?;
        last.length = bytes.len() as u64;
    }
    let directory_bytes = layout::encode_directory(&entries);

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
    for (i, ct) in blob_cts.iter().enumerate() {
        pad_to(&mut out, layout.file_offsets[i]);
        out.extend_from_slice(ct);
    }

    if let Some(bytes) = &signature_bytes {
        pad_to(&mut out, layout.signature_offset);
        out.extend_from_slice(bytes);
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
            payload: blob_hashes,
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
        let parsed = CapabilityId::parse(cap).map_err(anyhow::Error::msg)?;
        if !cfg
            .components
            .iter()
            .any(|c| c.capabilities.iter().any(|bound| bound == cap))
        {
            bail!("artifact capability '{cap}' has no implementing component");
        }
        if !out.contains(&parsed) {
            out.push(parsed);
        }
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

struct Components {
    blobs: Vec<Vec<u8>>,
    hashes: Vec<String>,
    refs: Vec<ComponentRef>,
}

fn build_components(
    cfg: &Config,
    base: &Path,
    payloads: &[PreparedPayload],
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
                bind_capabilities(&c.name, &blob, &c.capabilities, &world_exports)?
            }
            _ => {
                if !c.capabilities.is_empty() {
                    bail!(
                        "component '{}' declares capabilities without a WIT world",
                        c.name
                    );
                }
                exports::core_exports(&blob)?;
                exports::extract_exports(&blob)
            }
        };

        let mut access = Vec::with_capacity(c.access.len());
        for a in &c.access {
            let (payload_name, path) = parse_access(a)?;
            let payload_name = if payload_name.is_empty() {
                payloads
                    .first()
                    .context("access scope on a build without payloads")?
                    .name
                    .clone()
            } else {
                payload_name
            };
            let tree = payloads
                .iter()
                .find(|p| p.name == payload_name)
                .with_context(|| format!("access scope '{a}': unknown payload '{payload_name}'"))?;
            let node = payload::find(&tree.root_node, &path)
                .with_context(|| format!("access path '{path}' not found in payload"))?;
            access.push(AccessScope {
                payload: payload_name,
                path,
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

/// Parse an access string: `/path` addresses the default (first) payload,
/// `name:/path` addresses a named payload.
fn parse_access(access: &str) -> Result<(String, String)> {
    if access.starts_with('/') {
        return Ok((String::new(), access.to_string()));
    }
    let (name, path) = access
        .split_once(':')
        .with_context(|| format!("invalid access scope '{access}'"))?;
    if name.is_empty() || !path.starts_with('/') {
        bail!("invalid access scope '{access}'");
    }
    Ok((name.to_string(), path.to_string()))
}

/// Every capability recorded in the manifest must be callable with its
/// declared caf-abi signature. Unbound world exports are not advertised.
fn bind_capabilities(
    component_name: &str,
    wasm: &[u8],
    capabilities: &[String],
    world_exports: &[wit::WorldExport],
) -> Result<Vec<ExportEntry>> {
    let actual =
        exports::core_exports(wasm).with_context(|| format!("component '{component_name}'"))?;
    let mut out = Vec::new();
    let mut needs_bridge = false;
    for cap_str in capabilities {
        let cap = CapabilityId::parse(cap_str).map_err(anyhow::Error::msg)?;
        let we = world_exports
            .iter()
            .find(|w| w.name == cap.name)
            .with_context(|| format!("capability '{cap_str}' has no matching world export"))?;
        for f in &we.functions {
            let (name, signature) = actual.functions.get(&f.name)
                .with_context(|| format!("component '{component_name}' capability '{cap_str}' is missing WASM function '{}'", f.name))?;
            if signature != &f.core_type {
                bail!(
                    "component '{component_name}' export '{name}' signature mismatch: expected {:?}, got {:?}",
                    f.core_type,
                    signature
                );
            }
            needs_bridge |= f.needs_bridge;
            out.push(ExportEntry {
                capability: cap.to_string(),
                export: name.clone(),
                signature: f.signature.clone(),
            });
        }
    }
    if needs_bridge {
        if !actual.memory32 {
            bail!(
                "component '{component_name}' caf-abi memory bridge requires an exported, unshared 32-bit 'memory'"
            );
        }
        use wasmparser::{FuncType, ValType::I32};
        for (name, expected) in [
            ("alloc", FuncType::new([I32], [I32])),
            ("dealloc", FuncType::new([I32, I32], [])),
        ] {
            let (_, signature) = actual.functions.get(name).with_context(|| {
                format!("component '{component_name}' caf-abi memory bridge is missing '{name}'")
            })?;
            if signature != &expected {
                bail!(
                    "component '{component_name}' caf-abi memory bridge '{name}' signature mismatch: expected {expected:?}, got {signature:?}"
                );
            }
        }
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

/// Sign the artifact root hash (Encrypt-then-Sign: the signature covers the
/// stored-bytes identity — ciphertext for sealed artifacts). The section is a
/// CBOR list so co-signing is just another entry.
fn sign_root_hash(cfg: &Config, root_hash: &[u8; 32]) -> Result<Vec<u8>> {
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
    let entry = SignatureEntry {
        alg: SignatureAlgorithm::Ed25519,
        key_id: payload::signer_fingerprint(&pubkey),
        pubkey: ByteBuf::from(pubkey.to_vec()),
        sig: ByteBuf::from(sig.to_bytes().to_vec()),
    };
    cbor_bytes(&vec![entry])
}

fn decode_seed(what: &str, seed_hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(seed_hex).map_err(|e| anyhow::anyhow!("invalid {what}: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} must be 32 bytes (64 hex chars)"))
}

fn dir_entry(tag: u8, offset: u64, length: u64, hash: [u8; 32]) -> DirectoryEntry {
    DirectoryEntry {
        tag,
        flags: 0,
        hash_alg: layout::HASH_ALG_SHA256,
        offset,
        length,
        hash,
    }
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
