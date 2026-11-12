//! Full open-time verification of a `.caf` artifact: every section hash, the
//! manifest hash, the domain-separated root hash, access-scope bindings, and
//! the optional ed25519 signature (see `doc/spec/en/container-format.md`).
//!
//! Sealed artifacts (`FLAG_ENCRYPTED`) verify in two tiers: without a key,
//! every *stored* (ciphertext) byte is hash-checked and the signature — which
//! covers the ciphertext root hash — still validates; with the content key,
//! the private manifest is decrypted and the plaintext payload tree, access
//! scopes, and component hashes are verified as well.

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::crypto;
use crate::hex;
use crate::identity;
use crate::layout::{
    self, TAG_COMPONENT, TAG_KEYBOX, TAG_MANIFEST, TAG_PAYLOAD, TAG_PRIVATE, TAG_SIGNATURE,
};
use crate::manifest::*;
use crate::payload;

/// Summary of a successful verification, for display by `caf-tool verify`.
pub struct VerifyReport {
    /// Artifact name from the manifest (`"<sealed>"` when encrypted and no key
    /// was supplied).
    pub name: String,
    /// Artifact version from the manifest (likewise redacted when sealed).
    pub version: String,
    /// Domain-separated root hash (hex) — the artifact's content identity.
    pub root_hash: String,
    /// SHA-256 (hex) of the manifest (envelope) bytes.
    pub manifest_hash: String,
    /// Number of embedded WASM components.
    pub components: usize,
    /// Number of payload files (`0` when sealed and no key was supplied).
    pub payload_files: usize,
    /// Capabilities the artifact exposes.
    pub capabilities: Vec<CapabilityId>,
    /// Whether the artifact is sealed (components, payload, private manifest
    /// encrypted; see `crate::crypto`).
    pub encrypted: bool,
    /// Whether the artifact carries a signature section.
    pub signed: bool,
    /// Signature validity (`None` when the artifact is unsigned): every
    /// signature entry verified against the header root hash.
    pub signature_valid: Option<bool>,
    /// Signer fingerprints — one per signature entry (SHA-256 of each public
    /// key, hex), for comparison against an external trust store.
    pub signer_fingerprints: Vec<String>,
}

/// Open-time verification: recompute every section hash, the manifest hash, the
/// root hash, access-scope bindings, and (if present) the ed25519 signature.
pub fn verify(path: &Path) -> Result<VerifyReport> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    verify_bytes(&bytes)
}

/// [`verify`] with the content key, additionally decrypting the private
/// manifest and payload for full plaintext verification.
pub fn verify_with_key(path: &Path, content_key: &[u8; 32]) -> Result<VerifyReport> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    verify_bytes_keyed(&bytes, Some(content_key))
}

/// In-memory equivalent of [`verify`]: verify artifact bytes already loaded
/// (or received) by the caller.
pub fn verify_bytes(bytes: &[u8]) -> Result<VerifyReport> {
    verify_bytes_keyed(bytes, None)
}

/// In-memory verification with an optional content key. The key is required
/// for the plaintext tier of a sealed artifact and ignored otherwise.
pub fn verify_bytes_keyed(bytes: &[u8], content_key: Option<&[u8; 32]>) -> Result<VerifyReport> {
    let header = layout::read_header(bytes)?;
    let entries = layout::decode_directory(layout::slice(
        bytes,
        header.directory_offset,
        header.directory_len,
    )?)?;

    let encrypted = header.flags & layout::FLAG_ENCRYPTED != 0;
    let mut report = if encrypted {
        verify_sealed(bytes, &header, &entries, content_key)?
    } else {
        verify_plaintext(bytes, &header, &entries)?
    };

    // Signature (both modes): a CBOR list of signatures over the header root
    // hash (Encrypt-then-Sign for sealed artifacts). Every entry must carry an
    // honest key_id and a signature that verifies.
    report.signed = header.flags & layout::FLAG_SIGNED != 0;
    if report.signed {
        let sig_entry = entries
            .iter()
            .find(|e| e.tag == TAG_SIGNATURE)
            .context("signed artifact has no signature directory entry")?;
        let sig_bytes = layout::slice(bytes, sig_entry.offset, sig_entry.length)?;
        let signatures: Vec<SignatureEntry> =
            ciborium::de::from_reader(sig_bytes).context("decode signature section")?;
        let mut all_valid = !signatures.is_empty();
        for entry in &signatures {
            let valid = match entry.alg {
                SignatureAlgorithm::Ed25519 => {
                    entry.key_id == payload::signer_fingerprint(entry.pubkey.as_ref())
                        && payload::verify_signature(
                            entry.pubkey.as_ref(),
                            entry.sig.as_ref(),
                            &header.root_hash,
                        )
                }
            };
            all_valid &= valid;
            report.signer_fingerprints.push(entry.key_id.clone());
        }
        report.signature_valid = Some(all_valid);
    }
    Ok(report)
}

/// Plaintext artifact: full hash chain over manifest, components, payload
/// tree, and access scopes.
fn verify_plaintext(
    bytes: &[u8],
    header: &layout::Header,
    entries: &[layout::DirectoryEntry],
) -> Result<VerifyReport> {
    let manifest_bytes = layout::slice(bytes, header.manifest_offset, header.manifest_len)?;
    let interface_bytes = layout::slice(bytes, header.interface_offset, header.interface_len)?;

    // 0. Version admission, schema migration and header consistency.
    let manifest = crate::version::load_manifest(manifest_bytes, header.format_version)?;

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

    // 4. Payloads: file chunk-Merkle hashes + tree structure, in manifest
    //    order. Directory payload entries are ordered payload by payload.
    let payload_entries: Vec<_> = entries.iter().filter(|e| e.tag == TAG_PAYLOAD).collect();
    let total_files: usize = manifest
        .payloads
        .iter()
        .map(|p| {
            let mut files = Vec::new();
            payload::collect_files(&p.root, "", &mut files);
            files.len()
        })
        .sum();
    if payload_entries.len() != total_files {
        bail!(
            "payload file count mismatch: directory {}, trees {}",
            payload_entries.len(),
            total_files
        );
    }
    let mut payload_root_hashes = Vec::with_capacity(manifest.payloads.len());
    let mut next_entry = 0;
    for payload_ref in &manifest.payloads {
        let mut file_list: Vec<(String, String, u64)> = Vec::new();
        payload::collect_files(&payload_ref.root, "", &mut file_list);
        for (path, expected_hash, _len) in &file_list {
            let e = payload_entries[next_entry];
            next_entry += 1;
            let data = layout::slice(bytes, e.offset, e.length)?;
            let h = payload::verify_file(data)?;
            if &h != expected_hash {
                bail!("payload '{path}' hash mismatch");
            }
            if e.hash != decode_hash(&h)? {
                bail!("payload '{path}' directory hash mismatch");
            }
        }
        payload::verify_tree(&payload_ref.root)?;
        payload_root_hashes.push(payload_ref.root.hash.clone());
    }
    payload::validate_payloads(&manifest.payloads)?;
    if manifest.hashes.payload != payload_root_hashes {
        bail!("payload root hash mismatch");
    }

    // 5. Access scopes must resolve to real, hash-matching nodes.
    check_access_scopes(&manifest.components, &manifest.payloads)?;

    // 6. Root hash (domain-separated, shared with the builder).
    let root_hash = identity::root_hash(
        &manifest_hash,
        &interface_hash,
        &wasm_hashes,
        &payload_root_hashes,
    )?;
    if root_hash != header.root_hash {
        bail!("root hash mismatch");
    }

    Ok(VerifyReport {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        root_hash: hex::encode(&root_hash),
        manifest_hash,
        components: manifest.components.len(),
        payload_files: total_files,
        capabilities: manifest.capabilities.clone(),
        encrypted: false,
        signed: false,
        signature_valid: None,
        signer_fingerprints: Vec::new(),
    })
}

/// Sealed artifact: the public tier always runs; the plaintext tier runs when
/// a content key is supplied.
fn verify_sealed(
    bytes: &[u8],
    header: &layout::Header,
    entries: &[layout::DirectoryEntry],
    content_key: Option<&[u8; 32]>,
) -> Result<VerifyReport> {
    let envelope_bytes = layout::slice(bytes, header.manifest_offset, header.manifest_len)?;
    let interface_bytes = layout::slice(bytes, header.interface_offset, header.interface_len)?;
    let envelope = crate::version::load_envelope(envelope_bytes, header.format_version)?;

    let crypto = &crate::version::spec(header.format_version)?.crypto;
    if envelope.encryption.aead != crypto.aead
        || envelope.encryption.wrap != crypto.wrap
        || envelope.encryption.padding != crypto.padding
    {
        bail!("unsupported encryption parameters");
    }

    // Envelope hash (pinned by the directory's manifest entry).
    let envelope_hash = sha256_hex(envelope_bytes);
    let manifest_entry = entries
        .iter()
        .find(|e| e.tag == TAG_MANIFEST)
        .context("directory has no manifest entry")?;
    if manifest_entry.hash != decode_hash(&envelope_hash)? {
        bail!("envelope hash mismatch");
    }

    // Interface (plaintext).
    let interface_hash = sha256_hex(interface_bytes);
    if interface_hash != envelope.interface.hash {
        bail!("interface hash mismatch");
    }

    // Components (ciphertext sections, anonymous in the envelope).
    let component_entries: Vec<_> = entries.iter().filter(|e| e.tag == TAG_COMPONENT).collect();
    if component_entries.len() != envelope.components.len() {
        bail!(
            "component count mismatch: directory {}, envelope {}",
            component_entries.len(),
            envelope.components.len()
        );
    }
    let mut component_hashes = Vec::with_capacity(envelope.components.len());
    for (i, section) in envelope.components.iter().enumerate() {
        let e = component_entries[i];
        let data = layout::slice(bytes, e.offset, e.length)?;
        let h = sha256_hex(data);
        if h != section.hash || e.hash != decode_hash(&h)? || e.length != section.length {
            bail!("sealed component {i} hash/length mismatch");
        }
        component_hashes.push(h);
    }

    // Keybox (plaintext) and private manifest (ciphertext) sections.
    let keybox_entry = entries
        .iter()
        .find(|e| e.tag == TAG_KEYBOX)
        .context("sealed artifact has no keybox entry")?;
    let keybox_bytes = layout::slice(bytes, keybox_entry.offset, keybox_entry.length)?;
    if sha256_hex(keybox_bytes) != envelope.keybox.hash {
        bail!("keybox hash mismatch");
    }
    crypto::keybox_stanzas(keybox_bytes).context("decode keybox")?;

    let private_entry = entries
        .iter()
        .find(|e| e.tag == TAG_PRIVATE)
        .context("sealed artifact has no private manifest entry")?;
    let private_bytes = layout::slice(bytes, private_entry.offset, private_entry.length)?;
    if sha256_hex(private_bytes) != envelope.private.hash {
        bail!("private manifest hash mismatch");
    }

    // Payload blobs: one directory entry per payload, ciphertext hash-checked.
    let payload_entries: Vec<_> = entries.iter().filter(|e| e.tag == TAG_PAYLOAD).collect();
    if payload_entries.len() != envelope.payloads.len() {
        bail!(
            "payload blob count mismatch: directory {}, envelope {}",
            payload_entries.len(),
            envelope.payloads.len()
        );
    }
    let mut blob_hashes = Vec::with_capacity(envelope.payloads.len());
    for (i, blobref) in envelope.payloads.iter().enumerate() {
        let e = payload_entries[i];
        let blob = layout::slice(bytes, e.offset, e.length)?;
        let blob_hash = sha256_hex(blob);
        if blob_hash != blobref.hash || e.length != blobref.length {
            bail!("payload blob '{}' hash/length mismatch", blobref.name);
        }
        let chunks = payload::chunk_count(blobref.padded_length);
        if chunks != blobref.chunks {
            bail!("payload blob '{}' chunk count mismatch", blobref.name);
        }
        let expected_ct_len = blobref.padded_length + chunks * crypto::AEAD_TAG_LEN as u64;
        if expected_ct_len != blobref.length {
            bail!(
                "payload blob '{}' length does not match padded length + chunk tags",
                blobref.name
            );
        }
        blob_hashes.push(blob_hash);
    }

    // Root hash over the *stored* bytes (envelope, interface, ciphertext
    // components, ciphertext payload blobs).
    let root_hash = identity::root_hash(
        &envelope_hash,
        &interface_hash,
        &component_hashes,
        &blob_hashes,
    )?;
    if root_hash != header.root_hash {
        bail!("root hash mismatch");
    }

    let mut report = VerifyReport {
        name: "<sealed>".to_string(),
        version: "<sealed>".to_string(),
        root_hash: hex::encode(&root_hash),
        manifest_hash: envelope_hash,
        components: envelope.components.len(),
        payload_files: 0,
        capabilities: envelope.capabilities.clone(),
        encrypted: true,
        signed: false,
        signature_valid: None,
        signer_fingerprints: Vec::new(),
    };

    // Plaintext tier: decrypt the private manifest and verify names, the
    // payload trees, access scopes, and per-file plaintext hashes.
    if let Some(key) = content_key {
        let private_key = crypto::section_key(key, "private");
        let private_plain = crypto::open_chunk(&private_key, 0, private_bytes)?;
        let private: PrivateManifest = ciborium::de::from_reader(private_plain.as_slice())
            .context("decode private manifest")?;
        if private.components.len() != envelope.components.len() {
            bail!("private/envelope component count mismatch");
        }
        for (i, comp) in private.components.iter().enumerate() {
            let component_key = crypto::section_key(key, &format!("component/{i}"));
            let ct = layout::slice(
                bytes,
                component_entries[i].offset,
                component_entries[i].length,
            )?;
            let plain = crypto::open_chunk(&component_key, 0, ct)?;
            if sha256_hex(&plain) != comp.hash {
                bail!("component '{}' plaintext hash mismatch", comp.name);
            }
        }
        if private.payloads.len() != envelope.payloads.len() {
            bail!(
                "private/envelope payload count mismatch: {}, {}",
                private.payloads.len(),
                envelope.payloads.len()
            );
        }
        payload::validate_payloads(&private.payloads)?;
        check_access_scopes_private(&private.components, &private.payloads)?;
        let mut total_files = 0;
        for (i, payload_ref) in private.payloads.iter().enumerate() {
            let blobref = &envelope.payloads[i];
            if payload_ref.name != blobref.name {
                bail!("private/envelope payload name mismatch at index {i}");
            }
            if payload_ref.hash != blobref.hash
                || payload_ref.padded_length != Some(blobref.padded_length)
                || payload_ref.chunks.len() as u64 != blobref.chunks
            {
                bail!(
                    "private/envelope payload ref mismatch for '{}'",
                    payload_ref.name
                );
            }
            payload::verify_tree(&payload_ref.root)?;
            let payload_key = crypto::section_key(key, &format!("payload/{i}"));
            let blob = layout::slice(bytes, payload_entries[i].offset, payload_entries[i].length)?;
            let plaintext = open_blob(&payload_key, blob, blobref.padded_length)?;
            let mut file_list: Vec<(String, String, u64)> = Vec::new();
            payload::collect_files(&payload_ref.root, "", &mut file_list);
            let mut at = 0u64;
            for (path, expected_hash, len) in &file_list {
                let data = &plaintext[at as usize..(at + len) as usize];
                if &payload::verify_file(data)? != expected_hash {
                    bail!("payload '{path}' plaintext hash mismatch");
                }
                at += len;
            }
            if at != payload_ref.length {
                bail!("payload real length mismatch");
            }
            total_files += file_list.len();
        }
        report.name = private.name.clone();
        report.version = private.version.clone();
        report.payload_files = total_files;
    }

    Ok(report)
}

/// Decrypt a chunked ciphertext blob into its `padded_length` plaintext bytes,
/// hash-checking every chunk against the blob's chunk list first.
fn open_blob(section_key: &[u8; 32], blob: &[u8], padded_length: u64) -> Result<Vec<u8>> {
    let chunks = payload::chunk_count(padded_length);
    let mut out = Vec::with_capacity(padded_length as usize);
    for index in 0..chunks {
        let (cs, ce) = payload::chunk_range(padded_length, index);
        let ct_len = (ce - cs) + crypto::AEAD_TAG_LEN as u64;
        let ct_off = chunk_ct_offset(index);
        let ct = blob
            .get(ct_off as usize..(ct_off + ct_len) as usize)
            .context("payload blob chunk out of bounds")?;
        out.extend_from_slice(&crypto::open_chunk(section_key, index, ct)?);
    }
    Ok(out)
}

/// Absolute ciphertext offset of chunk `index` within a chunked encrypted
/// section (each stored chunk is `CHUNK_SIZE + tag` bytes except the last).
pub fn chunk_ct_offset(index: u64) -> u64 {
    index * (CHUNK_SIZE as u64 + crypto::AEAD_TAG_LEN as u64)
}

/// Decrypt the private manifest of a sealed artifact with the content key.
pub fn open_private_manifest(bytes: &[u8], content_key: &[u8; 32]) -> Result<PrivateManifest> {
    let header = layout::read_header(bytes)?;
    if header.flags & layout::FLAG_ENCRYPTED == 0 {
        bail!("artifact is not sealed");
    }
    let entries = layout::decode_directory(layout::slice(
        bytes,
        header.directory_offset,
        header.directory_len,
    )?)?;
    let private_entry = entries
        .iter()
        .find(|e| e.tag == TAG_PRIVATE)
        .context("sealed artifact has no private manifest entry")?;
    let private_ct = layout::slice(bytes, private_entry.offset, private_entry.length)?;
    let private_key = crypto::section_key(content_key, "private");
    let plain = crypto::open_chunk(&private_key, 0, private_ct)?;
    ciborium::de::from_reader(plain.as_slice()).context("decode private manifest")
}

fn check_access_scopes(components: &[ComponentRef], payloads: &[PayloadRef]) -> Result<()> {
    for comp in components {
        for scope in &comp.access {
            let payload_ref = payload::resolve_payload(payloads, &scope.payload)?;
            let node = payload::find(&payload_ref.root, &scope.path)
                .with_context(|| format!("access scope '{}' not found", scope.path))?;
            if node.hash != scope.hash {
                bail!("access scope '{}' hash mismatch", scope.path);
            }
        }
    }
    Ok(())
}

fn check_access_scopes_private(
    components: &[PrivateComponent],
    payloads: &[PayloadRef],
) -> Result<()> {
    for comp in components {
        for scope in &comp.access {
            let payload_ref = payload::resolve_payload(payloads, &scope.payload)?;
            let node = payload::find(&payload_ref.root, &scope.path)
                .with_context(|| format!("access scope '{}' not found", scope.path))?;
            if node.hash != scope.hash {
                bail!("access scope '{}' hash mismatch", scope.path);
            }
        }
    }
    Ok(())
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
