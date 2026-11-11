//! CAF host runtime.
//!
//! Opens a `.caf` artifact **lazily** over a [`PayloadSource`]: the boot area
//! (header, manifest, interface, directory) plus the component bytes — needed
//! for admission — are read and verified at open time; payload bytes stay on
//! the backing store and are Merkle-verified per chunk on first read. Every
//! byte handed to a component is verified before use; bytes that are never
//! read are never verified. This is what lets a host open a large remote
//! artifact after reading only a few KB.
//!
//! The runtime admits a component through the `caf-security` import-resolution
//! policy, instantiates it, exposes the read-only `payload-fs` host ABI (scoped
//! to the component's declared access), and enforces all four declared resource
//! budgets: fuel (engine), memory (store limits + no unbounded host buffering),
//! read (backing-store accounting), and output (emit/log plus the return
//! channel: result values and bytes the host pulls out of guest memory).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use wasmtime::{
    Caller, Config, Engine, Extern, Linker, Module, Store, StoreLimits, StoreLimitsBuilder,
};

use caf_core::{crypto, hex, identity, layout, manifest, payload};
use caf_security::{Import, Meter};

pub use wasmtime::{Val, ValType};

// ---------------------------------------------------------------------------
// Payload backing store.
// ---------------------------------------------------------------------------

/// The source payload bytes are read from. The runtime only ever touches the
/// artifact through this trait: a local byte slice, a local file, or an HTTP
/// Range / object-store client are interchangeable behind it.
pub trait PayloadSource: Send + Sync {
    /// Read `[offset, offset+len)`; implementations must bounds-check.
    fn read_at(&self, offset: u64, len: u64) -> Result<Vec<u8>>;
    /// Total byte length of the artifact.
    fn total_len(&self) -> u64;
}

/// An in-memory artifact.
pub struct SliceSource {
    bytes: Vec<u8>,
}

impl SliceSource {
    /// Wrap in-memory artifact bytes as a [`PayloadSource`].
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl PayloadSource for SliceSource {
    fn read_at(&self, offset: u64, len: u64) -> Result<Vec<u8>> {
        Ok(layout::slice(&self.bytes, offset, len)?.to_vec())
    }

    fn total_len(&self) -> u64 {
        self.bytes.len() as u64
    }
}

/// A [`PayloadSource`] backed by a local file: positional reads under a mutex,
/// so the artifact opens lazily without loading into memory.
pub struct FileSource {
    file: Mutex<std::fs::File>,
    len: u64,
}

impl FileSource {
    /// Open a local `.caf` file for lazy, positional reads.
    pub fn open(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let len = file.metadata()?.len();
        Ok(Self {
            file: Mutex::new(file),
            len,
        })
    }
}

impl PayloadSource for FileSource {
    fn read_at(&self, offset: u64, len: u64) -> Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let mut buf = vec![0u8; usize::try_from(len).context("read length out of range")?];
        let mut file = self
            .file
            .lock()
            .map_err(|_| anyhow::anyhow!("file lock poisoned"))?;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn total_len(&self) -> u64 {
        self.len
    }
}

// ---------------------------------------------------------------------------
// Artifact.
// ---------------------------------------------------------------------------

/// A parsed `.caf` artifact. Created either fully verified ([`Artifact::open`])
/// or lazily verified over a backing store ([`Artifact::open_source`]).
pub struct Artifact {
    source: Arc<dyn PayloadSource>,
    header: layout::Header,
    manifest: manifest::Manifest,
    directory: Vec<layout::DirectoryEntry>,
    /// Sealed-artifact state (content key, blob geometry, chunk hashes).
    sealed: Option<SealedState>,
    /// Bounded LRU cache of verified chunk bytes, keyed by the chunk's absolute
    /// start offset. Verified bytes are safe to reuse; the cache exists because
    /// guests read in small windows while verification needs whole chunks —
    /// without it, physical reads would amplify ~128×.
    chunk_cache: Mutex<ChunkCache>,
}

/// Decryption state of a sealed (`FLAG_ENCRYPTED`) artifact. The synthesized
/// `manifest` holds the plaintext view (names, tree, access scopes); this
/// state holds what the stored ciphertext needs.
struct SealedState {
    /// The unwrapped 32-byte content key.
    content_key: [u8; 32],
    /// Absolute offset of the payload ciphertext blob section.
    blob_offset: u64,
    /// Padded plaintext length (power of two).
    padded_length: u64,
    /// Global ciphertext chunk hashes of the payload blob.
    ct_chunk_hashes: Vec<String>,
    /// Path → (start offset within the plaintext blob, real length).
    file_starts: HashMap<String, (u64, u64)>,
    /// SHA-256 (hex) of each component's *plaintext* bytes.
    component_plaintext_hashes: Vec<String>,
}

/// Verified-chunk LRU with a fixed capacity (64 × 1 MiB chunks max).
struct ChunkCache {
    map: HashMap<u64, Vec<u8>>,
    order: std::collections::VecDeque<u64>,
}

impl ChunkCache {
    const CAP: usize = 64;

    fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    fn get(&mut self, key: u64) -> Option<Vec<u8>> {
        if !self.map.contains_key(&key) {
            return None;
        }
        self.order.retain(|k| *k != key);
        self.order.push_back(key);
        self.map.get(&key).cloned()
    }

    fn insert(&mut self, key: u64, bytes: Vec<u8>) {
        if self.map.contains_key(&key) {
            return;
        }
        while self.order.len() >= Self::CAP {
            if let Some(evict) = self.order.pop_front() {
                self.map.remove(&evict);
            }
        }
        self.order.push_back(key);
        self.map.insert(key, bytes);
    }
}

/// Read-only access to CAF contents, without execution admission checks.
/// Integrity, signatures and decryption are checked exactly as at runtime
/// open; payload contents are verified lazily as they are read. This wrapper
/// deliberately does not expose an `Artifact` that could be instantiated.
pub struct ArtifactContents(Artifact);

impl ArtifactContents {
    /// Open a backing store for inspection/export. Sealed artifacts require a key.
    pub fn open(source: Arc<dyn PayloadSource>, key: Option<&[u8; 32]>) -> Result<Self> {
        Ok(Self(Artifact::open_source_keyed(source, key, false)?))
    }

    /// Manifest view. For sealed artifacts, component hashes and lengths
    /// describe ciphertext; names and payload metadata have been decrypted.
    pub fn manifest(&self) -> &manifest::Manifest {
        &self.0.manifest
    }

    /// Original CAF content identity, as a hex string.
    pub fn root_hash(&self) -> String {
        self.0.root_hash()
    }

    /// Payload file paths, Merkle hashes and byte lengths, in stored order.
    pub fn payload_entries(&self) -> Vec<(String, String, u64)> {
        self.0.payload_entries()
    }

    /// Read a verified plaintext payload range; see `Artifact::read_payload_range`.
    pub fn read_payload_range(&self, path: &str, pos: u64, len: u64) -> Result<(Vec<u8>, u64)> {
        self.0.read_payload_range(path, pos, len)
    }

    /// Read a verified component, decrypting it when necessary.
    pub fn wasm_bytes(&self, index: usize) -> Result<Vec<u8>> {
        self.0.wasm_bytes(index)
    }
}

impl Artifact {
    /// Parse and **fully** verify an in-memory artifact (hash chain over every
    /// section, access scopes, signature), then open it. Use this for strict
    /// offline verification; [`Artifact::open_source`] is the lazy equivalent.
    pub fn open(bytes: Vec<u8>) -> Result<Self> {
        caf_core::verify::verify_bytes(&bytes).context("verify artifact")?;
        Self::open_source(Arc::new(SliceSource::new(bytes)))
    }

    /// [`Artifact::open`] for a sealed artifact, additionally decrypting with
    /// the content key.
    pub fn open_with_key(bytes: Vec<u8>, content_key: &[u8; 32]) -> Result<Self> {
        caf_core::verify::verify_bytes_keyed(&bytes, Some(content_key))
            .context("verify artifact")?;
        Self::open_source_keyed(Arc::new(SliceSource::new(bytes)), Some(content_key), true)
    }

    /// Open an artifact over a backing store, reading only the boot area
    /// (header, manifest, interface, directory), the component bytes (small;
    /// needed for admission), and the signature if present. Payload bytes are
    /// **not** read here: they are fetched and Merkle-verified per chunk on
    /// first use, so opening a large artifact costs a few KB of reads.
    pub fn open_source(source: Arc<dyn PayloadSource>) -> Result<Self> {
        Self::open_source_keyed(source, None, true)
    }

    /// [`Artifact::open_source`] for a sealed artifact. Payload chunks are
    /// still lazy: each fetched ciphertext chunk is hash-verified, decrypted,
    /// and only then served.
    pub fn open_source_with_key(
        source: Arc<dyn PayloadSource>,
        content_key: &[u8; 32],
    ) -> Result<Self> {
        Self::open_source_keyed(source, Some(content_key), true)
    }

    fn open_source_keyed(
        source: Arc<dyn PayloadSource>,
        key: Option<&[u8; 32]>,
        admit: bool,
    ) -> Result<Self> {
        let head = source.read_at(0, layout::HEADER_SIZE)?;
        let header = layout::read_header(&head)?;
        if header.flags & layout::FLAG_ENCRYPTED != 0 {
            return Self::open_sealed(source, header, key, admit);
        }

        let manifest_bytes = source.read_at(header.manifest_offset, header.manifest_len)?;
        let directory_bytes = source.read_at(header.directory_offset, header.directory_len)?;
        let directory = layout::decode_directory(&directory_bytes)?;

        // The manifest is pinned by the directory's manifest entry.
        let manifest_entry = directory
            .iter()
            .find(|e| e.tag == layout::TAG_MANIFEST)
            .context("directory has no manifest entry")?;
        let manifest_hash = payload::chunk_hash(&manifest_bytes);
        if manifest_entry.hash != decode_hash(&manifest_hash)? {
            bail!("manifest hash mismatch");
        }
        let manifest = caf_core::version::load_manifest(&manifest_bytes, header.format_version)?;

        // The interface is pinned by the manifest.
        let interface_bytes = source.read_at(header.interface_offset, header.interface_len)?;
        let interface_hash = payload::chunk_hash(&interface_bytes);
        if interface_hash != manifest.hashes.interface || interface_hash != manifest.interface.hash
        {
            bail!("interface hash mismatch");
        }

        // Exactly one payload tree in this format version; compression is
        // reserved — refuse compressed payloads rather than serving bytes the
        // component cannot interpret.
        if manifest.payloads.len() != 1 {
            bail!(
                "expected exactly one payload tree, got {}",
                manifest.payloads.len()
            );
        }
        if manifest.payloads[0].compressed.is_some() {
            bail!("payload compression is reserved in format v1 (not yet implemented)");
        }
        let payload_root = &manifest.payloads[0].root;

        // Payload tree structure and access scopes check against the manifest
        // alone; payload bytes verify lazily, per chunk, on first read.
        payload::verify_tree(payload_root)?;
        for comp in &manifest.components {
            for scope in &comp.access {
                let node = payload::find(payload_root, &scope.path)
                    .with_context(|| format!("access scope '{}' not found", scope.path))?;
                if node.hash != scope.hash {
                    bail!("access scope '{}' hash mismatch", scope.path);
                }
            }
        }

        // Components are read and hash-verified at open: they are small, and
        // admission needs their import lists.
        let component_entries: Vec<_> = directory
            .iter()
            .filter(|e| e.tag == layout::TAG_COMPONENT)
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
        let mut component_imports = Vec::with_capacity(manifest.components.len());
        for (i, comp) in manifest.components.iter().enumerate() {
            let e = component_entries[i];
            let data = source.read_at(e.offset, e.length)?;
            let h = payload::chunk_hash(&data);
            if h != comp.hash || h != manifest.hashes.wasm[i] || e.hash != decode_hash(&h)? {
                bail!("component '{}' hash mismatch", comp.name);
            }
            wasm_hashes.push(h);
            if admit {
                component_imports
                    .push(enumerate_imports(&data).context("admission: enumerate imports")?);
            }
        }

        // Root identity binds everything above together.
        let root_hash = identity::root_hash(
            &manifest_hash,
            &interface_hash,
            &wasm_hashes,
            &payload_root.hash,
        )?;
        if root_hash != header.root_hash {
            bail!("root hash mismatch");
        }

        // The signature section is 96 bytes; verify it at open. The signature
        // covers the header root hash (Encrypt-then-Sign for sealed artifacts;
        // the same rule keeps plaintext artifacts uniform).
        if header.flags & layout::FLAG_SIGNED != 0 {
            let sig_entry = directory
                .iter()
                .find(|e| e.tag == layout::TAG_SIGNATURE)
                .context("signed artifact has no signature directory entry")?;
            let sig_bytes = source.read_at(sig_entry.offset, sig_entry.length)?;
            if sig_bytes.len() != 96 {
                bail!(
                    "signature section has unexpected length {}",
                    sig_bytes.len()
                );
            }
            if !payload::verify_signature(&sig_bytes[..32], &sig_bytes[32..], &root_hash) {
                bail!("invalid signature");
            }
        }

        if admit {
            // Admission, part 1: a declared-but-unsupported capability is a hard
            // error at open time, not a silent no-op at run time. The execution
            // profile likewise must name a machine-checkable configuration.
            caf_security::check_policy_supported(&manifest.policy)
                .map_err(|e| anyhow::anyhow!("admission rejected: {e}"))?;
            caf_security::check_execution_profile(&manifest.execution)
                .map_err(|e| anyhow::anyhow!("admission rejected: {e}"))?;
            // Admission, part 2: every component import must resolve against the
            // declared policy before anyone can instantiate it (fail-closed).
            for (comp, imports) in manifest.components.iter().zip(&component_imports) {
                caf_security::resolve_imports(&manifest.policy, imports).map_err(|e| {
                    anyhow::anyhow!("admission rejected for component '{}': {e}", comp.name)
                })?;
            }
        }

        Ok(Self {
            source,
            header,
            manifest,
            directory,
            sealed: None,
            chunk_cache: Mutex::new(ChunkCache::new()),
        })
    }

    /// Open a sealed (`FLAG_ENCRYPTED`) artifact: verify every stored
    /// (ciphertext) hash and the signature, unwrap the private manifest with
    /// the content key, decrypt the components (small; admission needs their
    /// imports), and synthesize the plaintext manifest view. Payload chunks
    /// stay lazy.
    fn open_sealed(
        source: Arc<dyn PayloadSource>,
        header: layout::Header,
        key: Option<&[u8; 32]>,
        admit: bool,
    ) -> Result<Self> {
        let content_key = *key.context(
            "artifact is sealed (FLAG_ENCRYPTED); supply the content key via \
             open_with_key / open_source_with_key",
        )?;

        let envelope_bytes = source.read_at(header.manifest_offset, header.manifest_len)?;
        let directory_bytes = source.read_at(header.directory_offset, header.directory_len)?;
        let directory = layout::decode_directory(&directory_bytes)?;

        let envelope = caf_core::version::load_envelope(&envelope_bytes, header.format_version)?;
        let crypto = &caf_core::version::spec(header.format_version)?.crypto;
        if envelope.encryption.aead != crypto.aead
            || envelope.encryption.wrap != crypto.wrap
            || envelope.encryption.padding != crypto.padding
        {
            bail!("unsupported encryption parameters");
        }

        let manifest_entry = directory
            .iter()
            .find(|e| e.tag == layout::TAG_MANIFEST)
            .context("directory has no manifest entry")?;
        let envelope_hash = payload::chunk_hash(&envelope_bytes);
        if manifest_entry.hash != decode_hash(&envelope_hash)? {
            bail!("envelope hash mismatch");
        }

        let interface_bytes = source.read_at(header.interface_offset, header.interface_len)?;
        let interface_hash = payload::chunk_hash(&interface_bytes);
        if interface_hash != envelope.interface.hash {
            bail!("interface hash mismatch");
        }

        // Private manifest: decrypt and cross-check the section hash.
        let private_entry = directory
            .iter()
            .find(|e| e.tag == layout::TAG_PRIVATE)
            .context("sealed artifact has no private manifest entry")?;
        let private_ct = source.read_at(private_entry.offset, private_entry.length)?;
        if payload::chunk_hash(&private_ct) != envelope.private.hash {
            bail!("private manifest hash mismatch");
        }
        let private_key = crypto::section_key(&content_key, "private");
        let private_plain = crypto::open_chunk(&private_key, 0, &private_ct)?;
        let private: manifest::PrivateManifest =
            ciborium::de::from_reader(private_plain.as_slice())
                .context("decode private manifest")?;
        if private.payloads.len() != 1 {
            bail!(
                "expected exactly one payload tree, got {}",
                private.payloads.len()
            );
        }
        if private.components.len() != envelope.components.len() {
            bail!("private/envelope component count mismatch");
        }

        // Components: hash-check the ciphertext, decrypt, re-check the
        // plaintext hash from the private manifest, then enumerate imports.
        let component_entries: Vec<_> = directory
            .iter()
            .filter(|e| e.tag == layout::TAG_COMPONENT)
            .collect();
        if component_entries.len() != envelope.components.len() {
            bail!(
                "component count mismatch: directory {}, envelope {}",
                component_entries.len(),
                envelope.components.len()
            );
        }
        let mut component_ct_hashes = Vec::with_capacity(envelope.components.len());
        let mut component_imports = Vec::with_capacity(envelope.components.len());
        for (i, section) in envelope.components.iter().enumerate() {
            let e = component_entries[i];
            let ct = source.read_at(e.offset, e.length)?;
            let h = payload::chunk_hash(&ct);
            if h != section.hash || e.hash != decode_hash(&h)? {
                bail!("sealed component {i} hash mismatch");
            }
            let component_key = crypto::section_key(&content_key, &format!("component/{i}"));
            let plain = crypto::open_chunk(&component_key, 0, &ct)?;
            if payload::chunk_hash(&plain) != private.components[i].hash {
                bail!(
                    "component '{}' plaintext hash mismatch",
                    private.components[i].name
                );
            }
            component_ct_hashes.push(h);
            if admit {
                component_imports
                    .push(enumerate_imports(&plain).context("admission: enumerate imports")?);
            }
        }

        // Payload blob: one ciphertext section; lazy per-chunk verify+decrypt
        // on read.
        let payload_entries: Vec<_> = directory
            .iter()
            .filter(|e| e.tag == layout::TAG_PAYLOAD)
            .collect();
        if payload_entries.len() != 1 {
            bail!("sealed artifact must carry exactly one payload blob");
        }
        let blob_entry = payload_entries[0];
        let payload_ref = &private.payloads[0];
        let padded_length = payload_ref
            .padded_length
            .context("sealed payload ref misses padded_length")?;
        if payload::chunk_count(padded_length) != payload_ref.chunks.len() as u64 {
            bail!("payload chunk hash count mismatch");
        }
        let blob_len =
            padded_length + payload_ref.chunks.len() as u64 * crypto::AEAD_TAG_LEN as u64;
        if blob_entry.length != blob_len || blob_entry.length != envelope.payload.length {
            bail!("payload blob length mismatch");
        }
        // The blob's bytes verify lazily, per ciphertext chunk, on first read
        // (the whole-blob hash is checked by the eager `verify` path only);
        // the directory entry must still agree with the envelope.
        let blob_hash = envelope.payload.hash.clone();
        if blob_entry.hash != decode_hash(&blob_hash)? {
            bail!("payload blob directory hash mismatch");
        }

        // Payload tree structure and access scopes check against the private
        // manifest alone; payload bytes verify per chunk on first read.
        let payload_root = &payload_ref.root;
        payload::verify_tree(payload_root)?;
        for comp in &private.components {
            for scope in &comp.access {
                let node = payload::find(payload_root, &scope.path)
                    .with_context(|| format!("access scope '{}' not found", scope.path))?;
                if node.hash != scope.hash {
                    bail!("access scope '{}' hash mismatch", scope.path);
                }
            }
        }

        // Root identity over the stored (ciphertext) sections.
        let root_hash = identity::root_hash(
            &envelope_hash,
            &interface_hash,
            &component_ct_hashes,
            &blob_hash,
        )?;
        if root_hash != header.root_hash {
            bail!("root hash mismatch");
        }

        // Signature over the ciphertext root hash (Encrypt-then-Sign).
        if header.flags & layout::FLAG_SIGNED != 0 {
            let sig_entry = directory
                .iter()
                .find(|e| e.tag == layout::TAG_SIGNATURE)
                .context("signed artifact has no signature directory entry")?;
            let sig_bytes = source.read_at(sig_entry.offset, sig_entry.length)?;
            if sig_bytes.len() != 96 {
                bail!(
                    "signature section has unexpected length {}",
                    sig_bytes.len()
                );
            }
            if !payload::verify_signature(&sig_bytes[..32], &sig_bytes[32..], &root_hash) {
                bail!("invalid signature");
            }
        }

        // Synthesize the plaintext manifest view the rest of the runtime (and
        // the host ABI) works against.
        let manifest = manifest::Manifest {
            name: private.name.clone(),
            version: private.version.clone(),
            format_version: envelope.format_version,
            interface: envelope.interface.clone(),
            components: private
                .components
                .iter()
                .enumerate()
                .map(|(i, c)| manifest::ComponentRef {
                    name: c.name.clone(),
                    world: c.world.clone(),
                    length: envelope.components[i].length,
                    hash: envelope.components[i].hash.clone(),
                    exports: c.exports.clone(),
                    access: c.access.clone(),
                })
                .collect(),
            capabilities: envelope.capabilities.clone(),
            execution: envelope.execution.clone(),
            resources: envelope.resources.clone(),
            policy: envelope.policy.clone(),
            provenance: private.provenance.clone(),
            payloads: private.payloads.clone(),
            hashes: manifest::SectionHashes {
                interface: envelope.interface.hash.clone(),
                wasm: envelope.components.iter().map(|c| c.hash.clone()).collect(),
                payload: vec![envelope.payload.hash.clone()],
            },
        };

        let mut file_starts = HashMap::new();
        let mut at = 0u64;
        let mut file_list = Vec::new();
        payload::collect_files(&manifest.payloads[0].root, "", &mut file_list);
        for (path, _hash, len) in &file_list {
            file_starts.insert(path.clone(), (at, *len));
            at += len;
        }
        if at != payload_ref.length {
            bail!("payload real length mismatch");
        }

        if admit {
            // Admission: identical policy gates to the plaintext path.
            caf_security::check_policy_supported(&manifest.policy)
                .map_err(|e| anyhow::anyhow!("admission rejected: {e}"))?;
            caf_security::check_execution_profile(&manifest.execution)
                .map_err(|e| anyhow::anyhow!("admission rejected: {e}"))?;
            for (comp, imports) in private.components.iter().zip(&component_imports) {
                caf_security::resolve_imports(&manifest.policy, imports).map_err(|e| {
                    anyhow::anyhow!("admission rejected for component '{}': {e}", comp.name)
                })?;
            }
        }

        let sealed = SealedState {
            content_key,
            blob_offset: blob_entry.offset,
            padded_length,
            ct_chunk_hashes: payload_ref.chunks.clone(),
            file_starts,
            component_plaintext_hashes: private.components.iter().map(|c| c.hash.clone()).collect(),
        };

        Ok(Self {
            source,
            header,
            manifest,
            directory,
            sealed: Some(sealed),
            chunk_cache: Mutex::new(ChunkCache::new()),
        })
    }

    /// Artifact name from the manifest.
    pub fn name(&self) -> &str {
        &self.manifest.name
    }

    /// Artifact version from the manifest.
    pub fn version(&self) -> &str {
        &self.manifest.version
    }

    /// Hex-encoded root hash — the artifact's content identity.
    pub fn root_hash(&self) -> String {
        hex::encode(&self.header.root_hash)
    }

    /// The components embedded in the artifact.
    pub fn components(&self) -> &[manifest::ComponentRef] {
        &self.manifest.components
    }

    /// Capabilities the artifact exposes.
    pub fn capabilities(&self) -> &[manifest::CapabilityId] {
        &self.manifest.capabilities
    }

    /// `(path, length)` for every payload file, in deterministic DFS order.
    pub fn payload_files(&self) -> Vec<(String, u64)> {
        let mut files = Vec::new();
        payload::collect_files(&self.manifest.payloads[0].root, "", &mut files);
        files
            .into_iter()
            .map(|(path, _hash, len)| (path, len))
            .collect()
    }

    /// `(path, hash, length)` for every payload file, in deterministic DFS order.
    pub fn payload_entries(&self) -> Vec<(String, String, u64)> {
        let mut files = Vec::new();
        payload::collect_files(&self.manifest.payloads[0].root, "", &mut files);
        files
    }

    /// Read a payload file's bytes by its `/`-prefixed path.
    pub fn read_payload(&self, path: &str) -> Result<Vec<u8>> {
        let map = self.payload_map()?;
        let &(_offset, length) = map
            .get(path)
            .with_context(|| format!("payload '{path}' not found"))?;
        Ok(self.read_payload_range(path, 0, length)?.0)
    }

    /// Read `[pos, pos + len)` of a payload file, fetching and Merkle-verifying
    /// every covering chunk against the manifest's chunk hashes. Returns the
    /// requested bytes plus the number of bytes actually pulled from the
    /// backing store (for read budgeting).
    pub fn read_payload_range(&self, path: &str, pos: u64, len: u64) -> Result<(Vec<u8>, u64)> {
        self.read_payload_range_metered(path, pos, len, None)
    }

    fn read_payload_range_metered(
        &self,
        path: &str,
        pos: u64,
        len: u64,
        mut meter: Option<&mut Meter>,
    ) -> Result<(Vec<u8>, u64)> {
        let map = self.payload_map()?;
        let &(offset, flen) = map
            .get(path)
            .with_context(|| format!("payload '{path}' not found"))?;
        if len > flen || pos > flen - len {
            bail!("payload range [{pos}, {pos}+{len}) out of bounds for '{path}' ({flen} bytes)");
        }
        if len == 0 {
            return Ok((Vec::new(), 0));
        }

        // Sealed artifact: `offset` is the file's start within the plaintext
        // blob; covering ciphertext chunks are hash-verified, then decrypted.
        if let Some(sealed) = &self.sealed {
            return self.read_sealed_range(sealed, offset, pos, len, meter);
        }

        let node = payload::find(&self.manifest.payloads[0].root, path)
            .with_context(|| format!("payload '{path}' not in tree"))?;

        let mut fetched = 0u64;
        if node.chunks.len() <= 1 {
            // Single-chunk (or empty) file: the root hash is the plain SHA-256
            // of the bytes. Fetch once, verify, slice out the window.
            let data = self.fetch_verified(offset, flen, &node.hash, &mut fetched, meter)?;
            let start = usize::try_from(pos).context("offset out of range")?;
            let end = start
                .checked_add(usize::try_from(len).context("length out of range")?)
                .context("range overflow")?;
            Ok((data[start..end].to_vec(), fetched))
        } else {
            let chunk_size = manifest::CHUNK_SIZE as u64;
            let first = pos / chunk_size;
            let last = (pos + len - 1) / chunk_size;
            let mut out = Vec::with_capacity(usize::try_from(len).context("length out of range")?);
            let mut index = first;
            while index <= last {
                let (cs, ce) = payload::chunk_range(flen, index);
                let expected = node
                    .chunks
                    .get(usize::try_from(index).context("chunk index out of range")?)
                    .context("chunk hash missing")?;
                let data = self.fetch_verified(
                    offset + cs,
                    ce - cs,
                    expected,
                    &mut fetched,
                    meter.as_deref_mut(),
                )?;
                let from =
                    usize::try_from(pos.saturating_sub(cs)).context("offset out of range")?;
                let remaining = usize::try_from(len).context("length out of range")? - out.len();
                let take = (data.len() - from).min(remaining);
                out.extend_from_slice(&data[from..from + take]);
                index += 1;
            }
            Ok((out, fetched))
        }
    }

    /// Read a range of a sealed payload blob: fetch each covering ciphertext
    /// chunk, verify it against the chunk hashes from the private manifest,
    /// decrypt, and slice out the window. Padding is never served (the caller
    /// bounds-checked against the real file length).
    fn read_sealed_range(
        &self,
        sealed: &SealedState,
        file_start: u64,
        pos: u64,
        len: u64,
        mut meter: Option<&mut Meter>,
    ) -> Result<(Vec<u8>, u64)> {
        let abs_start = file_start + pos;
        let abs_end = abs_start + len;
        let chunk_size = manifest::CHUNK_SIZE as u64;
        let first = abs_start / chunk_size;
        let last = (abs_end - 1) / chunk_size;
        let mut out = Vec::with_capacity(usize::try_from(len).context("length out of range")?);
        let mut fetched = 0u64;
        let mut index = first;
        while index <= last {
            let chunk =
                self.fetch_chunk_sealed(sealed, index, &mut fetched, meter.as_deref_mut())?;
            let chunk_base = index * chunk_size;
            let from =
                usize::try_from(abs_start.saturating_sub(chunk_base)).context("offset range")?;
            let remaining = usize::try_from(len).context("length out of range")? - out.len();
            let take = (chunk.len() - from).min(remaining);
            out.extend_from_slice(&chunk[from..from + take]);
            index += 1;
        }
        Ok((out, fetched))
    }

    /// Fetch ciphertext chunk `index` of a sealed payload blob, hash-verify,
    /// decrypt, and cache the plaintext (LRU, keyed by ciphertext offset).
    fn fetch_chunk_sealed(
        &self,
        sealed: &SealedState,
        index: u64,
        fetched: &mut u64,
        meter: Option<&mut Meter>,
    ) -> Result<Vec<u8>> {
        let chunk_size = manifest::CHUNK_SIZE as u64;
        let plain_len = chunk_size.min(sealed.padded_length - index * chunk_size);
        let ct_off = sealed.blob_offset + index * (chunk_size + crypto::AEAD_TAG_LEN as u64);
        let ct_len = plain_len + crypto::AEAD_TAG_LEN as u64;
        {
            let mut cache = self
                .chunk_cache
                .lock()
                .map_err(|_| anyhow::anyhow!("chunk cache lock poisoned"))?;
            if let Some(data) = cache.get(ct_off) {
                return Ok(data);
            }
        }
        charge_fetch(meter, ct_len)?;
        let ct = self.source.read_at(ct_off, ct_len)?;
        *fetched += ct_len;
        let expected = sealed
            .ct_chunk_hashes
            .get(usize::try_from(index).context("chunk index out of range")?)
            .context("chunk hash missing")?;
        if &payload::chunk_hash(&ct) != expected {
            bail!("payload chunk {index} ciphertext hash mismatch");
        }
        let payload_key = crypto::section_key(&sealed.content_key, "payload");
        let plain = crypto::open_chunk(&payload_key, index, &ct)?;
        self.chunk_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("chunk cache lock poisoned"))?
            .insert(ct_off, plain.clone());
        Ok(plain)
    }

    /// Fetch `[chunk_off, chunk_off + len)` from the backing store and verify
    /// the bytes against `expected_hash`. Verified chunks are served from a
    /// bounded LRU cache; only cache misses pull from the store (and are the
    /// only bytes charged to the read budget).
    fn fetch_verified(
        &self,
        chunk_off: u64,
        len: u64,
        expected_hash: &str,
        fetched: &mut u64,
        meter: Option<&mut Meter>,
    ) -> Result<Vec<u8>> {
        {
            let mut cache = self
                .chunk_cache
                .lock()
                .map_err(|_| anyhow::anyhow!("chunk cache lock poisoned"))?;
            if let Some(data) = cache.get(chunk_off) {
                return Ok(data);
            }
        }
        charge_fetch(meter, len)?;
        let data = self.source.read_at(chunk_off, len)?;
        *fetched += len;
        if payload::chunk_hash(&data) != expected_hash {
            bail!("payload chunk at offset {chunk_off} hash mismatch");
        }
        self.chunk_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("chunk cache lock poisoned"))?
            .insert(chunk_off, data.clone());
        Ok(data)
    }

    fn payload_map(&self) -> Result<HashMap<String, (u64, u64)>> {
        // Sealed artifact: paths map into the plaintext blob (offset, real
        // length); decryption happens in the read path.
        if let Some(sealed) = &self.sealed {
            return Ok(sealed.file_starts.clone());
        }
        let mut files = Vec::new();
        payload::collect_files(&self.manifest.payloads[0].root, "", &mut files);
        let entries: Vec<_> = self
            .directory
            .iter()
            .filter(|e| e.tag == layout::TAG_PAYLOAD)
            .collect();
        if entries.len() != files.len() {
            bail!(
                "payload directory/file count mismatch: {} vs {}",
                entries.len(),
                files.len()
            );
        }
        let mut map = HashMap::new();
        for (i, (path, _hash, _len)) in files.iter().enumerate() {
            map.insert(path.clone(), (entries[i].offset, entries[i].length));
        }
        Ok(map)
    }

    /// Read and verify a component, decrypting it when the artifact is sealed.
    fn wasm_bytes(&self, index: usize) -> Result<Vec<u8>> {
        let entries: Vec<_> = self
            .directory
            .iter()
            .filter(|e| e.tag == layout::TAG_COMPONENT)
            .collect();
        let e = entries
            .get(index)
            .with_context(|| format!("component index {index} out of range"))?;
        let data = self.source.read_at(e.offset, e.length)?;
        // Bytes were verified at open, but the backing store may have changed
        // since; re-check before instantiating.
        let comp = &self.manifest.components[index];
        if payload::chunk_hash(&data) != comp.hash {
            bail!("component '{}' hash mismatch", comp.name);
        }
        // Sealed artifact: `data` is the ciphertext section; decrypt and check
        // the plaintext hash from the private manifest.
        if let Some(sealed) = &self.sealed {
            let key = crypto::section_key(&sealed.content_key, &format!("component/{index}"));
            let plain = crypto::open_chunk(&key, 0, &data)?;
            if payload::chunk_hash(&plain) != sealed.component_plaintext_hashes[index] {
                bail!("component '{}' plaintext hash mismatch", comp.name);
            }
            return Ok(plain);
        }
        Ok(data)
    }
}

// Reserve before attempting the physical read, including attempts that later
// fail verification or I/O. Such work must never be free to retry.
fn charge_fetch(meter: Option<&mut Meter>, len: u64) -> Result<()> {
    if let Some(meter) = meter
        && !meter.charge_read(len)
    {
        bail!("payload read exceeds the read budget");
    }
    Ok(())
}

fn decode_hash(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("hash is not 32 bytes"))
}

// ---------------------------------------------------------------------------
// Host state and the payload-fs ABI.
// ---------------------------------------------------------------------------

struct OpenFile {
    path: String,
    pos: u64,
}

/// Path → (offset, len) descriptors plus directory listings. No payload bytes
/// are loaded up front: components fetch through the artifact's verifying
/// reader on demand, and every fetched byte is charged against `read_max`.
struct Fs {
    files: HashMap<String, (u64, u64)>,
    dirs: HashMap<String, Vec<String>>,
}

struct HostState {
    fs: Fs,
    fds: Vec<Option<OpenFile>>,
    artifact: Arc<Artifact>,
    meter: Meter,
    emitted: Vec<u8>,
    limits: StoreLimits,
}

fn build_fs(artifact: &Artifact, access: &[manifest::AccessScope]) -> Result<Fs> {
    let root = &artifact.manifest.payloads[0].root;
    let offsets = artifact.payload_map()?;
    let mut fs = Fs {
        files: HashMap::new(),
        dirs: HashMap::new(),
    };
    build_fs_rec(root, "/", access, &offsets, &mut fs)?;
    Ok(fs)
}

fn build_fs_rec(
    node: &manifest::PayloadNode,
    path: &str,
    access: &[manifest::AccessScope],
    offsets: &HashMap<String, (u64, u64)>,
    fs: &mut Fs,
) -> Result<()> {
    if !is_reachable(path, access) {
        return Ok(());
    }
    if node.kind == manifest::EntryKind::File {
        let desc = offsets
            .get(path)
            .with_context(|| format!("payload '{path}' has no directory entry"))?;
        fs.files.insert(path.to_string(), *desc);
        return Ok(());
    }
    let mut names = Vec::new();
    for child in &node.entries {
        let child_path = if path == "/" {
            format!("/{}", child.name)
        } else {
            format!("{path}/{}", child.name)
        };
        if is_reachable(&child_path, access) {
            names.push(child.name.clone());
            build_fs_rec(child, &child_path, access, offsets, fs)?;
        }
    }
    fs.dirs.insert(path.to_string(), names);
    Ok(())
}

/// A node is reachable if it is an ancestor of, equal to, or descendant of a
/// declared access scope. `access = []` yields an empty filesystem (deny all).
fn is_reachable(path: &str, access: &[manifest::AccessScope]) -> bool {
    if path == "/" {
        return !access.is_empty();
    }
    for scope in access {
        let sp = scope.path.trim_end_matches('/');
        if sp.is_empty() {
            return true;
        }
        if path == sp {
            return true;
        }
        if path.starts_with(&format!("{sp}/")) {
            return true;
        }
        if sp.starts_with(&format!("{path}/")) {
            return true;
        }
    }
    false
}

/// Validate the complete range before allocating any host-side buffer.
fn guest_range(
    caller: &mut Caller<'_, HostState>,
    ptr: i32,
    len: i32,
) -> Option<std::ops::Range<usize>> {
    let start = usize::try_from(ptr).ok()?;
    let len = usize::try_from(len).ok()?;
    if len as u64 > caller.data().meter.budgets().memory_max {
        return None;
    }
    let end = start.checked_add(len)?;
    let mem = match caller.get_export("memory") {
        Some(Extern::Memory(m)) => m,
        _ => return None,
    };
    (end <= mem.data_size(&*caller)).then_some(start..end)
}

fn read_guest_mem(caller: &mut Caller<'_, HostState>, ptr: i32, len: i32) -> Option<Vec<u8>> {
    let range = guest_range(caller, ptr, len)?;
    let mem = match caller.get_export("memory") {
        Some(Extern::Memory(m)) => m,
        _ => return None,
    };
    Some(mem.data(&*caller).get(range)?.to_vec())
}

fn read_guest_output(caller: &mut Caller<'_, HostState>, ptr: i32, len: i32) -> Option<Vec<u8>> {
    guest_range(caller, ptr, len)?;
    if !caller.data_mut().meter.charge_output(len as u64) {
        return None;
    }
    read_guest_mem(caller, ptr, len)
}

fn read_guest_str(caller: &mut Caller<'_, HostState>, ptr: i32, len: i32) -> Option<String> {
    String::from_utf8(read_guest_mem(caller, ptr, len)?).ok()
}

fn write_guest(caller: &mut Caller<'_, HostState>, ptr: i32, data: &[u8]) -> bool {
    match caller.get_export("memory") {
        Some(Extern::Memory(m)) => m.write(caller, ptr as usize, data).is_ok(),
        _ => false,
    }
}

// -- payload-fs --------------------------------------------------------------

fn host_open(mut caller: Caller<'_, HostState>, path_ptr: i32, path_len: i32) -> i32 {
    let path = match read_guest_str(&mut caller, path_ptr, path_len) {
        Some(p) => p,
        None => return -1,
    };
    let state = caller.data_mut();
    if !state.fs.files.contains_key(&path) {
        return -1;
    }
    // Reuse a vacated slot when possible so fds stay small and `close` is real.
    if let Some((i, slot)) = state
        .fds
        .iter_mut()
        .enumerate()
        .find(|(_, slot)| slot.is_none())
    {
        *slot = Some(OpenFile { path, pos: 0 });
        i as i32
    } else {
        state.fds.push(Some(OpenFile { path, pos: 0 }));
        (state.fds.len() - 1) as i32
    }
}

fn host_read(mut caller: Caller<'_, HostState>, fd: i32, buf_ptr: i32, buf_len: i32) -> i32 {
    if fd < 0 || buf_len <= 0 {
        return -1;
    }
    let (path, pos, n) = {
        let state = caller.data();
        let Some(file) = state.fds.get(fd as usize).and_then(|slot| slot.as_ref()) else {
            return -1;
        };
        let Some(&(_, flen)) = state.fs.files.get(&file.path) else {
            return -1;
        };
        (
            file.path.clone(),
            file.pos,
            flen.saturating_sub(file.pos).min(buf_len as u64),
        )
    };
    if n == 0 {
        return 0;
    }
    if guest_range(&mut caller, buf_ptr, n as i32).is_none() {
        return -1;
    }
    let data = {
        let state = caller.data_mut();
        // A cache miss reserves its budget before I/O and cache insertion.
        // Denied reads cannot populate the cache and become free on retry.
        match state
            .artifact
            .read_payload_range_metered(&path, pos, n, Some(&mut state.meter))
        {
            Ok((data, _)) => data,
            Err(_) => return -1,
        }
    };
    if !write_guest(&mut caller, buf_ptr, &data) {
        return -1;
    }
    if let Some(file) = caller.data_mut().fds[fd as usize].as_mut() {
        file.pos = pos + n;
    }
    data.len() as i32
}

fn host_readdir(
    mut caller: Caller<'_, HostState>,
    path_ptr: i32,
    path_len: i32,
    buf_ptr: i32,
    buf_len: i32,
) -> i32 {
    let path = match read_guest_str(&mut caller, path_ptr, path_len) {
        Some(p) => p,
        None => return -1,
    };
    let names = caller
        .data()
        .fs
        .dirs
        .get(&path)
        .cloned()
        .unwrap_or_default();
    let listing = names.join("\n");
    let data = listing.as_bytes();
    let n = data.len().min(buf_len as usize);
    if n == 0 {
        return 0;
    }
    if write_guest(&mut caller, buf_ptr, &data[..n]) {
        n as i32
    } else {
        -1
    }
}

/// `stat(path) -> i64`: file length, `-2` for a directory, `-1` if not found.
fn host_stat(mut caller: Caller<'_, HostState>, path_ptr: i32, path_len: i32) -> i64 {
    let path = match read_guest_str(&mut caller, path_ptr, path_len) {
        Some(p) => p,
        None => return -1,
    };
    let state = caller.data();
    if let Some(&(_offset, len)) = state.fs.files.get(&path) {
        len as i64
    } else if state.fs.dirs.contains_key(&path) {
        -2
    } else {
        -1
    }
}

/// `seek(fd, offset) -> i32`: absolute positioning within the file.
fn host_seek(mut caller: Caller<'_, HostState>, fd: i32, offset: i64) -> i32 {
    if fd < 0 || offset < 0 {
        return -1;
    }
    let state = caller.data_mut();
    let Some(file) = state
        .fds
        .get_mut(fd as usize)
        .and_then(|slot| slot.as_mut())
    else {
        return -1;
    };
    let Some(&(_off, flen)) = state.fs.files.get(&file.path) else {
        return -1;
    };
    let offset = offset as u64;
    if offset > flen {
        return -1;
    }
    file.pos = offset;
    0
}

fn host_close(mut caller: Caller<'_, HostState>, fd: i32) -> i32 {
    if fd < 0 {
        return -1;
    }
    let state = caller.data_mut();
    // Vacate the slot for real; `open` reuses freed slots.
    match state.fds.get_mut(fd as usize) {
        Some(slot) if slot.is_some() => {
            *slot = None;
            0
        }
        _ => -1,
    }
}

// -- meta I/O ----------------------------------------------------------------

/// `self_size() -> i64`: total byte length of the artifact.
fn host_self_size(caller: Caller<'_, HostState>) -> i64 {
    caller.data().artifact.source.total_len() as i64
}

/// `emit(ptr, len) -> i32`: structured output, charged against `output_max`.
fn host_emit(mut caller: Caller<'_, HostState>, ptr: i32, len: i32) -> i32 {
    let Some(bytes) = read_guest_output(&mut caller, ptr, len) else {
        return -1;
    };
    let state = caller.data_mut();
    state.emitted.extend_from_slice(&bytes);
    0
}

/// `log(ptr, len) -> i32`: diagnostic output, also charged against `output_max`.
fn host_log(mut caller: Caller<'_, HostState>, ptr: i32, len: i32) -> i32 {
    let Some(bytes) = read_guest_output(&mut caller, ptr, len) else {
        return -1;
    };
    eprintln!("[caf log] {}", String::from_utf8_lossy(&bytes));
    0
}

/// `abort(code)`: deterministic trap with the guest-supplied code.
fn host_abort(code: i32) -> wasmtime::Result<()> {
    Err(wasmtime::format_err!("caf abort({code})"))
}

// ---------------------------------------------------------------------------
// Admission.
// ---------------------------------------------------------------------------

/// Enumerate the core-module imports of a component binary. Unparseable bytes
/// fail closed (the engine would reject them anyway).
fn enumerate_imports(wasm: &[u8]) -> Result<Vec<Import>> {
    use wasmparser::{Parser, Payload};
    let mut out = Vec::new();
    for payload in Parser::new(0).parse_all(wasm) {
        if let Payload::ImportSection(reader) = payload.context("parse wasm imports")? {
            for group in reader {
                for item in group.context("parse wasm import")? {
                    let (_offset, import) = item.context("parse wasm import")?;
                    out.push(Import::new(import.module, import.name));
                }
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Instantiation and invocation.
// ---------------------------------------------------------------------------

/// An instantiated component bound to a single `.caf` artifact.
pub struct Session {
    store: Store<HostState>,
    instance: wasmtime::Instance,
}

/// Metered consumption so far in this session `(read_bytes, output_bytes)`.
pub struct Usage {
    /// Bytes fetched from the payload backing store.
    pub read: u64,
    /// Bytes emitted as output (emit/log, results, host memory reads).
    pub output: u64,
}

impl Session {
    /// The wasm signature (params/results) of an exported function.
    pub fn signature(&mut self, name: &str) -> Result<wasmtime::FuncType> {
        let func = self
            .instance
            .get_func(&mut self.store, name)
            .with_context(|| format!("export '{name}' not found"))?;
        Ok(func.ty(&self.store))
    }

    /// Call an exported function with typed arguments.
    pub fn call(&mut self, name: &str, args: &[Val]) -> Result<Box<[Val]>> {
        let func = self
            .instance
            .get_func(&mut self.store, name)
            .with_context(|| format!("export '{name}' not found"))?;
        let result_arity = func.ty(&self.store).results().len();
        let mut results = vec![Val::I32(0); result_arity];
        func.call(&mut self.store, args, &mut results)
            .map_err(|e| anyhow::anyhow!("call '{name}': {e}"))?;
        // Return values cross the host boundary: charge them against the
        // output budget, exactly like emit/log bytes.
        let bytes: u64 = results.iter().map(val_size).sum();
        if !self.store.data_mut().meter.charge_output(bytes) {
            return Err(anyhow::anyhow!(
                "call '{name}': result exceeds the output budget"
            ));
        }
        Ok(results.into_boxed_slice())
    }

    /// Read `len` bytes from the component's linear memory at `ptr`.
    pub fn read_memory(&mut self, ptr: u32, len: u32) -> Result<Vec<u8>> {
        let mem = self
            .instance
            .get_memory(&mut self.store, "memory")
            .context("component has no exported memory")?;
        let start = ptr as usize;
        let end = start
            .checked_add(len as usize)
            .context("guest memory range overflow")?;
        if len as u64 > self.store.data().meter.budgets().memory_max
            || end > mem.data_size(&self.store)
        {
            bail!("read component memory: range out of bounds");
        }
        if !self.store.data_mut().meter.charge_output(len as u64) {
            bail!("read_memory exceeds the output budget");
        }
        Ok(mem.data(&self.store)[start..end].to_vec())
    }

    /// Bytes emitted via `caf.emit` so far.
    pub fn emitted(&self) -> &[u8] {
        &self.store.data().emitted
    }

    /// Metered consumption so far.
    pub fn usage(&self) -> Usage {
        let meter = &self.store.data().meter;
        Usage {
            read: meter.read_used(),
            output: meter.output_used(),
        }
    }
}

/// Instantiate the component named `component` from an artifact.
pub fn instantiate(artifact: &Arc<Artifact>, component: &str) -> Result<Session> {
    let index = artifact
        .components()
        .iter()
        .position(|c| c.name == component)
        .with_context(|| format!("component '{component}' not found"))?;
    instantiate_at(artifact, index)
}

/// Instantiate the `index`-th component.
pub fn instantiate_at(artifact: &Arc<Artifact>, index: usize) -> Result<Session> {
    let comp = artifact
        .components()
        .get(index)
        .with_context(|| format!("component index {index} out of range"))?;
    let wasm = artifact.wasm_bytes(index)?;
    let fs = build_fs(artifact, &comp.access)?;

    // Admission was enforced for every component at open time; resolve again
    // here to obtain the grant set — only granted imports are provided by the
    // linker, so a component structurally cannot reach undeclared authority.
    let imports = enumerate_imports(&wasm).context("admission: enumerate imports")?;
    let grants = caf_security::resolve_imports(&artifact.manifest.policy, &imports)
        .map_err(|e| anyhow::anyhow!("admission rejected for component '{}': {e}", comp.name))?;

    let mut config = Config::new();
    config.consume_fuel(true);
    // caf-d1 (validated as deterministic at open time): canonical NaN
    // semantics, no platform-dependent relaxed-SIMD, no threads — the same
    // (FileId, FunctionId, Args) yields the same result everywhere.
    if artifact.manifest.execution.deterministic {
        config.cranelift_nan_canonicalization(true);
        config.relaxed_simd_deterministic(true);
        config.wasm_threads(false);
    }
    let engine = Engine::new(&config)?;
    let module =
        Module::new(&engine, &wasm).map_err(|e| anyhow::anyhow!("compile component: {e}"))?;

    let mut linker = Linker::<HostState>::new(&engine);
    if grants.payload_fs {
        linker.func_wrap("caf", "open", host_open)?;
        linker.func_wrap("caf", "read", host_read)?;
        linker.func_wrap("caf", "readdir", host_readdir)?;
        linker.func_wrap("caf", "stat", host_stat)?;
        linker.func_wrap("caf", "seek", host_seek)?;
        linker.func_wrap("caf", "close", host_close)?;
    }
    linker.func_wrap("caf", "self_size", host_self_size)?;
    linker.func_wrap("caf", "emit", host_emit)?;
    linker.func_wrap("caf", "log", host_log)?;
    linker.func_wrap("caf", "abort", host_abort)?;

    let limits = StoreLimitsBuilder::new()
        .memory_size(artifact.manifest.resources.memory_max as usize)
        .build();
    let mut store = Store::new(
        &engine,
        HostState {
            fs,
            fds: Vec::new(),
            artifact: artifact.clone(),
            meter: Meter::new((&artifact.manifest.resources).into()),
            emitted: Vec::new(),
            limits,
        },
    );
    store.set_fuel(artifact.manifest.resources.cpu_fuel)?;
    store.limiter(|state: &mut HostState| &mut state.limits);

    let instance = linker.instantiate(&mut store, &module)?;
    Ok(Session { store, instance })
}

/// Whether a single-result `i32`/`i64` return should be interpreted as the
/// packed `(ptr | len << 32)` string convention.
pub fn is_packed_result(results: &[Val]) -> bool {
    matches!(results, [Val::I32(_)] | [Val::I64(_)])
}

/// Byte size of a result value crossing the host boundary.
fn val_size(v: &Val) -> u64 {
    match v {
        Val::I32(_) | Val::F32(_) => 4,
        Val::I64(_) | Val::F64(_) => 8,
        Val::V128(_) => 16,
        _ => 0,
    }
}
