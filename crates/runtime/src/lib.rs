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

use caf_core::{hex, identity, layout, manifest, payload};
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
    /// Bounded LRU cache of verified chunk bytes, keyed by the chunk's absolute
    /// start offset. Verified bytes are safe to reuse; the cache exists because
    /// guests read in small windows while verification needs whole chunks —
    /// without it, physical reads would amplify ~128×.
    chunk_cache: Mutex<ChunkCache>,
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

impl Artifact {
    /// Parse and **fully** verify an in-memory artifact (hash chain over every
    /// section, access scopes, signature), then open it. Use this for strict
    /// offline verification; [`Artifact::open_source`] is the lazy equivalent.
    pub fn open(bytes: Vec<u8>) -> Result<Self> {
        caf_core::verify::verify_bytes(&bytes).context("verify artifact")?;
        Self::open_source(Arc::new(SliceSource::new(bytes)))
    }

    /// Open an artifact over a backing store, reading only the boot area
    /// (header, manifest, interface, directory), the component bytes (small;
    /// needed for admission), and the signature if present. Payload bytes are
    /// **not** read here: they are fetched and Merkle-verified per chunk on
    /// first use, so opening a large artifact costs a few KB of reads.
    pub fn open_source(source: Arc<dyn PayloadSource>) -> Result<Self> {
        let head = source.read_at(0, layout::HEADER_SIZE)?;
        let header = layout::read_header(&head)?;

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
        let manifest: manifest::Manifest =
            ciborium::de::from_reader(manifest_bytes.as_slice()).context("decode manifest")?;
        if header.format_version != manifest.format_version {
            bail!(
                "format version mismatch: header {}, manifest {}",
                header.format_version,
                manifest.format_version
            );
        }

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
            component_imports
                .push(enumerate_imports(&data).context("admission: enumerate imports")?);
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

        // The signature section is 96 bytes; verify it at open.
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
            if !payload::verify_signature(&sig_bytes[..32], &sig_bytes[32..], &manifest_bytes) {
                bail!("invalid signature");
            }
        }

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

        Ok(Self {
            source,
            header,
            manifest,
            directory,
            chunk_cache: Mutex::new(ChunkCache::new()),
        })
    }

    pub fn name(&self) -> &str {
        &self.manifest.name
    }

    pub fn version(&self) -> &str {
        &self.manifest.version
    }

    pub fn root_hash(&self) -> String {
        hex::encode(&self.header.root_hash)
    }

    pub fn components(&self) -> &[manifest::ComponentRef] {
        &self.manifest.components
    }

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
        let node = payload::find(&self.manifest.payloads[0].root, path)
            .with_context(|| format!("payload '{path}' not in tree"))?;

        let mut fetched = 0u64;
        if node.chunks.len() <= 1 {
            // Single-chunk (or empty) file: the root hash is the plain SHA-256
            // of the bytes. Fetch once, verify, slice out the window.
            let data = self.fetch_verified(offset, flen, &node.hash, &mut fetched)?;
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
                let data = self.fetch_verified(offset + cs, ce - cs, expected, &mut fetched)?;
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
        Ok(data)
    }
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

fn read_guest_mem(caller: &mut Caller<'_, HostState>, ptr: i32, len: i32) -> Option<Vec<u8>> {
    if ptr < 0 || len < 0 {
        return None;
    }
    let mem = match caller.get_export("memory") {
        Some(Extern::Memory(m)) => m,
        _ => return None,
    };
    let mut buf = vec![0u8; len as usize];
    mem.read(caller, ptr as usize, &mut buf).ok()?;
    Some(buf)
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
    // Fetch through the artifact's verifying reader; every byte pulled from the
    // backing store is charged against the read budget. The borrow of the store
    // data ends before we write back into guest memory.
    let fetched = {
        let state = caller.data_mut();
        let Some(file) = state.fds.get(fd as usize).and_then(|slot| slot.as_ref()) else {
            return -1;
        };
        let path = file.path.clone();
        let pos = file.pos;
        let Some(&(_offset, flen)) = state.fs.files.get(&path) else {
            return -1;
        };
        let remaining = flen.saturating_sub(pos);
        let n = remaining.min(buf_len as u64);
        if n == 0 {
            return 0;
        }
        match state.artifact.read_payload_range(&path, pos, n) {
            Ok((data, fetched_bytes)) => {
                if !state.meter.charge_read(fetched_bytes) {
                    return -1; // read budget exhausted
                }
                if let Some(file) = state.fds[fd as usize].as_mut() {
                    file.pos = pos + n;
                }
                data
            }
            Err(_) => return -1,
        }
    };
    if write_guest(&mut caller, buf_ptr, &fetched) {
        fetched.len() as i32
    } else {
        -1
    }
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
    let Some(bytes) = read_guest_mem(&mut caller, ptr, len) else {
        return -1;
    };
    let state = caller.data_mut();
    if !state.meter.charge_output(bytes.len() as u64) {
        return -1; // output budget exhausted
    }
    state.emitted.extend_from_slice(&bytes);
    0
}

/// `log(ptr, len) -> i32`: diagnostic output, also charged against `output_max`.
fn host_log(mut caller: Caller<'_, HostState>, ptr: i32, len: i32) -> i32 {
    let Some(bytes) = read_guest_mem(&mut caller, ptr, len) else {
        return -1;
    };
    let state = caller.data_mut();
    if !state.meter.charge_output(bytes.len() as u64) {
        return -1;
    }
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
    pub read: u64,
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
        // Bytes pulled out of guest memory are output too (the packed-result
        // channel): charge them before copying anything out.
        if !self.store.data_mut().meter.charge_output(len as u64) {
            return Err(anyhow::anyhow!("read_memory exceeds the output budget"));
        }
        let mem = self
            .instance
            .get_memory(&mut self.store, "memory")
            .context("component has no exported memory")?;
        let mut buf = vec![0u8; len as usize];
        mem.read(&self.store, ptr as usize, &mut buf)
            .context("read component memory")?;
        Ok(buf)
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
