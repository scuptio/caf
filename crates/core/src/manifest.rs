//! The artifact manifest: the container's self-description ("DNA"), serialized
//! as canonical CBOR (see `doc/spec/container-format.md` §2).
//!
//! The manifest carries **no absolute offsets** — section layout lives in the
//! binary directory ([`crate::layout`]) — so its content hash is independent of
//! where sections happen to land, and there are no self-referential hash fields.

use serde::{Deserialize, Serialize};

/// Payload files are hashed as a Merkle tree over fixed-size chunks. Files at
/// or below one chunk hash to a single chunk (and therefore to the same digest
/// as the whole file); larger files produce a multi-chunk tree root, enabling
/// range reads and per-chunk verification without reading the whole file.
pub const CHUNK_SIZE: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Enums — typed domain model (replaces the previous bare `String` fields).
// ---------------------------------------------------------------------------

/// Kind of a payload tree node.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    /// A regular file: a leaf node with content hashes.
    File,
    /// A directory: an interior node whose hash covers its children.
    Dir,
}

impl EntryKind {
    /// The lowercase wire name, as serialized in the manifest.
    pub fn as_str(self) -> &'static str {
        match self {
            EntryKind::File => "file",
            EntryKind::Dir => "dir",
        }
    }
}

/// Access mode of a component's payload access scope.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum AccessMode {
    /// Read-only access (the only mode in format v1).
    Read,
}

/// How a payload file's bytes are laid out for reading.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum PayloadLayout {
    /// Whole-block read (single chunk).
    Opaque,
    /// Chunked / range-readable (multiple chunks).
    Range,
    /// Reserved for streaming layout.
    Stream,
}

/// Compression applied to a payload (reserved, not yet implemented).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    /// Zstandard.
    Zstd,
    /// Gzip.
    Gzip,
}

// ---------------------------------------------------------------------------
// Capability id — a namespaced, versioned interface name.
// ---------------------------------------------------------------------------

/// `namespace:name@version`, e.g. `cf:spatial-query@1` or `org:example:infer@2`.
/// The namespace may itself contain `:`; the version is separated by `@` and the
/// name is everything after the *last* `:` before the `@`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CapabilityId {
    /// Namespace prefix, e.g. `cf` or `org:example`.
    pub namespace: String,
    /// Interface name, e.g. `spatial-query`.
    pub name: String,
    /// Interface version (the `@N` suffix).
    pub version: u32,
}

impl CapabilityId {
    /// Parse `namespace:name@version`; the version follows the last `@` and the
    /// name follows the last `:` before it. Both parts must be non-empty.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (name_ns, version) = s
            .rsplit_once('@')
            .ok_or_else(|| format!("capability id '{s}' is missing the '@version' suffix"))?;
        let version: u32 = version
            .parse()
            .map_err(|_| format!("capability id '{s}' has a non-numeric version"))?;
        let (namespace, name) = name_ns
            .rsplit_once(':')
            .ok_or_else(|| format!("capability id '{s}' is missing the ':' separator"))?;
        if namespace.is_empty() || name.is_empty() {
            return Err(format!(
                "capability id '{s}' has an empty namespace or name"
            ));
        }
        Ok(Self {
            namespace: namespace.to_string(),
            name: name.to_string(),
            version,
        })
    }
}

impl std::fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}@{}", self.namespace, self.name, self.version)
    }
}

impl Serialize for CapabilityId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CapabilityId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        CapabilityId::parse(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Manifest — the artifact's self-description. Contains *no* absolute offsets:
// layout (offsets) lives in the binary section directory, keeping the manifest
// content-addressed independently of where sections happen to land.
// ---------------------------------------------------------------------------

/// The artifact's self-description: identity, interface, components,
/// capabilities, execution profile, resource limits, policy, provenance,
/// payload trees, and the hashes of the other sections.
///
/// All manifest structs deny unknown fields: a reader rejects a manifest
/// carrying fields it does not know (fail-closed), so any new field — e.g. an
/// `encrypted` marker — requires a `format_version` major bump rather than
/// being silently ignored.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Artifact name.
    pub name: String,
    /// Artifact version (semver).
    pub version: String,
    /// Container format version (must match the header's).
    pub format_version: u32,
    /// Reference to the interface (WIT text) section.
    pub interface: InterfaceRef,
    /// WASM components embedded in the artifact.
    pub components: Vec<ComponentRef>,
    /// Capabilities the artifact exposes (`namespace:name@version`).
    pub capabilities: Vec<CapabilityId>,
    /// Execution profile the components run under.
    pub execution: ExecutionProfile,
    /// Declared resource budgets.
    pub resources: ResourceLimits,
    /// Capability policy: the ambient authority the artifact requests.
    pub policy: CapabilityPolicy,
    /// Publisher provenance for data, algorithm, and artifact.
    pub provenance: Provenance,
    /// Payload trees (exactly one in format v1).
    pub payloads: Vec<PayloadRef>,
    /// Content hashes of the other sections (interface / wasm / payload).
    pub hashes: SectionHashes,
}

/// Reference to the artifact's interface (WIT text) section.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct InterfaceRef {
    /// Whether the WIT text is inlined in the manifest (unused in format v1).
    pub inline: bool,
    /// Byte length of the interface section.
    pub length: u64,
    /// SHA-256 (hex) of the interface section.
    pub hash: String,
}

/// Manifest binding for one embedded WASM component.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ComponentRef {
    /// Component name (unique within the artifact).
    pub name: String,
    /// WIT world the component implements (empty without a declared interface).
    pub world: String,
    /// Byte length of the component section.
    pub length: u64,
    /// SHA-256 (hex) of the component bytes.
    pub hash: String,
    /// Capability-bound exports (see `doc/spec/caf-abi.md`).
    pub exports: Vec<ExportEntry>,
    /// Payload paths the component may read — a hard runtime invariant.
    pub access: Vec<AccessScope>,
}

/// One exported function, bound to the capability that names it.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ExportEntry {
    /// Capability id (`namespace:name@version`) this export belongs to.
    pub capability: String,
    /// Export name.
    pub export: String,
    /// Function signature (WIT-derived, or a raw WASM export kind when the
    /// component declares no WIT world).
    pub signature: String,
}

/// A payload path a component may read, pinned to the node's hash.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AccessScope {
    /// `/`-prefixed payload path.
    pub path: String,
    /// SHA-256 (hex) of the payload node at `path`.
    pub hash: String,
    /// Access mode (read-only in format v1).
    pub mode: AccessMode,
}

/// A named, machine-checkable engine configuration the components run under.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProfile {
    /// Profile name (this runtime knows `caf-d1`).
    pub profile: String,
    /// Whether execution must be bit-for-bit deterministic.
    pub deterministic: bool,
}

/// Declared resource budgets, enforced at instantiation and run time.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// Maximum guest linear memory, in bytes (engine store limiter).
    pub memory_max: u64,
    /// CPU budget, in fuel units (engine-enforced).
    pub cpu_fuel: u64,
    /// Maximum bytes fetched from the payload backing store.
    pub read_max: u64,
    /// Maximum bytes of output (emit/log, results, host memory reads).
    pub output_max: u64,
}

/// Ambient authority the artifact requests. A capability declared but
/// unsupported by the runtime is a hard admission error (fail-closed).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPolicy {
    /// May read the artifact's own payload (the scoped `payload-fs` host ABI).
    pub self_read: bool,
    /// Network access (unsupported; rejected at admission).
    pub network: bool,
    /// Host filesystem access (unsupported; rejected at admission).
    pub filesystem: bool,
    /// Wall-clock access (unsupported; rejected at admission).
    pub clock: bool,
    /// Randomness access (unsupported; rejected at admission).
    pub random: bool,
}

/// Publisher provenance for the three roles that produced the artifact.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// Who published the input data.
    pub data: Publisher,
    /// Who published the algorithm (interface and components).
    pub algorithm: Publisher,
    /// Who assembled and signed the artifact.
    pub artifact: Publisher,
}

/// A named publisher, optionally carrying a signature reference.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Publisher {
    /// Publisher identity (free-form name).
    pub publisher: String,
    /// Optional signature reference.
    pub signature: Option<String>,
}

impl Publisher {
    /// An anonymous publisher with no signature.
    pub fn empty() -> Self {
        Self {
            publisher: String::new(),
            signature: None,
        }
    }
}

/// Reference to one payload tree: a virtual filesystem of content-hashed files.
/// In a sealed artifact this lives in the *private* manifest and additionally
/// describes the encrypted single-blob layout (`chunks` / `padded_length`).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PayloadRef {
    /// Root node of the Merkle-hashed directory tree. In a sealed artifact the
    /// per-file hashes cover *plaintext* (identity after decryption).
    pub root: PayloadNode,
    /// Media type of the payload bytes.
    pub media_type: String,
    /// Total real plaintext byte length of the payload (sealed artifacts;
    /// unused otherwise).
    pub length: u64,
    /// SHA-256 (hex) of the tree root (plaintext mode) or of the encrypted
    /// payload blob's ciphertext (sealed mode) — mirrors the directory entry.
    pub hash: String,
    /// Compression, if any (reserved in format v1).
    pub compressed: Option<Compression>,
    /// Padded plaintext length of the payload blob (sealed artifacts only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub padded_length: Option<u64>,
    /// Global ciphertext chunk hashes of the payload blob (sealed artifacts
    /// only), covering chunks of `padded_length` bytes including AEAD tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<String>,
}

/// One node of the payload tree: a file (with chunk hashes) or a directory
/// (whose hash covers its children).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PayloadNode {
    /// File or directory.
    pub kind: EntryKind,
    /// Base name within the parent (empty for the root).
    pub name: String,
    /// Content hash (hex): the file's Merkle root, or the directory hash.
    pub hash: String,
    /// Byte length (files only; directories are 0).
    pub length: u64,
    /// Chunked-read layout hint (files only).
    pub layout: Option<PayloadLayout>,
    /// Per-chunk SHA-256 hashes (hex) for multi-chunk files.
    pub chunks: Vec<String>,
    /// Children (directories only).
    pub entries: Vec<PayloadNode>,
}

/// Hashes of the *other* sections, used to verify each section independently of
/// the manifest's own encoding. The manifest hash and root hash are *not* stored
/// here — they are derived (root lives in the header; manifest hash lives in the
/// directory), which keeps the manifest free of self-referential hashes.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct SectionHashes {
    /// SHA-256 (hex) of the interface section.
    pub interface: String,
    /// SHA-256 (hex) of each component, in manifest order.
    pub wasm: Vec<String>,
    /// SHA-256 (hex) of each payload tree root.
    pub payload: Vec<String>,
}

// ---------------------------------------------------------------------------
// Sealed artifacts (FLAG_ENCRYPTED): the manifest section holds the public
// envelope; everything sensitive moves into the encrypted private manifest.
// ---------------------------------------------------------------------------

/// Reference to one ciphertext (or fixed-format plaintext) section: its byte
/// length and SHA-256 (hex) over the *stored* bytes.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct SectionRef {
    /// Byte length of the section as stored.
    pub length: u64,
    /// SHA-256 (hex) of the stored bytes.
    pub hash: String,
}

/// Reference to the single encrypted payload blob.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PayloadBlobRef {
    /// Byte length of the stored ciphertext (padded plaintext + per-chunk tags).
    pub length: u64,
    /// Padded plaintext length (power of two, >= 4096).
    pub padded_length: u64,
    /// Number of 1 MiB ciphertext chunks.
    pub chunks: u64,
    /// SHA-256 (hex) of the stored ciphertext blob.
    pub hash: String,
}

/// AEAD algorithm for sealed sections.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AeadAlgorithm {
    /// AES-256-GCM with per-section sub-keys and counter nonces.
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
}

/// Key-wrap algorithm for keybox stanzas.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyWrapAlgorithm {
    /// P-256 ECDH + domain-separated SHA-256 KDF + AES-256-GCM wrap.
    #[serde(rename = "p256-ecdh-sha256")]
    P256EcdhSha256,
}

/// Payload length-hiding padding profile.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum PaddingProfile {
    /// Padded to the next power of two, 4 KiB floor.
    #[serde(rename = "pow2")]
    Pow2,
}

/// Encryption parameters of a sealed artifact (public; algorithms only, no keys).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct EncryptionInfo {
    /// AEAD for sealed sections.
    pub aead: AeadAlgorithm,
    /// Keybox stanza wrap algorithm.
    pub wrap: KeyWrapAlgorithm,
    /// Payload padding profile.
    pub padding: PaddingProfile,
}

/// The public **envelope manifest** of a sealed artifact: only what admission
/// and discovery need before decryption — no names, no payload tree, no
/// provenance. All hashes cover the *stored* (ciphertext) bytes.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// Container format version (must match the header's).
    pub format_version: u32,
    /// Reference to the interface (WIT text) section (plaintext).
    pub interface: InterfaceRef,
    /// Anonymous ciphertext refs of the WASM components, in manifest order.
    pub components: Vec<SectionRef>,
    /// Capabilities the artifact exposes (`namespace:name@version`).
    pub capabilities: Vec<CapabilityId>,
    /// Execution profile the components run under.
    pub execution: ExecutionProfile,
    /// Declared resource budgets.
    pub resources: ResourceLimits,
    /// Capability policy: the ambient authority the artifact requests.
    pub policy: CapabilityPolicy,
    /// Encryption parameters.
    pub encryption: EncryptionInfo,
    /// Encrypted private manifest section.
    pub private: SectionRef,
    /// Keybox section (plaintext recipient stanzas).
    pub keybox: SectionRef,
    /// Encrypted payload blob.
    pub payload: PayloadBlobRef,
}

/// A component's private metadata: everything the envelope hides.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PrivateComponent {
    /// Component name (unique within the artifact).
    pub name: String,
    /// WIT world the component implements (empty without a declared interface).
    pub world: String,
    /// SHA-256 (hex) of the *plaintext* component bytes.
    pub hash: String,
    /// Capability-bound exports (see `doc/spec/caf-abi.md`).
    pub exports: Vec<ExportEntry>,
    /// Payload paths the component may read — a hard runtime invariant.
    pub access: Vec<AccessScope>,
}

/// The encrypted **private manifest**: names, versions, provenance, component
/// bindings, and the payload tree with real (plaintext) lengths and hashes.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PrivateManifest {
    /// Artifact name.
    pub name: String,
    /// Artifact version (semver).
    pub version: String,
    /// Per-component private metadata, in envelope component order.
    pub components: Vec<PrivateComponent>,
    /// Publisher provenance for data, algorithm, and artifact.
    pub provenance: Provenance,
    /// Payload trees (exactly one in format v1).
    pub payloads: Vec<PayloadRef>,
}
