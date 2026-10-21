use serde::{Deserialize, Serialize};

/// Payload files are hashed as a Merkle tree over fixed-size chunks. Files at
/// or below one chunk hash to a single chunk (and therefore to the same digest
/// as the whole file); larger files produce a multi-chunk tree root, enabling
/// range reads and per-chunk verification without reading the whole file.
pub const CHUNK_SIZE: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Enums — typed domain model (replaces the previous bare `String` fields).
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
}

impl EntryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EntryKind::File => "file",
            EntryKind::Dir => "dir",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum AccessMode {
    Read,
}

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

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    Zstd,
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
    pub namespace: String,
    pub name: String,
    pub version: u32,
}

impl CapabilityId {
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

#[derive(Serialize, Deserialize, Debug)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub format_version: u32,
    pub interface: InterfaceRef,
    pub components: Vec<ComponentRef>,
    pub capabilities: Vec<CapabilityId>,
    pub execution: ExecutionProfile,
    pub resources: ResourceLimits,
    pub policy: CapabilityPolicy,
    pub provenance: Provenance,
    pub payloads: Vec<PayloadRef>,
    pub hashes: SectionHashes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InterfaceRef {
    pub inline: bool,
    pub length: u64,
    pub hash: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ComponentRef {
    pub name: String,
    pub world: String,
    pub length: u64,
    pub hash: String,
    pub exports: Vec<ExportEntry>,
    pub access: Vec<AccessScope>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExportEntry {
    pub capability: String,
    pub export: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccessScope {
    pub path: String,
    pub hash: String,
    pub mode: AccessMode,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExecutionProfile {
    pub profile: String,
    pub deterministic: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResourceLimits {
    pub memory_max: u64,
    pub cpu_fuel: u64,
    pub output_max: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CapabilityPolicy {
    pub self_read: bool,
    pub network: bool,
    pub filesystem: bool,
    pub clock: bool,
    pub random: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Provenance {
    pub data: Publisher,
    pub algorithm: Publisher,
    pub artifact: Publisher,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Publisher {
    pub publisher: String,
    pub signature: Option<String>,
}

impl Publisher {
    pub fn empty() -> Self {
        Self {
            publisher: String::new(),
            signature: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PayloadRef {
    pub root: PayloadNode,
    pub media_type: String,
    pub length: u64,
    pub hash: String,
    pub compressed: Option<Compression>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PayloadNode {
    pub kind: EntryKind,
    pub name: String,
    pub hash: String,
    pub length: u64,
    pub layout: Option<PayloadLayout>,
    pub chunks: Vec<String>,
    pub entries: Vec<PayloadNode>,
}

/// Hashes of the *other* sections, used to verify each section independently of
/// the manifest's own encoding. The manifest hash and root hash are *not* stored
/// here — they are derived (root lives in the header; manifest hash lives in the
/// directory), which keeps the manifest free of self-referential hashes.
#[derive(Serialize, Deserialize, Debug)]
pub struct SectionHashes {
    pub interface: String,
    pub wasm: Vec<String>,
    pub payload: Vec<String>,
}
