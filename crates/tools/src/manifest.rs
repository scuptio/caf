use serde::Serialize;

pub const ZERO_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Serialize)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub format_version: u32,
    pub interface: InterfaceRef,
    pub components: Vec<ComponentRef>,
    pub capabilities: Vec<String>,
    pub execution: ExecutionProfile,
    pub resources: ResourceLimits,
    pub policy: CapabilityPolicy,
    pub provenance: Provenance,
    pub payloads: Vec<PayloadRef>,
    pub hashes: SectionHashes,
}

#[derive(Serialize)]
pub struct InterfaceRef {
    pub inline: bool,
    pub offset: u64,
    pub length: u64,
    pub hash: String,
}

#[derive(Serialize)]
pub struct ComponentRef {
    pub name: String,
    pub world: String,
    pub offset: u64,
    pub length: u64,
    pub hash: String,
    pub exports: Vec<ExportEntry>,
    pub access: Vec<AccessScope>,
}

#[derive(Serialize)]
pub struct ExportEntry {
    pub capability: String,
    pub export: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct AccessScope {
    pub path: String,
    pub hash: String,
    pub mode: String,
}

#[derive(Serialize)]
pub struct ExecutionProfile {
    pub profile: String,
    pub deterministic: bool,
}

#[derive(Serialize)]
pub struct ResourceLimits {
    pub memory_max: u64,
    pub cpu_fuel: u64,
    pub output_max: u64,
}

#[derive(Serialize)]
pub struct CapabilityPolicy {
    pub self_read: bool,
    pub network: bool,
    pub filesystem: bool,
    pub clock: bool,
    pub random: bool,
}

#[derive(Serialize)]
pub struct Provenance {
    pub data: Publisher,
    pub algorithm: Publisher,
    pub artifact: Publisher,
}

#[derive(Serialize)]
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

#[derive(Serialize)]
pub struct PayloadRef {
    pub root: PayloadNode,
    pub media_type: String,
    pub offset: u64,
    pub length: u64,
    pub hash: String,
    pub compressed: Option<String>,
}

#[derive(Serialize)]
pub struct PayloadNode {
    pub kind: String,
    pub name: String,
    pub hash: String,
    pub offset: u64,
    pub length: u64,
    pub layout: Option<String>,
    pub entries: Vec<PayloadNode>,
}

#[derive(Serialize)]
pub struct SectionHashes {
    pub interface: String,
    pub wasm: Vec<String>,
    pub payload: Vec<String>,
    pub manifest: String,
    pub root: String,
}
