//! The `build.toml` schema and its loading: artifact identity, interfaces,
//! payload root, execution profile, resource limits, capability policy,
//! signing, and components — with defaults matching the format's v1 profile.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The root `build.toml` table: everything `assemble` needs to build an
/// artifact.
#[derive(Deserialize)]
pub struct Config {
    /// Artifact name.
    pub name: String,
    /// Artifact version (semver, per artifact).
    pub version: String,
    /// Container format version to write; defaults to the current version and
    /// must be one this build can also read (`caf_core::version`).
    #[serde(default = "default_format_version")]
    pub format_version: u32,
    /// WIT source files, concatenated in the listed order.
    #[serde(default)]
    pub interfaces: Vec<String>,
    /// `[[payloads]]`: the payload trees; the first is the default payload,
    /// mounted at `/` in the guest filesystem.
    #[serde(default)]
    pub payloads: Vec<PayloadConfig>,
    /// `[execution]`: the execution profile.
    #[serde(default)]
    pub execution: ExecutionConfig,
    /// `[resources]`: runtime resource limits.
    #[serde(default)]
    pub resources: ResourceConfig,
    /// `[policy]`: the deny-by-default capability policy.
    #[serde(default)]
    pub policy: PolicyConfig,
    /// `[sign]`: sign the root hash with this ed25519 seed.
    #[serde(default)]
    pub sign: Option<SignConfig>,
    /// `[encrypt]`: seal the artifact (components, payload, private manifest).
    #[serde(default)]
    pub encrypt: Option<EncryptConfig>,
    /// `[[components]]`: the WASM components, in manifest order.
    #[serde(default)]
    pub components: Vec<ComponentConfig>,
    /// Artifact-level capabilities; each must be implemented by a component.
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// `[encrypt]`: seal the artifact (components, payload, private manifest).
#[derive(Deserialize)]
pub struct EncryptConfig {
    /// P-256 recipient public keys (uncompressed SEC-1, hex). One anonymous
    /// keybox stanza is emitted per recipient.
    pub recipients: Vec<String>,
    /// Optional 32-byte seed (hex) for **convergent** builds: the content key
    /// is derived from the seed and complete plaintext/private metadata
    /// identity. Keybox ephemerals also bind the resulting content key, so
    /// identical inputs reproduce identical ciphertext without nonce reuse
    /// across distinct plaintexts. Omit it
    /// for a fresh random content key per build.
    #[serde(default)]
    pub key_seed: Option<String>,
}

/// `[[payloads]]`: one payload tree.
#[derive(Deserialize)]
pub struct PayloadConfig {
    /// Payload name (unique within the artifact); the first payload is the
    /// default, mounted at `/` in the guest filesystem.
    pub name: String,
    /// Payload root directory (relative to the `build.toml`).
    pub root: String,
    /// Media type recorded for the payload (default `application/octet-stream`).
    #[serde(default = "default_media_type")]
    pub media_type: String,
}

/// `[[components]]`: one WASM component and its bindings.
#[derive(Deserialize)]
pub struct ComponentConfig {
    /// Component name (unique within the artifact).
    pub name: String,
    /// WIT world name; empty means no world (raw export fallback).
    pub world: String,
    /// Path to the `.wasm` file (relative to the `build.toml`).
    pub path: String,
    /// Capabilities this component implements (bound to world exports).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Payload paths this component may read (access scopes).
    #[serde(default)]
    pub access: Vec<String>,
    /// Embed the WIT world metadata into the module at build time.
    #[serde(default)]
    pub embed: bool,
    /// `[components.build]`: compile the component before packing.
    #[serde(default)]
    pub build: Option<ComponentBuild>,
}

/// `[components.build]`: how to produce `path` before packing.
#[derive(Deserialize)]
pub struct ComponentBuild {
    /// Shell command run in the project directory (`sh -c` / `cmd /C`).
    pub command: String,
    /// File the command produces; copied to `path` when it differs from `path`.
    #[serde(default)]
    pub artifact: Option<String>,
}

/// `[execution]`: the execution profile.
#[derive(Deserialize)]
pub struct ExecutionConfig {
    /// Execution profile name (v1: `caf-d1`).
    #[serde(default = "default_profile")]
    pub profile: String,
    /// Whether execution must be deterministic (v1 profiles require it).
    #[serde(default = "default_true")]
    pub deterministic: bool,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            profile: default_profile(),
            deterministic: true,
        }
    }
}

/// `[resources]`: runtime resource limits enforced by the host.
#[derive(Deserialize)]
pub struct ResourceConfig {
    /// Maximum component linear memory in bytes.
    #[serde(default = "default_memory_max")]
    pub memory_max: u64,
    /// CPU budget in wasmtime fuel units.
    #[serde(default = "default_cpu_fuel")]
    pub cpu_fuel: u64,
    /// Maximum payload bytes read per session.
    #[serde(default = "default_read_max")]
    pub read_max: u64,
    /// Maximum output bytes (results, emit/log, memory reads) per session.
    #[serde(default = "default_output_max")]
    pub output_max: u64,
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            memory_max: default_memory_max(),
            cpu_fuel: default_cpu_fuel(),
            read_max: default_read_max(),
            output_max: default_output_max(),
        }
    }
}

/// `[policy]`: the deny-by-default capability policy.
#[derive(Deserialize)]
pub struct PolicyConfig {
    /// Components may read the artifact's own payload via the `caf.*` ABI.
    #[serde(default = "default_true")]
    pub self_read: bool,
    /// Network access (unsupported in format v1).
    #[serde(default = "default_false")]
    pub network: bool,
    /// Host filesystem access (unsupported in format v1).
    #[serde(default = "default_false")]
    pub filesystem: bool,
    /// Wall-clock access (unsupported in format v1).
    #[serde(default = "default_false")]
    pub clock: bool,
    /// Randomness access (unsupported in format v1).
    #[serde(default = "default_false")]
    pub random: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            self_read: true,
            network: false,
            filesystem: false,
            clock: false,
            random: false,
        }
    }
}

/// `[sign]`: sign the root hash with this ed25519 seed.
#[derive(Deserialize)]
pub struct SignConfig {
    /// 32-byte ed25519 seed (hex). Keep it secret; the fingerprint of the
    /// matching public key is what trust stores record.
    pub seed: String,
}

fn default_format_version() -> u32 {
    caf_core::version::CURRENT.version
}

fn default_media_type() -> String {
    "application/octet-stream".to_string()
}

fn default_profile() -> String {
    "caf-d1".to_string()
}

fn default_memory_max() -> u64 {
    256 * 1024 * 1024
}

fn default_cpu_fuel() -> u64 {
    100_000_000
}

fn default_read_max() -> u64 {
    1024 * 1024 * 1024
}

fn default_output_max() -> u64 {
    64 * 1024 * 1024
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

/// Load `build.toml`, returning the parsed config and the directory all
/// relative paths resolve against.
pub fn load(path: &Path) -> Result<(Config, PathBuf)> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    let cfg: Config =
        toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))?;
    let base = path
        .parent()
        .map(|p| {
            if p.as_os_str().is_empty() {
                PathBuf::from(".")
            } else {
                p.to_path_buf()
            }
        })
        .unwrap_or_else(|| PathBuf::from("."));
    Ok((cfg, base))
}
