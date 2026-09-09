use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
pub struct Config {
    pub name: String,
    pub version: String,
    #[serde(default = "default_format_version")]
    pub format_version: u32,
    #[serde(default)]
    pub interfaces: Vec<String>,
    pub payload: PayloadConfig,
    #[serde(default)]
    pub execution: ExecutionConfig,
    #[serde(default)]
    pub resources: ResourceConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub sign: Option<SignConfig>,
    #[serde(default)]
    pub components: Vec<ComponentConfig>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Deserialize)]
pub struct PayloadConfig {
    pub root: String,
    #[serde(default = "default_media_type")]
    pub media_type: String,
}

#[derive(Deserialize)]
pub struct ComponentConfig {
    pub name: String,
    pub world: String,
    pub path: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub access: Vec<String>,
}

#[derive(Deserialize)]
pub struct ExecutionConfig {
    #[serde(default = "default_profile")]
    pub profile: String,
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

#[derive(Deserialize)]
pub struct ResourceConfig {
    #[serde(default = "default_memory_max")]
    pub memory_max: u64,
    #[serde(default = "default_cpu_fuel")]
    pub cpu_fuel: u64,
    #[serde(default = "default_output_max")]
    pub output_max: u64,
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            memory_max: default_memory_max(),
            cpu_fuel: default_cpu_fuel(),
            output_max: default_output_max(),
        }
    }
}

#[derive(Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_true")]
    pub self_read: bool,
    #[serde(default = "default_false")]
    pub network: bool,
    #[serde(default = "default_false")]
    pub filesystem: bool,
    #[serde(default = "default_false")]
    pub clock: bool,
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

#[derive(Deserialize)]
pub struct SignConfig {
    pub seed: String,
}

fn default_format_version() -> u32 {
    1
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

fn default_output_max() -> u64 {
    64 * 1024 * 1024
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

pub fn load(path: &Path) -> Result<(Config, PathBuf)> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    let cfg: Config =
        toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))?;
    let base = path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    Ok((cfg, base))
}
