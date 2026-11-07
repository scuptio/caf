use anyhow::Result;
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use caf_core::{hex, layout, manifest, payload, verify};
use caf_runtime::{Artifact, FileSource};

mod assemble;
mod config;
mod exports;
mod run;
mod wit;
mod wizard;

#[cfg(test)]
mod tests;

#[derive(Parser)]
#[command(
    name = "caf-tool",
    version,
    about = "Build Computable Artifact Format (.caf) files"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(
        about = "Compile a payload directory, interfaces and components into a .caf artifact"
    )]
    Build {
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,

        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        #[arg(long, value_name = "FILE")]
        dump_manifest: Option<PathBuf>,
    },

    #[command(about = "Verify a .caf artifact (hash chain, access scopes, signature)")]
    Verify {
        #[arg(value_name = "FILE")]
        file: PathBuf,

        #[arg(
            long,
            value_name = "FILE",
            help = "TOML trust store: [keys] <fingerprint> = \"publisher\""
        )]
        trusted_keys: Option<PathBuf>,

        #[arg(long, help = "Fail unless the artifact is signed by a trusted key")]
        require_trusted: bool,
    },

    #[command(
        about = "Generate an ed25519 signing key (seed for build.toml, fingerprint for trust stores)"
    )]
    Keygen,

    #[command(about = "Print a human-readable summary of a .caf artifact")]
    Inspect {
        #[arg(value_name = "FILE")]
        file: PathBuf,

        #[arg(long, help = "Also print the full manifest as JSON")]
        json: bool,
    },

    #[command(about = "Scaffold a new CAF project (WIT + build config + language skeleton)")]
    New {
        #[arg(value_name = "NAME")]
        name: String,

        #[arg(long, value_name = "LANG", default_value = "rust")]
        lang: wizard::Language,

        #[arg(long, value_name = "DIR", default_value = ".")]
        dir: PathBuf,
    },

    #[command(about = "Execute a component function from a .caf artifact")]
    Run {
        #[arg(value_name = "FILE")]
        file: PathBuf,

        #[arg(short = 'f', long = "fn", alias = "function", value_name = "NAME")]
        function: String,

        #[arg(long, value_name = "A,B,C", value_delimiter = ',')]
        args: Vec<String>,

        #[arg(long, value_name = "NAME")]
        component: Option<String>,

        #[arg(long, help = "Do not decode packed (ptr|len) string results")]
        raw: bool,
    },

    #[command(about = "List the payload files and components of a .caf artifact")]
    Ls {
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },

    #[command(about = "Diff two .caf artifacts (capabilities, components, payload)")]
    Diff {
        #[arg(value_name = "FILE_A")]
        a: PathBuf,

        #[arg(value_name = "FILE_B")]
        b: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Build {
            config,
            output,
            dump_manifest,
        } => {
            let (cfg, base) = config::load(&config)?;
            let built = assemble::assemble(&cfg, &base)?;
            std::fs::write(&output, &built.bytes)?;
            if let Some(p) = dump_manifest {
                let json = serde_json::to_string_pretty(&built.manifest)?;
                std::fs::write(&p, json)?;
            }
            println!("wrote {} ({} bytes)", output.display(), built.bytes.len());
        }
        Command::Verify {
            file,
            trusted_keys,
            require_trusted,
        } => {
            let report = verify::verify(&file)?;
            println!("OK {} {}", report.name, report.version);
            println!("  root hash:     {}", report.root_hash);
            println!("  manifest hash: {}", report.manifest_hash);
            println!("  components:    {}", report.components);
            println!("  payload files: {}", report.payload_files);
            println!("  capabilities:  {}", report.capabilities.len());
            for c in &report.capabilities {
                println!("    - {c}");
            }
            if report.signed {
                let valid = report.signature_valid.unwrap_or(false);
                println!(
                    "  signature:     {}",
                    if valid { "valid" } else { "INVALID" }
                );
                if let Some(fp) = &report.signer_fingerprint {
                    println!("  signer:        {fp}");
                }
            } else {
                println!("  signature:     none (unsigned)");
            }
            if let Some(keys_path) = &trusted_keys {
                let store = TrustStore::load(keys_path)?;
                let trusted = report
                    .signer_fingerprint
                    .as_deref()
                    .and_then(|fp| store.keys.get(fp));
                match trusted {
                    Some(publisher) => println!("  trust:         trusted ({publisher})"),
                    None => println!("  trust:         UNTRUSTED signer"),
                }
                if require_trusted
                    && !(report.signed
                        && report.signature_valid.unwrap_or(false)
                        && trusted.is_some())
                {
                    anyhow::bail!("artifact is not signed by a trusted key");
                }
            } else if require_trusted {
                anyhow::bail!("--require-trusted needs --trusted-keys");
            }
        }
        Command::Keygen => {
            keygen()?;
        }
        Command::Inspect { file, json } => {
            let bytes = std::fs::read(&file)?;
            let header = layout::read_header(&bytes)?;
            let manifest_bytes =
                layout::slice(&bytes, header.manifest_offset, header.manifest_len)?;
            let manifest: manifest::Manifest = ciborium::de::from_reader(manifest_bytes)?;
            println!("name:          {}", manifest.name);
            println!("version:       {}", manifest.version);
            println!("format:        {}", manifest.format_version);
            println!("root hash:     {}", hex::encode(&header.root_hash));
            println!("capabilities:");
            for c in &manifest.capabilities {
                println!("  - {c}");
            }
            println!("components:");
            for c in &manifest.components {
                println!(
                    "  - {} (world: {}, exports: {})",
                    c.name,
                    c.world,
                    c.exports.len()
                );
                for e in &c.exports {
                    println!("      export {} [{}]", e.export, e.signature);
                }
                for a in &c.access {
                    println!("      access {} ({})", a.path, a.hash);
                }
            }
            let mut files = Vec::new();
            payload::collect_files(&manifest.payloads[0].root, "", &mut files);
            println!("payload files: {}", files.len());
            for (path, hash, len) in &files {
                println!("  - {path}  {} bytes  {}", len, hash);
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&manifest)?);
            }
        }
        Command::New { name, lang, dir } => {
            wizard::scaffold(&name, lang, &dir)?;
        }
        Command::Run {
            file,
            function,
            args,
            component,
            raw,
        } => {
            run::run(&file, &function, &args, component.as_deref(), raw)?;
        }
        Command::Ls { file } => {
            let artifact = open_lazy(&file)?;
            println!(
                "{} {} (root {})",
                artifact.name(),
                artifact.version(),
                artifact.root_hash()
            );
            println!("components:");
            for c in artifact.components() {
                println!("  - {}", c.name);
            }
            println!("payload:");
            for (path, len) in artifact.payload_files() {
                println!("  {path}  {len} bytes");
            }
        }
        Command::Diff { a, b } => {
            let artifact_a = open_lazy(&a)?;
            let artifact_b = open_lazy(&b)?;
            diff(&artifact_a, &artifact_b);
        }
    }
    Ok(())
}

fn diff(a: &Artifact, b: &Artifact) {
    if a.root_hash() == b.root_hash() {
        println!("identical (root {})", a.root_hash());
        return;
    }
    println!(
        "{} {} -> {} {}",
        a.name(),
        a.version(),
        b.name(),
        b.version()
    );

    let caps_a: Vec<String> = a.capabilities().iter().map(|c| c.to_string()).collect();
    let caps_b: Vec<String> = b.capabilities().iter().map(|c| c.to_string()).collect();
    for c in &caps_a {
        if !caps_b.contains(c) {
            println!("- capability {c}");
        }
    }
    for c in &caps_b {
        if !caps_a.contains(c) {
            println!("+ capability {c}");
        }
    }

    let comps_a: HashMap<_, _> = a
        .components()
        .iter()
        .map(|c| (c.name.clone(), c.hash.clone()))
        .collect();
    let comps_b: HashMap<_, _> = b
        .components()
        .iter()
        .map(|c| (c.name.clone(), c.hash.clone()))
        .collect();
    for (name, hash) in &comps_a {
        match comps_b.get(name) {
            Some(bh) if bh != hash => println!("~ component {name} ({hash} -> {bh})"),
            Some(_) => {}
            None => println!("- component {name}"),
        }
    }
    for name in comps_b.keys() {
        if !comps_a.contains_key(name) {
            println!("+ component {name}");
        }
    }

    let files_a: HashMap<_, _> = a
        .payload_entries()
        .into_iter()
        .map(|(p, h, _)| (p, h))
        .collect();
    let files_b: HashMap<_, _> = b
        .payload_entries()
        .into_iter()
        .map(|(p, h, _)| (p, h))
        .collect();
    for (path, hash) in &files_a {
        match files_b.get(path) {
            Some(bh) if bh != hash => println!("~ payload {path} ({hash} -> {bh})"),
            Some(_) => {}
            None => println!("- payload {path}"),
        }
    }
    for path in files_b.keys() {
        if !files_a.contains_key(path) {
            println!("+ payload {path}");
        }
    }
}

/// Open an artifact lazily over the file (boot area + components only;
/// payload chunks are fetched and verified on demand).
fn open_lazy(path: &Path) -> Result<Artifact> {
    Artifact::open_source(Arc::new(FileSource::open(path)?))
}

/// External trust store: maps signer fingerprints to publisher names.
/// The signature proves the artifact is self-consistent with the embedded
/// key; the trust store is what ties that key to a publisher identity.
#[derive(serde::Deserialize)]
struct TrustStore {
    #[serde(default)]
    keys: HashMap<String, String>,
}

impl TrustStore {
    fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read trust store {}: {e}", path.display()))?;
        let store: TrustStore = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parse trust store {}: {e}", path.display()))?;
        Ok(store)
    }
}

/// Generate an ed25519 signing keypair. The seed goes into `build.toml`'s
/// `[sign]` section (keep it secret); the fingerprint is public and is what
/// consumers put in their trust store.
fn keygen() -> Result<()> {
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let seed = signing_key.to_bytes();
    let pubkey = signing_key.verifying_key().to_bytes();
    println!("seed:        {}", hex::encode(&seed));
    println!("fingerprint: {}", payload::chunk_hash(&pubkey));
    Ok(())
}
