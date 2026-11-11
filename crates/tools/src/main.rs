//! `caf-tool`: command-line tool to build, verify, inspect, diff, and execute
//! `.caf` artifacts (see `doc/spec/container-format.md`).
//!
//! Subcommands: `build` assembles an artifact from a `build.toml`; `verify`
//! checks the hash chain, access scopes, and signature against an optional
//! trust store; `keygen` generates ed25519 signing keys; `inspect`, `ls`, and
//! `diff` examine artifacts; `run` executes a component function through
//! `caf-runtime`; `new` scaffolds a fresh CAF project; `export` writes a ZIP
//! containing all embedded contents; `import` rebuilds a byte-identical
//! plaintext artifact from an export ZIP (see `doc/spec/round-trip.md`).

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use caf_core::{crypto, hex, layout, manifest, payload, verify};
use caf_runtime::{Artifact, FileSource};

mod assemble;
mod config;
mod export;
mod exports;
mod import;
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
    #[command(about = "Export all CAF contents to a ZIP (sealed artifacts require a key)")]
    Export {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(short, long, value_name = "ZIP")]
        output: PathBuf,
        #[arg(long, help = "Replace an existing output ZIP")]
        force: bool,
        #[arg(
            long,
            value_enum,
            default_value = "deflate",
            help = "ZIP compression: deflate (default) or stored (uncompressed)"
        )]
        compression: export::Compression,
        #[arg(long, value_name = "HEX", conflicts_with = "recipient_key")]
        key: Option<String>,
        #[arg(long, value_name = "HEX")]
        recipient_key: Option<String>,
    },
    #[command(
        about = "Rebuild a plaintext .caf from an export ZIP (byte-identical, root-hash verified)"
    )]
    Import {
        #[arg(value_name = "ZIP")]
        file: PathBuf,
        #[arg(short, long, value_name = "CAF")]
        output: PathBuf,
        #[arg(long, help = "Replace an existing output file")]
        force: bool,
    },
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

        #[arg(
            long,
            value_name = "HEX",
            help = "Content key (32 bytes hex) for a sealed artifact's plaintext tier"
        )]
        key: Option<String>,

        #[arg(
            long,
            value_name = "HEX",
            help = "P-256 recipient secret key (hex); unwraps the keybox"
        )]
        recipient_key: Option<String>,
    },

    #[command(
        about = "Generate an ed25519 signing key (seed for build.toml, fingerprint for trust stores)"
    )]
    Keygen {
        #[arg(
            long,
            help = "Generate a P-256 recipient keypair for [encrypt] instead of a signing key"
        )]
        recipient: bool,
    },

    #[command(about = "Print a human-readable summary of a .caf artifact")]
    Inspect {
        #[arg(value_name = "FILE")]
        file: PathBuf,

        #[arg(long, help = "Also print the full manifest as JSON")]
        json: bool,

        #[arg(long, value_name = "HEX", help = "Content key (32 bytes hex)")]
        key: Option<String>,

        #[arg(long, value_name = "HEX", help = "P-256 recipient secret key (hex)")]
        recipient_key: Option<String>,
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

        #[arg(long, value_name = "HEX", help = "Content key (32 bytes hex)")]
        key: Option<String>,

        #[arg(long, value_name = "HEX", help = "P-256 recipient secret key (hex)")]
        recipient_key: Option<String>,
    },

    #[command(about = "List the payload files and components of a .caf artifact")]
    Ls {
        #[arg(value_name = "FILE")]
        file: PathBuf,

        #[arg(long, value_name = "HEX", help = "Content key (32 bytes hex)")]
        key: Option<String>,

        #[arg(long, value_name = "HEX", help = "P-256 recipient secret key (hex)")]
        recipient_key: Option<String>,
    },

    #[command(about = "Diff two .caf artifacts (capabilities, components, payload)")]
    Diff {
        #[arg(value_name = "FILE_A")]
        a: PathBuf,

        #[arg(value_name = "FILE_B")]
        b: PathBuf,

        #[arg(
            long,
            value_name = "HEX",
            help = "Content key (32 bytes hex), applied to both artifacts"
        )]
        key: Option<String>,

        #[arg(
            long,
            value_name = "HEX",
            help = "P-256 recipient secret key (hex), applied to both artifacts"
        )]
        recipient_key: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Export {
            file,
            output,
            force,
            compression,
            key,
            recipient_key,
        } => {
            export::export(
                &file,
                &output,
                force,
                key.as_deref(),
                recipient_key.as_deref(),
                compression,
            )?;
            println!("wrote {}", output.display());
        }
        Command::Import {
            file,
            output,
            force,
        } => {
            import::import(&file, &output, force)?;
            println!("wrote {}", output.display());
        }
        Command::Build {
            config,
            output,
            dump_manifest,
        } => {
            let (cfg, base) = config::load(&config)?;
            let built = assemble::assemble(&cfg, &base)?;
            std::fs::write(&output, &built.bytes)?;
            if let Some(p) = dump_manifest {
                // Sealed builds dump both manifest layers (a local record; the
                // artifact itself stores the private layer only encrypted).
                let json = match (&built.envelope, &built.private) {
                    (Some(envelope), Some(private)) => serde_json::to_string_pretty(
                        &serde_json::json!({ "envelope": envelope, "private": private }),
                    )?,
                    _ => serde_json::to_string_pretty(&built.manifest)?,
                };
                std::fs::write(&p, json)?;
            }
            let sealed = if built.envelope.is_some() {
                " (sealed)"
            } else {
                ""
            };
            println!(
                "wrote {} ({} bytes){sealed}",
                output.display(),
                built.bytes.len()
            );
            // Convergent builds derive the content key from key_seed and the
            // plaintext identity, so printing it reveals nothing a seed holder
            // does not already have — and lets demo/CI hosts open the sealed
            // artifact. Random-key builds never print it.
            if let (Some(key), Some(enc)) = (built.content_key, &cfg.encrypt)
                && enc.key_seed.is_some()
            {
                println!("content key: {}", hex::encode(&key));
            }
        }
        Command::Verify {
            file,
            trusted_keys,
            require_trusted,
            key,
            recipient_key,
        } => {
            let content_key = content_key_for(&file, &key, &recipient_key)?;
            let report = match &content_key {
                Some(k) => verify::verify_with_key(&file, k)?,
                None => verify::verify(&file)?,
            };
            println!("OK {} {}", report.name, report.version);
            println!("  root hash:     {}", report.root_hash);
            println!("  manifest hash: {}", report.manifest_hash);
            println!("  encrypted:     {}", report.encrypted);
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
        Command::Keygen { recipient } => {
            keygen(recipient)?;
        }
        Command::Inspect {
            file,
            json,
            key,
            recipient_key,
        } => {
            let bytes = std::fs::read(&file)?;
            let header = layout::read_header(&bytes)?;
            if header.flags & layout::FLAG_ENCRYPTED != 0 {
                inspect_sealed(
                    &bytes,
                    &header,
                    json,
                    content_key_for(&file, &key, &recipient_key)?,
                )?;
                return Ok(());
            }
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
            key,
            recipient_key,
        } => {
            let content_key = content_key_for(&file, &key, &recipient_key)?;
            run::run(
                &file,
                &function,
                &args,
                component.as_deref(),
                raw,
                content_key,
            )?;
        }
        Command::Ls {
            file,
            key,
            recipient_key,
        } => {
            let content_key = content_key_for(&file, &key, &recipient_key)?;
            let artifact = open_lazy(&file, content_key.as_ref())?;
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
        Command::Diff {
            a,
            b,
            key,
            recipient_key,
        } => {
            let key_a = content_key_for(&a, &key, &recipient_key)?;
            let key_b = content_key_for(&b, &key, &recipient_key)?;
            let artifact_a = open_lazy(&a, key_a.as_ref())?;
            let artifact_b = open_lazy(&b, key_b.as_ref())?;
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
/// payload chunks are fetched and verified on demand). Sealed artifacts need
/// the content key.
fn open_lazy(path: &Path, content_key: Option<&[u8; 32]>) -> Result<Artifact> {
    let source = Arc::new(FileSource::open(path)?);
    match content_key {
        Some(key) => Artifact::open_source_with_key(source, key),
        None => Artifact::open_source(source),
    }
}

/// Resolve `--key` / `--recipient-key` into a content key. Returns `None` when
/// neither is given (plaintext artifacts and the public tier of sealed ones).
fn content_key_for(
    path: &Path,
    key: &Option<String>,
    recipient_key: &Option<String>,
) -> Result<Option<[u8; 32]>> {
    match (key, recipient_key) {
        (Some(hex_key), None) => {
            let bytes = hex::decode(hex_key)?;
            let key: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("--key must be 32 bytes (64 hex chars)"))?;
            Ok(Some(key))
        }
        (None, Some(hex_key)) => {
            let secret = crypto::parse_recipient_secret(hex_key)?;
            let bytes = std::fs::read(path)?;
            crypto::unwrap_artifact(&bytes, &secret)?
                .ok_or_else(|| anyhow::anyhow!("no keybox stanza matches this recipient key"))
                .map(Some)
        }
        (None, None) => Ok(None),
        (Some(_), Some(_)) => anyhow::bail!("--key and --recipient-key are mutually exclusive"),
    }
}

/// `inspect` view of a sealed artifact: the public envelope always, the
/// private manifest when a content key is supplied.
fn inspect_sealed(
    bytes: &[u8],
    header: &layout::Header,
    json: bool,
    content_key: Option<[u8; 32]>,
) -> Result<()> {
    let envelope_bytes = layout::slice(bytes, header.manifest_offset, header.manifest_len)?;
    let envelope: manifest::Envelope = ciborium::de::from_reader(envelope_bytes)?;
    println!("sealed:        aes-256-gcm (names, provenance and the payload tree are encrypted)");
    println!("format:        {}", envelope.format_version);
    println!("root hash:     {}", hex::encode(&header.root_hash));
    println!("capabilities:");
    for c in &envelope.capabilities {
        println!("  - {c}");
    }
    println!("components:    {}", envelope.components.len());
    println!(
        "payload blob:  {} bytes (padded to {})",
        envelope.payload.length, envelope.payload.padded_length
    );
    match content_key {
        Some(key) => {
            let private = verify::open_private_manifest(bytes, &key)?;
            println!("name:          {}", private.name);
            println!("version:       {}", private.version);
            println!("components:");
            for c in &private.components {
                println!(
                    "  - {} (world: {}, exports: {})",
                    c.name,
                    c.world,
                    c.exports.len()
                );
                for a in &c.access {
                    println!("      access {} ({})", a.path, a.hash);
                }
            }
            let mut files = Vec::new();
            payload::collect_files(&private.payloads[0].root, "", &mut files);
            println!("payload files: {}", files.len());
            for (path, hash, len) in &files {
                println!("  - {path}  {} bytes  {}", len, hash);
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "envelope": envelope,
                        "private": private,
                    }))?
                );
            }
        }
        None => {
            println!("(supply --key or --recipient-key for names, components and payload files)");
            if json {
                println!("{}", serde_json::to_string_pretty(&envelope)?);
            }
        }
    }
    Ok(())
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
/// consumers put in their trust store. With `--recipient`, generate a P-256
/// recipient keypair instead: the public key goes into `[encrypt] recipients`,
/// the secret key unwraps sealed artifacts (`--recipient-key`).
fn keygen(recipient: bool) -> Result<()> {
    use rand_core::OsRng;

    if recipient {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let secret = p256::SecretKey::random(&mut OsRng);
        let public = secret.public_key();
        println!("recipient secret: {}", hex::encode(&secret.to_bytes()));
        println!(
            "recipient public: {}",
            hex::encode(public.to_encoded_point(false).as_bytes())
        );
        return Ok(());
    }

    use ed25519_dalek::SigningKey;

    let signing_key = SigningKey::generate(&mut OsRng);
    let seed = signing_key.to_bytes();
    let pubkey = signing_key.verifying_key().to_bytes();
    println!("seed:        {}", hex::encode(&seed));
    println!("fingerprint: {}", payload::chunk_hash(&pubkey));
    Ok(())
}
