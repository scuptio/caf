use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod assemble;
mod config;
mod exports;
mod hex;
mod layout;
mod manifest;
mod payload;
mod verify;
mod wit;
mod wizard;

#[cfg(test)]
mod tests;

#[derive(Parser)]
#[command(name = "caf-tool", version, about = "Build Computable Artifact Format (.caf) files")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Compile a payload directory, interfaces and components into a .caf artifact")]
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
    },

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
        Command::Verify { file } => {
            let report = verify::verify(&file)?;
            println!(
                "OK {} {}",
                report.name, report.version
            );
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
                println!("  signature:     {}", if valid { "valid" } else { "INVALID" });
            } else {
                println!("  signature:     none (unsigned)");
            }
        }
        Command::Inspect { file, json } => {
            let bytes = std::fs::read(&file)?;
            let header = layout::read_header(&bytes)?;
            let manifest_bytes = layout::slice(&bytes, header.manifest_offset, header.manifest_len)?;
            let manifest: manifest::Manifest =
                ciborium::de::from_reader(manifest_bytes)?;
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
                println!("  - {} (world: {}, exports: {})", c.name, c.world, c.exports.len());
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
    }
    Ok(())
}
