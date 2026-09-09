use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod assemble;
mod config;
mod hex;
mod layout;
mod manifest;
mod payload;

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
    }
    Ok(())
}
