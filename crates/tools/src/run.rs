//! `caf-tool run`: parse CLI arguments into wasm values, call a component
//! export through `caf-runtime`, and print the results (decoding packed
//! `(ptr | len << 32)` string results unless `--raw`).

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use caf_runtime::{Artifact, FileSource, Session, Val, ValType};

/// Execute a component function against a `.caf` artifact.
pub fn run(
    file: &Path,
    function: &str,
    args: &[String],
    component: Option<&str>,
    raw: bool,
    content_key: Option<[u8; 32]>,
) -> Result<()> {
    // Lazy open: only the boot area and component bytes are read up front;
    // payload chunks are fetched and Merkle-verified on demand.
    let source = Arc::new(FileSource::open(file)?);
    let artifact = Arc::new(match &content_key {
        Some(key) => Artifact::open_source_with_key(source, key)?,
        None => Artifact::open_source(source)?,
    });

    let comp_name = component
        .map(str::to_string)
        .or_else(|| artifact.components().first().map(|c| c.name.clone()))
        .context("artifact has no components")?;

    let mut session = caf_runtime::instantiate(&artifact, &comp_name)?;
    let vals = {
        let sig = session.signature(function)?;
        let params: Vec<ValType> = sig.params().collect();
        parse_args(args, &params)?
    };
    let results = session.call(function, &vals)?;
    print_results(&mut session, &results, raw);
    Ok(())
}

fn parse_args(args: &[String], types: &[ValType]) -> Result<Vec<Val>> {
    if args.len() != types.len() {
        bail!("function expects {} args, got {}", types.len(), args.len());
    }
    args.iter()
        .zip(types)
        .map(|(a, t)| match t {
            ValType::I32 => a
                .parse::<i32>()
                .map(Val::I32)
                .map_err(|e| anyhow::anyhow!("arg '{a}' is not an i32: {e}")),
            ValType::I64 => a
                .parse::<i64>()
                .map(Val::I64)
                .map_err(|e| anyhow::anyhow!("arg '{a}' is not an i64: {e}")),
            ValType::F32 => a
                .parse::<f32>()
                .map(|f| Val::F32(f.to_bits()))
                .map_err(|e| anyhow::anyhow!("arg '{a}' is not an f32: {e}")),
            ValType::F64 => a
                .parse::<f64>()
                .map(|f| Val::F64(f.to_bits()))
                .map_err(|e| anyhow::anyhow!("arg '{a}' is not an f64: {e}")),
            other => bail!("unsupported parameter type {other:?}"),
        })
        .collect()
}

fn print_results(session: &mut Session, results: &[Val], raw: bool) {
    for (i, r) in results.iter().enumerate() {
        match r {
            Val::I32(v) => println!("[{i}] i32: {v}"),
            Val::I64(v) => {
                println!("[{i}] i64: {v}");
                if !raw {
                    let ptr = (v & 0xffff_ffff) as u32;
                    let len = (v >> 32) as u32;
                    print_packed_string(session, ptr, len);
                }
            }
            Val::F32(bits) => println!("[{i}] f32: {}", f32::from_bits(*bits)),
            Val::F64(bits) => println!("[{i}] f64: {}", f64::from_bits(*bits)),
            other => println!("[{i}] {other:?}"),
        }
    }
}

fn print_packed_string(session: &mut Session, ptr: u32, len: u32) {
    if len == 0 || len > 64 * 1024 * 1024 {
        return;
    }
    if let Ok(bytes) = session.read_memory(ptr, len)
        && let Ok(s) = String::from_utf8(bytes)
    {
        println!("    (string) {s}");
    }
}
