use anyhow::Result;
use std::path::{Path, PathBuf};

use crate::{assemble, config, hex, layout, manifest, payload, verify};

fn temp_root(name: &str) -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("caf-tool-test-{}-{}", std::process::id(), name));
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(dir.join("payload/data"))?;
    std::fs::create_dir_all(dir.join("payload/index"))?;
    Ok(dir)
}

fn write_config(dir: &Path, access: &[&str]) -> Result<()> {
    write_config_impl(dir, access, None)
}

fn write_signed_config(dir: &Path, access: &[&str]) -> Result<()> {
    let seed = "11".repeat(32);
    write_config_impl(dir, access, Some(&seed))
}

fn write_config_impl(dir: &Path, access: &[&str], seed: Option<&str>) -> Result<()> {
    let access = access
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let sign = match seed {
        Some(s) => format!("\n[sign]\nseed = \"{s}\"\n"),
        None => String::new(),
    };
    let toml = format!(
        "name = \"city\"\nversion = \"0.1.0\"\n\ninterfaces = [\"spatial.wit\"]\n\n[payload]\nroot = \"payload\"\nmedia_type = \"application/x-spatial\"\n\n[[components]]\nname = \"spatial\"\nworld = \"spatial-file\"\npath = \"spatial.wasm\"\ncapabilities = [\"cf:metadata@1\", \"cf:spatial-query@1\"]\naccess = [{access}]\n{sign}"
    );
    std::fs::write(dir.join("build.toml"), toml)?;
    std::fs::write(
        dir.join("spatial.wit"),
        "package cf:gis@0.1.0;\nworld spatial-file {\n  export metadata: interface { name: func() -> string; }\n}\n",
    )?;
    std::fs::write(dir.join("spatial.wasm"), b"\0asm\x01\0\0\0")?;
    std::fs::write(dir.join("payload/data/city.parquet"), b"parquet-bytes")?;
    std::fs::write(dir.join("payload/index/rtree.bin"), b"index-bytes")?;
    Ok(())
}

fn build_bytes(dir: &Path) -> Result<Vec<u8>> {
    let (cfg, base) = config::load(&dir.join("build.toml"))?;
    let built = assemble::assemble(&cfg, &base)?;
    Ok(built.bytes)
}

fn decode_manifest(bytes: &[u8]) -> Result<manifest::Manifest> {
    let header = layout::read_header(bytes)?;
    let manifest_bytes = layout::slice(bytes, header.manifest_offset, header.manifest_len)?;
    ciborium::de::from_reader(manifest_bytes).map_err(anyhow::Error::from)
}

#[test]
fn builds_a_caf_file() -> Result<()> {
    let dir = temp_root("build")?;
    write_config(&dir, &["/data", "/index"])?;

    let bytes = build_bytes(&dir)?;
    assert_eq!(&bytes[0..4], b"CAF\0");

    let header = layout::read_header(&bytes)?;
    assert_eq!(header.format_version, 1);
    assert_eq!(header.manifest_offset, 96);
    assert!(header.manifest_len > 0);
    assert!(header.interface_len > 0);
    assert!(header.directory_len > 0);
    assert!(header.interface_offset >= header.manifest_offset + header.manifest_len);
    assert!(header.directory_offset >= header.interface_offset + header.interface_len);
    assert!(header.root_hash.iter().any(|b| *b != 0));

    let manifest = decode_manifest(&bytes)?;
    assert_eq!(manifest.components.len(), 1);
    assert_eq!(manifest.components[0].access.len(), 2);
    assert_eq!(manifest.capabilities.len(), 2);

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn rejects_unknown_access_scope() -> Result<()> {
    let dir = temp_root("bad-access")?;
    write_config(&dir, &["/data", "/nope"])?;

    let (cfg, base) = config::load(&dir.join("build.toml"))?;
    assert!(assemble::assemble(&cfg, &base).is_err());

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn manifest_hash_matches_actual_bytes() -> Result<()> {
    // Regression test for the content-addressing self-reference bug: the hash
    // stored for the manifest must equal SHA256 of the manifest bytes on disk.
    let dir = temp_root("hash")?;
    write_config(&dir, &["/data"])?;
    let bytes = build_bytes(&dir)?;

    let header = layout::read_header(&bytes)?;
    let manifest_bytes = layout::slice(&bytes, header.manifest_offset, header.manifest_len)?;
    let directory = layout::decode_directory(layout::slice(
        &bytes,
        header.directory_offset,
        header.directory_len,
    )?)?;

    let manifest_entry = directory
        .iter()
        .find(|e| e.tag == layout::TAG_MANIFEST)
        .ok_or_else(|| anyhow::anyhow!("missing manifest directory entry"))?;
    assert_eq!(hex::encode(&manifest_entry.hash), sha256_hex(manifest_bytes));

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn verify_roundtrips() -> Result<()> {
    let dir = temp_root("verify")?;
    write_config(&dir, &["/data", "/index"])?;
    let bytes = build_bytes(&dir)?;

    let report = verify::verify_bytes(&bytes)?;
    assert_eq!(report.name, "city");
    assert_eq!(report.components, 1);
    assert_eq!(report.payload_files, 2);
    assert!(!report.signed);

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn deterministic_build() -> Result<()> {
    let dir = temp_root("deterministic")?;
    write_config(&dir, &["/data"])?;

    let a = build_bytes(&dir)?;
    let b = build_bytes(&dir)?;
    assert_eq!(a, b);

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn signed_roundtrip_verifies() -> Result<()> {
    let dir = temp_root("signed")?;
    write_signed_config(&dir, &["/data"])?;
    let bytes = build_bytes(&dir)?;

    let header = layout::read_header(&bytes)?;
    assert_ne!(header.flags & layout::FLAG_SIGNED, 0);

    let report = verify::verify_bytes(&bytes)?;
    assert!(report.signed);
    assert_eq!(report.signature_valid, Some(true));

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn tampered_payload_is_detected() -> Result<()> {
    let dir = temp_root("tamper")?;
    write_config(&dir, &["/data"])?;
    let mut bytes = build_bytes(&dir)?;

    let header = layout::read_header(&bytes)?;
    let directory = layout::decode_directory(layout::slice(
        &bytes,
        header.directory_offset,
        header.directory_len,
    )?)?;
    let payload_entry = directory
        .iter()
        .find(|e| e.tag == layout::TAG_PAYLOAD)
        .ok_or_else(|| anyhow::anyhow!("missing payload directory entry"))?;
    let idx = payload_entry.offset as usize;
    bytes[idx] ^= 0xff;

    assert!(verify::verify_bytes(&bytes).is_err());

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn capability_id_parsing() -> Result<()> {
    let c = manifest::CapabilityId::parse("cf:spatial-query@1").map_err(anyhow::Error::msg)?;
    assert_eq!(c.namespace, "cf");
    assert_eq!(c.name, "spatial-query");
    assert_eq!(c.version, 1);
    assert_eq!(c.to_string(), "cf:spatial-query@1");

    let c = manifest::CapabilityId::parse("org:example:infer@2").map_err(anyhow::Error::msg)?;
    assert_eq!(c.namespace, "org:example");
    assert_eq!(c.name, "infer");
    assert_eq!(c.version, 2);

    assert!(manifest::CapabilityId::parse("cf:query").is_err());
    assert!(manifest::CapabilityId::parse("cf:query@x").is_err());
    assert!(manifest::CapabilityId::parse("query@1").is_err());
    Ok(())
}

#[test]
fn empty_file_hash_is_sha256_empty() -> Result<()> {
    let (hash, chunks) = payload::file_hash(b"")?;
    assert!(chunks.is_empty());
    assert_eq!(hash, sha256_hex(b""));
    Ok(())
}

#[test]
fn large_file_is_chunked() -> Result<()> {
    let data = vec![0xabu8; manifest::CHUNK_SIZE * 2 + 5];
    let (hash, chunks) = payload::file_hash(&data)?;
    assert_eq!(chunks.len(), 3);
    // Root differs from a flat whole-file hash when chunked.
    assert_ne!(hash, sha256_hex(&data));
    // And it matches the verifier.
    assert_eq!(payload::verify_file(&data)?, hash);
    Ok(())
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(&h.finalize())
}
