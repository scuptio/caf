use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::{assemble, config, export::Compression, wizard};
use caf_core::{crypto, hex, layout, manifest, payload, verify};

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
    let extra = match seed {
        Some(s) => format!("\n[sign]\nseed = \"{s}\"\n"),
        None => String::new(),
    };
    write_config_full(dir, access, &wasm_with_bridge(), &extra)?;
    bind_test_capabilities(dir, &["cf:metadata@1", "cf:spatial-query@1"])
}

/// Full control over the component bytes and any extra TOML sections
/// (`[policy]`, `[execution]`, `[resources]`, `[sign]`, ...).
fn write_config_full(dir: &Path, access: &[&str], wasm: &[u8], extra: &str) -> Result<()> {
    let access = access
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let toml = format!(
        "name = \"city\"\nversion = \"0.1.0\"\n\ninterfaces = [\"spatial.wit\"]\n\n[payload]\nroot = \"payload\"\nmedia_type = \"application/x-spatial\"\n\n[[components]]\nname = \"spatial\"\nworld = \"spatial-file\"\npath = \"spatial.wasm\"\ncapabilities = []\naccess = [{access}]\n{extra}"
    );
    std::fs::write(dir.join("build.toml"), toml)?;
    std::fs::write(
        dir.join("spatial.wit"),
        "package cf:gis@0.1.0;\nworld spatial-file {\n  export metadata: interface { name: func() -> string; }\n  export spatial-query: interface { query: func() -> string; }\n}\n",
    )?;
    std::fs::write(dir.join("spatial.wasm"), wasm)?;
    std::fs::write(dir.join("payload/data/city.parquet"), b"parquet-bytes")?;
    std::fs::write(dir.join("payload/index/rtree.bin"), b"index-bytes")?;
    Ok(())
}

/// Explicitly bind capabilities only in fixtures that implement their WIT.
fn bind_test_capabilities(dir: &Path, caps: &[&str]) -> Result<()> {
    let path = dir.join("build.toml");
    let config = std::fs::read_to_string(&path)?;
    let caps = caps
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        path,
        config.replace("capabilities = []", &format!("capabilities = [{caps}]")),
    )?;
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
    // Capabilities are bound to the world's exports.
    assert_eq!(manifest.components[0].exports.len(), 2);
    assert_eq!(
        manifest.components[0].exports[0].capability,
        "cf:metadata@1"
    );
    assert_eq!(
        manifest.components[0].exports[1].capability,
        "cf:spatial-query@1"
    );

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
    assert_eq!(
        hex::encode(&manifest_entry.hash),
        sha256_hex(manifest_bytes)
    );

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
fn unknown_header_flags_are_rejected() -> Result<()> {
    let dir = temp_root("unknown-flags")?;
    write_config(&dir, &["/data"])?;
    let mut bytes = build_bytes(&dir)?;

    // Set an undefined flag bit (header flags are the u16 at offset 10).
    bytes[10] |= 0x04;

    assert!(layout::read_header(&bytes).is_err());

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn manifest_with_unknown_field_is_rejected() -> Result<()> {
    let dir = temp_root("unknown-field")?;
    write_config(&dir, &["/data"])?;
    let bytes = build_bytes(&dir)?;

    // Add an `encrypted` key to the manifest map: a future reader's extension
    // must be a hard error for this reader, never silently ignored.
    let header = layout::read_header(&bytes)?;
    let manifest_bytes = layout::slice(&bytes, header.manifest_offset, header.manifest_len)?;
    let mut value: ciborium::value::Value = ciborium::de::from_reader(manifest_bytes)?;
    let ciborium::value::Value::Map(ref mut map) = value else {
        anyhow::bail!("manifest is not a CBOR map");
    };
    map.push((
        ciborium::value::Value::Text("encrypted".to_string()),
        ciborium::value::Value::Bool(true),
    ));
    let mut tampered = Vec::new();
    ciborium::ser::into_writer(&value, &mut tampered)?;

    let decoded: Result<manifest::Manifest, _> = ciborium::de::from_reader(tampered.as_slice());
    assert!(decoded.is_err());

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ---------------------------------------------------------------------------
// Sealed artifacts ([encrypt]): keybox, envelope/private manifest, AEAD chunks.
// ---------------------------------------------------------------------------

use p256::elliptic_curve::sec1::ToEncodedPoint;

/// A fresh P-256 recipient keypair `(secret, public)` for sealed-build tests.
fn recipient_keypair() -> (p256::SecretKey, String) {
    let secret = p256::SecretKey::random(&mut rand_core::OsRng);
    let public = hex::encode(secret.public_key().to_encoded_point(false).as_bytes());
    (secret, public)
}

fn write_sealed_config(
    dir: &Path,
    access: &[&str],
    recipient_pub: &str,
    key_seed: Option<&str>,
    sign_seed: Option<&str>,
) -> Result<()> {
    let seed_line = key_seed
        .map(|s| format!("key_seed = \"{s}\"\n"))
        .unwrap_or_default();
    let sign_section = match sign_seed {
        Some(s) => format!("\n[sign]\nseed = \"{s}\"\n"),
        None => String::new(),
    };
    let extra =
        format!("\n[encrypt]\nrecipients = [\"{recipient_pub}\"]\n{seed_line}{sign_section}");
    write_config_full(dir, access, b"\0asm\x01\0\0\0", &extra)
}

#[test]
fn sealed_roundtrip_reads_payload() -> Result<()> {
    let (secret, public) = recipient_keypair();
    let dir = temp_root("sealed")?;
    let seed = "22".repeat(32);
    write_sealed_config(&dir, &["/data"], &public, Some(&seed), None)?;
    let bytes = build_bytes(&dir)?;

    let header = layout::read_header(&bytes)?;
    assert_ne!(header.flags & layout::FLAG_ENCRYPTED, 0);

    // Public tier: verifies without a key, redacts everything sensitive.
    let report = verify::verify_bytes(&bytes)?;
    assert!(report.encrypted);
    assert_eq!(report.name, "<sealed>");
    assert_eq!(report.payload_files, 0);
    assert_eq!(report.components, 1);

    // The recipient unwraps the keybox; a stranger does not.
    let content_key = caf_core::crypto::unwrap_artifact(&bytes, &secret)?.expect("stanza matches");
    let (stranger, _) = recipient_keypair();
    assert!(caf_core::crypto::unwrap_artifact(&bytes, &stranger)?.is_none());

    // Full tier with the content key.
    let report = verify::verify_bytes_keyed(&bytes, Some(&content_key))?;
    assert_eq!(report.name, "city");
    assert_eq!(report.payload_files, 2);

    // The runtime reads payload bytes through decryption; opening without the
    // key must fail.
    assert!(caf_runtime::Artifact::open(bytes.clone()).is_err());
    let artifact = caf_runtime::Artifact::open_with_key(bytes, &content_key)?;
    assert_eq!(
        artifact.read_payload("/data/city.parquet")?,
        b"parquet-bytes"
    );
    assert_eq!(artifact.read_payload("/index/rtree.bin")?, b"index-bytes");

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn sealed_convergent_builds_are_deterministic() -> Result<()> {
    let (_secret, public) = recipient_keypair();
    let dir = temp_root("sealed-convergent")?;
    let seed = "33".repeat(32);
    write_sealed_config(&dir, &["/data"], &public, Some(&seed), None)?;

    let a = build_bytes(&dir)?;
    let b = build_bytes(&dir)?;
    assert_eq!(a, b, "same key_seed must reproduce identical ciphertext");

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn sealed_random_builds_differ() -> Result<()> {
    let (_secret, public) = recipient_keypair();
    let dir = temp_root("sealed-random")?;
    write_sealed_config(&dir, &["/data"], &public, None, None)?;

    let a = build_bytes(&dir)?;
    let b = build_bytes(&dir)?;
    assert_ne!(a, b, "random content keys must randomize the ciphertext");

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn sealed_signed_roundtrip_verifies() -> Result<()> {
    let (secret, public) = recipient_keypair();
    let dir = temp_root("sealed-signed")?;
    let seed = "44".repeat(32);
    let sign_seed = "55".repeat(32);
    write_sealed_config(&dir, &["/data"], &public, Some(&seed), Some(&sign_seed))?;
    let bytes = build_bytes(&dir)?;

    let header = layout::read_header(&bytes)?;
    assert_ne!(header.flags & layout::FLAG_ENCRYPTED, 0);
    assert_ne!(header.flags & layout::FLAG_SIGNED, 0);

    // Encrypt-then-Sign: the signature covers the ciphertext root hash and
    // verifies on the public tier.
    let report = verify::verify_bytes(&bytes)?;
    assert_eq!(report.signature_valid, Some(true));
    let content_key = caf_core::crypto::unwrap_artifact(&bytes, &secret)?.expect("stanza matches");
    let report = verify::verify_bytes_keyed(&bytes, Some(&content_key))?;
    assert_eq!(report.signature_valid, Some(true));

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn sealed_tampered_ciphertext_is_detected() -> Result<()> {
    let (secret, public) = recipient_keypair();
    let dir = temp_root("sealed-tamper")?;
    let seed = "66".repeat(32);
    write_sealed_config(&dir, &["/data"], &public, Some(&seed), None)?;
    let mut bytes = build_bytes(&dir)?;

    // Flip a byte inside the payload blob's first chunk.
    let header = layout::read_header(&bytes)?;
    let directory = layout::decode_directory(layout::slice(
        &bytes,
        header.directory_offset,
        header.directory_len,
    )?)?;
    let blob = directory
        .iter()
        .find(|e| e.tag == layout::TAG_PAYLOAD)
        .ok_or_else(|| anyhow::anyhow!("missing payload blob entry"))?;
    bytes[blob.offset as usize] ^= 0xff;

    assert!(verify::verify_bytes(&bytes).is_err());
    let content_key = caf_core::crypto::unwrap_artifact(&bytes, &secret)?.expect("stanza matches");
    // Lazy open succeeds (payload bytes are verified on first read)...
    let artifact = caf_runtime::Artifact::open_source_with_key(
        std::sync::Arc::new(caf_runtime::SliceSource::new(bytes)),
        &content_key,
    )?;
    // ...and the tampered chunk is caught on read.
    assert!(artifact.read_payload("/data/city.parquet").is_err());

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

#[test]
fn wizard_scaffolds_and_builds() -> Result<()> {
    let dir = std::env::temp_dir().join(format!("caf-tool-wiz-{}", std::process::id()));
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;

    wizard::scaffold("demo", wizard::Language::Rust, &dir)?;
    let proj = dir.join("demo");
    let mut wasm = wasm_with_bridge();
    // Rename the fixture's complex result function to the scaffold's ping.
    let name = wasm
        .windows(4)
        .position(|w| w == b"name")
        .context("fixture name")?;
    wasm[name..name + 4].copy_from_slice(b"ping");
    std::fs::write(proj.join("demo.wasm"), wasm)?;

    let (cfg, base) = config::load(&proj.join("build.toml"))?;
    let built = assemble::assemble(&cfg, &base)?;

    let report = verify::verify_bytes(&built.bytes)?;
    assert_eq!(report.name, "demo");
    assert_eq!(built.manifest.components[0].exports.len(), 1);
    assert_eq!(
        built.manifest.components[0].exports[0].capability,
        "cf:demo@1"
    );

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn runtime_opens_and_reads_payload() -> Result<()> {
    let dir = temp_root("runtime")?;
    write_config(&dir, &["/data"])?;
    let bytes = build_bytes(&dir)?;

    let artifact = caf_runtime::Artifact::open(bytes)?;
    assert_eq!(artifact.name(), "city");
    assert_eq!(artifact.components().len(), 1);
    let files = artifact.payload_files();
    assert_eq!(files.len(), 2);
    assert_eq!(
        artifact.read_payload("/data/city.parquet")?,
        b"parquet-bytes"
    );

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Open a built artifact expecting failure; returns the error.
fn open_expect_err(bytes: Vec<u8>) -> anyhow::Error {
    match caf_runtime::Artifact::open(bytes) {
        Ok(_) => anyhow::anyhow!("open unexpectedly succeeded"),
        Err(e) => e,
    }
}

#[test]
fn open_rejects_component_with_undeclared_import() -> Result<()> {
    let dir = temp_root("bad-import")?;
    // Minimal module: type () -> (), plus one import of `evil.net`.
    let wasm = b"\0asm\x01\0\0\0\x01\x04\x01\x60\x00\x00\x02\x0c\x01\x04evil\x03net\x00\x00";
    write_config_full(&dir, &["/data"], wasm, "")?;
    let bytes = build_bytes(&dir)?;

    // The hash chain verifies; open-time admission is what rejects it.
    verify::verify_bytes(&bytes)?;
    let err = open_expect_err(bytes);
    assert!(
        format!("{err:#}").contains("undeclared host function"),
        "{err:#}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn open_rejects_fs_import_when_self_read_denied() -> Result<()> {
    let dir = temp_root("no-self-read")?;
    // Minimal module importing `caf.open`.
    let wasm = b"\0asm\x01\0\0\0\x01\x04\x01\x60\x00\x00\x02\x0c\x01\x03caf\x04open\x00\x00";
    write_config_full(&dir, &["/data"], wasm, "\n[policy]\nself_read = false\n")?;
    let bytes = build_bytes(&dir)?;

    let err = open_expect_err(bytes);
    assert!(
        format!("{err:#}").contains("self_read is not granted"),
        "{err:#}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn open_rejects_nondeterministic_caf_d1() -> Result<()> {
    let dir = temp_root("bad-d1")?;
    write_config_full(
        &dir,
        &["/data"],
        b"\0asm\x01\0\0\0",
        "\n[execution]\ndeterministic = false\n",
    )?;
    let bytes = build_bytes(&dir)?;

    let err = open_expect_err(bytes);
    assert!(
        format!("{err:#}").contains("requires deterministic"),
        "{err:#}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn open_rejects_unknown_execution_profile() -> Result<()> {
    let dir = temp_root("bad-profile")?;
    write_config_full(
        &dir,
        &["/data"],
        b"\0asm\x01\0\0\0",
        "\n[execution]\nprofile = \"caf-x9\"\n",
    )?;
    let bytes = build_bytes(&dir)?;

    let err = open_expect_err(bytes);
    assert!(format!("{err:#}").contains("not supported"), "{err:#}");

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn return_channel_is_charged_against_output_budget() -> Result<()> {
    let dir = temp_root("output-meter")?;
    // Module exporting memory and `pair: () -> (i64, i64)`:
    //   type: () -> (i64, i64); func 0; memory min 1 page;
    //   exports "memory" / "pair"; body: i64.const 0, i64.const 0.
    let wasm = b"\0asm\x01\0\0\0\
        \x01\x06\x01\x60\x00\x02\x7e\x7e\
        \x03\x02\x01\x00\
        \x05\x03\x01\x00\x01\
        \x07\x11\x02\x06memory\x02\x00\x04pair\x00\x00\
        \x0a\x08\x01\x06\x00\x42\x00\x42\x00\x0b";
    write_config_full(&dir, &["/data"], wasm, "\n[resources]\noutput_max = 8\n")?;
    let bytes = build_bytes(&dir)?;

    let artifact = std::sync::Arc::new(caf_runtime::Artifact::open(bytes)?);
    let mut session = caf_runtime::instantiate(&artifact, "spatial")?;

    // A two-i64 result is 16 bytes > output_max = 8: the call fails.
    let err = match session.call("pair", &[]) {
        Ok(_) => return Err(anyhow::anyhow!("call unexpectedly succeeded")),
        Err(e) => e,
    };
    assert!(format!("{err:#}").contains("output budget"), "{err:#}");

    // Reading guest memory (the packed-result channel) is output too.
    assert!(session.read_memory(0, 8).is_ok());
    assert!(session.read_memory(0, 1).is_err());
    assert_eq!(session.usage().output, 8);

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(&h.finalize())
}

// ---------------------------------------------------------------------------
// caf-abi memory-bridge enforcement at build time.
// ---------------------------------------------------------------------------

/// Module exporting `name: () -> i64` (matches the complex WIT function
/// `name: func() -> string`), with memory, `alloc`, and `dealloc` exports.
fn wasm_with_bridge() -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    // types: ()->i64, (i32)->i32, (i32,i32)->()
    wasm.extend(wasm_section(
        1,
        &[
            0x03, 0x60, 0x00, 0x01, 0x7e, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x60, 0x02, 0x7f, 0x7f,
            0x00,
        ],
    ));
    // funcs: three, types 0/1/2
    wasm.extend(wasm_section(3, &[0x03, 0x00, 0x01, 0x02]));
    // memory: min 1 page
    wasm.extend(wasm_section(5, &[0x01, 0x00, 0x01]));
    // exports: name=f0, memory, alloc=f1, dealloc=f2
    let mut exports = vec![0x05];
    exports.extend(b"\x04name\x00\x00");
    exports.extend(b"\x05query\x00\x00");
    exports.extend(b"\x06memory\x02\x00");
    exports.extend(b"\x05alloc\x00\x01");
    exports.extend(b"\x07dealloc\x00\x02");
    wasm.extend(wasm_section(7, &exports));
    // code: name { i64.const 0 }, alloc { local.get 0 }, dealloc { }
    let mut code = vec![0x03];
    code.extend([0x04, 0x00, 0x42, 0x00, 0x0b]); // f0: no locals, i64.const 0, end
    code.extend([0x04, 0x00, 0x20, 0x00, 0x0b]); // f1: no locals, local.get 0, end
    code.extend([0x02, 0x00, 0x0b]); // f2: no locals, end
    wasm.extend(wasm_section(10, &code));
    wasm
}

#[test]
fn build_rejects_complex_export_without_memory_bridge() -> Result<()> {
    let dir = temp_root("abi-missing")?;
    // Exports the complex WIT function `name` but neither alloc nor dealloc.
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.extend(wasm_section(1, &[0x01, 0x60, 0x00, 0x01, 0x7e]));
    wasm.extend(wasm_section(3, &[0x01, 0x00]));
    wasm.extend(wasm_section(5, &[0x01, 0x00, 0x01]));
    let mut exports = vec![0x02];
    exports.extend(b"\x04name\x00\x00");
    exports.extend(b"\x06memory\x02\x00");
    wasm.extend(wasm_section(7, &exports));
    wasm.extend(wasm_section(10, &[0x01, 0x04, 0x00, 0x42, 0x00, 0x0b]));

    write_config_full(&dir, &["/data"], &wasm, "")?;
    bind_test_capabilities(&dir, &["cf:metadata@1"])?;
    let err = match build_bytes(&dir) {
        Ok(_) => return Err(anyhow::anyhow!("build unexpectedly succeeded")),
        Err(e) => e,
    };
    assert!(format!("{err:#}").contains("memory bridge"), "{err:#}");

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn build_accepts_complex_export_with_memory_bridge() -> Result<()> {
    let dir = temp_root("abi-ok")?;
    write_config_full(&dir, &["/data"], &wasm_with_bridge(), "")?;
    bind_test_capabilities(&dir, &["cf:metadata@1", "cf:spatial-query@1"])?;
    let bytes = build_bytes(&dir)?;
    verify::verify_bytes(&bytes)?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn scalar_only_exports_need_no_bridge() -> Result<()> {
    let dir = temp_root("abi-scalar")?;
    // A bound scalar WIT function requires no memory bridge.
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.extend(wasm_section(1, &[0x01, 0x60, 0x00, 0x01, 0x7f]));
    wasm.extend(wasm_section(3, &[0x01, 0x00]));
    let mut exports = vec![0x01];
    exports.extend(b"\x06answer\x00\x00");
    wasm.extend(wasm_section(7, &exports));
    wasm.extend(wasm_section(10, &[0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b]));
    write_config_full(&dir, &["/data"], &wasm, "")?;
    std::fs::write(
        dir.join("spatial.wit"),
        "package cf:gis@0.1.0; world spatial-file { export answer: func() -> u32; }",
    )?;
    bind_test_capabilities(&dir, &["cf:answer@1"])?;
    build_bytes(&dir)?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ---------------------------------------------------------------------------
// Lazy (incremental) verification over a backing store.
// ---------------------------------------------------------------------------

/// A PayloadSource that records every read, to prove laziness.
struct CountingSource {
    inner: caf_runtime::SliceSource,
    reads: std::sync::Mutex<Vec<(u64, u64)>>,
}

impl CountingSource {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: caf_runtime::SliceSource::new(bytes),
            reads: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn bytes_read(&self) -> u64 {
        match self.reads.lock() {
            Ok(reads) => reads.iter().map(|(_, len)| *len).sum(),
            Err(_) => 0,
        }
    }
}

impl caf_runtime::PayloadSource for CountingSource {
    fn read_at(&self, offset: u64, len: u64) -> Result<Vec<u8>> {
        if let Ok(mut reads) = self.reads.lock() {
            reads.push((offset, len));
        }
        self.inner.read_at(offset, len)
    }

    fn total_len(&self) -> u64 {
        self.inner.total_len()
    }
}

/// Add a multi-chunk (> 1 MiB) payload file before building.
fn write_big_payload(dir: &Path) -> Result<()> {
    std::fs::write(dir.join("payload/data/big.bin"), vec![7u8; 3 * 1024 * 1024])?;
    Ok(())
}

fn lazy_open(
    bytes: Vec<u8>,
) -> Result<(
    std::sync::Arc<caf_runtime::Artifact>,
    std::sync::Arc<CountingSource>,
)> {
    let source = std::sync::Arc::new(CountingSource::new(bytes));
    let artifact = caf_runtime::Artifact::open_source(source.clone())?;
    Ok((std::sync::Arc::new(artifact), source))
}

#[test]
fn lazy_open_reads_only_boot_area() -> Result<()> {
    let dir = temp_root("lazy-boot")?;
    write_config(&dir, &["/data", "/index"])?;
    write_big_payload(&dir)?;
    let total = build_bytes(&dir)?.len() as u64;
    let bytes = build_bytes(&dir)?;

    let (artifact, source) = lazy_open(bytes)?;
    let boot_bytes = source.bytes_read();
    assert!(
        boot_bytes < 512 * 1024,
        "open should read only the boot area + components, got {boot_bytes} bytes of {total}"
    );

    // Payload reads work and are verified lazily: a small window of a large
    // file fetches only its covering chunk, not the whole file.
    let before = source.bytes_read();
    let (window, fetched) = artifact.read_payload_range("/data/big.bin", 1024 * 1024 + 5, 100)?;
    assert_eq!(window, vec![7u8; 100]);
    assert_eq!(fetched, 1024 * 1024);
    let after = source.bytes_read();
    assert_eq!(after - before, 1024 * 1024);

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Find the directory offset span of the payload file that is `len` bytes long.
fn payload_span(bytes: &[u8], len: u64) -> Result<(u64, u64)> {
    let header = layout::read_header(bytes)?;
    let dir_bytes = layout::slice(bytes, header.directory_offset, header.directory_len)?;
    for e in layout::decode_directory(dir_bytes)? {
        if e.tag == layout::TAG_PAYLOAD && e.length == len {
            return Ok((e.offset, e.length));
        }
    }
    Err(anyhow::anyhow!("payload entry of length {len} not found"))
}

#[test]
fn lazy_open_defers_payload_verification_to_read() -> Result<()> {
    let dir = temp_root("lazy-tamper")?;
    write_config(&dir, &["/data"])?;
    write_big_payload(&dir)?;
    let mut bytes = build_bytes(&dir)?;

    // Corrupt one byte inside the big payload file.
    let (offset, _len) = payload_span(&bytes, 3 * 1024 * 1024)?;
    let i = usize::try_from(offset)?;
    bytes[i] ^= 0xff;

    // Full offline verification still catches it...
    assert!(verify::verify_bytes(&bytes).is_err());
    // ...but lazy open succeeds (payload bytes are not read at open)...
    let source = std::sync::Arc::new(CountingSource::new(bytes));
    let artifact = caf_runtime::Artifact::open_source(source)?;
    // ...and the tamper is caught before the bytes are ever handed out.
    assert!(artifact.read_payload("/data/big.bin").is_err());
    // Untouched files still read fine.
    assert_eq!(
        artifact.read_payload("/data/city.parquet")?,
        b"parquet-bytes"
    );

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn lazy_open_rejects_tampered_component_at_open() -> Result<()> {
    let dir = temp_root("lazy-tamper-comp")?;
    write_config(&dir, &["/data"])?;
    let mut bytes = build_bytes(&dir)?;

    // Corrupt one byte inside the component section.
    let header = layout::read_header(&bytes)?;
    let dir_bytes = layout::slice(&bytes, header.directory_offset, header.directory_len)?;
    let entry = layout::decode_directory(dir_bytes)?
        .into_iter()
        .find(|e| e.tag == layout::TAG_COMPONENT)
        .ok_or_else(|| anyhow::anyhow!("no component entry"))?;
    let i = usize::try_from(entry.offset)?;
    bytes[i] ^= 0xff;

    let source = std::sync::Arc::new(CountingSource::new(bytes));
    assert!(caf_runtime::Artifact::open_source(source).is_err());

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// `(id, payload)` wasm section encoding.
fn wasm_section(id: u8, payload_bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![id, payload_bytes.len() as u8];
    out.extend_from_slice(payload_bytes);
    out
}

/// A component that opens and closes a payload file twice and reports whether
/// the second open reused the first fd — proving `close` frees the slot.
#[test]
fn close_frees_and_reuses_fds() -> Result<()> {
    let dir = temp_root("close-fd")?;
    let path = b"/data/city.parquet";

    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    // types: (i32,i32)->i32 for open/churn; (i32)->i32 for close
    wasm.extend(wasm_section(
        1,
        &[
            0x02, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x60, 0x01, 0x7f, 0x01, 0x7f,
        ],
    ));
    // imports: caf.open (type 0), caf.close (type 1)
    let mut imports = vec![0x02];
    imports.extend(b"\x03caf\x04open\x00\x00");
    imports.extend(b"\x03caf\x05close\x00\x01");
    wasm.extend(wasm_section(2, &imports));
    // func churn: type 0
    wasm.extend(wasm_section(3, &[0x01, 0x00]));
    // memory: min 1 page
    wasm.extend(wasm_section(5, &[0x01, 0x00, 0x01]));
    // exports: memory, churn (func index 2)
    let mut exports = vec![0x02];
    exports.extend(b"\x06memory\x02\x00");
    exports.extend(b"\x05churn\x00\x02");
    wasm.extend(wasm_section(7, &exports));
    // code: churn(p, l) = { fd = open(p, l); close(fd); open(p, l) == fd }
    let mut body = vec![0x01, 0x01, 0x7f]; // one i32 local
    body.extend([
        0x20, 0x00, 0x20, 0x01, 0x10, 0x00, 0x21, 0x02, // fd = open(p, l)
        0x20, 0x02, 0x10, 0x01, 0x1a, // close(fd)
        0x20, 0x00, 0x20, 0x01, 0x10, 0x00, // open(p, l)
        0x20, 0x02, 0x46, 0x0b, // == fd; end
    ]);
    let mut code = vec![0x01, body.len() as u8];
    code.extend(&body);
    wasm.extend(wasm_section(10, &code));
    // data: the payload path at offset 16
    let mut data = vec![0x01, 0x00, 0x41, 0x10, 0x0b, path.len() as u8];
    data.extend(path);
    wasm.extend(wasm_section(11, &data));

    write_config_full(&dir, &["/data"], &wasm, "")?;
    let bytes = build_bytes(&dir)?;

    let (artifact, _source) = lazy_open(bytes)?;
    let mut session = caf_runtime::instantiate(&artifact, "spatial")?;
    let results = session.call(
        "churn",
        &[caf_runtime::Val::I32(16), caf_runtime::Val::I32(18)],
    )?;
    assert!(matches!(results.first(), Some(caf_runtime::Val::I32(1))));

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ---------------------------------------------------------------------------
// Signer fingerprints and trust stores.
// ---------------------------------------------------------------------------

#[test]
fn signed_report_carries_signer_fingerprint() -> Result<()> {
    use ed25519_dalek::SigningKey;

    let dir = temp_root("fingerprint")?;
    write_signed_config(&dir, &["/data"])?;
    let bytes = build_bytes(&dir)?;

    let report = verify::verify_bytes(&bytes)?;
    assert!(report.signed);
    assert_eq!(report.signature_valid, Some(true));
    let Some(fp) = &report.signer_fingerprint else {
        return Err(anyhow::anyhow!("missing signer fingerprint"));
    };

    // The fingerprint is the sha256 of the public key derived from the seed.
    let seed = hex::decode(&"11".repeat(32))?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad seed length"))?;
    let pubkey = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    assert_eq!(fp, &payload::chunk_hash(&pubkey));

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn unsigned_report_has_no_signer_fingerprint() -> Result<()> {
    let dir = temp_root("no-fingerprint")?;
    write_config(&dir, &["/data"])?;
    let bytes = build_bytes(&dir)?;
    let report = verify::verify_bytes(&bytes)?;
    assert!(!report.signed);
    assert_eq!(report.signer_fingerprint, None);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn trust_store_loads_and_matches() -> Result<()> {
    let dir = temp_root("trust")?;
    let path = dir.join("trusted.toml");
    std::fs::write(&path, "[keys]\nabc123 = \"Example Publisher\"\n")?;
    let store = crate::TrustStore::load(&path)?;
    assert_eq!(
        store.keys.get("abc123").map(String::as_str),
        Some("Example Publisher")
    );
    assert!(!store.keys.contains_key("def456"));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

fn stored_section(bytes: &[u8], tag: u8) -> Result<&[u8]> {
    let header = layout::read_header(bytes)?;
    let entries = layout::decode_directory(layout::slice(
        bytes,
        header.directory_offset,
        header.directory_len,
    )?)?;
    let entry = entries
        .iter()
        .find(|e| e.tag == tag)
        .context("missing section")?;
    layout::slice(bytes, entry.offset, entry.length)
}

#[test]
fn convergent_builds_rotate_keys_for_metadata_and_content_changes() -> Result<()> {
    let (secret, public) = recipient_keypair();
    let dir = temp_root("convergent-key-rotation")?;
    write_sealed_config(&dir, &["/data"], &public, Some(&"77".repeat(32)), None)?;
    let (cfg, base) = config::load(&dir.join("build.toml"))?;
    let original = assemble::assemble(&cfg, &base)?;
    let old_key = original.content_key.context("content key")?;
    let old_stanza = &stored_section(&original.bytes, layout::TAG_KEYBOX)?[4..];
    for change in 0..6 {
        let (mut cfg, base) = config::load(&dir.join("build.toml"))?;
        match change {
            0 => cfg.version = "0.2.0".into(),
            1 => cfg.name = "renamed".into(),
            2 => cfg.payload.media_type = "application/new-type".into(),
            3 => cfg.components[0].name = "renamed-component".into(),
            4 => cfg.components[0].access = vec!["/index".into()],
            _ => std::fs::write(dir.join("payload/data/city.parquet"), b"new payload")?,
        }
        let changed = assemble::assemble(&cfg, &base)?;
        let new_key = changed.content_key.context("new content key")?;
        assert_ne!(
            old_key, new_key,
            "change {change} must rotate the content key"
        );
        let new_stanza = &stored_section(&changed.bytes, layout::TAG_KEYBOX)?[4..];
        assert_ne!(
            &old_stanza[..65],
            &new_stanza[..65],
            "wrapping ephemeral must rotate"
        );
        // The former attack recovered the new key using the known old key.
        let recovered: Vec<_> = old_stanza[77..109]
            .iter()
            .zip(&new_stanza[77..109])
            .zip(old_key)
            .map(|((a, b), key)| a ^ b ^ key)
            .collect();
        assert_ne!(recovered.as_slice(), new_key.as_slice());
        assert_eq!(
            caf_core::crypto::unwrap_artifact(&changed.bytes, &secret)?,
            Some(new_key)
        );
        verify::verify_bytes_keyed(&changed.bytes, Some(&new_key))?;
        assert!(
            caf_core::crypto::open_chunk(
                &caf_core::crypto::section_key(&old_key, "private"),
                0,
                stored_section(&changed.bytes, layout::TAG_PRIVATE)?,
            )
            .is_err()
        );
        assert_eq!(changed.bytes, assemble::assemble(&cfg, &base)?.bytes);
    }
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

/// Probe opens a payload file and reads one byte. Calling it again must not
/// make a previously denied read succeed through the chunk cache.
fn read_probe_wasm() -> Vec<u8> {
    read_probe_wasm_len(1, 1)
}

fn read_probe_wasm_len(read_len: u32, memory_pages: u8) -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.extend(wasm_section(
        1,
        &[
            3, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, 0x60, 3, 0x7f, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 1, 0x7f,
        ],
    ));
    wasm.extend(wasm_section(
        2,
        b"\x02\x03caf\x04open\x00\x00\x03caf\x04read\x00\x01",
    ));
    wasm.extend(wasm_section(3, &[1, 2]));
    wasm.extend(wasm_section(5, &[1, 0, memory_pages]));
    wasm.extend(wasm_section(7, b"\x02\x06memory\x02\x00\x05probe\x00\x02"));
    let mut body = vec![0, 0x41, 16, 0x41, 18, 0x10, 0, 0x41, 0, 0x41];
    let mut value = read_len;
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        let done = value == 0 && byte & 0x40 == 0;
        body.push(if done { byte } else { byte | 0x80 });
        if done {
            break;
        }
    }
    body.extend([0x10, 1, 0x0b]);
    let mut code = vec![1, body.len() as u8];
    code.extend(body);
    wasm.extend(wasm_section(10, &code));
    let path = b"/data/city.parquet";
    let mut data = vec![1, 0, 0x41, 16, 0x0b, path.len() as u8];
    data.extend(path);
    wasm.extend(wasm_section(11, &data));
    wasm
}

#[test]
fn read_budget_is_reserved_before_io_for_plain_and_sealed_payloads() -> Result<()> {
    for sealed in [false, true] {
        let dir = temp_root(if sealed {
            "sealed-read-budget"
        } else {
            "read-budget"
        })?;
        if sealed {
            let (_, public) = recipient_keypair();
            write_sealed_config(&dir, &["/data"], &public, Some(&"88".repeat(32)), None)?;
            std::fs::write(dir.join("spatial.wasm"), read_probe_wasm())?;
        } else {
            write_config_full(&dir, &["/data"], &read_probe_wasm(), "")?;
        }
        for limit in [0, 1, 13, 4112] {
            let (mut cfg, base) = config::load(&dir.join("build.toml"))?;
            cfg.resources.read_max = limit;
            let built = assemble::assemble(&cfg, &base)?;
            let source = std::sync::Arc::new(CountingSource::new(built.bytes));
            let artifact = std::sync::Arc::new(match built.content_key {
                Some(key) => caf_runtime::Artifact::open_source_with_key(source.clone(), &key)?,
                None => caf_runtime::Artifact::open_source(source.clone())?,
            });
            let mut session = caf_runtime::instantiate(&artifact, "spatial")?;
            let before = source.bytes_read();
            let cost = if sealed { 4112 } else { 13 };
            for _ in 0..3 {
                let result = session.call("probe", &[])?;
                assert!(
                    matches!(result[0], caf_runtime::Val::I32(v) if v == if limit >= cost { 1 } else { -1 })
                );
            }
            assert_eq!(
                source.bytes_read() - before,
                if limit >= cost { cost } else { 0 }
            );
            assert_eq!(session.usage().read, if limit >= cost { cost } else { 0 });
        }
        std::fs::remove_dir_all(dir)?;
    }
    Ok(())
}

fn host_memory_probe(import: &str) -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.extend(wasm_section(1, &[1, 0x60, 2, 0x7f, 0x7f, 1, 0x7f]));
    let mut imports = vec![1, 3, b'c', b'a', b'f', import.len() as u8];
    imports.extend(import.as_bytes());
    imports.extend([0, 0]);
    wasm.extend(wasm_section(2, &imports));
    wasm.extend(wasm_section(5, &[1, 0, 1]));
    wasm.extend(wasm_section(7, b"\x02\x06memory\x02\x00\x05probe\x00\x00"));
    wasm
}

#[test]
fn guest_memory_ranges_are_checked_before_copying_or_charging_output() -> Result<()> {
    let dir = temp_root("guest-memory-bounds")?;
    for import in ["open", "emit", "log"] {
        write_config_full(
            &dir,
            &["/data"],
            &host_memory_probe(import),
            "\n[resources]\nmemory_max = 65536\noutput_max = 8\n",
        )?;
        let artifact = std::sync::Arc::new(caf_runtime::Artifact::open(build_bytes(&dir)?)?);
        for (ptr, len) in [(0, i32::MAX), (65535, 2), (-1, 1), (0, -1)] {
            let mut session = caf_runtime::instantiate(&artifact, "spatial")?;
            let result = session.call(
                "probe",
                &[caf_runtime::Val::I32(ptr), caf_runtime::Val::I32(len)],
            )?;
            assert!(matches!(result[0], caf_runtime::Val::I32(-1)));
            assert!(session.emitted().is_empty());
            assert_eq!(session.usage().output, 4, "only the i32 result is charged");
        }
        let mut session = caf_runtime::instantiate(&artifact, "spatial")?;
        assert!(session.read_memory(0, u32::MAX).is_err());
        assert!(session.read_memory(65535, 2).is_err());
        assert_eq!(session.usage().output, 0);
        assert_eq!(session.read_memory(65535, 1)?, [0]);
        assert_eq!(session.usage().output, 1);
        if import != "open" {
            // In-bounds output is still denied before copying if over budget.
            let result = session.call(
                "probe",
                &[caf_runtime::Val::I32(0), caf_runtime::Val::I32(16)],
            )?;
            assert!(matches!(result[0], caf_runtime::Val::I32(-1)));
            assert!(session.emitted().is_empty());
            assert_eq!(session.usage().output, 5);
        }
    }
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn build_rejects_missing_capability_exports_and_unimplemented_artifact_capabilities() -> Result<()>
{
    let dir = temp_root("missing-wit-export")?;
    write_config_full(&dir, &["/data"], b"\0asm\x01\0\0\0", "")?;
    bind_test_capabilities(&dir, &["cf:metadata@1"])?;
    let err = build_bytes(&dir)
        .err()
        .context("missing export must fail")?;
    assert!(format!("{err:#}").contains("missing WASM function 'name'"));
    let (mut cfg, base) = config::load(&dir.join("build.toml"))?;
    cfg.components[0].capabilities.clear();
    cfg.capabilities.push("cf:metadata@1".into());
    let err = assemble::assemble(&cfg, &base)
        .err()
        .context("unbound capability must fail")?;
    assert!(format!("{err:#}").contains("no implementing component"));
    cfg.capabilities.clear();
    cfg.components[0].capabilities.push("cf:metadata@1".into());
    cfg.interfaces.clear();
    let err = assemble::assemble(&cfg, &base)
        .err()
        .context("missing WIT must fail")?;
    assert!(format!("{err:#}").contains("without a WIT world"));
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn build_checks_scalar_parameter_and_result_types_and_records_actual_export_name() -> Result<()> {
    let dir = temp_root("wit-signatures")?;
    // Actual function is (i32) -> i32, exported with a snake_case name.
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.extend(wasm_section(1, &[1, 0x60, 1, 0x7f, 1, 0x7f]));
    wasm.extend(wasm_section(3, &[1, 0]));
    wasm.extend(wasm_section(7, b"\x01\x0bscalar_call\x00\x00"));
    wasm.extend(wasm_section(10, &[1, 4, 0, 0x20, 0, 0x0b]));
    write_config_full(&dir, &["/data"], &wasm, "")?;
    bind_test_capabilities(&dir, &["cf:scalar-call@1"])?;
    for (signature, accepted) in [
        ("func(x: u32) -> u32", true),
        ("func(x: f64) -> u32", false),
        ("func(x: u32) -> u64", false),
        ("func() -> u32", false),
        ("func(x: u32)", false),
    ] {
        std::fs::write(
            dir.join("spatial.wit"),
            format!(
                "package cf:gis@0.1.0; world spatial-file {{ export scalar-call: {signature}; }}"
            ),
        )?;
        let built = build_bytes(&dir);
        assert_eq!(built.is_ok(), accepted, "{signature}");
        if let Ok(bytes) = built {
            assert_eq!(
                decode_manifest(&bytes)?.components[0].exports[0].export,
                "scalar_call"
            );
        }
    }
    // Aliases, enums and flags lower to i32 as well.
    std::fs::write(
        dir.join("spatial.wit"),
        "package cf:gis@0.1.0; world spatial-file { type number = u32; export scalar-call: func(x: number) -> number; }",
    )?;
    build_bytes(&dir)?;
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn build_checks_complex_parameters_memory_and_bridge_signatures() -> Result<()> {
    let dir = temp_root("wit-complex-signatures")?;
    let wasm = wasm_with_bridge();
    write_config_full(&dir, &["/data"], &wasm, "")?;
    bind_test_capabilities(&dir, &["cf:metadata@1"])?;
    // A string parameter requires (ptr, len); name() takes no parameters.
    std::fs::write(
        dir.join("spatial.wit"),
        "package cf:gis@0.1.0; world spatial-file { export metadata: interface { name: func(value: string) -> string; } }",
    )?;
    let err = build_bytes(&dir)
        .err()
        .context("complex argument mismatch must fail")?;
    assert!(format!("{err:#}").contains("signature mismatch"));
    write_config_full(&dir, &["/data"], &wasm, "")?;
    bind_test_capabilities(&dir, &["cf:metadata@1"])?;
    // Valid WASM with an alloc export of the wrong type (points at name).
    let mut wrong_alloc = wasm.clone();
    let at = wrong_alloc
        .windows(7)
        .position(|w| w == b"\x05alloc\x00")
        .context("alloc export")?;
    wrong_alloc[at + 7] = 0;
    std::fs::write(dir.join("spatial.wasm"), wrong_alloc)?;
    let err = build_bytes(&dir)
        .err()
        .context("wrong alloc signature must fail")?;
    assert!(format!("{err:#}").contains("memory bridge 'alloc' signature mismatch"));
    let mut wrong_dealloc = wasm.clone();
    let at = wrong_dealloc
        .windows(9)
        .position(|w| w == b"\x07dealloc\x00")
        .context("dealloc export")?;
    wrong_dealloc[at + 9] = 1;
    std::fs::write(dir.join("spatial.wasm"), wrong_dealloc)?;
    let err = build_bytes(&dir)
        .err()
        .context("wrong dealloc signature must fail")?;
    assert!(format!("{err:#}").contains("memory bridge 'dealloc' signature mismatch"));
    let mut no_memory = wasm.clone();
    let at = no_memory
        .windows(6)
        .position(|w| w == b"memory")
        .context("memory export")?;
    no_memory[at..at + 6].copy_from_slice(b"hidden");
    std::fs::write(dir.join("spatial.wasm"), no_memory)?;
    let err = build_bytes(&dir)
        .err()
        .context("missing memory must fail")?;
    assert!(format!("{err:#}").contains("requires an exported"));
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn partial_and_corrupt_reads_cannot_retry_without_charging_their_io() -> Result<()> {
    let dir = temp_root("partial-read-budget")?;
    let length = 2 * manifest::CHUNK_SIZE + 5;
    write_config_full(
        &dir,
        &["/data"],
        &read_probe_wasm_len(length as u32, 64),
        "",
    )?;
    std::fs::write(dir.join("payload/data/city.parquet"), vec![7; length])?;
    let (mut cfg, base) = config::load(&dir.join("build.toml"))?;
    // Two full chunks can be fetched, but the last five bytes cannot.
    cfg.resources.read_max = (length - 1) as u64;
    let built = assemble::assemble(&cfg, &base)?;
    let source = std::sync::Arc::new(CountingSource::new(built.bytes));
    let artifact = std::sync::Arc::new(caf_runtime::Artifact::open_source(source.clone())?);
    let mut session = caf_runtime::instantiate(&artifact, "spatial")?;
    let before = source.bytes_read();
    for _ in 0..3 {
        let results = session.call("probe", &[])?;
        assert!(matches!(results[0], caf_runtime::Val::I32(-1)));
    }
    assert_eq!(
        source.bytes_read() - before,
        2 * manifest::CHUNK_SIZE as u64
    );
    assert_eq!(session.usage().read, 2 * manifest::CHUNK_SIZE as u64);
    // Even a verification failure retains its reservation and never caches
    // corrupt bytes. A second attempt cannot perform another uncharged read.
    write_config_full(&dir, &["/data"], &read_probe_wasm(), "")?;
    let (mut cfg, base) = config::load(&dir.join("build.toml"))?;
    cfg.resources.read_max = 13;
    let mut built = assemble::assemble(&cfg, &base)?;
    let (offset, _) = payload_span(&built.bytes, 13)?;
    built.bytes[offset as usize] ^= 1;
    let source = std::sync::Arc::new(CountingSource::new(built.bytes));
    let artifact = std::sync::Arc::new(caf_runtime::Artifact::open_source(source.clone())?);
    let mut session = caf_runtime::instantiate(&artifact, "spatial")?;
    let before = source.bytes_read();
    for _ in 0..3 {
        let results = session.call("probe", &[])?;
        assert!(matches!(results[0], caf_runtime::Val::I32(-1)));
    }
    assert_eq!(source.bytes_read() - before, 13);
    assert_eq!(session.usage().read, 13);
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

fn zip_bytes(archive: &mut zip::ZipArchive<std::fs::File>, name: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    archive.by_name(name)?.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[test]
fn export_zip_preserves_contents_and_is_deterministic() -> Result<()> {
    let dir = temp_root("export-plain")?;
    write_signed_config(&dir, &["/data"])?;
    std::fs::create_dir_all(dir.join("payload/empty-dir"))?;
    std::fs::write(dir.join("payload/empty"), [])?;
    let large = vec![0x5a; 2 * 1024 * 1024 + 17];
    std::fs::write(dir.join("payload/large.bin"), &large)?;
    let bytes = build_bytes(&dir)?;
    let input = dir.join("input.caf");
    let output = dir.join("output.zip");
    std::fs::write(&input, &bytes)?;
    crate::export::export(&input, &output, false, None, None, Compression::Deflate)?;
    let mut zip = zip::ZipArchive::new(std::fs::File::open(&output)?)?;
    let header = layout::read_header(&bytes)?;
    assert_eq!(
        zip_bytes(&mut zip, "manifest.cbor")?,
        layout::slice(&bytes, header.manifest_offset, header.manifest_len)?
    );
    assert_eq!(
        zip_bytes(&mut zip, "interfaces/interface.wit")?,
        std::fs::read(dir.join("spatial.wit"))?
    );
    assert_eq!(
        zip_bytes(&mut zip, "components/0000.wasm")?,
        std::fs::read(dir.join("spatial.wasm"))?
    );
    assert_eq!(
        zip_bytes(&mut zip, "payload/data/city.parquet")?,
        b"parquet-bytes"
    );
    assert_eq!(zip_bytes(&mut zip, "payload/large.bin")?, large);
    assert!(zip_bytes(&mut zip, "payload/empty")?.is_empty());
    assert!(zip.by_name("payload/empty-dir/")?.is_dir());
    assert_eq!(zip_bytes(&mut zip, "signature.bin")?.len(), 96);
    let metadata: serde_json::Value = serde_json::from_slice(&zip_bytes(&mut zip, "export.json")?)?;
    assert_eq!(metadata["export_version"], 2);
    assert_eq!(metadata["components"][0]["name"], "spatial");
    assert_eq!(metadata["root_hash"], hex::encode(&header.root_hash));
    let second = dir.join("second.zip");
    crate::export::export(&input, &second, false, None, None, Compression::Deflate)?;
    assert_eq!(std::fs::read(&output)?, std::fs::read(&second)?);
    assert!(
        crate::export::export(&input, &output, false, None, None, Compression::Deflate).is_err()
    );
    crate::export::export(&input, &output, true, None, None, Compression::Deflate)?;
    assert!(crate::export::export(&input, &input, true, None, None, Compression::Deflate).is_err());
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn export_sealed_zip_requires_key_and_exports_plaintext() -> Result<()> {
    let dir = temp_root("export-sealed")?;
    let (secret, public) = recipient_keypair();
    write_sealed_config(&dir, &["/data"], &public, None, Some(&"11".repeat(32)))?;
    let large = vec![0xab; 2 * 1024 * 1024 + 31];
    std::fs::write(dir.join("payload/large"), &large)?;
    let bytes = build_bytes(&dir)?;
    let key = crypto::unwrap_artifact(&bytes, &secret)?.context("no content key")?;
    let input = dir.join("input.caf");
    let output = dir.join("output.zip");
    std::fs::write(&input, &bytes)?;
    assert!(
        crate::export::export(&input, &output, false, None, None, Compression::Deflate).is_err()
    );
    assert!(
        crate::export::export(
            &input,
            &output,
            false,
            Some(&"00".repeat(32)),
            None,
            Compression::Deflate
        )
        .is_err()
    );
    assert!(!output.exists());
    crate::export::export(
        &input,
        &output,
        false,
        None,
        Some(&hex::encode(&secret.to_bytes())),
        Compression::Deflate,
    )?;
    let mut zip = zip::ZipArchive::new(std::fs::File::open(&output)?)?;
    assert_eq!(
        zip_bytes(&mut zip, "components/0000.wasm")?,
        b"\0asm\x01\0\0\0"
    );
    assert_eq!(zip_bytes(&mut zip, "payload/large")?, large);
    let private = verify::open_private_manifest(&bytes, &key)?;
    let exported: manifest::PrivateManifest =
        ciborium::de::from_reader(zip_bytes(&mut zip, "private-manifest.cbor")?.as_slice())?;
    assert_eq!(private.name, exported.name);
    let second = dir.join("second.zip");
    crate::export::export(
        &input,
        &second,
        false,
        Some(&hex::encode(&key)),
        None,
        Compression::Deflate,
    )?;
    assert_eq!(std::fs::read(&output)?, std::fs::read(&second)?);
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn export_failure_preserves_existing_output_and_cleans_temporary_file() -> Result<()> {
    let dir = temp_root("export-failure")?;
    write_config(&dir, &["/data"])?;
    let mut bytes = build_bytes(&dir)?;
    let header = layout::read_header(&bytes)?;
    let entries = layout::decode_directory(layout::slice(
        &bytes,
        header.directory_offset,
        header.directory_len,
    )?)?;
    let file = entries
        .iter()
        .find(|e| e.tag == layout::TAG_PAYLOAD)
        .context("missing payload")?;
    bytes[file.offset as usize] ^= 1;
    let input = dir.join("input.caf");
    let output = dir.join("output.zip");
    std::fs::write(&input, bytes)?;
    std::fs::write(&output, b"original output")?;
    let count = std::fs::read_dir(&dir)?.count();
    assert!(
        crate::export::export(&input, &output, true, None, None, Compression::Deflate).is_err()
    );
    assert_eq!(std::fs::read(&output)?, b"original output");
    assert_eq!(std::fs::read_dir(&dir)?.count(), count);
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn export_does_not_require_execution_admission() -> Result<()> {
    let dir = temp_root("export-no-admission")?;
    write_config_full(
        &dir,
        &["/data"],
        b"\0asm\x01\0\0\0",
        "\n[policy]\nnetwork = true\n",
    )?;
    let bytes = build_bytes(&dir)?;
    verify::verify_bytes(&bytes)?;
    assert!(caf_runtime::Artifact::open(bytes.clone()).is_err());
    let input = dir.join("input.caf");
    std::fs::write(&input, bytes)?;
    crate::export::export(
        &input,
        &dir.join("output.zip"),
        false,
        None,
        None,
        Compression::Deflate,
    )?;
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn export_rejects_conflicting_or_unsafe_payload_paths() -> Result<()> {
    for (index, names) in [["case", "CASE"], ["bad:name", "other"]].iter().enumerate() {
        let dir = temp_root(&format!("export-unsafe-{index}"))?;
        write_config(&dir, &["/data"])?;
        for name in names {
            std::fs::write(dir.join("payload").join(name), b"content")?;
        }
        let input = dir.join("input.caf");
        let output = dir.join("output.zip");
        std::fs::write(&input, build_bytes(&dir)?)?;
        assert!(
            crate::export::export(&input, &output, false, None, None, Compression::Deflate)
                .is_err()
        );
        assert!(!output.exists());
        std::fs::remove_dir_all(dir)?;
    }
    Ok(())
}

#[test]
fn export_rejects_invalid_signature_and_corrupted_sealed_padding() -> Result<()> {
    for sealed in [false, true] {
        let dir = temp_root(if sealed {
            "export-bad-padding"
        } else {
            "export-bad-signature"
        })?;
        let (secret, public) = recipient_keypair();
        if sealed {
            write_sealed_config(&dir, &["/data"], &public, None, None)?;
        } else {
            write_signed_config(&dir, &["/data"])?;
        }
        let mut bytes = build_bytes(&dir)?;
        let key = if sealed {
            crypto::unwrap_artifact(&bytes, &secret)?.map(|key| hex::encode(&key))
        } else {
            None
        };
        let header = layout::read_header(&bytes)?;
        let entries = layout::decode_directory(layout::slice(
            &bytes,
            header.directory_offset,
            header.directory_len,
        )?)?;
        let tag = if sealed {
            layout::TAG_PAYLOAD
        } else {
            layout::TAG_SIGNATURE
        };
        let entry = entries
            .iter()
            .find(|e| e.tag == tag)
            .context("missing section")?;
        bytes[(entry.offset + entry.length - 1) as usize] ^= 1;
        let input = dir.join("input.caf");
        let output = dir.join("output.zip");
        std::fs::write(&input, bytes)?;
        assert!(
            crate::export::export(
                &input,
                &output,
                false,
                key.as_deref(),
                None,
                Compression::Deflate
            )
            .is_err()
        );
        assert!(!output.exists());
        std::fs::remove_dir_all(dir)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// import: byte-identical reconstruction from an export ZIP (round-trip).
// ---------------------------------------------------------------------------

/// Copy the `src` ZIP to `dst`, applying `edit` to the `target` entry's bytes.
fn rewrite_zip(src: &Path, dst: &Path, target: &str, edit: impl Fn(&mut Vec<u8>)) -> Result<()> {
    use std::io::{Read, Write};
    let mut archive = zip::ZipArchive::new(std::fs::File::open(src)?)?;
    let mut out = zip::ZipWriter::new(std::fs::File::create(dst)?);
    let options = zip::write::SimpleFileOptions::default();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_string();
        if entry.is_dir() {
            out.add_directory(&name, options)?;
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        if name == target {
            edit(&mut bytes);
        }
        out.start_file(&name, options)?;
        out.write_all(&bytes)?;
    }
    out.finish()?;
    Ok(())
}

#[test]
fn import_roundtrip_is_byte_identical() -> Result<()> {
    let dir = temp_root("import-roundtrip")?;
    write_signed_config(&dir, &["/data"])?;
    std::fs::create_dir_all(dir.join("payload/empty-dir"))?;
    std::fs::write(dir.join("payload/empty"), [])?;
    std::fs::write(
        dir.join("payload/large.bin"),
        vec![0x5a; 2 * 1024 * 1024 + 17],
    )?;
    let bytes = build_bytes(&dir)?;
    let caf = dir.join("input.caf");
    let zip_path = dir.join("output.zip");
    let rebuilt = dir.join("rebuilt.caf");
    std::fs::write(&caf, &bytes)?;
    crate::export::export(&caf, &zip_path, false, None, None, Compression::Deflate)?;
    crate::import::import(&zip_path, &rebuilt, false)?;
    assert_eq!(
        std::fs::read(&rebuilt)?,
        bytes,
        "build -> export -> import must reproduce the original bytes"
    );
    let report = verify::verify_bytes(&std::fs::read(&rebuilt)?)?;
    assert_eq!(report.signature_valid, Some(true));
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn import_roundtrip_unsigned() -> Result<()> {
    let dir = temp_root("import-unsigned")?;
    write_config(&dir, &["/data", "/index"])?;
    let bytes = build_bytes(&dir)?;
    assert!(!verify::verify_bytes(&bytes)?.signed);
    let caf = dir.join("input.caf");
    let zip_path = dir.join("output.zip");
    let rebuilt = dir.join("rebuilt.caf");
    std::fs::write(&caf, &bytes)?;
    crate::export::export(&caf, &zip_path, false, None, None, Compression::Deflate)?;
    crate::import::import(&zip_path, &rebuilt, false)?;
    assert_eq!(std::fs::read(&rebuilt)?, bytes);
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn import_rejects_sealed_export() -> Result<()> {
    let dir = temp_root("import-sealed")?;
    let (secret, public) = recipient_keypair();
    write_sealed_config(&dir, &["/data"], &public, None, None)?;
    let bytes = build_bytes(&dir)?;
    let caf = dir.join("input.caf");
    let zip_path = dir.join("output.zip");
    std::fs::write(&caf, &bytes)?;
    crate::export::export(
        &caf,
        &zip_path,
        false,
        None,
        Some(&hex::encode(&secret.to_bytes())),
        Compression::Deflate,
    )?;
    let err = crate::import::import(&zip_path, &dir.join("out.caf"), false).unwrap_err();
    assert!(format!("{err:#}").contains("sealed"), "{err:#}");
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn import_detects_tampering() -> Result<()> {
    let dir = temp_root("import-tamper")?;
    write_config(&dir, &["/data"])?;
    let bytes = build_bytes(&dir)?;
    let caf = dir.join("input.caf");
    let good = dir.join("good.zip");
    std::fs::write(&caf, &bytes)?;
    crate::export::export(&caf, &good, false, None, None, Compression::Deflate)?;

    // A flipped payload byte breaks the per-file Merkle check.
    let bad = dir.join("bad-payload.zip");
    rewrite_zip(&good, &bad, "payload/data/city.parquet", |b| b[0] ^= 1)?;
    let err = crate::import::import(&bad, &dir.join("out.caf"), false).unwrap_err();
    assert!(
        format!("{err:#}").contains("does not match the manifest"),
        "{err:#}"
    );

    // A rewritten export.json root hash breaks the identity gate.
    let bad = dir.join("bad-meta.zip");
    rewrite_zip(&good, &bad, "export.json", |b| {
        let mut meta: serde_json::Value = serde_json::from_slice(b).unwrap();
        meta["root_hash"] = "00".repeat(32).into();
        *b = serde_json::to_vec_pretty(&meta).unwrap();
    })?;
    assert!(crate::import::import(&bad, &dir.join("out2.caf"), false).is_err());

    // An undeclared payload entry is rejected.
    let bad = dir.join("bad-extra.zip");
    {
        use std::io::{Read, Write};
        let mut archive = zip::ZipArchive::new(std::fs::File::open(&good)?)?;
        let mut out = zip::ZipWriter::new(std::fs::File::create(&bad)?);
        let options = zip::write::SimpleFileOptions::default();
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            let name = entry.name().to_string();
            if entry.is_dir() {
                out.add_directory(&name, options)?;
                continue;
            }
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            out.start_file(&name, options)?;
            out.write_all(&bytes)?;
        }
        out.start_file("payload/sneaky.txt", options)?;
        out.write_all(b"sneaky")?;
        out.finish()?;
    }
    let err = crate::import::import(&bad, &dir.join("out3.caf"), false).unwrap_err();
    assert!(
        format!("{err:#}").contains("undeclared payload entry"),
        "{err:#}"
    );

    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn import_refuses_overwrite_and_self_overwrite() -> Result<()> {
    let dir = temp_root("import-overwrite")?;
    write_config(&dir, &["/data"])?;
    let bytes = build_bytes(&dir)?;
    let caf = dir.join("input.caf");
    let zip_path = dir.join("output.zip");
    std::fs::write(&caf, &bytes)?;
    crate::export::export(&caf, &zip_path, false, None, None, Compression::Deflate)?;
    let out = dir.join("out.caf");
    std::fs::write(&out, b"existing")?;
    assert!(crate::import::import(&zip_path, &out, false).is_err());
    assert_eq!(std::fs::read(&out)?, b"existing");
    crate::import::import(&zip_path, &out, true)?;
    assert_eq!(std::fs::read(&out)?, bytes);
    assert!(crate::import::import(&zip_path, &zip_path, true).is_err());
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn export_stored_compression_is_byte_deterministic() -> Result<()> {
    let dir = temp_root("export-stored")?;
    write_config(&dir, &["/data"])?;
    let bytes = build_bytes(&dir)?;
    let caf = dir.join("input.caf");
    std::fs::write(&caf, &bytes)?;
    let a = dir.join("a.zip");
    let b = dir.join("b.zip");
    crate::export::export(&caf, &a, false, None, None, Compression::Stored)?;
    crate::export::export(&caf, &b, false, None, None, Compression::Stored)?;
    assert_eq!(std::fs::read(&a)?, std::fs::read(&b)?);
    let mut archive = zip::ZipArchive::new(std::fs::File::open(&a)?)?;
    assert_eq!(
        archive.by_name("manifest.cbor")?.compression(),
        zip::CompressionMethod::Stored
    );
    // Stored exports round-trip through import exactly like deflated ones.
    let rebuilt = dir.join("rebuilt.caf");
    crate::import::import(&a, &rebuilt, false)?;
    assert_eq!(std::fs::read(&rebuilt)?, bytes);
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Format version registry (caf_core::version): admission is fail-closed.
// ---------------------------------------------------------------------------

#[test]
fn unsupported_format_version_is_rejected_at_the_header() -> Result<()> {
    let dir = temp_root("version-admission")?;
    write_config(&dir, &["/data"])?;
    let mut bytes = build_bytes(&dir)?;
    assert_eq!(layout::read_header(&bytes)?.format_version, 1);

    // Bump the declared container version to something this build never heard of.
    bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
    let err = layout::read_header(&bytes)
        .err()
        .context("unknown version must fail")?;
    assert!(
        format!("{err:#}").contains("unsupported format version 2"),
        "{err:#}"
    );
    assert!(verify::verify_bytes(&bytes).is_err());

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn build_rejects_unsupported_format_version() -> Result<()> {
    let dir = temp_root("version-build")?;
    write_config(&dir, &["/data"])?;
    let (mut cfg, base) = config::load(&dir.join("build.toml"))?;
    cfg.format_version = 2;
    let err = assemble::assemble(&cfg, &base)
        .err()
        .context("unsupported version must fail")?;
    assert!(
        format!("{err:#}").contains("unsupported format_version 2"),
        "{err:#}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ---------------------------------------------------------------------------
// exports.rs: WASM export enumeration and validation edge cases.
// ---------------------------------------------------------------------------

/// Module exporting one of each core kind: func, table, memory, global.
fn wasm_all_export_kinds() -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.extend(wasm_section(1, &[0x01, 0x60, 0x00, 0x00])); // type ()->()
    wasm.extend(wasm_section(3, &[0x01, 0x00])); // func 0 : type 0
    wasm.extend(wasm_section(4, &[0x01, 0x70, 0x00, 0x00])); // table funcref min 0
    wasm.extend(wasm_section(5, &[0x01, 0x00, 0x01])); // memory min 1
    wasm.extend(wasm_section(6, &[0x01, 0x7f, 0x00, 0x41, 0x00, 0x0b])); // global i32 = 0
    let mut exports = vec![0x04];
    for (name, kind) in [("f", 0x00u8), ("t", 0x01), ("m", 0x02), ("g", 0x03)] {
        exports.push(0x01);
        exports.extend(name.as_bytes());
        exports.extend([kind, 0x00]);
    }
    wasm.extend(wasm_section(7, &exports));
    wasm.extend(wasm_section(10, &[0x01, 0x02, 0x00, 0x0b])); // empty body
    wasm
}

#[test]
fn extract_exports_covers_all_core_kinds() {
    let exports = crate::exports::extract_exports(&wasm_all_export_kinds());
    let signatures: Vec<(&str, &str)> = exports
        .iter()
        .map(|e| (e.export.as_str(), e.signature.as_str()))
        .collect();
    assert_eq!(
        signatures,
        [
            ("f", "func"),
            ("t", "table"),
            ("m", "memory"),
            ("g", "global")
        ]
    );
    assert!(exports.iter().all(|e| e.capability.is_empty()));
}

#[test]
fn extract_exports_is_best_effort_on_garbage_and_truncation() {
    assert!(crate::exports::extract_exports(b"\0asm garbage").is_empty());

    // An export entry cut off mid-record keeps the entries parsed so far.
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.extend(wasm_section(1, &[0x01, 0x60, 0x00, 0x00]));
    wasm.extend(wasm_section(3, &[0x01, 0x00]));
    let mut exports = vec![0x02]; // declares two entries
    exports.extend([0x01, b'f', 0x00, 0x00]); // one complete entry
    exports.extend([0x01, b't']); // second entry truncated
    wasm.extend(wasm_section(7, &exports));
    let exports = crate::exports::extract_exports(&wasm);
    assert_eq!(exports.len(), 1);
    assert_eq!(exports[0].export, "f");
}

#[test]
fn core_exports_rejects_invalid_and_component_modules() {
    // A function referencing a missing type fails validation.
    let mut bad = b"\0asm\x01\0\0\0".to_vec();
    bad.extend(wasm_section(1, &[0x01, 0x60, 0x00, 0x00]));
    bad.extend(wasm_section(3, &[0x01, 0x09])); // func : type 9 (missing)
    let err = crate::exports::core_exports(&bad)
        .err()
        .context("invalid module must fail")
        .unwrap();
    assert!(
        format!("{err:#}").contains("validate WASM module"),
        "{err:#}"
    );

    // A component binary is not a format v1 component.
    let component = b"\0asm\x0d\x00\x01\x00";
    let err = crate::exports::core_exports(component)
        .err()
        .context("component must fail")
        .unwrap();
    assert!(format!("{err:#}").contains("core WASM module"), "{err:#}");
}

#[test]
fn core_exports_rejects_ambiguous_normalized_names() {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.extend(wasm_section(1, &[0x01, 0x60, 0x00, 0x00]));
    wasm.extend(wasm_section(3, &[0x02, 0x00, 0x00]));
    let mut exports = vec![0x02];
    exports.extend([0x07]);
    exports.extend(b"foo_bar");
    exports.extend([0x00, 0x00]);
    exports.extend([0x07]);
    exports.extend(b"foo-bar");
    exports.extend([0x00, 0x01]);
    wasm.extend(wasm_section(7, &exports));
    wasm.extend(wasm_section(
        10,
        &[0x02, 0x02, 0x00, 0x0b, 0x02, 0x00, 0x0b],
    ));
    let err = crate::exports::core_exports(&wasm)
        .err()
        .context("clashing names must fail")
        .unwrap();
    assert!(format!("{err:#}").contains("ambiguous"), "{err:#}");
}

#[test]
fn core_exports_classifies_memory32() -> Result<()> {
    // A 32-bit memory (imported here) exported as "memory" is memory32.
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    let mut imports = vec![0x01];
    imports.extend([0x03]);
    imports.extend(b"env");
    imports.extend([0x03]);
    imports.extend(b"mem");
    imports.extend([0x02, 0x00, 0x01]); // memory import, min 1
    wasm.extend(wasm_section(2, &imports));
    wasm.extend(wasm_section(7, b"\x01\x06memory\x02\x00"));
    assert!(crate::exports::core_exports(&wasm)?.memory32);

    // memory64 is not memory32.
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.extend(wasm_section(5, &[0x01, 0x05, 0x01, 0x01])); // memory64 min 1 max 1
    wasm.extend(wasm_section(7, b"\x01\x06memory\x02\x00"));
    assert!(!crate::exports::core_exports(&wasm)?.memory32);

    // A shared memory is not memory32 either.
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.extend(wasm_section(5, &[0x01, 0x03, 0x01, 0x01])); // shared min 1 max 1
    wasm.extend(wasm_section(7, b"\x01\x06memory\x02\x00"));
    assert!(!crate::exports::core_exports(&wasm)?.memory32);
    Ok(())
}

// ---------------------------------------------------------------------------
// wizard.rs: scaffold every language plus the rejection paths.
// ---------------------------------------------------------------------------

#[test]
fn wizard_scaffolds_all_languages() -> Result<()> {
    let dir = temp_root("wizard-langs")?;
    for lang in [
        wizard::Language::Python,
        wizard::Language::JavaScript,
        wizard::Language::TinyGo,
        wizard::Language::ActionScript,
    ] {
        let name = format!("demo-{lang:?}").to_lowercase();
        wizard::scaffold(&name, lang, &dir)?;
        let root = dir.join(&name);
        assert!(root.join("build.toml").exists());
        assert!(root.join("README.md").exists());
        assert!(root.join(format!("interfaces/{name}.wit")).exists());
        assert!(root.join("payload/.gitkeep").exists());
    }
    assert!(dir.join("demo-python/app.py").exists());
    assert!(dir.join("demo-javascript/src/component.js").exists());
    assert!(dir.join("demo-javascript/package.json").exists());
    assert!(dir.join("demo-tinygo/main.go").exists());
    assert!(dir.join("demo-tinygo/go.mod").exists());
    assert!(dir.join("demo-actionscript/src/Main.as").exists());

    // Hyphenated names map to underscore crate names; build.sh is executable.
    wizard::scaffold("my-rust", wizard::Language::Rust, &dir)?;
    let build_sh = dir.join("my-rust/build.sh");
    let text = std::fs::read_to_string(&build_sh)?;
    assert!(text.contains("my_rust"), "{text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&build_sh)?.permissions().mode() & 0o111,
            0o111
        );
    }
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn wizard_rejects_invalid_names_and_existing_dirs() -> Result<()> {
    let dir = temp_root("wizard-invalid")?;
    for name in ["", "a/b", "a\\b"] {
        assert!(wizard::scaffold(name, wizard::Language::Rust, &dir).is_err());
    }
    wizard::scaffold("taken", wizard::Language::Rust, &dir)?;
    assert!(wizard::scaffold("taken", wizard::Language::Python, &dir).is_err());
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// run.rs: caf-tool run against fixture components.
// ---------------------------------------------------------------------------

/// `answer: () -> i32` returning 42 (the scalar fixture).
fn wasm_scalar_answer() -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.extend(wasm_section(1, &[0x01, 0x60, 0x00, 0x01, 0x7f]));
    wasm.extend(wasm_section(3, &[0x01, 0x00]));
    wasm.extend(wasm_section(7, b"\x01\x06answer\x00\x00"));
    wasm.extend(wasm_section(10, &[0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b]));
    wasm
}

/// `greet: () -> i64` returning the packed (ptr 0 | len 5 << 32) string
/// "hello", plus the exported memory it points into.
fn wasm_packed_string() -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.extend(wasm_section(1, &[0x01, 0x60, 0x00, 0x01, 0x7e])); // ()->i64
    wasm.extend(wasm_section(3, &[0x01, 0x00]));
    wasm.extend(wasm_section(5, &[0x01, 0x00, 0x01])); // memory min 1
    let mut exports = vec![0x02];
    exports.extend(b"\x05greet\x00\x00");
    exports.extend(b"\x06memory\x02\x00");
    wasm.extend(wasm_section(7, &exports));
    // i64.const 21474836480 (5 << 32), end
    wasm.extend(wasm_section(
        10,
        &[
            0x01, 0x09, 0x00, 0x42, 0x80, 0x80, 0x80, 0x80, 0xd0, 0x00, 0x0b,
        ],
    ));
    // data "hello" at offset 0
    let mut data = vec![0x01, 0x00, 0x41, 0x00, 0x0b, 0x05];
    data.extend(b"hello");
    wasm.extend(wasm_section(11, &data));
    wasm
}

/// `add4: (i32, i64, f32, f64) -> i32`.
fn wasm_add4() -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.extend(wasm_section(
        1,
        &[0x01, 0x60, 0x04, 0x7f, 0x7e, 0x7d, 0x7c, 0x01, 0x7f],
    ));
    wasm.extend(wasm_section(3, &[0x01, 0x00]));
    wasm.extend(wasm_section(7, b"\x01\x04add4\x00\x00"));
    wasm.extend(wasm_section(10, &[0x01, 0x04, 0x00, 0x41, 0x00, 0x0b]));
    wasm
}

/// A component without a WIT world: the manifest export fallback path.
fn write_nowit_config(dir: &Path, wasm: &[u8]) -> Result<()> {
    std::fs::write(
        dir.join("build.toml"),
        "name = \"raw\"\nversion = \"0.1.0\"\ninterfaces = []\n\n[payload]\nroot = \"payload\"\nmedia_type = \"application/x-raw\"\n\n[[components]]\nname = \"raw\"\nworld = \"\"\npath = \"raw.wasm\"\ncapabilities = []\naccess = []\n",
    )?;
    std::fs::write(dir.join("raw.wasm"), wasm)?;
    Ok(())
}

fn build_to_caf(dir: &Path) -> Result<PathBuf> {
    let bytes = build_bytes(dir)?;
    let caf = dir.join("artifact.caf");
    std::fs::write(&caf, &bytes)?;
    Ok(caf)
}

#[test]
fn run_calls_scalar_export() -> Result<()> {
    let dir = temp_root("run-scalar")?;
    write_config_full(&dir, &["/data"], &wasm_scalar_answer(), "")?;
    std::fs::write(
        dir.join("spatial.wit"),
        "package cf:gis@0.1.0; world spatial-file { export answer: func() -> u32; }",
    )?;
    bind_test_capabilities(&dir, &["cf:answer@1"])?;
    let caf = build_to_caf(&dir)?;
    crate::run::run(&caf, "answer", &[], None, false, None)?;
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn run_decodes_packed_string_results_unless_raw() -> Result<()> {
    let dir = temp_root("run-string")?;
    write_nowit_config(&dir, &wasm_packed_string())?;
    let caf = build_to_caf(&dir)?;
    crate::run::run(&caf, "greet", &[], None, false, None)?;
    crate::run::run(&caf, "greet", &[], None, true, None)?;
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn run_parses_all_scalar_arg_types() -> Result<()> {
    let dir = temp_root("run-args")?;
    write_nowit_config(&dir, &wasm_add4())?;
    let caf = build_to_caf(&dir)?;
    crate::run::run(
        &caf,
        "add4",
        &["1".into(), "2".into(), "1.5".into(), "2.5".into()],
        None,
        true,
        None,
    )?;
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn run_reports_cli_style_errors() -> Result<()> {
    let dir = temp_root("run-errors")?;
    write_nowit_config(&dir, &wasm_add4())?;
    let caf = build_to_caf(&dir)?;
    // Missing artifact file.
    assert!(crate::run::run(&dir.join("nope.caf"), "add4", &[], None, false, None).is_err());
    // Unknown component name.
    assert!(crate::run::run(&caf, "add4", &[], Some("nope"), false, None).is_err());
    // Unknown export.
    assert!(crate::run::run(&caf, "nope", &[], None, false, None).is_err());
    // Wrong arity.
    assert!(crate::run::run(&caf, "add4", &[], None, false, None).is_err());
    // Unparsable i32.
    assert!(
        crate::run::run(
            &caf,
            "add4",
            &["x".into(), "2".into(), "1.5".into(), "2.5".into()],
            None,
            false,
            None
        )
        .is_err()
    );
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn run_opens_sealed_artifacts_with_a_key() -> Result<()> {
    let dir = temp_root("run-sealed")?;
    let (secret, public) = recipient_keypair();
    write_sealed_config(&dir, &["/data"], &public, None, None)?;
    std::fs::write(
        dir.join("spatial.wit"),
        "package cf:gis@0.1.0; world spatial-file { export answer: func() -> u32; }",
    )?;
    std::fs::write(dir.join("spatial.wasm"), wasm_scalar_answer())?;
    let bytes = build_bytes(&dir)?;
    let key = crypto::unwrap_artifact(&bytes, &secret)?.context("no content key")?;
    let caf = dir.join("sealed.caf");
    std::fs::write(&caf, &bytes)?;
    crate::run::run(&caf, "answer", &[], None, false, Some(key))?;
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// main.rs: CLI dispatch coverage (Cli::try_parse_from + dispatch).
// ---------------------------------------------------------------------------

use clap::Parser;

fn cli(args: &[&str]) -> Result<()> {
    crate::dispatch(crate::Cli::try_parse_from(args)?.command)
}

fn sp(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
fn cli_build_verify_inspect_ls_diff_export_import() -> Result<()> {
    let dir = temp_root("cli-main")?;
    write_config(&dir, &["/data"])?;
    let caf = dir.join("a.caf");
    let dump = dir.join("dump.json");
    cli(&[
        "caf-tool",
        "build",
        "-c",
        &sp(&dir.join("build.toml")),
        "-o",
        &sp(&caf),
        "--dump-manifest",
        &sp(&dump),
    ])?;
    assert!(dump.exists());
    let caf = sp(&caf);
    cli(&["caf-tool", "verify", &caf])?;
    cli(&["caf-tool", "inspect", &caf])?;
    cli(&["caf-tool", "inspect", &caf, "--json"])?;
    cli(&["caf-tool", "ls", &caf])?;
    cli(&["caf-tool", "diff", &caf, &caf])?;

    // A differing artifact exercises the diff detail branches.
    std::fs::write(dir.join("payload/data/city.parquet"), b"changed")?;
    let other = sp(&dir.join("b.caf"));
    std::fs::write(&other, build_bytes(&dir)?)?;
    cli(&["caf-tool", "diff", &caf, &other])?;

    let zip = sp(&dir.join("a.zip"));
    cli(&["caf-tool", "export", &caf, "-o", &zip])?;
    cli(&[
        "caf-tool",
        "export",
        &caf,
        "-o",
        &sp(&dir.join("b.zip")),
        "--compression",
        "stored",
    ])?;
    cli(&[
        "caf-tool",
        "import",
        &zip,
        "-o",
        &sp(&dir.join("rebuilt.caf")),
    ])?;
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn cli_build_sealed_and_inspect_with_keys() -> Result<()> {
    let dir = temp_root("cli-sealed")?;
    let (secret, public) = recipient_keypair();
    write_sealed_config(&dir, &["/data"], &public, Some(&"99".repeat(32)), None)?;
    let caf = dir.join("s.caf");
    let dump = dir.join("dump.json");
    cli(&[
        "caf-tool",
        "build",
        "-c",
        &sp(&dir.join("build.toml")),
        "-o",
        &sp(&caf),
        "--dump-manifest",
        &sp(&dump),
    ])?;
    let caf = sp(&caf);
    let bytes = std::fs::read(&caf)?;
    let content_key = crypto::unwrap_artifact(&bytes, &secret)?.context("no content key")?;
    let key = hex::encode(&content_key);
    cli(&["caf-tool", "verify", &caf])?; // public tier
    cli(&["caf-tool", "verify", &caf, "--key", &key])?; // full tier
    cli(&["caf-tool", "inspect", &caf])?; // sealed, public tier only
    cli(&["caf-tool", "inspect", &caf, "--key", &key])?;
    cli(&["caf-tool", "inspect", &caf, "--key", &key, "--json"])?;
    cli(&["caf-tool", "ls", &caf, "--key", &key])?;
    cli(&[
        "caf-tool",
        "verify",
        &caf,
        "--recipient-key",
        &hex::encode(&secret.to_bytes()),
    ])?;
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn cli_keygen_and_new() -> Result<()> {
    let dir = temp_root("cli-misc")?;
    cli(&["caf-tool", "keygen"])?;
    cli(&["caf-tool", "keygen", "--recipient"])?;
    cli(&["caf-tool", "new", "demo", "--dir", &sp(&dir)])?;
    assert!(dir.join("demo/build.toml").exists());
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn cli_verify_trust_store_paths() -> Result<()> {
    use ed25519_dalek::SigningKey;
    let dir = temp_root("cli-trust")?;
    write_signed_config(&dir, &["/data"])?;
    let caf = sp(&build_to_caf(&dir)?);
    let seed: [u8; 32] = hex::decode(&"11".repeat(32))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("seed length"))?;
    let pubkey = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let store = dir.join("trusted.toml");
    std::fs::write(
        &store,
        format!(
            "[keys]\n\"{}\" = \"Test Publisher\"\n",
            payload::chunk_hash(&pubkey)
        ),
    )?;
    cli(&[
        "caf-tool",
        "verify",
        &caf,
        "--trusted-keys",
        &sp(&store),
        "--require-trusted",
    ])?;
    // A store that does not contain the signer fails --require-trusted.
    let empty = dir.join("empty.toml");
    std::fs::write(&empty, "[keys]\n")?;
    assert!(
        cli(&[
            "caf-tool",
            "verify",
            &caf,
            "--trusted-keys",
            &sp(&empty),
            "--require-trusted"
        ])
        .is_err()
    );
    // --require-trusted without a store is a usage error.
    assert!(cli(&["caf-tool", "verify", &caf, "--require-trusted"]).is_err());
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn cli_run_dispatch() -> Result<()> {
    let dir = temp_root("cli-run")?;
    write_config_full(&dir, &["/data"], &wasm_scalar_answer(), "")?;
    std::fs::write(
        dir.join("spatial.wit"),
        "package cf:gis@0.1.0; world spatial-file { export answer: func() -> u32; }",
    )?;
    bind_test_capabilities(&dir, &["cf:answer@1"])?;
    let caf = sp(&build_to_caf(&dir)?);
    cli(&["caf-tool", "run", &caf, "--fn", "answer"])?;
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn content_key_for_combinations() -> Result<()> {
    let dir = temp_root("content-key")?;
    write_config(&dir, &["/data"])?;
    let caf = build_to_caf(&dir)?;
    assert!(crate::content_key_for(&caf, &None, &None)?.is_none());
    let key = Some("00".repeat(32));
    assert!(crate::content_key_for(&caf, &key, &None)?.is_some());
    assert!(crate::content_key_for(&caf, &Some("zz".into()), &None).is_err());
    assert!(crate::content_key_for(&caf, &key, &Some("11".repeat(32))).is_err());
    // A recipient key cannot unwrap an artifact without a keybox.
    assert!(crate::content_key_for(&caf, &None, &Some("11".repeat(32))).is_err());
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn trust_store_rejects_missing_and_malformed_files() -> Result<()> {
    let dir = temp_root("trust-errors")?;
    assert!(crate::TrustStore::load(&dir.join("missing.toml")).is_err());
    std::fs::write(dir.join("bad.toml"), "not [valid")?;
    assert!(crate::TrustStore::load(&dir.join("bad.toml")).is_err());
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn extract_exports_covers_component_model_binaries() -> Result<()> {
    // A real component: encode the scalar module against a WIT world.
    let mut resolve = wit_parser::Resolve::new();
    let pkg = resolve.push_str(
        "answer.wit",
        "package cf:demo@0.1.0; world w { export answer: func() -> u32; }",
    )?;
    let world = resolve.select_world(&[pkg], Some("w"))?;
    let mut core = wasm_scalar_answer();
    wit_component::embed_component_metadata(
        &mut core,
        &resolve,
        world,
        wit_component::StringEncoding::UTF8,
        false,
    )?;
    let component = wit_component::ComponentEncoder::default()
        .module(&core)?
        .encode()?;
    let exports = crate::exports::extract_exports(&component);
    assert!(
        exports
            .iter()
            .any(|e| e.export == "answer" && e.signature == "func"),
        "{exports:?}"
    );
    Ok(())
}
