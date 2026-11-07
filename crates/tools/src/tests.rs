use anyhow::Result;
use std::path::{Path, PathBuf};

use crate::{assemble, config, wizard};
use caf_core::{hex, layout, manifest, payload, verify};

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
    write_config_full(dir, access, b"\0asm\x01\0\0\0", &extra)
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
        "name = \"city\"\nversion = \"0.1.0\"\n\ninterfaces = [\"spatial.wit\"]\n\n[payload]\nroot = \"payload\"\nmedia_type = \"application/x-spatial\"\n\n[[components]]\nname = \"spatial\"\nworld = \"spatial-file\"\npath = \"spatial.wasm\"\ncapabilities = [\"cf:metadata@1\", \"cf:spatial-query@1\"]\naccess = [{access}]\n{extra}"
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
    std::fs::write(proj.join("demo.wasm"), b"\0asm\x01\0\0\0")?;

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
    let mut exports = vec![0x04];
    exports.extend(b"\x04name\x00\x00");
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
    let bytes = build_bytes(&dir)?;
    verify::verify_bytes(&bytes)?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn scalar_only_exports_need_no_bridge() -> Result<()> {
    let dir = temp_root("abi-scalar")?;
    // `query` is complex in the WIT, but this module exports only `answer`,
    // which is scalar-shaped and unbound — no bridge required.
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.extend(wasm_section(1, &[0x01, 0x60, 0x00, 0x01, 0x7f]));
    wasm.extend(wasm_section(3, &[0x01, 0x00]));
    let mut exports = vec![0x01];
    exports.extend(b"\x06answer\x00\x00");
    wasm.extend(wasm_section(7, &exports));
    wasm.extend(wasm_section(10, &[0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b]));
    write_config_full(&dir, &["/data"], &wasm, "")?;
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
