use anyhow::Result;
use std::path::{Path, PathBuf};

use crate::{assemble, config, layout};

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
    let access = access
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let toml = format!(
        "name = \"city\"\nversion = \"0.1.0\"\n\ninterfaces = [\"spatial.wit\"]\n\n[payload]\nroot = \"payload\"\nmedia_type = \"application/x-spatial\"\n\n[[components]]\nname = \"spatial\"\nworld = \"spatial-file\"\npath = \"spatial.wasm\"\ncapabilities = [\"cf:metadata@1\", \"cf:spatial-query@1\"]\naccess = [{access}]\n"
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

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(buf)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(buf)
}

#[test]
fn builds_a_caf_file() -> Result<()> {
    let dir = temp_root("build")?;
    write_config(&dir, &["/data", "/index"])?;

    let (cfg, base) = config::load(&dir.join("build.toml"))?;
    let built = assemble::assemble(&cfg, &base)?;

    let bytes = &built.bytes;
    assert_eq!(&bytes[0..4], b"CAF\0");
    assert_eq!(read_u32(bytes, 4), 1);
    assert_eq!(read_u64(bytes, 8) as u16, layout::HEADER_SIZE as u16);

    let manifest_offset = read_u64(bytes, 12);
    let manifest_len = read_u64(bytes, 20);
    let interface_offset = read_u64(bytes, 28);
    let interface_len = read_u64(bytes, 36);
    let directory_offset = read_u64(bytes, 44);
    let directory_len = read_u64(bytes, 52);

    assert_eq!(manifest_offset, 96);
    assert!(manifest_len > 0);
    assert!(interface_len > 0);
    assert!(directory_len > 0);
    assert!(interface_offset >= manifest_offset + manifest_len);
    assert!(directory_offset >= interface_offset + interface_len);

    let root_hash = &bytes[60..92];
    assert!(root_hash.iter().any(|b| *b != 0));

    assert_eq!(built.manifest.components.len(), 1);
    assert_eq!(built.manifest.components[0].access.len(), 2);
    assert!(bytes.len() > 92);

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn rejects_unknown_access_scope() -> Result<()> {
    let dir = temp_root("bad-access")?;
    write_config(&dir, &["/data", "/nope"])?;

    let (cfg, base) = config::load(&dir.join("build.toml"))?;
    let result = assemble::assemble(&cfg, &base);

    assert!(result.is_err());

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
