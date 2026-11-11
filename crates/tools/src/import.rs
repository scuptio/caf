//! Byte-identical reconstruction of a plaintext `.caf` from its export ZIP
//! (see `doc/spec/round-trip.md` §4). Every byte is verified against the
//! preserved `manifest.cbor` — the sole ordering authority — and the rebuild
//! is published only after the recomputed root hash matches `export.json` and
//! the reconstructed artifact passes strict verification.
use anyhow::{Context, Result, ensure};
use caf_core::{hex, identity, layout, manifest, payload, verify};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, io::Read, path::Path};
use zip::ZipArchive;

pub fn import(input: &Path, output: &Path, force: bool) -> Result<()> {
    if let Ok(target) = output.canonicalize() {
        ensure!(
            target != input.canonicalize()?,
            "output must differ from the input ZIP"
        );
    }
    ensure!(
        force || !output.try_exists()?,
        "output exists; use --force to replace it"
    );
    let file = std::fs::File::open(input).with_context(|| format!("open {}", input.display()))?;
    let mut zip = ZipArchive::new(file).context("read ZIP archive")?;

    // export.json: format gate and identity anchor, never an ordering source.
    let meta_bytes = read_entry(&mut zip, "export.json")?;
    let meta: serde_json::Value =
        serde_json::from_slice(&meta_bytes).context("parse export.json")?;
    let version = meta["export_version"]
        .as_u64()
        .context("export.json: missing export_version")?;
    ensure!(
        (1..=2).contains(&version),
        "unsupported export_version {version}"
    );
    ensure!(
        meta["source_encrypted"] == false,
        "sealed artifacts cannot be reconstructed from plaintext exports; \
         see doc/spec/round-trip.md §6 for the sealed routes"
    );

    // manifest.cbor: the sole ordering authority (components, payload DFS).
    let manifest_bytes = read_entry(&mut zip, "manifest.cbor")?;
    let manifest: manifest::Manifest =
        ciborium::de::from_reader(manifest_bytes.as_slice()).context("parse manifest.cbor")?;
    if let Some(v) = meta["format_version"].as_u64() {
        ensure!(
            v == manifest.format_version as u64,
            "export.json format_version does not match the manifest"
        );
    }
    let manifest_hash = sha256(&manifest_bytes);

    // Interface section.
    let interface_bytes = read_entry(&mut zip, "interfaces/interface.wit")?;
    ensure!(
        interface_bytes.len() as u64 == manifest.interface.length
            && hex::encode(&sha256(&interface_bytes)) == manifest.interface.hash,
        "interface.wit does not match the manifest"
    );

    // Components, in manifest order.
    let mut component_blobs = Vec::with_capacity(manifest.components.len());
    for (i, comp) in manifest.components.iter().enumerate() {
        let bytes = read_entry(&mut zip, &format!("components/{i:04}.wasm"))?;
        ensure!(
            bytes.len() as u64 == comp.length && hex::encode(&sha256(&bytes)) == comp.hash,
            "component '{}' does not match the manifest",
            comp.name
        );
        if let Some(name) = meta["components"].get(i).and_then(|c| c["name"].as_str()) {
            ensure!(name == comp.name, "export.json component {i} name mismatch");
        }
        component_blobs.push(bytes);
    }

    // Payload files, in manifest DFS order; reject undeclared entries.
    ensure!(
        manifest.payloads.len() == 1,
        "expected exactly one payload, found {}",
        manifest.payloads.len()
    );
    let root = &manifest.payloads[0].root;
    let mut file_list = Vec::new();
    payload::collect_files(root, "", &mut file_list);
    let mut declared = HashSet::with_capacity(file_list.len());
    let mut payload_blobs = Vec::with_capacity(file_list.len());
    for (path, hash, len) in &file_list {
        let zip_path = format!("payload{path}");
        let bytes = read_entry(&mut zip, &zip_path)?;
        ensure!(
            bytes.len() as u64 == *len && payload::verify_file(&bytes)? == *hash,
            "payload '{path}' does not match the manifest"
        );
        declared.insert(zip_path);
        payload_blobs.push(bytes);
    }
    for i in 0..zip.len() {
        let name = zip.by_index(i)?.name().to_string();
        ensure!(
            !name.starts_with("payload/") || name.ends_with('/') || declared.contains(&name),
            "undeclared payload entry in ZIP: {name}"
        );
    }

    // Optional signature section: stored verbatim, directory hash zero.
    let signature = match zip.by_name("signature.bin") {
        Ok(mut entry) => {
            let mut bytes = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut bytes)?;
            ensure!(bytes.len() == 96, "signature.bin must be 96 bytes");
            Some(bytes)
        }
        Err(zip::result::ZipError::FileNotFound) => None,
        Err(e) => return Err(e.into()),
    };
    let signed = signature.is_some();

    // Replay the canonical layout over the verified sections.
    let entry_count = 1 + component_blobs.len() + payload_blobs.len() + usize::from(signed);
    let directory_len = 4 + (entry_count * layout::DIRECTORY_ENTRY_SIZE) as u64;
    let component_lens: Vec<u64> = component_blobs.iter().map(|b| b.len() as u64).collect();
    let file_lens: Vec<u64> = file_list.iter().map(|(_, _, len)| *len).collect();
    let lay = layout::compute(
        manifest_bytes.len() as u64,
        interface_bytes.len() as u64,
        directory_len,
        &component_lens,
        &file_lens,
        signed,
        None,
    );
    let mut entries = Vec::with_capacity(entry_count);
    entries.push(layout::DirectoryEntry {
        tag: layout::TAG_MANIFEST,
        offset: lay.manifest_offset,
        length: manifest_bytes.len() as u64,
        hash: sha256(&manifest_bytes),
    });
    for (i, blob) in component_blobs.iter().enumerate() {
        entries.push(layout::DirectoryEntry {
            tag: layout::TAG_COMPONENT,
            offset: lay.component_offsets[i],
            length: blob.len() as u64,
            hash: sha256(blob),
        });
    }
    for (i, (_, hash, len)) in file_list.iter().enumerate() {
        entries.push(layout::DirectoryEntry {
            tag: layout::TAG_PAYLOAD,
            offset: lay.file_offsets[i],
            length: *len,
            hash: hex::decode(hash)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("payload hash is not 32 bytes"))?,
        });
    }
    if signed {
        entries.push(layout::DirectoryEntry {
            tag: layout::TAG_SIGNATURE,
            offset: lay.signature_offset,
            length: 96,
            hash: [0u8; 32],
        });
    }
    let directory_bytes = layout::encode_directory(&entries);

    // Identity gate: the recomputed root hash must equal the exported one.
    let component_hashes: Vec<String> =
        manifest.components.iter().map(|c| c.hash.clone()).collect();
    let root_hash = identity::root_hash(
        &hex::encode(&manifest_hash),
        &manifest.interface.hash,
        &component_hashes,
        &root.hash,
    )?;
    if let Some(expected) = meta["root_hash"].as_str() {
        ensure!(
            hex::encode(&root_hash) == expected,
            "reconstructed root hash does not match export.json"
        );
    }

    let mut out = Vec::new();
    let flags = if signed { layout::FLAG_SIGNED } else { 0 };
    layout::write_header(&mut out, &lay, manifest.format_version, &root_hash, flags);
    pad_to(&mut out, lay.manifest_offset);
    out.extend_from_slice(&manifest_bytes);
    pad_to(&mut out, lay.interface_offset);
    out.extend_from_slice(&interface_bytes);
    pad_to(&mut out, lay.directory_offset);
    out.extend_from_slice(&directory_bytes);
    for (i, blob) in component_blobs.iter().enumerate() {
        pad_to(&mut out, lay.component_offsets[i]);
        out.extend_from_slice(blob);
    }
    for (i, blob) in payload_blobs.iter().enumerate() {
        pad_to(&mut out, lay.file_offsets[i]);
        out.extend_from_slice(blob);
    }
    if let Some(signature) = &signature {
        pad_to(&mut out, lay.signature_offset);
        out.extend_from_slice(signature);
    }

    // Final oracle: strict verification of the reconstructed bytes, including
    // the signature when present.
    let report =
        verify::verify_bytes(&out).context("reconstructed artifact failed verification")?;
    ensure!(
        !signed || report.signature_valid == Some(true),
        "signature.bin does not verify against the reconstructed artifact"
    );

    // Atomic publish: write beside the destination, fsync, then rename.
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    std::io::Write::write_all(&mut temp, &out)?;
    temp.as_file().sync_all()?;
    if force {
        temp.persist(output).map_err(|e| e.error)?;
    } else {
        temp.persist_noclobber(output).map_err(|e| e.error)?;
    }
    Ok(())
}

fn read_entry(zip: &mut ZipArchive<std::fs::File>, name: &str) -> Result<Vec<u8>> {
    let mut entry = zip
        .by_name(name)
        .with_context(|| format!("ZIP is missing '{name}'"))?;
    let mut bytes = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn pad_to(out: &mut Vec<u8>, offset: u64) {
    let cur = out.len() as u64;
    if cur < offset {
        out.resize(offset as usize, 0);
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}
