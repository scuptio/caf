//! Transactional, deterministic ZIP export of a CAF's stored contents.
use anyhow::{Context, Result, bail, ensure};
use caf_core::{crypto, hex, layout, manifest, payload};
use caf_runtime::{ArtifactContents, FileSource, PayloadSource};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, io::Write, path::Path, sync::Arc};
use zip::{ZipWriter, write::SimpleFileOptions};

const BLOCK: u64 = manifest::CHUNK_SIZE as u64;

pub fn export(
    input: &Path,
    output: &Path,
    force: bool,
    key: Option<&str>,
    recipient: Option<&str>,
) -> Result<()> {
    ensure!(
        !(key.is_some() && recipient.is_some()),
        "--key and --recipient-key are mutually exclusive"
    );
    if let Ok(target) = output.canonicalize() {
        ensure!(
            target != input.canonicalize()?,
            "output must differ from the input CAF"
        );
    }
    ensure!(
        force || !output.try_exists()?,
        "output exists; use --force to replace it"
    );
    let source: Arc<dyn PayloadSource> = Arc::new(FileSource::open(input)?);
    let header = layout::read_header(&source.read_at(0, layout::HEADER_SIZE)?)?;
    let entries =
        layout::decode_directory(&source.read_at(header.directory_offset, header.directory_len)?)?;
    let sealed = header.flags & layout::FLAG_ENCRYPTED != 0;
    let content_key = match (key, recipient) {
        (Some(key), _) => Some(decode_key(key)?),
        (_, Some(secret)) => {
            let entry = entries
                .iter()
                .find(|e| e.tag == layout::TAG_KEYBOX)
                .context("artifact has no keybox")?;
            Some(
                crypto::unwrap_keybox(
                    &source.read_at(entry.offset, entry.length)?,
                    &crypto::parse_recipient_secret(secret)?,
                )
                .context("no keybox stanza matches this recipient key")?,
            )
        }
        _ => None,
    };
    ensure!(
        !sealed || content_key.is_some(),
        "sealed export requires --key or --recipient-key; exported ZIP contains plaintext"
    );
    let artifact = ArtifactContents::open(source.clone(), content_key.as_ref())?;

    // Check all stored ciphertext, including padding which is not exposed as
    // a payload file. Plain payload directory hashes are Merkle roots rather
    // than ordinary SHA-256; their entries are checked separately below.
    for entry in &entries {
        ensure!(
            entry.offset <= source.total_len() && entry.length <= source.total_len() - entry.offset,
            "section out of bounds"
        );
        if entry.tag == layout::TAG_SIGNATURE || (!sealed && entry.tag == layout::TAG_PAYLOAD) {
            continue;
        }
        let mut hash = Sha256::new();
        let mut pos = 0;
        while pos < entry.length {
            let len = BLOCK.min(entry.length - pos);
            hash.update(source.read_at(entry.offset + pos, len)?);
            pos += len;
        }
        ensure!(
            hash.finalize().as_slice() == entry.hash,
            "section hash mismatch"
        );
    }
    if !sealed {
        ensure!(
            artifact.manifest().hashes.payload
                == [artifact.manifest().payloads[0].root.hash.clone()],
            "payload root hash mismatch"
        );
        let files = artifact.payload_entries();
        let stored: Vec<_> = entries
            .iter()
            .filter(|e| e.tag == layout::TAG_PAYLOAD)
            .collect();
        ensure!(files.len() == stored.len(), "payload file count mismatch");
        for ((_, hash, len), entry) in files.iter().zip(stored) {
            ensure!(
                *len == entry.length && hex::decode(hash)? == entry.hash,
                "payload directory mismatch"
            );
        }
    }

    // Validate the tree before constructing paths: a slash in a node name
    // must never be mistaken for a legitimate nested directory.
    let mut paths = HashSet::new();
    let mut nodes = Vec::new();
    collect_nodes(
        &artifact.manifest().payloads[0].root,
        "",
        true,
        &mut paths,
        &mut nodes,
    )?;
    nodes.sort_by(|a, b| a.0.cmp(&b.0));
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    let mut zip = ZipWriter::new(temp.as_file_mut());
    let manifest_bytes = source.read_at(header.manifest_offset, header.manifest_len)?;
    add(&mut zip, "manifest.cbor", &manifest_bytes)?;
    let json = if sealed {
        let envelope: manifest::Envelope = ciborium::de::from_reader(manifest_bytes.as_slice())?;
        let entry = entries
            .iter()
            .find(|e| e.tag == layout::TAG_PRIVATE)
            .context("missing private manifest")?;
        let private_bytes = crypto::open_chunk(
            &crypto::section_key(content_key.as_ref().context("missing key")?, "private"),
            0,
            &source.read_at(entry.offset, entry.length)?,
        )?;
        let private: manifest::PrivateManifest =
            ciborium::de::from_reader(private_bytes.as_slice())?;
        add(&mut zip, "private-manifest.cbor", &private_bytes)?;
        add(
            &mut zip,
            "private-manifest.json",
            &serde_json::to_vec_pretty(&private)?,
        )?;
        serde_json::to_vec_pretty(&envelope)?
    } else {
        serde_json::to_vec_pretty(artifact.manifest())?
    };
    add(&mut zip, "manifest.json", &json)?;
    add(
        &mut zip,
        "interfaces/interface.wit",
        &source.read_at(header.interface_offset, header.interface_len)?,
    )?;
    let mut components = Vec::new();
    for (index, component) in artifact.manifest().components.iter().enumerate() {
        let path = format!("components/{index:04}.wasm");
        let bytes = artifact.wasm_bytes(index)?;
        add(&mut zip, &path, &bytes)?;
        components.push(serde_json::json!({"name": component.name, "path": path}));
    }
    zip.add_directory("payload/", options(0).unix_permissions(0o755))?;
    for (path, node) in nodes {
        let target = format!("payload/{path}");
        if node.kind == manifest::EntryKind::Dir {
            zip.add_directory(format!("{target}/"), options(0).unix_permissions(0o755))?;
        } else {
            zip.start_file(target, options(node.length))?;
            let mut hashes = Vec::new();
            let mut pos = 0;
            while pos < node.length {
                let len = BLOCK.min(node.length - pos);
                let (bytes, _) = artifact.read_payload_range(&format!("/{path}"), pos, len)?;
                ensure!(bytes.len() as u64 == len, "short payload read");
                hashes.push(payload::chunk_hash(&bytes));
                zip.write_all(&bytes)?;
                pos += len;
            }
            // Also validate the plaintext file root for sealed artifacts and
            // empty files, which do not necessarily trigger a runtime read.
            ensure!(
                payload::merkle_root(&hashes)? == node.hash,
                "payload '{path}' hash mismatch"
            );
        }
    }
    for entry in entries
        .iter()
        .filter(|e| matches!(e.tag, layout::TAG_SIGNATURE | layout::TAG_KEYBOX))
    {
        let name = if entry.tag == layout::TAG_SIGNATURE {
            "signature.bin"
        } else {
            "keybox.bin"
        };
        add(&mut zip, name, &source.read_at(entry.offset, entry.length)?)?;
    }
    add(
        &mut zip,
        "export.json",
        &serde_json::to_vec_pretty(&serde_json::json!({
            "export_version": 1,
            "root_hash": artifact.root_hash(),
            "source_encrypted": sealed,
            "components": components,
            "manifest": if sealed { "public-envelope" } else { "manifest" },
            "signature_scope": "original-caf-root-hash"
        }))?,
    )?;
    zip.finish()?;
    temp.as_file().sync_all()?;
    if force {
        temp.persist(output).map_err(|e| e.error)?;
    } else {
        temp.persist_noclobber(output).map_err(|e| e.error)?;
    }
    Ok(())
}

fn options(length: u64) -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::default())
        .unix_permissions(0o644)
        // Reserve ZIP64 early enough for incompressible input whose deflate
        // stream could be slightly larger than the original file.
        .large_file(length >= u32::MAX as u64 / 2)
}

fn add<W: Write + std::io::Seek>(zip: &mut ZipWriter<W>, name: &str, bytes: &[u8]) -> Result<()> {
    zip.start_file(name, options(bytes.len() as u64))?;
    zip.write_all(bytes)?;
    Ok(())
}

fn collect_nodes<'a>(
    node: &'a manifest::PayloadNode,
    parent: &str,
    root: bool,
    paths: &mut HashSet<String>,
    out: &mut Vec<(String, &'a manifest::PayloadNode)>,
) -> Result<()> {
    let path = if root {
        ensure!(
            node.name.is_empty() && node.kind == manifest::EntryKind::Dir,
            "invalid payload root"
        );
        String::new()
    } else {
        let name = &node.name;
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains(['/', '\\', ':'])
            || name.chars().any(char::is_control)
            || name.ends_with(['.', ' '])
        {
            bail!("unsafe ZIP path component: {name:?}");
        }
        let path = if parent.is_empty() {
            name.clone()
        } else {
            format!("{parent}/{name}")
        };
        ensure!(
            paths.insert(path.to_lowercase()),
            "duplicate ZIP path: {path}"
        );
        out.push((path.clone(), node));
        path
    };
    ensure!(
        node.kind != manifest::EntryKind::File || node.entries.is_empty(),
        "payload file has children"
    );
    for child in &node.entries {
        collect_nodes(child, &path, false, paths, out)?;
    }
    Ok(())
}

fn decode_key(value: &str) -> Result<[u8; 32]> {
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("content key must be 32 bytes"))
}
