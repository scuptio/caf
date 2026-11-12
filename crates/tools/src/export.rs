//! Transactional, deterministic ZIP export of a CAF's stored contents.
use anyhow::{Context, Result, bail, ensure};
use caf_core::{crypto, hex, layout, manifest, payload, version};
use caf_runtime::{ArtifactContents, FileSource, PayloadSource};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, io::Write, path::Path, sync::Arc};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

const BLOCK: u64 = manifest::CHUNK_SIZE as u64;

/// export.json schema version written by this build (`doc/spec/en/round-trip.md` §3).
/// v3: multi-payload inventory (`payloads/<name>/`), indexed interfaces
/// (`interfaces.cbor` + `interfaces/<name>`), signature list
/// (`signatures.cbor`).
pub const EXPORT_FORMAT_CURRENT: u64 = 3;
/// Oldest export.json schema version `import` accepts.
pub const EXPORT_FORMAT_MIN: u64 = 3;

/// ZIP compression mode for `export`: `deflate` (default) or `stored`
/// (uncompressed; removes the deflate implementation from the set of inputs
/// the ZIP bytes depend on — see `doc/spec/en/round-trip.md` §3).
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Compression {
    /// Deflate-compressed entries (default; smaller archives).
    Deflate,
    /// Uncompressed entries; ZIP bytes then depend only on the pinned zip
    /// writer, not on a deflate implementation.
    Stored,
}

impl Compression {
    fn method(self) -> CompressionMethod {
        match self {
            Self::Deflate => CompressionMethod::Deflated,
            Self::Stored => CompressionMethod::Stored,
        }
    }
}

/// Export a CAF's stored contents to the ZIP at `output`
/// (`doc/spec/en/round-trip.md` §3). `force` replaces an existing output; sealed
/// artifacts require `key` or `recipient`, and the ZIP then holds plaintext.
pub fn export(
    input: &Path,
    output: &Path,
    force: bool,
    key: Option<&str>,
    recipient: Option<&str>,
    compression: Compression,
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
        let manifest = artifact.manifest();
        let root_hashes: Vec<String> = manifest
            .payloads
            .iter()
            .map(|p| p.root.hash.clone())
            .collect();
        ensure!(
            manifest.hashes.payload == root_hashes,
            "payload root hash mismatch"
        );
        let files = artifact.payload_entries();
        let stored: Vec<_> = entries
            .iter()
            .filter(|e| e.tag == layout::TAG_PAYLOAD)
            .collect();
        ensure!(files.len() == stored.len(), "payload file count mismatch");
        for ((_, _, hash, len), entry) in files.iter().zip(stored) {
            ensure!(
                *len == entry.length && hex::decode(hash)? == entry.hash,
                "payload directory mismatch"
            );
        }
    }

    // Validate the trees before constructing paths: a slash in a node name
    // must never be mistaken for a legitimate nested directory.
    let mut payload_nodes = Vec::with_capacity(artifact.manifest().payloads.len());
    for payload_ref in &artifact.manifest().payloads {
        let mut paths = HashSet::new();
        let mut nodes = Vec::new();
        collect_nodes(&payload_ref.root, "", true, &mut paths, &mut nodes)?;
        nodes.sort_by(|a, b| a.0.cmp(&b.0));
        payload_nodes.push((payload_ref.name.clone(), nodes));
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    let mut zip = ZipWriter::new(temp.as_file_mut());
    let manifest_bytes = source.read_at(header.manifest_offset, header.manifest_len)?;
    add(&mut zip, "manifest.cbor", &manifest_bytes, compression)?;
    let json = if sealed {
        let envelope = version::load_envelope(&manifest_bytes, header.format_version)?;
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
        add(
            &mut zip,
            "private-manifest.cbor",
            &private_bytes,
            compression,
        )?;
        add(
            &mut zip,
            "private-manifest.json",
            &serde_json::to_vec_pretty(&private)?,
            compression,
        )?;
        serde_json::to_vec_pretty(&envelope)?
    } else {
        serde_json::to_vec_pretty(artifact.manifest())?
    };
    add(&mut zip, "manifest.json", &json, compression)?;
    // Interfaces: the raw CBOR section (authoritative for import) plus each
    // WIT source under its original name (for reading).
    let interface_bytes = source.read_at(header.interface_offset, header.interface_len)?;
    if !interface_bytes.is_empty() {
        add(&mut zip, "interfaces.cbor", &interface_bytes, compression)?;
        let files: Vec<manifest::InterfaceFile> =
            ciborium::de::from_reader(interface_bytes.as_slice())
                .context("decode interface section")?;
        for file in &files {
            add(
                &mut zip,
                &format!("interfaces/{}", file.name),
                file.text.as_bytes(),
                compression,
            )?;
        }
    }
    let mut components = Vec::new();
    for (index, component) in artifact.manifest().components.iter().enumerate() {
        let path = format!("components/{index:04}.wasm");
        let bytes = artifact.wasm_bytes(index)?;
        add(&mut zip, &path, &bytes, compression)?;
        components.push(serde_json::json!({"name": component.name, "path": path}));
    }
    zip.add_directory("payloads/", options(0, compression).unix_permissions(0o755))?;
    for (payload_index, (payload_name, nodes)) in payload_nodes.iter().enumerate() {
        zip.add_directory(
            format!("payloads/{payload_name}/"),
            options(0, compression).unix_permissions(0o755),
        )?;
        for (path, node) in nodes {
            let target = format!("payloads/{payload_name}/{path}");
            if node.kind == manifest::EntryKind::Dir {
                zip.add_directory(
                    format!("{target}/"),
                    options(0, compression).unix_permissions(0o755),
                )?;
            } else {
                zip.start_file(target, options(node.length, compression))?;
                // The mounted path the runtime resolves this file under.
                let mounted = if payload_index == 0 {
                    format!("/{path}")
                } else {
                    format!("/{payload_name}/{path}")
                };
                let mut hashes = Vec::new();
                let mut pos = 0;
                while pos < node.length {
                    let len = BLOCK.min(node.length - pos);
                    let (bytes, _) = artifact.read_payload_range(&mounted, pos, len)?;
                    ensure!(bytes.len() as u64 == len, "short payload read");
                    hashes.push(payload::chunk_hash(&bytes));
                    zip.write_all(&bytes)?;
                    pos += len;
                }
                // Also validate the plaintext file root for sealed artifacts
                // and empty files, which do not trigger a runtime read.
                ensure!(
                    payload::merkle_root(&hashes)? == node.hash,
                    "payload '{path}' hash mismatch"
                );
            }
        }
    }
    for entry in entries
        .iter()
        .filter(|e| matches!(e.tag, layout::TAG_SIGNATURE | layout::TAG_KEYBOX))
    {
        let name = if entry.tag == layout::TAG_SIGNATURE {
            "signatures.cbor"
        } else {
            "keybox.bin"
        };
        add(
            &mut zip,
            name,
            &source.read_at(entry.offset, entry.length)?,
            compression,
        )?;
    }
    add(
        &mut zip,
        "export.json",
        &serde_json::to_vec_pretty(&serde_json::json!({
            "export_version": EXPORT_FORMAT_CURRENT,
            "root_hash": artifact.root_hash(),
            "source_encrypted": sealed,
            "format_version": header.format_version,
            "signed": header.flags & layout::FLAG_SIGNED != 0,
            "components": components,
            "manifest": if sealed { "public-envelope" } else { "manifest" },
            "signature_scope": "original-caf-root-hash"
        }))?,
        compression,
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

fn options(length: u64, compression: Compression) -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(compression.method())
        .last_modified_time(zip::DateTime::default())
        .unix_permissions(0o644)
        // Reserve ZIP64 early enough for incompressible input whose deflate
        // stream could be slightly larger than the original file.
        .large_file(length >= u32::MAX as u64 / 2)
}

fn add<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    name: &str,
    bytes: &[u8],
    compression: Compression,
) -> Result<()> {
    zip.start_file(name, options(bytes.len() as u64, compression))?;
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
