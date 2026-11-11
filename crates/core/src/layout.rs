//! Binary section layout of a `.caf` container: the fixed bootstrap header and
//! the fixed-width section directory (see `doc/spec/container-format.md` §1).
//!
//! All integers are little-endian and sections are 8-byte aligned. Because the
//! manifest carries no offsets and directory entries are fixed-width, the whole
//! layout is computed in a single forward pass — there is no self-referential
//! layout to converge on.

use anyhow::{Context, Result, bail};

/// File magic at offset 0, identifying a `.caf` artifact.
pub const MAGIC: [u8; 4] = *b"CAF\0";
/// Size of the fixed bootstrap header in bytes.
pub const HEADER_SIZE: u64 = 92;
/// Header flag: the artifact carries an ed25519 signature section.
pub const FLAG_SIGNED: u16 = 0x0001;
/// Header flag: components, payload and the private manifest are encrypted
/// (see `crate::crypto`); the manifest section then holds the public envelope.
pub const FLAG_ENCRYPTED: u16 = 0x0002;
/// Mask of every defined header flag. Readers reject unknown flag bits
/// (fail-closed), so a future flag such as an encryption marker can never be
/// silently ignored by an old reader serving ciphertext as plaintext.
pub const KNOWN_FLAGS: u16 = FLAG_SIGNED | FLAG_ENCRYPTED;

// Directory entry tags (single binary TOC, fixed-width entries).
/// Directory entry tag for a WASM component section.
pub const TAG_COMPONENT: u8 = 0;
/// Directory entry tag for a payload file section.
pub const TAG_PAYLOAD: u8 = 1;
/// Directory entry tag for the manifest section.
pub const TAG_MANIFEST: u8 = 2;
/// Directory entry tag for the signature section.
pub const TAG_SIGNATURE: u8 = 3;
/// Directory entry tag for the keybox section (encrypted artifacts).
pub const TAG_KEYBOX: u8 = 4;
/// Directory entry tag for the encrypted private-manifest section.
pub const TAG_PRIVATE: u8 = 5;
/// Every tag a v1 reader understands; unknown tags are rejected (fail-closed).
pub const KNOWN_TAGS: [u8; 6] = [
    TAG_COMPONENT,
    TAG_PAYLOAD,
    TAG_MANIFEST,
    TAG_SIGNATURE,
    TAG_KEYBOX,
    TAG_PRIVATE,
];

/// Fixed-width directory entry: `tag u8` + `offset u64` + `length u64` + `hash [u8;32]`.
pub const DIRECTORY_ENTRY_SIZE: usize = 1 + 8 + 8 + 32;

/// One section-directory entry: a typed `(offset, length, hash)` pointer into
/// the artifact.
pub struct DirectoryEntry {
    /// Section kind (`TAG_*`).
    pub tag: u8,
    /// Absolute byte offset of the section.
    pub offset: u64,
    /// Byte length of the section.
    pub length: u64,
    /// SHA-256 of the section bytes.
    pub hash: [u8; 32],
}

/// Section layout. All offsets are computed in a single forward pass: the
/// manifest carries no offsets and the directory is fixed-width, so neither
/// section's size depends on the values of the offsets it would contain.
pub struct Layout {
    /// Offset of the manifest section.
    pub manifest_offset: u64,
    /// Byte length of the manifest section.
    pub manifest_len: u64,
    /// Offset of the interface (WIT text) section.
    pub interface_offset: u64,
    /// Byte length of the interface section.
    pub interface_len: u64,
    /// Offset of the section directory.
    pub directory_offset: u64,
    /// Byte length of the section directory.
    pub directory_len: u64,
    /// Offset of the keybox section (sealed artifacts; `0` when absent).
    pub keybox_offset: u64,
    /// Offset of the encrypted private-manifest section (sealed; `0` when absent).
    pub private_offset: u64,
    /// Byte length of the encrypted private-manifest section (sealed; `0` when absent).
    pub private_len: u64,
    /// Offset of each WASM component, in manifest order.
    pub component_offsets: Vec<u64>,
    /// Offset of each payload file, in deterministic DFS order.
    pub file_offsets: Vec<u64>,
    /// Offset of the 96-byte signature section (`0` when unsigned).
    pub signature_offset: u64,
}

/// Compute the full section layout in a single forward pass, 8-byte aligning
/// every section. `signed` reserves room for the signature section at the end;
/// `sealed` reserves the keybox and private-manifest sections (in that order)
/// right after the directory.
pub fn compute(
    manifest_len: u64,
    interface_len: u64,
    directory_len: u64,
    component_lens: &[u64],
    file_lens: &[u64],
    signed: bool,
    sealed: Option<(u64, u64)>,
) -> Layout {
    let mut cursor = align_up(HEADER_SIZE, 8);
    let manifest_offset = cursor;
    cursor = align_up(cursor + manifest_len, 8);
    let interface_offset = cursor;
    cursor = align_up(cursor + interface_len, 8);
    let directory_offset = cursor;
    cursor = align_up(cursor + directory_len, 8);

    let (keybox_offset, private_offset, private_len) = match sealed {
        Some((keybox_len, private_len)) => {
            let keybox_offset = cursor;
            cursor = align_up(cursor + keybox_len, 8);
            let private_offset = cursor;
            cursor = align_up(cursor + private_len, 8);
            (keybox_offset, private_offset, private_len)
        }
        None => (0, 0, 0),
    };

    let mut component_offsets = Vec::with_capacity(component_lens.len());
    for len in component_lens {
        component_offsets.push(cursor);
        cursor = align_up(cursor + len, 8);
    }

    let mut file_offsets = Vec::with_capacity(file_lens.len());
    for len in file_lens {
        file_offsets.push(cursor);
        cursor = align_up(cursor + len, 8);
    }

    let signature_offset = if signed { cursor } else { 0 };

    Layout {
        manifest_offset,
        manifest_len,
        interface_offset,
        interface_len,
        directory_offset,
        directory_len,
        keybox_offset,
        private_offset,
        private_len,
        component_offsets,
        file_offsets,
        signature_offset,
    }
}

/// Round `v` up to the next multiple of `align` (a power of two).
pub fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

/// Serialize the 92-byte bootstrap header: magic, format version, header size,
/// flags, the manifest/interface/directory offsets and lengths, and the
/// artifact root hash.
pub fn write_header(
    out: &mut Vec<u8>,
    layout: &Layout,
    format_version: u32,
    root_hash: &[u8; 32],
    flags: u16,
) {
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&format_version.to_le_bytes());
    out.extend_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&layout.manifest_offset.to_le_bytes());
    out.extend_from_slice(&layout.manifest_len.to_le_bytes());
    out.extend_from_slice(&layout.interface_offset.to_le_bytes());
    out.extend_from_slice(&layout.interface_len.to_le_bytes());
    out.extend_from_slice(&layout.directory_offset.to_le_bytes());
    out.extend_from_slice(&layout.directory_len.to_le_bytes());
    out.extend_from_slice(root_hash);
}

/// Serialize the section directory: a `u32` entry count followed by
/// fixed-width entries.
pub fn encode_directory(entries: &[DirectoryEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + entries.len() * DIRECTORY_ENTRY_SIZE);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        out.push(e.tag);
        out.extend_from_slice(&e.offset.to_le_bytes());
        out.extend_from_slice(&e.length.to_le_bytes());
        out.extend_from_slice(&e.hash);
    }
    out
}

/// Parse a section directory produced by [`encode_directory`], rejecting
/// truncated input and entry counts whose size would overflow.
pub fn decode_directory(bytes: &[u8]) -> Result<Vec<DirectoryEntry>> {
    let count = le_u32(bytes.get(0..4).context("directory too short")?)? as usize;
    let expected = 4usize
        .checked_add(
            count
                .checked_mul(DIRECTORY_ENTRY_SIZE)
                .context("directory size overflow")?,
        )
        .context("directory size overflow")?;
    if bytes.len() < expected {
        bail!(
            "directory truncated: expected {expected} bytes, got {}",
            bytes.len()
        );
    }
    let mut entries = Vec::with_capacity(count);
    let mut pos = 4usize;
    for _ in 0..count {
        let tag = bytes[pos];
        if !KNOWN_TAGS.contains(&tag) {
            bail!("unknown directory entry tag {tag}");
        }
        let offset = le_u64(
            bytes
                .get(pos + 1..pos + 9)
                .context("directory entry truncated")?,
        )?;
        let length = le_u64(
            bytes
                .get(pos + 9..pos + 17)
                .context("directory entry truncated")?,
        )?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(
            bytes
                .get(pos + 17..pos + 49)
                .context("directory entry truncated")?,
        );
        entries.push(DirectoryEntry {
            tag,
            offset,
            length,
            hash,
        });
        pos += DIRECTORY_ENTRY_SIZE;
    }
    Ok(entries)
}

/// The parsed 92-byte bootstrap header.
pub struct Header {
    /// Container format version (must match the manifest's).
    pub format_version: u32,
    /// Header flags (`FLAG_*`).
    pub flags: u16,
    /// Offset of the manifest section.
    pub manifest_offset: u64,
    /// Byte length of the manifest section.
    pub manifest_len: u64,
    /// Offset of the interface (WIT text) section.
    pub interface_offset: u64,
    /// Byte length of the interface section.
    pub interface_len: u64,
    /// Offset of the section directory.
    pub directory_offset: u64,
    /// Byte length of the section directory.
    pub directory_len: u64,
    /// Domain-separated artifact root hash (see [`crate::identity`]).
    pub root_hash: [u8; 32],
}

/// Parse and validate the bootstrap header (magic, declared header size) from
/// the start of the artifact.
pub fn read_header(bytes: &[u8]) -> Result<Header> {
    if bytes.len() < HEADER_SIZE as usize {
        bail!("file too small for a CAF header");
    }
    if bytes.get(0..4) != Some(&MAGIC[..]) {
        bail!("bad magic (not a .caf file)");
    }
    let format_version = le_u32(bytes.get(4..8).context("header truncated")?)?;
    let header_size = le_u16(bytes.get(8..10).context("header truncated")?)?;
    let flags = le_u16(bytes.get(10..12).context("header truncated")?)?;
    if flags & !KNOWN_FLAGS != 0 {
        bail!("unknown header flags 0x{flags:04x} (known mask 0x{KNOWN_FLAGS:04x})");
    }
    // Version admission is fail-closed at the header, before any further
    // parsing (doc/spec/container-format.md §12).
    crate::version::spec(format_version)?;
    if header_size != HEADER_SIZE as u16 {
        bail!("unsupported header size {header_size}");
    }
    let manifest_offset = le_u64(bytes.get(12..20).context("header truncated")?)?;
    let manifest_len = le_u64(bytes.get(20..28).context("header truncated")?)?;
    let interface_offset = le_u64(bytes.get(28..36).context("header truncated")?)?;
    let interface_len = le_u64(bytes.get(36..44).context("header truncated")?)?;
    let directory_offset = le_u64(bytes.get(44..52).context("header truncated")?)?;
    let directory_len = le_u64(bytes.get(52..60).context("header truncated")?)?;
    let mut root_hash = [0u8; 32];
    root_hash.copy_from_slice(bytes.get(60..92).context("header truncated")?);
    Ok(Header {
        format_version,
        flags,
        manifest_offset,
        manifest_len,
        interface_offset,
        interface_len,
        directory_offset,
        directory_len,
        root_hash,
    })
}

/// Read a `[offset, offset+len)` slice, validating bounds.
pub fn slice(bytes: &[u8], offset: u64, len: u64) -> Result<&[u8]> {
    let start = usize::try_from(offset).context("offset out of range")?;
    let end = start
        .checked_add(usize::try_from(len).context("length out of range")?)
        .context("section range overflow")?;
    bytes
        .get(start..end)
        .with_context(|| format!("section [{offset}, {offset}+{len}) out of bounds"))
}

fn le_u16(b: &[u8]) -> Result<u16> {
    let arr: [u8; 2] = b.try_into().context("short u16")?;
    Ok(u16::from_le_bytes(arr))
}

fn le_u32(b: &[u8]) -> Result<u32> {
    let arr: [u8; 4] = b.try_into().context("short u32")?;
    Ok(u32::from_le_bytes(arr))
}

fn le_u64(b: &[u8]) -> Result<u64> {
    let arr: [u8; 8] = b.try_into().context("short u64")?;
    Ok(u64::from_le_bytes(arr))
}
