use anyhow::{Context, Result, bail};

pub const MAGIC: [u8; 4] = *b"CAF\0";
pub const HEADER_SIZE: u64 = 92;
pub const FLAG_SIGNED: u16 = 0x0001;

// Directory entry tags (single binary TOC, fixed-width entries).
pub const TAG_COMPONENT: u8 = 0;
pub const TAG_PAYLOAD: u8 = 1;
pub const TAG_MANIFEST: u8 = 2;
pub const TAG_SIGNATURE: u8 = 3;

/// Fixed-width directory entry: `tag u8` + `offset u64` + `length u64` + `hash [u8;32]`.
pub const DIRECTORY_ENTRY_SIZE: usize = 1 + 8 + 8 + 32;

pub struct DirectoryEntry {
    pub tag: u8,
    pub offset: u64,
    pub length: u64,
    pub hash: [u8; 32],
}

/// Section layout. All offsets are computed in a single forward pass: the
/// manifest carries no offsets and the directory is fixed-width, so neither
/// section's size depends on the values of the offsets it would contain.
pub struct Layout {
    pub manifest_offset: u64,
    pub manifest_len: u64,
    pub interface_offset: u64,
    pub interface_len: u64,
    pub directory_offset: u64,
    pub directory_len: u64,
    pub component_offsets: Vec<u64>,
    pub file_offsets: Vec<u64>,
    pub signature_offset: u64,
}

pub fn compute(
    manifest_len: u64,
    interface_len: u64,
    directory_len: u64,
    component_lens: &[u64],
    file_lens: &[u64],
    signed: bool,
) -> Layout {
    let mut cursor = align_up(HEADER_SIZE, 8);
    let manifest_offset = cursor;
    cursor = align_up(cursor + manifest_len, 8);
    let interface_offset = cursor;
    cursor = align_up(cursor + interface_len, 8);
    let directory_offset = cursor;
    cursor = align_up(cursor + directory_len, 8);

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
        component_offsets,
        file_offsets,
        signature_offset,
    }
}

pub fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

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

pub struct Header {
    pub format_version: u32,
    pub flags: u16,
    pub manifest_offset: u64,
    pub manifest_len: u64,
    pub interface_offset: u64,
    pub interface_len: u64,
    pub directory_offset: u64,
    pub directory_len: u64,
    pub root_hash: [u8; 32],
}

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
