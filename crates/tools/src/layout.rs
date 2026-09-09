pub const MAGIC: [u8; 4] = *b"CAF\0";
pub const HEADER_SIZE: u64 = 92;
pub const FLAG_SIGNED: u16 = 0x0001;

pub struct Layout {
    pub manifest_offset: u64,
    pub manifest_len: u64,
    pub interface_offset: u64,
    pub interface_len: u64,
    pub directory_offset: u64,
    pub directory_len: u64,
    pub component_offsets: Vec<u64>,
    pub file_offsets: Vec<u64>,
    pub payload_offset: u64,
    pub payload_len: u64,
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

    let payload_offset = cursor;
    let mut file_offsets = Vec::with_capacity(file_lens.len());
    for len in file_lens {
        file_offsets.push(cursor);
        cursor = align_up(cursor + len, 8);
    }
    let payload_len = cursor - payload_offset;

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
        payload_offset,
        payload_len,
        signature_offset,
    }
}

pub fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

pub fn write_header(out: &mut Vec<u8>, layout: &Layout, format_version: u32, root_hash: &[u8; 32], flags: u16) {
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
