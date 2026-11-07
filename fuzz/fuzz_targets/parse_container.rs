#![no_main]

use libfuzzer_sys::fuzz_target;

// Header/directory parsing and section slicing must be panic-free on
// arbitrary bytes.
fuzz_target!(|data: &[u8]| {
    if let Ok(header) = caf_core::layout::read_header(data) {
        let _ = caf_core::layout::slice(data, header.manifest_offset, header.manifest_len);
        let _ = caf_core::layout::slice(data, header.interface_offset, header.interface_len);
        if let Ok(dir) = caf_core::layout::slice(data, header.directory_offset, header.directory_len)
        {
            let _ = caf_core::layout::decode_directory(dir);
        }
    }
});
