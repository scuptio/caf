#![no_main]

use libfuzzer_sys::fuzz_target;

// The full offline verifier must reject malformed bytes with an error, never
// panic: it runs on untrusted input.
fuzz_target!(|data: &[u8]| {
    let _ = caf_core::verify::verify_bytes(data);
});
