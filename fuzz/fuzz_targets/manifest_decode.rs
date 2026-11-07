#![no_main]

use libfuzzer_sys::fuzz_target;

// The manifest is canonical CBOR decoded into a typed struct; decoding must
// fail cleanly on malformed input.
fuzz_target!(|data: &[u8]| {
    let _: Result<caf_core::manifest::Manifest, _> = ciborium::de::from_reader(data);
});
