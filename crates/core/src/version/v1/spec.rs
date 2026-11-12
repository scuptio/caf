//! Format v1 parameters: the layout, identity and crypto rules documented in
//! `doc/spec/en/container-format.md`.
use super::super::{CryptoSuite, FormatSpec};
use crate::{identity, layout, manifest};

/// Everything container format v1 pins down. Frozen once released; changes
/// land in `v2::SPEC` instead.
pub const SPEC: FormatSpec = FormatSpec {
    version: 1,
    header_size: layout::HEADER_SIZE,
    align: 8,
    chunk_size: manifest::CHUNK_SIZE,
    root_domain: identity::ROOT_DOMAIN,
    known_flags: layout::KNOWN_FLAGS,
    known_tags: &layout::KNOWN_TAGS,
    crypto: CryptoSuite {
        aead: manifest::AeadAlgorithm::Aes256Gcm,
        wrap: manifest::KeyWrapAlgorithm::P256EcdhSha256,
        padding: manifest::PaddingProfile::Pow2,
    },
};
