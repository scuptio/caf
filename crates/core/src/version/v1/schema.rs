//! Format v1 manifest/envelope schemas.
//!
//! While v1 is current, these alias the live types in `crate::manifest`. When
//! v2 ships, the v1 definitions are copied here and frozen, and the live
//! types evolve into the v2 shape (see `version/mod.rs`).

/// The v1 manifest schema (currently the live type).
pub type Manifest = crate::manifest::Manifest;

/// The v1 public envelope schema (currently the live type).
pub type Envelope = crate::manifest::Envelope;
