//! Shared CAF container parsing and verification, used by both the build tool
//! (`caf-tool`) and the host runtime (`caf-runtime`).

pub mod crypto;
pub mod hex;
pub mod identity;
pub mod layout;
pub mod manifest;
pub mod payload;
pub mod verify;
