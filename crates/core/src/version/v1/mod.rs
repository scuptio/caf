//! Container format version 1. A version folder owns everything needed to
//! read that version: its parameters (`spec`), its frozen schemas (`schema`),
//! and — for v2 and later — the migration from its predecessor (`migrate`).
//! Once released, a version folder never changes.
pub mod schema;
mod spec;

pub use spec::SPEC;
