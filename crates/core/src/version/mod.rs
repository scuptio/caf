//! Central registry of container format versions: the single place that
//! defines what each `format_version` pins down, which versions this build
//! supports, and how older schemas migrate to the current one
//! (`doc/spec/en/container-format.md` §12).
//!
//! Two levels live here:
//!
//! - **Parameters** ([`FormatSpec`]): the layout constants, identity domain
//!   and crypto suite a version implies. Readers resolve them through
//!   [`spec`], which is fail-closed on unknown versions.
//! - **Schemas** ([`VersionedSchema`] + the migration chains): each released
//!   version's manifest/envelope schema is frozen; reading parses at the
//!   declared version and migrates stepwise through pure functions
//!   `f(v - 1) -> v`. Stored bytes are never rewritten — migration is a
//!   read-path view, so root hashes and signatures keep their meaning.
//!
//! ## Layout: one folder per version
//!
//! `vN/` owns everything needed to read that version: `spec.rs` (its
//! [`FormatSpec`]), `schema.rs` (its frozen schemas), and — for v2 and later —
//! `migrate.rs` (the pure steps from vN−1). A version folder never changes
//! once released; review flags any post-release edit.
//!
//! The maintainer procedure for cutting a new version — when a bump is
//! required, the exact steps, migration-function rules, and testing
//! obligations — is `doc/spec/en/versioning.md`.

use anyhow::{Context, Result, bail, ensure};

use crate::manifest;

pub mod v1;

/// Format version 1's parameters.
pub use v1::SPEC as V1;

/// The crypto suite a sealed artifact of a given format version must use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoSuite {
    /// AEAD algorithm for sealed sections.
    pub aead: manifest::AeadAlgorithm,
    /// Key-wrap algorithm for keybox stanzas.
    pub wrap: manifest::KeyWrapAlgorithm,
    /// Payload length-hiding padding profile.
    pub padding: manifest::PaddingProfile,
}

/// Everything a container `format_version` pins down. Adding a version means
/// a new `vN/` folder — never editing a released one.
pub struct FormatSpec {
    /// The version identifier stored in the header and manifest.
    pub version: u32,
    /// Fixed bootstrap header size in bytes.
    pub header_size: u64,
    /// Section alignment in bytes.
    pub align: u64,
    /// Payload chunk size in bytes (feeds Merkle identities).
    pub chunk_size: usize,
    /// Root-hash domain separator.
    pub root_domain: &'static [u8],
    /// Header flags a reader of this version understands.
    pub known_flags: u16,
    /// Directory tags a reader of this version understands.
    pub known_tags: &'static [u8],
    /// Crypto suite for sealed artifacts.
    pub crypto: CryptoSuite,
}

/// Every format version this build can read.
pub const SUPPORTED: &[FormatSpec] = &[v1::SPEC];

/// The format version this build writes.
pub const CURRENT: &FormatSpec = &v1::SPEC;

/// Resolve a declared format version; unknown versions are a hard error
/// (fail-closed, per `container-format.md` §12).
pub fn spec(version: u32) -> Result<&'static FormatSpec> {
    SUPPORTED
        .iter()
        .find(|s| s.version == version)
        .with_context(|| format!("unsupported format version {version}"))
}

/// The header and the manifest/envelope must declare the same format version.
pub fn ensure_consistent(header: u32, section: u32, what: &str) -> Result<()> {
    ensure!(
        header == section,
        "format version mismatch: header {header}, {what} {section}"
    );
    Ok(())
}

/// A parsed manifest/envelope at its declared schema version. Released
/// schemas are frozen: evolution means a new variant plus a [`Migration`].
pub trait VersionedSchema: Sized {
    /// The current-schema type this migrates into.
    type Current;
    /// Structural version of this variant (not data read from the bytes).
    fn variant_version(&self) -> u32;
    /// The current-schema view (identity for the latest variant).
    fn into_current(self) -> Self::Current;
}

/// One pure migration step `f(v - 1) -> v`: no IO, no clock, no randomness.
/// Data that cannot be carried forward is a hard error, never silently
/// dropped. The functions live in the target version's `vN/migrate.rs`.
pub struct Migration<M: VersionedSchema> {
    /// Source schema version.
    pub from: u32,
    /// Target schema version (must equal `from + 1`).
    pub to: u32,
    /// What changed; doubles as changelog material.
    pub description: &'static str,
    /// The migration function.
    pub migrate: fn(M) -> Result<M>,
}

/// Compose the registered steps from `value`'s version up to `target`.
pub fn migrate_to<M: VersionedSchema>(
    mut value: M,
    target: u32,
    migrations: &[Migration<M>],
) -> Result<M::Current> {
    while value.variant_version() != target {
        let from = value.variant_version();
        let step = migrations
            .iter()
            .find(|s| s.from == from)
            .with_context(|| format!("no migration path from format v{from}"))?;
        ensure!(
            step.to == from + 1,
            "migration v{} -> v{} skips a version",
            step.from,
            step.to
        );
        value = (step.migrate)(value)?;
    }
    Ok(value.into_current())
}

/// Compose the registered steps from `value`'s version up to [`CURRENT`].
pub fn migrate_to_current<M: VersionedSchema>(
    value: M,
    migrations: &[Migration<M>],
) -> Result<M::Current> {
    migrate_to(value, CURRENT.version, migrations)
}

/// The manifest as declared by each format version. Once a version ships its
/// variant is frozen; new fields land in a new variant plus one migration.
pub enum VersionedManifest {
    /// Format v1.
    V1(v1::schema::Manifest),
}

impl VersionedSchema for VersionedManifest {
    type Current = manifest::Manifest;
    fn variant_version(&self) -> u32 {
        match self {
            Self::V1(_) => V1.version,
        }
    }
    fn into_current(self) -> manifest::Manifest {
        match self {
            Self::V1(m) => m,
        }
    }
}

/// The public envelope of a sealed artifact, as declared by each version.
pub enum VersionedEnvelope {
    /// Format v1.
    V1(v1::schema::Envelope),
}

impl VersionedSchema for VersionedEnvelope {
    type Current = manifest::Envelope;
    fn variant_version(&self) -> u32 {
        match self {
            Self::V1(_) => V1.version,
        }
    }
    fn into_current(self) -> manifest::Envelope {
        match self {
            Self::V1(e) => e,
        }
    }
}

/// Registered manifest migrations. Empty while v1 is current; the v1 -> v2
/// step lands here (function in `v2/migrate.rs`) when v2 ships.
pub const MANIFEST_MIGRATIONS: &[Migration<VersionedManifest>] = &[];

/// Registered envelope migrations (see [`MANIFEST_MIGRATIONS`]).
pub const ENVELOPE_MIGRATIONS: &[Migration<VersionedEnvelope>] = &[];

/// Parse `bytes` as the manifest schema of `version`, check it agrees with
/// the declared version, and migrate stepwise to the current schema.
pub fn load_manifest(bytes: &[u8], version: u32) -> Result<manifest::Manifest> {
    spec(version)?;
    let parsed = match version {
        1 => VersionedManifest::V1(ciborium::de::from_reader(bytes).context("decode manifest")?),
        v => bail!("unsupported format version {v}"),
    };
    let declared = match &parsed {
        VersionedManifest::V1(m) => m.format_version,
    };
    ensure_consistent(version, declared, "manifest")?;
    migrate_to_current(parsed, MANIFEST_MIGRATIONS)
}

/// [`load_manifest`] for the public envelope of a sealed artifact. The
/// private manifest inherits the envelope's version.
pub fn load_envelope(bytes: &[u8], version: u32) -> Result<manifest::Envelope> {
    spec(version)?;
    let parsed = match version {
        1 => VersionedEnvelope::V1(ciborium::de::from_reader(bytes).context("decode envelope")?),
        v => bail!("unsupported format version {v}"),
    };
    let declared = match &parsed {
        VersionedEnvelope::V1(e) => e.format_version,
    };
    ensure_consistent(version, declared, "envelope")?;
    migrate_to_current(parsed, ENVELOPE_MIGRATIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_is_fail_closed() -> Result<()> {
        assert_eq!(spec(1)?.version, 1);
        assert!(spec(0).is_err());
        assert!(spec(2).is_err());
        Ok(())
    }

    // Migration chain mechanics over a toy schema. The real chains are empty
    // while v1 is current, so the machinery is exercised here.
    struct Toy(u32, String);

    impl VersionedSchema for Toy {
        type Current = (u32, String);
        fn variant_version(&self) -> u32 {
            self.0
        }
        fn into_current(self) -> (u32, String) {
            (self.0, self.1)
        }
    }

    fn up_1_2(mut t: Toy) -> Result<Toy> {
        t.0 = 2;
        t.1.push('b');
        Ok(t)
    }

    fn up_2_3(mut t: Toy) -> Result<Toy> {
        t.0 = 3;
        t.1.push('c');
        Ok(t)
    }

    #[test]
    fn migrations_compose_stepwise() -> Result<()> {
        let chain = [
            Migration {
                from: 1,
                to: 2,
                description: "add b",
                migrate: up_1_2,
            },
            Migration {
                from: 2,
                to: 3,
                description: "add c",
                migrate: up_2_3,
            },
        ];
        assert_eq!(
            migrate_to(Toy(1, "a".into()), 3, &chain)?,
            (3, "abc".into())
        );
        // Already current: no step runs.
        assert_eq!(migrate_to(Toy(3, "z".into()), 3, &chain)?, (3, "z".into()));
        Ok(())
    }

    #[test]
    fn missing_or_skipping_step_is_a_hard_error() {
        let gap = [Migration {
            from: 2,
            to: 3,
            description: "add c",
            migrate: up_2_3,
        }];
        let err = migrate_to(Toy(1, "a".into()), 3, &gap).unwrap_err();
        assert!(format!("{err:#}").contains("no migration path"), "{err:#}");

        let skip = [Migration {
            from: 1,
            to: 3,
            description: "skip",
            migrate: up_2_3,
        }];
        let err = migrate_to(Toy(1, "a".into()), 3, &skip).unwrap_err();
        assert!(format!("{err:#}").contains("skips a version"), "{err:#}");
    }
}
