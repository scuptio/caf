# Versioning & Upgrade Guide

How CAF format versions are organized, when a change requires a version bump,
and the exact procedure for cutting a new one. The machine-readable registry
lives in `crates/core/src/version/`; this document is the human procedure
around it.

## 1. Version axes

CAF has four version axes. Only the first two are format versions maintained
in `crates/core/src/version/` and `caf-tool`:

| Axis | Carried in | Bumped when |
|---|---|---|
| Container `format_version` | header + manifest/envelope | anything an old reader reject (§2) |
| `export_version` (ZIP profile) | `export.json` | the ZIP inventory or its rules change |
| Artifact version (`manifest.version`) | manifest | publisher's own semver, per artifact |
| Capability / WIT versions (`cf:name@1`) | manifest, WIT | interface semantics change |

Do **not** fold the last two into format versioning — they are user-space
contracts, not reader contracts.

## 2. When a `format_version` bump is required

Readers are fail-closed: unknown header flags, directory tags, manifest
fields, and versions are hard errors. Therefore any of these is a **major**
change requiring a new `format_version`:

- a new header flag, directory tag, or manifest/envelope field;
- a new crypto-suite member (AEAD, key-wrap, padding profile) or KDF domain;
- a layout change (alignment, header size, section order) or chunk-size
  change — both alter byte identity;
- a root-hash domain change (identity redefinition).

Conversely: a change no reader can observe (an implementation detail, a
stricter *writer* rule) needs no bump.

## 3. Layout: one folder per version

```text
crates/core/src/version/
├── mod.rs        # registry: SUPPORTED, CURRENT, spec(), migration machinery
└── vN/
    ├── spec.rs     # FormatSpec: parameters this version pins down
    ├── schema.rs   # frozen manifest/envelope schemas of this version
    └── migrate.rs  # (v2 and later) pure steps from vN-1 into vN
```

Ownership rules:

- A version folder owns everything needed to *read* that version. Once
  released, it never changes — a post-release edit to `vN/` is a review red
  flag.
- The *live* schema types in `crates/core/src/manifest.rs` are always the
  **current** version. Old schemas exist only as frozen snapshots inside
  `version/vN/schema.rs`.
- The newest version knows its predecessor: the `vN-1 → vN` migration lives
  in `vN/migrate.rs`.

## 4. Cutting a new version (v1 → v2 worked example)

1. **Freeze the old schema.** Copy the v1 schema definitions from
   `manifest.rs` into `version/v1/schema.rs`, replacing the aliases, and
   repoint `VersionedManifest::V1`/`VersionedEnvelope::V1` at them.
2. **Evolve the live schema.** Make the change in `manifest.rs` (it now
   describes v2). Set its `format_version` to 2.
3. **Create `version/v2/`.** `spec.rs` holds v2's `FormatSpec` (copy v1's,
   change what changed); `schema.rs` aliases the live types while v2 is
   current.
4. **Write the migration.** `v2/migrate.rs` exposes
   `fn migrate_manifest_v1_v2(VersionedManifest) -> Result<VersionedManifest>`
   (and the envelope twin). Register both in `MANIFEST_MIGRATIONS` /
   `ENVELOPE_MIGRATIONS` in `version/mod.rs`.
5. **Register the version.** `SUPPORTED = &[v1::SPEC, v2::SPEC]`;
   `CURRENT = &v2::SPEC`.
6. **Test.** Golden v1 fixtures must still read and migrate; the build writes
   v2; `verify` accepts both, rejects v3.

Old builds reject v2 artifacts at the header — the fail-closed contract from
`container-format.md` §12 is what makes this safe.

## 5. Writing a migration function

A migration step `f(v-1) -> v` is a **pure, total-or-loud function**:

- no IO, no clock, no randomness — same input, same output, forever;
- data that cannot be carried forward is a hard error, never silently
  dropped;
- steps are adjacent (`from + 1 == to`); the machinery composes
  `f(1) ∘ f(2) ∘ …` automatically and rejects gaps;
- it operates on the *logical* representation. Stored bytes are never
  rewritten: migration is a read-path view, so the artifact's root hash and
  signatures keep their meaning. "Upgrading" an artifact's identity is an
  explicit rebuild (`caf-tool build` / round-trip via `export` + `import`),
  never a side effect of reading.

## 6. The ZIP export profile (`export_version`)

`export.json` versions independently (`EXPORT_FORMAT_MIN` /
`EXPORT_FORMAT_CURRENT` in `crates/tools/src/export.rs`):

- bump when the ZIP inventory or its rules change (new entry kinds, new
  fields import relies on);
- `import` accepts the inclusive range `MIN..=CURRENT`; drop old versions only
  deliberately;
- an export profile implicitly covers specific container versions — record
  that in `export.json`'s `format_version` field (done since v2) and keep
  `import` cross-checking it.

## 7. Testing obligations per version

- **Golden fixtures**: keep a minimal artifact per supported version under
  test fixtures; reading it must succeed and migrate to the current schema
  with the expected field values.
- **Chain composition**: with two or more registered steps, test that a v1
  input composes through every intermediate step (the machinery rejects
  missing or skipping steps; see `version/mod.rs` tests).
- **Writer identity**: `build` emits exactly `CURRENT`; a build requesting an
  unsupported `format_version` fails.
- **Admission**: an artifact declaring an unknown version is rejected at the
  header before any further parsing.

## 8. Non-goals

No downgrades (readers never write old versions), no in-place rewriting of
stored artifacts, and no auto-migration of signatures — identity is immutable
by design (see `round-trip.md` §1).
