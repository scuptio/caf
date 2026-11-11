# Deterministic Round-Trip: `project → .caf ⇄ .zip` — Specification

This document is the normative contract for rebuilding a `.caf` artifact
byte-for-byte: from its project sources (reproducible build), and from its
export ZIP (reconstruction). It complements `container-format.md` (the byte
layout) and covers **plaintext artifacts**; sealed reconstruction is specified
as future work in §6.

Terminology: an edge is *byte-deterministic* when repeating it on identical
inputs yields identical bytes; the round-trip is *verified* when the
reconstructed artifact's root hash is recomputed and compared, not trusted.

## 1. Why byte identity is attainable

Three properties of the format make byte-identical reconstruction a matter of
engineering discipline rather than luck:

- The section layout is a pure function of the section lengths: a single
  forward pass with 8-byte alignment (`container-format.md` §1). Offsets are
  never stored in the manifest, so nothing is self-referential.
- The root hash is content identity. Recomputation is a cryptographic oracle:
  a reconstruction is correct **iff** the root hash matches — correctness is
  proven, never assumed.
- Plaintext artifacts have no random inputs: no content key, and ed25519
  (RFC 8032) is a deterministic signature scheme.

## 2. Canonical build (`project → .caf`)

A conforming build is a pure function of `(project files, build.toml, pinned
toolchain)`. The rules:

1. **Sorted enumeration.** Payload entries are ordered by file name at every
   directory level (depth-first); implementations must never leak filesystem
   `readdir` order into the artifact. WIT sources are concatenated in the
   order of `build.toml`'s `interfaces` list. Components follow `build.toml`
   declaration order.
2. **No wall-clock.** Neither the manifest nor any section embeds build
   timestamps. Build metadata must come from explicit config, never the
   environment clock.
3. **No randomness (plaintext).** Plaintext artifacts have no random inputs;
   ed25519 signing is deterministic. Sealed builds must set
   `[encrypt] key_seed` (convergent derivation) to be reproducible; a random
   content key intentionally randomizes the ciphertext.
4. **Pinned toolchain.** `source → .wasm` compilation is out of CAF's scope:
   byte-identical component bytes require a pinned compiler
   (`rust-toolchain.toml`, `cargo build --locked`, or a container image).
   With an unpinned toolchain the build is only environment-equivalent, while
   the `.caf ⇄ .zip` edges below remain byte-deterministic regardless.

## 3. Canonical ZIP export (`.caf → .zip`)

`caf-tool export` writes a ZIP that is **content-deterministic** in every
mode:

1. Entries are written in a fixed order (`manifest.cbor`, `manifest.json`,
   `interfaces/interface.wit`, `components/NNNN.wasm` in manifest order,
   `payload/` tree sorted by path, `signature.bin`, `keybox.bin`,
   `export.json`).
2. Timestamps are the fixed DOS epoch default; permissions are fixed
   (`0o644` files, `0o755` directories).
3. Compression is caller-selected: `--compression deflate` (default) or
   `--compression stored`. The deflate stream is deterministic for a pinned
   `flate2`/`Cargo.lock` but may differ across zlib implementations;
   `stored` removes that variable, so ZIP *byte* identity across environments
   additionally requires the zip writer pinned via `Cargo.lock`.
4. `export.json` carries `export_version` (currently 2), the original
   `root_hash`, `source_encrypted`, `format_version`, `signed`, and the
   component name/path mapping. It is metadata for verification and tooling —
   never an ordering authority.

## 4. Reconstruction (`.zip → .caf`)

`caf-tool import` rebuilds a byte-identical plaintext artifact:

1. **Authority.** All ordering comes from the preserved `manifest.cbor`:
   component order, payload DFS order, per-file lengths and Merkle hashes.
   ZIP entry order and metadata never affect the output bytes.
2. **Entry verification.** Every entry is checked against the manifest before
   use: interface SHA-256 and length; each component's SHA-256 and length;
   each payload file's length and recomputed Merkle root
   (`payload::verify_file`). Payload entries present in the ZIP but absent
   from the manifest are rejected.
3. **Reassembly.** The canonical layout (§1 of `container-format.md`) is
   replayed over the verified sections: header (`format_version` from the
   manifest, `FLAG_SIGNED` iff `signature.bin` is present), manifest,
   interface, recomputed directory, components, payload files, signature —
   zero padding between sections. Directory payload hashes are the manifest
   tree hashes; the signature entry's hash is zero.
4. **Verification gates, in order:** per-entry hashes (step 2) → recomputed
   root hash must equal `export.json.root_hash` → the reconstructed bytes
   must pass full strict verification (`verify`), including the signature
   when present. Any failure aborts the import.
5. **Atomic publish.** The artifact is written to a temporary file beside the
   destination, fsynced, and renamed only after every gate has passed.
   Existing outputs require `--force`; failures preserve them.

The result is byte-identical to the original `.caf`; for signed artifacts the
embedded signature verifies against the reconstructed bytes, which is the
strongest available proof of faithful reconstruction.

## 5. Verification matrix (CI gates)

Determinism is an invariant to be tested, not a property to be asserted:

- `build × 2` on the same project → identical bytes.
- `build → export → import` → identical bytes and identical root hash, across
  a corpus covering unsigned/signed, empty files and directories, and
  multi-chunk (> 1 MiB) payload files.
- `export × 2` → identical ZIP bytes in both compression modes.
- Fuzz round-trip (`export` → `import` on arbitrary artifacts) is future work.

## 6. Sealed artifacts (future work)

Plaintext export discards the ciphertext of a sealed artifact, so the routes
above do not apply. Two reconstruction routes are specified but **not
implemented**; `import` rejects sealed exports with a pointer here.

- **Route A — raw export.** Export every section verbatim (ciphertext,
  padding, keybox, signature, directory). Reassembly needs no key and the
  signature remains valid by construction. The ZIP is then an exploded view
  of the container, not a plaintext reading.
- **Route B — deterministic re-encryption.** Rebuild from the plaintext
  export with the original content key: chunk nonces are counters and the
  Pow2 padding profile is deterministic, so re-encryption reproduces the
  original ciphertext exactly; the keybox is reattached verbatim (never
  re-wrapped). Requires the content key — which the export already required.

Both routes close with the same oracle as §4: recomputed root hash plus, when
signed, signature verification.
