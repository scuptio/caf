# CAF — Computable Artifact Format

> English | [简体中文](README.zh-CN.md) · License: [Apache-2.0](LICENSE)

[![CI](https://github.com/scuptio/caf/actions/workflows/ci.yml/badge.svg)](https://github.com/scuptio/caf/actions/workflows/ci.yml)

A Rust workspace implementing the **Computable Artifact Format (`.caf`)** — a
general, domain-agnostic way to ship *data together with the computation that
operates on it*.

> **Stop shipping data. Ship capabilities.**

A `.caf` file is not a passive data carrier: it bundles data, a typed interface
(WIT), portable computation (WASM components), a capability policy, and
cryptographic identity into a single, immutable, range-readable,
content-addressed object.

```
Application (Rust / Python / JS / CLI / Agent)
        │  capability ABI  (namespaced, versioned interfaces)
        ▼
CAF Runtime  (WASM sandbox + capability policy + resource metering)
        │
        ▼
artifact.caf   (manifest + data + WASM components + signatures)
        │
        ▼  HTTP Range / local / S3 / CDN
```

The container knows nothing about any particular domain. A specialized artifact
(geospatial, ML inference, reporting, agent tools, …) is a **profile**: it is
expressed entirely through (a) its WIT interface, (b) its WASM components, and
(c) payload conventions — never through container-level fields.

## Design principles

1. **Interface first** — a file describes what it *can do* (`capabilities()`),
   not how its bytes are laid out.
2. **Minimal host ABI** — a read-only `payload-fs` plus `memory`/`return`;
   everything else is denied by default.
3. **Immutable by default** — artifacts are content-addressed; results are
   cached externally, never written back into the file.
4. **No ambient authority** — no network / filesystem / clock / random unless
   the file explicitly declares them and the runtime authorizes them.
5. **Version everything** — container, interface, execution profile, and payload
   schema versions are independent.
6. **Existing formats are carriers** — payload bytes may be Parquet, JSON/CSV,
   model weights, or any private format; only the interface + components know
   how to interpret them.

## Workspace layout

```
caf/
├── crates/
│   ├── core/          # caf-core: container format parsing + verification
│   ├── runtime/       # caf-runtime: WASM host (payload-fs ABI + capability enforcement)
│   ├── security/      # caf-security: import admission policy + resource metering
│   ├── guest/         # caf-guest: guest-side helpers (ABI decls, memory bridge, packed results)
│   └── tools/         # caf-tool: build/verify/inspect/run/ls/diff/export/import/keygen/versions + project wizard
├── examples/
│   └── gis-demo/      # a worked example profile (browser demo, no backend)
├── fuzz/              # cargo-fuzz targets for the parsers and verifier
└── doc/
    └── spec/          # container format, value-encoding ABI specifications
```

## Quick start

```bash
# Build the tooling and install caf-tool
cargo build --workspace
cargo make install            # release binary into Cargo's bin directory

# Scaffold → pack → verify
caf-tool new my-artifact --lang rust    # rust|python|js|go|as
caf-tool build -c build.toml -o artifact.caf --dump-manifest artifact.manifest.json
caf-tool verify artifact.caf

# Execute a component function (host runtime with capability enforcement)
caf-tool run artifact.caf --fn reproject_x --args 120,30,4326,3857
```

Without installing, prefix any command with `cargo run -p caf-tool --` instead.

### More caf-tool commands

```bash
caf-tool inspect artifact.caf        # human-readable summary
caf-tool ls artifact.caf             # payload files + components
caf-tool diff a.caf b.caf            # per-section diff
caf-tool export artifact.caf -o artifact.zip   # export embedded contents to a ZIP
caf-tool import artifact.zip -o rebuilt.caf    # rebuild a byte-identical .caf (plaintext)
caf-tool keygen --recipient          # P-256 recipient keypair for sealed artifacts
caf-tool versions                    # supported container format versions
```

Sealing (`[encrypt]` recipients), sealed verification (`--recipient-key`), the ZIP
layout, and the reconstruction guarantees are specified in
[container-format.md](doc/spec/en/container-format.md) §8 and
[round-trip.md](doc/spec/en/round-trip.md).

## Ecosystem

- [CAFDReader](https://github.com/scuptio/CAFDReader) — the cross-platform reader for
  CAFD (`.cafd`) interactive documents, a document profile built on the CAF
  container ([CAFD 1.0.0 spec](https://github.com/scuptio/CAFDReader/blob/main/spec/en/CAFD.md)).

## Documentation

- [`doc/spec/container-format.md`](doc/spec/en/container-format.md) — the `.caf`
  container format (byte layout, manifest, components, payload, incremental
  verification, trust model, versioning).
- [`doc/spec/caf-abi.md`](doc/spec/en/caf-abi.md) — the value-encoding ABI: how
  complex values cross the host↔component boundary in format v1.
- [`doc/spec/round-trip.md`](doc/spec/en/round-trip.md) — deterministic
  round-trip rules: reproducible build, ZIP export, byte-identical import.
- [`doc/spec/versioning.md`](doc/spec/en/versioning.md) — the maintainer upgrade
  guide: version axes, when a bump is required, the per-version folder
  procedure.
- [`doc/spec/terminology.md`](doc/spec/terminology.md) — the English–Chinese
  glossary shared across CAF ecosystem documents.
- [`examples/gis-demo/gis-profile.md`](examples/gis-demo/gis-profile.md) — an example profile
  layered on top of the generic container.
