# CAF — Computable Artifact Format

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
│   └── tools/         # caf-tool: build/verify/inspect/run/ls/diff/export/keygen + project wizard
├── examples/
│   └── gis-demo/      # a worked example profile (browser demo, no backend)
├── fuzz/              # cargo-fuzz targets for the parsers and verifier
└── doc/
    └── spec/          # container format, value-encoding ABI specifications
```

## Quick start

```bash
# Build the tooling
cargo build --workspace

# Install the release caf-tool binary into Cargo's bin directory
cargo make install
# Optional: select a different installation root
cargo make install --root /path/to/install

# Scaffold a new project (WIT + build config + language skeleton)
cargo run -p caf-tool -- new my-artifact --lang rust   # rust|python|js|go|as

# Pack a payload directory + interface + WASM components into a .caf artifact
cargo run -p caf-tool -- build -c build.toml -o artifact.caf \
    --dump-manifest artifact.manifest.json

# Verify a .caf artifact (hash chain, access scopes, signature)
cargo run -p caf-tool -- verify artifact.caf

# Seal an artifact (encrypted components + payload + private manifest);
# see doc/spec/container-format.md §8
cargo run -p caf-tool -- keygen --recipient   # P-256 recipient keypair
#   → add [encrypt] recipients = ["<pub hex>"] to build.toml
cargo run -p caf-tool -- verify artifact.caf --recipient-key <secret hex>

# Inspect / list / diff
cargo run -p caf-tool -- inspect artifact.caf        # human-readable summary
cargo run -p caf-tool -- ls artifact.caf             # payload files + components
cargo run -p caf-tool -- diff a.caf b.caf            # per-section diff

# Export all embedded contents to a ZIP
cargo run -p caf-tool -- export artifact.caf -o artifact.zip
# Sealed artifacts require a key; the ZIP contains decrypted contents
cargo run -p caf-tool -- export artifact.caf -o artifact.zip --recipient-key <secret hex>

# Execute a component function (host runtime with capability enforcement)
cargo run -p caf-tool -- run artifact.caf --fn reproject_x --args 120,30,4326,3857
```

`caf-tool` compiles the `build.toml` configuration (artifact identity, WIT
interfaces, WASM components, capability/access declarations, and payload) into a
single content-addressed `.caf` file. It validates the WIT interfaces with
`wit-parser`, binds each declared capability to its world export, and (with
`embed = true` on a component) embeds the world metadata into the module via
`wit-component`.

`caf-runtime` opens and verifies an artifact, instantiates its WASM components,
exposes the read-only `payload-fs` ABI scoped to each component's declared
access, and enforces the deny-by-default capability policy and fuel limits.

### ZIP export

`caf-tool export FILE -o OUTPUT.zip` exports the embedded contents without
executing a component. It writes `manifest.cbor` (the exact stored bytes),
`manifest.json`, `interfaces/interface.wit`, numbered `components/0000.wasm`
files, and the original directory tree under `payload/`, including empty files
and directories. `export.json` records export format version 1, the original
CAF root hash, whether the source was encrypted, and component name/path mappings.
Signature and keybox sections, when present, are retained as `signature.bin`
and `keybox.bin`.

For sealed CAFs, supply `--key HEX` or `--recipient-key HEX`. The stored manifest
is the public envelope; decrypted private metadata is exported separately as
`private-manifest.cbor` and `private-manifest.json`. WASM and payload files in
the ZIP are plaintext. No secret keys are included.

Payload data is read and verified in bounded chunks; ZIP64 supports large
files. Entries have fixed timestamps and ordering for reproducible exports.
Unsafe or conflicting paths are rejected. The ZIP is written to a temporary
file beside the destination and published only after successful verification
and completion. Existing outputs require `--force`; failures preserve them.

WIT sources are stored concatenated inside CAF, so their original filenames
and boundaries cannot be recovered. WASM bytes reflect the embedded component,
including any metadata added at build time. Source code, build scripts and
`build.toml` are exported only if they were included in the payload. This ZIP
is a content export, not a rebuild configuration: manifest references describe
the original CAF, and the retained signature authenticates the original CAF
root hash rather than the ZIP.

For a complete, runnable end-to-end example — including a browser host runtime,
a WASM component, and a payload in multiple open formats — see
[`examples/gis-demo`](examples/gis-demo/README.md).

## Documentation

- [`doc/spec/container-format.md`](doc/spec/container-format.md) — the `.caf`
  container format (byte layout, manifest, components, payload, incremental
  verification, trust model, versioning).
- [`doc/spec/caf-abi.md`](doc/spec/caf-abi.md) — the value-encoding ABI: how
  complex values cross the host↔component boundary in format v1.
- [`examples/gis-demo/gis-profile.md`](examples/gis-demo/gis-profile.md) — an example profile
  layered on top of the generic container.
