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
│   └── tools/        # caf-tool: build/inspect .caf artifacts
├── examples/
│   └── gis-demo/     # a worked example profile (browser demo, no backend)
└── doc/
    └── spec/         # container format & ABI specifications
```

## Quick start

```bash
# Build the tooling
cargo build --workspace

# Scaffold a new project (WIT + build config + language skeleton)
cargo run -p caf-tool -- new my-artifact --lang rust   # rust|python|js|go|as

# Pack a payload directory + interface + WASM components into a .caf artifact
cargo run -p caf-tool -- build -c build.toml -o artifact.caf \
    --dump-manifest artifact.manifest.json

# Verify a .caf artifact (hash chain, access scopes, signature)
cargo run -p caf-tool -- verify artifact.caf

# Print a human-readable summary (or full JSON with --json)
cargo run -p caf-tool -- inspect artifact.caf
```

`caf-tool` compiles the `build.toml` configuration (artifact identity, WIT
interfaces, WASM components, capability/access declarations, and payload) into a
single content-addressed `.caf` file. It validates the WIT interfaces with
`wit-parser`, binds each declared capability to its world export, and (with
`embed = true` on a component) embeds the world metadata into the module via
`wit-component`.

For a complete, runnable end-to-end example — including a browser host runtime,
a WASM component, and a payload in multiple open formats — see
[`examples/gis-demo`](examples/gis-demo/README.md).

## Documentation

- [`doc/spec/container-format.md`](doc/spec/container-format.md) — the `.caf`
  container format (byte layout, manifest, components, payload, verification).
- [`examples/gis-demo/gis-profile.md`](examples/gis-demo/gis-profile.md) — an example profile
  layered on top of the generic container.
