# CAF Container Format (`.caf`) — Specification

Version: **0.1.0** · Status: draft

A `.caf` file is a **Computable Artifact**: a single, immutable, range-readable,
content-addressed container that carries data *and* the portable computation
that operates on it.

The container is **domain-agnostic**. A specialized artifact (e.g. GIS) is a
*profile*: it is expressed entirely through (a) the WIT interface, (b) the
embedded WASM components, and (c) payload conventions — never through
container-level fields. The manifest knows nothing about "CRS", "layers", or
"tiles"; it only knows about interfaces, components, capabilities, and payload
sections.

```text
artifact = manifest + interface (WIT) + components (WASM) + payload + policy + identity
```

## 1. Byte layout

All integers are little-endian. Offsets are byte offsets from the start of the
file. Sections are 8-byte aligned.

```text
+-----------------------------------+ offset 0
| Magic            "CAF\0" (4 B)    |
| Format Version   u32              |
| Header Size      u16              |
| Flags            u16              |
+-----------------------------------+  <- fixed Bootstrap Header
| manifest_offset  u64              |
| manifest_len     u64              |
| interface_offset u64              |
| interface_len    u64              |
| directory_offset u64              |
| directory_len    u64              |
| root_hash        [u8; 32]         |
+-----------------------------------+
| Manifest         (canonical CBOR) |
+-----------------------------------+
| Interface        (WIT text)       |
+-----------------------------------+
| Section Directory (binary TOC)    |
+-----------------------------------+
| WASM component #1                 |
| WASM component #2                 |
| ...                               |
+-----------------------------------+
| Payload section(s)                |
+-----------------------------------+
| Signature        (ed25519)        |
+-----------------------------------+
```

The **bootstrap header** is the only part that must be read eagerly (a few dozen
bytes); manifest, interface, and directory are the "boot area" read on open (a
few KB); payload and WASM components are read on demand by offset + HTTP Range.
A 500 GB remote file is thus opened after reading a few KB.

The **section directory** is a fixed-width binary table (not CBOR): a `u32` entry
count followed by `count` entries of `tag u8 | offset u64 | length u64 | hash
[u8; 32]` (49 bytes each). Because every entry is fixed-width and the manifest
carries *no* offsets, all section offsets are computed in a single forward pass —
there is no self-referential layout to converge.

## 2. Manifest

The manifest is the artifact's self-description ("DNA"). It is serialized as
**canonical CBOR** and is domain-agnostic — no profile-specific fields.

```rust
struct Manifest {
    // identity
    name: String,
    version: String,                 // artifact version (semver)
    format_version: u32,             // container format version

    // interface: types & functions (see §3)
    interface: InterfaceRef,         // inline WIT or offset into interface section

    // computation: one or more WASM components
    components: Vec<ComponentRef>,

    // capabilities exposed by the artifact (namespace:name@ver)
    capabilities: Vec<CapabilityId>,

    // execution policy & resource limits
    execution: ExecutionProfile,
    resources: ResourceLimits,

    // security & trust
    policy: CapabilityPolicy,
    provenance: Provenance,
    trust: Option<TrustInfo>,        // reserved

    // payload references (virtual filesystem, see §5)
    payloads: Vec<PayloadRef>,

    // content addressing of the *other* sections
    hashes: SectionHashes,           // interface / wasm / payload
}
```

The manifest carries **no absolute offsets**: section layout (where the
interface, components, and payload files live) is recorded solely in the section
directory (§1). This keeps the manifest's content hash independent of layout, so
`ManifestHash = SHA256(manifest)` is well-defined and there are no
self-referential hash fields.

### Component binding & access scope (hard invariant)

A manifest **must** bind each WASM component to the payload paths it may read.
This binding is a hard, non-negotiable invariant: a component is denied access to
any payload node outside its declared scope, by construction, at runtime.

```rust
struct ComponentRef {
    name: String,                    // component name
    world: String,                   // matching WIT world (= interface contract)
    length: u64,
    hash: [u8; 32],
    exports: Vec<ExportEntry>,       // capability -> export name -> function signature
    access: Vec<AccessScope>,        // payload subtrees visible to this component
}

struct AccessScope {
    path: String,                    // logical path within the payload tree
    hash: [u8; 32],                  // content hash of the scoped node
    mode: AccessMode,                // read-only (only value in v0.1)
}
```

`access` binds a payload **path** to the **content hash** of the tree node it
resolves to, so a scope is pinned to content — not to a name that can be forged
or traversed. Scopes may overlap across components. A component that reads no
payload (e.g. metadata embedded in the WASM itself) may declare `access = []`.

Validation is enforced at three stages; the invariant holds only if all three
hold:

1. **build time** — every `access` node must resolve to a real node in the payload
   tree, or the artifact is rejected.
2. **open time** — the referenced node's hash must match the payload section;
   ghost files, path traversal, and forged scopes fail verification.
3. **run time** — the host exposes each component only its declared subtrees via
   preopened directory descriptors; `open()` resolves *only* within that set and
   returns an error otherwise (see §4).

Consequences: a component can read every byte *within* its scope, but nothing
outside it. The isolation unit is the **component**, not the individual export;
to narrow a trust boundary further, split into multiple components. This is
read-visibility scoping, not semantic/row-level control.

### Capability id

A capability id is a namespaced, versioned interface name, opaque to the
container layer:

```text
cf:spatial-query@1
cf:map-render@1
org:example:infer@2
```

Applications depend only on capability ids, never on the physical layout.
A **profile** is, by convention, the set of capabilities plus the WIT world that
an artifact exposes.

## 3. Interface section (WIT)

The interface is the artifact's stable contract, expressed in **WIT**
(WebAssembly Component Model). It defines both data types (`record` / `variant`
/ `enum` / `flags` / `type`) and functions (`func ... -> result<.., ..>`).

```wit
package example:file@0.1.0;

world computable-file {
    export compute: interface {
        query: func(req: query-request) -> result<query-result, string>;
    }
}
```

The container layer treats WIT as opaque text; all profile semantics live here.

## 4. WASM components

Computation is distributed as WASM **components** (component model), one per
exported capability, matching a WIT world. The host ABI exposed to a component
is minimal and read-only:

```text
payload-fs      (POSIX-like filesystem; preopened per-component scope)
  open(path: string) -> fd
  read(fd: fd, len: u64) -> list<u8>
  readdir(path: string) -> list<entry>
  stat(path: string) -> meta
  seek(fd: fd, offset: u64)
  close(fd: fd)
self.size() -> u64                  (whole-file byte count)
memory                              (host-managed linear memory)
return                              (component result)
```

By default components have **no** network / external filesystem / process /
environment / clock / random access. The only filesystem is the payload root,
mounted read-only, and **preopened per component**: each component receives a
descriptor set containing only the payload subtrees declared in its `access`
scope (§2). `open(path)` resolves against that set only — any path outside the
declared scope (including `..` traversal) is rejected, making the
component↔path binding a hard invariant rather than a documented convention.

## 5. Payload section (virtual filesystem)

Payload is one or more files organized as a **directory tree**, accessed via the
POSIX-like API above. Each entry is a file or directory, named, and individually
hashed.

```rust
struct PayloadRef {
    root: PayloadNode,               // directory tree root
    media_type: String,              // logical type (not physical format)
    length: u64,
    hash: [u8; 32],                  // tree root hash
    compressed: Option<Compression>,
}

struct PayloadNode {
    kind: EntryKind,                 // file | dir
    name: String,
    hash: [u8; 32],                  // file: Merkle root over chunks; dir: hash over children
    length: u64,
    layout: Option<PayloadLayout>,   // file only: opaque / range / stream
    chunks: Vec<[u8; 32]>,           // file only: chunk hashes (empty for single-chunk)
    entries: Vec<PayloadNode>,       // dir only: children
}
```

- **layout**: `opaque` (single chunk, whole-block read) / `range` (multi-chunk,
  range-readable) / `stream` (streaming). A file whose bytes fit in one chunk has
  `layout: opaque` and `chunks: []`; its hash is the plain SHA-256 of the bytes.
- **content addressing**: files are split into fixed-size chunks (1 MiB) whose
  hashes form a Merkle tree; the file's `hash` is the tree root. Larger files are
  therefore verifiable and readable per-chunk (HTTP Range) without reading the
  whole file. Directory hashes are computed over their children's
  `kind | name | hash`.
- **format-transparent**: payload bytes may be GeoParquet, PMTiles, JSON/CSV,
  model weights, or any private format — only the interface + components know
  how to interpret it.
- **read-only**: the tree is read-only; components may only
  `open/read/readdir/stat/seek/close` (Immutable by Default).

## 6. Execution profile & resource limits

```yaml
execution:
  profile: caf-d1         # deterministic profile
  deterministic: true
capabilities:
  self_read: true
  network: false
  filesystem: false
  clock: false
  random: false
resources:
  memory_max: 256MiB
  cpu_fuel: 100000000
  output_max: 64MiB
```

`caf-d1` defines canonical NaN behavior, fixed numeric semantics, and a frozen
imported interface set so the same `(FileId, FunctionId, Args, Profile)` yields
the same result everywhere.

## 7. Identity & verification

```text
InterfaceHash = SHA256(WIT text)
WasmHash      = SHA256(each component bytes)
PayloadHash   = Merkle root over payload chunks (single chunk == SHA256 of bytes)
ManifestHash  = SHA256(canonical manifest)            -- stored in the directory
RootHash      = SHA256(ManifestHash || InterfaceHash || WasmHash* || PayloadHash*)
FileId        = RootHash                               -- stored in the header
```

The manifest stores the interface/wasm/payload hashes (of the *other* sections);
its own hash and the root hash are derived and stored outside the manifest (root
in the header, manifest hash in the directory), so the manifest is free of
self-referential hashes and `SHA256(manifest)` always equals the stored
`ManifestHash`.

Signatures are ed25519 over the canonical manifest bytes (which in turn cover all
section hashes). Provenance distinguishes **data** / **algorithm** / **artifact**
publishers.

## 8. Result verification

```text
ResultID = H(FileId, FunctionId, CanonicalArgs, ExecutionProfile)
```

A deterministic run produces a **verifiable computational claim**: different
parties using the same file + function + args + profile obtain the same
`ResultID`.

## 9. Profiles

A profile is a convention layered on top of this generic container. It defines:

- a WIT world (the capability contract),
- a set of capability ids,
- payload directory conventions (which files live under the payload root),
- optionally, an execution profile.

The GIS profile is specified in [`../../examples/gis-demo/gis-profile.md`](../../examples/gis-demo/gis-profile.md). Other
profiles (ML inference, reporting, scientific datasets, agent tools) register
their own namespaces without touching this document.
