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
A remote artifact is thus opened after reading only the boot area plus the
(small) component bytes — see §10 for the incremental-verification contract
that makes this sound.

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

`exports` is populated at build time from the WIT world: for each declared
capability `ns:name@ver`, the world's `name` export is located and its functions
are bound to that capability id. A capability declared without a matching world
export is a build error. Without a WIT world, `exports` falls back to the raw
WASM export names (empty capability).

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

Computation is distributed as WASM modules matching a WIT world, one per
exported capability. Format v1 executes **core modules** against the `caf.*`
host ABI described below (imports are enumerated at open time and resolved
against the declared policy, fail-closed); embedding component-model metadata
is supported at build time, and the value-encoding contract that applies until
true Component Model instantiation lands is specified in
[`caf-abi.md`](caf-abi.md). The host ABI exposed to a component is minimal and
read-only:

```text
payload-fs      (POSIX-like filesystem; preopened per-component scope)
  open(path: string) -> fd
  read(fd: fd, len: u64) -> list<u8>
  readdir(path: string) -> list<entry>
  stat(path: string) -> meta
  seek(fd: fd, offset: u64)
  close(fd: fd)
self.size() -> u64                  (whole-file byte count)
emit(bytes)                         (structured result output, charged to output_max)
log(bytes)                          (diagnostic output, charged to output_max)
abort(code)                         (explicit deterministic trap)
memory                              (host-managed linear memory)
return                              (component result, charged to output_max)
```

The `payload-fs` functions are provided only when the policy grants `self_read`;
`self.size` / `emit` / `log` / `abort` are always available. Every byte that
crosses the host boundary as output — `emit`, `log`, and the return channel
(result values plus bytes the host reads out of component memory) — is charged
against `output_max`.

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
- **uncompressed in v1**: the `compressed` field is reserved. Runtimes reject a
  non-`None` value at open time (fail-closed) rather than risk serving bytes a
  component cannot interpret. Chunk-aligned compression is a v2 topic.
- **one tree in v1**: this format version carries exactly one payload tree;
  the root-hash construction (§7) already leaves room for more.

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
  read_max: 1GiB
  output_max: 64MiB
```

`caf-d1` defines canonical NaN behavior, a deterministic relaxed-SIMD subset, no
threads, and no clock/random/environment imports, so the same `(FileId,
FunctionId, Args, Profile)` yields the same result everywhere. A profile is a
machine-checkable engine configuration: `caf-d1` requires `deterministic:
true`, and a profile the runtime does not know is rejected at open time
(fail-closed) rather than silently ignored.

All four budgets are enforced — none is a dead declaration:

| budget | enforcement point |
|---|---|
| `memory_max` | store linear-memory limit (+ bounded host-side payload buffering) |
| `cpu_fuel` | engine fuel, decremented per instruction |
| `read_max` | bytes actually fetched from the payload backing store (cache hits excluded) |
| `output_max` | bytes crossing the host boundary via emit / log / the return channel |

## 7. Identity & verification

```text
InterfaceHash   = SHA256(WIT text)
WasmHash        = SHA256(each component bytes)
PayloadRootHash = root hash of the payload tree (file hash = chunk-Merkle root;
                  a single-chunk file hashes to the plain SHA-256 of its bytes)
ManifestHash    = SHA256(canonical manifest)          -- stored in the directory
RootHash        = SHA256("CAF1"
                         || u64le(len) || ManifestHash
                         || u64le(len) || InterfaceHash
                         || u64le(n)   || (u64le(len) || WasmHash)*
                         || u64le(len) || PayloadRootHash)
FileId          = RootHash                             -- stored in the header
```

The `"CAF1"` domain separator, explicit length prefixes, and the component count
make the hash input unambiguous to parse and leave room for multiple payloads or
a future hash-algorithm migration. Because the manifest hash transitively covers
the policy, execution profile, interface ref, component refs, access scopes, and
payload tree, binding strength is equivalent to hashing those fields directly.
This format version carries exactly one payload tree.

The manifest stores the interface/wasm/payload hashes (of the *other* sections);
its own hash and the root hash are derived and stored outside the manifest (root
in the header, manifest hash in the directory), so the manifest is free of
self-referential hashes and `SHA256(manifest)` always equals the stored
`ManifestHash`.

Signatures are ed25519 over the canonical manifest bytes (which in turn cover all
section hashes). Provenance distinguishes **data** / **algorithm** / **artifact**
publishers.

### 7.1 Trust model

The signature section carries `(pubkey, signature)`: the key needed to verify
travels inside the file. A valid signature therefore proves **integrity and
self-consistency** — the manifest was signed by the holder of the matching
private key — but says nothing about *who* that holder is. Authenticity is
established out of band:

- **Signer fingerprint**: `SHA256(pubkey)`, hex-encoded. `caf-tool verify`
  prints it for every signed artifact.
- **Trust store**: consumers keep an external mapping from fingerprints to
  publisher identities. `caf-tool verify --trusted-keys keys.toml` resolves
  the signer against it (TOML: `[keys] <fingerprint> = "publisher name"`), and
  `--require-trusted` turns an unknown or unsigned artifact into a hard error.
- **TOFU by default**: without a trust store, first use of a fingerprint is a
  decision point for the consumer; distributions are expected to publish their
  fingerprint through a separate authenticated channel (project site, signed
  release notes, …), exactly like SSH host keys.
- **Browser verification**: the JS host verifies signatures with WebCrypto
  Ed25519 (supported in current Chrome/Edge/Safari/Firefox). On a platform
  without it, verification degrades to "unverifiable" with a warning rather
  than rejection — integrity is still guaranteed by the hash chain.

Multiple signers and certificate chains are v2 topics.

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

## 10. Opening & incremental verification

A host opens an artifact **lazily** over its backing store (local file, HTTP
Range endpoint, object storage). Opening reads and verifies only:

1. the bootstrap header,
2. the boot area — manifest (pinned by the directory's manifest entry),
   interface (pinned by the manifest), and the section directory,
3. each component's bytes (small; hash-verified, then admission enumerates
   their imports against the declared policy),
4. the 96-byte signature section, if present.

The payload tree's structure (directory hashes) and every declared access
scope are checked against the manifest at open. **Payload bytes are verified
incrementally**: when a component reads `[pos, pos + len)` of a payload file,
the host fetches only the covering 1 MiB chunks and checks each chunk against
the manifest's chunk hashes *before* handing bytes to the guest. Every byte a
component receives is therefore verified before use; bytes that are never read
are never fetched or verified. Hosts may cache verified chunk bytes; the
`read_max` budget counts bytes actually pulled from the backing store, cache
hits excluded.

The security invariant is unchanged versus whole-file verification: tampering
is detected before the affected bytes are used, and undetected tampering is
impossible — only *detection latency* moves from open time to first read.

Note on scale: the manifest carries the chunk hashes, so its size grows with
payload size (32 bytes per 1 MiB chunk). This keeps even large artifacts'
boot areas small (≈32 KB per GiB of payload); profiles shipping enormous
payloads should prefer fewer, larger payload files to keep directory and tree
overhead proportional.

Note on JS hosts: true on-demand Range reads additionally require JSPI
(`WebAssembly.Suspending`) so the synchronous payload-fs ABI can wait on async
fetches. Where JSPI is unavailable the whole artifact downloads once and is
then lazily verified in memory. Profiles that must stay interactive under
whole-file download should ship **multiple smaller artifacts** (e.g. one for
text, one per media bundle) rather than one giant file — composition over
size, and no format change required.

## 11. Versioning & stability

- `format_version` (header + manifest) is the container contract. v1 readers
  reject a higher major version at the header, before any further parsing.
- While the format is at draft stage (`0.1.x`), byte layout may change between
  releases with a `format_version` bump; no compatibility guarantee is made.
- Starting with the first stable tag (`1.0`): readers accept all artifacts of
  the same major version; a reader rejects only *higher* major versions.
  Profiles version independently (`namespace:name@version`); artifact
  versions are semver per artifact.
- WIT interfaces inside an artifact follow normal semantic-import
  versioning: adding functions is a minor capability change; changing or
  removing one requires a capability version bump.
