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

A sealed artifact (`FLAG_ENCRYPTED`, §8) inserts two sections right after the
directory — the **keybox** (recipient stanzas) and the encrypted **private
manifest** — and stores a single encrypted **payload blob** instead of
per-file payload sections:

```text
| Section Directory (binary TOC)    |
+-----------------------------------+
| Keybox           (plaintext)      |
+-----------------------------------+
| Private Manifest (ciphertext)     |
+-----------------------------------+
| WASM components  (ciphertext)     |
+-----------------------------------+
| Payload blob     (ciphertext)     |
+-----------------------------------+
```

`Flags` is a `u16` bitfield. v1 defines two bits: `0x0001 SIGNED` — the
artifact carries a 96-byte ed25519 signature section — and `0x0002 ENCRYPTED`
— the artifact is sealed (§8). Readers **must reject an artifact carrying any
unknown flag bit** (fail-closed): a reader that silently ignored a future flag
— e.g. an encryption marker — would serve ciphertext as plaintext. New flags
are therefore only ever introduced together with a `format_version` major bump
(§12).

Directory entry tags: `0` WASM component · `1` payload (file section, or the
single payload blob in a sealed artifact) · `2` manifest (the envelope manifest
in a sealed artifact) · `3` signature · `4` keybox · `5` private manifest.
Readers reject unknown tags (fail-closed).

The **bootstrap header** is the only part that must be read eagerly (a few dozen
bytes); manifest, interface, and directory are the "boot area" read on open (a
few KB); payload and WASM components are read on demand by offset + HTTP Range.
A remote artifact is thus opened after reading only the boot area plus the
(small) component bytes — see §11 for the incremental-verification contract
that makes this sound.

The **section directory** is a fixed-width binary table (not CBOR): a `u32` entry
count followed by `count` entries of `tag u8 | offset u64 | length u64 | hash
[u8; 32]` (49 bytes each). Because every entry is fixed-width and the manifest
carries *no* offsets, all section offsets are computed in a single forward pass —
there is no self-referential layout to converge.

## 2. Manifest

The manifest is the artifact's self-description ("DNA"). It is serialized as
**canonical CBOR** and is domain-agnostic — no profile-specific fields. In a
sealed artifact (`FLAG_ENCRYPTED`) the manifest section instead carries the
public **envelope** and the full manifest moves into the encrypted **private
manifest** — see §8; everything below describes the plaintext form.

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
- **sealed payloads**: in a sealed artifact the per-file sections are replaced
  by a single encrypted, pow2-padded payload blob, and the tree (with real
  lengths and plaintext hashes) moves into the private manifest — see §8.

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
`ManifestHash`. In a sealed artifact (§8) every section hash covers the *stored*
bytes — ciphertext — so the root hash is the ciphertext identity.

Signatures are ed25519 over the 32-byte **root hash**, which transitively covers
every section. For sealed artifacts this is Encrypt-then-Sign: the signature
binds the ciphertext identity and verifies without the content key; the
signature section stays plaintext.
Provenance distinguishes **data** / **algorithm** / **artifact**
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

## 8. Sealed artifacts (encryption)

A sealed artifact (`FLAG_ENCRYPTED`) encrypts the components, the payload, and
a **private manifest**, leaving only a minimal public **envelope** in the
manifest section. The design hides file names, directory structure, real file
lengths, component metadata, provenance, and artifact name/version; it does
not hide the number of components, the capabilities offered, or the padded
total payload size.

```text
content key (32 B, random per build — or convergent, see below)
  ├─ section key "private"      → AES-256-GCM encrypts the private manifest
  ├─ section key "component/<i>" → AES-256-GCM encrypts each component
  └─ section key "payload"      → AES-256-GCM encrypts the payload blob
                                    per 1 MiB chunk
```

- **KDF**: `KDF(label, ikm) = SHA-256("CAF-KDF-1" ‖ 0x00 ‖ label ‖ 0x00 ‖ ikm)`.
  Section keys are `KDF("section", content_key ‖ label)`. This plain
  hash-KDF is sound here because every IKM is a uniformly random 32-byte
  value (a fresh content key or an ECDH shared secret) — it is *not* a
  password KDF.
- **Chunk nonces**: per-section sub-keys make nonces section-local, so chunk
  `i` uses the nonce `0x00000000 ‖ u64be(i)` — a counter, never random.
- **Keybox**: a `u32` stanza count followed by fixed-width **anonymous**
  stanzas (125 B each): `ephemeral_pubkey (65 B, uncompressed SEC-1) ‖
  nonce (12 B) ‖ wrapped_key (48 B)`. Each stanza wraps the content key with
  `p256-ecdh-sha256`: ECDH between the ephemeral key and the recipient's P-256
  key, `KDF("keywrap", shared)`, AES-256-GCM. No recipient key id is stored,
  so the keybox does not reveal *who* the recipients are; a recipient tries
  every stanza.
- **Envelope manifest** (public, CBOR, still the `TAG_MANIFEST` section):
  `format_version`, interface ref, capabilities, execution profile, resource
  limits, policy, the `encryption` block (`aead` / `wrap` / `padding`
  algorithm ids), anonymous ciphertext refs for the components, and refs for
  the keybox / private / payload sections. Everything else moves into the
  private manifest.
- **Private manifest** (encrypted, CBOR, `TAG_PRIVATE`): artifact name and
  version, provenance, per-component metadata (names, worlds, plaintext
  hashes, exports, access scopes), and the payload tree.
- **Payload blob**: all payload files concatenated in DFS order, zero-padded
  to the **next power of two** (4 KiB floor; `padding: "pow2"`), split into
  1 MiB chunks, each chunk sealed with the payload section key. The private
  manifest's payload ref carries the real length, the padded length, and the
  global ciphertext-chunk hash list; per-file plaintext hashes stay in the
  tree. Publicly the directory leaks only the padded blob size — not the file
  count or individual sizes.
- **Reads**: a host decrypts the private manifest at open, then serves payload
  reads by fetching each covering ciphertext chunk, hash-checking it against
  the private manifest's chunk list, and only then decrypting (AEAD) and
  handing plaintext to the guest. Verification-before-use is unchanged; the
  guest ABI is untouched.
- **Verification tiers**: without a key, `caf-tool verify` checks every stored
  hash and the signature (public tier) and reports the artifact as sealed.
  With `--key` / `--recipient-key` it additionally decrypts and verifies the
  private manifest, plaintext component hashes, and per-file payload hashes
  (plaintext tier).
- **Convergent builds**: `caf-tool build` normally draws a fresh random
  content key, so two builds of identical input differ. Setting
  `[encrypt] key_seed` derives the content key from the seed plus the
  complete plaintext identity, making builds byte-reproducible. The identity
  is SHA-256 of the CBOR tuple `(interface_hash, private_manifest_before_encryption)`.
  This private manifest includes all private metadata, component plaintext
  hashes/exports/scopes, and the full payload tree and lengths; its payload
  `hash` is temporarily SHA-256 of the padded plaintext blob and `chunks` is
  empty. After key derivation these two fields are replaced by ciphertext refs.
  Thus changing private metadata also rotates the content key, avoiding reuse
  of the private section's key and nonce with different plaintext.
  Each recipient's ephemeral scalar is derived using
  `KDF("keybox-eph", seed || content_key || recipient_sec1 || counter)`
  (first valid scalar for counter 0..255). Including the content key prevents
  reuse of a wrapping key and nonce across different content keys.
  This fixes the former draft derivation: reproducible build bytes and keys
  change, while existing sealed artifacts remain readable. Existing artifacts
  made with the former derivation should be rebuilt using a fresh seed; the
  fix does not retroactively protect their ciphertext.

### 8.1 Fetch modes and access patterns

Sealed artifacts protect **content at rest**, not **access patterns**. A host
that fetches ciphertext chunks on demand reveals *which* chunks are read.
Deployments choose one of two modes:

- **Whole-file fetch** — download the artifact once, then read locally; no
  access-pattern leakage beyond "the artifact was fetched". This is the
  required mode for JS hosts opening sealed artifacts (WebCrypto decryption
  happens at open) and the recommended mode whenever access patterns are
  sensitive.
- **Range fetch** — lazily fetch ciphertext chunks (§11); leaks the chunk
  access pattern to the backing store, but scales to huge artifacts.

Padding (`pow2`) bounds the *static* size leak; neither padding nor encryption
hides the *dynamic* access pattern in range-fetch mode.

## 9. Result verification

```text
ResultID = H(FileId, FunctionId, CanonicalArgs, ExecutionProfile)
```

A deterministic run produces a **verifiable computational claim**: different
parties using the same file + function + args + profile obtain the same
`ResultID`.

## 10. Profiles

A profile is a convention layered on top of this generic container. It defines:

- a WIT world (the capability contract),
- a set of capability ids,
- payload directory conventions (which files live under the payload root),
- optionally, an execution profile.

The GIS profile is specified in [`../../examples/gis-demo/gis-profile.md`](../../examples/gis-demo/gis-profile.md). Other
profiles (ML inference, reporting, scientific datasets, agent tools) register
their own namespaces without touching this document.

## 11. Opening & incremental verification

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
hits excluded. Native hosts reserve each cache miss against `read_max` before
I/O or cache insertion. Denied misses never populate the cache; attempted
reads that fail I/O or verification retain their reservation, so repeated
failures cannot perform uncharged work.

The security invariant is unchanged versus whole-file verification: tampering
is detected before the affected bytes are used, and undetected tampering is
impossible — only *detection latency* moves from open time to first read.

For a **sealed** artifact the boot area additionally reads the keybox and the
encrypted private manifest (small), components are decrypted at open (their
imports are needed for admission), and each fetched payload chunk is
hash-checked against the private manifest's ciphertext-chunk list and then
AEAD-decrypted before any plaintext reaches the guest. Fetch-mode choice
(whole-file vs. range) and access-pattern leakage are covered in §8.1.

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

## 12. Versioning & stability

- `format_version` (header + manifest) is the container contract. v1 readers
  reject a higher major version at the header, before any further parsing.
  The supported set, per-version parameters, and schema migrations are
  maintained in `crates/core/src/version/` (one folder per version) — nowhere
  else. The maintainer procedure is `doc/spec/versioning.md`.
- Readers reject unknown header flag bits, unknown directory tags, and unknown
  manifest fields (fail-closed). Consequently any new flag, tag, or manifest
  field — e.g. a future AEAD revision — is a *major* change: it ships with a
  `format_version` bump, never silently ignored by an old reader.
- While the format is at draft stage (`0.1.x`), byte layout may change between
  releases with a `format_version` bump; no compatibility guarantee is made.
- Starting with the first stable tag (`1.0`): readers accept all artifacts of
  the same major version; a reader rejects only *higher* major versions.
  Profiles version independently (`namespace:name@version`); artifact
  versions are semver per artifact.
- WIT interfaces inside an artifact follow normal semantic-import
  versioning: adding functions is a minor capability change; changing or
  removing one requires a capability version bump.
- Byte-identical rebuild rules (reproducible build, ZIP export, and
  reconstruction) live in `doc/spec/round-trip.md`.
