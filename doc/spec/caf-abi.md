# CAF Canonical Value Encoding (`caf-abi`) — v1

Status: draft · applies to container format v1 (core-module execution).

The container spec ([`container-format.md`](container-format.md)) fixes how
bytes are laid out and verified; this document fixes how **values** cross the
host↔component boundary when the Component Model canonical ABI is not in play.
It turns what used to be an ad-hoc convention into a contract hosts and
component authors can rely on.

## 1. Execution model

Format v1 executes **core WASM modules** against the `caf.*` host ABI. WIT is
the *declared* contract, and calls are made against raw WASM exports. At build
time every function of a declared capability must have a real function export
with exactly the caf-abi parameter and result types. Missing exports, wrong
kinds/types, malformed modules, or invalid memory bridges are hard errors.
Kebab-case WIT names may bind to snake_case WASM names; ambiguous normalized
names are rejected and the manifest records the actual WASM export name.
World exports not bound to a component capability are not advertised. Each
artifact-level capability must have an implementing component. True Component Model instantiation is the
v2 upgrade path (see §6).

## 2. Scalars

- WIT scalar types map directly: `u32/s32` → `i32`, `u64/s64` → `i64`,
  `f32`/`f64` → `f32`/`f64`, `bool` → `i32` (0/1), `char` → `i32` (scalar value).
- Enums and flags with at most 32 flags lower to `i32`; larger flag sets use
  the complex-value encoding. Type aliases lower like their target.
- A function whose WIT signature uses only scalars needs no memory bridge.

## 3. Complex values

A complex value (string, list, record, option, result, bytes) is **encoded to
bytes**, placed in the component's linear memory, and referenced as
`(ptr, len)`.

- **Default encoding: canonical CBOR** — the same canonical form as the
  manifest (definite lengths, shortest-form integers, lexicographic map keys).
  Hosts already ship a CBOR decoder for the manifest; components get a
  machine-friendly, self-describing format.
- **Profiles may choose a different encoding** (e.g. the GIS demo profile uses
  UTF-8 JSON for human-inspectable results). The encoding is a *profile
  convention*, recorded in the profile document; the transport mechanism below
  is fixed.

### 3.1 Arguments

For a complex argument, the host:
1. calls the component's exported `alloc(len: u32) -> u32`,
2. writes the encoded bytes at the returned pointer,
3. calls the function with `(ptr: i32, len: i32)` in place of the value.

### 3.2 Results

A function returning a complex value returns a single `i64`:

```text
result = ptr | (len << 32)
```

- The guest allocates the buffer and **leaks it to the host**; the host reads
  `len` bytes at `ptr`, then calls the component's exported
  `dealloc(ptr: u32, len: u32)` to release it.
- A component with bound functions accepting or returning complex values
  **must** export `alloc: (i32) -> i32`, `dealloc: (i32, i32) -> ()`, and an
  unshared 32-bit linear memory named `memory`. Export names alone do not
  satisfy the bridge: the builder verifies their kinds and signatures.
- `len == 0` with `ptr == 0` encodes the empty value.
- Complex results always use `i64`; an `i32` result is a scalar, not a packed
  pointer/length pair.

### 3.3 The emit channel

For output larger than practical memory copies or genuinely streaming results,
components use `caf.emit(ptr, len)`: chunks are appended to the host's emit
buffer and charged to `output_max`. Profiles define how emitted chunks frame
individual values (newline-delimited CBOR/JSON recommended).

## 4. Reference implementation

- Guest side (Rust): the `caf-guest` crate provides `alloc`/`dealloc`,
  `return_bytes`/`return_str`/`return_json`, and safe wrappers over the
  payload-fs imports.
- Host side (native): `Session::call` + `Session::read_memory` in
  `caf-runtime`; packed results are detected with `is_packed_result`.
- Host side (browser): `caf.js` implements the same packing rules.

## 5. Errors

A failed capability call returns the encoding of the profile's error shape
(e.g. `{ "error": "message" }`), never a trap. Traps are reserved for budget
exhaustion and policy violations, which are host-enforced, not values.

## 6. Upgrade path to the Component Model (v2)

v2 artifacts may carry true components (with embedded world metadata, already
supported at build time via `embed = true`). A v2 runtime instantiates them
through the Component Model canonical ABI, where WIT types lower/lift
natively and this document's §3 no longer applies. Hosts that cannot run
components (e.g. browsers without a transpiled glue layer) continue to accept
v1 artifacts; the container format signals which execution model an artifact
needs via a future `format_version` bump. Profiles are encouraged to keep
their WIT source of truth stable so the same interface works under both ABIs.
