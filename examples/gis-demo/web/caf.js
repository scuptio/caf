// caf.js — CAF host runtime for the browser (and Node), container format v1.
//
// Opens a .caf artifact LAZILY: only the boot area (header, manifest,
// interface, section directory), the component bytes, and the signature are
// read up front; payload bytes are fetched per 1 MiB chunk and Merkle-verified
// before any byte reaches the component. Loading modes (openCaf's `fetchMode`
// option, default "auto"):
//
//   1. URL on a Range-capable server + JSPI support: true on-demand reads
//      (HTTP Range per chunk) — a 500 GB artifact opens after a few KB.
//   2. URL without Range/JSPI (or fetchMode: "whole"): one whole-file GET,
//      then in-memory lazy verify.
//   3. ArrayBuffer / Uint8Array / Blob (file picker, drag-and-drop): in-memory.
//
// Sealed artifacts (FLAG_ENCRYPTED, spec §8) open with the 32-byte content key
// (`openCaf(input, { contentKey })`): the whole artifact is fetched once
// (no lazy range reads — decryption is async), the private manifest,
// components, and payload blob are AES-256-GCM decrypted at open, and reads
// are served from the verified plaintext.
//
// Security: every byte handed to the component is hash-verified before use;
// component imports are enumerated and checked against the manifest's declared
// capability policy (fail-closed), mirroring the native caf-security crate.
// Budget note: the JS host enforces the read/output budgets and the import
// policy; CPU fuel and memory ceilings are left to the browser tab sandbox.

const MAGIC = [0x43, 0x41, 0x46, 0x00]; // "CAF\0"
const HEADER_SIZE = 92;
const CHUNK_SIZE = 1024 * 1024;
const AEAD_TAG_LEN = 16;
const TAG_COMPONENT = 0;
const TAG_PAYLOAD = 1;
const TAG_MANIFEST = 2;
const TAG_SIGNATURE = 3;
const TAG_KEYBOX = 4;
const TAG_PRIVATE = 5;
const KNOWN_TAGS = new Set([TAG_COMPONENT, TAG_PAYLOAD, TAG_MANIFEST, TAG_SIGNATURE, TAG_KEYBOX, TAG_PRIVATE]);
const FLAG_SIGNED = 0x0001;
const FLAG_ENCRYPTED = 0x0002;
const KNOWN_FLAGS = FLAG_SIGNED | FLAG_ENCRYPTED;

const utf8 = new TextDecoder();
const utf8enc = new TextEncoder();

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

function toHex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function leU16(dv, off) { return dv.getUint16(off, true); }
function leU32(dv, off) { return dv.getUint32(off, true); }
function leU64(dv, off) { return Number(dv.getBigUint64(off, true)); }

function concatBytes(parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

function u64le(n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}

// ---------------------------------------------------------------------------
// Synchronous SHA-256 (chunk verification must work inside sync host imports)
// ---------------------------------------------------------------------------

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function sha256Sync(data) {
  const bitLen = data.length * 8;
  const padded = Math.ceil((data.length + 9) / 64) * 64;
  const buf = new Uint8Array(padded);
  buf.set(data);
  buf[data.length] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(padded - 4, bitLen >>> 0, false);
  dv.setUint32(padded - 8, Math.floor(bitLen / 0x100000000), false);

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);

  for (let off = 0; off < padded; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
      const s1 = (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  for (const [i, v] of [h0, h1, h2, h3, h4, h5, h6, h7].entries()) odv.setUint32(i * 4, v, false);
  return out;

  function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }
}

function sha256Hex(data) { return toHex(sha256Sync(data)); }

// ---------------------------------------------------------------------------
// Canonical-CBOR decoder (definite-length maps/arrays, text/bytes, ints,
// bools, null, floats) — sufficient for the CAF manifest.
// ---------------------------------------------------------------------------

function decodeCBOR(data, offset) {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const first = data[offset];
  const major = first >> 5;
  const info = first & 0x1f;
  let pos = offset + 1;

  function arg() {
    if (info < 24) return info;
    if (info === 24) { const v = data[pos]; pos += 1; return v; }
    if (info === 25) { const v = (data[pos] << 8) | data[pos + 1]; pos += 2; return v; }
    if (info === 26) { const v = dv.getUint32(pos); pos += 4; return v; }
    if (info === 27) { const v = Number(dv.getBigUint64(pos)); pos += 8; return v; }
    throw new Error("bad cbor length");
  }

  let value;
  switch (major) {
    case 0: value = arg(); break;
    case 1: value = -1 - arg(); break;
    case 2: { const len = arg(); value = data.slice(pos, pos + len); pos += len; break; }
    case 3: { const len = arg(); value = utf8.decode(data.slice(pos, pos + len)); pos += len; break; }
    case 4: {
      const len = arg(); value = [];
      for (let i = 0; i < len; i++) { const r = decodeCBOR(data, pos); value.push(r.value); pos = r.next; }
      break;
    }
    case 5: {
      const len = arg(); value = {};
      for (let i = 0; i < len; i++) {
        const k = decodeCBOR(data, pos);
        const v = decodeCBOR(data, k.next);
        value[k.value] = v.value;
        pos = v.next;
      }
      break;
    }
    case 6: { arg(); const inner = decodeCBOR(data, pos); value = inner.value; pos = inner.next; break; }
    case 7:
      if (info === 20) value = false;
      else if (info === 21) value = true;
      else if (info === 22) value = null;
      else if (info === 26) { value = dv.getFloat32(pos); pos += 4; }
      else if (info === 27) { value = dv.getFloat64(pos); pos += 8; }
      else throw new Error("bad simple value");
      break;
    default: throw new Error("bad major type");
  }
  return { value, next: pos };
}

// ---------------------------------------------------------------------------
// Backing sources
// ---------------------------------------------------------------------------

class BufferSource {
  constructor(bytes) { this.bytes = bytes; this.rangeReads = 0; }
  static async from(input) {
    if (input instanceof Uint8Array) return new BufferSource(input);
    if (input instanceof ArrayBuffer) return new BufferSource(new Uint8Array(input));
    if (input && typeof input.arrayBuffer === "function") {
      return new BufferSource(new Uint8Array(await input.arrayBuffer()));
    }
    throw new Error("unsupported source type");
  }
  totalLen() { return this.bytes.length; }
  async readAt(off, len) { this.rangeReads++; return this.bytes.slice(off, off + len); }
  readAtSync(off, len) { return this.bytes.slice(off, off + len); }
}

class RangeSource {
  constructor(url, totalLen, head) {
    this.url = url;
    this.len = totalLen;
    this.rangeReads = 0;
    this.bytesFetched = 0;
    this.chunkCache = new Map(); // absolute chunk start offset -> Uint8Array
    this.prefetched = new Map([[0, head]]); // boot head already fetched
  }
  totalLen() { return this.len; }
  // Whole-chunk aligned reads are cached; unaligned reads pass through.
  async readAt(off, len) {
    if (this.prefetched.has(off) && this.prefetched.get(off).length >= len) {
      return this.prefetched.get(off).slice(0, len);
    }
    const start = Math.floor(off / CHUNK_SIZE) * CHUNK_SIZE;
    const end = Math.min(this.len, Math.ceil((off + len) / CHUNK_SIZE) * CHUNK_SIZE);
    if (end - start > 4 * CHUNK_SIZE) {
      // Large non-payload reads (components): fetch as-is.
      const r = await this.#fetch(off, off + len - 1);
      return r;
    }
    for (let cs = start; cs < end; cs += CHUNK_SIZE) {
      if (!this.chunkCache.has(cs)) {
        const ce = Math.min(cs + CHUNK_SIZE, this.len);
        this.chunkCache.set(cs, await this.#fetch(cs, ce - 1));
      }
    }
    const parts = [];
    for (let cs = start; cs < end; cs += CHUNK_SIZE) {
      const chunk = this.chunkCache.get(cs);
      const from = Math.max(off - cs, 0);
      const to = Math.min(off + len - cs, chunk.length);
      if (to > from) parts.push(chunk.slice(from, to));
    }
    return concatBytes(parts);
  }
  async #fetch(from, to) {
    this.rangeReads++;
    const resp = await fetch(this.url, { headers: { Range: `bytes=${from}-${to}` } });
    if (resp.status !== 206) throw new Error(`range fetch failed: HTTP ${resp.status}`);
    const buf = new Uint8Array(await resp.arrayBuffer());
    this.bytesFetched += buf.length;
    return buf;
  }
}

// ---------------------------------------------------------------------------
// Container parsing helpers
// ---------------------------------------------------------------------------

function readHeader(bytes) {
  if (bytes.length < HEADER_SIZE) throw new Error("file too small for a CAF header");
  for (let i = 0; i < 4; i++) if (bytes[i] !== MAGIC[i]) throw new Error("bad magic (not a .caf file)");
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const headerSize = leU16(dv, 8);
  if (headerSize !== HEADER_SIZE) throw new Error(`unsupported header size ${headerSize}`);
  const flags = leU16(dv, 10);
  if (flags & ~KNOWN_FLAGS) throw new Error(`unknown header flags 0x${flags.toString(16)}`);
  return {
    formatVersion: leU32(dv, 4),
    flags,
    manifestOffset: leU64(dv, 12),
    manifestLen: leU64(dv, 20),
    interfaceOffset: leU64(dv, 28),
    interfaceLen: leU64(dv, 36),
    directoryOffset: leU64(dv, 44),
    directoryLen: leU64(dv, 52),
    rootHash: toHex(bytes.slice(60, 92)),
  };
}

function decodeDirectory(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const count = leU32(dv, 0);
  const entries = [];
  let pos = 4;
  for (let i = 0; i < count; i++) {
    const tag = bytes[pos];
    if (!KNOWN_TAGS.has(tag)) throw new Error(`unknown directory entry tag ${tag}`);
    const flags = bytes[pos + 1];
    if (flags !== 0) throw new Error(`unknown directory entry flags 0x${flags.toString(16)}`);
    const hashAlg = bytes[pos + 2];
    if (hashAlg !== 0) throw new Error(`unknown directory entry hash algorithm ${hashAlg}`);
    if (bytes[pos + 3] !== 0) throw new Error("nonzero reserved byte in directory entry");
    entries.push({
      tag,
      offset: leU64(dv, pos + 4),
      length: leU64(dv, pos + 12),
      hash: toHex(bytes.slice(pos + 20, pos + 52)),
    });
    pos += 52;
  }
  return entries;
}

// Files of the payload tree in deterministic DFS order (mirrors caf-core's
// collect_files); paired positionally with the directory's TAG_PAYLOAD entries.
function collectFiles(node, parent, out) {
  const path = node.name === "" ? parent : parent + "/" + node.name;
  if (node.kind === "file") out.push({ path, node });
  else for (const c of node.entries || []) collectFiles(c, path, out);
  return out;
}

function dirHash(node) {
  const parts = [];
  for (const e of node.entries || []) {
    parts.push(utf8enc.encode(e.kind), new Uint8Array([0]), u64le(e.name.length), utf8enc.encode(e.name), hexToBytes(e.hash));
  }
  return toHex(sha256Sync(concatBytes(parts)));
}

function verifyTree(node) {
  if (node.kind === "file") return;
  for (const c of node.entries || []) verifyTree(c);
  if (dirHash(node) !== node.hash) throw new Error(`directory '${node.name}' hash mismatch`);
}

function findNode(root, path) {
  if (path === "/" || path === "") return root;
  let node = root;
  for (const part of path.split("/").filter(Boolean)) {
    node = (node.entries || []).find((e) => e.name === part);
    if (!node) return null;
  }
  return node;
}

// RootHash = SHA256("CAF1" || u64le(len)||ManifestHash || u64le(len)||InterfaceHash
//                   || u64le(n)||(u64le(len)||WasmHash)*
//                   || u64le(m)||(u64le(len)||PayloadRootHash)*)
function computeRootHash(manifestHashHex, interfaceHashHex, wasmHashesHex, payloadRootsHex) {
  const parts = [utf8enc.encode("CAF1")];
  const push = (hex) => { const raw = hexToBytes(hex); parts.push(u64le(raw.length), raw); };
  push(manifestHashHex);
  push(interfaceHashHex);
  parts.push(u64le(wasmHashesHex.length));
  for (const h of wasmHashesHex) push(h);
  parts.push(u64le(payloadRootsHex.length));
  for (const h of payloadRootsHex) push(h);
  return toHex(sha256Sync(concatBytes(parts)));
}

// Multi-payload mount rules (mirrors caf-core::payload::validate_payloads):
// unique, safe names; the first payload mounts at "/", others at "/<name>/",
// so a named payload must not shadow a top-level entry of the default one.
function validatePayloads(payloads) {
  const names = new Set();
  for (const p of payloads) {
    const name = p.name || "";
    if (name === "" || name === "." || name === ".." || name.includes("/") || name.includes("\\")) {
      throw new Error(`invalid payload name '${name}'`);
    }
    if (names.has(name)) throw new Error(`duplicate payload name '${name}'`);
    names.add(name);
  }
  if (payloads.length > 0) {
    for (const entry of payloads[0].root.entries || []) {
      if ([...names].slice(1).includes(entry.name)) {
        throw new Error(`payload name '${entry.name}' collides with a top-level entry of the default payload`);
      }
    }
  }
}

// The default payload keeps tree-relative paths; other payloads are prefixed
// with their name. "" or the first payload's name selects the default.
function resolvePayloadIndex(payloads, name) {
  if (!name || name === payloads[0]?.name) return 0;
  const idx = payloads.findIndex((p) => p.name === name);
  return idx === -1 ? null : idx;
}

function mountPath(index, name, treePath) {
  return index === 0 ? treePath : `/${name}${treePath}`;
}

// ---------------------------------------------------------------------------
// Sealed artifacts (FLAG_ENCRYPTED): AES-256-GCM sections under a content key
// (spec §8). The JS host requires the *content key* directly (keybox unwrap is
// a tool-side concern: `caf-tool verify --recipient-key` resolves it) and
// decrypts everything at open — the whole-file fetch mode.
// ---------------------------------------------------------------------------

// KDF(label, ikm) = SHA-256("CAF-KDF-1" ‖ 0x00 ‖ label ‖ 0x00 ‖ ikm), matching
// caf-core::crypto. Sound here because every IKM is a uniform 32-byte value.
function cafKdf(label, ikm) {
  return sha256Sync(concatBytes([utf8enc.encode("CAF-KDF-1"), new Uint8Array([0]), utf8enc.encode(label), new Uint8Array([0]), ikm]));
}

function sectionKey(contentKey, label) {
  return cafKdf("section", concatBytes([contentKey, utf8enc.encode(label)]));
}

function chunkNonce(index) {
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setBigUint64(4, BigInt(index), false);
  return nonce;
}

async function openChunk(sectionKeyBytes, index, ciphertext) {
  const key = await crypto.subtle.importKey("raw", sectionKeyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: chunkNonce(index) }, key, ciphertext);
  return new Uint8Array(plain);
}

// ---------------------------------------------------------------------------
// Artifact
// ---------------------------------------------------------------------------

export class Artifact {
  #source;
  #files = new Map(); // mounted path -> { offset, length, node, payload, treePath }
  #verifiedChunks = new Set(); // absolute chunk start offsets already verified
  #sealed = null; // { blobs: [Uint8Array, ...] } — decrypted at open

  constructor(source, header, manifest, directory, components, signature, sealed = null) {
    this.#source = source;
    this.header = header;
    this.manifest = manifest;
    this.directory = directory;
    this.components = components; // [{ ref, bytes, entry }]
    this.signature = signature; // { fingerprint, valid, signers } | null
    this.#sealed = sealed;
    // Mounted file list: default payload at "/", others at "/<name>/".
    const fileList = [];
    (manifest.payloads || []).forEach((p, i) => {
      for (const f of collectFiles(p.root, "", [])) {
        fileList.push({ mounted: mountPath(i, p.name, f.path), treePath: f.path, node: f.node, payload: i });
      }
    });
    if (sealed) {
      // Sealed artifact: files map into the decrypted in-memory blobs; every
      // ciphertext chunk was hash-verified and AEAD-opened at open time.
      for (const f of fileList) {
        const start = sealed.starts[f.payload].get(f.treePath);
        this.#files.set(f.mounted, { offset: start, length: f.node.length, node: f.node, payload: f.payload, treePath: f.treePath });
      }
      return;
    }
    const payloadEntries = directory.filter((e) => e.tag === TAG_PAYLOAD);
    if (payloadEntries.length !== fileList.length) {
      throw new Error("payload directory/file count mismatch");
    }
    fileList.forEach((f, i) => {
      this.#files.set(f.mounted, { offset: payloadEntries[i].offset, length: payloadEntries[i].length, node: f.node, payload: f.payload, treePath: f.treePath });
    });
  }

  get name() { return this.manifest.name; }
  get version() { return this.manifest.version; }
  get rootHash() { return this.header.rootHash; }
  get capabilities() { return this.manifest.capabilities || []; }
  payloadFiles() { return [...this.#files.keys()]; }
  fileLength(path) { const m = this.#files.get(path); return m ? m.length : null; }
  get totalSize() { return this.#source.totalLen(); }
  stats() { return { rangeReads: this.#source.rangeReads ?? 0, bytesFetched: this.#source.bytesFetched ?? this.#source.totalLen() }; }

  async readPayload(path) {
    const meta = this.#files.get(path);
    if (!meta) throw new Error(`payload '${path}' not found`);
    return this.readPayloadRange(path, 0, meta.length);
  }

  async readPayloadRange(path, pos, len) {
    const meta = this.#files.get(path);
    if (!meta) throw new Error(`payload '${path}' not found`);
    if (pos + len > meta.length) throw new Error("payload range out of bounds");
    if (len === 0) return new Uint8Array(0);
    if (this.#sealed) {
      return this.#sealed.blobs[meta.payload].slice(meta.offset + pos, meta.offset + pos + len);
    }
    const node = meta.node;
    if ((node.chunks || []).length <= 1) {
      const data = await this.#fetchVerified(meta.offset, meta.length, node.hash);
      return data.slice(pos, pos + len);
    }
    const first = Math.floor(pos / CHUNK_SIZE);
    const last = Math.floor((pos + len - 1) / CHUNK_SIZE);
    const parts = [];
    for (let i = first; i <= last; i++) {
      const cs = i * CHUNK_SIZE;
      const ce = Math.min(cs + CHUNK_SIZE, meta.length);
      const chunk = await this.#fetchVerified(meta.offset + cs, ce - cs, node.chunks[i]);
      const from = Math.max(pos - cs, 0);
      const to = Math.min(pos + len - cs, ce - cs);
      parts.push(chunk.slice(from, to));
    }
    return concatBytes(parts);
  }

  // Synchronous variant for hosts without JSPI: requires a BufferSource.
  readPayloadRangeSync(path, pos, len) {
    const meta = this.#files.get(path);
    if (!meta) throw new Error(`payload '${path}' not found`);
    if (pos + len > meta.length) throw new Error("payload range out of bounds");
    if (len === 0) return new Uint8Array(0);
    if (this.#sealed) {
      return this.#sealed.blobs[meta.payload].slice(meta.offset + pos, meta.offset + pos + len);
    }
    const node = meta.node;
    if ((node.chunks || []).length <= 1) {
      const data = this.#fetchVerifiedSync(meta.offset, meta.length, node.hash);
      return data.slice(pos, pos + len);
    }
    const first = Math.floor(pos / CHUNK_SIZE);
    const last = Math.floor((pos + len - 1) / CHUNK_SIZE);
    const parts = [];
    for (let i = first; i <= last; i++) {
      const cs = i * CHUNK_SIZE;
      const ce = Math.min(cs + CHUNK_SIZE, meta.length);
      const chunk = this.#fetchVerifiedSync(meta.offset + cs, ce - cs, node.chunks[i]);
      const from = Math.max(pos - cs, 0);
      const to = Math.min(pos + len - cs, ce - cs);
      parts.push(chunk.slice(from, to));
    }
    return concatBytes(parts);
  }

  async #fetchVerified(absOff, len, expectedHash) {
    const data = await this.#source.readAt(absOff, len);
    this.#verifyChunk(absOff, data, expectedHash);
    return data;
  }

  #fetchVerifiedSync(absOff, len, expectedHash) {
    if (typeof this.#source.readAtSync !== "function") {
      throw new Error("source does not support synchronous reads");
    }
    const data = this.#source.readAtSync(absOff, len);
    this.#verifyChunk(absOff, data, expectedHash);
    return data;
  }

  #verifyChunk(absOff, data, expectedHash) {
    if (this.#verifiedChunks.has(absOff)) return;
    if (sha256Hex(data) !== expectedHash) {
      throw new Error(`payload chunk at offset ${absOff} hash mismatch`);
    }
    this.#verifiedChunks.add(absOff);
  }

  async instantiate(component) {
    const idx = typeof component === "number" ? component : this.components.findIndex((c) => c.ref.name === component);
    if (idx < 0) throw new Error(`component '${component}' not found`);
    const comp = this.components[idx];
    return ComponentHandle.create(this, comp);
  }
}

// ---------------------------------------------------------------------------
// Component handle: admission, host ABI, calls
// ---------------------------------------------------------------------------

const FS_IMPORTS = new Set(["open", "read", "readdir", "stat", "seek", "close"]);
const META_IMPORTS = new Set(["self_size", "emit", "log", "abort"]);

function jspiAvailable() {
  return typeof WebAssembly.Suspending === "function" && typeof WebAssembly.promising === "function";
}

class ComponentHandle {
  static async create(artifact, comp) {
    const module = new WebAssembly.Module(comp.bytes);
    // Admission: enumerate imports and resolve against the declared policy,
    // exactly like caf-security does natively (fail-closed).
    const selfRead = artifact.manifest.policy?.self_read !== false;
    for (const imp of WebAssembly.Module.imports(module)) {
      if (imp.module !== "caf") throw new Error(`admission rejected: undeclared import ${imp.module}.${imp.name}`);
      if (FS_IMPORTS.has(imp.name)) {
        if (!selfRead) throw new Error(`admission rejected: caf.${imp.name} but self_read is not granted`);
      } else if (!META_IMPORTS.has(imp.name)) {
        throw new Error(`admission rejected: unknown host function caf.${imp.name}`);
      }
    }

    const useJspi = jspiAvailable();
    const fds = new Map();
    let memory = null;
    let emitted = [];
    let budget = {
      readUsed: 0,
      outputUsed: 0,
      readMax: Number(artifact.manifest.resources?.read_max ?? 1 << 30),
      outputMax: Number(artifact.manifest.resources?.output_max ?? 64 * 1024 * 1024),
    };
    const memory8 = () => new Uint8Array(memory.buffer);
    const readGuestStr = (ptr, len) => utf8.decode(memory8().slice(ptr, ptr + len));

    // payload-fs over the artifact's access-scoped file set. Scopes are
    // tree-relative with a payload name; guests address mounted paths.
    const payloads = artifact.manifest.payloads || [];
    const scope = (comp.ref.access || []).map((s) => {
      const idx = resolvePayloadIndex(payloads, s.payload || "");
      if (idx === null) throw new Error(`access scope '${s.path}': unknown payload '${s.payload}'`);
      return idx === 0 ? s.path : `/${payloads[idx].name}${s.path}`;
    });
    const visible = (path) => {
      if (scope.length === 0) return false;
      return scope.some((sp) => {
        const p = sp.replace(/\/+$/, "");
        return p === "" || path === p || path.startsWith(p + "/");
      });
    };

    const impl = {
      open: (pathPtr, pathLen) => {
        const path = readGuestStr(pathPtr, pathLen);
        if (!visible(path) || !artifact.payloadFiles().includes(path)) return -1;
        let fd = 1;
        while (fds.has(fd)) fd++;
        fds.set(fd, { path, pos: 0 });
        return fd;
      },
      read: async (fd, bufPtr, bufLen) => {
        const f = fds.get(fd);
        if (!f || bufLen <= 0) return -1;
        const n = Math.min(bufLen, artifactFileLen(f.path) - f.pos);
        if (n <= 0) return 0;
        budget.readUsed += n;
        if (budget.readUsed > budget.readMax) return -1;
        try {
          const data = await artifact.readPayloadRange(f.path, f.pos, n);
          memory8().set(data, bufPtr);
          f.pos += n;
          return n;
        } catch {
          return -1;
        }
      },
      readSync: (fd, bufPtr, bufLen) => {
        const f = fds.get(fd);
        if (!f || bufLen <= 0) return -1;
        const n = Math.min(bufLen, artifactFileLen(f.path) - f.pos);
        if (n <= 0) return 0;
        budget.readUsed += n;
        if (budget.readUsed > budget.readMax) return -1;
        try {
          memory8().set(artifact.readPayloadRangeSync(f.path, f.pos, n), bufPtr);
          f.pos += n;
          return n;
        } catch {
          return -1;
        }
      },
      readdir: (pathPtr, pathLen, bufPtr, bufLen) => {
        const path = readGuestStr(pathPtr, pathLen);
        const prefix = path === "/" ? "" : path;
        const names = [];
        for (const p of artifact.payloadFiles()) {
          if (!visible(p)) continue;
          if (p.startsWith(prefix + "/")) {
            const name = p.slice(prefix.length + 1).split("/")[0];
            if (!names.includes(name)) names.push(name);
          }
        }
        const bytes = utf8enc.encode(names.join("\n"));
        if (bytes.length > bufLen) return -1;
        memory8().set(bytes, bufPtr);
        return bytes.length;
      },
      stat: (pathPtr, pathLen) => {
        const path = readGuestStr(pathPtr, pathLen);
        if (!visible(path)) return -1n;
        const len = artifactFileLen(path);
        if (len !== null) return BigInt(len);
        const prefix = path === "/" ? "" : path;
        const isDir = artifact.payloadFiles().some((p) => visible(p) && p.startsWith(prefix + "/"));
        return isDir ? -2n : -1n;
      },
      seek: (fd, offset) => {
        const f = fds.get(fd);
        if (!f || offset < 0n) return -1;
        const len = artifactFileLen(f.path);
        if (offset > BigInt(len)) return -1;
        f.pos = Number(offset);
        return 0;
      },
      close: (fd) => (fds.delete(fd) ? 0 : -1),
      self_size: () => BigInt(artifact.totalSize),
      emit: (ptr, len) => {
        budget.outputUsed += len;
        if (budget.outputUsed > budget.outputMax) return -1;
        emitted.push(memory8().slice(ptr, ptr + len));
        return 0;
      },
      log: (ptr, len) => {
        budget.outputUsed += len;
        if (budget.outputUsed > budget.outputMax) return -1;
        console.log("[caf log]", utf8.decode(memory8().slice(ptr, ptr + len)));
        return 0;
      },
      abort: (code) => { throw new Error(`caf abort(${code})`); },
    };

    function artifactFileLen(path) {
      return artifact.fileLength(path);
    }

    // In JSPI mode payload reads are truly async (HTTP Range per chunk);
    // otherwise they resolve synchronously from the in-memory buffer.
    const imports = { caf: {} };
    for (const [name, fn] of Object.entries(impl)) {
      if (name === "readSync") continue;
      if (name === "read") {
        imports.caf.read = useJspi ? new WebAssembly.Suspending(impl.read) : impl.readSync;
        continue;
      }
      imports.caf[name] = fn;
    }

    const instance = new WebAssembly.Instance(module, imports);
    memory = instance.exports.memory;
    return new ComponentHandle(artifact, instance, useJspi, () => emitted);
  }

  constructor(artifact, instance, jspi, emitted) {
    this.artifact = artifact;
    this.instance = instance;
    this.jspi = jspi;
    this.emitted = emitted;
    this.memory = instance.exports.memory;
  }

  exports() {
    return Object.keys(this.instance.exports).filter((n) => typeof this.instance.exports[n] === "function");
  }

  // For pure scalar functions that never touch the payload (no caf.* imports
  // on the call path): safe to call synchronously in both modes.
  callSync(name, ...args) {
    return this.instance.exports[name](...args);
  }

  async call(name, ...args) {
    const fn = this.instance.exports[name];
    if (this.jspi) {
      if (!this._promising) this._promising = new Map();
      let pf = this._promising.get(name);
      if (!pf) { pf = WebAssembly.promising(fn); this._promising.set(name, pf); }
      return await pf(...args);
    }
    return fn(...args);
  }

  // caf-abi §3: strings lower to (ptr, len) in guest memory; complex results
  // come back packed as (ptr | len<<32). Decoded as UTF-8; JSON.parse if it
  // looks like JSON. Buffers are deallocated after reading.
  async callPacked(name, ...args) {
    const flat = [];
    const allocs = [];
    for (const a of args) {
      if (typeof a === "string") {
        const bytes = utf8enc.encode(a);
        const ptr = this.instance.exports.alloc(bytes.length);
        new Uint8Array(this.memory.buffer).set(bytes, ptr);
        flat.push(ptr, bytes.length);
        allocs.push([ptr, bytes.length]);
      } else {
        flat.push(a);
      }
    }
    const res = await this.call(name, ...flat);
    let value = res;
    if (typeof res === "bigint" || typeof res === "number") {
      const packed = BigInt(res);
      const ptr = Number(packed & 0xffffffffn);
      const len = Number((packed >> 32n) & 0xffffffffn);
      if (len > 0) {
        const bytes = new Uint8Array(this.memory.buffer).slice(ptr, ptr + len);
        const text = utf8.decode(bytes);
        this.instance.exports.dealloc(ptr, len);
        value = text;
        const t = text.trim();
        if (t.startsWith("{") || t.startsWith("[")) {
          try { value = JSON.parse(text); } catch { /* keep as string */ }
        }
      } else {
        value = "";
      }
    }
    for (const [ptr, len] of allocs) this.instance.exports.dealloc(ptr, len);
    return value;
  }
}

// ---------------------------------------------------------------------------
// openCaf — the entry point
// ---------------------------------------------------------------------------

export async function openCaf(input, { fetchMode = "auto", contentKey = null } = {}) {
  // 1. Acquire a backing source.
  let source;
  if (typeof input === "string") {
    source = await openUrl(input, fetchMode);
  } else {
    source = await BufferSource.from(input);
  }

  // 2. Boot area.
  const head = await source.readAt(0, HEADER_SIZE);
  const header = readHeader(head);
  const manifestBytes = await source.readAt(header.manifestOffset, header.manifestLen);
  const directoryBytes = await source.readAt(header.directoryOffset, header.directoryLen);
  const directory = decodeDirectory(directoryBytes);

  const manifestEntry = directory.find((e) => e.tag === TAG_MANIFEST);
  if (!manifestEntry) throw new Error("directory has no manifest entry");
  const manifestHash = sha256Hex(manifestBytes);
  if (manifestHash !== manifestEntry.hash) throw new Error("manifest hash mismatch");

  // Sealed artifact: decrypt with the content key (whole-file mode, §8.1).
  if (header.flags & FLAG_ENCRYPTED) {
    return openSealed(source, header, directory, manifestBytes, manifestHash, contentKey);
  }

  const manifest = decodeCBOR(manifestBytes, 0).value;
  if (header.formatVersion !== manifest.format_version) throw new Error("format version mismatch");

  const interfaceBytes = await source.readAt(header.interfaceOffset, header.interfaceLen);
  const interfaceHash = sha256Hex(interfaceBytes);
  if (interfaceHash !== manifest.hashes.interface || interfaceHash !== manifest.interface.hash) {
    throw new Error("interface hash mismatch");
  }

  if (!manifest.payloads) throw new Error("manifest has no payloads");
  validatePayloads(manifest.payloads);
  for (const p of manifest.payloads) {
    if (p.compressed) {
      throw new Error("payload compression is reserved in format v1 (not yet implemented)");
    }
    verifyTree(p.root);
  }
  for (const comp of manifest.components || []) {
    for (const scope of comp.access || []) {
      const idx = resolvePayloadIndex(manifest.payloads, scope.payload || "");
      if (idx === null) throw new Error(`access scope '${scope.path}': unknown payload '${scope.payload}'`);
      const node = findNode(manifest.payloads[idx].root, scope.path);
      if (!node) throw new Error(`access scope '${scope.path}' not found`);
      if (node.hash !== scope.hash) throw new Error(`access scope '${scope.path}' hash mismatch`);
    }
  }

  // 3. Components (small; read + verify now, payload stays lazy).
  const componentEntries = directory.filter((e) => e.tag === TAG_COMPONENT);
  const components = [];
  const wasmHashes = [];
  for (let i = 0; i < (manifest.components || []).length; i++) {
    const ref = manifest.components[i];
    const entry = componentEntries[i];
    if (!entry) throw new Error("component count mismatch");
    const bytes = await source.readAt(entry.offset, entry.length);
    const h = sha256Hex(bytes);
    if (h !== ref.hash || h !== manifest.hashes.wasm[i] || h !== entry.hash) {
      throw new Error(`component '${ref.name}' hash mismatch`);
    }
    wasmHashes.push(h);
    components.push({ ref, bytes, entry });
  }

  // 4. Root identity.
  const payloadRoots = (manifest.payloads || []).map((p) => p.root.hash);
  const rootHash = computeRootHash(manifestHash, interfaceHash, wasmHashes, payloadRoots);
  if (rootHash !== header.rootHash) throw new Error("root hash mismatch");

  // 5. Signature over the root hash (best-effort: needs WebCrypto Ed25519).
  const signature = await readSignature(source, header, directory, rootHash);

  const artifact = new Artifact(source, header, manifest, directory, components, signature);
  return artifact;
}

// The signature section is a CBOR list of { alg, key_id, pubkey, sig } entries
// over the 32-byte header root hash — the identity of the stored bytes
// (ciphertext for sealed artifacts: Encrypt-then-Sign). Every entry must
// verify; unknown algorithms are a hard error (fail-closed).
async function readSignature(source, header, directory, rootHash) {
  if (!(header.flags & FLAG_SIGNED)) return null;
  const sigEntry = directory.find((e) => e.tag === TAG_SIGNATURE);
  if (!sigEntry) throw new Error("signed artifact has no signature directory entry");
  const sigBytes = await source.readAt(sigEntry.offset, sigEntry.length);
  const list = decodeCBOR(sigBytes, 0).value;
  if (!Array.isArray(list) || list.length === 0) throw new Error("signature section is empty");
  const signers = [];
  let valid = true;
  for (const entry of list) {
    if (entry.alg !== "ed25519") throw new Error(`unknown signature algorithm ${entry.alg}`);
    const fingerprint = sha256Hex(entry.pubkey);
    if (entry.key_id !== fingerprint) throw new Error("signature key_id does not match its public key");
    const v = await tryVerifyEd25519(entry.pubkey, entry.sig, hexToBytes(rootHash));
    if (v === false) throw new Error("invalid signature");
    signers.push({ fingerprint, valid: v });
    if (v !== true) valid = v; // null = unverifiable platform
  }
  return { fingerprint: signers[0].fingerprint, valid, signers };
}

// Open a sealed artifact: verify the ciphertext hash chain, decrypt the
// private manifest, components, and payload blob, and synthesize the
// plaintext manifest view. Requires the whole artifact in memory (the
// whole-file fetch mode — sealed artifacts never use lazy range reads here).
async function openSealed(source, header, directory, envelopeBytes, envelopeHash, contentKeyOpt) {
  if (!contentKeyOpt) {
    throw new Error("artifact is sealed (FLAG_ENCRYPTED); pass { contentKey } (32-byte hex or bytes)");
  }
  const contentKey = typeof contentKeyOpt === "string" ? hexToBytes(contentKeyOpt) : contentKeyOpt;
  if (contentKey.length !== 32) throw new Error("content key must be 32 bytes");
  if (source instanceof RangeSource) {
    // Decryption is async; lazy range reads are not supported for sealed
    // artifacts — download once, then everything is local (§8.1).
    const resp = await fetch(source.url);
    if (!resp.ok) throw new Error(`fetch failed: HTTP ${resp.status}`);
    source = new BufferSource(new Uint8Array(await resp.arrayBuffer()));
  }

  const envelope = decodeCBOR(envelopeBytes, 0).value;
  if (header.formatVersion !== envelope.format_version) throw new Error("format version mismatch");
  if (envelope.encryption?.aead !== "aes-256-gcm" || envelope.encryption?.wrap !== "p256-ecdh-sha256") {
    throw new Error("unsupported encryption parameters");
  }

  const interfaceBytes = await source.readAt(header.interfaceOffset, header.interfaceLen);
  const interfaceHash = sha256Hex(interfaceBytes);
  if (interfaceHash !== envelope.interface.hash) throw new Error("interface hash mismatch");

  // Private manifest.
  const privateEntry = directory.find((e) => e.tag === TAG_PRIVATE);
  if (!privateEntry) throw new Error("sealed artifact has no private manifest entry");
  const privateCt = await source.readAt(privateEntry.offset, privateEntry.length);
  if (sha256Hex(privateCt) !== envelope.private.hash) throw new Error("private manifest hash mismatch");
  const privatePlain = await openChunk(sectionKey(contentKey, "private"), 0, privateCt);
  const priv = decodeCBOR(privatePlain, 0).value;
  if (!priv.payloads) throw new Error("private manifest has no payloads");
  validatePayloads(priv.payloads);
  if (priv.payloads.length !== (envelope.payloads || []).length) {
    throw new Error("private/envelope payload count mismatch");
  }
  for (const payloadRef of priv.payloads) verifyTree(payloadRef.root);
  for (const comp of priv.components || []) {
    for (const scope of comp.access || []) {
      const idx = resolvePayloadIndex(priv.payloads, scope.payload || "");
      if (idx === null) throw new Error(`access scope '${scope.path}': unknown payload '${scope.payload}'`);
      const node = findNode(priv.payloads[idx].root, scope.path);
      if (!node) throw new Error(`access scope '${scope.path}' not found`);
      if (node.hash !== scope.hash) throw new Error(`access scope '${scope.path}' hash mismatch`);
    }
  }

  // Components: ciphertext hash check, decrypt, plaintext hash check.
  const componentEntries = directory.filter((e) => e.tag === TAG_COMPONENT);
  if (componentEntries.length !== (envelope.components || []).length) throw new Error("component count mismatch");
  const components = [];
  const wasmHashes = [];
  for (let i = 0; i < envelope.components.length; i++) {
    const section = envelope.components[i];
    const entry = componentEntries[i];
    const ct = await source.readAt(entry.offset, entry.length);
    const h = sha256Hex(ct);
    if (h !== section.hash || h !== entry.hash) throw new Error(`sealed component ${i} hash mismatch`);
    const plain = await openChunk(sectionKey(contentKey, `component/${i}`), 0, ct);
    const ref = priv.components[i];
    if (sha256Hex(plain) !== ref.hash) throw new Error(`component '${ref.name}' plaintext hash mismatch`);
    wasmHashes.push(h);
    components.push({ ref: { ...ref, length: plain.length }, bytes: plain, entry });
  }

  // Payload blobs: verify each ciphertext hash, then decrypt per chunk.
  const blobEntries = directory.filter((e) => e.tag === TAG_PAYLOAD);
  if (blobEntries.length !== envelope.payloads.length) throw new Error("payload blob count mismatch");
  const blobs = [];
  const starts = [];
  const blobHashes = [];
  for (let i = 0; i < envelope.payloads.length; i++) {
    const blobRef = envelope.payloads[i];
    const payloadRef = priv.payloads[i];
    if (payloadRef.name !== blobRef.name) throw new Error(`private/envelope payload name mismatch at index ${i}`);
    const blobEntry = blobEntries[i];
    const blob = await source.readAt(blobEntry.offset, blobEntry.length);
    const blobHash = sha256Hex(blob);
    if (blobHash !== blobRef.hash || blobHash !== blobEntry.hash) throw new Error(`payload blob '${blobRef.name}' hash mismatch`);
    const paddedLength = Number(blobRef.padded_length);
    const chunkCount = Math.ceil(paddedLength / CHUNK_SIZE);
    if (chunkCount !== blobRef.chunks) throw new Error("payload chunk count mismatch");
    const payloadKey = sectionKey(contentKey, `payload/${i}`);
    const plainParts = [];
    for (let c = 0; c < chunkCount; c++) {
      const cs = c * CHUNK_SIZE;
      const ce = Math.min(cs + CHUNK_SIZE, paddedLength);
      const ctOff = c * (CHUNK_SIZE + AEAD_TAG_LEN);
      const ct = blob.slice(ctOff, ctOff + (ce - cs) + AEAD_TAG_LEN);
      if (sha256Hex(ct) !== payloadRef.chunks[c]) throw new Error(`payload chunk ${c} ciphertext hash mismatch`);
      plainParts.push(await openChunk(payloadKey, c, ct));
    }
    const map = new Map();
    let at = 0;
    for (const f of collectFiles(payloadRef.root, "", [])) { map.set(f.path, at); at += f.node.length; }
    blobs.push(concatBytes(plainParts));
    starts.push(map);
    blobHashes.push(blobHash);
  }

  // Root identity over the stored (ciphertext) sections, then the signature.
  const rootHash = computeRootHash(envelopeHash, interfaceHash, wasmHashes, blobHashes);
  if (rootHash !== header.rootHash) throw new Error("root hash mismatch");
  const signature = await readSignature(source, header, directory, rootHash);

  // Synthesize the plaintext manifest view.
  const manifest = {
    name: priv.name,
    version: priv.version,
    format_version: envelope.format_version,
    interface: envelope.interface,
    components: priv.components,
    capabilities: envelope.capabilities,
    execution: envelope.execution,
    resources: envelope.resources,
    policy: envelope.policy,
    provenance: priv.provenance,
    payloads: priv.payloads,
    hashes: { interface: interfaceHash, wasm: wasmHashes, payload: blobHashes },
  };
  const sealed = { blobs, starts };
  return new Artifact(source, header, manifest, directory, components, signature, sealed);
}

async function tryVerifyEd25519(pubkey, sig, msg) {
  try {
    if (!crypto?.subtle) return null;
    const key = await crypto.subtle.importKey("raw", pubkey, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, msg);
  } catch {
    return null; // platform without Ed25519: unknown, not invalid
  }
}

// URL loading. fetchMode: "auto" probes with a Range request (206 + JSPI →
// true range mode; otherwise whole-file fallback); "whole" forces one GET (no
// access-pattern leakage, the mode sealed artifacts use); "range" requires
// Range+JSPI and fails otherwise.
async function openUrl(url, fetchMode = "auto") {
  if (fetchMode === "whole") {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`fetch failed: HTTP ${resp.status}`);
    return new BufferSource(new Uint8Array(await resp.arrayBuffer()));
  }
  const probe = await fetch(url, { headers: { Range: `bytes=0-${HEADER_SIZE - 1}` } });
  if (probe.status === 206) {
    const total = respContentRangeTotal(probe);
    const head = new Uint8Array(await probe.arrayBuffer());
    if (total !== null && jspiAvailable()) {
      const src = new RangeSource(url, total, head);
      src.bytesFetched += head.length;
      return src;
    }
    if (fetchMode === "range") throw new Error("fetchMode 'range' requires JSPI (WebAssembly.Suspending)");
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`fetch failed: HTTP ${resp.status}`);
    return new BufferSource(new Uint8Array(await resp.arrayBuffer()));
  }
  if (!probe.ok) throw new Error(`fetch failed: HTTP ${probe.status}`);
  if (fetchMode === "range") throw new Error("fetchMode 'range' but the server does not support Range");
  return new BufferSource(new Uint8Array(await probe.arrayBuffer()));
}

function respContentRangeTotal(resp) {
  const cr = resp.headers.get("Content-Range");
  if (!cr) return null;
  const m = cr.match(/bytes\s+\d+-\d+\/(\d+|\*)/);
  return m && m[1] !== "*" ? Number(m[1]) : null;
}

// Convenience: open the first component directly.
export async function openComponent(input, component, options = {}) {
  const artifact = await openCaf(input, options);
  const comp = await artifact.instantiate(component ?? 0);
  return { artifact, comp };
}

// ---------------------------------------------------------------------------
// Worker mode: run the component in a Web Worker with a watchdog timeout.
//
// For untrusted artifacts. The JS host cannot meter CPU fuel or guest memory;
// instead, every call races a timer and the worker is terminated on overrun —
// a best-effort backstop, not deterministic budget enforcement. Note that
// calls cross postMessage, so hot paths (e.g. per-point reprojection while
// rendering) belong on the main thread with trusted artifacts.
// ---------------------------------------------------------------------------

export function openCafWorker(input, { component, timeout = 30000, options = {} } = {}) {
  const worker = new Worker(new URL("./caf.worker.js", import.meta.url), { type: "module" });
  let nextId = 1;
  let dead = false;
  const pending = new Map();

  worker.onmessage = (e) => {
    const { id, ok, value, error } = e.data;
    const p = pending.get(id);
    if (!p) return;
    pending.delete(id);
    clearTimeout(p.timer);
    if (ok) p.resolve(value);
    else p.reject(new Error(error));
  };

  function send(op, payload, transfer) {
    return new Promise((resolve, reject) => {
      if (dead) return reject(new Error("caf worker is terminated"));
      const id = nextId++;
      const timer = setTimeout(() => {
        dead = true;
        pending.clear();
        worker.terminate();
        reject(new Error(`caf worker call '${op}' exceeded ${timeout}ms — worker terminated`));
      }, timeout);
      pending.set(id, { resolve, reject, timer });
      worker.postMessage({ id, op, ...payload }, transfer || []);
    });
  }

  // File/Blob and ArrayBuffer are structured-cloneable into the worker;
  // strings (URLs) too. `options` (contentKey for sealed artifacts) rides along.
  return (async () => {
    const meta = await send("open", { source: input, component, options });
    return {
      mode: "worker",
      artifact: meta,
      callPacked: (name, ...args) => send("callPacked", { name, args }),
      call: (name, ...args) => send("call", { name, args }),
      stats: () => send("stats", {}),
      terminate() {
        dead = true;
        worker.terminate();
      },
    };
  })();
}

export default { openCaf, openComponent, openCafWorker, Artifact, decodeCBOR };
