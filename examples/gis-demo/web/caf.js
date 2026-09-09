// CAF container host runtime.
//
// This layer understands the CAF *container* (header, canonical-CBOR manifest,
// payload tree, component bytes). It does NOT understand any GIS format —
// that knowledge lives entirely inside the WASM component. It exposes a
// read-only `payload-fs` host ABI (open/read/readdir/close) that the WASM
// component uses to read the payload by path, never by offset or format.
(function (global) {
  "use strict";

  const MAGIC = "CAF\0";

  function utf8Decode(bytes) {
    return new TextDecoder().decode(bytes);
  }

  function utf8Encode(s) {
    return new TextEncoder().encode(s);
  }

  // Minimal canonical-CBOR decoder (definite-length maps/arrays, text/bytes,
  // ints, bools, null, floats). Sufficient for the CAF manifest.
  function decodeCBOR(data, offset) {
    const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const first = data[offset];
    const major = first >> 5;
    const info = first & 0x1f;
    let pos = offset + 1;

    function arg() {
      if (info < 24) return info;
      if (info === 24) {
        const v = data[pos];
        pos += 1;
        return v;
      }
      if (info === 25) {
        const v = (data[pos] << 8) | data[pos + 1];
        pos += 2;
        return v;
      }
      if (info === 26) {
        const v = dv.getUint32(pos);
        pos += 4;
        return v;
      }
      if (info === 27) {
        const v = Number(dv.getBigUint64(pos));
        pos += 8;
        return v;
      }
      throw new Error("bad cbor length");
    }

    let value;
    switch (major) {
      case 0:
        value = arg();
        break;
      case 1:
        value = -1 - arg();
        break;
      case 2: {
        const len = arg();
        value = data.slice(pos, pos + len);
        pos += len;
        break;
      }
      case 3: {
        const len = arg();
        value = utf8Decode(data.slice(pos, pos + len));
        pos += len;
        break;
      }
      case 4: {
        const len = arg();
        value = [];
        for (let i = 0; i < len; i++) {
          const r = decodeCBOR(data, pos);
          value.push(r.value);
          pos = r.next;
        }
        break;
      }
      case 5: {
        const len = arg();
        value = {};
        for (let i = 0; i < len; i++) {
          const k = decodeCBOR(data, pos);
          const v = decodeCBOR(data, k.next);
          value[k.value] = v.value;
          pos = v.next;
        }
        break;
      }
      case 6: {
        arg(); // tag
        const inner = decodeCBOR(data, pos);
        value = inner.value;
        pos = inner.next;
        break;
      }
      case 7:
        if (info === 20) value = false;
        else if (info === 21) value = true;
        else if (info === 22) value = null;
        else if (info === 26) {
          value = dv.getFloat32(pos);
          pos += 4;
        } else if (info === 27) {
          value = dv.getFloat64(pos);
          pos += 8;
        } else {
          throw new Error("bad simple value");
        }
        break;
      default:
        throw new Error("bad major type");
    }
    return { value, next: pos };
  }

  function walkPayload(node, parent, files) {
    const path =
      node.name === "" ? parent : parent === "" ? "/" + node.name : parent + "/" + node.name;
    if (node.kind === "file") {
      files.set(path, { offset: node.offset, length: node.length, hash: node.hash });
    } else if (node.entries) {
      for (const c of node.entries) walkPayload(c, path, files);
    }
  }

  function parseCaf(arrayBuffer) {
    const data = new Uint8Array(arrayBuffer);
    const dv = new DataView(arrayBuffer);

    if (utf8Decode(data.slice(0, 4)) !== MAGIC) {
      throw new Error("not a CAF file (bad magic)");
    }

    const header = {
      formatVersion: dv.getUint32(4, true),
      headerSize: dv.getUint16(8, true),
      flags: dv.getUint16(10, true),
      manifestOffset: Number(dv.getBigUint64(12, true)),
      manifestLen: Number(dv.getBigUint64(20, true)),
      interfaceOffset: Number(dv.getBigUint64(28, true)),
      interfaceLen: Number(dv.getBigUint64(36, true)),
      directoryOffset: Number(dv.getBigUint64(44, true)),
      directoryLen: Number(dv.getBigUint64(52, true)),
      rootHash: Array.from(data.slice(60, 92))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
    };

    const manifest = decodeCBOR(data, header.manifestOffset).value;

    const files = new Map();
    for (const p of manifest.payloads || []) {
      walkPayload(p.root, "", files);
    }

    let wasm = null;
    if (manifest.components && manifest.components.length > 0) {
      const c = manifest.components[0];
      wasm = data.slice(c.offset, c.offset + c.length);
    }

    return { header, manifest, files, wasm };
  }

  // Instantiate the WASM component against the payload-fs host ABI.
  async function instantiate(wasm, files, fileBuffer) {
    const fdTable = new Map();
    let nextFd = 1;
    let memory = null;

    const memory8 = () => new Uint8Array(memory.buffer);
    const readString = (ptr, len) => utf8Decode(memory8().slice(ptr, ptr + len));

    const imports = {
      caf: {
        open: (pathPtr, pathLen) => {
          const path = readString(pathPtr, pathLen);
          const f = files.get(path);
          if (!f) return -1;
          const fd = nextFd++;
          fdTable.set(fd, { offset: f.offset, length: f.length, pos: 0 });
          return fd;
        },
        read: (fd, bufPtr, bufLen) => {
          const f = fdTable.get(fd);
          if (!f) return -1;
          const remaining = f.length - f.pos;
          if (remaining <= 0) return 0;
          const n = Math.min(bufLen, remaining);
          const src = new Uint8Array(
            fileBuffer,
            f.offset + f.pos,
            n
          );
          memory8().set(src, bufPtr);
          f.pos += n;
          return n;
        },
        close: (fd) => {
          fdTable.delete(fd);
          return 0;
        },
        readdir: (pathPtr, pathLen, bufPtr, bufLen) => {
          const path = readString(pathPtr, pathLen);
          const prefix = path === "/" ? "" : path;
          const names = [];
          for (const p of files.keys()) {
            if (p.startsWith(prefix + "/")) {
              const name = p.slice(prefix.length + 1).split("/")[0];
              if (!names.includes(name)) names.push(name);
            }
          }
          const bytes = utf8Encode(names.join("\n"));
          if (bytes.length > bufLen) return -1;
          memory8().set(bytes, bufPtr);
          return bytes.length;
        },
      },
    };

    const { instance } = await WebAssembly.instantiate(wasm, imports);
    memory = instance.exports.memory;

    // High-level, format-agnostic calls into the component.
    function callFeatures() {
      const res = instance.exports.features(); // BigInt
      const ptr = Number(res & 0xffffffffn);
      const len = Number((res >> 32n) & 0xffffffffn);
      const bytes = memory8().slice(ptr, ptr + len);
      const text = utf8Decode(bytes);
      instance.exports.dealloc(ptr, len);
      return JSON.parse(text);
    }

    return {
      instance,
      features: callFeatures,
      reproject: (x, y, from, to) => [
        instance.exports.reproject_x(x, y, from, to),
        instance.exports.reproject_y(x, y, from, to),
      ],
      exports: () => {
        const names = Object.keys(instance.exports);
        return names.filter((n) => typeof instance.exports[n] === "function");
      },
    };
  }

  const CAF = { parseCaf, instantiate, decodeCBOR };
  global.CAF = CAF;
  if (typeof module !== "undefined" && module.exports) module.exports = CAF;
})(typeof self !== "undefined" ? self : globalThis);
