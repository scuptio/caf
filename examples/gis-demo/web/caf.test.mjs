// Node smoke test for the CAF JS host runtime (caf.js).
//
// Serves examples/gis-demo over two local HTTP servers — one Range-capable,
// one that always answers 200 with the whole body — and drives demo.caf
// through both paths plus a raw-buffer path.
//
//   node examples/gis-demo/web/caf.test.mjs
//
// Range mode additionally requires JSPI (WebAssembly.Suspending); without it
// the host falls back to a whole-file GET, which the test reports but does
// not fail on.

import http from "node:http";
import { execFileSync } from "node:child_process";
import { readFile, stat as fsStat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as CAF from "./caf.js";

const demoDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(demoDir, "../..");
const cafPath = path.join(demoDir, "demo.caf");

let failures = 0;
function ok(label) {
  console.log(`PASS ${label}`);
}
function fail(label, err) {
  failures++;
  console.log(`FAIL ${label}: ${err?.message ?? err}`);
}

function serve({ range }) {
  const server = http.createServer(async (req, res) => {
    const file = path.join(demoDir, decodeURIComponent(new URL(req.url, "http://x").pathname));
    let data;
    try {
      data = await readFile(file);
    } catch {
      res.writeHead(404).end();
      return;
    }
    const rangeHeader = req.headers.range;
    const m = range && rangeHeader ? rangeHeader.match(/bytes=(\d+)-(\d*)/) : null;
    if (m) {
      const from = Number(m[1]);
      const to = m[2] === "" ? data.length - 1 : Number(m[2]);
      res.writeHead(206, {
        "Content-Range": `bytes ${from}-${to}/${data.length}`,
        "Content-Length": to - from + 1,
      });
      res.end(data.subarray(from, to + 1));
      return;
    }
    res.writeHead(200, { "Content-Length": data.length });
    res.end(data);
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port }));
  });
}

async function exerciseArtifact(label, artifact) {
  if (artifact.name !== "global-countries") throw new Error(`unexpected name ${artifact.name}`);
  const comp = await artifact.instantiate("projection");

  // Scalar path (never touches the payload): sync call works in every mode.
  const x = comp.callSync("reproject_x", 120, 30, 4326, 3857);
  if (Math.abs(x - 13358338.895192828) > 1e-6) throw new Error(`reproject_x off: ${x}`);

  // Packed-result path through the payload: string arg, JSON result.
  const result = await comp.callPacked("features_from_file", "global.wkb");
  if (result?.error) throw new Error(`component error: ${result.error}`);
  if (!result || result.crs !== "EPSG:4326" || !Array.isArray(result.features) || result.features.length < 200) {
    throw new Error("features_from_file returned unexpected shape");
  }
  ok(`${label}: open + instantiate + reproject + features (${result.features.length} features)`);
  return artifact;
}

async function main() {
  const cafStat = await fsStat(cafPath);

  // Path 1: plain server (no Range) → whole-file fallback.
  {
    const { server, port } = await serve({ range: false });
    try {
      const artifact = await exerciseArtifact("whole-file", await CAF.openCaf(`http://127.0.0.1:${port}/demo.caf`));
      const s = artifact.stats();
      if (s.bytesFetched < cafStat.size) throw new Error("fallback should fetch the whole file");
      ok(`whole-file: bytes fetched = ${s.bytesFetched} (file is ${cafStat.size})`);
    } catch (e) {
      fail("whole-file", e);
    } finally {
      server.close();
    }
  }

  // Path 2: Range server. True on-demand mode needs JSPI; otherwise fallback.
  {
    const { server, port } = await serve({ range: true });
    try {
      const artifact = await exerciseArtifact("range", await CAF.openCaf(`http://127.0.0.1:${port}/demo.caf`));
      const s = artifact.stats();
      const jspi = typeof WebAssembly.Suspending === "function";
      if (jspi) {
        if (s.bytesFetched >= cafStat.size) {
          throw new Error(`range mode fetched ${s.bytesFetched} B of ${cafStat.size} B (not lazy)`);
        }
        ok(`range: opened + read features with ${s.bytesFetched} B fetched of ${cafStat.size} B (${s.rangeReads} requests)`);
      } else {
        console.log("SKIP range-laziness: JSPI (WebAssembly.Suspending) not available in this Node");
      }
    } catch (e) {
      fail("range", e);
    } finally {
      server.close();
    }
  }

  // Path 3: raw buffer (file picker equivalent).
  {
    try {
      const buf = await readFile(cafPath);
      await exerciseArtifact("buffer", await CAF.openCaf(new Uint8Array(buf)));
    } catch (e) {
      fail("buffer", e);
    }
  }

  // Cross-host conformance: the native caf-tool and this JS host must produce
  // identical results for the same artifact + function (caf-abi packed-result
  // channel, payload reads, and decoding all line up).
  {
    try {
      const jsResult = await (async () => {
        const buf = await readFile(cafPath);
        const artifact = await CAF.openCaf(new Uint8Array(buf));
        const comp = await artifact.instantiate("projection");
        return comp.callPacked("features");
      })();
      const nativeOut = execFileSync(
        "cargo",
        ["run", "-q", "-p", "caf-tool", "--", "run", cafPath, "--fn", "features"],
        { cwd: repoRoot, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }
      );
      const m = nativeOut.match(/\(string\) (\{.*\})/s);
      if (!m) throw new Error("native run produced no packed string output");
      const nativeResult = JSON.parse(m[1]);
      if (JSON.stringify(jsResult) !== JSON.stringify(nativeResult)) {
        throw new Error("native and JS hosts disagree on features()");
      }
      ok(`cross-host: native == JS on features() (${jsResult.features.length} features, byte-identical JSON)`);
    } catch (e) {
      fail("cross-host", e);
    }
  }

  if (failures) {
    console.log(`\n${failures} failure(s)`);
    process.exit(1);
  }
  console.log("\nall caf.js smoke tests passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
