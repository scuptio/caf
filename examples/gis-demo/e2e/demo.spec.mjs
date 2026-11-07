// Browser e2e for the CAF gis-demo: drives the real page in Chrome via
// playwright-core (channel "chrome" — uses the system browser, no download).
//
//   cd examples/gis-demo/e2e && npm install && node demo.spec.mjs
//
// Covers: page load with demo.caf over HTTP, canvas actually rendering,
// projection switch re-render, GeoJSON/WKB format equivalence, and the
// Worker host mode.

import http from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";

const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../web");

let failures = 0;
function ok(label) { console.log(`PASS ${label}`); }
function fail(label, err) { failures++; console.log(`FAIL ${label}: ${err?.message ?? err}`); }

const MIME = { ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".caf": "application/octet-stream", ".css": "text/css" };

function serve() {
  const server = http.createServer(async (req, res) => {
    const urlPath = decodeURIComponent(new URL(req.url, "http://x").pathname);
    const file = path.join(webDir, urlPath === "/" ? "index.html" : urlPath);
    if (!file.startsWith(webDir)) { res.writeHead(403).end(); return; }
    try {
      const data = await readFile(file);
      res.writeHead(200, { "Content-Type": MIME[path.extname(file)] ?? "application/octet-stream" });
      res.end(data);
    } catch {
      res.writeHead(404).end();
    }
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port }));
  });
}

// Count canvas pixels differing from the page background (#12141a).
async function nonBgPixels(page) {
  return page.evaluate(() => {
    const c = document.getElementById("map");
    const ctx = c.getContext("2d");
    const d = ctx.getImageData(0, 0, c.width, c.height).data;
    let n = 0;
    for (let i = 0; i < d.length; i += 16) {
      if (Math.abs(d[i] - 0x12) > 8 || Math.abs(d[i + 1] - 0x14) > 8 || Math.abs(d[i + 2] - 0x1a) > 8) n++;
    }
    return n;
  });
}

async function main() {
  const { server, port } = await serve();
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  try {
    const page = await browser.newPage();
    page.on("pageerror", (e) => console.log("  [pageerror]", e.message));

    await page.goto(`http://127.0.0.1:${port}/`);

    // 1. demo.caf loads and features render.
    await page.waitForFunction(
      () => document.getElementById("status")?.textContent.includes("features"),
      { timeout: 30000 }
    );
    const status = await page.textContent("#status");
    if (!/\d{3,} features/.test(status)) throw new Error(`unexpected status: ${status}`);
    ok(`page load (${status.trim()})`);

    // 2. Canvas actually rendered geometry.
    const px = await nonBgPixels(page);
    if (px < 1000) throw new Error(`canvas looks blank (${px} non-bg pixels)`);
    ok(`canvas rendered (${px} non-bg pixels)`);

    // 3. Projection switch re-renders (pixels change).
    await page.selectOption("#projSelect", "54009");
    await page.waitForTimeout(300);
    const px2 = await nonBgPixels(page);
    if (px2 < 1000 || px2 === px) throw new Error("projection switch did not re-render");
    ok(`projection switch to Mollweide (${px2} pixels)`);

    // 4. WKB and GeoJSON decode to the same feature count.
    await page.check("#fmtWkb");
    await page.waitForFunction(
      (prev) => document.getElementById("status")?.textContent.includes("features")
        && !document.getElementById("status")?.textContent.includes(prev),
      status.includes("geo.json") ? "geo.json" : "wkb",
      { timeout: 30000 }
    );
    const status2 = await page.textContent("#status");
    const count = (s) => s.match(/(\d+) features/)?.[1];
    if (count(status2) !== count(status)) {
      throw new Error(`format mismatch: ${status} vs ${status2}`);
    }
    ok(`WKB ≡ GeoJSON (${count(status2)} features)`);

    // 5. Worker host mode loads and computes.
    const workerFeatures = await page.evaluate(async () => {
      const CAF = await import("./caf.js");
      const w = await CAF.openCafWorker("demo.caf");
      const r = await w.callPacked("features_from_file", "global.wkb");
      w.terminate();
      return r?.features?.length ?? -1;
    });
    if (workerFeatures < 200) throw new Error(`worker returned ${workerFeatures} features`);
    ok(`worker mode (${workerFeatures} features)`);
  } catch (e) {
    fail("demo page", e);
  } finally {
    await browser.close();
    server.close();
  }

  if (failures) {
    console.log(`\n${failures} failure(s)`);
    process.exit(1);
  }
  console.log("\nall browser e2e tests passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
