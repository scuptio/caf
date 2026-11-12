# Presenting CAF with the GIS Demo · Talk Track

> English | [简体中文](PRESENTATION.zh-CN.md)

The one-liner to open with:

> **"Stop shipping data. Ship capabilities."**

---

## Act 1 · One file is everything

**Do**: `cd web && python3 -m http.server 8000`, open the browser, `demo.caf`
loads automatically. Click the **Artifact** panel on the right.

**Say**: this `demo.caf` (~31 MB) is not a data file — it is a *computable
artifact*. Packed inside it at once:

- the data (`global.geo.json` + `global.wkb`)
- the interface definition (`gis.wit`, a typed WIT interface)
- portable computation (`gis-demo.wasm`)
- a capability policy + a content-addressed identity (the `root` hash)

**Contrast**: delivering GIS the traditional way means a five-piece set —
`GeoJSON + a frontend rendering library + a backend service + a projection
toolchain`. CAF does it with one file plus one host.

---

## Act 2 · Interface first — the container knows no GIS

**Do**: click the **Capabilities** panel and see the `cf:spatial-transform@1`
badge; click **WASM exports** and see `features()` / `reproject_x` /
`reproject_y`.

**Say**: the container layer has **zero GIS fields** — no CRS, no layers, no
bounds. All GIS semantics are expressed through (a) the WIT interface + (b) the
embedded WASM component. So GIS is just one **profile** of CAF; swap in ML
inference, reporting, or agent tools and the container format does not change by
a single line.

---

## Act 3 · Same dataset, two formats — invisible to the browser

**Do**: click **Payload files** and see two files: `.geo.json` (GeoJSON) and
`.wkb` (an OGC WKB binary stream).

**Say**: the same dataset is packed in two open formats. The WASM component reads
both through **the same read-only `payload-fs` ABI** (`open/read/readdir/close`),
parses each, and de-duplicates by name — proving that "formats are carriers;
capabilities are the deliverable". The browser neither knows nor cares whether it
is JSON or binary inside.

---

## Act 4 · Computation travels with the data (the highlight)

**Do**: switch the **Projection** dropdown (Web Mercator → Equal Earth →
Mollweide → Hammer…). The canvas **reprojects in real time**.

**Say**: both directions of all 7 projections run **locally in WASM** — no
backend, no GDAL, no PostGIS. Traditionally these projection capabilities live in
a backend service or get bundled into a frontend library; CAF binds them to the
data itself — take the file, take the capability.

---

## Act 5 · Minimal privilege, denied by default

**Say** (no clicking; point at the code): the host ABI is only
`open/read/readdir/close` + `memory`, and **everything else is denied by
default** — no network, filesystem, clock, or randomness unless the file
explicitly declares it and the runtime authorizes it. The artifact is
**immutable and content-addressed**; results are cached externally, never written
back.

---

## Act 6 (finale) · Swap the file, keep the host

**Do**: click "Open .caf file" or drag in **any other** `.caf`.

**Say**: the host runtime (`caf.js` in the browser) does not change at all —
a different `.caf` brings a different set of capabilities. That is the final
proof of "interface first + capabilities travel with the data".

---

## Closing

The tradition is to hand data to a pile of external tools for interpretation; CAF
lets data **carry its own interpreter and capabilities**, in one verifiable,
least-privilege, offline-runnable artifact.

> A reminder: the demo currently implements only two capabilities, `features()` +
> `reproject` (`spatial-transform`); `bounds/query/aggregate/nearest/render` in
> `gis-profile.md` are planned extensions. Worth one line while presenting: "adding
> a capability at this level means changing the WIT and swapping the WASM
> component — the container format stays put."
