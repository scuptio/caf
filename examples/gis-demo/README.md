# CAF GIS Demo

> English | [简体中文](README.zh-CN.md)

A pure-frontend **Computable Spatial Artifact** demo: spatial data, interface
definitions, and portable computation (a WASM component) are packed into a single
`.caf` file, which the browser parses and executes locally — **no backend, no
plugins**.

> Core idea: **stop shipping GIS data; ship spatial capabilities.** The browser
> only sees the opaque `.caf` container; whether the payload is GeoJSON or WKB and
> how to parse it is entirely up to the embedded WASM component.

This demo is itself a project that was scaffolded with `caf-tool new` and then
filled with real computation. Below we first walk through **how to build it from
scratch, step by step**, then look at what the final artifact looks like.

## Step by step: from an empty project to a `.caf`

Make sure `caf-tool` is on your `PATH` (or just use `cargo run -p caf-tool -- ...`):

```bash
cargo make install
```

### 0. Generate the empty project with the wizard

```bash
caf-tool new gis-demo --lang rust
cd gis-demo
```

Generated:

```text
gis-demo/
├── build.toml              # caf-tool packaging config (generic skeleton)
├── build.sh
├── Cargo.toml              # Rust crate (generic skeleton)
├── interfaces/gis-demo.wit # placeholder interface (a single ping())
├── src/lib.rs              # minimal component (a single ping())
└── payload/                # empty payload
```

### 1. Define the interface (WIT)

Rename the placeholder interface and replace it with the spatial capability
`spatial-transform`:

```bash
mv interfaces/gis-demo.wit interfaces/gis.wit
```

`interfaces/gis.wit`:

```wit
package cf:gis@0.1.0;

interface spatial-transform {
  reproject-x: func(x: f64, y: f64, from-code: u32, to-code: u32) -> f64;
  reproject-y: func(x: f64, y: f64, from-code: u32, to-code: u32) -> f64;
}

world projection {
  export spatial-transform;
}
```

### 2. Implement the computation (`src/lib.rs`)

Replace the placeholder `ping()` in `src/lib.rs` with real projection + feature
parsing code (see this repo's `src/lib.rs`). It reads the payload through the
read-only `payload-fs` host ABI (`open`/`read`/`readdir`/`close`) and exports
`features()`, `features_from_file()`, `reproject_x()`, `reproject_y()`.

### 3. Point the packaging config at the real component

Edit `build.toml`: align the component name, world, and capabilities with the
interface (keep the wizard's default `gis-demo.wasm` for `path`):

```toml
interfaces = ["interfaces/gis.wit"]

[[components]]
name = "projection"
world = "projection"
path = "gis-demo.wasm"
capabilities = ["cf:spatial-transform@1"]
access = []
```

### 4. Add payload data

Put the source GeoJSON into `payload/data/`, then run `make_data.py` to generate
the second open format (WKB):

```bash
python3 make_data.py
```

### 5. Build the `.caf`

```bash
./build.sh
# or manually:
cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/gis_demo.wasm ./gis-demo.wasm
caf-tool build -c build.toml -o demo.caf
```

`caf-tool` validates the WIT with `wit-parser`, binds `cf:spatial-transform@1` to
the world's `spatial-transform` export, and packs data + interface + wasm + policy
+ identity into a single `demo.caf`.

### 6. Verify and inspect

```bash
caf-tool verify demo.caf
caf-tool inspect demo.caf
```

`inspect` shows the capability badges, the component exports (`reproject`), the
access scopes, and the payload file listing.

### 7. Execute a capability (caf-runtime)

`caf-runtime` verifies the artifact, instantiates the component, enforces the
read-only `payload-fs` ABI + capability policy + fuel limits, then calls the
component function:

```bash
caf-tool run demo.caf --fn reproject_x --args 120,30,4326,3857
# [0] f64: 13358338.895192828

caf-tool run demo.caf --fn features
# [0] i64: 47840777422831640
#     (string) {"crs":"EPSG:4326","features":[...]}
```

## Directory layout

```
gis-demo/
├── build.sh              # one-shot build: compile WASM → generate data → pack .caf
├── build.toml            # caf-tool packaging config (name, interface, payload, components)
├── Cargo.toml            # Rust crate (cdylib → wasm32-unknown-unknown)
├── make_data.py          # converts global.geo.json into the second open format, WKB
├── interfaces/gis.wit    # WIT interface: spatial-transform (reproject capability)
├── src/lib.rs            # data parsing + coordinate projection (compiled to a wasm component)
├── payload/data/         # source data (packed into the .caf payload)
│   ├── global.geo.json   # GeoJSON / RFC 7946 (world country boundaries + China's standard boundary / nine-dash line)
│   └── global.wkb        # WKB stream converted from the .geo.json
├── demo.caf              # the packed artifact (the single deliverable file)
└── web/                  # browser demo (static page + CAF host runtime)
    ├── index.html
    ├── caf.js            # CAF container parsing + chunked lazy verification + payload-fs host ABI + WASM instantiation
    ├── app.js            # rendering / interaction
    ├── caf.test.mjs      # Node smoke test (three loading paths)
    └── demo.caf          # manually copied into web/ for static hosting
```

## Quick start (run the demo directly)

```bash
# 1. (optional) rebuild the .caf (after changing src/lib.rs / the interface / data)
cd examples/gis-demo
bash build.sh

# 2. statically serve the web/ directory (must be started inside web/; demo.caf must be copied in first)
cd web
cp ../demo.caf .
python3 -m http.server 8000

# 3. open http://localhost:8000 in a browser
```

`demo.caf` loads automatically; you can also click "Open .caf file" or drag in any
`.caf` file.

**Loading modes** (chosen automatically by `caf.js`):

- **Range + JSPI**: when the server supports HTTP Range (nginx, CDN, etc.;
  `python3 -m http.server` does not) and the browser supports JSPI, the artifact is
  read in chunks on demand — opening fetches only the boot area and the components,
  and payload chunks are Merkle-verified lazily; the info panel shows the actual
  bytes read.
- **Whole-file fallback**: without Range or JSPI, one GET downloads the whole file,
  followed by chunked lazy verification (same semantics; the bytes are simply all
  local already).
- **Local file**: drag in or pick a `.caf` file (when index.html is opened directly
  via `file://`, `fetch("demo.caf")` fails — a browser restriction; open the file
  manually instead).

Without a backend you can also smoke-test the host runtime with Node directly:

```bash
cargo build -p caf-tool
PATH="$PWD/target/debug:$PATH" bash examples/gis-demo/build.sh
node examples/gis-demo/web/caf.test.mjs   # covers whole-file fallback / Range / in-memory / cross-host consistency
```

Run these commands from the repository root; the Rust `wasm32-unknown-unknown`
target is required (`rustup target add wasm32-unknown-unknown`). `build.sh`
produces the `demo.caf`, `demo-sealed.caf`, and `web/sealed-key.js` needed by the
tests; the CI `js-host` job runs the same build steps before the Node tests.

> Untrusted artifacts can be run in Worker mode (`CAF.openCafWorker(...)`): the
> component runs inside a Web Worker and a main-thread watchdog terminates it on
> timeout — a best-effort backstop against CPU/memory runaway (the JS host cannot
> meter at instruction level); hot paths like rendering should still use
> main-thread mode with trusted artifacts.

## Data and formats

- `payload/data/global.geo.json`: world country boundaries (Polygon +
  MultiPolygon) plus China's nine-dash line (LineString).
- `payload/data/global.wkb`: the second open format converted from the `.geo.json`
  by `make_data.py` (OGC WKB geometries in a length-prefixed stream).

> Coordinates carry 5 decimal places (about 1 m precision, far beyond web-map
> rendering needs) to keep size and mobile memory usage down.

### China map compliance note

The **China national boundary and nine-dash line** in this dataset come from
Alibaba Cloud DataV.GeoAtlas
(`https://geo.datav.aliyun.com/areas_v3/bound/100000*.json`), whose rendering is
consistent with the standard maps of the Ministry of Natural Resources:

- **Taiwan**, **Hong Kong**, and **Macao** are merged into the China boundary as
  Chinese territory (the previously separate Taiwan / Hong Kong / Macao features
  have been removed);
- **South Tibet** and **Aksai Chin** are included in the China boundary per China's
  claim (the India boundary is clipped accordingly);
- The **South China Sea islands** (Xisha/Nansha/Zengmu Ansha, etc.) are merged into
  the China boundary, and the **nine-dash line** is drawn separately
  (`Nine-dash line 1..10` features);
- The previously separate Spratly Is. / Scarborough Reef features have been
  removed.

All other country boundaries are Natural Earth Admin-0 data.

> Note: this demo only showcases the CAF container mechanism. For any official
> release or commercial map use, use the Ministry of Natural Resources' "standard
> map service" and obtain a map review number.

The same dataset is packed in two open formats; the WASM component reads and parses
both through **the same payload-fs host ABI** (`open`/`read`/`readdir`/`close`) and
then de-duplicates by name — proving the component can read either carrier while
the browser perceives no format at all.

## Supported projections

The `reproject(x, y, from-code, to-code)` capability in `interfaces/gis.wit`
supports the following coordinate reference systems (spherical, closed-form or
Newton-iteration formulas; both forward and inverse implemented):

| Projection | Code | Type |
|---|---|---|
| WGS84 | 4326 | geographic (degrees) |
| Web Mercator | 3857 | cylindrical |
| Equal Earth | 8857 | equal-area pseudocylindrical |
| Mollweide | 54009 | equal-area pseudocylindrical |
| Sinusoidal | 54008 | equal-area pseudocylindrical |
| Hammer | 54044 | equal-area (Hammer–Aitoff) |
| Winkel I | 54045 | compromise |

`transform` always routes through 4326, so any two supported projections can
convert to each other.

## How it works

1. **CAF container** (`caf.js`): parses the file header, the canonical-CBOR
   manifest, the payload directory tree, and the component bytes; payload is
   Merkle-verified lazily per 1 MiB chunk at read time, with HTTP Range on-demand
   fetching.
2. **Host ABI**: the browser host exposes a read-only `payload-fs` to the WASM
   component (path-based reads; no offsets/formats exposed) and enforces import
   admission per the policy declared in the manifest.
3. **WASM component** (`src/lib.rs`): implements `features()` (walk `/data`, parse
   each format, return normalized features) and `reproject_*` (coordinate
   transforms).
4. **Rendering** (`app.js`): draws the returned features onto a canvas in the
   selected projection; tiny regions (< 3px) degrade to point markers so they do
   not disappear.

## Build requirements

- Rust toolchain (with the `wasm32-unknown-unknown` target)
- Python 3
- `caf-tool` (`caf/crates/tools`; install with `cargo make install`)
