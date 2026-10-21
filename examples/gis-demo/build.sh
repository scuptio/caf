#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

# 1. Compile the computation to a WASM module (core wasm + caf host ABI).
cargo build --release --target wasm32-unknown-unknown
cp "$ROOT/target/wasm32-unknown-unknown/release/gis_demo.wasm" "$ROOT/gis-demo.wasm"

# 2. Generate the second data format (WKB) from the source GeoJSON.
python3 "$ROOT/make_data.py"

# 3. Pack data + interface + wasm into a single .caf artifact.
caf-tool build -c "$ROOT/build.toml" -o "$ROOT/demo.caf"

echo "built $ROOT/demo.caf"
