#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
FAAS_ROOT="$(cd "$ROOT/../.." && pwd)"

# 1. Compile the projection computation to a WASM module.
cargo build --manifest-path "$ROOT/projection/Cargo.toml" \
    --target wasm32-unknown-unknown --release
cp "$ROOT/projection/target/wasm32-unknown-unknown/release/gis_projection.wasm" \
    "$ROOT/projection.wasm"

# 2. Generate sample data in two open formats (GeoJSON + WKB).
python3 "$ROOT/make_data.py"

# 3. Pack data + interface + wasm into a single .caf artifact.
cargo run --manifest-path "$FAAS_ROOT/Cargo.toml" -p caf-tool -- \
    build -c "$ROOT/build.toml" -o "$ROOT/demo.caf" \
    --dump-manifest "$ROOT/demo.manifest.json"

# 4. Copy the artifact next to the browser plugin so serving web/ works.
cp "$ROOT/demo.caf" "$ROOT/web/demo.caf"

echo "built $ROOT/demo.caf"
