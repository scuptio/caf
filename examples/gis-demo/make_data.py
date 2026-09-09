#!/usr/bin/env python3
"""Convert the demo `data/global.geo.json` into a second open format.

The source of truth is `payload/data/global.geo.json` (GeoJSON / RFC 7946,
Admin-0 country boundaries + a compliant China boundary, Polygon /
MultiPolygon / LineString). This script converts it to a length-prefixed WKB
stream (`payload/data/global.wkb`) so the demo ships the *same* dataset in two
open formats.

The WASM component reads *both* through the same payload-fs ABI and parses
each format internally — the browser never sees the format.
"""

import json
import struct
import os

GEOJSON = "global.geo.json"
WKB_OUT = "global.wkb"

# China boundary provenance: the `China` feature (and the nine-dash line
# features) are sourced from Alibaba Cloud DataV.GeoAtlas
# (https://geo.datav.aliyun.com/areas_v3/bound/100000*.json), which represents
# Taiwan / 藏南 / 阿克赛钦 / 南海诸岛 consistently with the official Chinese
# standard map. The remaining countries are Natural Earth Admin-0 boundaries.


def geojson_kind(gtype):
    if gtype == "Point":
        return "point"
    if gtype == "LineString":
        return "line"
    if gtype == "Polygon":
        return "polygon"
    if gtype == "MultiPolygon":
        return "multipolygon"
    raise ValueError(f"unsupported geometry type {gtype}")


def wkb_geometry(kind, coords):
    if kind == "point":
        return b"\x01" + struct.pack("<I", 1) + struct.pack("<dd", *coords)
    if kind == "line":
        body = b"".join(struct.pack("<dd", x, y) for x, y in coords)
        return b"\x01" + struct.pack("<I", 2) + struct.pack("<I", len(coords)) + body
    if kind == "polygon":
        body = b"".join(
            struct.pack("<I", len(ring)) + b"".join(struct.pack("<dd", x, y) for x, y in ring)
            for ring in coords
        )
        return b"\x01" + struct.pack("<I", 3) + struct.pack("<I", len(coords)) + body
    if kind == "multipolygon":
        body = b"".join(
            struct.pack("<I", len(poly))
            + b"".join(
                struct.pack("<I", len(ring))
                + b"".join(struct.pack("<dd", x, y) for x, y in ring)
                for ring in poly
            )
            for poly in coords
        )
        return b"\x01" + struct.pack("<I", 6) + struct.pack("<I", len(coords)) + body
    raise ValueError(f"unknown kind {kind}")


def feature_from_geojson(f):
    props = f.get("properties") or {}
    layer = props.get("continent") or ""
    name = props.get("name") or props.get("name_long") or ""
    geom = f.get("geometry") or {}
    kind = geojson_kind(geom.get("type"))
    return layer, name, kind, geom.get("coordinates")


def build_wkb(features):
    out = bytearray()
    out += b"WKBSTREAM" + b"\x01\x00"  # magic + version
    for layer, name, kind, coords in features:
        layer_b = layer.encode("utf-8")
        name_b = name.encode("utf-8")
        geom = wkb_geometry(kind, coords)
        out += struct.pack("<I", len(layer_b)) + layer_b
        out += struct.pack("<I", len(name_b)) + name_b
        out += struct.pack("<I", len(geom)) + geom
    return bytes(out)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(here, "payload", "data")
    src = os.path.join(data_dir, GEOJSON)

    with open(src) as f:
        fc = json.load(f)

    features = [feature_from_geojson(f) for f in fc.get("features", [])]

    with open(os.path.join(data_dir, WKB_OUT), "wb") as f:
        f.write(build_wkb(features))

    kinds = {}
    for layer, name, kind, coords in features:
        kinds[kind] = kinds.get(kind, 0) + 1

    print(f"read {len(features)} features from payload/data/{GEOJSON}")
    print(f"wrote {len(features)} features to payload/data/{WKB_OUT} "
          f"(by kind: {kinds})")


if __name__ == "__main__":
    main()
