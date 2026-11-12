# GIS Profile — Spatial Capabilities (WIT)

> English | [简体中文](gis-profile.zh-CN.md)

Version: **0.1.0** · Status: draft

The GIS profile is a **profile** of the CAF container (see
[`../../doc/spec/en/container-format.md`](../../doc/spec/en/container-format.md)). A **Computable Spatial Artifact**
is a `.caf` file that exposes spatial capabilities: its data, index, and
computation all live behind a spatial WIT interface.

```text
Computable Spatial Artifact
=
CAF container
+ spatial WIT world
+ spatial WASM components
+ spatial payload (data + index)
+ capability policy + identity
```

The container-level manifest stays domain-agnostic: no CRS, layers, or bounds
fields. **All GIS semantics are expressed through (a) the WIT interface and (b)
the WASM components that implement it.**

## 1. Capability interfaces (small, composable, versioned)

| Capability | Exports |
|---|---|
| `cf:metadata@1` | `name()`, `description()`, `schema()`, `layers()`, `crs()`, `provenance()` |
| `cf:spatial-bounds@1` | `bounds()`, `extent(layer)` |
| `cf:spatial-query@1` | `query(layer, region, filter, projection)` |
| `cf:spatial-relations@1` | `intersects()`, `contains()`, `within()`, `touches()`, `distance()` |
| `cf:spatial-nearest@1` | `nearest(layer, point, k)` |
| `cf:spatial-aggregate@1` | `count()`, `sum()`, `avg()`, `min()`, `max()`, `group_by()` |
| `cf:spatial-transform@1` | `transform_geometry()`, `reproject()` |
| `cf:map-render@1` | `render_tile(z,x,y)`, `render_region(region,w,h)` |

MVP implements five: `bounds`, `query`, `aggregate`, `nearest`, `render`.

## 2. GIS metadata as WIT functions

GIS metadata (name, description, schema, layers, CRS, provenance, bounds) is
**not** stored in the manifest; it is exposed as WIT functions implemented by
the embedded WASM component. Applications obtain metadata by calling
capabilities, not by reading container fields.

```text
cf:metadata@1        -> name(), description(), schema(), layers(), crs(), provenance()
cf:spatial-bounds@1  -> bounds(), extent(layer)
```

## 3. WIT world

```wit
package cf:gis@0.1.0;

interface types {
  record bounds { min-x: f64, min-y: f64, max-x: f64, max-y: f64 }

  variant geometry {
    point(list<f64>),
    line-string(list<list<f64>>),
    polygon(list<list<list<f64>>>),
  }

  record query-request {
    layer: option<string>,
    region: option<geometry>,
    bbox: option<bounds>,
    filter: option<string>,
    projection: option<list<string>>,
    limit: option<u32>,
    offset: option<u64>,
  }

  record feature {
    id: string,
    geometry: option<geometry>,
    properties: list<tuple<string, string>>,
  }

  record query-result {
    features: list<feature>,
    total: u64,
  }
}

interface metadata {
  name: func() -> string;
  description: func() -> string;
  schema: func() -> string;
  layers: func() -> list<string>;
  crs: func() -> string;
  provenance: func() -> string;
}

interface spatial-bounds {
  use types.{bounds};
  bounds: func() -> bounds;
  extent: func(layer: string) -> bounds;
}

interface spatial-query {
  use types.{query-request, query-result};
  query: func(req: query-request) -> result<query-result, string>;
}

world spatial-file {
  export metadata;
  export spatial-bounds;
  export spatial-query;
  // export spatial-relations;
  // export spatial-nearest;
  // export spatial-aggregate;
  // export spatial-transform;
  // export map-render;
}
```

## 4. Payload conventions

The payload root of a spatial artifact conventionally contains:

```text
/data/        spatial data (GeoParquet / FlatGeobuf / PMTiles / COG / custom)
/index/       spatial index (R-tree / Hilbert / quadtree / tile directory)
```

The embedded component reads the index to determine which data ranges to fetch
(HTTP Range), enabling serverless `query()` over remote hosting.

| Data carrier | Notes |
|---|---|
| GeoParquet | columnar |
| FlatGeobuf | streaming |
| PMTiles / COG | tile directory / range-readable |
| custom | opaque, interpreted by the embedded component |

| Index | Purpose |
|---|---|
| R-tree (rstar) | bbox / polygon / nearest queries |
| Hilbert / GeoHash ordering | clustering, range reads |
| QuadTree / tile directory | `render_tile(z,x,y)` |

## 5. Execution profile

Spatial artifacts run under the generic deterministic profile `caf-d1`
(no network / clock / random, fixed numeric semantics, canonical NaN), so
`(FileId, FunctionId, Args, Profile)` yields the same result everywhere.

## 6. Multi-language access

```python
f = spatial.open("dataset.caf")
f.query(region)          # Python
```

```javascript
await f.query(region)    // JavaScript
```

```rust
f.query(region)?         // Rust
```

```bash
caf query dataset.caf --bbox 120,30,122,32
```

All four call the *same* function in the *same* computation, dispatched by the
codegen-generated bindings.

## 7. MVP

Five core functions cover most real-world scenarios:

```text
bounds()
query(region)
aggregate(region)
nearest(point)
render(region)
```
