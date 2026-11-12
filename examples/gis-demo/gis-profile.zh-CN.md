# GIS Profile —— 空间能力(WIT)

> [English](gis-profile.md) | 简体中文

版本:**0.1.0** · 状态:草案

GIS profile 是 CAF 容器的一个 **profile**(见
[`../../doc/spec/zh-CN/container-format.md`](../../doc/spec/zh-CN/container-format.md))。
**可计算空间工件**是一个暴露空间能力的 `.caf` 文件:它的数据、索引和计算都
位于空间 WIT 接口之后。

```text
可计算空间工件
=
CAF 容器
+ 空间 WIT world
+ 空间 WASM 组件
+ 空间载荷(数据 + 索引)
+ 能力策略 + 身份
```

容器层清单保持领域无关:没有 CRS、图层或 bounds 字段。**所有 GIS 语义都通过
(a) WIT 接口和 (b) 实现它的 WASM 组件来表达。**

## 1. 能力接口(小、可组合、带版本)

| 能力 | 导出 |
|---|---|
| `cf:metadata@1` | `name()`、`description()`、`schema()`、`layers()`、`crs()`、`provenance()` |
| `cf:spatial-bounds@1` | `bounds()`、`extent(layer)` |
| `cf:spatial-query@1` | `query(layer, region, filter, projection)` |
| `cf:spatial-relations@1` | `intersects()`、`contains()`、`within()`、`touches()`、`distance()` |
| `cf:spatial-nearest@1` | `nearest(layer, point, k)` |
| `cf:spatial-aggregate@1` | `count()`、`sum()`、`avg()`、`min()`、`max()`、`group_by()` |
| `cf:spatial-transform@1` | `transform_geometry()`、`reproject()` |
| `cf:map-render@1` | `render_tile(z,x,y)`、`render_region(region,w,h)` |

MVP 实现其中五个:`bounds`、`query`、`aggregate`、`nearest`、`render`。

## 2. 以 WIT 函数表达的 GIS 元数据

GIS 元数据(名称、描述、schema、图层、CRS、来源、bounds)**不**存储在清单
中;它作为由内嵌 WASM 组件实现的 WIT 函数暴露。应用通过调用能力获得元数
据,而不是读取容器字段。

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

## 4. 载荷约定

空间工件的载荷根按约定包含:

```text
/data/        spatial data (GeoParquet / FlatGeobuf / PMTiles / COG / custom)
/index/       spatial index (R-tree / Hilbert / quadtree / tile directory)
```

内嵌组件读取索引以决定取哪些数据区间(HTTP Range),从而在远程托管上实现无
服务端的 `query()`。

| 数据载体 | 说明 |
|---|---|
| GeoParquet | 列式 |
| FlatGeobuf | 流式 |
| PMTiles / COG | 瓦片目录 / 可按范围读取 |
| custom | 不透明,由内嵌组件解读 |

| 索引 | 用途 |
|---|---|
| R-tree(rstar) | bbox / 多边形 / 最近邻查询 |
| Hilbert / GeoHash 排序 | 聚簇、区间读取 |
| QuadTree / 瓦片目录 | `render_tile(z,x,y)` |

## 5. 执行环境配置

空间工件在通用确定性配置 `caf-d1` 下运行(无网络 / 时钟 / 随机数,固定数值
语义,规范 NaN),因此 `(FileId, FunctionId, Args, Profile)` 在任何地方产生
相同结果。

## 6. 多语言访问

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

四种调用经由代码生成的绑定,派发的是*同一个*计算中的*同一个*函数。

## 7. MVP

五个核心函数覆盖大多数真实场景:

```text
bounds()
query(region)
aggregate(region)
nearest(point)
render(region)
```
