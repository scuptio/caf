# CAF GIS Demo

一个纯前端的 **可计算空间工件（Computable Spatial Artifact）** 演示：把空间数据、接口定义与可移植计算（WASM 组件）打包进单个 `.caf` 文件，浏览器直接解析并在本地执行，**无后端、无插件**。

> 核心思想：**不再交付 GIS 数据，而是交付空间能力。** 浏览器只看到 `.caf` 这个不透明容器，至于里面是 GeoJSON 还是 WKB、如何解析，全部由内嵌的 WASM 组件决定。

## 目录结构

```
gis-demo/
├── build.sh              # 一键构建：编译 WASM → 生成数据 → 打包 .caf
├── build.toml            # caf-tool 打包配置（名称、接口、payload、组件）
├── make_data.py          # 将 global.geo.json 转换为第二种开放格式 WKB
├── interfaces/gis.wit    # WIT 接口：spatial-transform（reproject 能力）
├── projection/           # Rust → wasm32 组件（数据解析 + 坐标投影）
│   ├── Cargo.toml
│   └── src/lib.rs
├── payload/data/         # 源数据（打包进 .caf 的 payload）
│   ├── global.geo.json   # GeoJSON / RFC 7946（Natural Earth 国家数据）
│   └── global.wkb        # 由 .geo.json 转换生成的 WKB 流
├── projection.wasm       # 编译产物
├── demo.caf              # 打包产物（最终交付的单一文件）
└── web/                  # 浏览器演示（静态页面 + CAF 宿主运行时）
    ├── index.html
    ├── caf.js            # CAF 容器解析 + payload-fs 宿主 ABI + WASM 实例化
    ├── app.js            # 渲染 / 交互
    └── demo.caf          # build.sh 自动复制到此
```

## 快速开始

```bash
# 1.（可选）重新构建 .caf（已改动 projection / 接口 / 数据时）
cd faas/examples/gis-demo
bash build.sh

# 2. 静态托管 web/ 目录（必须在 web/ 内启动）
cd web
python3 -m http.server 8000

# 3. 浏览器打开 http://localhost:8000
```

打开后会自动加载 `demo.caf`；也可以点 "Open .caf file" 或拖入任意 `.caf` 文件。

> 注意：直接双击 `index.html`（`file://`）时 `fetch("demo.caf")` 会失败，需手动打开文件，因此推荐用上面的 HTTP 方式。

## 数据与格式

- `payload/data/global.geo.json`：Natural Earth 全球国家边界（258 个国家/地区，Polygon + MultiPolygon）。
- `payload/data/global.wkb`：由 `make_data.py` 从 `.geo.json` 转换生成的第二种开放格式（OGC WKB 几何，长度前缀流封装）。

同一份数据集以两种开放格式打包，WASM 组件通过**同一个 payload-fs 宿主 ABI**（`open`/`read`/`readdir`/`close`）读取并分别解析，再按名称去重——以此证明组件能读取任一载体，浏览器完全感知不到具体格式。

## 支持的投影

`interfaces/gis.wit` 中的 `reproject(x, y, from, to)` 能力支持以下坐标参考系（球面，闭式或牛顿迭代公式，正反解均实现）：

| 投影 | 代码 | 类型 |
|---|---|---|
| WGS84 | 4326 | 经纬度（度） |
| Web Mercator | 3857 | 圆柱 |
| Equal Earth | 8857 | 等积伪圆柱 |
| Mollweide | 54009 | 等积伪圆柱 |
| Sinusoidal | 54008 | 等积伪圆柱 |
| Hammer | 54044 | 等积（Hammer–Aitoff） |
| Winkel I | 54045 | 折中 |

`transform` 统一「经 4326 中转」，因此任意两个已支持投影之间均可互转。

## 工作原理

1. **CAF 容器**（`caf.js`）：解析文件头、canonical-CBOR manifest、payload 目录树与组件字节。
2. **宿主 ABI**：浏览器宿主向 WASM 组件暴露一个只读的 `payload-fs`（按路径读写，不暴露偏移/格式）。
3. **WASM 组件**（`projection/src/lib.rs`）：实现 `features()`（遍历 `/data`、解析每种格式、返回规范化要素）与 `reproject_*`（坐标变换）。
4. **渲染**（`app.js`）：把返回的要素按所选投影绘制到 canvas；小区域（< 3px）降级为点标记以免消失。

## 构建要求

- Rust 工具链（含 `wasm32-unknown-unknown` target）
- Python 3
- `caf-tool`（`faas/crates/tools`，由 `build.sh` 自动 `cargo run` 调用）
