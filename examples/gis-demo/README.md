# CAF GIS Demo

一个纯前端的 **可计算空间工件（Computable Spatial Artifact）** 演示：把空间数据、接口定义与可移植计算（WASM 组件）打包进单个 `.caf` 文件，浏览器直接解析并在本地执行，**无后端、无插件**。

> 核心思想：**不再交付 GIS 数据，而是交付空间能力。** 浏览器只看到 `.caf` 这个不透明容器，至于里面是 GeoJSON 还是 WKB、如何解析，全部由内嵌的 WASM 组件决定。

这个 demo 本身就是一个「用 `caf-tool new` 脚手架出来、再填上真实计算」的项目。下面先讲**如何从零一步步搭出来**，再看它最终长什么样。

## Step by step：从空项目到 `.caf`

先确保 `caf-tool` 在 `PATH` 上（或直接用 `cargo run -p caf-tool -- ...`）：

```bash
cargo install --path crates/tools
```

### 0. 用 wizard 生成空项目

```bash
caf-tool new gis-demo --lang rust
cd gis-demo
```

生成：

```text
gis-demo/
├── build.toml              # caf-tool 打包配置（通用骨架）
├── build.sh
├── Cargo.toml              # Rust crate（通用骨架）
├── interfaces/gis-demo.wit # 占位接口（一个 ping()）
├── src/lib.rs              # 最小组件（一个 ping()）
└── payload/                # 空 payload
```

### 1. 定义接口（WIT）

把占位接口重命名，并替换成空间能力 `spatial-transform`：

```bash
mv interfaces/gis-demo.wit interfaces/gis.wit
```

`interfaces/gis.wit`：

```wit
package cf:gis@0.1.0;

interface spatial-transform {
  record point {
    x: f64,
    y: f64,
  }

  reproject: func(x: f64, y: f64, from-code: u32, to-code: u32) -> point;
}

world projection {
  export spatial-transform;
}
```

### 2. 实现计算（`src/lib.rs`）

把 `src/lib.rs` 里的占位 `ping()` 换成真正的投影 + 要素解析代码（见本仓库的
`src/lib.rs`）。它通过只读的 `payload-fs` 宿主 ABI（`open`/`read`/`readdir`/`close`）
读取 payload，并导出 `features()`、`features_from_file()`、`reproject_x()`、
`reproject_y()`。

### 3. 让打包配置指向真正的组件

改 `build.toml`：组件名、world、capabilities 与接口对齐（`path` 保持 wizard 默认
的 `gis-demo.wasm` 即可）：

```toml
interfaces = ["interfaces/gis.wit"]

[[components]]
name = "projection"
world = "projection"
path = "gis-demo.wasm"
capabilities = ["cf:spatial-transform@1"]
access = []
```

### 4. 放入 payload 数据

把源 GeoJSON 放进 `payload/data/`，跑 `make_data.py` 生成第二种开放格式（WKB）：

```bash
python3 make_data.py
```

### 5. 构建 `.caf`

```bash
./build.sh
# 或手动：
cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/gis_demo.wasm ./gis-demo.wasm
caf-tool build -c build.toml -o demo.caf
```

`caf-tool` 会用 `wit-parser` 校验 WIT，把 `cf:spatial-transform@1` 绑定到 world 的
`spatial-transform` 导出，再把数据 + 接口 + wasm + 策略 + 身份打成单个 `demo.caf`。

### 6. 校验与查看

```bash
caf-tool verify demo.caf
caf-tool inspect demo.caf
```

`inspect` 会显示 capability 徽章、组件导出（`reproject`）、access scope 与 payload
文件清单。

### 7. 执行能力（caf-runtime）

`caf-runtime` 会校验工件、实例化组件，并强制 `payload-fs` 只读 ABI + 能力策略 +
fuel 限额，然后调用组件函数：

```bash
caf-tool run demo.caf --fn reproject_x --args 120,30,4326,3857
# [0] f64: 13358338.895192828

caf-tool run demo.caf --fn features
# [0] i64: 47840777422831640
#     (string) {"crs":"EPSG:4326","features":[...]}
```

## 目录结构

```
gis-demo/
├── build.sh              # 一键构建：编译 WASM → 生成数据 → 打包 .caf
├── build.toml            # caf-tool 打包配置（名称、接口、payload、组件）
├── Cargo.toml            # Rust crate（cdylib → wasm32-unknown-unknown）
├── make_data.py          # 将 global.geo.json 转换为第二种开放格式 WKB
├── interfaces/gis.wit    # WIT 接口：spatial-transform（reproject 能力）
├── src/lib.rs            # 数据解析 + 坐标投影（编译为 wasm 组件）
├── payload/data/         # 源数据（打包进 .caf 的 payload）
│   ├── global.geo.json   # GeoJSON / RFC 7946（全球国家边界 + 中国合规国界/九段线）
│   └── global.wkb        # 由 .geo.json 转换生成的 WKB 流
├── demo.caf              # 打包产物（最终交付的单一文件）
└── web/                  # 浏览器演示（静态页面 + CAF 宿主运行时）
    ├── index.html
    ├── caf.js            # CAF 容器解析 + 分块懒校验 + payload-fs 宿主 ABI + WASM 实例化
    ├── app.js            # 渲染 / 交互
    ├── caf.test.mjs      # Node 冒烟测试（三种加载路径）
    └── demo.caf          # 手动放入 web/ 以供静态托管
```

## 快速开始（直接跑 demo）

```bash
# 1.（可选）重新构建 .caf（已改动 src/lib.rs / 接口 / 数据时）
cd examples/gis-demo
bash build.sh

# 2. 静态托管 web/ 目录（必须在 web/ 内启动；demo.caf 需先拷入 web/）
cd web
cp ../demo.caf .
python3 -m http.server 8000

# 3. 浏览器打开 http://localhost:8000
```

打开后会自动加载 `demo.caf`；也可以点 "Open .caf file" 或拖入任意 `.caf` 文件。

**加载模式**（`caf.js` 自动选择）：

- **Range + JSPI**：服务器支持 HTTP Range（nginx、CDN 等；`python3 -m http.server`
  不支持）且浏览器支持 JSPI 时，工件按需分块读取——打开只取 boot 区与组件，
  payload 分块 Merkle 校验后懒加载，信息面板可见实际读取字节数。
- **整文件回退**：无 Range 或 JSPI 时一次 GET 下载全文件，随后分块懒校验
  （语义相同，只是字节已全量落地）。
- **本地文件**：拖入/选择 `.caf` 文件（`file://` 直接双击 index.html 时
  `fetch("demo.caf")` 会失败，属浏览器限制，手动打开即可）。

无后端时也可用 Node 直接冒烟测试宿主运行时：

```bash
node examples/gis-demo/web/caf.test.mjs   # 覆盖 整文件回退 / Range / 内存 / 跨宿主一致性
```

> 不可信工件可用 Worker 模式运行（`CAF.openCafWorker(...)`）：组件跑在 Web
> Worker 中，主线程看门狗超时即终止——这是对 CPU/内存失控的尽力兜底（JS 宿主
> 无法做指令级计量），渲染等热路径仍应使用可信工件的主线程模式。

## 数据与格式

- `payload/data/global.geo.json`：全球国家边界（Polygon + MultiPolygon）+ 中国九段线（LineString）。
- `payload/data/global.wkb`：由 `make_data.py` 从 `.geo.json` 转换生成的第二种开放格式（OGC WKB 几何，长度前缀流封装）。

> 坐标为 5 位小数（约 1 米精度，远高于 Web 地图渲染需求），以降低体积与移动端内存占用。

### 中国版图合规说明

数据集中的**中国国界与九段线**采用阿里云 DataV.GeoAtlas（`https://geo.datav.aliyun.com/areas_v3/bound/100000*.json`），其画法与自然资源部标准地图一致：

- **台湾**、**香港**、**澳门**作为中国领土并入中国国界（已移除原先独立的 Taiwan / Hong Kong / Macao 要素）；
- **藏南**、**阿克赛钦**按中国主张划入中国国界（印度国界已相应裁切）；
- **南海诸岛**（西沙/南沙/曾母暗沙等）并入中国国界，并单独绘制**九段线**（`Nine-dash line 1..10` 要素）；
- 移除了原先独立的 Spratly Is. / Scarborough Reef 要素。

其余国家边界为 Natural Earth Admin-0 数据。

> 提示：本演示仅用于展示 CAF 容器机制，若需正式发布/商用地图，应使用自然资源部"标准地图服务"并取得审图号。

同一份数据集以两种开放格式打包，WASM 组件通过**同一个 payload-fs 宿主 ABI**（`open`/`read`/`readdir`/`close`）读取并分别解析，再按名称去重——以此证明组件能读取任一载体，浏览器完全感知不到具体格式。

## 支持的投影

`interfaces/gis.wit` 中的 `reproject(x, y, from-code, to-code)` 能力支持以下坐标参考系（球面，闭式或牛顿迭代公式，正反解均实现）：

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

1. **CAF 容器**（`caf.js`）：解析文件头、canonical-CBOR manifest、payload 目录树与组件字节；payload 按 1 MiB 分块在读取时做 Merkle 校验（懒校验），支持 HTTP Range 按需取块。
2. **宿主 ABI**：浏览器宿主向 WASM 组件暴露一个只读的 `payload-fs`（按路径读写，不暴露偏移/格式），并按 manifest 声明的策略做导入准入检查。
3. **WASM 组件**（`src/lib.rs`）：实现 `features()`（遍历 `/data`、解析每种格式、返回规范化要素）与 `reproject_*`（坐标变换）。
4. **渲染**（`app.js`）：把返回的要素按所选投影绘制到 canvas；小区域（< 3px）降级为点标记以免消失。

## 构建要求

- Rust 工具链（含 `wasm32-unknown-unknown` target）
- Python 3
- `caf-tool`（`caf/crates/tools`，`cargo install --path crates/tools` 安装）
