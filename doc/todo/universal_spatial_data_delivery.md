# Universal Spatial Data Delivery

> 本文是愿景文档。USDD 已定位为通用可计算文件格式 **CAF**（`.caf`，见
> [`../spec/container-format.md`](../spec/container-format.md)）的一个 **GIS
> profile**（见 [`../spec/gis-profile.md`](../spec/gis-profile.md)）；文件扩展名
> 统一为 `.caf`，执行 profile 为 `caf-d1`。文中的 `.caf` / `caf-d1` 均按此
> 口径理解。

## 1. 概述

**Universal Spatial Data Delivery（USDD）** 是一种面向空间数据分发的新型计算范式。

传统 GIS 数据交付通常交付的是“数据文件”，使用方需要自行解决文件格式解析、空间索引、坐标系转换、查询、统计、渲染以及运行环境依赖等问题。USDD 的目标是将空间数据、空间计算能力、接口定义与执行约束封装为一个可移植、可验证的计算对象，使使用方不再依赖特定 GIS 软件、数据库或服务端系统。

其核心思想可以概括为：

> **Stop shipping GIS data. Ship spatial capabilities.**

在 USDD 中，一个空间文件不只是被动的数据载体，而是一个具有标准化计算接口的 **Computable Spatial Artifact**：

```text
Computable Spatial Artifact
=
Spatial Data
+ Spatial Index
+ Portable Computation
+ Typed Interface
+ Capability Policy
+ Cryptographic Identity
+ Provenance
```

应用程序不再关注底层数据究竟采用 GeoPackage、GeoParquet、FlatGeobuf、GeoTIFF、PMTiles 或未来的新格式，而只依赖稳定的空间计算接口。

---

## 2. 要解决的问题

今天的空间数据交付高度依赖格式、软件和运行环境。

一个典型 GIS 数据包可能包含：

```text
dataset/
├── buildings.shp
├── buildings.shx
├── buildings.dbf
├── buildings.prj
├── README.pdf
├── example.py
└── environment.yml
```

或者：

```text
dataset.parquet
+
schema.json
+
Python SDK
+
GDAL
+
GEOS
+
PROJ
+
PostGIS
+
API Server
```

使用方需要回答一系列问题：

- 文件是什么格式？
- 使用什么库解析？
- geometry 如何编码？
- CRS 是什么？
- 空间索引如何组织？
- 如何做 bbox query？
- 如何做 intersects / nearest？
- 如何重投影？
- 如何在浏览器展示？
- 是否需要部署 PostGIS / GeoServer？
- Python、JavaScript、Rust 是否得到相同结果？
- 数据发布多年以后，原来的解析和计算逻辑是否还存在？

其本质问题是：

```text
Spatial Data
        +
External Software Stack
        =
Usable GIS Capability
```

数据本身并不具有稳定的“能力接口”。

USDD 希望将这一模式变成：

```text
Computable Spatial Artifact
        =
Usable GIS Capability
```

---

## 3. 核心目标

USDD 希望实现以下目标。

### 3.1 格式透明

应用不需要理解文件内部采用的具体物理格式。

```text
GeoPackage
GeoParquet
FlatGeobuf
GeoTIFF
PMTiles
Custom Format
Future Format
        │
        ▼
Universal Spatial Interface
```

调用方式保持一致：

```python
f = spatial.open("dataset.caf")

f.bounds()
f.query(...)
f.aggregate(...)
f.nearest(...)
f.render(...)
```

---

### 3.2 数据与计算一起分发

文件携带解释和操作自身所需的可移植计算逻辑。

```text
dataset.caf
├── data
├── index
├── spatial.wasm
├── render.wasm
├── manifest
└── signatures
```

计算逻辑采用 WebAssembly / WebAssembly Component Model 等可移植执行技术，并通过类型化接口对外暴露。

---

### 3.3 多语言统一访问

相同文件可以从不同语言调用完全相同的能力。

Python：

```python
f.query(region)
```

JavaScript：

```javascript
await f.query(region)
```

Rust：

```rust
f.query(region)
```

CLI：

```bash
caf query dataset.caf --bbox 120,30,122,32
```

不同语言调用的是相同的文件函数和相同的计算实现。

---

### 3.4 无服务器分发

空间文件可以直接部署在：

```text
S3
OSS
R2
CDN
Nginx
Local File
USB
```

服务端只需要提供普通静态文件和 HTTP Range Request。

不必为只读或分析型空间数据部署：

```text
PostgreSQL
PostGIS
GeoServer
MapServer
Custom REST API
```

因此可以形成：

> **Static hosting, dynamic GIS.**

---

### 3.5 可验证与可长期执行

USDD 不只解决“能运行”，还应解决：

- 谁发布了这个数据？
- 文件是否被修改？
- 使用了哪个算法？
- 计算要求什么权限？
- 最大资源消耗是多少？
- 是否允许访问网络？
- 是否是确定性计算？
- 多年以后能否重新执行？

其目标不是简单的 executable document，而是：

> **Verifiable, capability-constrained and durable spatial computation.**

---

# 4. 核心抽象

USDD 的基本对象定义为：

```text
Computable Spatial Artifact
```

可以形式化表示为：

\[
F = (D, I, C, A, P, V)
\]

其中：

- `D`：Spatial Data
- `I`：Spatial Index
- `C`：Computation
- `A`：Typed API / ABI
- `P`：Capability & Resource Policy
- `V`：Verification & Provenance

传统空间文件主要是：

\[
F = D
\]

Self-describing spatial file：

\[
F = D + Schema + Index
\]

USDD：

\[
\boxed{
F =
Data
+
Index
+
Computation
+
Interface
+
Policy
+
Identity
}
\]

---

# 5. 文件不再暴露格式，而是暴露能力

传统 GIS 应用通常先判断：

```text
这是什么文件？
```

USDD 应用首先询问：

```text
这个文件能做什么？
```

例如：

```python
f.capabilities()
```

返回：

```text
cf:metadata@1
cf:spatial-bounds@1
cf:spatial-query@1
cf:spatial-nearest@1
cf:spatial-aggregate@1
cf:spatial-transform@1
cf:map-render@1
```

应用只依赖接口，不依赖内部格式。

因此 USDD 的核心转变是：

```text
Format Compatibility
        ↓
Interface Compatibility
```

---

# 6. Universal Spatial Interface

USDD 不建议设计一个巨大的 `GIS API`，而应采用小型、可组合、可版本化的能力接口。

## 6.1 Metadata

```text
cf:metadata@1
```

典型函数：

```text
name()
description()
schema()
layers()
crs()
provenance()
```

---

## 6.2 Spatial Bounds

```text
cf:spatial-bounds@1
```

```text
bounds()
extent(layer)
```

---

## 6.3 Spatial Query

```text
cf:spatial-query@1
```

```text
query(
    layer,
    region,
    filter,
    projection
)
```

支持：

```text
bbox query
polygon query
attribute filter
projection
pagination / streaming
```

---

## 6.4 Spatial Relations

```text
cf:spatial-relations@1
```

```text
intersects()
contains()
within()
touches()
distance()
```

---

## 6.5 Nearest Neighbor

```text
cf:spatial-nearest@1
```

```text
nearest(
    layer,
    point,
    k
)
```

---

## 6.6 Spatial Aggregate

```text
cf:spatial-aggregate@1
```

```text
count()
sum()
avg()
min()
max()
group_by()
```

典型调用：

```python
population = f.aggregate(
    region=polygon,
    metric="population",
    op="sum"
)
```

---

## 6.7 CRS / Transform

```text
cf:spatial-transform@1
```

```text
transform_geometry()
reproject()
```

---

## 6.8 Rendering

```text
cf:map-render@1
```

```text
render_tile(z, x, y)
render_region(region, width, height)
```

---

# 7. 最通用的交互模型：Region → Answer

大量 GIS 应用可以归纳为一个非常通用的问题：

> **给我一个区域，告诉我这个区域里面有什么。**

统一抽象：

```text
          Region
            │
            ▼
┌────────────────────────┐
│ Computable Spatial File│
└────────────────────────┘
            │
            ▼
          Answer
```

例如：

### 房地产

```text
某地块附近：
- 学校数量
- 医院数量
- 地铁距离
- 人口
- 建筑面积
```

### 零售选址

```text
门店 3km 范围：
- 人口
- 竞品
- POI
- 道路密度
```

### 城市规划

```text
规划区域：
- 建筑数量
- 道路长度
- 绿地比例
- 常住人口
```

### 物流

```text
配送区域：
- 客户数量
- 道路长度
- 最近仓库
```

### 环境

```text
某流域：
- 土地利用
- 森林覆盖
- 人口
- 污染源
```

USDD 不需要知道业务是什么。

它只提供稳定的空间能力：

```text
query(region)
aggregate(region)
nearest(point)
intersects(region)
render(region)
```

---

# 8. Universal Spatial Data Delivery 架构

```text
                     Application
                         │
                         │ Universal Spatial ABI
                         ▼
              ┌──────────────────────┐
              │ USDD Runtime         │
              │                      │
              │ WASM Runtime         │
              │ Capability Sandbox   │
              │ Resource Metering    │
              │ Verification         │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │ dataset.caf         │
              │                      │
              │ Manifest             │
              │ Spatial Data         │
              │ Spatial Index        │
              │ WASM Components      │
              │ Signatures           │
              └──────────┬───────────┘
                         │
                         │ Range Read
                         ▼
                 Local / S3 / CDN
```

---

# 9. Remote Execution

大型 GIS 数据不能依赖整文件下载。

例如：

```text
world.caf = 500 GB
```

浏览器首次访问只读取：

```text
Bootstrap Header
Manifest
Function Directory
Index Directory
```

例如前几十 KB。

随后调用：

```javascript
f.query({
    bbox: [120, 30, 122, 32]
})
```

文件中的 WASM 根据自身索引计算需要读取的数据块：

```text
query()
  │
  ├── inspect spatial index
  │
  ├── determine required ranges
  │
  ▼
HTTP Range Requests
  │
  ▼
selected chunks only
```

因此：

```text
Remote File
+
HTTP Range
+
Embedded Query Logic
=
Serverless Spatial Query
```

---

# 10. 多文件组合

USDD 不要求所有数据放在一个巨大文件中。

应用可以同时打开：

```text
buildings.caf
roads.caf
population.caf
poi.caf
```

这些文件可以：

- 来自不同机构；
- 使用不同内部格式；
- 使用不同空间索引；
- 使用不同数据布局；
- 使用不同计算实现。

但都暴露统一接口：

```text
cf:spatial-query
cf:spatial-aggregate
cf:spatial-nearest
```

应用：

```python
buildings = caf.open("buildings.caf")
roads = caf.open("roads.caf")
population = caf.open("population.caf")
```

然后：

```python
b = buildings.query(region)
r = roads.query(region)
p = population.aggregate(region)
```

这可以形成：

> **Composable Spatial Computing Objects**

---

# 11. WASM 作为 Spatial File ISA

USDD 的关键技术不是单纯把 WASM 放进文件。

WASM 的角色更接近：

> **Spatial File ISA**

传统模式：

```text
Application
   │
   ▼
GDAL / GEOS / PROJ
   │
   ▼
File Format
   │
   ▼
Data
```

USDD：

```text
Application
   │
   ▼
Universal Spatial ABI
   │
   ▼
WASM
   │
   ▼
Data
```

因此文件内部无论采用：

```text
R-tree
Hilbert Order
QuadTree
Columnar Layout
Tile Layout
Custom Encoding
```

都可以通过相同接口暴露能力。

---

# 12. 安全模型

可执行文件最大的历史问题之一是安全。

USDD 必须从第一版就采用最小权限模型。

默认文件函数只能：

```text
read(self)
allocate(memory)
compute()
return(result)
```

默认不能：

```text
network
filesystem
process
environment
clock
random
device
```

除非由文件显式声明并由运行时授权。

---

## 12.1 Capability Manifest

例如：

```yaml
execution:
  profile: caf-d1
  deterministic: true

capabilities:
  self_read: true
  network: false
  filesystem: false
  clock: false
  random: false

resources:
  memory_max: 256MiB
  cpu_fuel: 100000000
  output_max: 64MiB
```

运行时在执行代码前就可以知道：

```text
它能访问什么？
它最多消耗多少资源？
它是否确定性执行？
```

---

# 13. 资源治理

WASM Sandbox 并不能自动防止资源耗尽。

恶意或异常空间文件可能：

```text
无限循环
超大内存分配
超大输出
解压炸弹
病态 geometry
极端复杂 polygon
```

因此 USDD Runtime 需要限制：

```text
CPU / fuel
memory
stack
self-read bytes
output size
wall time
recursion
```

资源限制必须属于协议的一部分，而不是单纯由实现决定。

---

# 14. 确定性执行

如果 USDD 希望支持：

```text
长期可重现
结果验证
科学计算
政府公开数据
```

就不能只说：

```text
WASM is portable
```

还必须定义 Deterministic Execution Profile。

例如：

```text
caf-d1
```

可以规定：

```text
no network
no clock
no randomness
fixed numeric semantics
canonical NaN behavior
fixed imported interfaces
specified resource behavior
```

目标是：

\[
R =
Execute(
FileID,
FunctionID,
Arguments,
ExecutionProfile
)
\]

对于相同输入得到稳定结果。

---

# 15. Cryptographic Identity

Computable Spatial Artifact 应具有稳定内容身份。

例如：

```text
FileID = SHA256(manifest + data-root + code-root)
```

对于大型文件可以采用：

```text
Merkle Tree / Merkle DAG
```

以支持：

```text
partial verification
HTTP Range verification
incremental update
deduplication
```

文件可分别记录：

```text
Data Hash
Index Hash
WASM Hash
Manifest Hash
Root Hash
```

---

# 16. Provenance 与签名

空间数据和计算代码可能由不同主体提供。

例如：

```text
Data:
  Publisher: Government Agency
  Signature: ...

Algorithm:
  Publisher: Open Source Project
  Signature: ...

Artifact:
  Publisher: Data Provider
  Signature: ...
```

因此 USDD 应区分：

```text
Data provenance
Algorithm provenance
Artifact provenance
```

而不是只有一个简单文件签名。

---

# 17. 可验证计算结果

如果计算函数是确定性的，则结果可以定义内容地址：

\[
ResultID =
H(
FileID,
FunctionID,
Arguments,
ExecutionProfile
)
\]

例如：

```text
dataset.caf
+
population.aggregate
+
region
=
ResultID
```

这意味着不同机构只要使用：

```text
相同文件
相同函数
相同参数
相同执行配置
```

即可验证得到相同结果。

因此 GIS 计算结果可以从：

```text
“某软件算出的一个数字”
```

变成：

> **Verifiable Computational Claim**

---

# 18. Browser Runtime

USDD 的重要运行环境之一是浏览器。

```text
Browser
├── HTTP Range
├── WASM Runtime
├── Component Model
├── Capability Sandbox
├── WebWorker
├── WebGPU (optional)
└── Map Rendering
```

浏览器调用：

```javascript
const f = await SpatialFile.open(url)

const result = await f.query({
    region: polygon
})
```

服务器无需提供：

```text
/api/query
/api/intersects
/api/aggregate
```

只需返回静态字节。

---

# 19. 本地与离线执行

同一个文件可以：

```text
HTTP URL
Local File
USB
Object Storage
Edge Device
```

运行。

例如：

```bash
caf info dataset.caf

caf query dataset.caf \
   --bbox 121,31,122,32
```

无需：

```text
Internet
Database
Cloud Service
Vendor Software
```

因此 USDD 同时适用于：

```text
开放数据
边缘计算
应急场景
科研数据
长期归档
离线分析
```

---

# 20. 与传统 GIS Server 的关系

传统 GIS：

```text
Browser
   │
   ▼
REST / OGC API
   │
   ▼
GeoServer
   │
   ▼
PostGIS
   │
   ▼
Storage
```

USDD：

```text
Browser / Python / Rust
          │
          ▼
      dataset.caf
          │
          ▼
       S3 / CDN
```

USDD 并不是要完全替代 PostGIS。

它更适合：

```text
read-heavy
immutable
versioned
public distribution
analytical
edge / offline
```

而传统数据库仍然更适合：

```text
high-frequency updates
multi-user transactions
server-side authorization
complex cross-dataset joins
high-write workloads
```

---

# 21. 与现有技术的区别

## 21.1 GeoTIFF / GeoPackage / GeoParquet

这些主要解决：

```text
如何存储空间数据
```

USDD 进一步解决：

```text
空间数据应该暴露什么稳定能力
+
这些能力如何随数据一起移动
```

---

## 21.2 COG

COG 使文件内部布局适合 HTTP Range：

```text
File knows how its data should be fetched.
```

USDD 更进一步：

```text
File knows what can be done with its data
and carries the implementation.
```

---

## 21.3 PMTiles

PMTiles 可以把地图 tiles 打包成单文件并通过 Range Request 读取。

USDD 不只提供：

```text
tile retrieval
```

还提供：

```text
query
filter
aggregate
transform
nearest
intersects
render
domain computation
```

---

## 21.4 DuckDB-Wasm

DuckDB-Wasm 的模型是：

```text
Application
+
Database Engine
+
Spatial Extension
+
Data
```

USDD 的模型是：

```text
Computable Spatial Artifact
=
Data
+
Exact Computation
+
Interface
+
Policy
```

其核心区别是：

> **DuckDB-Wasm brings computation to the browser.  
> USDD binds computation to the data.**

---

## 21.5 GeoServer / PostGIS

GeoServer / PostGIS 提供强大的集中式 GIS 服务。

USDD 更关注：

```text
distributed artifact
static hosting
portable computation
offline execution
long-term compatibility
```

二者可以互补。

---

# 22. 应用价值

## 22.1 开放数据

政府或机构今天通常发布：

```text
ZIP
SHP
GeoJSON
CSV
README
```

USDD 可以直接发布：

```text
dataset.caf
```

任何用户都可以：

```text
query
aggregate
render
verify
```

---

## 22.2 GIS 数据供应商

传统交付：

```text
Data
+
SDK
+
Documentation
+
Sample Code
```

USDD：

```text
Computable Spatial Artifact
```

数据供应商交付的不只是数据，而是：

> **Spatial Capability**

---

## 22.3 Web GIS

大量只读 Web GIS 可以不再部署完整服务器栈：

```text
.caf
+
CDN
+
Browser Runtime
```

---

## 22.4 科学数据

算法、数据与版本绑定：

```text
dataset
+
processing implementation
+
execution profile
```

提高长期可复现性。

---

## 22.5 AI / Agent

Agent 不需要学习几十种 GIS 格式。

只需要：

```text
capabilities()
```

然后调用：

```text
query()
aggregate()
nearest()
render()
```

USDD 可以成为 AI Agent 的统一空间数据接口。

---

# 23. 对 AI Agent 的价值

传统 Agent 面对空间数据时需要：

```text
识别格式
选择工具
加载库
解析 schema
构造 SQL
理解 CRS
调用 GIS 软件
```

USDD：

```text
Agent
  │
  ▼
capabilities()
  │
  ▼
typed spatial functions
```

例如：

```text
User:
“这个区域有多少人口？”

Agent:
population.caf
    .aggregate(
        region,
        metric="population"
    )
```

这使空间文件从：

```text
Data Resource
```

变成：

```text
Tool + Data Resource
```

特别适合未来 Agentic Computing。

---

# 24. 第一阶段 MVP

第一版不应该试图实现完整 GIS。

建议只实现五个核心函数：

```text
bounds()
query(region)
aggregate(region)
nearest(point)
render(region)
```

这五个能力已经可以覆盖大量实际场景。

---

## 24.1 MVP 数据

选择一个城市级公开数据集：

```text
buildings
roads
POI
population
administrative boundaries
```

规模：

```text
1–10 GB
```

---

## 24.2 MVP 文件

```text
city.caf
```

内部：

```text
Header
Manifest
Spatial Index
Columnar / Tile Data
WASM Components
Signature
```

---

## 24.3 MVP Runtime

提供：

```text
JavaScript SDK
Python SDK
CLI
```

接口保持一致。

---

## 24.4 MVP Browser Demo

网页：

```text
Drop city.caf
```

自动显示：

```text
Dataset
Layers
Bounds
CRS
Capabilities
Signature
Resource Limits
```

用户可以：

```text
浏览地图
画 Polygon
Spatial Query
Aggregate
Nearest
Render
```

浏览器 Network 面板中只有：

```text
206 Partial Content
```

没有 GIS API。

---

# 25. Demo 的三个 Wow Moment

## Wow Moment 1：无后端 GIS

页面显示：

```text
GIS Server: None
Database: None
Backend API: None
```

但仍然能够：

```text
query
aggregate
render
nearest
```

---

## Wow Moment 2：换一个完全不同的文件格式

例如：

```text
dataset-A.caf
内部 = GeoParquet

dataset-B.caf
内部 = FlatGeobuf

dataset-C.caf
内部 = Custom Format
```

前端代码完全不变：

```javascript
f.query(...)
```

证明：

> **Format disappears behind the interface.**

---

## Wow Moment 3：验证计算

点击：

```text
Inspect Computation
```

显示：

```text
Publisher       ✓
Data Hash       ✓
WASM Hash       ✓
Signature       ✓
Deterministic   Yes
Network         No
Filesystem      No
Memory Limit    256 MB
CPU Budget      ...
```

证明它不是普通的 executable document，而是一个受治理的计算 artifact。

---

# 26. 技术挑战

USDD 需要重点解决以下问题：

### P0

- Minimal Host ABI
- Deterministic Execution Profile
- Capability Security
- Resource Metering
- Stable Interface Model

### P1

- HTTP Range Execution
- Cryptographic Identity
- Provenance
- Versioning
- Interface Negotiation

### P2

- Zero-copy
- Streaming
- SIMD
- GPU Acceleration
- Distributed Dataset
- Cache / Materialized Results

---

# 27. 设计原则

建议 USDD 遵循以下原则。

## 27.1 Interface First

优先定义：

```text
File can do what?
```

而不是：

```text
File bytes are laid out how?
```

---

## 27.2 Minimal Host ABI

宿主接口越小，长期兼容越强。

理想核心 Host ABI：

```text
self.size()
self.read(offset, length)
memory
return
```

---

## 27.3 Immutable by Default

核心 artifact 默认不可变。

计算结果：

```text
external cache
content-addressed result
sidecar
```

避免把系统过早变成数据库。

---

## 27.4 No Ambient Authority

文件代码默认没有：

```text
network
filesystem
clock
random
```

---

## 27.5 Version Everything

分别版本化：

```text
Container Version
Interface Version
Execution Profile Version
Data Schema Version
```

---

## 27.6 Existing Formats Are Carriers

USDD 不应要求所有 GIS 数据迁移到一种全新的物理格式。

可以支持：

```text
GeoPackage + USDD
GeoParquet + USDD
PMTiles + USDD
GeoTIFF + USDD
Custom Container
```

核心标准应更接近：

> **Computable Spatial Artifact Protocol**

而不是单一文件格式。

---

# 28. 长期愿景

USDD 最终希望实现：

```text
Any Spatial Dataset
        │
        ▼
Computable Spatial Artifact
        │
        ▼
Universal Spatial ABI
        │
   ┌────┼────┬────┐
   ▼    ▼    ▼    ▼
Python JS   Rust  Agent
```

应用程序不再关心：

```text
Format
Parser
Library
Index Layout
Codec
Storage Engine
```

它只关心：

```text
Capabilities
```

这意味着空间数据从：

```text
Passive Files
```

升级为：

```text
Portable Spatial Computing Objects
```

最终形成：

> **Universal Spatial Data Delivery**

其核心范式变化是：

```text
Today:

Ship Data
+
Tell users how to use it


Future:

Ship Data
+
The capability to use it
```

最终可以浓缩成三句话：

> **A spatial file should describe what it can do, not merely how its bytes are laid out.**

> **Static hosting should be enough to deliver dynamic spatial capabilities.**

> **Stop shipping GIS data. Ship spatial capabilities.**

