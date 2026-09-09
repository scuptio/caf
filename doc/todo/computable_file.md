# 可计算文件（Computable File）设计文档

> 状态：草案 v0.1 · 主题：**通用「包含计算的文件」格式规范**
>
> GIS（空间数据交付）只是本格式的第一个应用场景，不是格式本身的目标。
> 本格式描述的是一个通用抽象：**把数据、接口定义与可移植计算打包为单一、
> 可验证、可长期执行的文件对象。**

---

## 0. 定位与原则

### 0.1 我们要构建什么

一个**通用的、自描述、可执行、可验证的文件容器**。文件内部携带：

1. 清单（manifest）
2. 数据类型与函数定义（接口，WIT / WIT-like）
3. 一个或多个 WASM 组件（计算实现）
4. 可选签名
5. 可选安全与信任信息
6. 数据 payload

应用程序通过**稳定接口**调用文件的能力，而不关心数据物理格式、解析库、
运行环境。

```
传统文件：  data + (外部软件栈) = 能力
可计算文件：data + 接口定义 + 计算实现 + 策略 + 身份 = 能力
```

### 0.2 核心原则

- **Interface First**：先定义「文件能做什么」，再谈「字节如何布局」。
- **Minimal Host ABI**：宿主接口越小，长期兼容越强。
- **No Ambient Authority**：文件内代码默认无网络/文件系统/时钟/随机数。
- **Immutable by Default**：内容寻址，不可变，结果外部缓存。
- **Version Everything**：容器、接口、执行 profile、数据 schema 分别版本化。
- **Existing Formats Are Carriers**：不强制迁移到新物理格式，任何格式都可作为
  payload 的载体。

### 0.3 命名（工作名，可改）

- 对象：**Computable File / Computable Artifact**（可计算文件 / 可计算工件）
- 容器格式：**CAF（Computable Artifact Format）**（暂定）
- 文件扩展名：`.caf`（暂定）
- CLI：`caf`（暂定）

> 名称与扩展名均为工作名，待最终确认后统一替换。

---

## 1. 文件规范（File Specification）

### 1.1 总体结构

所有整数小端序，偏移为相对文件头部的字节偏移，section 按需对齐（默认 8 字节）。

```text
+-----------------------------------+
| Magic            "CAF\0" (4B)     |
| Format Version   u32              |
| Header Size      u16              |
| Flags            u16              |
+-----------------------------------+  <- 固定 Bootstrap Header
| manifest_offset  u64              |
| manifest_len     u64              |
| interface_offset u64              |
| interface_len    u64              |
| directory_offset u64              |
| directory_len    u64              |
| root_hash        [u8;32]          |
+-----------------------------------+
| Manifest         (canonical CBOR) |
+-----------------------------------+
| Interface        (WIT text)       |  <- 数据类型 + 函数定义
+-----------------------------------+
| Section Directory (TOC)           |
+-----------------------------------+
| WASM component #1                 |
| WASM component #2                 |
| ...                               |
+-----------------------------------+
| Payload section(s)  (data)        |
+-----------------------------------+
| Trust / Security info             |  <- 可选
+-----------------------------------+
| Signature                         |  <- 可选
+-----------------------------------+
```

Bootstrap Header 是唯一必须**急切**读取的部分（几十字节）；manifest、interface、
directory 是打开文件时读取的「引导区」（前几十 KB）；payload 与 wasm 组件按
offset + HTTP Range 按需读取。因此一个 500GB 的远程文件可以被浏览器在读取几 KB
后打开并查询。

### 1.2 第 1 部分 — 清单文件（Manifest）

Manifest 是文件的「DNA」，描述文件是什么、能做哪些事、如何校验、受何约束。
序列化为 **canonical CBOR**（键排序、确定性），其哈希参与内容寻址。

```rust
struct Manifest {
    // 身份
    name: String,
    version: String,                 // artifact 版本（semver）
    format_version: u32,             // 容器格式版本

    // 接口：类型与函数定义（见 1.3）
    interface: InterfaceRef,         // 内嵌 WIT 或指向 interface section

    // 计算：一个或多个 wasm 组件
    components: Vec<ComponentRef>,   // name + export map + hash

    // 能力：文件暴露的能力标识（namespace:name@ver）
    capabilities: Vec<CapabilityId>,

    // 执行策略与资源约束
    execution: ExecutionProfile,
    resources: ResourceLimits,

    // 安全与信任（见 1.5）
    policy: CapabilityPolicy,
    provenance: Provenance,
    trust: Option<TrustInfo>,        // 保留字段，供扩展

    // 数据 payload 引用（见 1.6）
    payloads: Vec<PayloadRef>,

    // 内容寻址
    hashes: SectionHashes,           // interface / wasm / payload / manifest / root
}
```

```rust
struct ComponentRef {
    name: String,                    // 组件名
    world: String,                   // 对应 WIT world（= 接口契约）
    offset: u64,
    length: u64,
    hash: [u8; 32],
    exports: Vec<ExportEntry>,       // capability -> export 名 -> 函数签名
}
```

### 1.3 第 2 部分 — 数据类型与函数定义（Interface）

接口是文件的**稳定对外契约**，采用 **WIT**（WebAssembly Component Model 接口语言）
描述。WIT 同时定义：

- **数据类型**：`record` / `variant` / `enum` / `flags` / `type` 别名
- **函数**：`func f(args) -> result<out, err>`

```wit
package example:file@0.1.0;

world computable-file {
    export compute: interface {
        query: func(req: query-request) -> result<query-result, string>;
        aggregate: func(req: aggregate-request) -> result<f64, string>;
    }
}
```

**为什么用 WIT**：`wit-bindgen` 生态可直接从 WIT 生成多语言绑定：

| 语言 | 生成的类型定义 | 生成的能力 |
|---|---|---|
| Rust | `struct` / `enum` | `fn query(req) -> Result<...>` |
| Python（componentize-py） | dataclass / class | `def query(req) -> ...` |
| JavaScript（jco） | class / TS 类型 | `await f.query(req)` |
| C / C++ / Go / ... | struct | 函数调用 |

即：**「数据类型与函数定义」由工具直接生成多种语言的 struct/class 定义与
（在 wasm 中的）函数调用桩**，这正好对应第 2 部分的目标。

**与 hexortex `.hxs` 的关系**：`.hxs` 是一种 WIT-like 的 record schema DSL（tree-sitter
语法 + IR + 校验 + Rust/Py/JS codegen）。它可作为**数据 record schema** 的补充层：
属性/记录结构用 `.hxs` 描述（复用现有工具链），跨语言函数接口用 WIT 描述；工具
可将 `.hxs` 记录编译为 WIT record，二者互通。

> 简言之：WIT 定义「函数接口」；`.hxs`（可选）描述「数据结构」，且可编译到 WIT。

### 1.4 第 3 部分 — 一个或多个 WASM 组件

计算实现以 **WASM 组件**（component model）形式随文件分发，与 WIT world 一一对应。

- 每个组件实现一个或多个 capability 的 export。
- 组件实例化的**宿主 ABI 极小**。核心原语如下：

```text
payload-fs      (类 POSIX 文件系统，作用域 = payload 根目录)
  open(path: string) -> fd
  read(fd: fd, len: u64) -> list<u8>
  readdir(path: string) -> list<entry>
  stat(path: string) -> meta
  seek(fd: fd, offset: u64)
  close(fd: fd)
self.size() -> u64                  (整文件字节数)
memory                              (宿主管理的线性内存)
return                              (组件返回值)
```

- 组件默认**无**网络 / 外部文件系统 / 进程 / 环境变量 / 时钟 / 随机数访问。
  唯一可访问的「文件系统」是 payload 根目录挂载的沙箱虚拟 FS。
- 允许：读自身（payload + manifest）、分配内存、计算、返回结果。

### 1.5 第 4 / 5 部分 — 签名与安全/信任信息

**签名（可选）**：ed25519，覆盖 canonical manifest（进而覆盖所有 section 的 hash）。

**安全与信任信息（可选，保留扩展空间）**：

```yaml
capabilities:          # 文件请求的能力，默认全 false
  self_read: true
  network: false
  filesystem: false
  clock: false
  random: false

resources:             # 运行时强制执行的资源上限
  memory_max: 256MiB
  cpu_fuel: 100000000
  output_max: 64MiB
  wall_time_ms: 5000

execution:             # 执行 profile
  profile: caf-d1      # 确定性 profile
  deterministic: true

provenance:            # 分层来源：data / algorithm / artifact
  data:     { publisher, signature }
  algorithm:{ publisher, signature }
  artifact: { publisher, signature }

trust:                 # 保留字段，供未来扩展
  attestation: ...
  chain_of_custody: ...
  revocation: ...
```

确定性 profile（`caf-d1`）规定：无网络/时钟/随机、固定数值语义、canonical NaN、
冻结的 imported 接口集 —— 使 `Execute(FileId, FunctionId, Args, Profile)` 对相同输入
产生相同结果，从而可做**结果验证**与**长期可复现**。

### 1.6 第 6 部分 — 数据 Payload（虚拟文件系统）

Payload 是文件携带的数据，可包含**一个或多个文件**，组织为**目录结构**
（虚拟文件系统 / 文件树），可命名、可按类型分类：

```rust
struct PayloadRef {
    root: PayloadNode,               // 目录树根节点
    media_type: String,              // 逻辑类型（非物理格式）
    offset: u64,                     // 整棵树的字节范围
    length: u64,
    hash: [u8; 32],                  // 树根哈希（大文件用 Merkle 树）
    compressed: Option<Compression>,
}

struct PayloadNode {
    kind: EntryKind,                 // file | dir
    name: String,
    hash: [u8; 32],
    layout: Option<PayloadLayout>,   // 仅 file：opaque / range / stream
    entries: Vec<PayloadNode>,       // 仅 dir：子节点
}
```

组件通过**类 POSIX 文件系统 API**（`open/read/readdir/stat/seek/close`）
访问 payload 目录，作用域限定为 payload 根（见 §1.4 宿主 ABI）。

- **layout**：`opaque`（整块）/ `range`（支持 Range Read，如列式或分块布局，供大
  文件远程按需读取）/ `stream`（流式）。
- **格式透明**：payload 内部可以是 GeoParquet、FlatGeobuf、PMTiles、COG、任意
  JSON/CSV、模型权重、乃至私有格式 —— 只要接口/组件知道如何解释它。**应用只依赖
  接口，不依赖 payload 物理格式。**
- **只读**：目录结构只读，组件只能 `open/read/readdir/stat/seek/close`，无写入能力
  （保持 Immutable by Default）。

### 1.7 内容寻址与哈希

```text
InterfaceHash = SHA256(WIT 文本)
WasmHash      = SHA256(每个组件的字节)
PayloadHash   = SHA256(payload 字节)（大文件可用 Merkle 树）
ManifestHash  = SHA256(canonical manifest)
RootHash      = SHA256(ManifestHash || InterfaceHash || WasmHash* || PayloadHash*)
FileId        = RootHash
```

对超大 payload，采用 **Merkle Tree / Merkle DAG**，以支持部分校验、HTTP Range
校验、增量更新与去重。

**结果可验证**：

```text
ResultID = H(FileId, FunctionId, CanonicalArgs, ExecutionProfile)
```

---

## 2. 能力模型（Interface / Capability）

文件不暴露「格式」，只暴露「能力」。能力是小型、可组合、可版本化的接口：

```text
cf:metadata@1        cf:compute@1        cf:query@1        cf:aggregate@1
cf:nearest@1         cf:render@1         cf:transform@1    ...
```

- `cf:` 前缀表示「可计算文件通用能力」命名空间。
- GIS 场景把它实例化为 `cf:spatial-query@1`、`cf:map-render@1` 等（见 §4）。
- 其它领域（ML 推理、报表、科学计算、Agent 工具）注册自己的命名空间能力。

应用只需：

```python
f = open("artifact.caf")
f.capabilities()      # -> ["cf:query@1", "cf:aggregate@1", ...]
f.query(...)
f.aggregate(...)
```

---

## 3. 运行与工具链

### 3.1 运行时

- **本地 / 远程 / 浏览器**三种宿主共用同一契约。
- WASM 组件在 `wasmtime`（component model）中运行：fuel 计量、内存上限、
  capability 沙箱、资源限额、确定性 profile、签名校验。
- 打开远程文件只读取 Bootstrap + Manifest + Interface + Directory（几 KB），
  随后由组件根据自身索引决定需要哪些 payload 范围，发起 HTTP Range 请求。

### 3.2 编译工具（Builder）

把「数据 + 接口定义 + 计算代码」编译为一个 `.caf`：

```bash
caf build \
  --wit interface.wit \          # 类型与函数定义
  --component compute.wasm \     # 一个或多个 wasm 组件
  --data payload.bin \           # 数据 payload
  [--sign key.pem] \             # 可选签名
  [--policy policy.yaml] \       # 可选安全/信任信息
  -o artifact.caf
```

### 3.3 代码生成（Codegen）

从 WIT（及可选 `.hxs`）生成多语言绑定：

```bash
caf codegen --wit interface.wit --lang rust   # -> structs + fn stubs
caf codegen --wit interface.wit --lang python
caf codegen --wit interface.wit --lang js
```

生成内容 = 各语言的**类型定义（struct/class）** + **函数调用桩**（对接 wasm 组件）。

---

## 4. 第一个应用场景：GIS（USDD）

GIS 是本格式的一个 **profile / 应用层**，不是格式本身：

| 通用层 | GIS 实例化 |
|---|---|
| payload | 空间数据（GeoParquet / FlatGeobuf / PMTiles / COG / 私有格式） |
| interface（WIT） | `world spatial-file`：`query/aggregate/nearest/render/...` |
| capabilities | `cf:spatial-bounds@1` `cf:spatial-query@1` `cf:spatial-nearest@1` `cf:spatial-aggregate@1` `cf:map-render@1` |
| 数据 record schema | `.hxs` 记录（属性字段）+ 几何列 + CRS |
| index | R-tree / 分块索引（作为 payload 的辅助 section） |
| render | `render_tile(z,x,y)` / `render_region(...)`，浏览器可视化 |

详见 `universal_spatial_data_delivery.md` —— 它从「通用可计算文件」视角下就是
**空间数据能力的可计算文件**。规范化的 profile 定义见
[`../spec/gis-profile.md`](../spec/gis-profile.md)，容器格式见
[`../spec/container-format.md`](../spec/container-format.md)。

其它潜在场景：ML 模型 + 推理函数、报表 + 计算逻辑、科学数据集 + 处理算法、
Agent 工具（data + tool）、金融数据集 + 派生计算等。

---

## 5. 技术挑战

- **P0**：最小宿主 ABI、确定性执行 profile、capability 安全、资源计量、稳定接口模型
- **P1**：HTTP Range 执行、加密身份、provenance、版本化、接口协商
- **P2**：zero-copy、流式、SIMD、GPU 加速、分布式数据集、结果缓存

---

## 6. 待确认

1. 命名：格式名（CAF？）、扩展名（`.caf`？）、CLI 名（`caf`？）、能力命名空间（`cf:`？）。
2. Interface 是否以 WIT 为唯一标准，还是 WIT（函数）+ `.hxs`（记录）双轨。
3. Manifest 序列化：canonical CBOR vs canonical JSON。
4. Payload 布局与 Merkle 树的粒度（块大小）。
