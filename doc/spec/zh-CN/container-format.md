# CAF 容器格式(`.caf`)—— 规范

> [English](../en/container-format.md) | 简体中文

版本:**0.1.0** · 状态:草案

一个 `.caf` 文件是一个**可计算构件(Computable Artifact)**:一个单一、不可变、
可按范围读取、内容寻址的容器,同时携带数据*和*操作这些数据的可移植计算。

容器是**领域无关**的。专用构件(如 GIS)是一个 *profile*:它完全通过
(a) WIT 接口、(b) 内嵌的 WASM 组件、(c) 载荷约定来表达——从不通过容器层
字段。清单不知道"CRS"、"图层"或"瓦片"是什么;它只知道接口、组件、能力和
载荷段。

```text
构件 = 清单 + 接口 (WIT) + 组件 (WASM) + 载荷 + 策略 + 身份
```

## 1. 字节布局

所有整数为小端序。偏移量是从文件起始的字节偏移。各段按 8 字节对齐。

```text
+-----------------------------------+ 偏移 0
| 魔数             "CAF\0" (4 B)    |
| 格式版本         u32              |
| 头部长度         u16              |
| 标志             u16              |
+-----------------------------------+  <- 固定引导头
| manifest_offset  u64              |
| manifest_len     u64              |
| interface_offset u64              |
| interface_len    u64              |
| directory_offset u64              |
| directory_len    u64              |
| root_hash        [u8; 32]         |
+-----------------------------------+
| 清单             (规范 CBOR)      |
+-----------------------------------+
| 接口             (WIT 文本)       |
+-----------------------------------+
| 段目录           (二进制目录表)   |
+-----------------------------------+
| WASM 组件 #1                      |
| WASM 组件 #2                      |
| ...                               |
+-----------------------------------+
| 载荷段                            |
+-----------------------------------+
| 签名列表         (CBOR)           |
+-----------------------------------+
```

封存构件(`FLAG_ENCRYPTED`,§8)在目录之后紧接插入两个段——**密钥盒**
(接收方条目)和加密的**私有清单**——并且每个载荷以一个加密的
**载荷块(blob)** 存储,而不是逐文件的载荷段:

```text
| 段目录           (二进制目录表)   |
+-----------------------------------+
| 密钥盒           (明文)           |
+-----------------------------------+
| 私有清单         (密文)           |
+-----------------------------------+
| WASM 组件        (密文)           |
+-----------------------------------+
| 载荷块           (密文)           |
+-----------------------------------+
```

`Flags` 是一个 `u16` 位字段。v1 定义两位:`0x0001 SIGNED` ——构件携带
签名段(签名条目的 CBOR 列表,§7);`0x0002 ENCRYPTED` ——构件已封存
(§8)。读取方**必须拒绝携带任何未知标志位的构件**(fail-closed):一个
默默忽略未来标志——例如加密标记——的读取方会把密文当明文提供。因此新标志
只随 `format_version` 主版本升级一同引入(§12)。

目录条目标记:`0` WASM 组件 · `1` 载荷(文件段,或封存构件中每个载荷一个
载荷块)· `2` 清单(封存构件中的信封清单)· `3` 签名列表 · `4` 密钥盒 ·
`5` 私有清单。读取方拒绝未知标记(fail-closed)。

**引导头**是唯一必须立即读取的部分(几十字节);清单、接口和目录是打开时
读取的"引导区"(几 KB);载荷和 WASM 组件按偏移 + HTTP Range 按需读取。
因此打开一个远程构件只需读取引导区加上(较小的)组件字节——使这一点成立
的增量验证契约见 §11。

**段目录**是定长二进制表(不是 CBOR):一个 `u32` 条目计数,后跟 `count`
个条目,每个为 `tag u8 | flags u8 | hash_alg u8 | reserved u8 | offset u64 |
length u64 | hash [u8; 32]`(各 52 字节)。`flags` 承载段级属性(v1 未定义
任何位——读取方拒绝任何非零位),`hash_alg` 标记条目的哈希算法(`0` =
SHA-256;其他拒绝),`reserved` 必须为零——两者都是 fail-closed,因此未来
的属性和哈希算法无需改变布局即可落地。由于每个条目定长且清单*不*携带偏移,
所有段偏移都可以在单次前向扫描中算出——不存在需要收敛的自引用布局。

## 2. 清单

清单是构件的自我描述("DNA")。它以**规范 CBOR** 序列化,领域无关——没有
profile 特定字段。在封存构件(`FLAG_ENCRYPTED`)中,清单段改为携带公开的
**信封**,完整清单移入加密的**私有清单**——见 §8;下文描述的都是明文形式。

```rust
struct Manifest {
    // identity
    name: String,
    version: String,                 // artifact version (semver)
    format_version: u32,             // container format version

    // interface: types & functions (see §3)
    interface: InterfaceRef,         // inline WIT or offset into interface section

    // computation: one or more WASM components
    components: Vec<ComponentRef>,

    // capabilities exposed by the artifact (namespace:name@ver)
    capabilities: Vec<CapabilityId>,

    // execution policy & resource limits
    execution: ExecutionProfile,
    resources: ResourceLimits,

    // security & trust
    policy: CapabilityPolicy,
    provenance: Provenance,

    // payload references (virtual filesystem, see §5)
    payloads: Vec<PayloadRef>,

    // content addressing of the *other* sections
    hashes: SectionHashes,           // interface / wasm / payload
}
```

清单**不携带绝对偏移**:段布局(接口、组件和载荷文件的位置)仅由段目录
(§1)记录。这使清单的内容哈希与布局无关,`ManifestHash = SHA256(manifest)`
因此良定义,且不存在自引用的哈希字段。

### 组件绑定与访问范围(硬不变量)

清单**必须**把每个 WASM 组件绑定到它可读取的载荷路径。该绑定是硬的、不可
协商的不变量:组件在运行时按构造被拒绝访问其声明范围之外的任何载荷节点。

```rust
struct ComponentRef {
    name: String,                    // component name
    world: String,                   // matching WIT world (= interface contract)
    length: u64,
    hash: [u8; 32],
    exports: Vec<ExportEntry>,       // capability -> export name -> function signature
    access: Vec<AccessScope>,        // payload subtrees visible to this component
}

struct AccessScope {
    path: String,                    // logical path within the payload tree
    hash: [u8; 32],                  // content hash of the scoped node
    mode: AccessMode,                // read-only (only value in v0.1)
}
```

`exports` 在构建时从 WIT world 填充:对每个声明的能力 `ns:name@ver`,定位
world 的 `name` 导出并将其函数绑定到该能力 id。声明了能力却没有匹配的
world 导出是构建错误。没有 WIT world 时,`exports` 退化为原始 WASM 导出名
(空能力)。

`access` 把载荷**路径**绑定到它解析到的树节点的**内容哈希**,因此范围被钉
在内容上——而不是一个可伪造或可穿越的名字上。范围可以在组件间重叠。不读取
任何载荷的组件(例如元数据内嵌在 WASM 里)可声明 `access = []`。

校验在三个阶段强制执行;三个都成立时不变量才成立:

1. **构建时** ——每个 `access` 节点必须解析到载荷树中的真实节点,否则构件
   被拒绝。
2. **打开时** ——被引用节点的哈希必须与载荷段匹配;幽灵文件、路径穿越和
   伪造范围都无法通过校验。
3. **运行时** ——宿主通过预打开的目录描述符只向每个组件暴露其声明的子树;
   `open()` *只*在该集合内解析,否则返回错误(见 §4)。

推论:组件可以读取其范围*内*的每个字节,但范围之外的一个字节也读不到。
隔离单元是**组件**,不是单个导出;要进一步收窄信任边界,就拆成多个组件。
这是读可见性范围控制,不是语义/行级控制。

### 能力 id

能力 id 是命名空间化、带版本的接口名,对容器层不透明:

```text
cf:spatial-query@1
cf:map-render@1
org:example:infer@2
```

应用只依赖能力 id,从不依赖物理布局。按约定,一个 **profile** 就是构件对外
暴露的能力集合加上对应的 WIT world。

## 3. 接口段(WIT)

接口是构件的稳定契约,用 **WIT**(WebAssembly 组件模型)表达。它既定义数据
类型(`record` / `variant` / `enum` / `flags` / `type`),也定义函数
(`func ... -> result<.., ..>`)。

```wit
package example:file@0.1.0;

world computable-file {
    export compute: interface {
        query: func(req: query-request) -> result<query-result, string>;
    }
}
```

容器层把 WIT 当作不透明文本;所有 profile 语义都生活在这里。该段以**保留名
字的 CBOR 列表** `[{ name, text }]` 存储各源文件,因此原始文件名和边界在容
器中得以保留(并能经 `export`/`import` 往返);构建时按声明顺序拼接文本进
行解析。没有接口的构件具有零长度的接口段。

## 4. WASM 组件

计算以匹配某个 WIT world 的 WASM 模块分发,每个被导出的能力对应一个。格式
v1 针对下文所述的 `caf.*` 宿主 ABI 执行**核心模块**;导入在打开时枚举并对
照声明的策略解析,fail-closed);构建时支持内嵌组件模型元数据,在真正的组
件模型实例化落地之前适用的值编码契约规定在
[`caf-abi.md`](caf-abi.md) 中。暴露给组件的宿主 ABI 是最小且只读的:

```text
payload-fs      (POSIX 式文件系统;按组件预打开的范围)
  open(path: string) -> fd
  read(fd: fd, len: u64) -> list<u8>
  readdir(path: string) -> list<entry>
  stat(path: string) -> meta
  seek(fd: fd, offset: u64)
  close(fd: fd)
self.size() -> u64                  (整个文件的字节数)
emit(bytes)                         (结构化结果输出,计入 output_max)
log(bytes)                          (诊断输出,计入 output_max)
abort(code)                         (显式确定性陷阱)
memory                              (宿主管理的线性内存)
return                              (组件结果,计入 output_max)
```

`payload-fs` 函数仅在策略授予 `self_read` 时提供;`self.size` / `emit` /
`log` / `abort` 始终可用。每一个作为输出越过宿主边界的字节——`emit`、
`log` 和返回通道(结果值加上宿主从组件内存读出的字节)——都计入
`output_max`。

默认情况下组件**没有**网络 / 外部文件系统 / 进程 / 环境 / 时钟 / 随机数访问。
唯一的文件系统是载荷根,只读挂载,且**按组件预打开**:每个组件收到的描述符
集合只包含其 `access` 范围(§2)中声明的载荷子树。`open(path)` 只对该集合
解析——声明范围之外的任何路径(包括 `..` 穿越)都被拒绝,使组件↔路径绑定
成为硬不变量,而不是文档化的约定。

## 5. 载荷段(虚拟文件系统)

载荷是一个或多个组织为**目录树**的文件,通过上述 POSIX 式 API 访问。每个
条目是文件或目录,有名字,并单独哈希。

```rust
struct PayloadRef {
    name: String,                    // mount name; the first payload is the default
    root: PayloadNode,               // directory tree root
    media_type: String,              // logical type (not physical format)
    length: u64,
    hash: [u8; 32],                  // tree root hash
    compressed: Option<Compression>,
}

struct PayloadNode {
    kind: EntryKind,                 // file | dir
    name: String,
    hash: [u8; 32],                  // file: Merkle root over chunks; dir: hash over children
    length: u64,
    layout: Option<PayloadLayout>,   // file only: opaque / range / stream
    chunks: Vec<[u8; 32]>,           // file only: chunk hashes (empty for single-chunk)
    entries: Vec<PayloadNode>,       // dir only: children
}
```

一个构件携带**一棵或多棵命名载荷树**。第一棵是默认载荷:它的树挂载在客端
文件系统的 `/`;其余每个载荷挂载在 `/<name>/`。访问范围注明其载荷
(`build.toml` 中的 `name:/path`;裸 `/path` 形式指默认载荷)。载荷名必须
唯一、是安全的路径段、且不得与默认载荷的顶层条目冲突——构建时检查,校验/
打开时再查一次(fail-closed)。

- **layout**:`opaque`(单块,整块读取)/ `range`(多块,可按范围读取)/
  `stream`(流式)。字节能放进一个块的文件为 `layout: opaque` 且
  `chunks: []`;其哈希是字节的普通 SHA-256。
- **内容寻址**:文件被切成定长块(1 MiB),块的哈希构成 Merkle 树;文件的
  `hash` 是树根。因此较大的文件无需整读即可逐块(HTTP Range)校验和读取。
  目录哈希对其子项的 `kind | name | hash` 计算。
- **格式透明**:载荷字节可以是 GeoParquet、PMTiles、JSON/CSV、模型权重或
  任何私有格式——只有接口 + 组件知道如何解读。
- **只读**:树是只读的;组件只能 `open/read/readdir/stat/seek/close`
  (默认不可变)。
- **v1 不压缩**:`compressed` 字段保留。运行时在打开时拒绝非 `None` 值
  (fail-closed),而不是冒险提供组件无法解读的字节。块对齐压缩是 v2 议题。
- **封存载荷**:在封存构件中,每个载荷的逐文件段被一个加密的、按 2 的幂
  填充的载荷块替代,各树(带真实长度和明文哈希)移入私有清单——见 §8。

## 6. 执行环境配置与资源限额

```yaml
execution:
  profile: caf-d1         # deterministic profile
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
  read_max: 1GiB
  output_max: 64MiB
```

`caf-d1` 定义了规范的 NaN 行为、确定性的 relaxed-SIMD 子集、无线程、无
时钟/随机数/环境导入,因此相同的 `(FileId, FunctionId, Args, Profile)` 在
任何地方产生相同的结果。profile 是机器可检查的引擎配置:`caf-d1` 要求
`deterministic: true`;运行时不认识的 profile 在打开时拒绝(fail-closed),
而不是默默忽略。

全部四项预算都被强制执行——没有一项是摆设:

| 预算 | 执行点 |
|---|---|
| `memory_max` | store 线性内存上限(+有界的宿主侧载荷缓冲) |
| `cpu_fuel` | 引擎燃料,逐指令递减 |
| `read_max` | 实际从载荷后备存储取回的字节数(缓存命中不计) |
| `output_max` | 经 emit / log / 返回通道越过宿主边界的字节数 |

## 7. 身份与校验

```text
InterfaceHash   = SHA256(interface section)
WasmHash        = SHA256(each component bytes)
PayloadRootHash = root hash of each payload tree (file hash = chunk-Merkle
                  root; a single-chunk file hashes to the plain SHA-256 of
                  its bytes)
ManifestHash    = SHA256(canonical manifest)          -- stored in the directory
RootHash        = SHA256("CAF1"
                         || u64le(len) || ManifestHash
                         || u64le(len) || InterfaceHash
                         || u64le(n)   || (u64le(len) || WasmHash)*
                         || u64le(m)   || (u64le(len) || PayloadRootHash)*)
FileId          = RootHash                             -- stored in the header
```

`"CAF1"` 域分隔符、显式的长度前缀以及组件和载荷计数使哈希输入的解析无歧
义,并为未来的哈希算法迁移留出空间。由于清单哈希传递性地覆盖了策略、执行
环境配置、接口引用、组件引用、访问范围和载荷树,绑定强度等同于直接对这些
字段做哈希。

清单存储的是(*其他*段的)接口/wasm/载荷哈希;它自身的哈希和根哈希是派生
的,存在清单之外(根哈希在头部,清单哈希在目录),因此清单中没有自引用哈
希,`SHA256(manifest)` 恒等于存储的 `ManifestHash`。在封存构件(§8)中,
每个段哈希覆盖的是*存储的*字节——密文——因此根哈希是密文身份。

签名段是签名条目的 CBOR **列表**,每个条目为 `{ alg, key_id, pubkey, sig
}`,签名对象是 32 字节的**根哈希**——它传递性地覆盖每个段。每个条目都必
须验签通过;读取方在遇到第一个无效条目时拒绝整个构件(fail-closed)。v1
定义 `alg: "ed25519"`;共同签名、密钥轮换和未来算法都只是新增条目。对封存
构件这是先加密后签名(Encrypt-then-Sign):签名绑定密文身份,无需内容密钥
即可验签;签名段保持明文。
来源(Provenance)区分**数据** / **算法** / **构件** 发布者。

### 7.1 信任模型

每个签名条目携带 `(key_id, pubkey, signature)`:验签所需的密钥随文件携带,
`key_id` 是签名者的指纹(`SHA256(pubkey)`,hex)。因此有效签名证明**完整
性与自洽性**——清单确实由持有匹配私钥的人签署——但并不说明持有者*是谁*。
真实性在带外建立:

- **签名者指纹**:`caf-tool verify` 为每个签名条目打印一个。
- **信任库**:消费者在本地维护指纹到发布者身份的外部映射。
  `caf-tool verify --trusted-keys keys.toml` 对照它解析每个签名者(TOML:
  `[keys] <fingerprint> = "publisher name"`);`--require-trusted` 把"没有
  至少一个可信且有效签名"的构件变成硬错误。
- **默认 TOFU**:没有信任库时,指纹的首次使用是消费者的决策点;发行方应通
  过独立的认证渠道(项目站点、签名的发布说明……)公布指纹——与 SSH 主机密
  钥完全相同。
- **浏览器验签**:JS 宿主用 WebCrypto Ed25519 验签(当前
  Chrome/Edge/Safari/Firefox 均支持)。在不支持的平台上,验签降级为"无法
  验证"并告警,而不是拒绝——完整性仍由哈希链保证。

证书链是 v2 议题。

## 8. 封存构件(加密)

封存构件(`FLAG_ENCRYPTED`)加密组件、载荷和一份**私有清单**,只在清单段
保留最小的公开**信封**。该设计隐藏文件名、目录结构、真实文件长度、组件元
数据、来源以及构件名称/版本;它不隐藏组件数量、提供的能力或填充后的载荷总
大小。

```text
内容密钥(32 B,每次构建随机——或收敛式,见下)
  ├─ 段密钥 "private"       → AES-256-GCM 加密私有清单
  ├─ 段密钥 "component/<i>" → AES-256-GCM 加密每个组件
  └─ 段密钥 "payload/<i>"   → AES-256-GCM 按 1 MiB 块加密每个载荷块
```

- **KDF**:`KDF(label, ikm) = SHA-256("CAF-KDF-1" ‖ 0x00 ‖ label ‖ 0x00 ‖
  ikm)`。段密钥为 `KDF("section", content_key ‖ label)`。这种朴素的哈希
  KDF 在这里是安全的,因为每个 IKM 都是均匀随机的 32 字节值(新的内容密钥
  或 ECDH 共享秘密)——它*不是*口令 KDF。
- **块 nonce**:段级子密钥使 nonce 段内局部,块 `i` 使用 nonce
  `0x00000000 ‖ u64be(i)` ——计数器,绝不随机。
- **密钥盒**:一个 `u32` 条目计数,后跟定长**匿名**条目(各 125 B):
  `ephemeral_pubkey (65 B,未压缩 SEC-1) ‖ nonce (12 B) ‖ wrapped_key
  (48 B)`。每个条目用 `p256-ecdh-sha256` 包裹内容密钥:临时密钥与接收方
  P-256 密钥做 ECDH,`KDF("keywrap", shared)`,AES-256-GCM。不存储接收方
  密钥 id,因此密钥盒不泄露接收方*是谁*;接收方逐个尝试条目。
- **信封清单**(公开,CBOR,仍是 `TAG_MANIFEST` 段):`format_version`、
  接口引用、能力、执行环境配置、资源限额、策略、`encryption` 块(`aead` /
  `wrap` / `padding` 算法 id)、组件的匿名密文引用,以及密钥盒/私有段的引
  用和每个载荷一个 `PayloadBlobRef`(名称、长度、块数、密文哈希)。其余一
  切移入私有清单。
- **私有清单**(加密,CBOR,`TAG_PRIVATE`):构件名称与版本、来源、逐组件
  元数据(名称、world、明文哈希、导出、访问范围)以及载荷树。
- **载荷块**:每个载荷一个——其所有文件按 DFS 顺序拼接,零填充到**下一个
  2 的幂**(下限 4 KiB;`padding: "pow2"`),切成 1 MiB 块,每块用该载荷的
  段密钥(`payload/<i>`)封存。私有清单的载荷引用携带真实长度、填充长度和
  密文块哈希列表;逐文件明文哈希留在树中。对外,目录只泄露填充后的块大小
  ——不泄露文件数或各自大小。
- **读取**:宿主在打开时解密私有清单,之后提供载荷读取时,取回每个覆盖的
  密文块,先对照私有清单的块列表做哈希校验,然后才解密(AEAD)并把明文交
  给客端。先用前验证不变;客端 ABI 不变。
- **校验层级**:没有密钥时,`caf-tool verify` 检查每个存储的哈希和签名
  (公开层),并报告构件为封存。带 `--key` / `--recipient-key` 时,额外解
  密并校验私有清单、明文组件哈希和逐文件载荷哈希(明文层)。
- **收敛构建**:`caf-tool build` 通常抽取新的随机内容密钥,因此相同输入的
  两次构建字节不同。设置 `[encrypt] key_seed` 会从种子加上完整明文身份派生
  内容密钥,使构建字节可复现。身份是 CBOR 元组 `(interface_hash,
  private_manifest_before_encryption)` 的 SHA-256。这份私有清单包含全部私
  有元数据、组件明文哈希/导出/范围以及完整的载荷树和长度;其载荷 `hash`
  暂时是填充后明文块的 SHA-256,`chunks` 为空。密钥派生后这两个字段被密文
  引用替换。因此改变私有元数据也会轮换内容密钥,避免私有段的密钥和 nonce
  与不同明文重用。每个接收方的临时标量用 `KDF("keybox-eph", seed ||
  content_key || recipient_sec1 || counter)` 派生(counter 取 0..255 中首
  个有效标量)。纳入内容密钥可防止包裹密钥和 nonce 跨不同内容密钥重用。
  这修正了此前草案的派生方式:可复现的构建字节和密钥会改变,而已有封存构
  件仍然可读。用旧派生方式制作的构件应用新种子重建;本修复不会追溯性地保
  护它们的密文。

### 8.1 取回模式与访问模式

封存构件保护的是**静态内容**,不是**访问模式**。按需取回密文块的宿主会泄
露*哪些*块被读取。部署在两种模式中选择:

- **整文件取回** ——一次下载构件,然后本地读取;除了"构件被取回过"之外不
  泄露访问模式。这是 JS 宿主打开封存构件的必需模式(WebCrypto 解密在打开
  时进行),也是访问模式敏感时的推荐模式。
- **Range 取回** ——惰性取回密文块(§11);向后备存储泄露块访问模式,但可
  扩展到巨型构件。

填充(`pow2`)约束*静态*大小泄露;在 Range 取回模式下,填充和加密都不能
隐藏*动态*访问模式。

## 9. 结果校验

```text
ResultID = H(FileId, FunctionId, CanonicalArgs, ExecutionProfile)
```

确定性运行产生**可验证的计算声明**:不同参与方使用相同的文件 + 函数 + 参
数 + 环境配置,得到相同的 `ResultID`。

## 10. Profile

profile 是叠加在这个通用容器之上的约定。它定义:

- 一个 WIT world(能力契约),
- 一组能力 id,
- 载荷目录约定(哪些文件放在载荷根下),
- 可选地,一个执行环境配置。

GIS profile 规定在
[`../../../examples/gis-demo/gis-profile.zh-CN.md`](../../../examples/gis-demo/gis-profile.zh-CN.md)
中。其他 profile(ML 推理、报表、科学数据集、Agent 工具)注册自己的命名空
间,不改动本文档。

## 11. 打开与增量验证

宿主在其后备存储(本地文件、HTTP Range 端点、对象存储)上**惰性**打开构
件。打开只读取并验证:

1. 引导头,
2. 引导区——清单(由目录的清单条目钉住)、接口(由清单钉住)和段目录,
3. 每个组件的字节(较小;先做哈希校验,然后准入枚举其导入并对照声明的策
   略),
4. 签名列表段(如存在)。

载荷树的结构(目录哈希)和每个声明的访问范围在打开时对照清单检查。**载荷
字节增量验证**:当组件读取载荷文件的 `[pos, pos + len)` 时,宿主只取回覆
盖的 1 MiB 块,并在把字节交给客端*之前*对照清单的块哈希逐块检查。因此组
件收到的每个字节都经过先用前验证;从不被读取的字节从不被取回或验证。宿主
可以缓存已验证的块字节;`read_max` 预算只计实际从后备存储拉取的字节,缓存
命中不计。原生宿主在 I/O 或缓存插入之前先把每次缓存未命中计入 `read_max`
预留。被拒绝的未命中从不进入缓存;I/O 或验证失败的读取保留其预留,因此反
复失败也无法做不计量的工作。

与整文件校验相比安全不变量不变:篡改用在使用受影响字节之前被检测,不被检
测的篡改不可能发生——只有*检测时延*从打开时移到了首次读取。

对于**封存**构件,引导区额外读取密钥盒和加密的私有清单(较小),组件在打
开时解密(准入需要它们的导入),每个取回的载荷块先对照私有清单的密文块列
表做哈希校验,然后 AEAD 解密,之后明文才到达客端。取回模式选择(整文件
vs. Range)与访问模式泄露见 §8.1。

关于规模的说明:清单携带块哈希,其大小随载荷大小增长(每 1 MiB 块 32 字
节)。这使即使很大的构件引导区也很小(每 GiB 载荷约 32 KB);携带超大载荷
的 profile 应优先使用更少、更大的载荷文件,使目录和树的开销保持成比例。

关于 JS 宿主的说明:真正的按需 Range 读取还需要 JSPI
(`WebAssembly.Suspending`),使同步的 payload-fs ABI 能够等待异步取回。在
没有 JSPI 的环境中,整个构件先下载一次,然后在内存中惰性验证。必须在整文
件下载下保持交互性的 profile 应发布**多个较小的构件**(例如文本一个、每个
媒体包一个),而不是一个巨型文件——以组合代替体量,且无需格式变更。

## 12. 版本化与稳定性

- `format_version`(头部 + 清单)是容器契约。v1 读取方在头部就拒绝更高的
  主版本,不做任何进一步解析。受支持集合、逐版本参数和 schema 迁移维护在
  `crates/core/src/version/`(每个版本一个目录)——不在任何其他地方。维护
  者流程见 `doc/spec/zh-CN/versioning.md`。
- 读取方拒绝未知的头部标志位、未知的目录标记和未知的清单字段
  (fail-closed)。因此任何新标志、标记或清单字段——例如未来的 AEAD 修订
  ——都是*主版本*变更:它随 `format_version` 升级一起发布,旧读取方从不默
  默忽略。
- 在格式处于草案阶段(`0.1.x`)时,字节布局可能随发布改变并伴随
  `format_version` 升级;不提供兼容性保证。
- 从第一个稳定标签(`1.0`)起:读取方接受同一主版本的所有构件;读取方只
  拒绝*更高*的主版本。profile 独立版本化(`namespace:name@version`);构件
  版本按 semver 逐构件递增。
- 构件内的 WIT 接口遵循常规的语义化导入版本规则:新增函数是次版本能力变
  更;修改或移除函数需要能力主版本升级。
- 字节一致重建规则(可复现构建、ZIP 导出与重建)见
  `doc/spec/zh-CN/round-trip.md`。
