# 版本化与升级指南

> [English](../en/versioning.md) | 简体中文

CAF 格式版本如何组织、什么变更需要升版,以及切一个新版本的精确流程。机器可
读的注册表在 `crates/core/src/version/`;本文档是围绕它的人类流程。

## 1. 版本轴

CAF 有四条版本轴。只有前两条是格式版本,维护在 `crates/core/src/version/`
和 `caf-tool` 中:

| 轴 | 携带于 | 何时升版 |
|---|---|---|
| 容器 `format_version` | 头部 + 清单/信封 | 旧读取方会拒绝的任何变更(§2) |
| `export_version`(ZIP 配置) | `export.json` | ZIP 清单或其规则变化 |
| 构件版本(`manifest.version`) | 清单 | 发布者自己的 semver,逐构件 |
| 能力 / WIT 版本(`cf:name@1`) | 清单、WIT | 接口语义变化 |

**不要**把后两条并入格式版本——它们是用户空间的契约,不是读取方契约。

## 2. 何时需要 `format_version` 升版

读取方是 fail-closed 的:未知的头部标志、目录标记、清单字段和版本都是硬错
误。因此以下任何一项都是需要新 `format_version` 的**主版本**变更:

- 新的头部标志、目录标记或清单/信封字段;
- 新的密码套件成员(AEAD、密钥包裹、填充配置)或 KDF 域;
- 布局变更(对齐、头部长度、段顺序)或块大小变更——两者都改变字节身份;
- 根哈希域变更(身份重定义)。

4 字节文件魔数(`CAF\0`)永不改变:它标识文件*种类*,版本由
`format_version` 承载。根哈希域(`CAF1`)不同:**仅**在身份语义变化(哈
希算法、覆盖范围或前缀结构)时升级,而不是每次升版都改——它是逐版本的
`FormatSpec` 字段,一旦存在两个域,`identity::root_hash` 必须改为使用
`spec().root_domain`。

反过来:任何读取方都观察不到的变化(实现细节、更严格的*写入方*规则)不需
要升版。

## 3. 布局:每个版本一个目录

```text
crates/core/src/version/
├── mod.rs        # registry: SUPPORTED, CURRENT, spec(), migration machinery
└── vN/
    ├── spec.rs     # FormatSpec: parameters this version pins down
    ├── schema.rs   # frozen manifest/envelope schemas of this version
    └── migrate.rs  # (v2 and later) pure steps from vN-1 into vN
```

归属规则:

- 版本目录拥有*读取*该版本所需的一切。一旦发布,它永不改变——发布后对
  `vN/` 的修改是评审中的危险信号。
- `crates/core/src/manifest.rs` 中的*活跃* schema 类型始终是**当前**版本。
  旧 schema 只作为冻结快照存在于 `version/vN/schema.rs`。
- 最新版本知道它的前身:`vN-1 → vN` 迁移在 `vN/migrate.rs`。

`caf-tool versions` 打印注册表:每个受支持的 `format_version` 及其参数(头
部长度、对齐、块大小、根域、密码套件)、`build` 写哪个版本,以及接受的
`export.json` 范围。它直接读取 `SUPPORTED`/`CURRENT`,因此在代码中注册版本
即完成对外公布。

## 4. 切新版本(v1 → v2 示例)

1. **冻结旧 schema。** 把 v1 schema 定义从 `manifest.rs` 复制进
   `version/v1/schema.rs`,替换别名,并把
   `VersionedManifest::V1`/`VersionedEnvelope::V1` 指过去。
2. **演进活跃 schema。** 在 `manifest.rs` 中做变更(它现在描述 v2)。把它
   的 `format_version` 设为 2。
3. **创建 `version/v2/`。** `spec.rs` 放 v2 的 `FormatSpec`(复制 v1 的,
   改动有变化的部分);v2 为当前版本期间,`schema.rs` 起别名到活跃类型。
4. **写迁移。** `v2/migrate.rs` 暴露
   `fn migrate_manifest_v1_v2(VersionedManifest) -> Result<VersionedManifest>`
   (以及信封孪生)。在 `version/mod.rs` 的 `MANIFEST_MIGRATIONS` /
   `ENVELOPE_MIGRATIONS` 中注册两者。
5. **注册版本。** `SUPPORTED = &[v1::SPEC, v2::SPEC]`;`CURRENT = &v2::SPEC`。
6. **测试。** v1 黄金夹具必须仍可读并迁移;构建写出 v2;`verify` 接受 v1
   与 v2,拒绝 v3。

旧构建在头部即拒绝 v2 构件——`container-format.md` §12 的 fail-closed 契约
保证了这一点。

## 5. 编写迁移函数

迁移步骤 `f(v-1) -> v` 是**纯的、全定义或报错**的函数:

- 无 IO、无时钟、无随机——相同输入永远相同输出;
- 无法前向携带的数据是硬错误,绝不静默丢弃;
- 步骤相邻(`from + 1 == to`);机制自动组合 `f(1) ∘ f(2) ∘ …` 并拒绝断档;
- 它作用于*逻辑*表示。存储的字节从不被改写:迁移是读取路径上的视图,因此
  构件的根哈希和签名保持其含义。"升级"构件身份是显式的重建
  (`caf-tool build` 或经 `export` + `import` 往返),绝不是读取的副作用。

## 6. ZIP 导出配置(`export_version`)

`export.json` 独立版本化(`crates/tools/src/export.rs` 中的
`EXPORT_FORMAT_MIN` / `EXPORT_FORMAT_CURRENT`):

- ZIP 清单或其规则变化时升版(新条目种类、`import` 依赖的新字段);
- `import` 接受闭区间 `MIN..=CURRENT`;只有刻意为之才丢弃旧版本;
- 导出配置隐式覆盖特定容器版本——把它记录在 `export.json` 的
  `format_version` 字段(自 v2 起如此),并保持 `import` 对其交叉核对。

## 7. 逐版本测试义务

- **黄金夹具**:为每个受支持版本在测试夹具中保留一个最小构件;读取它必须
  成功,并以预期的字段值迁移到当前 schema。
- **链式组合**:注册两个或更多步骤后,测试 v1 输入能经每个中间步骤组合
  (机制拒绝缺失或跳步;见 `version/mod.rs` 测试)。
- **写入方身份**:`build` 恰好写出 `CURRENT`;请求不受支持的
  `format_version` 的构建失败。
- **准入**:声明未知版本的构件在任何进一步解析之前就在头部被拒绝。

## 8. 非目标

不支持降级(读取方从不写旧版本)、不就地改写已存储的构件、不自动迁移签名
——身份按设计不可变(见 `round-trip.md` §1)。
