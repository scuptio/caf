# CAF — 可计算构件格式

> [English](README.md) | 简体中文 · 许可证:[Apache-2.0](LICENSE)

[![CI](https://github.com/scuptio/caf/actions/workflows/ci.yml/badge.svg)](https://github.com/scuptio/caf/actions/workflows/ci.yml)

一个实现**可计算构件格式(`.caf`)** 的 Rust 工作区——一种把*数据和操作数据
的计算一起交付*的通用、领域无关方式。

> **别再交付数据,交付能力。**

`.caf` 文件不是被动的数据载体:它把数据、类型化接口(WIT)、可移植计算
(WASM 组件)、能力策略和密码学身份打包进一个单一、不可变、可按范围读取、
内容寻址的对象。

```
应用程序 (Rust / Python / JS / CLI / Agent)
        │  capability ABI(命名空间化、带版本的接口)
        ▼
CAF 运行时  (WASM 沙箱 + 能力策略 + 资源计量)
        │
        ▼
artifact.caf   (清单 + 数据 + WASM 组件 + 签名)
        │
        ▼  HTTP Range / 本地 / S3 / CDN
```

容器本身不了解任何具体领域。专用构件(地理信息、ML 推理、报表、Agent 工
具……)是一个 **profile**:它完全通过 (a) 其 WIT 接口、(b) 其 WASM 组件
和 (c) 载荷约定来表达——从不通过容器层字段。

## 设计原则

1. **接口优先** —— 文件描述自己*能做什么*(`capabilities()`),而不是字节
   如何排布。
2. **最小宿主 ABI** —— 只读的 `payload-fs` 加上 `memory`/`return`;其余一
   切默认拒绝。
3. **默认不可变** —— 构件内容寻址;结果在外部缓存,从不写回文件。
4. **无环境特权** —— 没有网络 / 文件系统 / 时钟 / 随机数,除非文件显式声
   明且运行时授权。
5. **版本一切** —— 容器、接口、执行环境配置和载荷 schema 的版本相互独立。
6. **现有格式皆可为载体** —— 载荷字节可以是 Parquet、JSON/CSV、模型权重或
   任何私有格式;只有接口 + 组件知道如何解读。

## 工作区布局

```
caf/
├── crates/
│   ├── core/          # caf-core:容器格式解析 + 校验
│   ├── runtime/       # caf-runtime:WASM 宿主(payload-fs ABI + 能力执行)
│   ├── security/      # caf-security:导入准入策略 + 资源计量
│   ├── guest/         # caf-guest:客端辅助(ABI 声明、内存桥、打包结果)
│   └── tools/         # caf-tool:build/verify/inspect/run/ls/diff/export/import/keygen/versions + 项目向导
├── examples/
│   └── gis-demo/      # 一个完整的示例 profile(浏览器演示,无后端)
├── fuzz/              # 面向解析器与验证器的 cargo-fuzz 目标
└── doc/
    └── spec/          # 容器格式、值编码 ABI 规范(en/ 英文原文,zh-CN/ 中文译本)
```

## 快速开始

```bash
# 构建工具链并安装 caf-tool
cargo build --workspace
cargo make install            # 安装 release 版到 Cargo 的 bin 目录

# 脚手架 → 编译并打包 → 校验
caf-tool new my-artifact --lang rust    # rust|python|js|go|as
cd my-artifact
caf-tool build -c build.toml -o artifact.caf --dump-manifest artifact.manifest.json
caf-tool verify artifact.caf

# 执行组件函数(带能力执行的宿主运行时)
caf-tool run artifact.caf --fn ping    # 骨架自带的 ping() 返回 "pong"
```

未安装 caf-tool 时,可用 `cargo run -p caf-tool -- ...` 代替以上命令。

### 更多 caf-tool 命令

```bash
caf-tool inspect artifact.caf        # 人类可读摘要
caf-tool ls artifact.caf             # 载荷文件 + 组件
caf-tool diff a.caf b.caf            # 逐段 diff
caf-tool export artifact.caf -o artifact.zip   # 导出内嵌内容为 ZIP
caf-tool import artifact.zip -o rebuilt.caf    # 从 ZIP 重建字节一致的 .caf(明文)
caf-tool keygen --recipient          # 封存构件的 P-256 接收方密钥对
caf-tool versions                    # 受支持的容器格式版本
```

封存(`[encrypt]` recipients)、封存校验(`--recipient-key`)、ZIP 布局与重建保
证规定在 [container-format.md](doc/spec/zh-CN/container-format.md) §8 与
[round-trip.md](doc/spec/zh-CN/round-trip.md)。

## 生态

- [CAFDReader](https://github.com/scuptio/CAFDReader) —— CAFD(`.cafd`)交互文档的跨平台
  阅读器;CAFD 是建立在 CAF 容器之上的文档
  profile([CAFD 1.0.0 规范](https://github.com/scuptio/CAFDReader/blob/main/spec/zh-CN/CAFD.md))。

## 文档

- [`doc/spec/zh-CN/container-format.md`](doc/spec/zh-CN/container-format.md) ——
  `.caf` 容器格式(字节布局、清单、组件、载荷、增量验证、信任模型、版本化)。
- [`doc/spec/zh-CN/caf-abi.md`](doc/spec/zh-CN/caf-abi.md) —— 值编码
  ABI:复杂值如何在格式 v1 中跨越宿主↔组件边界。
- [`doc/spec/zh-CN/round-trip.md`](doc/spec/zh-CN/round-trip.md) —— 确定性
  往返规则:可复现构建、ZIP 导出、字节一致导入。
- [`doc/spec/zh-CN/versioning.md`](doc/spec/zh-CN/versioning.md) —— 维护者
  升级指南:版本轴、何时需要升版、逐版本目录流程。
- [`doc/spec/terminology.md`](doc/spec/terminology.md) —— CAF 生态文档共用的
  英中术语表。
- [`examples/gis-demo/gis-profile.zh-CN.md`](examples/gis-demo/gis-profile.zh-CN.md)
  —— 叠加在通用容器之上的示例 profile。
