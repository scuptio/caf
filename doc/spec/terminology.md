# 术语表 · Terminology

CAF 生态文档的英中术语对照。新增或翻译文档时以此为准,保持双语一致。
The English–Chinese glossary for CAF ecosystem documents. Follow it when writing
or translating documentation so both languages stay consistent.

## CAF 容器 / Container

| English | 中文 | 说明 / Notes |
|---|---|---|
| artifact | 构件 | 一个 `.caf` 文件;computable artifact = 可计算构件 |
| manifest | 清单 | 构件的自我描述,规范 CBOR 序列化 |
| payload | 载荷 | 随构件携带的数据;payload tree = 载荷树 |
| section | 段 | 容器的字节分区;section directory = 段目录 |
| bootstrap header | 引导头 | 文件起始的定长头部 |
| boot area | 引导区 | 打开时读取的清单 + 接口 + 目录 |
| capability | 能力 | capability id = 能力 id(`namespace:name@version`) |
| profile | profile | 不译;容器之上的领域约定 |
| interface | 接口 | WIT 表达的契约 |
| component | 组件 | WASM 组件 |
| host | 宿主 | 运行构件的一侧;guest = 客端(组件一侧) |
| capability policy | 能力策略 | 默认拒绝(deny-by-default) |
| execution profile | 执行环境配置 | 如 `caf-d1` |
| resource limits | 资源限额 | memory_max / cpu_fuel / read_max / output_max |
| fuel | 燃料 | CPU 指令计量 |
| content-addressed | 内容寻址 | root hash = 根哈希即身份 |
| range-readable | 可按范围读取 | HTTP Range / 偏移读取 |
| incremental verification | 增量验证 | 逐块先用前验证 |
| fail-closed | fail-closed | 遇未知即拒绝,不译 |
| access scope | 访问范围 | 组件可见的载荷子树 |
| admission | 准入 | 导入对照策略的准入检查 |
| chunk | 块 | 1 MiB 定长分块;Merkle tree = Merkle 树 |
| sealed artifact | 封存构件 | 加密的构件 |
| envelope manifest | 信封清单 | 封存构件的公开部分 |
| private manifest | 私有清单 | 封存构件的加密部分 |
| keybox | 密钥盒 | 接收方包裹条目 |
| content key | 内容密钥 | 每次构建随机 |
| provenance | 来源 | 区分数据/算法/构件发布者 |
| trust store | 信任库 | 指纹到身份的带外映射;TOFU = 首用信任 |
| value encoding | 值编码 | caf-abi;emit channel = emit 通道 |
| round-trip | 往返 | project → .caf ⇄ .zip |
| reproducible build | 可复现构建 | 字节一致 |
| deterministic | 确定性 | 相同输入相同输出 |
| domain separator | 域分隔符 | 如 `"CAF1"`、`"CAF-KDF-1"` |

## CAFD 阅读 / Reading

| English | 中文 | 说明 / Notes |
|---|---|---|
| interactive document | 交互文档 | CAFD,`.cafd` |
| thin host | 薄宿主 | 阅读器角色 |
| reading profile | 阅读 profile | `caf:doc@1` |
| app protocol | 应用协议 | `caf:doc-web@1` |
| bridge | 桥接 | 宿主向书内应用提供的受控通道 |
| bookshelf | 书架 | 文档架同义,UI 用"书架" |
| fixture | 夹具 | 测试用最小文档 |
| entry | 入口 | 应用清单的 HTML 入口 |
| mount | 挂载 | 书内应用的挂载 |
