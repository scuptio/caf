# 用 GIS Demo 演示 CAF 能力 · 讲解脚本

核心一句话（开场就抛出来）：

> **"Stop shipping data. Ship capabilities."（不再交付 GIS 数据，而是交付空间能力。）**

---

## 第 1 幕 · 一个文件就是一切

**操作**：`cd web && python3 -m http.server 8000`，浏览器打开，自动加载 `demo.caf`。点右侧 **Artifact** 面板。

**讲**：这个 `demo.caf`（约 31MB）不是数据文件，是"可计算工件"——里面同时打包了：

- 数据（`global.geo.json` + `global.wkb`）
- 接口定义（`gis.wit`，WIT 类型化接口）
- 可移植计算（`gis-demo.wasm`）
- 能力策略 + 内容寻址身份（`root` 哈希）

**对比**：传统交付 GIS 要 `GeoJSON + 前端渲染库 + 后端服务 + 投影工具链` 五件套；CAF 一个文件 + 一个宿主搞定。

---

## 第 2 幕 · 接口优先，容器不懂 GIS

**操作**：点 **Capabilities** 面板，看到 `cf:spatial-transform@1` 徽章；点 **WASM exports** 看到 `features()` / `reproject_x` / `reproject_y`。

**讲**：容器层**没有任何 GIS 字段**——没有 CRS、图层、bounds。GIS 语义完全通过 (a) WIT 接口 + (b) 内嵌 WASM 组件表达。所以 GIS 只是 CAF 的一个 **profile**；换成 ML 推理、报表、agent 工具，容器格式一行不改。

---

## 第 3 幕 · 同一份数据两种格式，浏览器无感知

**操作**：点 **Payload files**，看到两个文件：`.geo.json`（GeoJSON）和 `.wkb`（OGC WKB 二进制流）。

**讲**：同一份数据集用两种开放格式打包。WASM 组件通过**同一个只读 `payload-fs` ABI**（`open/read/readdir/close`）读取、各自解析、再按名去重——证明"格式只是载体，能力才是交付物"，浏览器根本不知道也不关心里面是 JSON 还是二进制。

---

## 第 4 幕 · 计算跟着数据走（最亮的点）

**操作**：切换 **Projection** 下拉框（Web Mercator → Equal Earth → Mollweide → Hammer…），画布**实时重投影**。

**讲**：7 种投影的**正反解全部在 WASM 里本地跑**，无后端、无 GDAL、无 PostGIS。传统做法这些投影能力要么在后端服务、要么打包进前端库；CAF 把它们和数据绑定在一起，拿到文件就拿到能力。

---

## 第 5 幕 · 默认拒绝的最小权限

**讲**（不操作，指代码）：宿主 ABI 只有 `open/read/readdir/close` + `memory`，**默认拒绝一切**——没有网络、文件系统、时钟、随机数，除非文件显式声明且运行时授权。工件是**不可变、内容寻址**的，结果只外部缓存、从不写回。

---

## 第 6 幕（收尾）· 换文件，宿主不变

**操作**：点 "Open .caf file" 或拖入**任意另一个** `.caf`。

**讲**：宿主运行时（浏览器里的 `caf.js`）完全不动，换一个 `.caf` 就换了一套能力。这就是"接口优先 + 能力随数据走"的最终证明。

---

## 收束

传统是把数据交给一堆外置工具去解释；CAF 让数据**自带解释器和能力**，在一个可验证、最小权限、可离线运行的工件里完成。

> 一点提醒：demo 目前只实现了 `features()` + `reproject`（`spatial-transform`）两个能力；`gis-profile.md` 里的 `bounds/query/aggregate/nearest/render` 是规划中的扩展，讲解时可以点一句"往这一档加能力就是改 WIT + 换 WASM 组件，容器格式不动"。
