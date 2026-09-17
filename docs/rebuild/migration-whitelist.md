# 白名单移植

[重建入口](README.md)

旧实现默认不进入重建分支。白名单表示“该产品结果或窄组件值得复用”，不表示可以整提交、整目录
或连同旧依赖直接 cherry-pick。每次移植都必须能映射到一个核心模型实体或明确的 adapter；否则删除。

## 来源边界

| 来源 | 用途 |
|---|---|
| `6be9e4c9` | 新分支源码基线 |
| `archive/v2-overgrown-20260917` | 只读取证、选择性移植和现网格式导入；不继续开发 |
| 现网私有配置与证据 | 只用于保留身份、密钥、数据、floor、latch 和实际部署坐标 |

基线选择不改变生产状态。任何 importer 只允许“旧认证状态 → 新最小模型”单向转换；不得让新 daemon
长期同时读写两套格式，也不得把 v1 fallback 带回运行时。

## 整体保留的产品资产

以下资产应尽量保持布局、文案和交互，不因后端重建回退：

- `internal/webui/static/*` 中的浏览器 SPA、样式、图标和拓扑交互；
- Releases、Devices、Topology、Live paths、Services、Events 和 SSOT 页面；
- Android 的主界面、Enrollment 窗口、profile/选路/状态交互、颜色、图标与 launcher 资源；
- Windows 的 Misaka 界面、profile 管理、选路与路径详情交互、状态图标、manifest 和原生资源；
- 双环拓扑不因聚焦或当前路径重排，当前路径只作只读叠加；
- 浏览器 TLS、管理员证书、same-origin 与 read/admin Unix socket 权限边界；
- 签名 release catalog、逐文件摘要校验和精确制品下载体验。

后端 DTO、旧 SSOT callback、registry 拼接和独立 SSR 页面不在白名单。Web 只消费
[控制面 Web 投影](web-ui-projection.md)。Android/Windows 保留的是产品界面和交互语义；Enrollment manager、
route manager、scheduler、probe 与平台 runtime 仍须逐项映射到新模型，不能因 UI 保留而整目录搬回。

## 可复用的窄能力

| 能力 | 允许复用 | 移植条件 |
|---|---|---|
| 规范化、typed hash、签名与 Merkle 基元 | 小型纯函数及 golden | 必须被新 wire 直接使用；不连带旧 proof zoo |
| HY2/Trojan listener 与 relay adapter | 已真实 bind/accept/dial 的 transport 部分 | 输入只能来自 EndpointGeneration；不得自建生命周期 |
| 私有 TLS、Device mTLS 与用途隔离 | 证书校验和 listener 边界 | authority 只读 `CertifiedHead` 所认证的 `Projection` / DeviceView |
| sealed artifact 存储 | 密文正文、first-result 原子保存 | 只保存不可重算秘密或外部副作用结果，不成为第二权威 |
| capability attempt/byte 限额 | 重启后仍不可重置的消费计数 | 绑定同一 BootstrapCapability，不另建授权模型 |
| fake website 与 immutable Nginx renderer | 静态路径、header 和拒绝动态路由的规则 | 公网不得出现 per-device view/config/secret ref |
| 通用 immutable publisher | 按给定对象写入、回读 exact bytes | publisher 不决定对象是否公开，也不选择 latest |
| 纯渲染器与原子 runtime 安装 | 确定性配置、preflight、apply/readback/rollback | 输入来自新 Projection/DeviceView；删除旧兼容分支 |
| 客户端身份与 LKG 安全存储 | 平台 key、cert、floor、原子候选槽 | 不保留旧网络 fallback、旧 scheduler 或重复 runtime LKG |
| 本机 `.env` 配置入口 | 节点别名、角色及必要部署引用的严格 loader | 服从[配置模型](configuration-model.md)；不移植无消费者变量、命令字符串、运行状态或重复默认目录 |

“复用语义”优先于“复用文件”。旧文件若混合必要 transport 与错误状态机，提取最小纯组件并删除其余部分。

## 必须迁移的数据

- cluster、Device 与管理员身份；
- 当前 ControlSet、最后可信 certified state 与 anti-rollback floors；
- v2 latch 与恢复锚点；
- 设备本地私钥、证书、sealed secret 和当前 LKG；
- 当前网络、服务、职责、授权和必要 EndpointGeneration；
- Web UI 展示所需但仍有效的 release metadata 与动态观测。

迁移器必须输出规范新状态和逐对象摘要，再由新 reader 独立验证。迁移完成后，新进程不得回读旧 store。
不可逆 floor/latch 已推进时只允许前向修复，不以源码基线为由降低。

## 禁止移植

- `operations.json`、`control-state.json` 的重复 Head/QC/phase 权威；
- MembershipLedger、独立 Head attestation service、application history 和 progress history；
- 全量 CRDT snapshot 往返、每次写入重写全集、Raft 每轮发送完整日志；
- 独立 Enrollment sequencer、ResumeIssuer/Resume service、第二份 transaction store；
- progress/completion 两套大型 receipt、proof/profile/plan/gate 的重复 lineage；
- rotation gate、动态 NAT port reservation/quarantine 和 issue 验收状态；
- 未接线的 DNS/ACME/provider executor；
- Android/客户端旧 scheduler、probe user/secret、period/window、`min_samples`、probe budget、
  一次性 underlay registry 和持久 selection 副本；
- 公开 per-device LinkIntent、WG/control tunnel、runtime config、view 或 secret ref；
- v1 public claim/config/report、旧 registry 邀请回调和任何 v2 latch 后 fallback；
- 只被测试调用、没有正式入口的生产实现。
- 无消费者、可确定性推导、只服务旧阶段脚本，或把输出/历史/运行状态写回 `.env` 的变量。

## 移植步骤

1. 在对应模型文档中找到目标实体或 adapter；找不到则不移植。
2. 写一条说明删除该能力会破坏的明确需求。
3. 只复制满足该需求的最小代码和必要测试，移除旧命名、状态及依赖。
4. 沿正常入口验证一次结果；不能用原 fixture 证明新接线。
5. 在同一改动中删除被替代旧代码，不保留长期双栈。

控制面 Web、Android 和 Windows UI 都是明确保全的产品面；保留的是页面、品牌资源与有效交互，不是偶然为其供数的旧权威模型或平台状态机。
