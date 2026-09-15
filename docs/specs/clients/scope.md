# 客户端规范 · 范围与迁移输入

[客户端规范入口](../../client-access.md) · [文档地图](../../README.md) · [源码能力](../../implementation.md)

**规范状态：已批准的客户端契约。** 本文负责 范围与迁移输入；标为 v1 的内容仅适用于迁移输入，
v2 认证、对象与事务以[控制面规范](../../distributed-control-plane.md)的对应条款定义。
平台运行情况由验收回执确认；本文保留原章节编号，不记录部署进度。

## 1. 结论

客户端不应实现三套独立网络栈。三类平台共用 sing-box 数据平面、Loom 的签名
配置格式、设备身份和调度语义，只为操作系统生命周期做薄适配。

| 平台 | 流量接管 | 客户端形态 | 结论 |
|---|---|---|---|
| Windows 桌面 | TUN 主接管 + 同规则的本地 `1080` mixed | Windows Service（v1 目标态）；托盘 UI 可分阶段交付 | 需要薄客户端；规则来自已验证且可激活的 Device view/兼容 snapshot |
| Linux Server | 本地 `1080` mixed，由进程显式使用 | Loom + sing-box 二进制分发包 | 不开发独立 GUI |
| Android | `VpnService` TUN | Android App，内嵌 sing-box | 必须开发 App；规则来自已验证且可激活的 Device view/兼容 snapshot |

这里的“一个入口”是一个**客户端逻辑策略入口**，不是一个控制节点：请求先由已验证且可激活视图中的
matcher 映射到 Service，
再映射到既有 `AccessDeclaration`。Windows 同时暴露 TUN 与 `1080` 是为了适配不同
应用，并不形成两套策略；两者必须使用同一份已验证规则。选择“默认德国”也复用
这个入口，不新增德国端口。Linux 为迁移旧部署而保留的端口覆盖属于兼容/高级
能力，不是日常入口或 Service 页面的产品模型。

客户端只提供一个顶层路由模式控件，且只有三种模式：

- **Direct**：全部接管的业务流量从设备本地直连，不进入 Loom 服务器路径；
- **Auto**：完整使用 certified Device view（或 latch 前的已验证 v1 snapshot）
  授权的 `Host → Service → Policy`，路径由 Agent 自动选择；
- **指定出口**：从当前全部在役 `egress_capable` 节点中选一台作为全部接管业务流量的最终出口，
  最终一跳固定，但到该出口之前的路径仍由 Agent 自动择优。

客户端不能手选 Current Paths；路径只读展示运行时结果。三态是本机受控偏好：
客户端只切换本地 selector，不编辑控制平面规则或生成的 sing-box 配置；Auto 规则与
指定出口列表仍来自最后一份验签通过的配置包。

静态导入现成 sing-box 兼容客户端可用于验证链路，但它不提供完整的签名 pull、
设备吊销、Loom 调度、离线排名与可信观测，不能作为最终托管方案。

---

## 2. v1 实现边界与迁移输入

> 本节只定义迁移输入；源码接线见[实现对照](../../implementation.md)，部署结果另按相关验收回执核对。

v1 的兼容形状固定如下；这里只定义迁移约束，不声明仓库或部署进度：

| 边界 | v1 形状 | v2 迁移要求 |
|---|---|---|
| 平台 | `android` / `windows-desktop` / `linux-server`；拒绝含糊 `desktop` | 保持枚举稳定，能力通过 versioned view 协商 |
| 邀请 | 单 HTTPS enroll endpoint、一次性 token、平台 key digest、严格 schema | 并行 QR/invite v2：紧凑 descriptor 精确携带 token/commitment、minimum recovery/trusted checkpoint、`bootstrap_catalog_hash`、`proof_bundle_hash`、2～3 个静态 distribution mirror、有界 `PrivateEnrollmentServiceRefV1` 和短期 bootstrap capability；claim 经临时隧道进入私有 Enrollment |
| 配置 | 单签 current、全局 generation、静态多镜像 | per-device Merkle view、提交后 ControlSet QC；recovery、control、head 与 Device view 四组 durable floor（含 recovery policy hash）与不可逆 v2 latch |
| 报告 | enrollment 同源 report、canonical v5 + self-check v1、`200/204` | 经 Loom overlay 访问 `ControlServiceDirectoryV1` 中 `role=device_report` 的私有服务；保留 producer 签名和原时间，跨 control CRDT 去重 |
| 数据入口 | 单 `public_endpoint + inbound_port`；客户端使用签名候选 | 稳定 logical endpoint；首版 Hysteria2/Trojan 支持多 listener generation overlap，WireGuard 另需双 interface/peer profile |
| 本机状态 | Linux 0600；Windows DPAPI；Android Keystore + 应用私有存储 | 原身份私钥不重建，原子增加 checkpoint/QC/EndpointSet、四组 floor、bootstrap transition hash 与 v2 latch |
| 路由偏好 | Direct / Auto / 指定出口是本机偏好；`default_declaration` 仅为 Auto catch-all | 语义不变，端口轮换和 control failover 不新增用户选择轴 |

v1 读写器对未知字段 fail closed，因此迁移只能新增明确版本的资源和 parser，先升级 reader、
再双发、再扩 ControlSet，最后撤销 v1 signer。任何 `Running`、bundle 验签、invite claim、
`ready` 或候选写入都不能单独解释成 VPN 已连接。v2 中 `committed_not_certified`
不是可激活状态：它不得发布 mutable current、改变客户端授权或驱动外部副作用；
`certified`、`mirrored`、`applied` 与 `healthy` 也必须分开。源码能力由[实现对照](../../implementation.md)说明，
发行签名和真机结果按[部署证据](../../operations/local-deployment.md)核实。

---

## 3. 目标与非目标

### 3.1 目标

1. 创建端先生成并封装 exact-version 一次性 token，再由已入网管理员经
   Loom overlay 访问已信 `ControlServiceDirectoryV1` 中 `role=control_api` 的私有服务，验证服务器证书/IP
   并使用 admin cert 认证后，提交公开层只含 commitment/private-binding hash 的 Create Device
   intent；完整 artifact ref 与明文一致性回执仅进入 control-private replicated binding；
   只有 Raft 耐久提交、apply/recompute 且
   取得 replication QC 成为 certified 后，renderer 才可解封同一 token 并输出邀请。用户导入短时
   二维码即可加入网络，不经邮件或 IM 传明文配置。
2. 客户端只接受 Raft durable commit 后由当前 ControlSet quorum 复算签署的
   certified head，且 recovery（epoch/statement/policy hash）、control（epoch/set hash）、
   head（revision/hash）、Device view（generation/leaf/view hash）四组 floor 和 protocol latch 均未回退。
3. 全部控制入口不可用或控制面失去 quorum 时，客户端继续使用最后一份已验证配置转发流量。
4. 同一份访问声明在不同平台保持相同的授权、候选和 fallback 语义。
5. 设备可被单独吊销，不依赖删除其他设备共享的配置。
6. 平台适配失败时显式阻断安装，不把 Linux 产物伪装成 Windows/Android 包。
7. Auto 模式统一经过中控 matcher → Service → `AccessDeclaration`，各平台只按
   系统能力呈现接入面，不另建本地策略模型。
8. 设备提供 Direct、Auto、指定出口三个顶层模式；指定出口可选择任一在役
   `egress_capable` 节点，且只固定最后一跳。

### 3.2 非目标

- 不自行实现代理协议、TLS、WireGuard 或 Android VPN 网络栈。
- 不 fork sing-box 来承载 Loom 控制逻辑。
- 不让客户端获得完整 SSOT、其他设备凭据或无权访问的服务清单。
- 不让移动端启动第二套系统 VPN 或加入独立 Headscale mesh；正式 WG control/L3 overlay
  必须由同一个 VpnService/libbox 运行时承载。
- 不依赖控制平面在线或拥有 quorum 参与数据转发。
- 不承诺连接建立后的无损路径迁移；切换只影响新连接。
- 不允许 Windows/Android 客户端本地新增或修改 matcher、Service、声明定义或
  fallback；客户端只能切换三种顶层模式，并在指定出口模式选择已下发节点。
- v1 不提供同一域名按账号选择不同固定出口的 profile。L4/TUN 看不到账号身份，
  该能力需要显式 profile、SDK 或 L7 代理，留待后续版本另行决策。

---
