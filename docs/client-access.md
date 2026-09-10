# Loom · 客户端接入设计

> **状态：** 本文定义跨平台客户端契约，不再复制易过期的实施进度。当前生产、真机验收
> 和剩余缺口只看 [status/current.md](status/current.md)。文中明确标为 v1 的单控制节点、
> 单平台签名和单 endpoint 是 v1 迁移输入；ControlSet/QC/EndpointSet 是 v2
> 目标协议。任一代协议的实施、部署与验收状态都不由本文声明。
>
> **设计复核日期：** 2026-09-10
>
> **适用范围:** Windows、Linux Server 与 Android 接入设备；v1 不考虑 Linux Desktop
>
> **上位约束:** [设计文档](design.md)中的模型、安全边界与控制平面不变量是
> v1 兼容边界；统一 Device、内部 Enrollment 协议和版本化对象图的迁移目标见
> [Device 生命周期与交付架构](device-lifecycle-and-delivery.md)，本文只展开平台客户端交付。
> 动态 `ControlSet`、QR v2、多控制入口、quorum certificate、托管域名和端口轮换见
> [分布式控制平面设计](distributed-control-plane.md)。它们是目标态；本文标出的单 endpoint、
> 单平台签名与 `generation` 是 v1 迁移基线，不能混写成已部署。
> 具名局域网访问是独立目标协议，
> 见 [Local Network 专题](local-network.md)。若专题与设计文档冲突，以设计文档为准。

---

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

> 本节记录为什么目标协议必须兼容 v1 数据形状，不作为实时进度表；实现与部署状态
> 统一由 `status/current.md` 维护。

v1 的兼容形状固定如下；这里只定义迁移约束，不声明仓库或部署进度：

| 边界 | v1 形状 | v2 迁移要求 |
|---|---|---|
| 平台 | `android` / `windows-desktop` / `linux-server`；拒绝含糊 `desktop` | 保持枚举稳定，能力通过 versioned view 协商 |
| 邀请 | 单 HTTPS enroll endpoint、一次性 token、平台 key digest、严格 schema | 并行 QR/invite v2，携带 bootstrap/recovery checkpoint、多个带 transport pin 的 direct seed |
| 配置 | 单签 current、全局 generation、静态多镜像 | per-device Merkle view、提交后 ControlSet QC；recovery、control、head 与 Device view 四组 durable floor（含 recovery policy hash）与不可逆 v2 latch |
| 报告 | enrollment 同源 report、canonical v5 + self-check v1、`200/204` | signed `EndpointSet(role=device_report)`；保留 producer 签名和原时间，跨 control CRDT 去重 |
| 数据入口 | 单 `public_endpoint + inbound_port`；客户端使用签名候选 | 稳定 logical endpoint；首版 Hysteria2/Trojan 支持多 listener generation overlap，WireGuard 另需双 interface/peer profile |
| 本机状态 | Linux 0600；Windows DPAPI；Android Keystore + 应用私有存储 | 原身份私钥不重建，原子增加 checkpoint/QC/EndpointSet、四组 floor、bootstrap transition hash 与 v2 latch |
| 路由偏好 | Direct / Auto / 指定出口是本机偏好；`default_declaration` 仅为 Auto catch-all | 语义不变，端口轮换和 control failover 不新增用户选择轴 |

v1 读写器对未知字段 fail closed，因此迁移只能新增明确版本的资源和 parser，先升级 reader、
再双发、再扩 ControlSet，最后撤销 v1 signer。任何 `Running`、bundle 验签、invite claim、
`ready` 或候选写入都不能单独解释成 VPN 已连接。v2 中 `committed_not_certified`
不是可激活状态：它不得发布 mutable current、改变客户端授权或驱动外部副作用；
`certified`、`mirrored`、`applied` 与 `healthy` 也必须分开。具体实现、发行签名和真机验收状态统一见
[当前状态](status/current.md)。

---

## 3. 目标与非目标

### 3.1 目标

1. 创建端先生成并封装 exact-version 一次性 token，再由管理员从已信
   certified `EndpointSet(role=control_api)` 选择入口，验证精确 transport identity
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
- 不让移动端加入常驻 WireGuard/Headscale mesh。
- 不依赖控制平面在线或拥有 quorum 参与数据转发。
- 不承诺连接建立后的无损路径迁移；切换只影响新连接。
- 不允许 Windows/Android 客户端本地新增或修改 matcher、Service、声明定义或
  fallback；客户端只能切换三种顶层模式，并在指定出口模式选择已下发节点。
- v1 不提供同一域名按账号选择不同固定出口的 profile。L4/TUN 看不到账号身份，
  该能力需要显式 profile、SDK 或 L7 代理，留待后续版本另行决策。

---

## 4. 客户端共同不变量

### 4.1 数据平面只有一个实现

所有平台都使用受版本约束的 sing-box 核心。Loom 负责生成候选、授权和路由规则，
客户端宿主负责启动、停止与观察核心。平台 UI 不能自己维护第二份路由判断。
Windows 与 Android UI 中的规则、Service、声明定义和当前路径均为只读；连接、
断开、重连和诊断属于生命周期操作。唯一的本地路由偏好是 Direct / Auto / 指定出口
三模式；客户端可以离线切换，但只能使用签名配置已经授权的规则、出口和凭据，不能
形成第二份 matcher、Policy 或候选模型。

### 4.2 配置与秘密分离

签名配置包只包含 `${secret:...}` 引用。设备加入网络后取得的凭据只进入本机安全
存储，安装前在本机合并。控制平面静态分发树和普通缓存节点不得出现明文秘密。

### 4.3 签名高于传输信任

HTTPS 保护传输，提交后的 ControlSet replication QC 证明 Raft 已提交且 quorum 已复算授权。
未加入客户端对 QR seed 只做一个受限的 bootstrap transport gate：先核对 descriptor 自带的精确
URL、hostname/WebPKI 与 SPKI pin，且只允许无 token、无 Device 凭据的 proof GET；取回 proof 后
必须完成下列 authority 链，才可发送 claim token。这个 gate 不把 seed 或 EndpointSet 提前提升为
配置 authority。

目标 v2 客户端激活稳态 DeviceView 必须按顺序验证：

- 部署专属 `BootstrapTransitionV1ToV2` 或新装 QR checkpoint、
  `recovery_epoch/recovery_statement_hash/recovery_policy_hash` 与
  合法 recovery/ControlSet transition chain；
- QC tag 与 head kind 必须匹配：stable QC 的去重 signer 必须属于该唯一
  ControlSet 且达到 `floor(N/2)+1`；Joint/Final transition QC 必须依 exact
  old/new signer refs 分别归属两个 ControlSet，两侧各自达到多数，不能合并成
  一个 union 后只计一次 quorum；
- head 是 Raft durable commit 后 apply/recompute 的结果，并带该结果的 replication QC；
  `committed_not_certified` 不得进入下一步；
- certified head 的单调坐标、`device_views_root` 与 transition proof；
- 本 Device canonical leaf 的 RFC 6962 inclusion proof、state、payload hash 与
  `endpoint_set_hash`；在此之前不得拨新 EndpointSet 或发送任何凭据；
- 由该 leaf 授权的 EndpointSet exact bytes，以及其中 URL、hostname/WebPKI、role/protocol、
  address/domain intent、credential/certificate generation 与 transport identity/SPKI pin 依赖；
- 配置包内容哈希；
- 本地四组 durable floor：
  `recovery_epoch/recovery_statement_hash/recovery_policy_hash`、
  `control_epoch/control_set_hash`、`control_revision/head_hash` 与
  `device_generation/device_leaf_hash/device_view_hash`；
- 客户端能够理解的 schema 和最低版本；
- 本设备确实在该快照中拥有配置。

下载点、DNS 和 TLS 终止点可以被替换或缓存，但不能使客户端接受 pin 不匹配、被篡改、属于
别人的、QC/proof 不足或已回退的配置。首次接受 v2 时必须把 transition hash、
上述四组 floor 与 `protocol_latch=v2` 原子耐久写入；之后 v1 current/QR/view
永不再成为 authority。v1 的单平台签名/generation 只允许在 latch 前的显式迁移
路径使用，不是 v2 QC。

### 4.4 离线继续运行

网络失败、全部已授权 `EndpointSet(role=device_config)` 入口停机、可达成员不足
quorum 或更新校验失败时，不删除
当前工作配置。客户端继续运行最后一次成功安装的版本，并把“控制入口不可达”“控制面
无 quorum”“副本落后”和“数据面不可用”分开显示。

### 4.5 fail closed

未知 schema、凭据缺失、签名失败和声明候选集为空都必须明确失败。Auto 模式完全
服从 certified Device view（或 latch 前已验证 v1 snapshot）的控制规则，未匹配 Service 时按
该视图的 fallback 处理。任何错误都不得自动
切换到 Direct 或指定出口；Direct 只在用户明确选择时启用。

### 4.6 顶层路由模式是唯一可写偏好

三个模式共用同一个 TUN/mixed 入口，不增加模式专用端口：

```text
Direct          → 全部本地直连，不生成 Loom 服务器路径
Auto            → Host → Service → Policy → Agent 自动选择完整路径
指定出口(node)  → 全部接管的业务流量最终从 node 出口；Agent 自动选择到 node 的前置路径
```

指定出口列表直接来自 SSOT 中全部在役 `egress_capable` 节点，不显示任意 IP 输入框。
固定出口只钉住服务器轴的最后一跳，不得关闭 Agent 对前置中继的授权选择。原生客户端
为每个底层网络代维护 probe registry。Direct 不冻结候选、不启动入口探测；该网络代第一次
进入 Auto 或指定出口时原子冻结当时的候选快照，只对其中去重后的授权入口各做至多一次轻量并行
探测；配置刷新、模式/出口切换和同一网络代内的断线重连复用该证据，不重复探测，也不把
同代后来出现的新入口加入主动探测集合。入口之后只复用可信服务器观测和
实际运行反馈，不主动扫描完整或业务路径，也不等待入口探测才启动数据面。
Current Paths 始终是只读观测，不是这三个模式的选择器。

签名配置包必须携带本设备获授权的出口节点与对应候选材料。客户端只在受保护的本地
偏好中原子保存模式（指定出口时再保存节点 ID），并切换本机 selector；控制面离线时
仍可依据最后一份已验证配置切换。偏好可以随状态上报供观察，但不是 SSOT 期望态，
无需为每次切换触发全网发布。若后续配置撤掉当前固定出口的授权，客户端保持选择可见、
明确标为不可用并 fail closed，不静默改成 Direct 或 Auto。

### 4.7 v1 服务端接口与本地三模式的边界

v1 单控制节点契约提供以下运维端点：

```text
GET /api/control/default-exit?node=<node_id>
PUT /api/control/default-exit
Content-Type: application/json

{"node":"win01","declaration":"de-fixed","revision":"<sha256>"}
```

GET 返回 `node`、当前 SSOT `revision`、当前默认策略和授权选项。每个选项只有
`id/name/mode/available`，不返回凭据、候选链、节点 IP 或完整拓扑；`id=""`、
`mode="none"` 表示未匹配即阻断。PUT 只接受 GET 返回且 `available=true` 的策略，
旧 revision 返回 HTTP 409，未知字段、任意节点/IP 或无权策略均被拒绝。成功写入
`access.default_declaration` 后，仍由现有发布器生成签名快照。

该接口是现有 catch-all 编辑器，不是客户端三模式接口：它没有 Direct 状态，也不能
表达“Auto 完全服从已验证且可激活视图的控制规则”和“全部接管业务流量
固定最终出口”的顶层互斥关系。
三态不需要新增 SSOT 字段或写 API；UI 不得把现有接口包装成三模式后端。

该 v1 运维端点只接受指定控制节点的 SameSite 运维会话，并要求 JSON PUT；契约不启用 CORS，也不接受
数据面凭据充当控制面身份。Windows/Android 客户端不得保存运维 cookie 或调用它。

目标 v2 中，管理客户端只能从已信 certified `EndpointSet(role=control_api)`
选择入口，验证精确 URL/hostname/WebPKI/SPKI pin 后再提交同一管理
proposal；接收端还必须验证 admin cert、certified ACL 与 expected
`{recovery_epoch, control_epoch, revision, head_hash}`。Raft commit
后 QC 未齐只能返回 `committed_not_certified`；取得提交后 quorum attestation 才返回
`certified`。`committed_not_certified` 不更新 mutable current、不授权客户端、不调用
DNS/CA/listener 等外部 executor。这不会把三模式改成远程偏好：Windows/Android
仍不持 admin credential，
本地三态仍不写 SSOT。

### 4.8 EndpointSet、域名与端口轮换

客户端从带 inclusion proof 的 Device view 获得按用途拆分的 EndpointSet：
`control_api/enroll/device_config/device_report/distribution/data_ingress` 不能互相推导。
Invite v2 只把一次性 token 发给 `InviteBootstrapDescriptorV2.delivery_context` 直接携带的 HTTPS
seed；首次 POST 前必须验证精确 URL、hostname/WebPKI 与 descriptor-carried TLS SPKI pin，并禁止
重定向。加入后，新 endpoint/pin 必须由已信 ControlSet 的 certified head 连续引入。DNS 只
解析已签 hostname，不能把任意新地址加入集合；合法 WebPKI 证书也不能替代 pin。

首版 Hysteria2/Trojan 数据入口使用稳定 logical endpoint ID 和多个 listener generation。正常 overlap 中旧、新
端口同时可用：新连接在 `prefer` 阶段先试新端口、失败立即回退仍 advertised 的旧端口；
既有连接留在旧端口直至自然结束。端口变化不改变出口节点、RouteCandidate 或三态选择。
Windows/Android 在每个底层网络代第一次进入 Auto/指定出口时冻结当时的候选快照，只对其中的 listener 与其他去重
授权入口各做至多一次并行入口测量；同代后来 advertise 的 listener 不主动 probe，只能从
真实拨号/回退取得被动证据，到下一底层网络代才可进入新的快照。配置刷新、模式/出口切换
或同代重连都不能重置预算。Linux access Agent 仍把 listener 纳入既有 `tuning/window` 预算，
但不得另起 rotation probe loop。任何平台都不能把测量扩张为额外业务 DNS/HTTPS 验证、重复
样本预热或数据面启动门槛。WireGuard 在双 interface/peer/key/address/route 专用 profile 完成
跨平台验收前只能显式 disruptive maintenance，不进入这套计划内无中断 scheduler。完整状态机见
[分布式控制平面 §13～§14](distributed-control-plane.md#13-endpointset-与公网端口模型)。

---

## 5. 总体架构

```text
                    Loom ControlSet(epoch)
         ┌─────────────────────────────────────┐
         │ 1..全部合格 control Device · q/N QC │
         │ 邀请/身份 · certified head/Device view │
         │ 多 EndpointSet · 观测 CRDT · 吊销     │
         └──────────────────┬──────────────────┘
                            │ HTTPS/mTLS；多 seed/mirror
                 signed view│ + transition/QC
                            ▼
        ┌──────────────── 客户端公共逻辑 ────────────────┐
        │ 加入 · endpoint failover · QC/迁移链验签      │
        │ 四组 durable floor + v2 latch · pull/hydrate  │
        │ 配置预检 · selector 控制 · 状态 · 最后可用版本 │
        └───────────┬─────────────┬─────────────┬────────┘
                    │             │             │
             Windows Service   systemd     Android VpnService
                    └─────────────┴─────────────┘
                                  │
                             sing-box 核心
                                  │
                         Loom 服务器链 → 目标
```

公共逻辑优先从现有 Go 包中提取，而不是在 Kotlin、Windows UI 与 CLI 中分别重写
验签、generation、候选和配置语义。平台无法直接复用 Go 运行时时，可通过稳定的
本地库边界或窄协议复用；不得复制一份行为略有差异的验证器。

---

## 6. 客户端组件边界

| 组件 | 职责 | 不负责 |
|---|---|---|
| 平台宿主 | 权限申请、前后台生命周期、服务启停、通知 | 候选生成、授权判断与本地策略编辑 |
| 配置客户端 | 保存 trust/ControlSet checkpoint；current/view/QC/transition 验证、recovery/control/head/Device view 四组 durable floor（含 recovery policy hash）、v2 latch、EndpointSet failover 与原子安装；保存本地三态偏好 | 数据转发、编辑控制规则或 Current Paths |
| 安全存储 | 设备私钥、客户端证书、凭据、API secret | SSOT 存储 |
| sing-box 核心 | TUN/mixed、DNS、出站协议、selector | 设备加入和应用更新 |
| 调度适配 | 使用已下发候选、测量、阻尼切换、保存最后排名 | 扩大候选集 |
| 状态与观测 | 当前版本、连接状态、有限 L4 指标、问题摘要 | 上传访问内容 |

客户端收到的是本设备最小配置，不是完整拓扑。服务器地址、候选 tag 和必要的
服务匹配可以出现；其他设备、平台密钥私有部分和无关声明不得出现。

---

## 7. 流量接管方式

### 7.1 TUN

TUN 适合无法逐个配置代理的应用，承担系统流量兜底。它需要系统权限，并必须排除：

- 客户端自身的控制面连接；
- sing-box 到第一跳服务器的连接；
- 本地回环与必要的局域网流量；
- 平台要求不能进入 VPN 的系统流量。

这里的“局域网排除”只是在避免 TUN 递归或破坏本机连接，不等于发布或访问远端
局域网。后者必须显式选择目标地址域，并受独立授权约束，见
[Local Network 专题](local-network.md)。

错误的 TUN 路由可能造成控制连接递归或设备失联，因此新配置必须先离线预检，
启动失败时恢复上一个工作配置。

### 7.2 mixed

mixed 同时提供本地 HTTP 与 SOCKS5 入口，适合浏览器、开发工具、CI、容器和
systemd 服务显式接入。v1 日常只提供 `127.0.0.1:1080` 一个遵循已验签 snapshot 规则的 mixed
入口；Windows 的 mixed 与 TUN 使用同一份 matcher → Service → `AccessDeclaration`
映射，Android 不提供 mixed。

Linux Server 默认只使用 mixed，避免改默认路由后锁死 SSH。应用使用
`socks5h://127.0.0.1:1080`，让代理端解析域名，避免本地 DNS 结果使出口判断失真。
HTTP 代理仍可复用同一个 mixed 监听。

旧“端口绑定声明”只在 Linux 作为命名明确、默认仅回环监听的兼容/高级覆盖保留，
用于迁移已有脚本或临时 CLI 强制出口。它仍受目标授权、候选集与 fail-closed 约束，
不得扩权，也不得出现在 Service 页面的主流程中。Windows/Android 不渲染或编辑
这类覆盖；生产既有端口迁移必须显式完成，不能静默复用端口号改变含义。

### 7.2.1 业务域名由最终出口解析

DNS 归属不因宿主平台变化。Direct 模式在接入设备本地解析并本地直连；Auto 和指定出口
必须把业务 FQDN 保留到实际候选链的最后一跳，由最终出口使用本机受管 resolver 解析，不能
把接入侧取得的 A/AAAA 沿链转发。Linux mixed 使用 `socks5h`；Windows/Android TUN 使用
FakeIP + 持久映射 + FQDN 恢复，或经过同一测试向量证明的等价机制。IP literal 保持原样。

EndpointSet 内 `control_api/enroll/device_config/device_report/distribution/data_ingress` 的
hostname 只用于建立受信传输，必须走与业务 FakeIP 分离的 underlay resolver/cache，并配合
hostname/WebPKI、transport identity pin 及平台防回环。它们不能被送到某个业务出口解析；
反过来，业务域名也不能借 bootstrap resolver 提前固化成接入侧 IP。

### 7.3 Windows Portable 与安装版

Portable 与 TUN/mixed 是两个维度：Portable 表示不通过 MSI 注册持久服务，TUN/mixed
表示流量接管方式。产品和测试说明必须使用完整名称，不能只写“Portable”让用户猜测
是否需要管理员权限或是否会修改系统网络。

| 运行形态 | 接管范围 | 管理员权限 | 系统改动 | 推荐用途 |
|---|---|---|---|---|
| **Portable Mixed** | 仅显式使用本机 HTTP/SOCKS 代理的应用 | 不需要 | 不创建虚拟网卡、不改系统路由 | 默认开发模式、浏览器、IDE、CLI |
| **Portable TUN** | 纳入 TUN 路由的系统 TCP/UDP/DNS 流量 | 导入二维码不需要；启用 TUN 前要求以管理员身份重启 | 加载 Wintun、创建虚拟网卡并修改路由；退出必须恢复 | 不支持代理的应用、UDP/QUIC、全局接管测试 |
| **安装版** | TUN 主接管 + 同规则 mixed | MSI 安装需管理员；日常 UI、导入和连接不需要 | MSI 注册 Service、创建受限 ProgramData ACL；普通用户经本机管道操作 | 常规 Windows 客户端 |

Portable TUN 只是“不装 MSI、不注册常驻 Service”，不是“零安装痕迹”或“普通用户 TUN”。
若启动失败、进程崩溃或电脑关机，下一次启动必须识别并清理遗留适配器/路由，再决定是否
恢复 previous。由于 Portable 文件通常位于用户可写目录，提权进程不得直接信任相邻 DLL：
必须重放 Loom 包签名与哈希校验、验证 Wintun Authenticode、限制 DLL 搜索路径，并从受
保护的运行槽启动。

Portable 状态默认放在 `%LocalAppData%\LoomPortable`，凭据使用用户范围 DPAPI；正式
安装版使用 `%ProgramData%\Loom`、机器范围 DPAPI 和受限 ACL。Portable ZIP 目录本身只
是运输载体，不是秘密存储。两种 Portable 形态与安装版都复用相同签名配置和 Direct /
Auto / 指定出口语义。Mixed 不保证覆盖未配置代理的应用、应用自带 DNS 或全部 UDP；
需要这些能力时才选择 TUN。

Windows 打包契约生成 `installed`、`portable-mixed`、`portable-tun` 三种内嵌身份（各含
amd64/arm64），并为每个 edition 生成一个完整 ZIP。ZIP 内包含 edition 对应的 EXE、
固定名称 `windows-dataplane.zip`、`PREVIEW-NOTICE.txt` 和静态链接依赖的许可证；客户端自动定位并验签组件，
不接受用户提供的组件路径。六个 ZIP 全部构建和验证成功后才进入发布阶段，并最后更新
`windows-clients-SHA256SUMS`；该清单是整组构建的提交标记，消费者必须据此拒绝中断造成的
部分发布。Windows 上另用 WiX 构建双架构 MSI，独立验证输入 ZIP 清单后最后发布 MSI
清单。构建默认输出未签名预览包；显式配置证书时先签 EXE 再打包，并独立签名 MSI。
要求正式签名的构建缺证书或时间戳就失败，不把预览包标成已签名发行。

三个构建复用同一套原生 GUI 和加入核心。Installed 普通用户界面经受限本机 named pipe
调用 SCM 服务，服务持有 machine-scope DPAPI 身份并运行现有加入/更新/数据面状态机。
MSI 将操作用户固定为安装时的 Windows 用户；管道只允许该用户和管理员，拒绝远程访问。
UI 在发送二维码凭据前核对管道服务 PID 与 SCM 注册记录。IPC 只接受状态查询、本地
连接配置的添加/选择/重命名、加入、连接、断开、签名配置已授权的出口偏好和本地删除；
配置操作使用有界标识和名称，由服务解析受保护目录，不接受任意路径、命令或配置正文。
产品状态机是：`未加入网络 → 导入二维码 → 正在加入 → 已加入 → 连接`。
二维码 PNG 与 `.loom-invite` 文件是同一次加入的等价输入；导入不会创建第二个 Device。
原生 Win32 GUI 使用“左侧连接配置列表、右侧选中配置详情与主动作”布局。侧栏加号将
右侧内容区切换为加入表单，左侧列表保留并暂时禁用；先提供二维码 PNG 或 `.loom-invite`
邀请并填写本地名称，校验后再提交加入，不因打开或取消表单而留下空配置。表单保留
与首页一致的一层白色内容卡片，不叠加居中模态框；卡片内部直接排列名称输入、邀请
说明与文件选择、粘贴按钮，不再嵌套上传卡片。
加入请求已经提交后的 pending 身份与恢复资料仍受
DPAPI 保护，失败时可继续重试，不能为了隐藏草稿而丢弃已经领取的身份。加入成功后
保持未连接，点击“连接”才接管流量。列表单击只改变查看对象；双击名称在原位置编辑，
Enter 保存、Esc 取消，也支持 F2 或右键重命名；不再常驻名称输入框和“保存名称”按钮。
名称只在本机保存，重命名不重启连接；实际连接另有状态标记。连接另一配置时，
先完整停止并等待原配置宿主退出，再启动新宿主，同一时间最多一个配置连接中或已连接。
每份配置独立保存 DPAPI 身份、签名候选、出口偏好和 Agent 证据；原单配置身份就地保留，
不迁移或重建身份。删除已断开的条目只清除该条目本地资料，不影响其他配置。
窗口标题栏、侧栏、状态与路径卡片使用统一的 Misaka 自绘外观，保留窗口拖动、缩放、
最小化、最大化和关闭语义。名称编辑与文件选择继续使用系统输入能力；支持选择或拖入
本地文件，不接受包含 bearer token 的进程参数。
尚未绑定的条目明确显示“未加入”，不能用本机名伪造 Device 或已连接网络。

状态文字左侧与列表条目都有对应图标：连接中为蓝色进度、已连接为绿色、断开中为灰色
进度、未连接为灰色、失败为红色；连接中允许取消。进度动画只刷新图标区域，同一份状态
轮询不重排或重绘整个窗口。连接后的“当前选路”按 Service 使用独立卡片，只读绘制
“本机 → 实际服务器链 → 服务目标”的路径图；节点数量与名称来自实际路径，目标地址
不成为服务器节点。展开详情分别显示当前底层网络代的单次入口证据、已验签服务器分段观测、
实际运行反馈、切换原因与读取时间。没有对应证据时保持未知；不显示“完整路径健康”、“最佳质量”或
客户端实测端到端 P50/P95，也不把服务器分段 RTT 冒充客户端测量。
Auto/固定出口复用当前共享 Agent 的
GET 读回投影，按签名 plan 映射 chain；Direct 同样 GET 验证授权零跳候选。界面后台至多
每五秒读取一次，不发探测、不写 selector、不增加报告。断开、出口切换或激活代次变化
清除旧路径，读取失败显示未知，缺测量不显示虚构的零值。该区域代表当前 selector 选择，
已有长连接可能仍沿用之前的路径。

通知区图标显示连接状态，关闭主窗口只收起到托盘，显式“退出 Loom”才停止当前前台
进程。Windows 的 EXE/Explorer、任务栏、窗口标题栏和通知区基础图标必须直接使用
`internal/webui/favicon.svg`；只允许从该 SVG 生成多种原生 ICO 尺寸，不得以重新绘制、
改色、反色、Windows 专用衍生图或 `loom-logo-v4.svg` 替换。已连接状态只允许在 favicon
右下角叠加 Windows 原生绿色盾牌，不改变底层 favicon。`assets/loom-logo-v4.svg` 仅用于
窗口左上角产品名旁的大尺寸品牌区。这是 Windows 客户端的固定资产规则，不以“小尺寸
优化”为理由更换图形。二维码
导入不启动 TUN、不改路由，也不要求管理员权限；Portable TUN 只在随后启用数据面前检查
管理员令牌，并由 GUI 在这个边界请求 UAC 重启。`config\client.json` 最后写入，作为普通启动可见的加入
完成标记；失败或 pending 时继续复用 DPAPI 保护的原身份，已加入状态拒绝被另一二维码
静默覆盖。v1 发行物契约内嵌部署平台公钥；它是公开的迁移/发行验证锚，不是 Device 凭据、
连接密钥或控制端地址。干净首启只等待二维码，不读取该公钥；导入或恢复加入事务时才加载它。
提交一次性加入码前，客户端先完成组件签名/架构校验，再把二维码携带的平台公钥 SHA-256
指纹与发行包内嵌公钥在本地比对，避免拿错部署包
后才消费加入码，也不为此增加另一条公网 API 或反向代理依赖。schema 1 registry 中尚未
消费的旧邀请在服务端升级时全部失效，不保留缺少该字段的旧二维码兼容路径。
目标 v2 把该 key 只用于验证一次 bootstrap transition，之后由 DPAPI 原子保存 recovery
anchor、ControlSet checkpoint/transition chain、EndpointSet（含 TLS SPKI pin generation/overlap）、
recovery/control/head/Device view 四组 floor（含 recovery policy hash）、bootstrap transition hash 和
`protocol_latch=v2`；不能把任一新
controller 的单 key 重新钉成永久平台 key。
Portable v1 兼容契约把二维码 pending 数据、ready 恢复日志和身份放在操作用户
DPAPI 下保护；
中控只允许同一 token、CSR、request ID、平台和 Device facts 在一小时恢复窗口内重放，
下次启动可继续，`config\client.json` 提交后立即清除 pending token。Installed 经 Service
使用 machine-scope DPAPI 与 `%ProgramData%\Loom`；安装器将目录设为 SYSTEM/管理员独占。
服务启动时检查目录所有者、ACL、重解析点和硬链接，拒绝将用户可写的旧预览状态当成可信机器状态。
全局进程锁阻止两个 Windows GUI 同时运行或两个数据面争抢端口/TUN，最终完成标记使用
create-only 提交；数据面锁覆盖整个 joined workload，不在子进程更新切换间释放。

二维码解析、身份绑定、signed first pull、TUN/mixed 生命周期、MSI/IPC、代码签名及各架构
实机覆盖属于独立验收项；设计文档不记录其完成勾选。交叉构建、进程启动或测试签名不能
替代真实权限、网卡、升级和网络切换证据，结果只见[当前状态](status/current.md)。

---

## 8. 平台设计

### 8.1 Linux Server

Linux Server 是交付优先的无 GUI 客户端形态；它与 Windows/Android 遵守同一
签名、授权、floor 和 certified 门禁。具体完成范围只见
[当前状态](status/current.md)。

**部署形态：**

- `loom` 静态二进制；
- sing-box 固定版本；
- `loom-pull.timer`、`loom-agent.service`、`loom-report.service`；
- 一个由控制平面配置的 `127.0.0.1:1080` mixed 日常入口，不创建 TUN；
- 可选的 Linux 兼容/高级覆盖入口，仅用于既有脚本迁移或显式 CLI 强制出口；
- 配置位于 `/etc/loom`，运行状态位于 `/var/lib/loom`；
- 秘密文件 root 所有、0600。

应用通过环境变量、显式 SOCKS/HTTP 参数、容器环境或 systemd drop-in 接入。安装
工具不应自动修改全局 `HTTP_PROXY`，因为这会影响包管理、控制通道和无关服务。

Direct / Auto / 指定出口共用 `socks5h://127.0.0.1:1080`，不新增端口。指定出口
可以是任一在役 `egress_capable` 节点，但前置路径仍由 Agent 自动择优。

**交付契约：** Linux 使用可校验的 `tar.gz`，包含 Loom、钉住版本的
sing-box、manifest、文件哈希与安装器。节点专属 systemd unit 不固化在通用包中，
而是在加入完成后的首份签名 bundle 中通过事务安装。v1 不要求 deb/rpm、通用
卸载器或独立客户端 GUI。实际制品状态见 current.md，操作见
[Linux 客户端安装](linux-client-install.md)。

### 8.2 Windows

Windows 不需要新的网络核心，但需要平台宿主：

**功能原型（定义布局与交互，不作为窗口逐像素实现）：**
[Windows 客户端首页 v2](../assets/client/windows/loom-client-home-misaka-v2.svg) 与
[重命名、添加和连接状态 v2](../assets/client/windows/loom-client-interactions-misaka-v2.svg)。
浅色 Misaka 外观采用紧凑配置侧栏、36 DIP 自绘标题栏、连接摘要和当前选路面板；各服务
在同一白色面板内逐行展示，用贯穿面板的细线分隔，测量标在对应连线上。交互沿用首页完整窗口、侧栏和单层白色
内容卡片：重命名只增加条目内编辑框，添加在右侧卡片直接排列表单，不嵌套上传面板；
连接中只更新原摘要状态。三个 edition
共用布局，以实际运行方式显示系统 TUN 或本地代理状态。原型中的 `demo-*` 身份与路径
与连线数值只用于说明结构，均为合成示例；[v1](../assets/client/windows/loom-client-home-misaka-v1.svg)
保留为早期视觉参考，v2 原型定义交互与分段测量展示契约。
窗口标题和托盘提示统一为 `Loom (Portable TUN) 已连接 · demo-work`，随版本、
连接状态和名称更新；有连接正在运行时显示实际连接，未连接时显示当前查看的配置。
展开详情时按链路分组，标题 12 DIP、正文 11 DIP，时间与诊断信息另行排列。每个服务按
自身内容计算行高，不共享最长行高；当前选路右侧不再显示用途提示。详见
[选路详情原型](../assets/client/windows/loom-client-route-details-misaka-v2.svg)。
出口列表打开时，滚轮在列表内浏览候选；移到右侧页面滚动时取消未确认的选择并收起列表，
不会切换出口。页面滚动直接批量平移控件，不重算详情行高；背景和子控件一并刷新。

- v1 产品契约由 Windows Service 以受控权限运行配置客户端和 sing-box；
- 托盘程序只调用本机受限控制接口，显示状态、启停和当前路径；
- 首次启动若尚未加入网络，前台界面显示“导入二维码”；该动作绑定控制平面已经创建的 Device；
- 连接信息只展示选中配置的加入状态、设备身份、操作系统与证书/配置状态，不是远端节点管理；
- TUN 用于系统流量主接管，`127.0.0.1:1080` mixed 用于明确设置代理的开发工具；
  两者使用同一份签名配置和同一个顶层路由模式；
- matcher、Service、声明定义和 fallback 只读展示；用户只可在签名配置给出的列表中
  选择 Direct / Auto / 指定出口，指定出口列表只含全部在役 `egress_capable` 节点；
- Current Paths 按 Service 只读展示实际读回路径，不提供节点点选、路径选择或 Apply；
- 设备密钥和凭据使用 DPAPI/CNG 保护；
- Portable 的配置与状态放入 `%LocalAppData%\LoomPortable`；Installed 目标态放入带受限
  ACL 的 `%ProgramData%\Loom`，都不写入用户下载目录；
- 安装器负责服务注册、TUN 驱动依赖、卸载与恢复；
- 程序和安装器必须经过 Windows 代码签名。

v1 产品形态是 Windows Service + TUN + 一个同规则 mixed。若某发行只提供
mixed-only 预览，必须明确标注“非全局接管”，且不能宣称 v1 已完成
或设备已完全受 Loom 管理。

Windows 为睡眠/网络变化建立新的底层网络代 probe registry；Direct 不探测，该代首次进入
Auto/指定出口时才冻结当时的候选快照，并对按地址与源接口去重的入口各探测至多一次；
同一网络代内的进程重连、配置刷新或模式/出口切换不重测，也不能把一次 Wi-Fi 重连当作配置
失效。服务升级与配置更新是两条流程：配置走 Loom 签名快照；程序升级走签名
安装包并保留可恢复版本。

**实现约束：**

- 新增依赖收敛的纯 Go Windows 客户端入口，不把包含发布器、SSH 接入和 Linux
  生命周期的 `cmd/loom` 整体搬到 Windows；
- 后台使用 Windows Service，平台适配通过 `golang.org/x/sys/windows/svc` 和带
  `windows` build tag 的窄实现完成；
- 三个 edition 使用纯 Go 调用 Win32 自绘窗口和路径图，复用系统输入、字体与文件选择
  能力；直接复用共享加入和运行状态机，不依赖 WebView2、.NET、Node、外部字体或额外
  GUI 运行时。品牌图形使用规定的既有资产，其他图标用简单矢量绘制；静止状态不启动
  连续渲染循环，状态变化与动画只使必要区域失效，保持小体积与低空闲开销；
- 高权限 Service 持有设备密钥、配置与 sing-box 生命周期，普通用户 UI 只通过带
  Windows ACL 的本机 named pipe 读取状态和执行已定义操作；
- 数据平面使用钉住版本的 sing-box Windows 制品和官方签名 Wintun，不自行构建或
  分发同名驱动；
- 设备密钥与凭据使用 DPAPI/CNG，安装器使用 WiX/MSI，发布制品由 Windows SDK
  SignTool 做 Authenticode 签名和验证。

**Linux/CI 开发边界：** 共享 Go 核心、三模式本地 selector、签名
pull/回滚状态机和本地控制协议可在 Linux/CI 验证，并通过依赖收敛的
Windows 专用入口交叉编译。包含发布、SSH、Linux Agent 和 Unix API 的全量
`cmd/loom` 不是 Windows 客户端构建目标；安装 MinGW 不能修正错误的程序边界。
GUI、Service、TUN/Wintun、睡眠恢复、安装器和 Authenticode 必须在 Windows
宿主终验；工具安装与已取得证据只见[当前状态](status/current.md)。

### 8.3 Android

Android 必须提供应用宿主，因为只有应用可以通过 `VpnService` 接管其他 App
流量并满足前台服务生命周期要求。

**界面原型：** [Android 客户端首页](../assets/client/android/loom-client-home-misaka-v1.svg)

Android App 包含：

- 加入网络二维码扫描与 `.loom-invite` 文件导入；
- Android Keystore 中的设备密钥；
- 配置 pull、平台验签、防回退和最后可用配置；
- sing-box Android 核心；
- `VpnService` 与常驻通知；
- 当前路径、连接状态、有限诊断与手动重连；
- 最小调度适配：实际 selector 读回、Direct 不探测、每底层网络代首次进入 Auto/指定出口时
  对按地址与源接口去重入口各至多一次轻量并行测量、
  服务器签名观测复用、离线沿用和实际路径状态上报。
- 中控下发的 package/domain/IP matcher、Service 与声明关系；界面只读展示生效
  结果；用户只能选择 Direct / Auto / 指定出口三种顶层模式。

**实现约束：**

- Kotlin + Gradle Kotlin DSL 作为平台宿主，Jetpack Compose 负责原生 UI；
- Android `VpnService` 建立系统 TUN，并按平台要求运行前台 Service 与常驻通知；
- 使用钉住版本的 sing-box `libbox.aar` 承担 TUN 和代理数据平面，不复制协议实现，
  也不把上游客户端的 profile/规则编辑模型带入 Loom；
- 应用的 A/AAAA 查询只接收持久化 FakeIP，连接进入 libbox 后恢复为 FQDN 并沿
  候选链传到最终出口解析；FakeIP 规则只匹配 `tun-in`，不会接管 libbox 自己的
  公网入口/bootstrap 解析；宿主对已经配置 TUN 地址但 libbox 未显式列路由的
  地址族补默认路由，保证 FakeIP 双栈都进入同一数据面；生产 TUN 显式使用 1500
  MTU，不能沿用上游 9000 默认值跨越普通移动/Wi-Fi underlay；
- `reverse_only` 只约束 WireGuard 发起方向。v1 latch 前，服务器在已验签 snapshot 中显式
  启用 `public_data_ingress` 时，移动端可获得到最终出口的一跳已配置 data-ingress transport
  候选（Hysteria2 或 Trojan）；v2 latch 后该布尔值单独无效，必须由 certified
  `PublicEndpointIntent` 和本 Device 的 `EndpointSet(role=data_ingress)` 授权。两跳国内中继
  保留兼容，但不得让同协议套叠的两跳候选压过同等健康的一跳路径；
- 继续使用现有窄 `mobile/loomcore` binding，通过 `gomobile bind` 与钉住的 libbox 一起
  生成 Android AAR，复用平台无关的 Loom 验签、generation floor、最后可用配置和
  selector 状态机；不得把完整 CLI/server core 绑定进应用，也不得在 Kotlin 中另写一套
  行为略有差异的验证器；
- 设备 P-256 identity/CSR key 与独立 wrapping/PoP key 都进入 Android Keystore；API 31+ wrapping
  使用 P-256 `SIGN|AGREE_KEY`，API 26–30 使用 RSA-2048 `SIGN|DECRYPT` + exact OAEP fallback，绝不
  导出软件 ECDH 私钥；应用私有目录只保存签名配置、状态和不能放进 Keystore 的最小材料；
- Emulator 用于 Compose、加入网络、权限和基本 TUN 流程，真实 Android 设备负责扫码、
  移动网络/Wi-Fi 切换、Doze、厂商后台限制、重启和长期运行验证。

v1 Android 必须先校验二维码平台 key 指纹，再以同一 Keystore key 绑定 CSR；signed pull
先持久化 generation floor，再验证 current/manifest/bundle。候选只经严格静态校验、secret hydrate、
libbox 配置预检、TUN/路由与 selector 本地启动验证后原子提交；这些本机检查不发送业务
DNS/HTTPS 请求，不等待入口或服务器观测才启动数据面。本地启动事务失败才恢复 previous。
canonical v5 与 self-check v1 由 Keystore 签名；移动计划必须与 selector、候选顺序、显式 chain 和授权一致。
Kotlin 宿主只负责生命周期、Direct 不探测、每底层网络代首次进入 Auto/指定出口时对按地址与
源接口去重入口各至多一次的轻量并行测量、Keystore 状态和
回环 selector 事务；配置刷新、模式/出口切换和同一网络代内重连不重测。它不运行候选预算轮换、
业务 DNS/HTTPS 探测或完整路径窗口聚合。

目标 v2 复用同一 Device identity key、经认证生成上述独立 wrapping key，并原子保存 ControlSet checkpoint/transition、QC、
recovery/control/head/Device view 四组 floor（含 recovery policy hash）、bootstrap transition hash、
`protocol_latch=v2` 和带 TLS SPKI pin generation/overlap 的 EndpointSet，不要求清除身份或重新扫码。
原生宿主、服务端纵向测试、Emulator 和真机
的实际完成范围只见[当前状态](status/current.md)；开发签名 APK、模拟器成功或 HTTP 204
不能冒充生产手机已经入网和可靠性验收。

Android 不安装 Linux 版 Loom Agent、systemd unit、`/etc/loom` 路径或 Loom
二进制自更新器。应用更新通过应用商店、企业 MDM 或签名 APK 渠道完成；Loom 只
更新配置和排名。

Android 同时只能有一个活动 `VpnService`。因此它不加入 Tailscale/Headscale
mesh；需要访问 mesh 内网时，由被授权的 Loom 服务器代为转发。Auto 模式由中控
规则按 package、domain 或 IP 匹配 Service；Direct 与指定出口是互斥的顶层覆盖。
相同 package 内同一域名的多账号无法由 L4/TUN 可靠区分，profile 能力不进入 v1。

### 8.4 开发、构建与验证环境

“能在某个系统生成制品”不等于“已经验证该平台语义”。平台无关逻辑尽量在 Linux
和 CI 中测试，操作系统生命周期、权限、驱动和安装事务必须在对应系统运行。

| 工作 | Linux / CI | Windows 实体机或 VM | Android Emulator | Android 真机 |
|---|---|---|---|---|
| 共享 Go 核心、配置验签与 selector 单测 | 主环境 | 原生复测 | 通过 AAR 间接验证 | 最终复测 |
| Windows Service 未签名 `.exe` | 可交叉编译 | 安装与运行验证 | — | — |
| Windows Portable 原生 GUI | 可交叉编译 | 文件选择、窗口生命周期与 DPI 布局验证 | — | — |
| Windows DPAPI、签名组件包、Wintun 与可执行预检 | 可交叉编译、验证 Loom 包签名和 PE/build identity | DPAPI、WinVerifyTrust、真实 `sing-box check` 与 Job Object 验证 | — | — |
| Windows TUN 激活、CNG、MSI 与 Loom 代码签名 | 只能准备共享逻辑和输入 | 必须完成管理员权限、驱动/路由恢复、安装和签名终验 | — | — |
| Android APK/AAB | 可无界面构建 | Android Studio 开发最方便 | UI/权限/基本 VPN | 移动网络与生命周期终验 |

原生测试必须分别覆盖 DPAPI machine/user scope、ACL、原子替换、SCM/LocalSystem、
WinVerifyTrust、`sing-box check`、Job Object、TUN/路由清理、MSI 升级及代码签名；一次
交叉编译或临时宿主验证不能替代其他项。具体已取得的证据和剩余终验只见
[当前状态](status/current.md)。

**推荐工作站：** 有真实 Windows 机器时，在 Windows 上 clone 同一仓库，用它同时
承担 Windows 原生客户端、Android Studio 和 Android Emulator。Windows 只构建明确
的客户端目标；含 Unix API 的全量 `cmd/loom` 与全仓后台测试在 Linux、WSL2
或 CI 运行。不要为两个平台复制 SSOT、matcher、Policy 或 selector 模型。

目标代码边界固定如下，使构建系统无需猜平台：

```text
clients/windows/       Windows Service、薄 UI 外壳与安装器
clients/android/       Kotlin/Compose、VpnService 与 Android 打包
internal/clientcore/   两个平台复用的平台无关 Go 核心
```

Android Emulator 本身就是专用虚拟机。它应直接运行在 Windows 实体机的系统虚拟化
上，或直接运行在独立 Linux builder 的 KVM 上；不要把它放进 Windows VM 再做嵌套
虚拟化。嵌套方案会增加性能、USB/相机和网络语义的不确定性，却不能替代真机测试。

**控制设备不是默认客户端开发机。** 是否能运行 Windows VM 或 Android Emulator，
由部署者在本地根据 CPU 虚拟化、`/dev/kvm`、内存、磁盘和当前负载核对；这些现网
硬件信息属于部署状态，不写入版本库。控制面承担生产职责时，不应默认再承载桌面 VM
或 Emulator。

确需在独立 Linux builder 建一台临时 Windows 开发 VM 时，最小栈为 QEMU/KVM + Q35
+ OVMF UEFI + swtpm 2.0 + qcow2。初期使用 QEMU user-mode NAT，安装画面和 RDP 只
绑定 `127.0.0.1` 并经 SSH 转发；不要先引入 libvirt bridge 去改动已有 Docker、
WireGuard 和 nftables。Windows 介质只能使用用户提供的合法 ISO 或微软正式
Evaluation ISO。该 VM 足以做 Service、UI、安装器与基本 TUN 集成，但真实睡眠、
Wi-Fi/有线切换和长期桌面行为仍由实体 Windows 终验。

若没有 Windows 工作站、只需 Android CI，则在**独立** Linux builder 安装 OpenJDK、
Android command-line tools、SDK、platform-tools、Emulator 和 x86_64 system image，
直接使用 KVM 跑 headless Emulator；只有自行重建 native AAR 时才增加 NDK。不安装
Android-x86 通用 VM。无界面 APK 可以在独立 builder 构建；生产控制设备不作为日常
Android Studio 或 Emulator 工作站。

---

## 9. 加入网络与设备身份

### 9.1 加入码与交付方式

创建端先用 CSPRNG 生成 token 并封装为 exact-version secret artifact；管理员从已信
certified `EndpointSet(role=control_api)` 选择入口，验证精确 transport identity 并用
admin cert 认证后，提交公开层只含 commitment/private-binding hash 的 Create Device/invite intent；
完整 exact-version ref 与明文一致性回执只保存在 control-private replicated binding。提案经 Raft durable
commit、apply/recompute 并获得 replication QC 成为 certified 后，renderer 才可解封同一 token
并一次性输出邀请。平台、Responsibilities、Destination grants 以及 `forward` 所需的 direction
在 exact `DeviceEnrollmentIntentV1` 提案中已经固定，并由 certified invite record
的 hash 承诺。客户端仍按自身
构建目标报告平台，控制平面要求它与 certified invite
精确一致；客户端不能在 claim 时选择或扩张职责。加入码不携带运行时路由模式或手选出口
参数；加入完成后再由客户端选择 Direct / Auto / 指定出口。QR/URI 中的有界
`InviteBootstrapDescriptorV2` 包含：

- `cluster_id/invite_id`、`bootstrap_transition_hash`、最低 recovery epoch/statement/policy hash、
  当前 ControlSet 与创建 intent 的 base-head commitment；
- 最多 3 个直接写入 descriptor 的精确 HTTPS seed enrollment endpoints（`role=enroll`），以及
  各自 TLS SPKI pin set/有效期；
- 短 TTL、单次使用的随机 token；
- token/context commitment、无 token immutable proof bundle hash、过期时间和协议 schema。

纯 `use_loom` 创建成功后页面呈现二维码图片和同一 descriptor 的可复制
`loom://enroll/v2#d=…` 内部协议 URI；最终 URI 不超过 1800 ASCII bytes，超限时不得生成不可扫
二维码。备用 `.loom-invite` 可以内嵌 descriptor 和完整无 token proof bundle。包含 `forward` 的 Linux Device 不提供二维码或
加入文件，只把该 URI 作为本地 shell 或管理员 SSH 登录目标机后执行同一 bootstrap 的
一次性标准输入；控制平面不保存 SSH 凭据。Windows
Portable 还可在 control 页面复制二维码图片后直接按 `Ctrl+V` 或点击“粘贴二维码”；图片只在
内存中解析，不写临时文件。这些 access-only 载体
共享 TTL 与单次消费状态；原始 token 只在创建结果中出现，列表不能再次取回。URI 的
fragment 由客户端本地解析，token 只在内部 claim POST body 发送，不进入 HTTPS query。
它们不包含长期凭据、完整 SSOT 或设备私钥。设备绑定不得依赖浏览器指纹，必须基于客户
端本地生成且不可导出的非对称密钥。

客户端只能使用 descriptor 直接携带的 seed。它先验证精确 URL、hostname/WebPKI 与 SPKI pin，
在不把 claim token 放入 URL/header/cookie/body 的前提下 GET 与 descriptor hash 一致的 immutable
`InviteProofBundleV2`，拒绝重定向；重算 token/context commitment 并验证 record inclusion、
bootstrap/recovery/ControlSet transition、head/QC 后，才可把 token 放进 claim POST body。
不能先信任未认证 DNS/HTTP 发现的新 URL。
seed 的提示顺序可来自 Web 实时观测，但不删掉其他已签 seed，也不成为 authority。加入后
端点变化必须由已信 ControlSet 的新 EndpointSet/QC 连续引入。

加入入口的 TLS 验收必须在受支持的 Android 真机系统信任库上执行，不能只用服务器侧
OpenSSL/curl 判定。服务端必须发送能一直构建到目标系统已有根证书的完整兼容链；例如
Let’s Encrypt Generation Y 的默认 ECDSA 链应继续经交叉签名构建到 ISRG Root X1，不能只
发送终止于部分设备尚未信任的 ISRG Root X2 的短链。客户端不得通过跳过主机名、证书或
系统时间校验来兼容错误链；部署时须按 CA 当前公布的 Chains of Trust 核对完整链。

### 9.2 加入流程

```text
已信 certified EndpointSet(role=control_api) 内入口验精确 transport + admin cert，接收管理员提案
    ↓ validate → Raft commit → apply/recompute → attest/QC
    ↓ certified 后返回带 checkpoint/base-head commitment、proof-bundle hash 和 seed pins 的有界 QR descriptor；加入文件可另内嵌完整 head/QC proof bundle
客户端导入 access-only QR/文件，或在 Linux 本地/SSH 会话执行 shell bootstrap
    ↓
设备在安全存储中生成独立的 P-256 identity/CSR key 与 intent 允许的不可导出 wrapping/PoP key
（Android API 31+ P-256，API 26–30 RSA fallback），只上传公钥、CSR 与 PoP
    ↓
仅本 descriptor 有界 EndpointSet(role=enroll) 内的 seed 在 transport pin 验证后接收，
    以 transport-only token envelope 提交绑定 device_id/platform/identity SPKI/wrapping SPKI 的 claim
    ↓
Raft durable commit 原子预留 token/Device ID，并承诺 Membership 计划、职责/grants、sealed
secret-artifact root 与 future Device view；尚不激活或交付
    ↓
apply/recompute 规范 reservation/head 字节，quorum 对相同结果 attest 并形成 claim config QC
    ↓
CA 验 claim QC 与最新 active/fenced profile后确定性签证，并把 first-result 写入 Raft issuance registry
    ↓
enrollment voters 验证 issued certificate、issuance entry/profile proof 后形成 approval QC
    ↓
approval-QC-authorized completion 进入第二个 ordinary head，current config QC 后原子消费 invite、
激活 Membership/Device view 并授权 artifact release
    ↓
返回绑定 claim/completion leaf/root/head/config+approval QC 的 ready receipt、节点证书、CA/checkpoint、只为 wrapping key 封装的本机秘密与分发坐标
    ↓
客户端验 bootstrap/recovery/transition/QC/inclusion proof/floor，原子 latch v2 后 hydrate、预检并安装
    ↓
客户端上报首份可信状态后，才可由运行态观测判定 online
```

Device 详情页的 Runtime evidence 只展示经过现有信任链验证的运行问题原文；未签名或
身份校验失败的客户端自述不能作为该问题详情。

加入网络不是单独的“注册客户端”流程，也不是日常连接动作。二维码导入只绑定 certified
invite 已经创建的 Device，不创建第二条记录。重连、网络切换、更新配置、更新程序和重新
启动都继续使用现有设备身份，不得再次要求二维码。v2 首次 POST 前，客户端验证 bootstrap
transition/checkpoint；v1 Windows 兼容流程比较二维码部署公钥指纹与发行包内嵌公钥。加入码
一旦成功绑定，控制平面只允许同一 token、同一 CSR/wrapping descriptor、
同一 request ID、平台和 Device facts 在限定的一小时恢复窗口内幂等重试；Windows
Portable v1 兼容契约将这组 pending 数据用操作用户 DPAPI 保护，并在加入提交后清除 token。
Installed 经受限 Service broker 使用 machine-scope/受保护 ProgramData。其他 CSR 身份重复消费、未知/不受支持的平台、设备 ID
已被另一身份绑定、SSOT revision 冲突或签名验证失败都不得留下部分加入状态。
加入码在成功绑定前过期时，详情页可重新生成加入码；创建端先封存新 token/artifact，再以
同一个 proposal 撤销旧 record 并创建新 record，事务 certified 后旧码才失效并一次性交付新码。
纯 `use_loom` Device 可显示二维码，包含 `forward` 的 Linux Device 只提供 shell/SSH 辅助交付。若已加入的纯
`use_loom` Device 丢失或删除了本机身份，管理员可在详情页确认后执行 Rejoin Device：
旧接入从 SSOT 移除，旧身份归档，新 ID 和新二维码沿用原名称、平台、职责与 grants。旧数据面凭据
随服务器应用签名配置撤销。该流程不复用已消费 token、不把新密钥绑定到旧 ID，也不
把本机删除解释为已完成远程停机。仍在 provisioning 的未完成身份及服务器职责的恢复
不走这一窄入口，须先处理其原事务。详见
[二维码重发与本机身份丢失](device-lifecycle-and-delivery.md#411-二维码重发与本机身份丢失)。

不需要替换时，详情页的 **Remove Device** 提交一个安全关键事务；只有该事务
Raft durable commit、apply/recompute 并取得 replication QC 成为 certified 后，才移除
纯 `use_loom` Device 的 SSOT membership 和专属数据面凭据，并把 enrollment identity
标为 revoked。它不要求
客户端在线或先消费 decommission，也不会声称已经清除客户端本机文件；旧连接在转发服务器
收敛到下一份 signed snapshot 后失效。包含 `forward` / `internet_egress` 的 Device 不走
该窄入口，因为删除前必须处理隧道、出口策略与依赖凭据。

### 9.3 稳态认证

首次加入使用客户端本地 P-256 key/CSR 签发 Device 证书，供可信报告和私有读取使用；
私钥不离机。目标 pull 同时验证 HTTPS/mTLS + WebPKI/SPKI transport pin、
提交后 ControlSet QC、Device Merkle proof、内容 hash、四组 durable floor（含 recovery
policy hash）与 v2 latch，任何一层都不能替代另一层。v1 兼容协议依赖 HTTPS、
单平台签名和 generation floor；严格 schema
决定了 v2 使用并行资源迁移，不能原位添加字段后声称兼容。

### 9.4 吊销

吊销设备需要同时产生两类结果：

1. 控制面拒绝该设备继续 pull 或上传；
2. 下一份服务器配置移除该设备凭据，阻止旧配置继续使用数据平面。

只做第一项不能阻止设备凭最后一份离线配置继续连服务器。吊销提案先经
确定性 candidate view 生成/校验后进入 Raft durable commit，apply/recompute 必须复得同一 view，
再由 replication QC 证明为 certified；此后才发布并由服务器应用这份已复算、已认证 view。
`committed_not_certified` 不得触发撤权副作用。传播完成前任一
control UI 都显示“已认证、数据面撤权
尚未全部应用”，不能提前显示完成；落后副本不得凭旧 membership 向已撤权 Device 返回
受保护数据。

---

## 10. 配置制品

### 10.1 两层制品

客户端包拆为平台无关期望态与平台安装层：

| 层 | 内容 | 是否跨平台 |
|---|---|---|
| common | 节点绑定、候选、声明、组件约束、签名/generation 元数据 | 是 |
| sing-box | 该设备的 inbounds、outbounds、route、DNS | 大部分可复用，需平台校验 |
| secrets map | 占位符到本机安全存储键的映射 | 语义复用，存储实现不同 |
| lifecycle | systemd / Windows Service / Android App profile | 否 |
| update policy | 最低客户端版本、兼容 schema、强制更新时间 | 语义复用，执行不同 |

同一 snapshot 可以含多个平台包，但每台设备只能下载并安装绑定给自己的包。

### 10.2 渲染目标必须显式

旧的 `desktop` 无法决定路径、服务管理器和安全存储，目标平台枚举拆成不可含糊的部署目标：

```text
linux-server
windows-desktop
android
```

部署目标是输入事实，不是根据运行时猜测。校验器必须拒绝 Android + systemd、
Windows + `/etc/loom`、Linux server + TUN 等矛盾组合。

### 10.3 原子安装

所有平台都遵循同一事务语义：

```text
下载 → 验签/防回退 → secret hydrate → 平台预检
     → 写入新槽 → 启动验证 → 提交为 current
                          └失败→恢复 previous
```

配置文件不得在原路径上逐个覆盖。客户端至少保留 current 与 previous；失败日志
不得包含凭据明文。

---

## 11. 安全存储

| 平台 | 设备身份 | 访问凭据 | 配置状态 |
|---|---|---|---|
| Linux | root 0600 文件；有 TPM 时可增强 | root 0600 secrets 文件 | `/etc/loom` + `/var/lib/loom` |
| Windows Portable | 当前用户 DPAPI | 当前用户 DPAPI | `%LocalAppData%\LoomPortable` |
| Windows Installed（目标态） | CNG/DPAPI，优先机器范围不可导出密钥 | DPAPI machine scope | DPAPI candidate + ProgramData ACL |
| Android | Android Keystore，优先硬件支持 | Keystore 包装的应用私有存储 | app private storage |

日志、崩溃报告和持久 UI 状态都不得包含完整 token、私钥、密码或可直接导入的配置。
access-only 的加入二维码、截图、加入文件和剪贴板文本都携带同一个短时 bearer secret，
必须只交给目标设备，不得保存到相册、诊断导出、聊天记录或工单。诊断导出默认脱敏，
并由用户显式操作。

---

## 12. 配置更新与程序更新

配置更新和客户端程序更新不能混为一条通道。

| 平台 | 配置更新 | 程序更新 |
|---|---|---|
| Linux | Loom 签名 snapshot + pull/apply | Loom release/A-B 机制 |
| Windows | Loom 签名 snapshot | 代码签名安装包，服务级回滚 |
| Android | Loom 签名 profile/ranking | 商店、MDM 或同签名密钥 APK |

配置可以高频收敛；程序升级必须显式推进、验证兼容 schema 并控制爆炸半径。
Android 签名密钥是应用升级身份，必须备份和严格控制；丢失后不能把新 APK 当作
原应用升级。

---

## 13. 状态与观测

客户端 UI 至少区分以下状态：

- 应用/系统服务是否运行；
- TUN 或 mixed 是否已接管流量；
- 当前配置 snapshot 与 generation；
- 目标 v2 的 recovery epoch/statement/policy hash、control epoch/set hash、
  certified head revision/hash/QC、Device generation/leaf/view hash 四组 floor，以及
  bootstrap transition hash 和 protocol latch；
- EndpointSet generation/digest、当前 endpoint/listener generation、preferred/draining 状态和
  本 Device 的轮换 applied/ACK；v1 界面必须明确这些字段不可用，而不是填入默认绿色；
- 当前命中的只读规则、Service、声明和候选路径；
- 当前顶层路由模式；指定出口模式还显示目标节点及其在当前签名配置中的可用状态；
- 数据平面最近是否成功；
- 控制面最近是否成功 pull；
- 当前是否使用 previous/离线配置；
- 凭据是否临近过期或已被吊销。

“VPN 图标存在”不等于数据平面健康，“某个 `EndpointSet(role=device_config)`
入口可达”也不等于有 quorum 或
用户流量可达。
客户端只按证据范围分别报告本机运行面、入口单次结果、已验签服务器分段观测与
实际连接/握手反馈；不为健康结论新增业务 DNS/HTTPS 或完整路径探测，未覆盖范围保持未知。

客户端只上报调度与排障必要的 L4 信息：时间、候选、连接/握手结果、延迟、有限
吞吐和版本状态。默认不上传域名访问历史、URL、请求头、响应内容或应用清单。

---

## 14. 故障与恢复

| 故障 | 行为 |
|---|---|
| 全部已授权 `EndpointSet(role=device_config)` 入口不可达 | 继续 current，显示配置入口离线 |
| 只能访问少数派/无 quorum | 继续 current；可读旧状态但不接受未认证变更 |
| head 已提交但 QC 未齐 | 标记 `committed_not_certified`，继续 LKG；不授权、不发布 mutable current、不驱动外部副作用 |
| 新配置 QC 不足、signer/用途错误 | 拒绝，不触碰 current |
| recovery epoch/statement/policy hash 或 control epoch 无合法 transition proof | 拒绝新信任集合并产生安全事件 |
| control revision、device generation 回退或同坐标异 hash | 拒绝并产生安全事件 |
| 新 listener 失败但旧代仍 advertised | 保持/回退旧入口，报告新代失败，不切换路由模式 |
| EndpointSet 中所有数据 listener 均不可达 | 代理模式 fail closed，不静默 Direct |
| hydrate 缺秘密 | 整包失败，不留下半成品 |
| sing-box 预检失败 | 不切换；保留 previous |
| TUN/本地路由/selector 启动失败 | 回滚 previous；若本地接管破坏系统网络，停止 TUN 并恢复本机路由 |
| 实际连接或握手在运行中失败 | 保留当前已验证配置，按证据范围标记失败/未知并重算授权候选；不因单个业务目标失败回滚配置 |
| 程序版本过旧读不懂 schema | 拒绝配置并提示升级客户端 |
| 设备被吊销 | 停止获取新配置；服务器侧凭据移除后数据面失败 |
| Android 被系统回收 | 按用户授权与系统规则恢复前台 VPN，不伪装成始终在线 |

Installed MSI 卸载停止并移除服务、程序和活动 TUN 路由；受限机器身份与操作用户记录
保留，重装继续使用同一 Device。主动清除身份须在客户端断开后确认“删除本机 Device”。
本机删除不等于控制平面吊销；需要重新加入时使用 control UI 的 Rejoin Device 流程生成替代身份与
二维码，不能手工修补 registry 或静默改绑。

Windows Portable 界面只在数据面已断开时启用“删除”操作，并二次确认后清除本机身份、
签名配置与运行状态；它不会伪装成控制平面吊销。操作者仍须经 control quorum 下线并吊销原 Device。

---

## 15. 依赖顺序

本节定义先后依赖，不维护完成勾选；代码、部署和真机进度只见
[当前状态](status/current.md)。

### 阶段 C0：拆分渲染目标

- 引入明确部署目标；
- 把 common/sing-box 与 lifecycle 产物分开；
- Android/Windows 包中禁止出现 systemd 和 Linux 路径；
- 为每个平台建立 golden 与矛盾配置校验。

**完成判据：** `phone` bundle 不再含 systemd、Linux Agent 和 `/etc/loom` 安装
假设；未知部署目标硬失败，并由三平台参考矩阵与矛盾配置测试锁定。

### 阶段 C1：固化 Linux 接入

- Linux Server 的加入、pull、一个 `1080` 日常 mixed、Agent、report、回滚形成安装流程；
- 将旧端口入口迁到命名明确的 Linux 兼容/高级覆盖，并验证不会扩权；
- 生成统一二进制分发包，并提供可重复安装和卸载路径；
- 不建设 Linux GUI 或托盘客户端。

**完成判据：** 新 Linux 设备从导入一次性加入码到首份可信在线状态无需手工复制秘密。

### 阶段 C2：设备加入与吊销

- 一次性加入码与二维码；
- 设备本地密钥生成；
- 设备绑定配置；
- 控制面和数据面双重吊销；
- 审计与过期处理。

**完成判据：** 被吊销设备即使保留旧配置，也在服务器收敛后无法继续使用。

### 阶段 C3：Windows v1

- 从 `cmd/loom` 拆出纯 Go `clientcore` 和独立 Windows 程序入口；
- Windows Service、路径和安全存储；
- 一个 mixed 首通，再完成 TUN；两种接入面渲染同一份已验签 v1 snapshot 规则；
- 客户端只读展示 matcher、Service、声明与路径，只提供 Direct / Auto / 指定出口；
- Portable 原生 GUI 直接读取用户态状态；Installed 托盘通过受限本机 IPC 读取 Service 状态；
- 签名安装器与 previous 恢复；
- Linux 交叉编译进入 CI，Windows VM/实体机完成安装、权限、驱动和签名验证。

**完成判据：** 睡眠、网络切换、服务重启和配置失败后都能恢复，卸载不残留活动
路由或服务。

### 阶段 C4：Android v1

- Kotlin/Compose `VpnService` 宿主与钉住版本的 sing-box libbox 集成；
- 二维码加入、Keystore、签名 pull；
- 共享分段决策、实际 selector 读回、离线可信证据和逐连线路径展示；
- 按已验签 v1 snapshot 的 package/domain/IP matcher 渲染规则，并提供 Direct / Auto / 指定出口；
- Emulator 覆盖 UI、权限和基本 TUN，真机覆盖前后台、网络切换与省电策略；
- 签名 APK 发布和升级演练。

Direct 不探测；Auto/指定出口在每个底层网络代首次进入时才冻结当时的候选快照，对按地址与
源接口去重的授权入口各测至多一次，之后只复用已验签服务器观测；不做
候选轮测、完整路径窗口或 `min_samples` 等待。开发签名 APK、纯函数调度测试和 Emulator
均不能替代生产受管配置、网络故障切换、前后台、Wi-Fi/蜂窝、厂商省电限制、固定升级
签名及覆盖升级的分别验收。

**完成判据：** 飞行模式、进程回收、重启、配置损坏和全部已授权
`EndpointSet(role=device_config)` 入口离线下均有可解释
状态，且不会泄露凭据或把系统网络留在不可用状态。

### 阶段 C5：分布式控制协议迁移（目标态）

- 并行发布 schema 2 QR/current/view，不修改 v1 strict JSON 字节契约；
- 三平台保存 bootstrap/recovery/ControlSet checkpoint/transition、提交后 QC、Device proof、
  recovery（epoch/statement/policy hash）、control（epoch/set hash）、head（revision/hash）、
  Device view（generation/leaf/view hash）四组 durable floor，以及 bootstrap transition hash 和不可逆 v2 latch；
- `control_api/enroll/device_config/device_report/distribution/data_ingress` EndpointSet 按用途和
  transport pin 分开并支持多入口故障切换；
- 同一 Hysteria2/Trojan logical data endpoint 支持新旧 listener overlap、prefer、drain 与 retire；
  WireGuard 未完成专用双 interface/peer profile 时只能显式 disruptive maintenance；
- 先完成 reader 覆盖，再从单成员 ControlSet 扩容并最终撤销 v1 signer。

完整依赖与验收见
[分布式控制平面 §19～§20](distributed-control-plane.md#19-从当前实现迁移)。

---

## 16. 测试矩阵

每个平台至少覆盖：

1. 首次加入、同一公钥幂等重试、其他公钥重复消费、过期加入码、未知平台，以及客户端
   拒绝安装部署目标不匹配的 bundle；
2. v1 latch 前迁移兼容，以及 v2 正确/不足/重复/未知 signer 提交后 QC、
   `committed_not_certified` 门禁、Device Merkle proof 篡改、recovery epoch/statement/policy hash、
   control epoch/set hash、revision/head hash 和 Device generation/leaf/view hash 回退、同坐标分叉与未知 schema；
3. secret 缺失、凭据轮换与设备吊销；
4. current → candidate → previous 的原子安装与进程中断恢复；
5. 控制面离线但数据面继续工作；
6. TUN/mixed 的 DNS、IPv4、IPv6、局域网与回环行为；同一业务 FQDN 在不同最终出口返回
   不同 A/AAAA 时，Android/Windows TUN 与 Linux `socks5h` 必须命中各自出口解析结果，
   Direct 仍本地解析；EndpointSet transport hostname 走独立 underlay resolver/cache 且不形成
   VPN 回环。具名远端局域网另按 [Local Network 专题](local-network.md)的显式作用域与
   fail-closed 边界测试；
7. 睡眠、重启、网络切换、无网启动和系统时间异常；
8. 客户端旧版本配新配置、客户端新版本配旧配置；
9. 日志、诊断包、UI 和崩溃报告不含秘密；
10. 人工验收可以由操作者显式发起真实业务流量，但结果不进入客户端健康/排名、不成为激活门槛，
    也不转化为周期性 DNS/HTTPS 或完整路径探测。
11. Windows 的 TUN 与 mixed 对相同请求应用相同顶层模式；Auto 模式命中相同
    Service/声明，Android matcher 与中控预览一致；除三态偏好外，本地新增规则或
    扩大出口集合必须被拒绝。
12. 多端口声明覆盖只在 Linux 兼容/高级模式出现，默认回环监听，且不能扩大目标
    授权或绕过 fail-closed。
13. Direct / Auto / 指定出口切换只复用现有入口；指定出口固定最后一跳但前置路径
    仍自动择优；控制面离线时可基于最后一份已验证配置切换，已撤权或非
    `egress_capable` 的固定出口必须 fail closed。
14. Current Paths 在所有模式下均为只读；任何路径选择或 Apply 控件都视为回归。
15. N=1/2/3/5 的动态 quorum、joint ControlSet 迁移、少数分区拒绝写、全部控制入口离线
    继续 LKG，以及 recovery transition 必须连续绑定 statement/policy hash 而不重置其他 floor。
16. 同 token 只能跨同一 descriptor 有界 `EndpointSet(role=enroll)` 的多个 seed
    并发 claim，且只绑定一个 SPKI；精确重试幂等；QR seed 故障、
    hostname/WebPKI 或 QR pin 不匹配、持合法未钉住证书的假端点、集合外重定向、旧副本与
    已撤权 membership 均在发送秘密前 fail closed/换已签 endpoint。
17. 数据入口轮换期间新旧端口重叠，新连接优先新代且可回退、旧连接排空；端口变化不
    改变出口/三态。Android 的 Direct 不探测；每底层网络代首次进入 Auto/指定出口时冻结
    当时的候选快照，同代新增 listener 不追加主动
    probe，只从真实拨号取得被动证据，也不追加整路径探测。
18. 首次 v2 接受原子保存 bootstrap hash、四组 floors（含 recovery policy hash）和 latch；
    冲突 bootstrap、latch 后 v1 current/
    invite/recovery replay、删除非关键 cache 后诱导降级均失败关闭；身份状态丢失必须重新入网。

---

## 17. 尚需决定的问题

以下是协议刻意不替部署者决定的实现/运维选择；启用相应能力前必须把选择、责任人和
轮换/恢复步骤写进私有部署记录：

1. Windows 安装器与代码签名证书的持有、轮换和 CI 签名方式；
2. Android 首版已选固定包名和升级密钥连续的私有签名 APK；若以后迁移到应用商店或企业
   MDM，如何保持同一 package/signing lineage、回滚与离线安装能力；
3. **已定方向：** v2 私有 control/config/report 通道使用分用途 mTLS，配置授权仍由 QC；
   待选择具体 CA/HSM/中间 CA 部署与迁移窗口；
4. 客户端规模是否仍是少量自建固定设备；若面向多用户，设备库存和授权关系不能
   继续全部塞进拓扑 SSOT，需要独立的设备/租户模型。
5. 三态本地偏好在系统升级、用户切换与配置回滚时的存储位置和恢复细节；它不是
   SSOT，也不复用 `default_declaration` 运维 API。
6. DNS provider adapter 的首个实现、委派 zone 和最小权限 credential；provider 选择不
   改变协议。
7. EndpointSet 的最大离线兼容窗口、旧会话 quiet period 与 emergency retire 审批门槛。

v1 已明确只提供 Direct / Auto / 指定出口这一项三态路由偏好，不提供 matcher、
Service、声明定义、fallback 或同域名多账号 profile 的本地编辑。若后续要引入这些
能力，必须新增模型、安全边界和决策记录，不能借用旧端口覆盖隐式实现。

在这些问题确定前，不启用会强迫所有平台 fork 客户端的自定义协议参数。
