# 客户端规范 · 共同不变量与组件边界

[客户端规范入口](README.md) · [文档地图](../README.md) · [源码能力](../development/implementation.md)

**规范状态：已批准的客户端契约。** 本文负责 共同不变量与组件边界；标为 v1 的内容仅适用于迁移输入，
v2 认证、对象与事务以[控制面规范](../protocols/control-plane/README.md)的对应条款定义。
平台运行情况由验收回执确认，正文不记录部署进度。

## 客户端共同不变量

### 数据平面只有一个实现

所有平台都使用受版本约束的 sing-box 核心。Loom 负责生成候选、授权和路由规则，
客户端宿主负责启动、停止与观察核心。平台 UI 不能自己维护第二份路由判断。
Windows 与 Android UI 中的规则、Service、声明定义和当前路径均为只读；连接、
断开、重连和诊断属于生命周期操作。唯一的本地路由偏好是 Direct / Auto / 指定出口
三模式；客户端可以离线切换，但只能使用签名配置已经授权的规则、出口和凭据，不能
形成第二份 matcher、Policy 或候选模型。

### 配置与秘密分离

签名配置包只包含 `${secret:...}` 引用。设备加入网络后取得的凭据只进入本机安全
存储，安装前在本机合并。控制平面静态分发树和普通缓存节点不得出现明文秘密。

### 签名高于传输信任

HTTPS 保护传输，提交后的 ControlSet replication QC 证明 Raft 已提交且 quorum 已复算授权。
未加入客户端从 QR 中的 2～3 个 `DistributionEndpointSetV1` 镜像只能执行无 token 的
内容寻址 GET；按 descriptor 的 `bootstrap_catalog_hash` 和 `proof_bundle_hash`
分别验证静态 catalog/proof bundle 及其 authority 链后，才可使用其中的
`BootstrapIngressEndpointSetV1`。公开 proof 只含
`DeviceEnrollmentIntentCommitmentV1` 及其认证路径，不含 Device intent 的明文或 opening；
完整 `DeviceEnrollmentIntentOpeningV1` 只能在选中 ingress、建立受限隧道并验证
内层 TLS 后，由不含 token/CSR/key 的 `EnrollmentIntentPreflightRequestV1` /
`EnrollmentIntentPreflightResponseV1` 取得并与 commitment 核对。公网 Nginx 只提供 fake
website 和 immutable distribution，不接收、不转发 Enrollment，也永远不应看到
token、intent/opening、CSR、PoP 或 Device 凭据。

客户端从当前 underlay 对已验 bundle 中的实际 bootstrap transport 做一次有界并行测量，
优先 Hysteria2，正式版再以独立 Trojan/TLS TCP listener 处理 UDP 全阻断。镜像 HTTPS
RTT 只能帮助选下载源，不是 bootstrap path 质量。选定入口后，客户端才出示
短期 `BootstrapTunnelCapabilityV1`，其路由 ACL 只允许 descriptor 中
`PrivateEnrollmentServiceRefV1` 的 overlay IP/TCP port。内层 server-auth TLS 在客户端与
ControlSet 间终止。客户端先完成上述无 token preflight，再以稳定
`EnrollmentClaimCoreV2` 构造 claim；身份/CSR key 对含新鲜 server nonce 的
`EnrollmentPoPBodyV2` 签名，wrapping key 只用于封装凭据。`EnrollmentClaimSubmissionV2`
中的 token、`EnrollmentPoPChallengeV1` 和 detached signature 不进入稳定
`claim_core_hash`；重试必须保持 core 完全一致，但可对新 server nonce 重签。这些材料
只在内层 TLS 中发送，公网 ingress 看不到。

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

### 离线继续运行

网络失败、Loom overlay 或 `ControlServiceDirectoryV1` 中 `role=device_config` 的全部已授权私有服务停机、可达成员不足
quorum 或更新校验失败时，不删除
当前工作配置。客户端继续运行最后一次成功安装的版本，并把“控制入口不可达”“控制面
无 quorum”“副本落后”和“数据面不可用”分开显示。

### fail closed

未知 schema、凭据缺失、签名失败和声明候选集为空都必须明确失败。Auto 模式完全
服从 certified Device view（或 latch 前已验证 v1 snapshot）的控制规则，未匹配 Service 时按
该视图的 fallback 处理。任何错误都不得自动
切换到 Direct 或指定出口；Direct 只在用户明确选择时启用。

### 顶层路由模式是唯一可写偏好

三个模式共用同一个 TUN/mixed 入口，不增加模式专用端口：

```text
Direct          → 全部本地直连，不生成 Loom 服务器路径
Auto            → Host → Service → Policy → Agent 自动选择完整路径
指定出口(node)  → 全部接管的业务流量最终从 node 出口；Agent 自动选择到 node 的前置路径
```

指定出口列表直接来自 SSOT 中全部在役 `egress_capable` 节点，不显示任意 IP 输入框。
固定出口只钉住服务器轴的最后一跳，不得关闭 Agent 对前置中继的授权选择。
Windows/Android 的网络代 registry、入口预算、被动证据与启动边界统一遵守
[客户端消费规范](observations.md#客户端消费边界)。
Current Paths 始终是只读观测，不是这三个模式的选择器。

签名配置包必须携带本设备获授权的出口节点与对应候选材料。客户端只在受保护的本地
偏好中原子保存模式（指定出口时再保存节点 ID），并切换本机 selector；控制面离线时
仍可依据最后一份已验证配置切换。偏好可以随状态上报供观察，但不是 SSOT 期望态，
无需为每次切换触发全网发布。若后续配置撤掉当前固定出口的授权，客户端保持选择可见、
明确标为不可用并 fail closed，不静默改成 Direct 或 Auto。

### v1 服务端接口与本地三模式的边界

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

目标 v2 中，已入网管理客户端只能经 Loom overlay 从已信 private
`ControlServiceDirectoryV1` 中 `role=control_api` 的私有服务
选择入口，验证精确 overlay IP 和内部证书身份后再提交同一管理
proposal；接收端还必须验证 admin cert、certified ACL 与 expected
`{recovery_epoch, control_epoch, revision, head_hash}`。Raft commit
后 QC 未齐只能返回 `committed_not_certified`；取得提交后 quorum attestation 才返回
`certified`。`committed_not_certified` 不更新 mutable current、不授权客户端、不调用
DNS/CA/listener 等外部 executor。这不会把三模式改成远程偏好：Windows/Android
仍不持 admin credential，
本地三态仍不写 SSOT。

### EndpointSet、域名与端口轮换

用途必须在类型层拆分，不能从同源 URL 互相推导：

| 类型 | 可达性 | 用途 |
|---|---|---|
| `DistributionEndpointSetV1` | 公网 FQDN + TCP 443/替代端口 | Nginx fake website 与无秘密 immutable distribution |
| `BootstrapIngressEndpointSetV1` | 公网 HY2/UDP；正式版独立 Trojan/TLS TCP fallback | 建立短期、限路由 bootstrap tunnel |
| `ControlServiceDirectoryV1` | 只经临时或正式 Loom overlay 可达 | 按 role 分离 `control_api`、`enroll`、`device_config` 与 `device_report`；每项绑定 overlay IP、内部证书和主体策略，普通客户端不获取 control peer directory |
| `DataIngressEndpointSetV2` | 公网或已授权私网 transport | 正式数据转发 |

QR 只携带 token/commitment、trust checkpoint、`bootstrap_catalog_hash`、
`proof_bundle_hash`、2～3 个跨故障域的 distribution mirrors、有界
`PrivateEnrollmentServiceRefV1` 和短期 capability；完整 bootstrap ingress 集合位于
内容寻址 catalog。公开 proof 只证明 intent 的 hiding commitment，完整 opening 只在
受限隧道内的 token-free preflight 交付。`.loom-invite` 可作为完整离线载体，
但和 QR 承载同一协议对象，不能把 intent/opening 发布到公网 mirror。
加入后的新 endpoint/pin 必须由已信 ControlSet 的 certified head 连续引入。DNS 只
解析已签 hostname，不能把任意新地址加入集合；合法 WebPKI 证书也不能替代已签 transport identity。
服务器侧同样不能靠手写 `listen` 或一张合法证书扩大入口：HY2/Trojan socket 必须逐项匹配
certified EndpointSet、PublicAccessProfile、frozen rotation tuple、资源池/NAT mapping、SNI 与
SPKI pin，且 transport credential 只在 catalog/listener 有效期交集内接受。同一 listener generation
的全部本地 tuple 必须先全部 bind 成功再开始 accept；任一 bind 失败要关闭本批已创建的 socket，
运行中任一 listener 异常退出则取消并关闭整批，不能留下只覆盖部分地址族的活跃 generation。
runtime 只有在同步完成全批 bind 并启动 transport goroutine 后才允许 local verify；local verify 对每个
exact bind tuple（wildcard 仅换成同地址族 loopback）完成真实 TLS/QUIC handshake，并生成绑定 prepared
certified state 的一分钟短期 evidence。
external verify 使用从上述 opaque binding 导出的 exact public IP:port 计划，分别完成真实 HY2/QUIC
或 Trojan/TLS outer handshake，只记录 TLS 1.3、ALPN 和 certified SPKI，不发送 capability；结果由
rotation 冻结 policy 中足量、跨故障域的 Ed25519 observer 签名，重启后从完整 artifact 重验，不能用
节点自报成功、DNS readback 或一个任意 evidence hash 代替。
外部 observer 使用 `loom bootstrap probe-outer -plan <canonical-json> -observer-id <id>
-key <0600-ed25519-key> -ca <roots.pem> -o <observation.json>` 执行这一步；命令拒绝非 canonical plan、
symlink/权限过宽私钥和混杂内容的 CA bundle，失败不改写既有报告，成功只原子写出 canonical 签名
observation。省略 `-ca` 时明确使用运行 observer 的系统 trust store，仍须同时命中 certified SPKI pin。
`advertised` transition 必须同时通过 local 与 external verified artifact 校验，不能只填两枚形状合法的 hash。
服务端以单一 prepared-generation handle 串起启动、local evidence、外部计划与签名聚合；local verify 失败
会等待整批 listener 关闭，listener 提前退出后该 handle 也不能继续产出 external evidence 或放行 advertise。

首版 Hysteria2/Trojan 数据入口使用稳定 logical endpoint ID 和多个 listener generation。正常 overlap 中旧、新
端口同时可用：新连接在 `prefer` 阶段先试新端口、失败立即回退仍 advertised 的旧端口；
既有连接留在旧端口直至自然结束。端口变化不改变出口节点、RouteCandidate 或三态选择。
Windows/Android 将 listener 作为普通授权入口，遵守同一
[网络代预算](observations.md#客户端消费边界)，轮换不额外触发测量。
Linux access Agent 仍把 listener 纳入既有 `tuning/window` 预算，
但不得另起 rotation probe loop。任何平台都不能把测量扩张为额外业务 DNS/HTTPS 验证、重复
样本预热或数据面启动门槛。WireGuard 在正式入网后承担持久 control/L3 overlay，
不作为首版 bootstrap transport；其双 interface/peer/key/address/route 专用 profile 完成
跨平台验收前只能显式 disruptive maintenance，不进入这套计划内无中断 scheduler。完整状态机见
[EndpointSet、catalog 与公网端口模型](../protocols/control-plane/endpoints.md#endpointsetcatalog-与公网端口模型)。

---

## 总体架构

```text
          公网 Nginx mirrors          公网 bootstrap ingress
       fake + immutable distribution       HY2 / Trojan-TLS
                    │                         │短期限路由隧道
                    └────────────┐    ┌──────────┘
                                 ▼    ▼
                    Loom ControlSet(epoch)
         ┌─────────────────────────────────────┐
         │ 1..全部合格 control Device · q/N QC │
         │ 私有 Enrollment/control/config/report │
         │ certified head/view · 观测 CRDT · 吊销 │
         └──────────────────┬──────────────────┘
                            │ Loom overlay + mTLS
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

## 客户端组件边界

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
