# EndpointSet、catalog 与端口模型

[文档地图](../../README.md) · [架构入口](../../design.md) · [控制面规范](../../distributed-control-plane.md) · [实现对照](../../implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

## 13. EndpointSet、catalog 与公网端口模型

### 13.1 按用途拆分，不再使用公开 role=enroll/control

一个通用 EndpointSet 里混装 distribution、Enrollment 和 control 会让 transport trust 扩权。
独立的链路授权先使用以下逐边契约；EndpointSet 只投影客户端可拨入口，不能替 LinkIntent 创造
server-to-server 边：

~~~text
LinkIntentV1
  schema = 1, cluster_id, link_id
  from_device_id
  to                              # tagged union: device_id | service_id
  purpose                         # control_overlay | data_forward | bootstrap
  allowed_transports[]            # wireguard | hysteria2 | trojan_tls；稳定排序
  initiator                       # from | to；由可达性验证后经共识固化
  listener_resource_refs[]
  credential_refs[]
  route_scope
  generation, parent_head_hash
~~~

LinkIntent 的发起方向不授予访问权限；一个 transport 可用也不允许将该边用于另一 purpose。目标
wire 不含 Device-wide direction。既有“境外端主动向境内端建立 WG”只是一条 data_forward
LinkIntent 的 initiator/transport 选择；同一逻辑数据边可在两端可达性、认证和 profile 均满足时
改为 HY2，不代表全网切换。HY2 未实现并验收 L3-over-HY2 前不能替换 control overlay 的 WG，
默认也不把 WG 套在 HY2 内。目标 EndpointSet/Directory 明确分为：

Linux reader 不接受命令行现造的 LinkIntent。它只读取 current Device view 中
`linux-link-intents` config ref 按 size/content hash/render contract 承诺的 exact canonical artifact，
再将每条 intent 与 Device responsibilities/grants、已安装 credential ID、endpoint transport 和
listener generation floor 交叉验证。服务端 producer 必须先以待生成 Head 的 parent hash 固化
artifact，再把 typed artifact ref 纳入新 Device view/Head；reader 要求 artifact 的
`authority_head_hash` 与 certified Head 的 `parent_head_hash` 精确相等，不能接受同一 Head 的循环
自引用或只凭一个可解析 hash。`control_overlay` 只允许 WireGuard，且本机与对端都必须出现在
Head 的 `control_peer_directory_hash` 绑定的 exact private directory；active 运行面一律拒绝 bootstrap intent。
新连接只按 preferred→advertised 取当前可拨代，draining/过期/低于已见 floor 的代均不进入计划，
也不会扫描相邻端口。

Linux 的第二级 `linux-runtime-v1` config artifact 是服务端 renderer 对上述授权计划的确定性投影。
它必须绑定 exact `linux-link-intents` content hash/generation，并逐项声明
`link_id/link_generation/mode/transport/endpoint_id/listener_generation/config_path/runtime_tag`；客户端
将其与已经落盘的 runtime plan 作集合级 exact 比较，不能靠数组顺序、相邻端口或本机角色补全。
artifact 只能写固定的 sing-box/Agent/WireGuard v2 目标，内容仍保留 LinkIntent 授权的
`${secret:...}` 引用。Linux 在本机 hydrate 后检查 JSON/WireGuard hook、certified FQDN/port/TLS 与
TUN/mixed 语义，再通过受 inventory CAS 保护的 staging/precheck/install/restart/verify/rollback
事务启用。生成的 systemd unit 固定在客户端代码中，服务端 artifact 无权下发任意 ExecStart。
Device view 进入 `revoked`/`decommissioned` tombstone 后，Linux 只按上次受保护 inventory 做
CAS 约束的事务下线；先停对应 v2 unit，再删除自身安装过的固定路径。terminal view 已清除的
artifact/secret 不得由命令行补回，active view 也不能调用 tombstone 下线入口。

~~~text
ListenerGenerationV2               # public；同一 logical endpoint 的一个可拨物理代次
  schema = 2, listener_generation
  published_state                   # advertised | preferred | draining
  dial_target_fqdn                  # 必须等于该 forward server 的 certified 稳定 FQDN
  public_port, address_families[]
  transport_identity_refs[]         # WebPKI/pin、HY2/Trojan credential 或 WG peer ref
  credential_generation
  certificate_identity_projection_hash? # TLS transports 必需，WG 禁止；例行续签不改变稳定身份
  public_profile_generation, introduced_revision
  valid_from, valid_until
  retire_not_before?                # 可选的旧代最早物理退役时间；guard 仍是最终门槛
  rotation_operation_hash

ListenerGenerationTombstoneV1      # public terminal fact；不再可拨
  schema = 1, listener_generation
  terminal_state                    # retired | revoked | abandoned
  terminal_at, reason
  rotation_operation_hash
  last_listener_generation_hash

DistributionEndpointV1
  endpoint_id, logical_server_id
  transport = https
  distribution_path_prefix = "/distribution/sha256/"
  listener_generations[]: ListenerGenerationV2
  listener_tombstones[]: ListenerGenerationTombstoneV1

DistributionEndpointSetV1          # public，可进 QR
  schema = 1, cluster_id, endpoint_set_id, generation
  valid_from, valid_until
  endpoints[]: DistributionEndpointV1
  parent_head_hash, config_qc

BootstrapIngressEndpointV1
  endpoint_id, logical_server_id
  transport                         # hysteria2 | trojan_tls
  hint_rank                         # 仅无实测时排序；不扩大 capability
  listener_generations[]: ListenerGenerationV2
  listener_tombstones[]: ListenerGenerationTombstoneV1

BootstrapIngressEndpointSetV1      # public catalog；不含 token/capability
  schema = 1, cluster_id, endpoint_set_id, generation
  valid_from, valid_until
  endpoints[]: BootstrapIngressEndpointV1
  parent_head_hash, config_qc

DataIngressEndpointV2
  endpoint_id, logical_server_id
  transport                         # hysteria2 | wireguard | trojan_tls
  listener_generations[]: ListenerGenerationV2
  listener_tombstones[]: ListenerGenerationTombstoneV1
  path_capabilities[]

DataIngressEndpointSetV2           # Device view；正式数据入口
  schema = 2, cluster_id, endpoint_set_id, generation
  valid_from, valid_until
  endpoints[]: DataIngressEndpointV2
  grants_root, parent_head_hash, config_qc

ControlServiceDirectoryV1          # private；只走认证的 Loom channel
  schema = 1, cluster_id, generation
  services[]: PrivateControlServiceV1
  control_set_hash, previous_directory_hash?
  parent_head_hash, config_qc

PrivateControlServiceV1
  service_id
  role                              # control_api | enroll | device_config |
                                    # device_report
  overlay_ip, port
  certificate_profile_ref, spki_pins[]
  authorized_subject_profiles[]
~~~

ControlServiceDirectoryV1 是 admin/Device/Enrollment 使用的私有 service directory；它与只供 voter
建立 Raft/复制连接的 ControlPeerDirectoryV1 是两个对象，均不得公开。两者可引用同一 control
Device，但不能复用证书 profile、ACL 或把 peer endpoint 下发给普通 Device。

各对象唯一摘要使用以下 domain：

~~~text
link_intent_hash                 = H(frame("loom-link-intent-v1", JCS(LinkIntentV1)))
listener_generation_hash        = H(frame("loom-listener-generation-v2",
  JCS(ListenerGenerationV2)))
listener_generation_tombstone_hash = H(frame("loom-listener-generation-tombstone-v1",
  JCS(ListenerGenerationTombstoneV1)))
distribution_endpoint_set_hash   = H(frame("loom-distribution-endpoint-set-v1",
  JCS(DistributionEndpointSetV1)))
bootstrap_ingress_set_hash       = H(frame("loom-bootstrap-ingress-endpoint-set-v1",
  JCS(BootstrapIngressEndpointSetV1)))
data_ingress_endpoint_set_hash   = H(frame("loom-data-ingress-endpoint-set-v2",
  JCS(DataIngressEndpointSetV2)))
control_service_directory_hash   = H(frame("loom-control-service-directory-v1",
  JCS(ControlServiceDirectoryV1)))
~~~

公开材料不再出现 role=enroll 或 role=control_api 的 HTTPS seed。Bootstrap ingress 只提供受限
transport，真正 enroll 是 ControlServiceDirectory 中的 private service。ControlServiceDirectory
完整 preimage 不进入公开 mirror；Invite descriptor 只携完成该次 claim 所需的一个有界
PrivateEnrollmentServiceRef。

每个 set 的 `endpoint_id` 标识稳定逻辑入口，嵌套的 `listener_generation` 标识物理 listener 代次。
同一 endpoint 内 generation 严格递增且唯一；同一代只能出现一次。`preparing` 只存在于 private
rotation state，绝不发布；可拨数组只接受 advertised/preferred/draining，retired/revoked/abandoned 只接受
tombstone。每个含可拨代的 logical endpoint 必须恰有一个 preferred 代；tombstone 必须引用该代最后发布 bytes 的
hash，低于客户端已见 generation floor 的可拨代不得复活。端口变化不能生成新的 logical_server_id，
也不能让客户端把同一 server 当成新的最终出口。
三类公网 Endpoint 的每个 listener 都必须使用其 forward server 已认证的稳定 FQDN；公开 wire
拒绝 IP literal。overlay IP 只出现在私有 service/peer directory 与本次邀请的有界 Enrollment ref。

### 13.2 公网与本地资源的分离

客户端可见 Endpoint 只包含它实际拨号的公网 tuple、transport identity、generation 与状态；
local bind port、NAT 内部地址、provider mapping ID 和防火墙 handle 只存在于 private
ForwardServerListenerResourcesV1。renderer/reconciler 必须证明以下链条后才 advertise：

~~~text
certified Endpoint public tuple
  ↔ active PublicAccessProfile
  ↔ verified DNS
  ↔ installed local listener
  ↔ direct reachability 或 exact transport-matching NAT mapping
  ↔ external probe success
~~~

端点状态：

| 状态 | 新拨号 | 已有会话 | 目录可见性 |
|---|---:|---:|---|
| preparing | 否 | 不适用 | private diagnostics only |
| advertised | 可作为候选 | 保留 | 新旧并存 |
| preferred | 优先 | 保留 | 正常 |
| draining | 不再选 | 保留至 deadline | 保留给旧 session |
| retired | 否 | 强制结束后清理 | 从新 set 移除 |
| revoked | 否 | 立即终止 | 保留审计 tombstone |

PublicAccessProfile 和 endpoint generation 必须一起被 certified head 引用；单独修改 DNS、NAT 或
本机配置不能使端点生效。

### 13.3 transport 与端口约束

| transport | L4 | 公开证书 | 是否首版 bootstrap | 典型用途 |
|---|---|---|---:|---|
| Hysteria2 | UDP/QUIC | WebPKI + pin | 是，首选 | bootstrap、数据链路 |
| Trojan/TLS | TCP/TLS | WebPKI + pin | 正式版 fallback | UDP 全阻断时 bootstrap、可选数据 |
| WireGuard | UDP | WG peer key | 否 | Enrollment 后永久 L3/control/data link |
| Nginx HTTPS | TCP/TLS | WebPKI + pin | 只下载 | fake website、immutable distribution |

HY2 与 WG 都是 UDP，不能绑定同一个 address/port tuple；它们即使数值端口不同，也必须有各自
listener ownership。Trojan 与 Nginx 都是 TCP，必须使用不同 tuple 或显式 L4 SNI dispatcher。
外部 NAT mapping 必须保留 transport，TCP 映射不能满足 UDP endpoint，反之亦然。

Hysteria2/Trojan 不要求固定在 443。所有客户端授权的数据入口都由当前签名 EndpointSet 明确
给出 public port；客户端禁止扫描端口、从 DNS 猜端口或读取 provider 私有 mapping。

### 13.4 客户端选择与测量边界

未入网客户端：

1. mirror hint 只决定 catalog 下载尝试顺序；
2. 验证 catalog 后，对当前底层网络代中的授权 bootstrap endpoint 做一次有界、并行真实
   transport probe；
3. HY2 有可用候选时选择最佳 HY2；检测到 UDP 全阻断或 HY2 全失败时才尝试已发布 TCP fallback；
4. 不探测未签地址、不做 Service × 路径扫描、不因 UI profile 切换重复测量；
5. 主动 probe 只完成真实 outer transport/SNI 身份验证，不发送 bearer；选中入口后才出示
   capability 建 tunnel，内层 TLS 完成后才发送 token。

已入网 Windows/Android 的稳态测量统一见
[客户端消费边界](../../client-observation-reuse.md#客户端消费边界)；Linux/server Agent 保持
[既有候选预算](../design/measurement.md#1622-探测预算有界而不是全探)。bootstrap registry 与
稳态 data registry 生命周期分开，完成 Enrollment 后必须删除前者。

服务器 Web 观测、控制面历史 RTT 和目录 priority 只能作为没有实测时的 hint。任何 UI 或 API
不得把它们标为客户端端到端延迟、丢包或已验证可用性。

---
