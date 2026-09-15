# Listener 与端口轮换

[文档地图](../../README.md) · [架构入口](../../architecture/README.md) · [控制面规范](README.md) · [实现对照](../../development/implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

## Listener 与端口无中断轮换

### 通用重叠状态机

HY2 和 Trojan/TLS 使用相同逻辑状态机：

~~~text
prepare
  → install new listener/credential without advertise
  → local self-check
  → verify from required external fault domains
  → advertise old + new
  → wait client-reader propagation floor
  → prefer new
  → stop accepting new sessions on old
  → drain old sessions until deadline
  → retire old listener, credential and mapping
~~~

每一步都写 operation ID、expected certified head、listener generation、deadline 和可重入完成证据。
reconciler 重启后从外部事实恢复，而不是重做随机选择。端口选择由提交操作注入；纯 renderer
不读时钟、不查询空闲端口、不产生随机数。

exact rotation wire 固定为：

~~~text
ListenerRotationFrozenDependenciesV1
  schema = 1, cluster_id
  endpoint_kind                     # distribution | bootstrap | data
  endpoint_set_id, endpoint_id, logical_server_id, transport
  source_listener_generation?, source_listener_generation_hash?
  target_listener_generation
  logical_public_endpoint_intent_hash
  public_access_profile_hash
  dns_address_binding_hash
  certificate_identity_projection_hash
  credential_artifact_refs_root
  render_contract_hash, evidence_policy_hash
  port_pool_hash, firewall_policy_hash
  forward_listener_resource_generation_hash
  port_mapping_intent_hash?         # 仅 nat_mapped
  link_intent_hashes[]              # 按 hash bytes 排序

ListenerRotationIntentV1
  schema = 1, cluster_id, rotation_id, operation_id
  base_head_hash, expected_endpoint_set_hash
  frozen_dependencies: ListenerRotationFrozenDependenciesV1
  frozen_dependencies_hash
  advertise_not_before, prefer_not_before, drain_not_before, drain_not_after
  retire_not_before                 # 必须 >= drain_not_after，且仍受 retirement guard 约束
  minimum_reader_floor

ListenerRetirementDependencyLeafV1  # control-private；按 (kind, object_hash) 排序
  schema = 1
  kind                              # endpoint_set | catalog | available_invite | initial_capability |
                                    # resume_descriptor | reserved_transaction | device_view |
                                    # certificate_pin_overlap | offline_lkg
  object_hash, reference_not_after

ListenerRetirementGuardV1
  schema = 1, cluster_id, rotation_id
  rotation_intent_hash, source_listener_generation_hash
  reference_cutoff_head_hash         # 此 head 后禁止创建新的旧代引用
  dependency_leaf_count, dependency_root
  maximum_reference_not_after
  minimum_reader_floor
  offline_grace_not_before, quiet_not_before, backup_retain_until

ListenerRotationStateV1             # reducer projection；不是 executor 自报权威
  schema = 1, cluster_id, rotation_id
  rotation_intent_hash, frozen_dependencies_hash
  phase                              # allocated | prepared | advertised | preferred |
                                     # draining | retired | abandoned | revoked
  source_listener_generation?, target_listener_generation
  retirement_guard_hash?             # draining/retired 必需
  last_transition_head_hash
  evidence_refs_root
~~~

以上四类对象分别使用 `loom-listener-rotation-frozen-dependencies-v1`、
`loom-listener-rotation-intent-v1`、`loom-listener-retirement-dependency-leaf-v1`、
`loom-listener-retirement-guard-v1` 和 `loom-listener-rotation-state-v1` domain 计算 hash。
intent 的 dependency object 必须逐字节重算到 `frozen_dependencies_hash`；从 allocated 到任一 terminal
phase，普通 reconcile/管理操作不得替换 logical/public intent、profile、地址绑定、证书身份投影、
credential、render/evidence policy、port pool、防火墙、listener resource generation、mapping 或
LinkIntent。确需变化时只能先安全 `abandoned` 再建新 rotation；安全事件可走
显式 `revoked`，但必须报告中断而非改写原 intent。

executor 使用单独的 `ExecutionPlanV1` 固定 source/target 的全部 L4 tuple；WireGuard 还必须固定
独立 old/new interface、key ref、tunnel address、route table 与 fwmark。plan 在任何外部 apply 前以
rotation_id 为 first-result key 原子写入 0600 control-private store，重启后不同 plan/port 一律冲突。
runtime reconciler 只接受该 store 返回的不透明 frozen plan，并先完整重放验证 certified rotation
history，再按 phase 计算 source/target desired state；每次 apply 后必须重新 observe 且完全收敛，
否则不生成成功 evidence。`retired` 前始终保留 source tuple，`abandoned`/`revoked` 回收 target tuple，
防止失败路径留下旁路 listener。

HY2/Trojan transport adapter 还必须把上述 runtime ownership 与 exact bootstrap catalog、其 parent
Head/config QC、`ServerPublicAccessProfile` 和 private listener resources 合成不可伪造的本地 listener
capability，不能重新接收手写的 `listen`、SNI 或 pin。direct 部署的 bind tuple 必须覆盖 catalog
声明的地址族且端口属于相应 HY2/Trojan pool；NAT 部署必须逐项命中 frozen
`PortMappingIntent` 的 public/local offset 与 L4 transport。实际 socket 的 `LocalAddr`、TLS SNI、
叶证书 SPKI 和 capability registry 的 ingress-set hash 都要在 accept/auth 前与该 capability 精确相等。
`prepared` listener 可在公开有效期前完成不携 bearer 的 outer self-check；任何携 transport
credential 的认证只在 catalog 与 listener validity 交集内开放。adapter 必须把同一 generation 的
全部 certified tuple 当作一个运行批次：全部 bind 成功后才启动 accept，部分失败关闭已建 socket；
运行中任一 listener 意外退出则取消并关闭整批，禁止把部分地址族覆盖误报成完整安装。external
verification plan 只投影 certified public IP:port、FQDN、TLS identity 与 validity，不携任何 bearer；
observer 必须真实完成 HY2/QUIC 或 Trojan/TLS 的 TLS 1.3/SNI/ALPN/SPKI handshake，并以 frozen
evidence policy 指定的 Ed25519 key 签名。advertise 要满足 observer/failure-domain 阈值和短有效期，
executor 重启或 control 接管时从完整 artifact 重验，不能把一个形状合法的任意 hash 当成可达证据。
部署在各外部故障域的 observer 通过 `loom bootstrap probe-outer` 消费 exact canonical plan；入口只接收
本地 0600 Ed25519 私钥与显式 CA bundle/系统 trust store，并原子输出 canonical signed observation。
命令没有 capability/token 参数，也不做 hostname DNS expansion，因而无法把外部验活偷换成 Enrollment。
本机 runtime 的 `Start` 只在全批 socket 已 bind 且 transport goroutine 已启动后返回；local verifier 随即
对每个 exact bind tuple 做同样的 TLS/QUIC identity handshake（wildcard 只映射同族 loopback），生成绑定
prepared certified state 且最长一分钟有效的 opaque evidence。advertise validator 必须同时接收这份
verified local evidence 与达到 frozen policy 阈值的 verified external evidence，拒绝任意 hash 占位。
上述步骤由同一个 prepared-generation handle 串联；local verify 失败必须同步回滚全批 listener，运行批次
终止后 handle 不再接受 observer report，也不能继续验证 advertise。

进入 draining 的 certified transition 同时建立 reference cutoff 和
`ListenerRetirementGuardV1`：ControlSet 必须枚举所有仍可能使客户端拨旧代的 immutable catalog、
available Invite、initial/resume capability、reserved transaction 的 `retry_not_after`、Device view、
certificate-pin overlap 与离线 LKG，形成 exact private dependency leaves/root，
并从 exact `reference_not_after` 求最大值。cutoff head 之后任何新对象引用 source generation 或包含
它的旧 EndpointSet hash 都拒绝 commit。只有当前 head 不低于 `minimum_reader_floor`，全部 dependency
期限、`drain_not_after`、`retire_not_before`、offline grace、quiet period 和 backup retention 均已过去，
且相应 signed observation 已
进入 operation 后，reducer 才接受 retired；executor 不得凭本地“没有连接”提前删除 frozen
listener、credential 或 mapping。retired 只禁止拨号并解锁后续清理，审计 tombstone 仍需保留。

“无中断”表示已建立在旧 listener 的 session 可活到 drain deadline，新连接逐步选择新 listener；
不承诺单个 QUIC/TCP session 跨端口迁移。紧急撤销可以跳过 drain，但 UI/API 必须明确显示会断开
旧会话。

### NAT 预映射池

nat_mapped server 若由操作者预先建立一段一一对应的 public/local UDP 映射，HY2 可以在该池中
选择下一个未占用端口并完成上述重叠；这里的“分配”只分配 Loom 对既有 tuple 的 reservation，
不修改光猫/网关。必须满足：

- certified private intent 记录池边界、transport 和 mapping generation；
- 激活前从外部验证具体 public tuple，不能只相信网关配置；
- HY2 active/draining 端口与 WG 固定/轮换端口不重叠；
- 池耗尽、映射消失或 public/local offset 不一致时停止轮换并报警；
- 客户端只看到当前 advertised/preferred public endpoints，不看到整段私有资源池。

control-private reducer 把 exact `PortMappingIntentV1` hash 与全部历史占用固定在
`MappingReservationSetV1`。每条记录固定 rotation、listener generation、public/local tuple、
allocation certified time/head；正常退役进入带确定 `reuse_not_before` 的 `quarantined`，端口冲突、
管理封禁或滥用进入首版不可逆 `blocked`。分配只复用已到 certified deadline 的 quarantine，
同一 rotation 重试返回原 first result，历史 tombstone 不删除；因此进程重启或 executor 接管不会
根据当前 socket 空闲误判端口可复用。

direct server 没有 PortMappingIntent，但仍要做 listener 与外部 reachability 验证。替代 HTTPS
TCP 映射和 Trojan TCP 池按相同原则处理，不能从 UDP 池推导。

生产验收只需对操作者明确提供的映射执行正常路径外部验证和真实流量；mapping 消失、池耗尽、
offset/transport 错误由合成 intent、verifier/reconciler 故障注入覆盖，不以更改真实网关为测试步骤。

### 客户端行为

客户端接收同一 endpoint_id 的新旧 generation 后：

1. 保持现有会话，不为观察到新 generation 立即重连；
2. 新拨号优先 preferred generation；
3. preferred 失败可在其仍 advertised 且未过期时回退旧 generation；
4. 已见 floor 不接受更低 generation；
5. retired 后不再新拨号；revoked 立即断开；
6. 不把端口代次变化计为最终出口变化。

离线客户端继续使用最后一个仍在有效/宽限期的 LKG endpoint。若离线跨过旧端口 retire deadline，
恢复时必须先取得合法新 set；不能扫描旧端口周边。

### WireGuard 独立状态机

WG 不自动继承 HY2 的 listener overlap 结论。若需要无中断 WG 轮换，必须实现双 interface/双 peer、
独立地址/route ownership、old/new peer overlap、握手验证与 drain。只更新同一 interface 的 listen
port 会影响现有 peer，不能宣称无中断。

WG control overlay 的 key/peer 轮换属于 private `ControlPeerDirectoryV1` 与 ControlSet 变更，不进入
public bootstrap port rotation。数据 WG endpoint 可进入 DataIngressEndpointSet，但仍使用专用
generation/state machine。

Gate 输入是按 component 严格排序的 `GateEvidenceReportV1`，每项携 artifact hash、certified Head
hash、passed/failed 与 observation time，再确定性派生 `GateStatus`；调用方不能直接手填布尔值冒充
证据。平台集合来自当前 certified deployment inventory；未部署的 Windows 不产生必需 evidence，
server/Linux/Android 按各自实际部署范围验收。

---
