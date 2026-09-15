# Bootstrap tunnel capability

[文档地图](../../README.md) · [架构入口](../../architecture/README.md) · [控制面规范](README.md) · [实现对照](../../development/implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---


bootstrap capability 是“允许建立受限临时 tunnel”的凭据，不是 Device identity，也不是
Enrollment token。二者必须独立；任何把 token 直接用作 HY2/Trojan 密码的实现都不合规。
transport 认证串固定为
`HashObject("loom-bootstrap-transport-credential-v1", BootstrapTunnelCapabilityV1)`；
只有完整验证 issuer registry inclusion、certified policy、签名、时间和 exact scope 后，入口与
客户端才可使用该派生值。HY2 直接把它作为 password，Trojan 再使用协议规定的 SHA-224
lowercase-hex key。入口只原子注册当前 certified capability 集合；认证表替换与 durable attempt
落盘之间不得留出旧 credential 新开 session 的竞态。该派生值、原 capability 和 enrollment token
均不得进入日志、diagnostics 或公开 catalog。

~~~text
BootstrapTunnelCapabilityBodyV1
  schema = 1, cluster_id, invite_id
  committed_invite_record_hash
  invite_issuance_policy_hash
  bootstrap_issuer_authorization_hash
  bootstrap_issuer_registry_root
  enrollment_service_ref_hash
  mode                                # initial_claim | resume_committed_claim
  resume_binding?                     # 仅 resume_committed_claim 必需
  issued_at, not_before, expires_at
  allowed_ingress_set_hash
  allowed_service_id
  allowed_destination_ip
  allowed_destination_prefix_length  # 仅允许 IPv4 /32 或 IPv6 /128
  allowed_destination_port
  allowed_inside_transport = tcp
  maximum_connection_attempts
  maximum_concurrent_sessions = 1
  maximum_session_seconds
  maximum_total_bytes
  issuer_epoch, issuer_key_id

BootstrapCapabilityResumeBindingV1
  request_id
  claim_operation_hash
  admission_qc_hash
  claim_core_hash, csr_hash
  identity_key_hash, wrapping_key_hash
  enrollment_transaction_state_hash

BootstrapTunnelCapabilityV1
  body
  capability_id                       # 由 body 派生；body 内不回填 ID
  signature                          # BootstrapIssuer purpose key

BootstrapIssuerAuthorizationActiveV1
  issuer_epoch, issuer_key_id
  issuer_public_key
  invite_issuance_policy_hash
  valid_from, valid_until
  maximum_capability_ttl_seconds
  maximum_connection_attempts
  maximum_concurrent_sessions
  maximum_session_seconds
  maximum_total_bytes
  permitted_ingress_set_hashes[]
  permitted_service_ids[]
  permitted_modes[]                   # initial_claim | resume_committed_claim

BootstrapIssuerAuthorizationRevocationV1
  revoked_authorization_hash
  effective_at, reason

BootstrapIssuerAuthorizationV1
  schema = 1, cluster_id, authorization_id, generation
  status                              # active | revoked
  previous_authorization_hash?        # generation>1 必需；同 ID 上一代
  active?: BootstrapIssuerAuthorizationActiveV1
  revocation?: BootstrapIssuerAuthorizationRevocationV1
  parent_head_hash

BootstrapIssuerAuthorizationLeafV1
  schema = 1, authorization_id, generation
  authorization_hash

BootstrapIssuerAuthorizationProofV1
  schema = 1, cluster_id
  authorization: BootstrapIssuerAuthorizationV1
  authorization_hash
  leaf: BootstrapIssuerAuthorizationLeafV1
  leaf_index, registry_tree_size, registry_audit_path[]
  registry_root

EnrollmentResumeDescriptorV1          # 带外一次性交付；不进 public mirror
  schema = 1, cluster_id, invite_id, request_id, expires_at
  resume_tunnel_capability: BootstrapTunnelCapabilityV1
  claim_core_hash, claim_operation_hash, admission_qc_hash
  enrollment_transaction_state_hash
  bootstrap_catalog_hash
  proof_bundle_hash
  enrollment_service_ref: PrivateEnrollmentServiceRefV1
  distribution_mirrors[]: DistributionMirrorRefV1
~~~

capability signature 覆盖
`frame("loom-bootstrap-tunnel-capability-signature-v1", JCS(BootstrapTunnelCapabilityBodyV1))`；
`capability_body_hash` 与 authorization hash 分别使用独立同名 v1 domain；
`capability_id = H(frame("loom-bootstrap-tunnel-capability-id-v1",`
`JCS(BootstrapTunnelCapabilityBodyV1)))`。ID 只存在 envelope，必须重算后逐字节相等；
不得将 ID 回填 body 再求 hash。authorization leaf 使用 [内容寻址操作](consensus.md#内容寻址操作) RFC 6962 规则，按
`(authorization_id, generation)` 排序并拒绝重复；`bootstrap_issuer_registry_root` 必须由
proof 的 leaf/index/tree size/path 重算。`authorization_hash` 使用
`loom-bootstrap-issuer-authorization-v1`，leaf 使用
`loom-bootstrap-issuer-authorization-leaf-v1`，resume descriptor 使用
`loom-enrollment-resume-descriptor-v1` domain。descriptor 中 capability
的 `allowed_ingress_set_hash` 必须等于所下载 catalog 的 `bootstrap_ingress_set_hash`，且必须出现在
active authorization 的 `permitted_ingress_set_hashes[]`；其 `enrollment_service_ref_hash` 必须从
descriptor 的 exact `PrivateEnrollmentServiceRefV1` 重算，service ID、目的 IP/前缀/端口也必须
逐字段相等并在 authorization 的 service scope 内。
只比较 service ID 而忽略实际 route tuple 不合法。
resume descriptor 的 claim/core/admission/transaction hashes 还必须逐字段等于 capability 的
`resume_binding`；任一重复字段不等都失败关闭。

authorization 是按 ID 的不可变链：generation 从 1 连续增加，首代缺
`previous_authorization_hash`，后续代必须精确指向前代。`active` 必须只携 active body，
`revoked` 必须只携 revocation body，并且其 `revoked_authorization_hash` 必须是该链上最近的
active hash；revoked 后不得回到 active。每个 certified `HeadEntryPayloadV2` 都携
`bootstrap_issuer_registry_root`，config attestation/QC 重复绑定该 root。Invite 记录的 root/proof
证明 capability 签发时的 exact active authorization；公网 ingress 在每次建连时还必须从本机
最新 certified head 重算当前 registry root，沿 same-ID previous-hash 链确认该 active hash 未被
revocation 代取代。无法取得当前 certified root、root 回退、链断裂或已撤销都拒绝；
不能因 capability 仍在时间有效期就继续放行。

Invite 必须先 commit 并取得 QC；随后才允许由 certified BootstrapIssuer 从该记录派生 capability。
BootstrapIssuer 使用独立用途 key，其 authorization 由 ControlSet QC 约束。入口验证：

1. 从 certified Invite record 取得 exact policy hash 和 issuer-registry root，重算 authorization
   leaf/audit path，再核对 capability 中的 authorization hash/root/key/epoch；authorization 必须仍在有效期且未撤销；
2. capability 的 invite/record/policy/service-ref hash、期限和 ingress set 与已验材料一致，且
   ingress-set/service 均在 exact authorization scope 内；
3. capability 的 TTL、流量、session、次数、并发和 ACL 同时不超过 exact authorization
   与 InviteIssuancePolicy；descriptor 字节数、mirror 数/故障域和 transport 也必须满足该 policy；
   initial capability 的 expires_at
   还不得晚于 Invite expires_at，且不得带 resume binding；resume 模式必须逐字段绑定已 committed
   的 claim/transaction，并不得授权新的 claim；
4. 当前 endpoint 属于 allowed ingress set；
5. 目的地址、端口和 transport 精确等于 capability，不接受客户端任意指定；
6. capability 不在本入口的并发、次数、流量或速率封禁状态。

initial/resume capability 默认有效期均为 15 分钟；policy 中两个 TTL 字段都必须在 5–30 分钟内，
签发值还不得超过各自字段，协议硬上限均为 30 分钟。`maximum_reservation_retry_seconds` 默认
1800 秒、必须为正且硬上限 86400 秒。新目标态不存在
1 小时自动恢复窗口；旧 1 小时只属于 v1 compatibility，不能进入 v2 policy。已建立 session
默认最多 180 秒、硬上限 300 秒，总流量默认 8 MiB，同一入口最多 3 次连接尝试且同一时刻最多
1 个 session。来源 IP 只能作为滥用信号，不能作为身份；移动网络切换后仍可在期限和次数内重试。

客户端自动重试只允许在当前 Invite 与 capability 都有效时进行。若 claim 已经 committed，事务为
reserved、issued_provisional 或 completed，但客户端因响应丢失而等到 capability 过期，不能自动刷新，
也不能创建新 request。
reserved/issued_provisional 的私有响应必须携 canonical progress receipt；客户端以原 Invite proof、
本机 opening/claim core 和 base Head/ControlSet 重放 admission QC、reservation/issuance operation 与
完整 Head lineage，只有 transaction hash 精确相等才把 claim-operation/admission-QC/transaction hashes
及 retry deadline 原子写入受保护 pending state。该状态只允许 exact replay 或
reserved→issued_provisional 前进，禁止同阶段分叉和回退；receipt 不含 token、CSR、challenge 或 PoP bytes。
管理员可在线性化读取 transaction 后，显式为同一 invite_id + request_id + claim/CSR/identity/
wrapping-key hashes 重签一个短期 resume capability。它只恢复到同一个幂等事务：不延长原 Invite、
不把 lifecycle 改回 available、不重置 reservation，也不再次消费 token；ControlSet 返回原有结果
或继续原事务。任一绑定不同都必须拒绝并要求创建全新 Invite。

这里“不延长 Invite”指 Invite 的 `available` 消费窗口仍在原 `expires_at` 截止；已 certified
reservation 是独立事务状态，其 policy-bound `retry_not_after` 可以晚于 Invite expiry。超过 Invite
expiry 后只能恢复该 exact committed transaction，绝不能以原 token 创建另一 claim、改变 core 或
把 Invite 从 reserved/consumed 改回 available。

重签结果只能是 `EnrollmentResumeDescriptorV1`。管理员必须经 private `control_api`、
admin mTLS 和相应 ACL 请求；ControlSet 线性化核对 transaction 为 `reserved`、`issued_provisional`
或 `completed`、
original claim core 与全部 resume binding 后，才能在一次性响应中返回 descriptor。它不含 token，
不进 public mirror/latest API，也不能被未入网客户自动刷新；管理员只可用新 QR 或
`.loom-resume` 文件带外交给原设备。客户端必须验证 descriptor/capability/hash，重用原
claim core 及 identity/wrapping keys，并对新 server nonce 重签 detached PoP。恢复请求使用不含
token 字段的 `EnrollmentResumeSubmissionV1`；private Enrollment 必须按 capability mode 严格区分
initial 与 resume wire，且在进入 Coordinator 后再次将 capability 中的 claim-operation、admission-QC
和 transaction-state hashes 与 durable record 逐字段核对。resume 不重新执行 admission、不再次消费
token，也不得用 resume capability 提交带 token 的 initial claim wire。`expires_at` 不得超过
capability、issuer authorization、policy、catalog、service ref 和 transaction `retry_not_after` 中最早的截止点。
客户端导入 resume 时必须从 descriptor 的 mirror refs 取得 exact proof bundle/catalog，并从本机
v1 platform key + migration anchor 重放 Invite authority；resume 没有可作为替代 trust root 的自报
checkpoint。catalog config QC 的 parent Head/ControlSet 必须能在该已验 lineage 中精确定位，随后再把
descriptor/capability 与受保护 pending progress 的 core/key/admission/retry binding 合并验证。本机保存的
transaction hash 是最后已验 floor，descriptor 绑定签发时服务端当前 state：两者可因响应丢失而不同，
但返回的 progress/completion receipt 必须从原 claim 重放出 descriptor state 或其同请求内后继，且
本机持久化规则继续拒绝同阶段分叉与回退。
签发器必须以已 certified 的管理员 operation_id 为 first-result key，把 exact request hash、issuer
public key、descriptor hash 与完整 descriptor 原子写入 control-private 存储后再响应；同一 operation_id
的进程内重试和崩溃恢复只能逐字节返回第一次结果，request、transaction state 或签名 body 有任何变化
都必须失败关闭，且不得重新读取后用较新的 transaction/catalog 拼装第二份结果。
该私有入口固定为 `POST /private/v2/control/enrollment/resume`；请求中的
`issue_enrollment_resume` schema-1 operation 必须承诺 exact authorization payload hash，并按其中
`device_id` 走 device scope ACL。响应同时携带 operation 的 Head/QC/inclusion proof 与一次性 descriptor，
且必须使用 `Cache-Control: no-store`。

各公网 ingress 对次数/流量的记账可以是保守的本地或最终一致状态，因此它不是全局一次性安全
边界。真正的一次性授权由 private Enrollment 对 token 做 Raft CAS。入口发现异常重放时可提前
拒绝；不能因 ingress 间尚未同步就把 Invite 标记 consumed。

临时 tunnel 的网络策略必须在 ingress 转发器和 private Enrollment 前防火墙两侧执行：

- 只允许 capability 中一个 Enrollment /32 或 /128、一个 TCP 端口；
- 禁止其他 overlay CIDR、control_api、Raft、SSH、DNS、ICMP、隧道内 UDP 和 Internet egress；
- 禁止横向连接、端口扫描和 server-originated reverse connection；
- session 结束或 capability 过期后立即撤销临时路由/状态；
- 日志只记录 capability_id、endpoint_id、计数和结果，不记录 token、CSR 或内层明文。
