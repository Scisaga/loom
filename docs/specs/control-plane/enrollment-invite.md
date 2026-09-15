# Enrollment 流程、Invite 与二维码

[文档地图](../../README.md) · [架构入口](../../design.md) · [控制面规范](../../distributed-control-plane.md) · [实现对照](../../implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

## 11. Enrollment、邀请与报告

本章定义新 Device 第一次进入 Loom 的唯一目标流程。**Enrollment 是私有控制服务**；
公网 Nginx 只提供 fake website 和无秘密、内容寻址的静态 distribution。公开入口不得接收、
终止、检查或反向代理 claim。尚无 Device identity 的客户端通过受限 bootstrap tunnel 到达
overlay 内的 Enrollment 服务；取得正式身份后，bootstrap 权限立即失效。

### 11.1 边界与端到端流程

角色严格分为四层：

| 层 | 公开性 | 功能 | 不允许 |
|---|---|---|---|
| distribution mirror | 公网 HTTPS | fake website、按 hash 下载签名制品和 bootstrap catalog | token、capability、claim、control/config/report |
| bootstrap ingress | 公网 HY2；正式版另有 Trojan/TLS TCP | 验短期 capability，建立限路由临时隧道 | 解密 Enrollment 内层 TLS、访问任意 overlay/Internet |
| private Enrollment | Loom overlay | 验 internal TLS、token、CSR、Keystore PoP，提交一次性 claim | 公网监听、接受未经 tunnel ACL 的来源 |
| steady-state Device API | Loom overlay | Device mTLS 下提供 view/config/report | 借用 bootstrap capability 或公开 Nginx |

规范流程：

~~~text
admin 已在 Loom 内
  → 通过 private control_api 创建 Invite
  → Raft commit + apply + QC，产生一次性 token commitment
  → 生成紧凑 QR / loom:// descriptor

未入网客户端
  → 离线验证 descriptor 的最小信任材料
  → 从 descriptor 中 2–3 个 distribution mirrors 下载 immutable catalog/proof
  → 验 hash、QC、有效期、lineage 与 anti-rollback floor
  → 在当前底层网络实测 catalog 中的 HY2 bootstrap ingress
  → UDP 全阻断且正式 TCP fallback 已发布时，实测 Trojan/TLS ingress
  → 向最佳可达入口出示短期 bootstrap tunnel capability
  → 得到仅通往 private Enrollment 服务的临时 tunnel
  → 在 tunnel 内验证 internal TLS server identity
  → 不发 token 地取得 private intent opening，重算 public hiding commitment
  → 生成/使用设备本地不可导出的 Keystore key，固定 stable claim core
  → 取得 server-nonce challenge，提交 token + claim core + detached PoP
  → enrollment voter 多数形成 token-validation admission QC，Raft CAS 预留该 core
  → 受约束 CA 产生并耐久登记 provisional issuance
  → enrollment voter 验证 issuance 后形成 approval QC
  → approval-QC-authorized completion 原子消费 Invite 并激活 Device identity/view
  → 客户端原子安装正式身份和 LKG，关闭并擦除 bootstrap 状态
~~~

网页 HTTPS RTT、服务器汇总测量和二维码生成端的观测只能决定 mirror 提示顺序，不能替代
客户端当前网络对真实 HY2/Trojan transport 的探测。下载 mirror 与建立 tunnel 的 ingress
可以是不同服务器。

首版 bootstrap transport 是 HY2。WG 不作为首版 bootstrap：它要求在正式 Enrollment 之前
创建临时 peer、地址和分发状态，会重新形成身份循环。WG 保留为完成 Enrollment 后的永久
L3/control overlay。schema 必须保留 transport tagged union，以后可增加 WG bootstrap profile，
但 reader 遇到未实现 transport 必须明确报不支持，不能静默改拨 HY2。

正式版必须提供**独立的** Trojan/TLS TCP fallback，以覆盖完全阻断 UDP 的接入网络。它可以
通过独立公网地址/端口，或由只做 L4 SNI 分发的前置 listener 与 Nginx 共用 TCP 入口；无论哪种
部署，Nginx 都不成为 tunnel 或 Enrollment handler，Enrollment 内层 TLS 始终端到端终止在
private control service。

### 11.2 Invite、catalog 与紧凑二维码

以下对象都使用 [§7.1](consensus.md#71-内容寻址操作) 的 canonical encoding、domain separator 和内容哈希。数组按文中键排序，
拒绝未知字段、重复 ID、非规范 URL、超限长度和不在 certified parent 中的引用。

~~~text
InviteIssuancePolicyV2
  schema = 2, cluster_id, policy_id, generation
  minimum_ttl_seconds
  maximum_ttl_seconds                 # 不得超过 1800
  maximum_descriptor_bytes
  maximum_intent_opening_bytes
  minimum_distribution_mirrors = 2
  maximum_distribution_mirrors = 3
  allowed_bootstrap_transports[]      # hysteria2 | trojan_tls；按 enum 排序
  maximum_initial_capability_ttl_seconds
  maximum_resume_capability_ttl_seconds
  maximum_reservation_retry_seconds
  bootstrap_session_seconds           # 默认 180，最大 300
  bootstrap_total_bytes               # 默认 8 MiB
  bootstrap_connection_attempts       # 默认 3
  bootstrap_max_concurrent_sessions = 1

InviteTokenCommitmentInputV2
  schema = 2, cluster_id, invite_id
  token                                # 解码后精确 32 bytes

DeviceEnrollmentIntentV1
  schema = 1, cluster_id, invite_id, device_id
  platform                            # windows-desktop | android | linux-server
  device_certificate_profile_ref: DeviceCertificateProfileRefV1
  wrapping_key_profiles[]
  membership: EnrollmentMembershipV1
  responsibilities: EnrollmentResponsibilitiesV1
  grants: EnrollmentDestinationGrantsV1

EnrollmentMembershipV1
  schema = 1, desired_state = "active_on_completion"

EnrollmentResponsibilitiesV1
  schema = 1
  values[]                            # use_loom | forward | internet_egress

EnrollmentDestinationGrantsV1
  schema = 1
  values[]                            # EnrollmentDestinationGrantV1，按 (kind,target_id) 排序

EnrollmentDestinationGrantV1
  kind                                # service | egress
  target_id

DeviceEnrollmentIntentOpeningV1       # control-private；只在 inner TLS preflight 返回
  schema = 1, cluster_id, invite_id
  device_enrollment_intent: DeviceEnrollmentIntentV1
  device_enrollment_intent_hash
  hiding_nonce                        # 32-byte CSPRNG，每个 Invite 唯一

DeviceEnrollmentIntentCommitmentV1    # public-safe；不含 Device 或授权字段
  schema = 1, cluster_id, invite_id
  opening_hash                        # 对 exact opening 的 domain-separated hash

CertifiedInviteRecordV2
  schema = 2, cluster_id, invite_id, generation
  issued_at, expires_at
  device_enrollment_intent_commitment_hash
  token_commitment
  token_artifact_binding_hash
  invite_issuance_policy_hash
  bootstrap_issuer_authorization_hash
  bootstrap_issuer_registry_root
  bootstrap_catalog_hash
  enrollment_service_ref_hash
  operation_id, parent_head_hash

InviteTokenArtifactBindingV2          # control-private；绝不进 QR/mirror
  schema = 2, cluster_id, invite_id, operation_id
  token_commitment
  token_artifact_ref: SecretArtifactRefV2
  device_enrollment_intent_opening_hash

InviteLifecycleStateV2                # reducer 输出
  schema = 2, cluster_id, invite_id, generation
  certified_invite_record_hash
  status                              # available | reserved | consumed | revoked | expired
  request_id?, claim_core_hash?, result_artifact_hash?
  last_operation_id

DistributionMirrorRefV1
  schema = 1, endpoint_id
  distribution_endpoint_set_hash
  listener_generation
  base_url                            # HTTPS；显式携带 443 或替代 TCP 端口
  server_name, webpki_profile_ref
  spki_pins[]
  hint_rank                           # 仅提示下载顺序

BootstrapEndpointCatalogV1
  schema = 1, cluster_id, catalog_generation
  valid_from, valid_until
  bootstrap_ingress_set: BootstrapIngressEndpointSetV1 # exact wire 见 §13.1
  bootstrap_ingress_set_hash
  required_client_protocol
  parent_head_hash
  config_qc_hash

InviteProofBundleV2                   # public immutable object；无 token/capability
  schema = 2, cluster_id, invite_id
  bootstrap_transition_bundle
  authority_transitions[]
  certified_invite_record
  invite_issuance_policy
  device_enrollment_intent_commitment
  invite_operation_leaf
  invite_leaf_index, invite_operation_tree_size, invite_operation_audit_path[]
  record_head, record_head_qc
  bootstrap_issuer_authorization_proof: BootstrapIssuerAuthorizationProofV1
  bootstrap_catalog_hash

PrivateEnrollmentServiceRefV1
  schema = 1, service_id
  overlay_ip                          # 精确 /32 或 /128 目的地址
  tcp_port
  internal_ca_profile_ref
  server_identity_spki_pins[]
  service_generation

InviteBootstrapDescriptorV2
  schema = 2, cluster_id, invite_id, expires_at
  token                              # 32-byte CSPRNG；只在 QR/offline package
  token_commitment
  bootstrap_tunnel_capability: BootstrapTunnelCapabilityV1
  bootstrap_catalog_hash
  proof_bundle_hash
  enrollment_service_ref: PrivateEnrollmentServiceRefV1
  distribution_mirrors[]: DistributionMirrorRefV1 # 2–3 个，跨 server/address/fault domain
  minimum_recovery_epoch
  trusted_checkpoint_hash

EnrollmentIntentPreflightRequestV1
  schema = 1, cluster_id, invite_id
  certified_invite_record_hash
  capability_id

EnrollmentIntentPreflightResponseV1
  schema = 1, cluster_id, invite_id
  request_hash
  device_enrollment_intent_commitment: DeviceEnrollmentIntentCommitmentV1
  device_enrollment_intent_opening: DeviceEnrollmentIntentOpeningV1

InviteOfflinePackageV2
  schema = 2
  descriptor
  bootstrap_catalog
  proof_bundle
~~~

关键摘要固定为：

~~~text
token_commitment = H(frame("loom-invite-token-commitment-v2",
  JCS(InviteTokenCommitmentInputV2)))
device_enrollment_intent_hash = H(frame("loom-device-enrollment-intent-v1",
  JCS(DeviceEnrollmentIntentV1)))
device_enrollment_intent_opening_hash = H(frame(
  "loom-device-enrollment-intent-opening-v1", JCS(DeviceEnrollmentIntentOpeningV1)))
device_enrollment_intent_commitment_hash = H(frame(
  "loom-device-enrollment-intent-commitment-v1", JCS(DeviceEnrollmentIntentCommitmentV1)))
invite_issuance_policy_hash = H(frame("loom-invite-issuance-policy-v2",
  JCS(InviteIssuancePolicyV2)))
certified_invite_record_hash = H(frame("loom-certified-invite-record-v2",
  JCS(CertifiedInviteRecordV2)))
bootstrap_catalog_hash = H(frame("loom-bootstrap-endpoint-catalog-v1",
  JCS(BootstrapEndpointCatalogV1)))
enrollment_service_ref_hash = H(frame("loom-private-enrollment-service-ref-v1",
  JCS(PrivateEnrollmentServiceRefV1)))
invite_proof_bundle_hash = H(frame("loom-invite-proof-bundle-v2",
  JCS(InviteProofBundleV2)))
invite_descriptor_hash = H(frame("loom-invite-bootstrap-descriptor-v2",
  JCS(InviteBootstrapDescriptorV2)))
enrollment_intent_preflight_request_hash = H(frame(
  "loom-enrollment-intent-preflight-request-v1", JCS(EnrollmentIntentPreflightRequestV1)))
~~~

DeviceEnrollmentIntentV1 只固定 Device 身份、platform、responsibilities 和 grants，不携节点级
direction。Enrollment 完成后，每条新 control/data 边必须通过独立 certified LinkIntent 固定两端、
purpose、allowed transports、发起方、listener/credential refs 和 route scope；不能从 Device 标签
推导全局发起方向。v1 direction 只能由迁移器一次性投影成 LinkIntent，不进入新 Invite wire。

创建 Invite 时必须预生成独立 32-byte `hiding_nonce`。公开 record/proof 只携
`DeviceEnrollmentIntentCommitmentV1`；因为 commitment 覆盖不公开的 nonce，mirror 无法对低熵
Device ID、platform、responsibilities 或 grants 做离线字典测试。客户端选定 ingress、建立
tunnel 并验过 inner TLS 后，先发送不含 token/CSR/key 的
`EnrollmentIntentPreflightRequestV1`。私有 Enrollment 只向与 capability/record 同一 Invite 的请求
返回 opening；客户端重算 intent hash、opening hash 和 public commitment hash，逐字节核对
cluster/invite/platform，并在发 token 前显示职责与 grants。任一不等立即关闭 tunnel。

二维码不内嵌完整 ingress catalog、Device intent 或 opening。它只携 token、短 capability、
catalog/proof 的哈希、private Enrollment service ref 和 2–3 个多样化 distribution mirror。完整 catalog 从
路径形如 /distribution/sha256/<digest> 的不可变对象下载；服务器不得根据 token 动态生成响应，
客户端也不得把 token 放进 URL、header、cookie、referer 或 DNS name。

如果扫码介质无法容纳 descriptor，应用可传递同一协议对象的 .loom-invite 文件。该文件不是
第二种授权语义；在线和离线载体必须产生相同 canonical descriptor hash。离线包可以携完整
catalog/public proof，但不得携 intent opening，且仍必须执行期限、QC、floor 和 endpoint identity 验证。

mirror 数不足 2 或超过 3 时必须拒绝创建 Invite，不存在单镜像例外。客户端可并行或顺序尝试
2–3 个 mirror，但只能接收与 QR 中 catalog/proof hash
完全相等的对象。任何 HTTP redirect 都失败关闭，避免 URL canonicalization、跨缓存层和秘密隔离
语义分叉。

每个 `DistributionMirrorRefV1` 必须在其 `distribution_endpoint_set_hash` 的 exact
`DistributionEndpointV1` 下唯一找到相同 endpoint ID 与 listener generation；该代必须是 advertised
或 preferred，不能是 draining/tombstone。`base_url` 必须由该代的 canonical HTTPS
`dial_target_fqdn/public_port` 和固定 distribution path prefix 重建后逐字节相等，mirror 的
server name、WebPKI profile/pins 也必须等于该代
transport identity projection；禁止 descriptor 用另一组 URL 或 identity 覆盖 EndpointSet。

`InviteProofBundleV2` 的验证顺序是固定的：先从 record head/QC 验 invite operation leaf
的 index/tree size/audit path，再核对 record 中的 intent commitment、policy、catalog、service ref、
issuer authorization hash 和 issuer-registry root。随包的 issuer authorization 必须按其
leaf/index/tree size/audit path 重算到该 root，其 hash 必须等于 record 的 exact
`bootstrap_issuer_authorization_hash`，且其 policy hash 必须等于 record 中的 exact
`invite_issuance_policy_hash`。缺少任一
exact bytes/hash/root/path/QC、重复 leaf key 或两个 head 不在已验连续 lineage 上均 fail closed。
