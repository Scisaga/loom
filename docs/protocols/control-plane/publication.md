# 签名发布、Device view 与 anti-rollback

[文档地图](../../README.md) · [架构入口](../../architecture/README.md) · [控制面规范](README.md) · [实现对照](../../development/implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

## 发布、签名与客户端 anti-rollback

### signed current v2

目标 signed current 对象不另造一套扁平但字段不全的 head。私有 Device API 可返回当前对象；
公开 mirror 只能按其内容 hash 保存不可变副本，不能提供未被 descriptor/认证响应约束的动态
latest locator。首版 exact envelope 为：

```text
SignedCurrentV2
  schema = 2
  head: HeadEntryV2
  quorum_certificate: CertifiedHeadQCV1
  published_at                  # 仅缓存/诊断；不参与 authority 排序
```

客户端必须按 [Raft committed log 与提交后 certified QC](consensus.md#raft-committed-log-与提交后-certified-qc) 重算完整 HeadEntry body 的 entry/head hash，并逐字段验证 tagged attestation、
签名 domain、ControlSet、排序/去重和 stable/joint 门槛；`published_at`、HTTP Date、ETag 或 URL
新鲜度都不能替代 head 中的 logical time、Raft 坐标与 floor。

signed current 不放一个含义不明的全局 `endpoint_set_hash`。不同 Device 可以因 role/grant
得到不同 EndpointSet；每个[signed current v2](#signed-current-v2) 的 `endpoint_set_hash` 承诺该 Device 的精确 bytes，
`device_views_root` 再统一承诺全部 leaves。仅供 UI 聚合的全局端点目录若存在，也只是另一个
由 head hash 引用的观测/管理对象，不能代替 per-Device 授权。

`device_views_root` 使用 RFC 6962 二进制 Merkle 形状：按规范化 `device_id` 原始字节升序
排列并拒绝重复 ID，`LeafHash=SHA-256(0x00 || canonical_leaf)`，
`NodeHash=SHA-256(0x01 || left || right)`，空树 root 为 `SHA-256("")`。首版 exact private view 为：

```text
DeviceConfigArtifactRefV1
  artifact_id, generation, platform
  media_type                           # application/vnd.loom.config+json |
                                       # application/vnd.loom.sing-box+json
  render_contract_id, size_bytes, content_hash

DeviceEndpointBundleV1
  schema = 1, cluster_id, device_id, device_generation
  data_ingress_sets[]                  # DeviceDataIngressBindingV1；按 endpoint_set_id 排序

DeviceDataIngressBindingV1
  endpoint_set_id
  endpoint_set: DataIngressEndpointSetV2, endpoint_set_hash

DeviceActiveViewV1
  identity_spki_hash
  membership: EnrollmentMembershipV1, membership_hash
  responsibilities: EnrollmentResponsibilitiesV1, responsibilities_hash
  grants: EnrollmentDestinationGrantsV1, grants_hash
  endpoint_bundle: DeviceEndpointBundleV1, endpoint_bundle_hash
  config_artifact_refs[]               # 按 artifact_id/generation 排序去重
  secret_artifact_refs_root

DeviceTombstoneViewV1
  reason                               # revoked | decommissioned

DeviceViewPayloadV2                    # exact tagged union；只存在一个 variant
  schema = 2, cluster_id, device_id, device_generation
  state                                # active | revoked | decommissioned
  active?: DeviceActiveViewV1
  tombstone?: DeviceTombstoneViewV1

DeviceViewLeafV2
  schema = 2, cluster_id, view_schema_version = 2
  device_id, device_generation, state
  payload_hash, previous_view_hash
  endpoint_set_hash                    # active 时等于 endpoint_bundle_hash；tombstone 为 EMPTY_HASH_V1
  min_reader_version

DeviceViewEnvelopeV2                   # 只由 overlay 内 Device mTLS device_config 返回
  schema = 2
  payload: DeviceViewPayloadV2
  leaf: DeviceViewLeafV2
  leaf_index, tree_size, audit_path[]
  signed_current: SignedCurrentV2
  secret_artifact_refs[]?              # active view root 的 exact private refs；按 权威 secret artifact 排序
```

摘要固定为：

```text
device_config_artifact_content_hash = H(frame(
  "loom-device-config-artifact-bytes-v1", raw_artifact_bytes
))
device_endpoint_bundle_hash = H(frame(
  "loom-device-endpoint-bundle-v1", JCS(DeviceEndpointBundleV1)
))
device_view_hash = H(frame("loom-device-view-v2", JCS(DeviceViewPayloadV2)))
device_view_envelope_hash = H(frame(
  "loom-device-view-envelope-v2", JCS(DeviceViewEnvelopeV2)
))
```

`payload_hash == device_view_hash`；`previous_view_hash` 指向上一已接受 generation 的该摘要，首代为
`EMPTY_HASH_V1`。`device_leaf_hash` 是 RFC 6962
`SHA-256(0x00 || JCS(DeviceViewLeafV2))`，不是另一种 payload hash；二者不能混用。payload 与 leaf
的 cluster/device/generation/state 必须相等，active/tombstone tag 与唯一 variant 一致。active 的三个
授权对象及 hash 必须从 effective state 重算，Membership 必须已完成 [内层 TLS、token、Keystore PoP 与一次性提交](enrollment-transaction.md#内层-tlstokenkeystore-pop-与一次性提交) completion；endpoint
bundle 的每个 DataIngressEndpointSet exact bytes/hash 必须满足 grants 和职责且数组无缺漏，不能只返回
一个裸 endpoint hash；binding hash 必须等于 [EndpointSet、catalog 与公网端口模型](endpoints.md#endpointsetcatalog-与公网端口模型) 对该 set 的规范摘要。distribution/bootstrap set
不进入正式 Device 授权 bundle，private ControlServiceDirectory 也不在此公开投影。Service/route/component 的源依赖索引只是 reducer 的失效重算优化，不进入
客户端 wire；其已授权结果必须体现在 grants、EndpointSet 与可按内容 hash 验证的 config artifact，
不能用未定义的 generic dependency ref 代替。config artifact 的
raw bytes 长度/hash/media type/platform/render contract 必须与 ref 相等。

active envelope 的 `secret_artifact_refs[]` 必须从 exact refs 重算为 payload root；不需要新 secret 时
可以为空数组但不能省略，tombstone 必须省略整个字段且不得携 endpoint/config/secret
内容。该 envelope 只是私有交付容器；secret refs 不进入 public head/mirror，envelope hash也不回写
payload/leaf/head，避免自引用。

叶不包含当前 head/revision/root，避免无关控制提交迫使所有 Device 增加 generation 或形成
自引用；leaf 任一字段变化都必须提高该 Device generation，吊销/删除必须留下 tombstone leaf，
缺 leaf 不表示吊销。canonical DeviceView payload 本身也不得嵌入仅代表响应时刻的 head/revision；
这些坐标由 envelope 携带，payload 只有授权内容实际变化时才换 hash/generation。
`DeviceViewEnvelopeV2` 同时返回 payload、canonical leaf、leaf index/tree
size、inclusion audit path、精确 signed current/head 和其 QC。客户端先验证
bootstrap/recovery、ControlSet/transition、head QC 与单调坐标，再重算 payload/leaf 和 Merkle
path，确认 root 等于已认证 head 的 `device_views_root`，最后核对 endpoint/grant 依赖与 Device
floor。单个 control 返回“看似已签名”的 payload 或孤立 QC，只要缺 inclusion proof 就不能
激活。Enrollment receipt 绑定同一个 leaf hash、root、head hash 和 QC；初始 view 不能走旁路。

`transition_proof_hash` 是 head entry 的普通被哈希字段：初始 v2 head 中它等于 [v1 → v2 不可逆 latch](#v1--v2-不可逆-latch) 的
`bootstrap_transition_hash`；恢复时等于不含 Genesis/Activation/head/QC 的 threshold-signed
transition proof hash；ControlSet 变化时同样只引用在该 head 之前已经固定的 Joint proof 与
signature-free Final body，不能引用包含自身 head/QC 的完整交付 bundle。无 transition 的普通
head 延续上一适用值。计算 `head_hash` 时不得忽略该字段；完整 delivery bundle 可以包含该 head
与 QC，但其外层 hash 永远不写回 head。首次 bootstrap 通过先承诺不含它的 payload、再生成
transition、最后生成完整 head 的单向 DAG 避免自引用。

### floor 与 recovery lineage

客户端耐久保存：

```text
accepted_recovery_epoch + recovery_statement_hash + recovery_policy_hash
accepted_control_epoch + control_set_hash
accepted_control_revision + head_hash
device_generation + device_leaf_hash + device_view_hash
bootstrap_transition_hash + v2_latched
```

版本先按 `recovery_epoch`，再按其内的 `control_epoch/control_revision/device_generation` 比较。
普通 joint transition 不能修改 recovery epoch；更高 recovery epoch 只有在 recovery proof 合法
且绑定上一最后可信 head 时接受，并压过旧集合后来产生的任何普通 revision。更高 control epoch
只有在 joint transition 合法时接受；不能只比较整数。
同 recovery epoch 出现不同 statement/policy hash、同 control epoch/revision 或同 device
generation 出现不同 hash 均视为分叉。合法回滚创建更高
revision/generation 指回旧内容，不重放旧 head。

### v1 → v2 不可逆 latch

为避免 `bootstrap_transition_hash ↔ initial_v2_head_hash` 循环，迁移固定为以下单向对象图：

```text
InitialV2HeadPayloadV1                 # 先生成；不含 transition proof/hash、head hash、QC
  schema = 1, cluster_id, recovery_epoch, recovery_statement_hash, recovery_policy_hash
  control_epoch = 0, control_set_hash, control_peer_directory_hash, control_revision = 1
  snapshot_hash, operation_root, effective_ssot_hash, device_views_root
  admin_acl_root, ca_profile_root, bootstrap_issuer_registry_root
  render_contract_version, min_reader_version
  max_clock_skew_seconds

BootstrapTransitionBodyV1ToV2          # signature-free；再 canonicalize
  cluster_id, schema = 1, v1_platform_key_id, v1_platform_key_digest
  v1_device_floor_merkle_root
  recovery_bootstrap_statement: RecoveryBootstrapStatementV1
  recovery_statement_hash
  initial_recovery_key_pop_root
  initial_control_set_hash, initial_control_peer_directory_hash, initial_control_key_pop_root
  initial_admin_acl_hash, internal_ca_profile_and_anchor_hash
  initial_bootstrap_issuer_registry_root
  initial_v2_head_payload_hash, initial_v2_raft_index = 1, minimum_reader_version

BootstrapTransitionProofV1ToV2
  body: BootstrapTransitionBodyV1ToV2
  body_hash
  v1_platform_signature                # {key_id, signature}

BootstrapHeadContextV1
  schema = 1, kind = "bootstrap"
  initial_v2_head_payload_hash

InitialV2HeadEntry                     # 最后生成、提交、apply/recompute 并取得 q(initial) QC
  schema = 1
  initial_payload: InitialV2HeadPayloadV1
  head: HeadEntryV2                    # payload.transition_context 为上列 context
  replication_qc: StableHeadReplicationQCV1

BootstrapTransitionBundleV1ToV2
  schema = 1
  transition_proof: BootstrapTransitionProofV1ToV2
  initial_recovery_policy: RecoveryPolicyV1
  initial_recovery_key_possession_proofs[] # RecoveryKeyPossessionProofV1，按 key ID 排序
  initial_control_set: ControlSetV1
  initial_control_key_possession_proofs[]  # ControlKeyPossessionProofV1，按 member/purpose 排序
  initial_head_entry: InitialV2HeadEntry

BootstrapDeviceFloorLeafV1
  schema = 1, device_id, v1_generation
  v1_signed_current_hash, v1_payload_hash

BootstrapDeviceFloorProofV1
  schema = 1
  leaf: BootstrapDeviceFloorLeafV1
  leaf_index, tree_size, audit_path[]

BootstrapDeviceMigrationPackageV1ToV2    # 每个既有 v1 Device 私有交付
  schema = 1
  bootstrap_bundle: BootstrapTransitionBundleV1ToV2
  device_floor_proof: BootstrapDeviceFloorProofV1
```

三个摘要都使用 [内容寻址操作](consensus.md#内容寻址操作) 的长度前缀 framing，首版固定为：

```text
initial_v2_head_payload_hash = H(frame("loom-initial-v2-head-payload-v1", JCS(initial_payload)))
bootstrap_transition_body_hash = H(frame(
  "loom-bootstrap-transition-body-v1-to-v2", JCS(BootstrapTransitionBodyV1ToV2)
))
bootstrap_transition_hash = H(frame(
  "loom-bootstrap-transition-proof-v1-to-v2", JCS(BootstrapTransitionProofV1ToV2)
))
```

`v1_platform_signature.signature` 覆盖
`frame("loom-bootstrap-transition-signature-v1-to-v2", JCS(BootstrapTransitionBodyV1ToV2))`，其 key ID
必须等于 body 的 ID，public key digest 必须匹配客户端预置的 v1 platform key；proof 中
`body_hash` 必须等于上式重算值。`initial_payload` 不包含 Raft 坐标、transition proof/hash、head
hash 或 QC。最终 `HeadEntryV2` 按 [Raft committed log 与提交后 certified QC](consensus.md#raft-committed-log-与提交后-certified-qc) 构造：
`head_kind="bootstrap"`，两个 predecessor 均为 `EMPTY_HASH_V1`，Raft index/control revision 为 1，
其余同名 roots/floor 与 initial payload 逐字段一致，包含 `committed_logical_time`，且
`max_clock_skew_seconds` 与 initial payload 相等；transition context
精确等于 `BootstrapHeadContextV1`，且
`transition_proof_hash=bootstrap_transition_hash`。因此构造顺序只有
payload → bootstrap transition body/signature/proof → initial head/QC，不允许把完整 initial head hash
塞回 transition。
Raft term 由初始集合选举产生；首个 v2 log entry/index 和 control revision 在首版固定为 1，
初始 control epoch 按 [丢失 quorum](recovery.md#丢失-quorum) 固定为 0。三种 hash/framing 必须提供跨平台黄金向量。

bootstrap 的重复承诺必须逐字段相等：statement 的
`cluster_id/recovery_epoch=0/recovery_policy_hash/initial_recovery_key_pop_root/`
`initial_control_epoch=0/initial_control_set_hash/initial_control_peer_directory_hash/`
`initial_control_key_pop_root/initial_admin_acl_hash/`
`internal_ca_profile_and_anchor_hash/initial_bootstrap_issuer_registry_root` 先导出 body 所带的
`recovery_statement_hash`；body 的 `cluster_id/initial_control_set_hash/`
`initial_control_peer_directory_hash/initial_admin_acl_hash/`
`internal_ca_profile_and_anchor_hash/initial_bootstrap_issuer_registry_root/minimum_reader_version` 必须分别等于 initial payload/head 的
`cluster_id/control_set_hash/control_peer_directory_hash/admin_acl_root/ca_profile_root/bootstrap_issuer_registry_root/min_reader_version`，initial payload 的
recovery 三元组也必须等于 statement 及其导出 hash。任何 set A/statement 配 head B 的组合都拒绝。
此外必须重算 `initial_v2_head_payload_hash`，并确认它同时等于
`BootstrapTransitionBodyV1ToV2.initial_v2_head_payload_hash` 与
`BootstrapHeadContextV1.initial_v2_head_payload_hash`；任一不同都属于拼接攻击。

完整 bootstrap 交付只能使用上列 `BootstrapTransitionBundleV1ToV2`。验证器必须从所携带的 initial
policy/set bytes 重算两个 hash，分别重算恰好覆盖全部 recovery keys 与全部 member 三用途 keys 的
PoP root，并与 bootstrap statement/body 重复字段相等；随后才用 initial ControlSet 验初始 head
QC。只带 v1 transition signature 与若干 public key hash、却没有 exact public key/PoP bytes 的载体
不可建立 v2 latch。
初始 control voters 还必须在 durable install 前经私有通道取得同 hash 的
`ControlPeerDirectoryPrivateObjectV1` 并验证与 initial set 一一对应；该 preimage 不进入公开 bootstrap
bundle，v1 reader 只验证 platform signature 与 initial config QC 对 hiding commitment 的绑定。
所携 initial recovery policy、ControlSet、每个 member/PoP body、bootstrap statement/body/payload/head
的 `cluster_id` 必须逐字节等于同一 cluster；不得只比较 set/policy hash 而跳过内层
cluster 边界。

迁移 floor leaves 按规范化 `device_id` 原始字节排序并拒绝重复；leaf hash 为
`SHA-256(0x00 || JCS(BootstrapDeviceFloorLeafV1))`，内部节点、奇数分树和空树规则与 [内容寻址操作](consensus.md#内容寻址操作)
的 RFC 6962 树完全相同。proof 的 index/tree size/path 必须重算到
`BootstrapTransitionBodyV1ToV2.v1_device_floor_merkle_root`。每台既有 v1 客户端必须验证
自己的 leaf/proof，确认 generation 不低于本地 v1 floor，且两个 hash 与已验 v1
bytes 一致。初始 v2 head
还必须带初始 ControlSet 的提交后 replication QC。transition 由旧 v1 key 签名，并必须匹配客户端通过部署专属升级
包、企业策略、现场 QR 或人工核验预置的独立 migration-anchor digest；普通应用代码签名本身
不能替某个 Loom 网络选择该 digest。两份都能通过旧 key、却不匹配同一预置 anchor 的
bootstrap 一律 fail closed，不能按时间或下载源择一。

`BootstrapDeviceMigrationPackageV1ToV2` 只可经既有 Device 身份认证的私有 v1 升级响应
或等价带外通道交付，不进入公共 distribution mirror、新邀请 QR 或共享
`BootstrapTransitionBundleV1ToV2`。新 v2 invite 创建的 Device 不在历史 v1 floor 树中，只验
invite proof bundle 而不伪造空 floor proof。

### 已有单成员控制日志的接续

 已经存在 certified Head、管理员轮换和 Raft 日志的网络，
不能重新生成 index=1 的 bootstrap，也不能把早期仅承诺原管理员根证书的恢复对象冒充
`RecoveryPolicyV1`。该形态使用一次性 `legacy_runtime_activation`，原位追加到既有日志；
它是迁移证明，不提供旧 Enrollment/config/report 的运行入口。

```text
LegacyRuntimePolicyV1
  schema = 1, admin_root              # 原始 Ed25519 自签 CA DER，base64url

RuntimeActivationRootsV1
  snapshot_hash, effective_ssot_hash, device_views_root
  admin_acl_root, ca_profile_root, bootstrap_issuer_registry_root
  render_contract_version            # >= 2

RuntimeActivationStatementV1
  schema = 1, cluster_id, operation_id
  parent_head_hash, parent_qc_hash, legacy_recovery_policy_hash
  v1_platform_key_id, v1_platform_public_key, v1_platform_key_digest
  new_recovery_epoch = 2, new_recovery_policy_hash, new_recovery_key_pop_root
  device_migration_root              # 逐设备私有迁移记录的 RFC 6962 根
  roots: RuntimeActivationRootsV1
  issued_at, reason

RuntimeActivationProofV1
  schema = 1, statement: RuntimeActivationStatementV1
  legacy_policy: LegacyRuntimePolicyV1
  owner_signature, platform_signature

RuntimeActivationContextV1
  schema = 1, kind = "legacy_runtime_activation", statement_hash

RuntimeActivationBundleV1
  schema = 1, proof: RuntimeActivationProofV1
  parent: HeadEntryV2, parent_qc: StableHeadReplicationQCV1
  control_set: ControlSetV1
  recovery_policy: RecoveryPolicyV1
  recovery_key_possession_proofs[]
  previous_operation_leaves[]: ControlOperationLeafV1
  head: HeadEntryV2, config_qc: StableHeadReplicationQCV1
```

适用条件必须同时成立：原集合恰为 N=1；parent 的 recovery/control epoch 都为 1，render contract
为 1；原 policy 摘要等于 `H(frame("loom-runtime-recovery-policy-v1", JCS(legacy_policy)))`；
parent QC 由原集合验证通过。原 owner 根 key 与原 v1 platform key 分别签署同一 statement 的
`loom-runtime-activation-owner-signature-v1` 和 `loom-runtime-activation-platform-signature-v1`
frame；当前管理员还必须对 daemon 的 exact base/request 签名。control config key、当前 ping
权限和服务器持有的任意新 key 都不能代替这两项旧 authority 授权。

statement、proof 的 hash domain 分别为 `loom-runtime-activation-statement-v1`、
`loom-runtime-activation-proof-v1`。新 policy 的所有 recovery keys 必须提供有效 PoP 并满足
与 control keys 的用途分离；新 head 的 recovery statement/policy/proof hash 必须逐字段匹配。
ControlSet、private peer directory commitment、原日志和原 operation leaves 全部保留；
仅附加 `{schema:1,operation_id,object_id:statement_hash}`，不得删改历史。新 recovery epoch 为 2、
control epoch 为 0，Raft term/index/前项继承真实日志，不能重置或预留假坐标。daemon 必须从私有
迁移输入独立重算实际 SSOT、身份、CA、ACL 和 issuer roots，而不是把签名中的 hash 直接当成配置。
旧式 parent 条件使同一 lineage 无法再次使用该转换。

逐设备迁移记录以 `RuntimeDeviceMigrationLeafV1` 固定 `cluster_id/device_id/platform`、
原 `BootstrapDeviceFloorLeafV1`、原身份 SPKI hash、wrapping key hash、新证书与 profile hash、
以及实际 activation 日志中的签发坐标。记录按 Device ID 严格排序、不重复，使用 RFC 6962
叶/内部节点规则生成 `device_migration_root`，由同一 owner/platform statement 承诺。
daemon 从完整私有 preimage 重算该根，并以实际迁移日志作为身份起点；不得构造虚假的
Enrollment reservation、completion 或新 Invite 来代表存量设备。

`RuntimeDeviceMigrationPackageV1` 私有交付相应 inclusion proof、activation bundle、该设备
的新证书、CA profile/registry、不可变镜像地址和 `DeviceConfigDeliveryV1`。配置窗口首项必须
属于实际 activation Head，之后沿正式 `device_config` 的连续 Head/QC/Device proof 推进。
这样，包含私有目录的 Device credential 可以绑定 activation 之后已经存在的同 epoch Head，
不产生 Head 与密封配置摘要的自引用。迁移包及其逐设备叶不能进入公开 distribution。

客户端先在保留的原平台信任根下验证旧 signed current 和本机防回退下限，再核对迁移承诺；
`RuntimeDeviceMigrationExpectedV1` 的身份 SPKI、wrapping key 和已验证旧 floor 必须从本机
受保护状态取得，不能复制包内自报字段。证书仍必须绑定同一 P-256 身份并匹配当前认证 CA
registry；包内目录不能自行获得 authority。安装时原子保存迁移来源证明、证书、配置、封装
凭据与四组 v2 floor，回读成功后才启动新版。历史证明和旧密钥存档不恢复任何 v1 业务入口。

客户端必须有独立的原 v1 platform key/ID/anchor digest、已信任的 exact parent Head，或现场 QR
交付的新 checkpoint 之一；提供多个 anchor 时必须全部匹配。bundle 自带公钥不构成信任根。
这只建立新 authority，**不替代既有 Device 的 floor 验证、身份迁移与配置激活**；这些仍必须按
本文的防回退要求完成，才能删除对应旧业务路径。新的邀请不制造历史 floor。公开 bundle 只含
公钥、承诺和 opaque leaves，SSOT、Device 列表、ACL preimage、token 与 intent opening 保持私有。

首次接受完整 v2 head/QC/view proof 时，客户端把 `v2_latched=true`、bootstrap hash 和全部
floor **原子耐久写入**。latch 前只可接受满足 BootstrapTransition 所声明 floor 的受限 v1
配置；latch 后 v1 current、配置、邀请、成员/恢复声明永远不能再成为 authority。迁移期可以
继续用 v1 HTTP 路径搬运 v2 bytes 或发送兼容报告，但传输路径不改变验证规则。客户端状态
丢失只能从可信备份、已钉住 v2 checkpoint/recovery 或带外 rebootstrap 恢复，禁止因“本地
没有 floor”自动退回 v1。

稳态 private `device_config` 的 retained window 必须以客户端 durable exact Head 为锚点，逐项使用
严格 tagged union：普通 Head 不带 transition，成员变更带 `ControlSetTransitionBundleV1`，紧急恢复
带 `EmergencyRecoveryBundleV1`，计划内恢复策略轮换带 `RecoveryPolicyActivationBundleV1`；同一项出现
多个 transition tag 一律拒绝。窗口可携当前 recovery policy 的公开 preimage，但客户端必须先重算
它与锚点 Head 的 `recovery_policy_hash` 相等，才能用其验证 old threshold。每类 authority transition
先验证本次 transition proof/新 Head，再推进对应 floor；durable `bootstrap_transition_hash` 始终保留
首次 v2 latch，不能被后续 Head 的 transition proof hash 覆盖。`revoked`/`decommissioned` 是合法
tombstone state 名称；接受后客户端在同一状态事务中清除运行 config 与 data-plane credential，不能
等待并不存在的字面 `state=tombstone`。

### 镜像

静态镜像仍然不可信并保留多地址并行拉取。它们只复制公开的 immutable
bootstrap/recovery/ControlSet transition、QC、无 token 的 bootstrap endpoint catalog、通用内容
寻址制品和按 hash 寻址的 signed head；不得复制 Invite token、bootstrap capability、
DeviceEnrollmentIntent/opening、per-Device view/leaf/proof、私有拓扑或 secret artifact ref。公开
Invite proof 只能携带加盐 hiding commitment 及其在 certified head 中的包含证明；完整
intent/opening 只能在相应 Loom 私网身份通道内返回。control
副本内部以内容寻址复制 view 不等于授权公共 publisher 输出它。不同镜像短暂落后是正常；客户端
只获取 QR 或已认证 private API 精确引用的 hash，不通过列目录猜“最新”。DNS、镜像顺序、网页探测和 RTT 只影响从哪里下载，不能覆盖签名、floor、
ControlSet，也不能替客户端选择实际 bootstrap/data tunnel。

每个 active forward server 的公网 Nginx 只提供 fake website 根路径与上述静态 distribution；
任何动态 claim、control、config、report handler 或反向代理 location 都是配置错误并必须 fail closed。

publisher 不再是某台中控上的 authority。任一 control 副本都可 materialize 相同字节；
只有带 QC 的 head 才能被 private API 作为 current 返回并把相应 immutable object 发布到镜像。
发布 executor 用租约避免无意义并发，失败后
任何合格副本都可接管。

---

## 私有 application 的部分交付

运行时 application schema 2 将每个顶层命名部分的规范内容摘要组成 RFC 6962 Merkle 树，
按字段名排序；`ControlApplicationSnapshotV2` 的网络、部分数量与树根进入 Head 的 `snapshot_hash`。
`ControlApplicationSectionProofV2` 只携所选字段的内容与 inclusion path。节点必须同时验证外部
信任锚、完整迁移/Head/QC、snapshot 摘要、网络、字段名、内容摘要及 Merkle path。
不能只验证调用方自报的树根，也不能为了交付一个 listener 计划把 SSOT、邀请 opening 或恢复
custody 发给 forward 节点。历史 schema 1 的整体对象摘要仅供原有证明和日志重放，不授权旧业务路径。
