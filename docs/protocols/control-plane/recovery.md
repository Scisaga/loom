# 丢失 quorum 的显式恢复

[文档地图](../../README.md) · [架构入口](../../architecture/README.md) · [控制面规范](README.md) · [实现对照](../../development/implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

## 丢失 quorum

recovery policy 本身是 floor authority，必须先有可跨平台重算的 exact bytes：

```text
RecoveryPolicyKeyV1
  key_id
  algorithm = "ed25519"
  public_key                       # raw 32 bytes，无 padding base64url

RecoveryPolicyV1
  schema = 1, cluster_id, policy_id, generation
  algorithm = "ed25519-multisig-v1"
  keys[]                           # RecoveryPolicyKeyV1，按 key_id 排序
  threshold
  private_key_custody_root         # 只公开 commitment；locator/recipient/receipt 留在 private object
  ceremony_profile = "offline-independent-keys-v1"

RecoveryKeyPossessionProofBodyV1
  schema = 1, cluster_id, policy_id, policy_generation
  key_id, public_key

RecoveryKeyPossessionProofV1
  body: RecoveryKeyPossessionProofBodyV1
  signature                         # raw 64-byte Ed25519，无 padding base64url

RecoveryCustodianRefV1
  custodian_id
  receipt_key_algorithm = "ed25519"
  receipt_key_id, receipt_public_key       # raw 32 bytes，无 padding base64url
  recipient_key?: SealedBlobRecipientKeyRefV1
  fault_domain

RecoveryKeyCustodyArtifactV1       # control-private exact preimage
  schema = 1, cluster_id, policy_id, policy_generation, key_id, public_key
  hiding_nonce                     # 32-byte CSPRNG，无 padding base64url
  key_artifact_ref: SecretArtifactRefV2   # purpose=recovery_private_key；当前使用 sealed artifact
  custodians[]                     # RecoveryCustodianRefV1，按 custodian_id 排序
  required_receipt_count, required_fault_domain_count, max_receipt_age_seconds

RecoveryKeyCustodyAvailabilityReceiptBodyV1
  schema = 1, cluster_id, policy_id, policy_generation, key_id
  custody_artifact_hash, custodian_id, recipient_key?: SealedBlobRecipientKeyRefV1
  artifact_or_version_digest, observed_at, recovery_key_test_signature

RecoveryKeyCustodyAvailabilityReceiptV1
  body: RecoveryKeyCustodyAvailabilityReceiptBodyV1
  receipt_key_algorithm = "ed25519", receipt_key_id
  receipt_signature                       # raw 64 bytes，无 padding base64url

RecoveryKeyCustodyAvailabilityLeafV1
  schema = 1, custodian_id, receipt_hash

RecoveryKeyCustodyBindingV1        # control-private；一把 recovery key 恰一个
  schema = 1
  artifact: RecoveryKeyCustodyArtifactV1, custody_artifact_hash
  availability_receipts[]          # 按 custodian_id 排序
  availability_receipts_root

RecoveryKeyCustodyLeafV1
  schema = 1, key_id, custody_binding_hash

RecoveryPrivateCustodyObjectV1     # bootstrap/transition 的私有同行对象
  schema = 1, cluster_id, policy_id, policy_generation
  bindings[]                       # 按 key_id 排序，与 public policy keys 一一对应
  private_key_custody_root
```

`key_id` 是 raw public key 的小写 `sha256:` hex；policy 非空，key ID/public key 均唯一，
`1 <= threshold <= len(keys)`，首版拒绝其他 algorithm/ceremony profile。policy 和 PoP 分别计算：

```text
recovery_policy_hash = H(frame("loom-recovery-policy-v1", JCS(RecoveryPolicyV1)))
recovery_key_pop_hash = H(frame("loom-recovery-key-pop-v1", JCS(RecoveryKeyPossessionProofV1)))
recovery_custody_artifact_hash = H(frame(
  "loom-recovery-custody-artifact-v1", JCS(RecoveryKeyCustodyArtifactV1)
))
recovery_custody_availability_receipt_hash = H(frame(
  "loom-recovery-custody-availability-receipt-v1",
  JCS(RecoveryKeyCustodyAvailabilityReceiptV1)
))
recovery_custody_binding_hash = H(frame(
  "loom-recovery-custody-binding-v1", JCS(RecoveryKeyCustodyBindingV1)
))
```

PoP signature 覆盖
`frame("loom-recovery-key-pop-signature-v1", JCS(RecoveryKeyPossessionProofBodyV1))`，并用同一 body 的
public key 验证。`new_policy_pop_root` 对按 key ID 排序、与 policy keys 一一对应的
`{key_id,recovery_key_pop_hash}` canonical leaves 使用 [内容寻址操作](consensus.md#内容寻址操作) RFC 6962 树规则计算；缺 key、重复、额外
proof 或字段与 policy 不等都拒绝。若未来采用 DKG/阈值聚合 key，必须新增 policy/ceremony
profile 和黄金向量，不能把它塞进首版独立 Ed25519 多签 schema。

每个 custody artifact 的 policy/key/public key 必须逐字节等于公开 policy；hiding nonce 必须解码为
32 bytes。内嵌 `key_artifact_ref` 的 cluster 必须相等，`proposal_id` 固定为
`H(frame("loom-recovery-custody-proposal-id-v1",JCS({schema:1,cluster_id,policy_id,
policy_generation})))`，`secret_id=key_id`、`purpose=recovery_private_key`，owner 必须是 matching
`recovery_policy` variant。ref 的 `public_key` 必须是 Ed25519 `AuthorityProofKeyV1`；从 strict DER
SPKI 提取的 raw 32-byte key 必须逐字节等于 policy/custody artifact 的 `public_key`。generic
AuthorityProof key ID 按 [权威 secret artifact](secret-artifacts.md#权威-secret-artifact) 的 SPKI domain 重算，**不要求**等于从 raw key 计算的 recovery policy
`key_id`：generic PoP 用前者，`RecoveryKeyPossessionProofV1` 与 threshold signature 用后者定位同一
raw key，两种命名空间不得直接比较。immutable ref 不得为
`latest`、alias 或可覆盖路径；sealed ref 的 recipient refs 必须与 custodian refs 一一对应并满足 [权威 secret artifact](secret-artifacts.md#权威-secret-artifact)
exact envelope，且每个 custodian/receipt 的 optional recipient key 都必须存在并相等；预留 provider
ref 的 custody 约束见[独立扩展计划](../../proposals/key-protection.md)。`custodians[]` 非空，custodian
ID、receipt key 和 fault domain 均唯一；仅对存在的 recipient key ref 要求彼此唯一，每个 present
recipient public key/profile/key ID
按 [权威 secret artifact](secret-artifacts.md#权威-secret-artifact) strict SPKI 与映射重算。receipt public key必须严格解码为 32-byte
Ed25519 raw key，`receipt_key_id` 等于其小写 `sha256:` digest，未知 algorithm、非规范 base64url 或
非 64-byte raw receipt signature 全部拒绝；
`1 <= required_receipt_count <= len(custodians)`、
`1 <= required_fault_domain_count <= required_receipt_count`，max age 为正。每个 availability receipt 的
字段/digest/recipient 必须等于 artifact 与对应 custodian ref，receipt signature 覆盖
`frame("loom-recovery-custody-availability-signature-v1",JCS(body))` 并由 exact Ed25519 receipt public key
验证；receipt envelope 的 algorithm/key ID 必须逐字段等于 custodian ref。
其中 `recovery_key_test_signature` 必须由该 recovery private key 覆盖
`frame("loom-recovery-custody-key-test-v1",JCS({schema:1,custody_artifact_hash,custodian_id,observed_at}))`；
wire 必须是 raw 64-byte Ed25519 signature。Recovery key PoP 与下述 threshold signature 也一律使用
raw 64-byte Ed25519、无 padding base64url；未知/错误长度拒绝。所以单纯声称“blob 存在”不能替代
一次真实解封与签名测试。

availability root 对按 custodian ID 排序的 `RecoveryKeyCustodyAvailabilityLeafV1`，custody root 对按
key ID 排序的 `RecoveryKeyCustodyLeafV1`，都使用 [内容寻址操作](consensus.md#内容寻址操作) RFC 6962 规则；leaf 中 hash 必须由同行 exact
对象重算。`availability_receipts[]` 是 proposal 固定的门槛子集，不要求所有 custodians 都签，但
每项必须来自列表中唯一 custodian、数量至少达到 receipt 门槛且去重 fault domain 至少达到其门槛；
未知、重复、过期或字段不等的 receipt 均拒绝。每把 public policy key 都必须恰有一份 binding，最终 root 必须等于
`RecoveryPolicyV1.private_key_custody_root`。公开 policy/statement/transition/bundle 只暴露该 root；
`RecoveryPrivateCustodyObjectV1` 的 locator、recipient 与 receipt 只交给 ceremony participant 和将要
接管的 control voters，普通客户端不取得。bootstrap、planned rotation intent commit、emergency
Genesis durable install 前，相关 control voters 都必须先持有并验证同一 private object；PoP 证明
当时有人持钥，不能替代此恢复介质可用性门禁。

每个 recovery epoch 必须由且只由一个 canonical `RecoveryStatementBodyV1` 建立。body 使用
[内容寻址操作](consensus.md#内容寻址操作) 的 JCS/UTF-8 规则，必须含 `schema=1` 和 `statement_type`，且不含签名数组、
`recovery_statement_hash` 或其他由自身导出的 hash。epoch 0 的 exact variant 是：

```text
RecoveryBootstrapStatementV1
  schema = 1, statement_type = "bootstrap"
  cluster_id, recovery_epoch = 0
  recovery_policy_hash, initial_recovery_key_pop_root
  initial_control_epoch = 0, initial_control_set_hash, initial_control_peer_directory_hash
  initial_control_key_pop_root
  initial_admin_acl_hash, internal_ca_profile_and_anchor_hash
  initial_bootstrap_issuer_registry_root
```

失去 quorum 的恢复使用下述 `RecoveryTransitionBodyV1` 全部字段并取
`statement_type="emergency"`；计划轮换使用 [recovery policy 的计划轮换](recovery-policy.md#recovery-policy-的计划轮换) 的
`RecoveryPolicyTransitionBodyV1` 全部字段并取 `statement_type="policy_rotation"`。三者统一计算：

```text
recovery_statement_hash = SHA-256(
  uint32_be(len("loom-recovery-statement-v1")) ||
  UTF8("loom-recovery-statement-v1") ||
  JCS(RecoveryStatementBodyV1)
)
```

这个导出的 `recovery_statement_hash` 是 signature-free statement body 的唯一身份；schema 中不存在
裸 `transition_hash` 别名。下文包含 threshold signatures 的 `transition_proof_hash` /
`policy_transition_proof_hash` 使用各自独立 domain，必定是另一层 envelope hash，绝不能填入
statement-hash 字段；threshold signatures 使用各自独立签名 domain 覆盖同一 canonical body。
Genesis/Activation、其首个 ControlHead、QR/checkpoint 和客户端三元组 floor 必须逐字节绑定同一
值。相同 epoch 的 statement 或 policy hash 任一不同都是 recovery fork。初始 v1→v2 bootstrap
transition 必须内嵌上述 bootstrap body 并承诺其导出 hash，不能把包含该 hash 的整个 transition
再自引用取 hash。实现前必须为三种 body 和错误自引用/错 type 准备跨平台黄金向量。

不得通过删除离线成员、修改 DNS 或让剩余节点自选新 epoch 恢复写入。正常恢复顺序是：

1. 修复足够旧成员；或
2. 使用离线 recovery policy/threshold 签署 canonical `RecoveryTransitionBodyV1`，至少绑定
   `cluster_id`、previous/new recovery epoch、previous trusted head/statement/policy hash、
   new recovery policy hash、完整新 ControlSet 与 key hashes、初始 admin ACL、内部 CA
   profile/anchor、无自引用的 new-lineage genesis payload、reason 和 `issued_at`；
   首版 `new_recovery_epoch == previous_recovery_epoch + 1`；
3. 新 ControlSet 对精确 genesis 做 `q(new)` durable install/commit、apply/recompute 和
   replication QC；
4. 客户端同时验证旧 recovery threshold transition 与新集合 genesis QC 后，才原子进入更高
   epoch 并永久拒绝旧 epoch；
5. 对操作日志、密钥和可能的冲突提交做人工审计。

```text
RecoveryTransitionBodyV1             # signature-free RecoveryStatementBodyV1 变体
  schema = 1, statement_type = "emergency"
  cluster_id
  previous_recovery_epoch, previous_recovery_statement_hash
  previous_recovery_policy_hash, previous_trusted_head_hash
  new_recovery_epoch                 # 首版精确等于 previous + 1
  new_recovery_policy_hash, new_policy_pop_root
  new_control_epoch = 0
  new_control_set_hash, new_control_peer_directory_hash, new_control_key_pop_root
  initial_admin_acl_hash, internal_ca_profile_and_anchor_hash
  initial_bootstrap_issuer_registry_root
  new_lineage_genesis_payload_hash
  reason, issued_at

RecoveryTransitionProofV1
  schema = 1
  body: RecoveryTransitionBodyV1
  recovery_statement_hash
  old_policy_threshold_signatures[]   # RecoveryThresholdSignatureV1

RecoveryGenesisPayloadV1              # 不含 statement hash、Raft envelope 或 QC
  schema = 1, cluster_id, new_recovery_epoch, new_recovery_policy_hash, new_policy_pop_root
  new_control_epoch = 0, new_control_set_hash, new_control_peer_directory_hash
  new_control_key_pop_root
  parent_recovery_head_hash
  initial_admin_acl_hash, internal_ca_profile_and_anchor_hash
  initial_bootstrap_issuer_registry_root
  operation_root, snapshot_hash, effective_ssot_hash, device_views_root
  render_contract_version, min_reader_version, max_clock_skew_seconds

RecoveryGenesisContextV1
  schema = 1, kind = "emergency_recovery"
  genesis_payload_hash

RecoveryGenesisV1                     # 唯一 exact genesis 交付形状
  schema = 1
  genesis_payload: RecoveryGenesisPayloadV1
  genesis_payload_hash
  head: HeadEntryV2                   # payload.transition_context 为上列 context
  replication_qc: StableHeadReplicationQCV1

EmergencyRecoveryBundleV1
  schema = 1
  transition_proof: RecoveryTransitionProofV1
  new_recovery_policy: RecoveryPolicyV1
  new_recovery_key_possession_proofs[] # RecoveryKeyPossessionProofV1，按 key ID 排序
  new_control_set: ControlSetV1
  new_control_key_possession_proofs[]  # ControlKeyPossessionProofV1，按 member/purpose 排序
  genesis: RecoveryGenesisV1
```

`new_recovery_statement_hash` 不作为 body 字段序列化，而按上式从这份 signature-free body
导出。`new_lineage_genesis_payload_hash = H(frame("loom-recovery-genesis-payload-v1",`
`JCS(RecoveryGenesisPayloadV1)))`，其中 `frame` 是 [内容寻址操作](consensus.md#内容寻址操作) 的长度前缀 domain framing；它只覆盖
上列 payload，并且 payload 不含 statement hash、
entry hash、Raft term/index 或 QC，因而不存在 transition ↔ genesis 自引用。首个 wire profile
在每条新 recovery lineage 把 `new_control_epoch` 固定重置为 0；实际 Raft term 由新集合选举
产生，首个 log index 和 control revision 固定为 1、`previous_log_entry_hash=EMPTY_HASH_V1`，均由
完整 Genesis HeadEntry 与 QC 绑定，而不是由旧 recovery signer 预选。
校验 transition 时必须逐字节确认 payload 的 `cluster_id/new_recovery_epoch/`
`new_recovery_policy_hash/new_policy_pop_root/new_control_epoch/new_control_set_hash/`
`new_control_peer_directory_hash/new_control_key_pop_root/initial_admin_acl_hash/`
`internal_ca_profile_and_anchor_hash/initial_bootstrap_issuer_registry_root` 与 transition 同名承诺一致，且
`payload.parent_recovery_head_hash == transition.previous_trusted_head_hash`；任一不等即拒绝，不能
让 hash 引用掩盖字段别名或 continuity 差异。
`RecoveryTransitionProofV1` 只包含上列 signature-free body、导出的 statement hash 和按
key ID 排序的旧 policy threshold signatures；
`transition_proof_hash = H(frame("loom-recovery-transition-proof-v1",`
`JCS(RecoveryTransitionProofV1)))`。它在 Genesis 之前已经完整，不包含 Genesis/head/QC；
Genesis head 的同名字段必须等于该值。其 `HeadEntryPayloadV2` 必须使用
`head_kind="emergency_recovery"`，`parent_head_hash=previous_trusted_head_hash`，recovery/control
三元组与 `operation_root/snapshot_hash/effective_ssot_hash/device_views_root` 必须与
`RecoveryGenesisPayloadV1` 逐字段一致，`admin_acl_root == initial_admin_acl_hash`、
`ca_profile_root == internal_ca_profile_and_anchor_hash`，
`bootstrap_issuer_registry_root == initial_bootstrap_issuer_registry_root`，
`render_contract_version/min_reader_version/max_clock_skew_seconds` 也逐字段相等，并包含
`committed_logical_time`；transition context 必须精确等于上列 `RecoveryGenesisContextV1`。包含
Genesis 与 QC 的完整 recovery delivery bundle 另有外层 content hash，但该 hash 不写回 Genesis。

实现还必须重算 genesis payload hash，并确认
`RecoveryTransitionBodyV1.new_lineage_genesis_payload_hash ==`
`RecoveryGenesisV1.genesis_payload_hash == RecoveryGenesisContextV1.genesis_payload_hash`；head 的
context 必须逐字节等于该 context，head/payload/transition 的 `cluster_id`、
`new_control_set_hash` 和 `new_control_peer_directory_hash` 也必须三方相等；head 的
`control_peer_directory_hash` 必须等于该 new directory hash。任何只对 hash 字符串做比较、却不验证所携带 ControlSetV1
bytes 与该 hash 相符的实现都必须拒绝。
Emergency bundle 还必须从 `new_control_set` 与 `new_recovery_policy` bytes 分别重算 transition、
genesis payload/head 所带的 set/policy hash；两者 cluster ID 必须与 transition 相等。它必须重算
全部 recovery key PoP 与 control 三用途 key PoP 的两个 RFC 6962 root，并分别匹配
`new_policy_pop_root/new_control_key_pop_root`；缺失、重复、额外或 key 字段与所携带 policy/set
不等时，在验证 Genesis QC 前即拒绝。这样旧 recovery threshold 不会把 floor 切到无人持有新
recovery key 或 enrollment key 仅存在于声明中的集合。
每个新 control voter 还必须经私有通道取得 `ControlPeerDirectoryPrivateObjectV1`，重算
`new_control_peer_directory_hash` 并验证与新 set 一一对应；该 preimage 不进入公开
`EmergencyRecoveryBundleV1`，普通客户端只验证旧 threshold 与新 config QC 对其 hash 的承诺。
`RecoveryThresholdSignatureV1` 精确为 `{key_id,signature}`，signature 是 raw 64-byte Ed25519、无 padding
base64url；数组按 key ID 排序并拒绝重复；
emergency signature 覆盖
`frame("loom-recovery-emergency-signature-v1", JCS(RecoveryTransitionBodyV1))`。客户端必须用
`previous_recovery_policy_hash` 指向的完整 public policy 验 key ID、用途、去重和 threshold，
不能只验证某一张“recovery cert”。`issued_at` 只供审计，不能代替 lineage/floor 证明新鲜度。

RecoveryTransition 只授权创建新 lineage，不能单凭离线签名冒充一个已经可用的配置 head。
transition 指定的新 ControlSet 必须先验证完整 transition/proof、key PoP、上述逐字段 equality，
再对代码块定义的唯一 `RecoveryGenesisV1`（其中 head 的
`recovery_statement_hash` 等于本 transition 的导出值，`genesis_payload_hash` 等于其承诺值）做 `q(new)` durable
install/commit，然后 apply/recompute，并由 `q(new)` 个新 config key 签
`HeadReplicationAttestationBodyV1` 形成 `StableHeadReplicationQCV1`。不同 genesis bytes、缺 durable quorum 或缺新集合
QC 都不得发布 current、签发邀请或执行副作用。

客户端只有同时验证旧 recovery threshold transition **和**精确 RecoveryGenesis 的新
ControlSet QC，才原子提高 recovery floor 并激活新 lineage；只拿到 transition 或单节点 genesis
时继续 last-known-good。该 transition、`q(new)` install evidence、genesis head/QC 和必要对象
构成不可裁剪的 recovery bundle，供长期离线客户端逐跳取得。

recovery 私钥不常驻 control Device。若 recovery anchor 也丢失，只能作为新集群重新
bootstrap，并要求每个客户端通过带外操作重新建立信任；不能伪装成连续升级。
普通 ControlSet 无权递增 `recovery_epoch`。current、transition、Device envelope 和客户端 floor
都持续绑定 `recovery_epoch + recovery_statement_hash + recovery_policy_hash`，所以恢复后的新 lineage 在排序上
优先于旧 quorum 继续产生的任意更高普通 revision；同 recovery epoch 的不同 statement hash
或 policy hash 直接视为 recovery fork 并失败关闭。Device Merkle leaf 按[signed current v2](publication.md#signed-current-v2)不重复放
head 坐标，而是由 envelope 中的 certified head/root 间接绑定上述三元组。
同一个 `previous_recovery_statement_hash` 指向两个 canonical bytes 不同的 transition 也始终是
fork，即使它们选择不同的更高 epoch；客户端不得按更大数字、时间或下载源择一。
