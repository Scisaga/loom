# Recovery policy 计划轮换

[文档地图](../../README.md) · [架构入口](../../architecture/README.md) · [控制面规范](README.md) · [实现对照](../../development/implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

## recovery policy 的计划轮换

有 quorum 时也应定期轮换 recovery 持有人/介质，但当前 ControlSet 不能单独给自己创造新的
最高 authority。新 policy 先在离线环境产生 canonical
`RecoveryPolicyV1{policy_id,generation,algorithm,key_ids_and_public_keys,threshold,`
`private_key_custody_root,ceremony_profile}` 和每把 key/DKG transcript 的 proof-of-possession；私有 share 走
[丢失 quorum](recovery.md#丢失-quorum) `RecoveryPrivateCustodyObjectV1` 的不可变 sealed artifact、真实 key-test 与离线
availability policy，不能复制给普通 voter 解密，也不能只靠 PoP 冒充可恢复备份。

首版 wire 固定为以下单向对象图；代码块中的 `body` 都是 exact schema，不得再内嵌一个含义不明
的“intent QC”对象：

```text
RecoveryPolicyIntentV1              # 旧 lineage 中的普通 control operation
  schema = 1, cluster_id, intent_id
  previous_recovery_epoch, previous_recovery_statement_hash
  previous_recovery_policy_hash
  previous_control_epoch, unchanged_control_set_hash, unchanged_control_peer_directory_hash
  parent_head_hash
  new_recovery_epoch                 # 必须等于 previous + 1
  new_recovery_policy_hash, new_policy_pop_root
  ceremony_id, reason

RecoveryPolicyTransitionBodyV1      # RecoveryStatementBodyV1 的 policy_rotation 变体
  schema = 1, statement_type = "policy_rotation"
  cluster_id, intent_id, intent_hash, intent_head_hash, intent_qc_hash
  previous_recovery_epoch, previous_recovery_statement_hash
  previous_recovery_policy_hash
  previous_control_epoch, unchanged_control_set_hash, unchanged_control_peer_directory_hash
  last_certified_head_hash
  new_recovery_epoch, new_recovery_policy_hash, new_policy_pop_root
  new_control_epoch = 0
  ceremony_id, reason, issued_at

RecoveryPolicyTransitionProofV1     # 在 Activation 之前即可完整取 hash
  schema = 1
  body: RecoveryPolicyTransitionBodyV1
  recovery_statement_hash
  old_policy_threshold_signatures[] # RecoveryThresholdSignatureV1；按 key ID 排序、拒绝重复

RecoveryPolicyActivationContextV1
  schema = 1, kind = "recovery_policy_activation"
  intent_hash, intent_head_hash, intent_qc_hash

RecoveryActivationHeadV1
  schema = 1
  head: HeadEntryV2                  # payload.transition_context 为上列 context
  replication_qc: StableHeadReplicationQCV1

RecoveryPolicyActivationBundleV1
  schema = 1
  intent: RecoveryPolicyIntentV1
  new_recovery_policy: RecoveryPolicyV1
  new_policy_possession_proofs[]      # RecoveryKeyPossessionProofV1，按 key ID 排序
  intent_operation: ControlOperationV1
  intent_operation_leaf: ControlOperationLeafV1
  intent_leaf_index, intent_operation_tree_size, intent_operation_audit_path[]
  intent_head: HeadEntryV2
  intent_head_qc: CertifiedHeadQCV1
  continuity_heads[]                 # {head: HeadEntryV2, qc: CertifiedHeadQCV1}，按链顺序
  transition_proof: RecoveryPolicyTransitionProofV1
  activation: RecoveryActivationHeadV1
  initial_device_view_proof?
```

`RecoveryPolicyIntentV1` 必须先由旧 lineage 的当前 ControlSet commit、apply/recompute 并取得
intent head/QC。`intent_hash = H(frame("loom-recovery-policy-intent-v1", JCS(intent)))`，且
`intent_operation` 必须是 [内容寻址操作](consensus.md#内容寻址操作) exact operation：
`kind="recovery_policy_intent"`、`payload_schema=1`、`payload_hash=intent_hash`、
`operation_id=intent.intent_id`；outer body 的 `cluster_id`、三个 `base_recovery_*`、
`base_control_epoch/base_control_set_hash`、`parent_head_hash` 必须分别等于 intent 的
cluster/previous recovery/previous control/parent 字段，`base_control_revision` 必须等于该
parent head 的已认证 revision。intent head 又必须直接以该 parent 为 parent，并在旧
recovery/control authority 下提交。bundle 必须提供 operation 的 leaf/index/tree
size/audit path 并重算到该 intent head 的 `operation_root`。
`intent_qc_hash = H(frame("loom-quorum-certificate-v1", JCS(intent_qc)))`；这里的
`intent_qc` 是签名按 signer ID 排序、拒绝重复后保存的精确不可变 QC，交付包必须携带同一 bytes，
transition body 本身不嵌入签名数组。Intent 的全部 previous/new 字段必须与 transition body
逐字段相等，且它承诺的新 policy/PoP 已完成公开可验证性检查。

旧 recovery policy 对
`frame("loom-recovery-policy-rotation-signature-v1", JCS(RecoveryPolicyTransitionBodyV1))` 签名并达到
阈值，签名条目使用 [丢失 quorum](recovery.md#丢失-quorum) 的 exact `RecoveryThresholdSignatureV1`。按 [丢失 quorum](recovery.md#丢失-quorum) 计算
`recovery_statement_hash`；随后计算：

```text
policy_transition_proof_hash = H(frame(
  "loom-recovery-policy-transition-proof-v1",
  JCS(RecoveryPolicyTransitionProofV1)
))
```

proof 不含 Activation/head/QC。`RecoveryActivationHeadV1` 的 `HeadEntryPayloadV2` 必须使用
`head_kind="recovery_policy_activation"` 及上列 exact context，并成为
`last_certified_head_hash` 的直接下一 head：`parent_head_hash` 精确等于该值，Raft log 坐标连续，
包含 `committed_logical_time`，`transition_proof_hash` 等于上述 proof hash，recovery 三元组切到
transition 指定的新值，`control_epoch` 重置为 0，`control_set_hash` 保持不变，且
`control_peer_directory_hash` 必须逐字节等于 intent/transition 的
`unchanged_control_peer_directory_hash`；当前同一 ControlSet 对它完成 durable
commit、apply/recompute 和 post-commit QC。Activation 后的首份 Device view 同样绑定该 head。
Activation 不授权夹带 ordinary state。确定性 reducer 从 `last_certified_head_hash` materialization
只替换 recovery policy/epoch/statement projection，并把 control epoch 重置为 0；业务对象、private
peer directory bytes 与 ControlSet 不变，再按同一 render contract 重算 snapshot/effective SSOT hash。
payload 的 `operation_root/device_views_root/admin_acl_root/ca_profile_root/bootstrap_issuer_registry_root/`
`render_contract_version/`
`min_reader_version/max_clock_skew_seconds` 必须逐字节继承 last head，`snapshot_hash` 与
`effective_ssot_hash` 必须等于该唯一 reducer 输出；logical time/raft index/revision 按 [Raft committed log 与提交后 certified QC](consensus.md#raft-committed-log-与提交后-certified-qc)与[时间语义](consensus.md#时间语义)
推进。其他字段变化一律拒绝，普通操作必须等 Activation certified 后再提交。
context 的 `intent_hash/intent_head_hash/intent_qc_hash` 必须逐字段等于
`RecoveryPolicyTransitionBodyV1` 同名字段；任一不同即拒绝，不能把同一 threshold proof 配给另一
Intent 的 Activation。
Activation head payload、context、transition body 与 intent 的 `cluster_id` 必须全部相等。
此外 transition body 的三个值必须分别等于重算的 `intent_hash`、实际
`intent_head.head_hash` 和实际 `intent_head_qc` 的 QC hash；intent operation inclusion proof 必须落在
同一个 intent head。任何只在两个声明对象间比较、却不回到实际 bytes/head/QC 重算的实现都拒绝。
bundle 必须从 `new_recovery_policy` exact bytes 重算 `new_recovery_policy_hash` 和全部 key PoP root。
policy hash 必须等于 intent/transition body 的 `new_recovery_policy_hash` 及 Activation head 的
`recovery_policy_hash`；PoP root 只与 intent/transition body 的 `new_policy_pop_root` 直接比较，并由
Activation `transition_proof_hash` 对 transition proof 的引用间接绑定，不得伪造一个
HeadEntry 中不存在的同名字段。只携 hash 而没有可验 public policy/PoP bytes 时不得提高
floor。
新旧 `RecoveryPolicyV1.cluster_id`、不变 `ControlSetV1.cluster_id`、所有 PoP body、intent、
transition body 和 Activation head 的 `cluster_id` 必须逐字节相等；任一 hash 可重算但
object 属于另一 cluster 的组合仍必须拒绝。

收集 threshold signature 前可以继续提交普通配置，但交付包必须给出从 intent head 到
`last_certified_head_hash` 的完整连续 head/QC 链，并证明其中 recovery 三元组、ControlSet 和
`control_peer_directory_hash` 均未变。
一旦 threshold proof 完成，Activation 必须紧接该 last head；若其间出现另一 commit，旧 proof
不得改 parent 或重放，必须选择新 last head 并重新取得旧 policy threshold signatures。intent 到
Activation 期间不得并行 ControlSet joint transition 或另一 recovery 操作。

完整 `RecoveryPolicyActivationBundleV1` 携带精确 intent/head/QC、上述连续链、transition proof、
Activation head/QC 和必要 view proof；bundle 的可选外层内容 hash 不写回任何内层对象。客户端
必须依次验证旧 lineage 的 intent head/QC、intent QC hash、连续链、旧 policy threshold、statement
hash、proof hash、Activation 的直接 parent 和同一 ControlSet 的 post-commit QC，全部成功后才
原子提高 `recovery_epoch + recovery_statement_hash + recovery_policy_hash` floor。仅有 intent、
threshold transition 或尚未 certified 的 Activation 时继续 LKG，绝不能提前抬 floor。

跨多次离线的 reader 依靠永久保留的公开 policy/transition/activation proof 逐跳追赶，不需要旧
private share。新 policy 完成独立恢复演练、Activation finality 且完整 bundle 有足够离线备份后，
应按 ceremony 销毁旧 private share，避免它继续签出竞争分叉。

ControlSet quorum 不可用时不存在“计划轮换”：旧 recovery threshold 仍可用则走 [丢失 quorum](recovery.md#丢失-quorum) 的
emergency recovery，并明确缺少 control QC；旧 threshold 已丢失时，普通 control quorum 无权
把另一把 key 宣布为连续的新 root，只能创建新 cluster 并逐 Device 带外 rebootstrap。若旧 key
疑似泄露，轮换无法抹去它已经签出冲突 transition 的可能性；客户端必须 fail closed，并通过
独立带外 witness/人工核验决定新锚，产品不得把“已轮换”误报成历史 compromise 已自动消失。

---
