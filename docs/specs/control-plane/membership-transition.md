# ControlSet 加入与移除

[文档地图](../../README.md) · [架构入口](../../design.md) · [控制面规范](../../distributed-control-plane.md) · [实现对照](../../implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

## 9. ControlSet 成员变化

### 9.1 加入

ControlSet 不是若干实现自行解释的 Device ID 列表。公开 authority 与 control peer 的私有拨号目录
必须拆开：公开 transition、邀请 proof 与静态镜像只携不暴露 Device/拓扑的 ControlSet，完整 peer
目录只在已认证 control-to-control 通道复制。首版 wire 使用以下 exact 对象；字段缺失、额外字段、
未排序数组、重复 member/key/endpoint 或同一公钥跨用途复用都必须拒绝：

加入流程的前置条件是候选已经是 active Device，持有 Device identity，安装过合法 LKG view，且能
经永久 Loom overlay 到达至少一个现有 control。管理员不能把二维码中的未入网身份直接写进
ControlSet，也不能用公网 FQDN、Nginx 或 bootstrap capability 承载 Raft learner 同步。

```text
ControlMemberV1
  schema = 1, cluster_id, member_id          # 128-bit CSPRNG opaque ID；不是 Device ID
  membership_key_id, membership_public_key
  config_key_id, config_public_key
  enrollment_key_id, enrollment_public_key
  minimum_control_protocol

ControlSetV1
  schema = 1, cluster_id
  members[]                                  # 完整 ControlMemberV1，按 member_id UTF-8 bytes 排序

ControlPeerDirectoryMemberV1                # private；禁止进入公开 transition/invite/mirror
  schema = 1, cluster_id, member_id, device_id
  peer_identity_spki_hash, peer_identity_artifact_hash
  peer_certificate_der, peer_certificate_hash
  peer_endpoints[]                           # {endpoint_id, url}，按 endpoint_id 排序
  fault_domain

ControlPeerDirectoryV1
  schema = 1, cluster_id, directory_generation
  hiding_nonce                              # 每代 32-byte CSPRNG；只随 private preimage 分发
  members[]                                  # 按 member_id UTF-8 bytes 排序

ControlPeerDirectoryPrivateObjectV1          # private content-addressed install object
  schema = 1, cluster_id, control_set_hash, control_peer_directory_hash
  directory: ControlPeerDirectoryV1

ControlKeyPossessionProofBodyV1
  schema = 1, cluster_id, control_set_hash, member_id
  key_purpose                                # membership | config | enrollment
  key_id, public_key

ControlKeyPossessionProofV1
  body: ControlKeyPossessionProofBodyV1
  signature: ControlKeyPossessionSignatureV1

ControlSetTransitionIntentV1
  schema = 1, cluster_id, transition_id
  recovery_epoch, recovery_statement_hash, recovery_policy_hash
  old_control_epoch, old_control_set_hash, old_control_peer_directory_hash
  target_control_epoch, new_control_set_hash, new_control_peer_directory_hash
  parent_certified_head_hash
  operation_id, reason

ControlMembershipApprovalProofV1
  schema = 1
  intent: ControlSetTransitionIntentV1
  admin_intent_operation: ControlOperationV1
  new_control_key_possession_proofs[]        # 按 (member_id,key_purpose) 排序
  signatures[]                               # ControlMembershipSignatureV1
  old_signer_refs[], new_signer_refs[]       # {member_id, membership_key_id}

JointControlSetEntryBodyV1                   # 内部 config-log entry；不是公开新 authority
  schema = 1, cluster_id, transition_id
  recovery_epoch, recovery_statement_hash, recovery_policy_hash
  old_control_epoch, old_control_set_hash, old_control_peer_directory_hash
  target_control_epoch, new_control_set_hash, new_control_peer_directory_hash
  parent_certified_head_hash
  membership_approval_proof_hash
  raft_term, raft_index, previous_log_entry_hash
  operation_id, reason, committed_logical_time

JointControlSetProofV1
  schema = 1
  joint_body: JointControlSetEntryBodyV1
  joint_entry_hash
  joint_replication_qc: JointConfigReplicationQCV1

FinalControlSetContextV1
  schema = 1, kind = "control_set_final"
  transition_id
  old_control_epoch, old_control_set_hash, old_control_peer_directory_hash
  new_control_epoch, new_control_set_hash, new_control_peer_directory_hash
  membership_approval_proof_hash
  joint_entry_hash, joint_proof_hash

FinalControlSetHeadV1
  schema = 1
  head: HeadEntryV2
  final_joint_replication_qc: JointHeadReplicationQCV1

ControlSetTransitionProofV1
  schema = 1, joint_proof_hash
  final_payload: HeadEntryPayloadV2

ControlSetTransitionBundleV1
  schema = 1
  old_control_set, new_control_set
  membership_approval_proof
  joint_proof
  final: FinalControlSetHeadV1
```

三个 Ed25519 public key 都是精确 32 bytes 的无 padding base64url，key ID 是对应 raw public key 的
小写 `sha256:` hex；三种用途必须使用三把不同 key。`member_id` 是创建成员时固定的 16-byte
CSPRNG 值，以大端 bit string、无 padding 的 26 位 Crockford Base32 编码；alphabet 精确为
`0123456789ABCDEFGHJKMNPQRSTVWXYZ`，首字符只允许 `0..7`。decoder 拒绝小写、`I/L/O/U` alias、
连字符、空白和非规范前导位，解码必须恰为 16 bytes 并重新编码逐字节相等。它永久不从 Device
ID、hostname 或公钥导出。
`ControlSetV1` 非空，所有 member ID、三类 key ID/public key 在集合内全局唯一；`control_epoch`
不进入集合 bytes，所以计划 recovery 将 epoch 重置为 0、但成员完全不变时可以继续绑定同一个
`control_set_hash`。每个 `ControlMemberV1.cluster_id` 必须等于其 `ControlSetV1.cluster_id`，old/new
两份 ControlSet 的 cluster ID 又必须等于 intent、Joint、Final head 的 `cluster_id`；任一不等即拒绝。

`ControlPeerDirectoryV1` 只在 control peer 的私有、双向 mTLS 内容寻址存储中出现。`hiding_nonce`
使用无 padding base64url 编码且解码后精确为 32 bytes，在 proposal 前固定并纳入 hash；它使公开的
directory hash 不能充当低熵 Device ID/私网 URL/fault-domain 的离线字典 oracle，轮换目录时不得
复用 nonce。每个 directory
member 必须与同 cluster 的 ControlSet member 按 `member_id` 一一对应，不能缺失或额外；Device ID、
peer SPKI、endpoint ID/URL 在目录内各自唯一，URL 按 RFC 3986 规范化且只允许 control-replication
profile 的 mTLS scheme。`fault_domain` 只用于部署风险/放置检查，不改变 quorum 公式。普通客户端
验证 authority 只需要公开 ControlSet 与被 authority 签过的 directory hash，不得请求其 preimage；
参与安装/投票的 control 必须先通过私有通道取得完整 exact directory 并重算 hash，否则拒绝
membership transition。目录内容进入 effective SSOT 的私有投影，绝不进入 public mirror、QR、
InviteProofBundleV2 或 per-Device view。
每个 `peer_identity_artifact_hash` 必须解析到 [§6.2](secret-artifacts.md#62-权威-secret-artifact) purpose=`control_peer_identity` 的 exact
`SecretArtifactRefV2`，owner 等于 directory Device、公开 SPKI hash相等且 PoP/availability 满足；
其中 `peer_identity_spki_hash=H(frame("loom-control-peer-identity-spki-v1",raw_spki_der))`，
`peer_certificate_hash=H(frame("loom-control-peer-certificate-der-v1",raw_certificate_der))`。
peer key 固定为 Ed25519；证书必须是 strict DER、自签且验签成功，SPKI 与 artifact 逐字节相等，
`BasicConstraints CA=false`、KeyUsage 仅含 `digitalSignature`、EKU 恰含 client/server authentication，
并在 [§7.5](consensus.md#75-时间语义) 可信时间窗内有效。control-peer TLS 固定 TLS 1.3，双方只接受当前 directory（Joint 时为
old/new directory 并集）中 exact certificate hash + SPKI pin 对应的成员；系统 trust store、DNS 名或
普通 Device/admin 证书都不能扩大 authority。不能用一个仅声明的 SPKI 把新 peer 加进 Raft。
`ControlPeerDirectoryPrivateObjectV1` 的 cluster、set/hash 必须从所携 exact set（经同一私有安装
事务取得）与 directory 重算；在 Joint/Bootstrap/Emergency durable commit 前，新 ControlSet 的每个
member 都必须通过 private channel 持久保存同一
`control_peer_directory_private_object_hash`。bootstrap 与 emergency Genesis 的新 directory
generation 固定为 1；正常 ControlSet transition 必须等于 old generation+1 并使用全新 nonce；planned
recovery policy rotation 不改 set/directory，必须逐字节复用同一 private object/hash。generation
只在 matching recovery authority 内比较，跨 emergency epoch 由 recovery statement/hash 隔离，不能
拿数值大小覆盖 recovery proof。公开 bundle 只携被签名的 directory hash，故普通 reader 无需也不得
取得该 private object。

peer 证书或 key 轮换走同一 Joint→Final transition；允许 ControlSet bytes 不变而 directory generation、
nonce、certificate/artifact 改变。新目录在 Joint 前已由 new-side voter 持久安装，Joint 期间新旧身份
重叠接受；Final 只在新身份已形成 Raft 多数连接后提交，certified 后旧身份不得发起新握手。

每个新 `ControlSetV1` 必须同时提供恰好 `3 × member_count` 个
`ControlKeyPossessionProofV1`。proof body 的 public key/key ID 必须逐字节等于所指 member 与
`key_purpose` 的对应字段，`control_set_hash` 必须由完整目标集合重算；数组按 member ID 的 UTF-8
bytes、再按固定 `membership → config → enrollment` 枚举排序，缺失、重复、额外 proof 或跨用途
复用全部拒绝。签名使用 proof 自己声明的 public key 验证，并覆盖：

```text
frame("loom-control-key-possession-signature-v1",
      JCS(ControlKeyPossessionProofBodyV1))
control_key_pop_hash = H(frame(
  "loom-control-key-possession-proof-v1", JCS(ControlKeyPossessionProofV1)
))
```

需要把 proof 集合承诺到另一对象时，`control_key_pop_root` 对相同排序的
`{member_id,key_purpose,control_key_pop_hash}` leaves 使用 [§7.1](consensus.md#71-内容寻址操作) 的 RFC 6962 规则计算。PoP 只证明
对应私钥确实存在，不授予成员资格；正常成员变化由
`ControlMembershipApprovalProofV1.new_control_key_possession_proofs` 携带并经其 hash 固定，紧急恢复
与首次 bootstrap 则分别由 [§9.3](recovery.md#93-丢失-quorum)、[§10.3](publication.md#103-v1--v2-不可逆-latch) 的旧 authority 签名对象承诺该 root。

用途隔离还必须跨对象验证，不只是同一 ControlSet 内三把 key 不同：任一
recovery policy key 的 raw public bytes/SPKI digest 不得与该 cluster 当前或候选
ControlSet 的 membership/config/enrollment key、control peer identity、Device identity、Device wrapping、admin
signing、CA signing、公网 TLS 或客户端/code-signing key 复用。同样，这些 purpose
class 相互也不得复用同一 public key；同一 TLS credential generation 在多个已授权
listener 中引用不算跨 purpose。验证器对相同
algorithm 比较 canonical public bytes，并对所有 algorithm 比较 DER SPKI SHA-256；不能因字段
key ID 命名不同就视为两把 key。normal ControlSet transition、bootstrap、emergency
recovery 和 planned policy rotation 都在签名/QC/floor 切换前针对各自完整候选对象执行
同一项交叉检查；普通 Device identity/wrapping、TLS/code-signing key 轮换的 candidate 也必须针对当前
recovery/control/admin/CA/peer key 做反向检查。

```text
control_set_hash = H(frame("loom-control-set-v1", JCS(ControlSetV1)))
control_peer_directory_hash = H(frame(
  "loom-control-peer-directory-v1", JCS(ControlPeerDirectoryV1)
))
control_peer_directory_private_object_hash = H(frame(
  "loom-control-peer-directory-private-object-v1",
  JCS(ControlPeerDirectoryPrivateObjectV1)
))
control_set_transition_intent_hash = H(frame(
  "loom-control-set-transition-intent-v1", JCS(ControlSetTransitionIntentV1)
))
membership_approval_proof_hash = H(frame(
  "loom-control-membership-approval-v1",
  JCS(ControlMembershipApprovalProofV1)
))
joint_entry_hash = H(frame("loom-joint-control-set-entry-v1", JCS(JointControlSetEntryBodyV1)))
joint_qc_hash    = H(frame("loom-quorum-certificate-v1", JCS(joint_replication_qc)))
joint_proof_hash = H(frame("loom-joint-control-set-proof-v1", JCS(JointControlSetProofV1)))
control_transition_proof_hash = H(frame(
  "loom-control-set-transition-proof-v1",
  JCS(ControlSetTransitionProofV1)
))
```

`admin_intent_operation` 必须是 [§7.1](consensus.md#71-内容寻址操作) exact admin-signed operation：
`kind="control_set_transition_intent"`、`payload_schema=1`，payload 逐字节等于 proof 的 `intent`，
`payload_hash=control_set_transition_intent_hash`，outer/intent 的 cluster 与 operation ID 分别相等。
outer 的 base recovery/control 坐标和 parent head 必须逐字段等于 intent 的 recovery、old control 与
`parent_certified_head_hash`，base revision 等于该 parent certified head；签名 admin cert/key 必须在
该 parent ACL 的独立 membership-management scope 中。它是将 proposal 直接纳入特殊 Joint config
entry 的 admin authorization，不进入一个更早 ordinary head 的 operation tree；Joint 通过完整
`membership_approval_proof_hash`、entry hash 与 QC 认证它。缺 operation、换 payload、ACL 越权或
把普通 Device/member signature 当 admin authorization 均拒绝。

membership signature 以 `loom-control-membership-approval-signature-v1` domain 覆盖
`ControlSetTransitionIntentV1` 的 canonical bytes；old/new 两侧都须达到各自多数，因而同时证明
旧集合授权与新集合接受。新集合三种用途的逐 key 持有性由 proof 内完整 PoP 数组独立证明，
不能因为已有 membership/config 多数签名就推断所有 enrollment key 可用。proof 中所有
signature/ref 按 `(member_id,key_id)` 排序且唯一。Joint body 与 intent 的同名字段（包括 old/new
peer directory hash）必须逐字段相等
并引用该 proof hash。

QC 的 `signatures` 也按 `(member_id,key_id)` 排序且每个 ref 只保存一份；key 未变的重叠 member ref
可以同时出现在 old/new 两个有序投影，key 轮换时则分别保存 old/new key 的签名。验证器必须从
两份 ControlSet 重算投影、签名用途和两边**唯一 member ID**门槛，不能相信发送方给出的计数，
同一 member 在同一侧永远只计一票。Joint config 与 Final head 分别使用 [§7.4](consensus.md#74-raft-committed-log-与提交后-certified-qc) 的 tagged QC，
不得共用或省略 attestation body。`target_control_epoch` 和 `new_control_epoch` 都必须等于
`old_control_epoch + 1`。Final payload/context 必须精确引用同一 membership proof 以及已提交
Joint 的 entry/proof hash。正常情况下其 Raft index/previous-log hash 紧接 Joint；若 Joint 后发生
leader 更替，只允许插入 [§7.4](consensus.md#74-raft-committed-log-与提交后-certified-qc) 的 current-term `RaftNoOpEntryV1` barrier，Final 坐标必须紧接真实
hash-chained Raft 前项，同时仍以 Joint entry/proof hash 绑定同一 transition；
`control_transition_proof_hash` 在 Final head 之前已经固定，不含 `HeadEntryBodyV2`、entry/head hash
或 QC，因而没有自引用。Final 的 `HeadEntryV2.body.payload` 必须逐字节等于 proof 中的
`final_payload`，`Final.head.body.transition_proof_hash` 必须等于重算的
`control_transition_proof_hash`；完整 bundle 的可选外层 hash 不写回
内层对象。

Final payload/context 与 Joint/intent 的重复承诺必须逐字段相等：payload 的
`cluster_id/recovery_epoch/recovery_statement_hash/recovery_policy_hash`，context 的
`transition_id/old_control_epoch/old_control_set_hash/old_control_peer_directory_hash/`
`membership_approval_proof_hash` 完全相同；context 的
`new_control_epoch/new_control_set_hash/new_control_peer_directory_hash` 分别等于 Joint/intent 的
`target_control_epoch/new_control_set_hash/new_control_peer_directory_hash`，且
`Final.payload.parent_head_hash ==`
`Joint.parent_certified_head_hash == Intent.parent_certified_head_hash`。Final payload 的
`control_epoch/control_set_hash` 又必须分别等于其 context 的
`new_control_epoch/new_control_set_hash`，不能让 transition 批准的集合与 Head authority 字段分离。
payload 的 `control_peer_directory_hash` 还必须等于 context 的
`new_control_peer_directory_hash`。
Final payload 的 `raft_index` 必须大于 Joint index。两者相邻时
`previous_log_entry_hash == joint_entry_hash`；存在 index gap 时两者必须不等，且 control voter
必须从本机 committed Raft prefix 验证 gap 恰由 hash-chained current-term no-op barrier 构成。
Joint 相对 parent certified Head 使用同一规则。任一 data-bearing entry、错误直接引用或日志断链
都必须拒绝，不能仅因 joint proof 本身有效就把它拼接到另一 lineage、parent 或目标 epoch。

Final membership transition 不授权夹带普通业务、ACL、CA 或 reader-policy 修改。确定性 Final
reducer 从 `parent_certified_head_hash` 的 materialized state 出发，只把 private operator
`control` projection 替换为 new public ControlSet hash、matching directory hash 与新 control epoch，
其余业务对象逐字节保持；随后按同一 render contract 重算 snapshot/effective SSOT hash。因此 Final
payload 的 `operation_root/device_views_root/admin_acl_root/ca_profile_root/bootstrap_issuer_registry_root/`
`render_contract_version/`
`min_reader_version/max_clock_skew_seconds` 必须逐字节继承 parent，`snapshot_hash` 与
`effective_ssot_hash` 必须等于上述唯一 reducer 输出，不能由 sender 自报。`committed_logical_time`
只能按 [§7.5](consensus.md#75-时间语义) 单调前进，`control_revision` 仍由 Final 的 raft index 映射；只有 authority 字段、
transition context/proof、Raft 坐标以及由 control projection 唯一导致的两个 materialization hash
可变化。若要同时改其他状态，必须等 Final certified 后以新的 ordinary admin operation 提交。

old directory hash 必须等于 parent certified private state 当前目录，new directory hash 必须从
candidate 的完整 `ControlPeerDirectoryV1` 重算；两者对应的目录都必须与各自 ControlSet 一一对应。
公开 `ControlSetTransitionBundleV1` 有意只携这些 hash 而不携目录 bytes：客户端验证 old/new
membership approval、Joint/Final QC 和 hash equality；control voter 还执行目录 preimage 与私有
state equality 检查。缺 private directory 的节点可验证公开 proof，但不能作为该 transition 的
安装 voter 或 Raft peer。

1. 管理员用 admin cert 提交公开的新成员 control keys，并经私有 control 通道提交对应 peer
   endpoints、Device 映射和 fault domain 目录。
2. 新节点以 learner 身份验证当前 certified checkpoint/QC、完整操作链并追到最新 committed
   index；其 apply 后状态 hash 必须与 certified head 或后续 attestation 一致。
3. 新节点证明持有三类 control 私钥和兼容版本；不得复制现有 voter 私钥。old/new 集合再用
   membership key 对同一 `ControlSetTransitionIntentV1` 各达多数，形成上文 approval proof。
4. 当前稳定配置在验证该 proof 后串行追加唯一 `JointControlSet(transition_id,C_old,C_new)`；它只有同时取得
   `q_old` 和 `q_new` 的 durable ack 才提交，apply 后的 replication QC 也必须分别满足两边
   多数。未提交的竞争成员变更按日志冲突规则丢弃。
5. `JointControlSet` 生效后，选举必须同时取得 old/new 多数；状态机进入
   `joint_finalization_only(transition_id)`，除与该 transition 精确匹配的 Final 及 leader 更替必需的
   current-term no-op barrier 外，不得追加或提交普通 head、另一 membership/recovery operation或
   外部副作用 intent。期间收到的普通提案只留在 CRDT/pending 层，等待 Final certified 后基于新
   head 重新做 CAS；不得把 data-bearing entry 插到 Joint 与 Final 之间。
   重叠 voter 在两边各计一次成员资格，但 QC 必须分别证明两边都达门槛。
6. 在 joint 规则下紧接 Joint（或紧接 leader 更替所需的 no-op barrier）提交并以 old/new 双多数 QC 认证
   `FinalControlSet(transition_id,C_new,new_epoch)`；Raft commit/apply Final 就切换内部 epoch 和
   voter rules，从该 entry **之后**只由 `C_new` 选举、提交；只有 Final 的 old/new joint QC
   形成后才物化/发布新 `control` projection 与客户端 transition。
7. 从 Final head 开始的 client view 必须提供上文 exact transition bundle；后续普通 current 延续
   `transition_proof_hash=control_transition_proof_hash`，直到下一次 transition 替换它。Final 的
   old/new 双多数 QC 已证明新集合参与并复算该 head，不另要求一个会阻塞切换的新 epoch 后继 head。
   bundle 可有内容寻址外层 hash，但 authority 绑定的是内层 proof hash，外层 hash 不写回 current。

同一稳定 head 同时只允许一个 membership transition；新的成员变更必须等待
`FinalControlSet` 的 old/new joint QC 形成并进入 certified transition bundle。
任一阶段崩溃后按日志中最后 committed config 恢复：Joint 已提交就继续双多数且只恢复该
transition 的 Finalization，不能回退为 `C_old` 单多数或先夹入普通 entry；Final 已提交就不能让旧
集合复活。这里的 joint state 是 Raft 配置状态机，
不是 SSOT 中一组可被 CRDT/LWW 合并的临时布尔字段。

### 9.2 移除

control membership 与数据面 drain/decommission 分开。移除 voter 前先保证剩余集合满足
目标故障容忍度，再走 old/new joint transition。普通 Device 的 Pause、Remove 或删除
`server` 块不能隐式移除 control；反过来，移除 control 也不自动停止它的 server/access。

偶数集合合法，但 1→2 不增加故障容忍，3→2 会失去 HA。界面必须在提交前展示旧/新
`N`、`q` 和可容忍故障数，而不是用“添加备用控制器”掩盖 2/2 的实际行为。
