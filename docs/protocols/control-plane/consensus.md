# CRDT、Raft、QC 与读写

[文档地图](../../README.md) · [架构入口](../../architecture/README.md) · [控制面规范](README.md) · [实现对照](../../development/implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

## 复制模型：CRDT 保存材料，共识决定生效

```text
管理员签名请求 / 节点签名事实
              │
              ▼
  内容寻址操作与对象集合 ── CRDT anti-entropy ── 所有 control 副本
              │
              ▼ 确定性校验、候选归约/渲染
       针对精确 parent/hash 的 Raft entry
              │
              ▼ durable commit → apply/recompute → quorum attest
       唯一 certified head + quorum certificate
              │
              ├──► 公开 head/QC/transition ──► 不可信静态镜像
              ├──► 每 Device Merkle-proofed view ──► 身份认证的 device_config API
              └──► DNS、ACME、端口、防火墙等幂等 reconciler
```

### 内容寻址操作

所有提案与事实写成不可变 canonical object；每种权威对象必须使用本节 framing 及其固定 domain，
不能依赖“对某段 JSON 直接 SHA-256”这种未标类型的摘要。
首个 wire profile 固定使用 RFC 8785 JSON Canonicalization Scheme（JCS）和 UTF-8：输入必须
先满足 I-JSON；协议整数限制为有符号 64 位且禁止浮点、`NaN`/Infinity；时间统一为带 `Z`
的 RFC 3339 字符串；hash/key ID 使用小写十六进制；证书使用 DER 后再做无 padding base64url；
可选字段缺失与 `null` 不等价。集合型数组必须按各 schema 指定的稳定键逐字节排序，序列型
数组保留顺序。签名输入采用 `uint32_be(domain_length) || domain || canonical_bytes`，禁止靠
字符串拼接做 domain separation。Go/Kotlin/Windows 必须共享黄金字节、hash 和签名向量；
不符合规范的 JSON 在 canonicalize 前失败关闭，不能“宽松解析后再签”。
所有验证公式的中间算术使用数学整数语义（实现至少使用 checked
128-bit 或等价大整数），最终 wire 结果必须可表示为 int64；任何加、减、乘、
时间戳转换或 RFC 3339 结果越界都 fail closed，不使用宿主语言 wrap/saturate。
basis-points 可用大整数 `floor(10000*n/d)` 或等价的 quotient/remainder 无溢出
算法，禁止先在 int64 中无检查计算 `10000*n`。

控制副本以 add-only set / Merkle DAG 做 anti-entropy；重复对象按 hash 去重，同一 ID
不同字节立即判损坏。首版管理操作的 exact envelope 为：

```text
ControlOperationBodyV1
  schema = 1, cluster_id, operation_id
  author_id, admin_cert_digest
  created_at, expires_at?
  base_recovery_epoch, base_recovery_statement_hash, base_recovery_policy_hash
  base_control_epoch, base_control_set_hash, base_control_revision, parent_head_hash
  kind, payload_schema, payload_hash
  reason

ControlOperationV1
  body: ControlOperationBodyV1
  author_signature: AdminOperationSignatureV1

AdminOperationSignatureV1
  algorithm = "ecdsa-p256-sha256" | "ed25519", admin_key_id
  signature                        # raw 64 bytes，无 padding base64url
```

`author_signature.signature` 覆盖
`frame("loom-control-operation-signature-v1", JCS(ControlOperationBodyV1))`；key ID 必须由 body 所指
admin cert 的 DER SPKI 重算，并在 base head 的 admin ACL scope 内获准执行 exact `kind`。证书/profile、
signature algorithm 和 wire 长度必须逐字段满足 [初始 admin/CA 与轮换](identity.md#初始-adminca-与轮换) 的 exact admin profile；P-256 必须使用
SHA-256 与规范 low-S raw64，不接受 DER、高 S 或算法标签替换。不能从本机 provider
默认值猜算法，也不接受 DER 或可变长度编码。
`object_id = H(frame("loom-control-operation-v1", JCS(ControlOperationV1)))`。每种 `kind` 必须在
版本化 schema 中固定 payload bytes 和 payload hash domain；未知 kind/schema、额外字段、cert digest
不匹配或相同 operation ID 的不同 object ID 全部拒绝。

时间和端口等公开随机选择由调用方产生并进入对象，归约器不读取本机时钟或随机源，继续
满足纯函数约束。秘密随机值同样在 proposal preparation 按 [权威 secret artifact](secret-artifacts.md#权威-secret-artifact) 预生成，绝不能由 reducer 或
commit 后 executor 临时生成；invite token 明文、Device 数据面凭据和私钥不进入
公开 operation/CRDT/SSOT，只提交 token commitment/binding hash 或公开密钥；需要可接管执行的
exact-version artifact ref 只进入 [权威 secret artifact](secret-artifacts.md#权威-secret-artifact) 规定的 control-private replicated object，并由公开 hash 承诺。
管理员重试复用 `operation_id`；相同 ID 不同 payload 必须失败关闭。

每个 certified head 的 `operation_root` 使用一个确定的累计操作树，而不是 map 的本地遍历顺序：

```text
ControlOperationLeafV1
  schema = 1, operation_id, object_id
```

只纳入该 head 已按序 apply 的 canonical operation objects；通常是 admin-signed
`ControlOperationV1`，三个非 admin variant 仅为 [内层 TLS、token、Keystore PoP 与一次性提交](enrollment-transaction.md#内层-tlstokenkeystore-pop-与一次性提交) 明确定义的 admission-QC-authorized
`EnrollmentClaimOperationV2`、CA-authorized `EnrollmentProvisionalIssuanceOperationV1` 与
approval-QC-authorized `EnrollmentCompletionOperationV2`。每个 leaf
的 `object_id` 按其 exact variant/domain 重算，operation ID
从对应 body 取得。leaf 按规范化 `operation_id` UTF-8 bytes 升序，跨 variant 重复 ID 同样拒绝；
`LeafHash=SHA-256(0x00 || JCS(ControlOperationLeafV1))`，内部节点为
`SHA-256(0x01 || left || right)`，奇数叶按 RFC 6962 的最大二次幂递归分树而不复制末叶，空树 root
为 `SHA-256("")`。所有 voter、Device proof 和 Enrollment proof 都必须使用同一 index/tree size；
不能按 object arrival、Raft follower 本地顺序或 JSON map 顺序构造 root。

### 哪些数据可以直接 CRDT 合并

| 数据 | 合并方式 | 是否直接改变权限/配置 |
|---|---|---:|
| 签名健康、测量、运行回执 | add-only set，按身份/时间/hash 去重 | ❌ |
| 不可变 snapshot、binary、Device view | control 副本内部的内容寻址集合；Device view 不进入公共镜像 | ❌ |
| UI 草稿、评审意见 | MV-register/operation set；冲突显式展示 | ❌ |
| pending proposal | operation DAG | ❌ |
| 审计附件 | add-only set | ❌ |

不得用 last-write-wins 静默解决两份管理员修改。冲突草稿可以都存在，但必须由管理员选择
或生成一个合并提案，最终对精确 hash 取得提交后 quorum attestation/QC。

首版 control 间 anti-entropy 使用 private peer 路径
`POST /private/v2/crdt/anti-entropy`：只接受当前 stable ControlSet，或 Joint 期间 old/new
directory 并集内的 exact control-peer mTLS leaf 与 TLS 1.3。请求和响应都携带不超过 64 MiB 的
完整、按 logical ID 严格排序的 object snapshot 及其 Merkle root；接收端重算 root，并在原子
merge 前按每个 object 的 kind/schema 重放 typed verifier，同一 logical ID 不同 bytes 整批拒绝。
响应返回 merge 后的 snapshot，发起端再次重算 root、执行相同 typed verifier 后再 merge；任一侧
返回或落盘这些材料都不表示它们已生效，外部副作用仍只读取 Raft committed、apply/recompute 且
取得 QC 的 certified head。

### 哪些状态必须串行提交

- ControlSet、信任根、admin 权限和证书 profile；
- Device membership、职责、grants、暂停、撤权和删除；
- 邀请创建、作废、一次性消费和 identity/SPKI 绑定；
- 生效 SSOT、release、rollback、每 Device view 与最低客户端版本；
- 唯一地址、域名、端口、credential generation 和资源租约；
- DNS 生效绑定、证书签发批准、入口 preferred/retired 代次；
- tombstone checkpoint 与垃圾回收水位。

原因不是这些数据无法序列化，而是两个分区各自合法地修改后，事后合并无法撤回已经签发
的证书、消费的 token 或暴露的数据。

### Raft committed log 与提交后 certified QC

v2 CFT profile 的提交权威是一个标准 Raft 复制日志，不是“先到先签、凑够签名”的自由投票。
每个 voter 必须耐久保存 `current_term`、`voted_for`、hash-chained log、`commit_index` 和
`last_applied`，执行 Raft 的单 leader、log matching、leader completeness、up-to-date election
及“只用当前 term 条目推进 commit index”规则。pre-vote、CRDT 已看到对象或单个节点本地保存
均不算提交。leader 只是临时协调者，不是固定控制节点或额外信任根。

leader 在完整取得输入并执行严格解码、校验和确定性 candidate render 后，向日志追加
`HeadEntryV2`；follower 在接受 AppendEntries 前也必须确定性验证完整 candidate，拒绝未知 schema、
缺对象或结果不一致的条目。首版普通及特殊 head 共用以下 exact envelope：

```text
HeadEntryPayloadV2
  schema = 2
  head_kind                     # ordinary/bootstrap/control_set_final/
                                # emergency_recovery/recovery_policy_activation
  cluster_id
  recovery_epoch, recovery_statement_hash, recovery_policy_hash
  control_epoch, control_set_hash, control_peer_directory_hash
  raft_term, raft_index, previous_log_entry_hash
  control_revision              # 由 committed raft_index 按 wire profile 确定，禁止另行分配
  parent_head_hash
  operation_root, snapshot_hash, effective_ssot_hash, device_views_root
  admin_acl_root, ca_profile_root, bootstrap_issuer_registry_root
  render_contract_version, min_reader_version
  committed_logical_time, max_clock_skew_seconds
  transition_context            # 按 head_kind 选择本文后续章节定义的 exact tagged object

HeadEntryBodyV2
  payload: HeadEntryPayloadV2
  transition_proof_hash

HeadEntryV2
  body: HeadEntryBodyV2
  entry_hash, head_hash          # QC 永不参与自身 hash
```

`ordinary` 的 transition context 精确为 `{schema:1,kind:"ordinary"}`；其他 kind 分别使用 [加入](membership-transition.md#加入)、[丢失 quorum](recovery.md#丢失-quorum)、
[recovery policy 的计划轮换](recovery-policy.md#recovery-policy-的计划轮换)、[v1 → v2 不可逆 latch](publication.md#v1--v2-不可逆-latch) 的 context。未知 kind、context 字段不匹配或额外字段全部拒绝。
每个 ordinary head 的 `parent_head_hash` 必须直接引用同一 Raft lineage 上前一个 certified
`HeadEntryV2`；两者之间不得跳过另一份 HeadEntry。`previous_log_entry_hash`/`raft_index` 则严格
跟随真实 Raft log 的直接前项，因此中间若有不产生 head 的内部 entry，`control_revision=raft_index`
可以出现间隙而不是伪造“连续 revision”。任一 HeadEntry 已 committed 但尚未取得 QC 时，后续
HeadEntry 必须冻结，直至该 entry certified 或进入本文定义的 recovery；不得用下一份 ordinary head
跳过一份已 apply 但未 certified 的状态。ordinary head 还必须
逐字节继承 parent 的 recovery epoch/statement/policy hash、control epoch/set hash、
`control_peer_directory_hash` 与 `transition_proof_hash`。只有相应 exact
ControlSet Final、emergency Genesis、planned RecoveryActivation 或 bootstrap head 可以改变这些
authority 字段；普通 operation 即使取得 admin 签名也不能。该全局规则先于各业务章节的局部
equality，防止普通 head 偷换 authority 或 private-directory commitment。
`EMPTY_HASH_V1 = "sha256:" + 64 个 ASCII '0'` 是唯一空前项 sentinel：
`previous_log_entry_hash` 只可在每条新 Raft lineage 的 `raft_index=1` 使用，即初始 `bootstrap` 或
`emergency_recovery` Genesis；`parent_head_hash` 只可在整个 cluster 的初始 `bootstrap` 使用，
emergency Genesis 必须指向旧 lineage 的最后可信 head。不得用空串、字段缺失或 `null` 表示。
两个 hash 分别为：

```text
entry_hash = H(frame("loom-raft-head-entry-v2", JCS(HeadEntryBodyV2)))
head_hash  = H(frame("loom-control-head-v2", JCS(HeadEntryBodyV2)))
```

`control_revision` 的 wire mapping 固定由 committed `raft_index` 推导，可以有因非 head entry
产生的间隙，但 leader、管理员和本地文件锁都不能独立选号或复用 revision。

follower 先按 Raft 验证 term/日志前缀，把精确 entry `fsync` 后返回普通 AppendEntries ack；
leader 仅按 Raft 当前-term规则和稳定配置多数（joint 时 old/new 双多数）推进 `commitIndex`。
这些内部复制 ack 不作为客户端 QC，也不得脱离 Raft term/日志规则凑签名提交。
新 leader 若日志非空，必须先追加并提交一个私有 `RaftNoOpEntryV1` current-term barrier，才能以
当前任期规则确认并传播继承自旧任期的 committed prefix；该内部 entry 不产生 Head，但其 exact
hash 是下一日志项的 `previous_log_entry_hash`。应用状态只可保存对本机已 fsync
`{member_id,term,index,entry_hash}` committed record 的引用，禁止让调用者在 Raft 之外重新提交一组
member ID 充当 durable ack 证据。进程重启后必须重新 pre-vote/election，不能从持久化 self-vote
推导自己仍是 leader。

voter 只有在得知该 entry 已 committed、按序 apply，并重算出逐字节相同的 roots/head 后，才用
独立 config key 签以下两个互不兼容的 attestation 之一：

```text
JointConfigAttestationBodyV1
  schema = 1, attestation_type = "joint_config"
  cluster_id
  recovery_epoch, recovery_statement_hash, recovery_policy_hash
  old_control_epoch, old_control_set_hash, old_control_peer_directory_hash
  target_control_epoch, new_control_set_hash, new_control_peer_directory_hash
  raft_term, raft_index, previous_log_entry_hash
  joint_entry_hash, membership_approval_proof_hash

HeadReplicationAttestationBodyV1
  schema = 1, attestation_type = "head"
  cluster_id
  recovery_epoch, recovery_statement_hash, recovery_policy_hash
  control_epoch, control_set_hash, control_peer_directory_hash
  raft_term, raft_index, previous_log_entry_hash, control_revision
  entry_hash, head_hash, parent_head_hash, transition_proof_hash
  operation_root, snapshot_hash, effective_ssot_hash, device_views_root
  admin_acl_root, ca_profile_root, bootstrap_issuer_registry_root
  render_contract_version, min_reader_version
  committed_logical_time, max_clock_skew_seconds

JointConfigReplicationQCV1
  schema = 1, qc_type = "joint_config"
  attestation: JointConfigAttestationBodyV1
  signatures[]                  # ControlConfigSignatureV1
  old_signer_refs[], new_signer_refs[]

StableHeadReplicationQCV1
  schema = 1, qc_type = "stable_head"
  attestation: HeadReplicationAttestationBodyV1
  signatures[]
  signer_refs[]

JointHeadReplicationQCV1
  schema = 1, qc_type = "joint_head"
  attestation: HeadReplicationAttestationBodyV1
  signatures[]
  old_signer_refs[], new_signer_refs[]

CertifiedHeadQCV1 = StableHeadReplicationQCV1 | JointHeadReplicationQCV1
```

Joint config signatures 覆盖
`frame("loom-joint-config-replication-attestation-v1", JCS(JointConfigAttestationBodyV1))`；两类 head
signatures 都覆盖
`frame("loom-head-replication-attestation-v1", JCS(HeadReplicationAttestationBodyV1))`。signature/ref
统一按 `(member_id,config_key_id)` 排序并拒绝重复；stable 从一个 ControlSet 重算唯一 member ID
多数，joint 从 old/new 两个集合分别重算。`qc_hash = H(frame("loom-quorum-certificate-v1",`
`JCS(exact_tagged_qc)))`，其中 exact tagged QC 只能是上述三种之一；因此 Joint config signature
不能被搬作 Head signature，stable QC 也不能伪装成 joint QC。

验 QC 前必须先验对象绑定：`JointConfigAttestationBodyV1` 的 cluster/recovery、old/target control、
Raft 坐标、membership proof 与 `joint_entry_hash` 必须和 `JointControlSetEntryBodyV1` 逐字段相等，
并从该 body 重算同一 entry hash；`HeadReplicationAttestationBodyV1` 的全部同名字段必须与
`HeadEntryV2` 逐字段相等，并先按上式重算 entry/head hash。attestation 与展示/交付对象只要任一
字段不同，即使签名本身可验也拒绝，不能由 reader 自选信任哪一份坐标或 root。

稳定配置收齐 `q(N)` 份，joint 配置收齐 old/new 两边各自多数，才组成对外 QC。因此可能短暂
存在 `committed_not_certified`：它已经进入内部状态机，
但不得由 private API 返回为 current、发布为可引用的 immutable signed head、驱动外部副作用或
返回“已生效”；客户端继续 LKG。QC 是对
“Raft 已提交且 quorum 已复算”的证明，不是 Raft 投票消息，也不能反向提交日志。

未被 Raft committed 的日志后缀可在更高 term 按 Raft 规则覆盖；不存在永久占用某个 revision
的应用层预签票，因此 leader 切换不会因分散预签而永久停写。已经 committed 的 entry
不得被冲突日志覆盖；同一 lineage/正式 revision 出现冲突 QC 是安全事件。外部 reader 只需
验证 ControlSet/transition、QC 的 term/index/hash/签名集合和 head 链，不需要信任或固定当前
leader。若未来替换 Raft，必须使用新 protocol profile，完整定义 term/round、锁定与解锁、
view change、成员迁移和可机检安全证明；不能只实现 parent/hash 多签。

### 时间语义

所有会影响归约结果的时间来自日志中的 `committed_logical_time`，并在同一 lineage 内严格
单调；reducer 不读取本机时钟。leader 提议时间，voter 只在其受监测时间源与提议值偏差不
超过最新 certified `max_clock_skew`、且不早于上一 head 时 ack。邀请/提案/证书在**提交时**按该
逻辑时间校验；接收者还要按本地可信墙钟和同一偏差上限再次校验有效期。时间源不可信时，
节点不得批准新邀请、证书或租约，但可以读取旧状态并维持 LKG。

首版 `max_clock_skew_seconds` 是 HeadEntry/QC 必签的 0..300 整数秒；不能用浮点、duration 字符串或
本地默认值。未入网客户端在下载 catalog/proof 和建立 tunnel 前使用 descriptor context 中的值，
但仍硬截断到 300 秒；下载后必须确认它等于 certified base/record head，不等即拒绝并且不发送
capability 或 token。

租约同时绑定 Raft term/log index 和有界墙钟期限；executor 必须在 deadline 前预留
`max_clock_skew + request_timeout` 安全裕量，跨过安全截止即停止发新请求。墙钟只帮助停止
旧 executor，不能替代 provider CAS 或本地 generation fencing，具体限制见 [外部副作用与租约](reconciliation-ui.md#外部副作用与租约)。

---

## 写入、读取与分区行为

### 写路径

```text
admin → 已信 private ControlServiceDirectory 中的任一 overlay control_api
      → 验 internal CA、overlay IP SAN/固定 SPKI、admin cert、权限、request id、expected head
      → 本地保存并 CRDT 广播 proposal
      → leader/协调者选择 parent，所有 voter 独立校验
      → Raft durable commit
      → apply/recompute，quorum attestation 形成 certified head/QC
      → 返回 certified epoch/revision/hash/QC
      → immutable-artifact renderer、publisher、reconciler 分别收敛
```

接受请求的 control 不必是 leader；它可经 control peer mTLS 转发，也可返回稳定 operation ID
让客户端轮询。该转发不经过公网 forward server 或 Nginx。
同步成功的 HTTP `200/201` 只能表示已经取得 QC。仅写入本地/CRDT 时显示 `pending`；已经
Raft commit 但尚未收齐 attestation 时显示 `committed_not_certified`，可用 `202 + operation ID`
轮询，但不得声称已生效。无法形成 quorum 返回可重试错误，不能把少数派草稿包装成“稍后会发布”。

所有写 API 携带 `expected {epoch, revision, head_hash}`。陈旧页面得到 conflict，并拿到
当前 head；服务端不能自动把旧表单套到新状态。多份不冲突草稿也必须在一个确定性提案中
提交，不能依赖不同副本的文件锁。

### 读路径

任何 control 副本都可以返回：

- 本地已验证的最新 certified head 和 QC，以及另行标识的 `committed_not_certified` 诊断状态；
- 该 head 的 materialized SSOT/view；
- CRDT 观测及其来源、新鲜度和覆盖范围；
- 本地 reconcile/applied 进度。

响应必须标明 `committed`、`observed_at` 和本副本是否已追上已知 quorum。读到较旧但仍有
合法 QC 的 certified 状态可以展示为 stale；涉及创建邀请、读取秘密、撤权判定或写前置条件时必须做
线性化读取，落后副本应转发或拒绝，不能凭本地旧状态授权。

### 分区

- 拥有 quorum 的一侧可以继续 commit/certify；少数派只能读旧 certified state、收集观测和草稿。
- 两侧都不能按“当前在线成员”重新计算门槛。
- Device 继续运行 last-known-good；本地 Direct/Auto/指定出口偏好仍可切换，但不扩权。
- 分区恢复后，CRDT 材料自动合并；只有 QC 链上的状态进入 effective SSOT。
- 同一 `(epoch, revision)` 出现不同 hash/QC 是安全事件，客户端和 publisher 全部 fail closed。

---
