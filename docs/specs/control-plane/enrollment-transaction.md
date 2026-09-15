# Enrollment TLS、claim 与事务完成

[文档地图](../../README.md) · [架构入口](../../design.md) · [控制面规范](../../distributed-control-plane.md) · [实现对照](../../implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

### 11.4 内层 TLS、token、Keystore PoP 与一次性提交

第一次 Enrollment 默认使用**服务端认证的内层 TLS + token + Keystore PoP**，不要求尚不存在的
正式 Device client certificate。服务端证书必须按 PrivateEnrollmentServiceRefV1 验 internal CA、
overlay IP SAN 和/或 certified SPKI pin；不得关闭证书验证或接受任意 internal certificate。

客户端在平台安全存储内生成身份 signing key 和 wrapping key。Android 私钥必须留在 Keystore；
Windows/Linux 使用各自受保护的不可导出能力，确实无法做到时必须在平台 profile 中明确降级，
不能把导出私钥伪装成硬件保护。

~~~text
EnrollmentClaimCoreV2                  # 幂等核心；不含 token/server nonce/PoP 签名
  schema = 2, cluster_id, invite_id, request_id
  certified_invite_record_hash
  device_enrollment_intent_commitment_hash
  device_enrollment_intent_opening_hash
  accepted_device_enrollment_intent_hash
  client_platform
  base_recovery_epoch, base_control_epoch, base_control_set_hash, base_head_hash
  device_identity_public_key
  device_identity_key_profile
  wrapping_public_key
  wrapping_key_profile
  csr_der
  client_nonce

EnrollmentPoPChallengeV1
  schema = 1, cluster_id, invite_id, request_id
  enrollment_service_id
  claim_core_hash
  server_nonce                         # 每次 inner-TLS 尝试新 32-byte CSPRNG
  issued_at, expires_at

EnrollmentPoPBodyV2
  schema = 2, cluster_id, invite_id, request_id
  claim_core_hash
  token_commitment
  challenge_hash

EnrollmentClaimSubmissionV2           # 只在 inner TLS；不进 Raft/CRDT/log
  schema = 2
  token
  claim_core: EnrollmentClaimCoreV2
  challenge: EnrollmentPoPChallengeV1
  pop_body: EnrollmentPoPBodyV2
  proof_signature                      # identity key 对 exact pop_body 的 detached 签名

ClaimPrivateEvidenceV1                 # control-private replicated transaction material；不进 operation log
  schema = 1
  opening: DeviceEnrollmentIntentOpeningV1
  wrapping_public_key, wrapping_key_profile

CompletionCertificationV1             # control-private durable apply evidence
  schema = 1
  operation: exact completion operation inclusion + Head/QC/ControlSet
  device_view_envelope: same Head/QC 下的 initial active view inclusion

CompletionProjectionV1                # 与 completed transaction 同一次原子落盘
  invite_status = "consumed"
  device_status = "active"
  result_release_status = "authorized"
  invite/request/token/claim/completion hashes
  completion head/QC、Device certificate/view、result artifact、completed transaction hashes

EnrollmentAdmissionAttestationBodyV1  # 稳定；不含 challenge/signature bytes
  schema = 1, attestation_type = "enrollment_admission"
  cluster_id, invite_id, request_id
  certified_invite_record_hash
  device_enrollment_intent_commitment_hash
  device_enrollment_intent_opening_hash
  token_commitment, claim_core_hash
  identity_key_hash, wrapping_key_hash, csr_hash
  pop_verification_profile = "loom-enrollment-server-nonce-detached-v2"
  base_recovery_epoch, base_control_epoch, base_control_set_hash, base_head_hash
  admission_not_after, retry_not_after

StableEnrollmentAdmissionQCV1
  schema = 1, qc_type = "stable_enrollment_admission"
  attestation: EnrollmentAdmissionAttestationBodyV1
  signatures[]                        # ControlSet enrollment-purpose signatures
  signer_refs[]

EnrollmentClaimOperationV2            # admission-QC-authorized；operation log 不含 token 明文
  schema = 2, cluster_id, operation_id, invite_id, request_id
  certified_invite_record_hash
  device_enrollment_intent_commitment_hash, device_enrollment_intent_opening_hash
  token_commitment, claim_core_hash, admission_qc_hash
  identity_key_hash, wrapping_key_hash, csr_hash
  reserved_at, retry_not_after

EnrollmentResultArtifactV1            # control-private；completion commit 前禁止释放
  schema = 1, cluster_id, invite_id, request_id
  device_certificate_der
  initial_device_view: DeviceViewPayloadV2
  secret_artifact_refs[]               # exact typed refs；仅 device/data-plane credential 或已授权 TLS key

EnrollmentProvisionalIssuanceBodyV1    # control-private；completion 前不向 Device 释放
  schema = 1, cluster_id, invite_id, request_id
  claim_operation_hash
  reservation_head_hash, reservation_head_qc_hash
  device_certificate_hash, initial_device_view_hash, secret_artifact_refs_root
  result_artifact_hash
  device_certificate_profile_state_hash
  issuance_log_coordinate: IssuanceLogCoordinateV1

EnrollmentProvisionalIssuanceV1
  body: EnrollmentProvisionalIssuanceBodyV1
  ca_signature                         # active/fenced Device CA purpose key

EnrollmentIssuanceRegistryLeafV1
  schema = 1, claim_operation_hash, provisional_issuance_hash

EnrollmentProvisionalIssuanceOperationV1 # CA-authorized first-result CAS
  schema = 1, cluster_id, operation_id, invite_id, request_id
  expected_transaction_state_hash
  claim_operation_hash, provisional_issuance_hash
  issuance_registry_leaf: EnrollmentIssuanceRegistryLeafV1
  previous_issuance_registry_root, resulting_issuance_registry_root
  issued_at

EnrollmentApprovalAttestationBodyV2
  schema = 2, attestation_type = "enrollment_approval"
  cluster_id, invite_id, request_id
  claim_operation_hash
  provisional_issuance_operation_hash, provisional_issuance_hash
  issuance_head_hash, issuance_head_qc_hash, resulting_issuance_registry_root
  device_certificate_hash, initial_device_view_hash
  secret_artifact_refs_root, result_artifact_hash

StableEnrollmentApprovalQCV2
  schema = 2, qc_type = "stable_enrollment_approval"
  attestation: EnrollmentApprovalAttestationBodyV2
  enrollment_signatures[]
  signer_refs[]

EnrollmentCompletionOperationV2       # approval-QC-authorized
  schema = 2, cluster_id, operation_id, invite_id, request_id
  expected_transaction_state_hash
  claim_operation_hash
  provisional_issuance_operation_hash, provisional_issuance_hash
  resulting_issuance_registry_root
  enrollment_approval_qc_hash
  result_artifact_hash

EnrollmentTransactionStateV2           # reducer 输出
  schema = 2, cluster_id, invite_id, request_id
  claim_core_hash, identity_key_hash, wrapping_key_hash
  status                               # reserved | issued_provisional | completed | aborted
  claim_operation_hash
  provisional_issuance_operation_hash?, provisional_issuance_hash?
  resulting_issuance_registry_root?
  enrollment_approval_qc_hash?
  completion_operation_hash?, result_artifact_hash?
~~~

`claim_core_hash`、`challenge_hash`、admission attestation/QC、claim operation、provisional
issuance body/envelope/operation、issuance registry leaf、result artifact、approval attestation/QC、completion operation
和 transaction state 分别使用
`loom-enrollment-claim-core-v2`、`loom-enrollment-pop-challenge-v1`、
`loom-enrollment-admission-{attestation,qc}-v1`、`loom-enrollment-claim-operation-v2`、
`loom-enrollment-provisional-issuance-{body,envelope,operation}-v1`、
`loom-enrollment-issuance-registry-leaf-v1`、`loom-enrollment-result-artifact-v1`、
`loom-enrollment-approval-{attestation,qc}-v2`、
`loom-enrollment-completion-operation-v2` 和 `loom-enrollment-transaction-state-v2` domain 计算内容哈希。
issuance registry 对每个 claim operation 的唯一 first-result leaf 按 claim-operation hash bytes 排序，
使用 [§7.1](consensus.md#71-内容寻址操作) RFC 6962 tree；provisional operation 必须携与 previous root 比较后唯一可能的
resulting root，相同 claim 的另一 issuance hash 是 CAS 冲突。

`proof_signature` 精确覆盖
`frame("loom-enrollment-pop-signature-v2", JCS(EnrollmentPoPBodyV2))`，由 claim core 中的 Device
identity private key 签名。服务端在已认证 inner TLS 中为每次尝试生成新
`server_nonce`；challenge 必须未过期、service ID 等于当前 private Enrollment、core hash 相等，
且未在该 service 的有界 replay cache 中使用。`EnrollmentPoPBodyV2.challenge_hash` 必须从
exact challenge 重算。CSR subject/key、声明 public key 和 PoP key 必须逐字段一致。
token 只在已建立且验证过的内层 TLS 中发送；public ingress 只能看到外层 capability，
不能看到 intent opening、token、CSR、Device ID 或签发结果。
admission 成功后只把 exact opening 与 wrapping public-key/profile 作为 private transaction evidence
耐久复制，以便另一 control 能重验后续 secret recipient；raw token、CSR、challenge 和 PoP bytes 仍不得
进入该证据或 operation log。`wrapping_public_key` 必须重算为 claim operation 已固定的
`wrapping_key_hash`，result 中每个 Device-owned sealed secret 必须存在绑定同一 Device ID 与该 SPKI 的 recipient。

stable claim identity 是 `token_commitment + claim_core_hash`。`EnrollmentClaimCoreV2` 必须重算
intent opening/commitment，并把 opening 的 exact intent hash、客户端平台、CSR/identity/wrapping key 及
已验 base authority 固定。它不含 token、server nonce、challenge 或 detached signature，所以跨
ingress 重试可以对新 challenge 重签 PoP，而不改变幂等 identity。

预留前，当前 stable ControlSet 的每个 enrollment voter 必须在私有 peer RPC 上独立获得
token preimage 和 exact submission，验 token commitment、intent opening、core、challenge/PoP、Invite 状态/
期限及 base authority，然后对不含秘密/challenge 的同一
`EnrollmentAdmissionAttestationBodyV1` 签名。`StableEnrollmentAdmissionQCV1` 必须满足该
base ControlSet 的 q(N)，签名按 member ID/key ID 排序去重；单 ingress 的“token 对”不是
admission。稳定的 `pop_verification_profile` 表示每个 signer 已对 exact core/key 验过至少一个
仍新鲜的 server-nonce detached PoP；它不把某次可变 challenge/signature 伪装成事务 identity。
`admission_not_after` 必须精确等于 certified Invite 的 `expires_at`；只有 Invite 仍为 available、
未 revoked 且 reservation commit logical time 不晚于该值时，admission QC 才能授权首次 CAS。
`retry_not_after` 必须精确等于
`checked_add(admission_not_after, InviteIssuancePolicyV2.maximum_reservation_retry_seconds)`，因此可晚于
Invite expiry，但只属于已 certified reservation。每个 voter 在签名前、reducer 在 apply 时都按
exact certified record/policy 重算两个值并做 checked arithmetic；leader 不能自选或延长。
claim operation 只引用 exact `admission_qc_hash`，其 `retry_not_after` 必须逐字节等于 admission
attestation 的值；它不把 token 或可变 detached PoP 写入日志。

ControlSet 对 claim 执行以下唯一顺序：

~~~text
available Invite + matching opening/token + valid detached PoP
  → stable enrollment quorum signs exact admission attestation
  → admission QC authorizes one claim-core reservation CAS
  → Raft commit/apply/QC reservation head (Invite remains reserved, Device inactive)
  → active/fenced CA creates exact provisional certificate/view/artifacts
  → CA-authorized provisional-issuance operation performs issuance-registry first-result CAS
  → Raft commit/apply/QC issuance head (nothing released to Device)
  → stable enrollment quorum verifies issuance/profile/registry/head and signs approval QC
  → approval-QC-authorized completion operation commits/applies/gets config QC
  → atomically consume Invite, activate Membership/view, authorize exact artifact release
~~~

CA signature 覆盖 exact `EnrollmentProvisionalIssuanceBodyV1`，其 profile state 必须在 reservation
和 issuance 时都 active、未过 issuance cutoff 且 fencing epoch 相等。provisional operation 只有在
reservation head/QC、transaction state、claim operation 和 registry previous root 全部相等时才可 CAS。
`StableEnrollmentApprovalQCV2` 必须满足 issuance head 的 stable ControlSet q(N)，逐字节绑定
provisional issuance/operation、registry root、certificate、view、secret refs 和 result artifact；config head QC
不能替代 admission/approval QC，三者也不能互换用途。
approval peer RPC 只发送稳定 attestation；每个 voter 必须从本机线性化的 replicated private state
取得上述完整 preimage、operation inclusion proof、Head/QC、两时点 CA registry 与 registry previous-root
preimage，全部独立重算后才用自己的 enrollment-purpose key 签名。leader 携带的裸 hash 或私有制品副本
不能替代 voter 的本地读取。
completion operation ID 必须从 exact transaction 与 approval QC 确定性派生，换 leader 后不能另选号。
completion reducer 必须同时验证 operation inclusion 与 initial active Device view inclusion 指向同一份
certified Head；随后把 Invite=`consumed`、Device=`active`、artifact release=`authorized` 和 completed
transaction 一次原子落盘。`reserved`/`issued_provisional` 响应禁止携 artifact；只有上述原子写成功后，
private claim 响应才可返回由 `result_artifact_hash` 锁定的 exact `EnrollmentResultArtifactV1`。
`completed` 响应还必须携 canonical `EnrollmentCompletionReceiptV1`：从客户端已验 Invite Head 开始的
reservation/issuance/completion Head lineage、三类 QC、各 operation inclusion、CA profile、同 Head
Device view proof 与原子 completion projection 必须齐全。客户端用本机 stable claim/core/key 重放 reducer，
验证正式证书及 sealed recipient 后才能安装；只有 artifact 而没有 receipt 必须失败关闭。

生产 Coordinator 不接受只返回 operation ID、逻辑时间或裸 Raft ack 的 planner。reservation、issuance
和 completion 每一步都必须返回并耐久保存 exact operation leaf、累计树 inclusion path、Head、config QC
及该步使用的 stable ControlSet；相邻阶段若隔着其他 data-bearing Head，还必须保存完整 Head lineage，
Raft no-op 只体现在 index/previous-log hash 中。稳定 sequencer 在清除 active Head 前先按 operation ID
耐久写入 certified first-result journal，因此 commit/apply/QC 后但 transaction CAS 或响应前崩溃时，
新 executor 只能恢复同一份结果，不能重新选号、重新签发或追加第二份 operation。
若 lineage 跨过 `control_set_final`，还必须逐个携带并验证完整 Joint→Final transition bundle；approval
仍由 issuance Head 的 stable ControlSet 形成，而 completion operation/config QC 使用完成时的当前 stable
ControlSet。不得要求两者相同，也不得仅凭新集合自签的后续 Head 跳过 membership transition proof。
CA/result preparer 也必须在提交 provisional operation 前，以确定性 operation ID、完整 reserved
transaction hash 和 sequencer coordinate 为键耐久冻结 first-result；进程重启只能返回同一证书、
初始 view 与密封 secret refs，不能再次调用签发器生成另一份候选。

同一 token 的合法自动重试必须复用完全相同的 claim core，因而 request ID、CSR、
identity/wrapping keys、client nonce、intent opening 和 base authority 全部不变；只允许 server
nonce/challenge 和 detached PoP signature 随尝试改变。自动重试仍受 Invite/capability 期限限制。
超时 reservation/issuance 只可按 certified policy 恢复或 abort，不能由单副本本地释放或改写
registry root。resume capability 到达时，private Enrollment 先按 binding 读取现有 transaction：
completed 直接返回既有 result artifact，reserved/issued_provisional 只继续同一事务，aborted 拒绝；
三者都不把 token 再做一次 available→reserved CAS。并发不同 core 只有一个能完成
reservation CAS，失败者不得获知胜者的 Device 材料。

QR 被复制后的主要风险是抢先消费。默认流程依靠高熵 token、短 capability、PoP 与管理员撤销；
高安全环境可增加“管理员反向扫描设备公钥并提交 Invite binding”的显式模式。不得把可复制的
临时客户端私钥塞进二维码。若合规规则强制首个业务请求使用 mTLS，可在 token+PoP 验证后签发
invite-scoped 临时 client cert，再进行第二阶段事务；它不是默认流程，也绝不能称为正式 Device
identity。
