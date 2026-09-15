# 信任域、管理员与 CA

[文档地图](../../README.md) · [架构入口](../../architecture/README.md) · [控制面规范](README.md) · [实现对照](../../development/implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

## 信任域与密钥

| 信任域 | 持有者 | 用途 | 明确不能做什么 |
|---|---|---|---|
| recovery root | 离线介质/可选多人门槛 | genesis、失去 quorum 后签新 recovery epoch | 日常发布、在线 API |
| control membership key | 每个 voter | ControlSet 联合迁移 | 签普通配置或 Device 报告 |
| control config key | 每个 voter | 对 committed head/view 投票签名 | 充当公开 TLS 或 admin 身份 |
| control enrollment key | 每个 voter | 对已提交 claim/CSR 作独立 Enrollment approval | 独自签发成员资格或替代 config QC |
| bootstrap issuer key | ControlSet 授权的有界 signer | 从已提交 Invite 派生短期 bootstrap tunnel capability | 签正式 Device 身份或扩大 capability ACL |
| control peer cert | control Device | overlay 内控制复制、选举、内部 RPC mTLS | 自动获得人类 admin 权限或公开服务 |
| admin cert | 人类/自动化管理员 | 通过私有 overlay control API 提交有范围的操作 | 参与 controller quorum或访问公网管理入口 |
| Device identity cert | 每台 Device | 报告、配置读取、节点声明 | 管理 SSOT 或成为 voter |
| internal CA | 离线根 + 受约束在线中间 CA | 签 control/admin/Device profile | 配置发布投票 |
| public WebPKI cert | active forward server | Nginx/Hysteria2/Trojan 传输身份 | Enrollment 应用认证、成员资格、配置真实性 |
| application code-signing key | 发布流水线 | APK/MSI/EXE 来源与升级连续性 | 签 SSOT 或 Enrollment |

不同证书 profile 使用不同 EKU、SAN、issuer policy 和私钥。Control peer、admin、Device 与
Enrollment 服务的 key 必须彼此隔离，也不得复用公开 TLS key。Nginx/HY2/Trojan 的公网 listener
始终分别建模；同一 FQDN 可出现在多个 listener，推荐分别持钥。若受限实现共享同一 public
WebPKI cert/key，每个 transport profile 必须显式引用同一 exact artifact 并共同轮换，不能靠本地
文件名暗中复用。验证器不得再用
`ExtKeyUsageAny` 把角色边界抹平。公开 ACME 证书本身不是配置 authority；但服务端 TLS
SPKI 发生变化时，必须先通过 quorum 把新旧 pin overlap 写入 EndpointSet/邀请 checkpoint，
不能把普通 WebPKI 续签当成静默替换服务身份。客户端同时验证 hostname/WebPKI、签名端点
中的身份 pin 和配置 QC。私有 control/Enrollment 服务使用 internal CA 与 overlay IP SAN
（或经 certified directory 绑定的固定 SPKI），不得关闭 hostname/IP 验证来迁就 IP URL。

每个 voter 持有独立 Ed25519 密钥。首版 quorum certificate 保留按 `signer_id` 排序的
多份普通签名，便于 Go、Android 和 Windows 审计；阈值/聚合签名可以后置，不能改变签名
对象或门槛语义。ControlSet 的 membership/config/enrollment 三类签名（包括 head QC、成员审批、
key PoP、token validation 与 enrollment approval）wire 一律为 raw 64-byte Ed25519、无 padding
base64url；每项 key ID 必须等于所指 member 对应 purpose key。未知算法、其他编码/长度、重复 signer
或跨 purpose key 全部失败关闭。

```text
ControlMembershipSignatureV1
  algorithm = "ed25519", member_id, membership_key_id, signature

ControlConfigSignatureV1
  algorithm = "ed25519", member_id, config_key_id, signature

ControlEnrollmentSignatureV1
  algorithm = "ed25519", member_id, enrollment_key_id, signature

ControlKeyPossessionSignatureV1
  algorithm = "ed25519", member_id, key_purpose, key_id, signature
```

上述 `signature` 都是精确 raw64 的无 padding base64url。所有 signer-ref 是相应 signature 对象删除
`algorithm/signature` 后的逐字段投影；签名对象、ref 与 ControlSet member 必须按用途逐字段相等。
`ControlKeyPossessionSignatureV1` 还必须等于其 proof body 的 member/purpose/key ID。任何只携裸签名字节、
省略算法或依赖调用方猜 key purpose 的替代 wire 都不合法。

### 初始 admin/CA 与轮换

bootstrap ceremony 一次性建立 recovery anchor、初始 admin ACL、证书 profile、第一张有界
admin 证书和 online intermediate 的公开材料；这些摘要全部进入 genesis/迁移对象。第一张
admin 证书由 ceremony 明确授权，不依赖尚未存在的 admin ACL，之后任何 admin/issuer 变更
都走正常 quorum 提交。recovery 私钥、CA 根私钥和各 Device/TLS 私钥不进入 SSOT。

online intermediate 轮换使用 `stage → issue/verify → overlap → revoke old`：先提交新 issuer
公钥/profile 和 CSR approval，再由持租约的 issuer executor 签发；足够 reader 接受新链后
才提交旧 issuer 的撤销与 CRL/registry 水位。admin key replacement 同样先增加新主体、验证
持钥，再撤旧主体，禁止用节点本地运维 cookie 绕过 ACL。

`admin_acl_root`、`ca_profile_root` 与 `bootstrap_issuer_registry_root` 不是 opaque 本地数据库摘要。
首个 v2 profile 固定以下 exact
preimage；它们只在 control-private/operator API 复制，公开 head/recovery/bootstrap 仅携 roots：

```text
AdminResourceScopeV1                    # exact tagged union
  scope_kind                            # cluster | device | endpoint | managed_zone |
                                        # control_membership | recovery_policy | ca_profile
  cluster?                              # exact empty object
  device?                               # {device_ids[]}，按 UTF-8 bytes 排序
  endpoint?                             # {endpoint_ids[]}，按 UTF-8 bytes 排序
  managed_zone?                         # {zone_ids[]}，按 UTF-8 bytes 排序
  control_membership?                   # exact empty object
  recovery_policy?                      # exact empty object
  ca_profile?                           # {profile_ids[]}，按 UTF-8 bytes 排序

AdminCertificateProfileRefV1
  profile_id, generation, admin_certificate_profile_hash

AdminCertificateProfileV1
  schema = 1, cluster_id, profile_id, generation
  issuer_chain_der[], admin_issuer_chain_hash
  subject_key_algorithm = "p256"          # 既有历史 profile 可为 ed25519
  operation_signature_algorithm = "ecdsa-p256-sha256" # 历史 ed25519 与 subject 配对
  required_eku_oids[], required_policy_oids[]
  maximum_validity_seconds

AdminAuthorizationV1
  schema = 1, cluster_id, authorization_id, generation
  previous_authorization_hash?
  admin_id, admin_certificate_der, admin_certificate_digest, admin_key_id
  certificate_profile_ref: AdminCertificateProfileRefV1
  not_before, not_after, status            # active | revoked
  allowed_operation_kinds[]                # 按 UTF-8 bytes 排序去重
  capabilities[]                           # manage_admin_acl | manage_ca_profiles，enum 顺序
  scopes[]                                 # 按 admin_resource_scope_hash bytes 排序去重

AdminACLLeafV1
  schema = 1, authorization_id, generation, admin_authorization_hash

CAProfileRegistryLeafV1                    # exact tagged union
  profile_kind                             # admin_certificate | device_certificate
  profile_id, generation, profile_hash

AuthorityRegistryPrivateObjectV1
  schema = 1, cluster_id
  admin_authorizations[]                   # 每 ID 最新代，按 authorization_id 排序
  admin_acl_root
  admin_certificate_profiles[]             # 按 profile_id 排序
  device_certificate_profile_states[]      # DeviceCertificateProfileStateV1，按 profile_id 排序
  ca_profile_root
  bootstrap_issuer_authorizations[]        # 每 authorization_id 最新代，按 ID 排序
  bootstrap_issuer_registry_root

DeviceCertificateProfileRefV1
  profile_id, generation
  device_certificate_profile_intent_hash, device_certificate_profile_state_hash

IssuanceLogCoordinateV1
  recovery_epoch, raft_index

DeviceCertificateProfileIntentV1
  schema = 1, cluster_id, profile_id, generation
  expected_previous_profile_state_hash?
  target_status                            # staged | active | retired | revoked
  issuer_id, issuer_generation, issuer_fencing_epoch
  issuance_not_before, issuance_not_after
  revocation_reason?                       # issuer_compromise | administrative
  profile_kind = "loom-device-x509-v1"
  issuer_certificate_der, issuer_certificate_hash
  issuer_chain_der[], issuer_chain_hash, issuer_key_artifact_hash
  allowed_platforms[], allowed_responsibilities[]
  validity_seconds, allowed_subject_key_algorithm = "p256"
  signature_algorithm = "ed25519", subject_mode = "empty"
  san_uri_prefix, key_usage_bits[]
  basic_constraints_ca = false
  required_eku_oids[], required_policy_oids[], extension_order_oids[]

DeviceCertificateProfileStateV1
  schema = 1, cluster_id, profile_id, generation
  profile_intent: DeviceCertificateProfileIntentV1
  device_certificate_profile_intent_hash
  status, status_changed_at
  issuance_cutoff?                         # terminal state 必需
```

摘要固定为：

```text
admin_resource_scope_hash = H(frame(
  "loom-admin-resource-scope-v1", JCS(AdminResourceScopeV1)
))
admin_certificate_profile_hash = H(frame(
  "loom-admin-certificate-profile-v1", JCS(AdminCertificateProfileV1)
))
admin_authorization_hash = H(frame(
  "loom-admin-authorization-v1", JCS(AdminAuthorizationV1)
))
device_certificate_profile_intent_hash = H(frame(
  "loom-device-certificate-profile-intent-v1", JCS(DeviceCertificateProfileIntentV1)
))
device_certificate_profile_state_hash = H(frame(
  "loom-device-certificate-profile-state-v1", JCS(DeviceCertificateProfileStateV1)
))
device_issuer_certificate_hash = H(frame(
  "loom-device-issuer-certificate-der-v1", raw_issuer_certificate_der
))
device_issuer_chain_hash = H(frame(
  "loom-device-issuer-chain-v1", JCS({schema:1,issuer_chain_der})
))
device_certificate_hash = H(frame(
  "loom-device-certificate-der-v1", raw_device_certificate_der
))
authority_registry_private_object_hash = H(frame(
  "loom-authority-registry-private-object-v1", JCS(AuthorityRegistryPrivateObjectV1)
))
```

`admin_acl_root` 对每个最新 `AdminAuthorizationV1` 重算 `AdminACLLeafV1`，按 authorization ID 排序并
使用 [内容寻址操作](consensus.md#内容寻址操作) RFC 6962 tree；`ca_profile_root` 对两类 profile 重算
`CAProfileRegistryLeafV1`，按 `(profile_kind enum,profile_id)` 排序使用同一 tree。profile 内 DER chain
从 issuing intermediate 到 anchor 排序，`admin_issuer_chain_hash=H(frame("loom-admin-issuer-chain-v1",`
`JCS({schema:1,issuer_chain_der})))`；证书 digest 是
`H(frame("loom-admin-certificate-der-v1",raw_der))`，key ID 从 leaf DER SPKI 重算。所有 refs、leaf、
roots 与 private object 都由 exact bytes 重算，不能从裸 ID 或本机 trust store恢复。
[Bootstrap tunnel capability](bootstrap-capability.md#bootstrap-tunnel-capability) 的 `bootstrap_issuer_registry_root` 对每个 authorization ID 的最新代
`BootstrapIssuerAuthorizationLeafV1` 按 ID 排序使用同一 tree；active/revoked 代均必须进 root，
不得通过删除 leaf 隐藏撤销。
其中 admin leaf 的 `profile_hash` 是 `admin_certificate_profile_hash`；Device leaf 的 `profile_hash`
是 reducer 派生的 `device_certificate_profile_state_hash`，并由 state 内嵌 intent 重算另一层 intent
hash。两个 variant 不得互换摘要 domain。

AdminAuthorization 同 ID generation 从 1 连续递增；首代无 previous，后续必须指向前代 hash。
`revoked` 必须保留前代 cert/profile/permissions/capabilities/scopes bytes且不可回到 active；active cert 必须按 exact
profile 验链/validity/EKU/OID，并要求 leaf SPKI 与 profile 的 subject 算法一致。新管理员使用 P-256
leaf 与 P-256 issuer，证书签名为 ECDSA/SHA-256；历史 Ed25519 profile 继续验证。admin key ID 固定为
leaf DER SPKI 的小写 `sha256:` digest；P-256 operation signature 为 SHA-256(frame) 上的 low-S raw
`r || s` 64 bytes，历史 Ed25519 为 raw 64 bytes。未知或不配对的 subject/signature
算法、非规范 key ID 或其他签名字节编码全部失败关闭。`scopes` tag 与唯一 variant 一致、数组非空
（cluster exact-empty 除外）。
校验 `ControlOperationV1` 时，从其 base head 的 private registry 解出唯一 active authorization，要求
author/key/cert digest、可信时间、allowed kind 与 payload 的 exact resource scope 同时满足；new head
里的 ACL 不能倒过来授权自己的 mutation。

当前 N=1 runtime 的 `local_admin_certificate_rotation` 是单独的本机维护仪式：控制进程已停止，
操作者独占 root-only 状态目录，出示当前 active 管理员私钥，下一 key 签署同一轮换内容作为 PoP。
它仅允许同一管理员的 active → active 连续换证，权限与授权截止不变，旧 profile/authorization
作为签名 preimage 留存；它不属于网络 API 的 allowed-kind 扩展，也不复用仅接受撤销的 successor
校验。新 ACL 仍须正常 Raft commit/apply/QC 后才能生效。该运行时维护路径不替代多成员的正式
admin/profile 变更 reducer。

`DeviceCertificateProfileIntentV1` 同 ID generation 从 1 连续递增，后代的
`expected_previous_profile_state_hash` 必须等于直接前代 state。后代唯一允许变化的字段是
`generation`、`expected_previous_profile_state_hash`、`target_status`、`issuer_fencing_epoch` 与
`revocation_reason`；cluster/profile ID、issuer ID/generation、key artifact、适用平台/职责、issuance
window、有效期及全部 X.509 profile bytes 必须逐字节不变。非 bootstrap profile 首代只能以
`target_status=staged` 创建，合法单向边只有
`staged→active→retired|revoked` 或 `staged→revoked`；`retired/revoked` 都是 registry 的 terminal
tombstone，不能恢复。bootstrap 可直接建立 active 首代。管理员只签可预先构造的 intent；reducer
用实际承载 Head 的坐标确定性派生 `DeviceCertificateProfileStateV1.status_changed_at` 和 terminal
`issuance_cutoff`，二者不得出现在 admin-signed payload 中或由管理员猜测。这样 Raft 在 proposal
之后分配的 index/time 不会反向进入管理员签名。
state 内嵌 intent 必须逐字节等于 operation payload，intent hash 重算相等；state 的 cluster/profile
ID/generation 与 intent 相等，`status == intent.target_status`。可选 cutoff/reason 的出现规则按本段
严格校验，不能由 reducer保留发送方附加字段。

`issuance_not_before < issuance_not_after`，active 只能在该半开区间内签新证。terminal state 的
`issuance_cutoff` 必须等于 `{recovery_epoch=head.recovery_epoch, raft_index=head.raft_index-1}`；其他
状态必须缺失。坐标只在由 recovery statement 连续证明的 lineage 中按 recovery epoch、再按 Raft
index 比较，不能只比较裸 index；新 recovery epoch 导入的历史 issuance 因而不会被重置为 1 的
index 误判。`retired` 只停止新签发；只有 issuance coordinate 不晚于 cutoff、且 approval
attestation 的 `approved_at < status_changed_at` 的既有证书才按自身有效期继续。
`revoked` 表示 issuer 安全撤销，验证
Device 身份时必须按最新 certified registry 拒绝该 issuer/profile 已签的证书。revoked 必须带 reason，
其他状态必须缺失。

`issuer_fencing_epoch` 在同一 `(issuer_id,issuer_generation,profile_id)` lineage 内严格递增，任一
stage/activate/retire/revoke 都提高它；若 reason=`issuer_compromise`，同一 head 必须把引用相同
`(issuer_id,issuer_generation)` 的所有非终态 profile 一并变为 revoked。CA executor 的租约和
key-unseal authorization 必须绑定 exact
`(issuer_id,issuer_generation,issuer_fencing_epoch,device_certificate_profile_state_hash)`。同一 issuer 的旧
fence 即使仍能产生密码学签名，也不得产生 cutoff 后的新 issuance、为尚未 approval 的 claim 补签
或创建新 Device；retired 前已满足上述 cutoff/approval 条件的证书仍可验证，只有 revoked 会使该
issuer/profile 的既有证书失效。多个
profile 可以同时 active 以完成 overlap，但 enrollment intent 必须显式引用其中一份 exact ref，不能
由 leader 按“最合适”选择。`allowed_platforms[]` 按 [Invite、catalog 与紧凑二维码](enrollment-invite.md#invitecatalog-与紧凑二维码) platform enum、
`allowed_responsibilities[]` 按 responsibility enum 排序去重且非空；引用者必须全部落在其 scope。

任一 stage/activate commit 都必须先严格解析 issuer material：`issuer_chain_der[]` 非空、
`issuer_chain_der[0] == issuer_certificate_der`，逐张 strict DER 从 online intermediate 验签到数组最后
一张 self-signed anchor；每张 CA 都必须 `BasicConstraints CA=true`，中间/anchor KeyUsage 含
`keyCertSign`，不得有未知 critical extension。issuer certificate/SPKI 固定为 Ed25519，certificate
signature chain 与 validity 必须有效，且 issuer validity 覆盖整个 issuance window 加
`validity_seconds` 的 checked upper bound；certificate/chain hashes 从 exact bytes 重算。数组最后的
anchor 就是该 profile 冻结的 trust anchor，不读取本机 trust store。
`issuer_key_artifact_hash` 必须解析到 [权威 secret artifact](secret-artifacts.md#权威-secret-artifact) purpose=`ca_private_key` 的 exact ref，owner/issuer executor
scope 相符，`public_key` 为 Ed25519 且 SPKI 逐字节等于 issuer certificate，PoP/availability 与
key-unseal fence 均通过；active transition 必须在 candidate time 下重新验证同一 exact
PoP/availability/fence，而不能沿用 staged 时的 mutable provider alias。任何一项不满足都不能形成 staged/active state，避免 registry 认证一份
永远无法签发的 profile。

普通变更的 outer kind 固定为 `upsert_admin_authorization`、`revoke_admin_authorization`、
`upsert_admin_certificate_profile` 或 `upsert_device_certificate_profile`，payload/hash 分别使用上式或
上文 `device_certificate_profile_intent_hash`；调用者在 base ACL 中还必须具有
对应 capability、outer kind 及 matching scope。reducer 以 expected previous
state hash 做 CAS，以 candidate Head 的 committed time/recovery epoch/Raft index 派生 profile state，
选择每 ID 最新代并重算两个 root；同一 head 内先按 operation ID 应用全部已授权操作，再计算 root。
bootstrap/emergency 的 `initial_admin_acl_hash` 与
`internal_ca_profile_and_anchor_hash` 精确解释为这两个 root：新 voters 必须在 Genesis durable
install 前私下取得 matching `AuthorityRegistryPrivateObjectV1` 并重算；public bundle仍只携 root。
planned recovery 与 ControlSet Final 按前文继承 registry bytes/roots。缺 preimage 的副本可验证公开
head QC，但不能投票、验证 admin write 或执行 CA。
