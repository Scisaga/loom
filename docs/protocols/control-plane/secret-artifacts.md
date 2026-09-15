# 权威 secret artifact

[文档地图](../../README.md) · [架构入口](../../architecture/README.md) · [控制面规范](README.md) · [实现对照](../../development/implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---


邀请 token、Device/数据面凭据、TLS/CA/provider key 等 authority-bearing secret 必须在引用
它的 proposal **提交前只生成一次**。当前交付使用本地软件密钥和不可覆盖的 `sealed_blob`，
不依赖 KMS/HSM。密钥目录权限为 `0700`、私钥文件为 `0600`，仅所属服务账号或 root 可读；
软件密钥可在签发进程内使用，不能声称不可导出。需要备份或授权接管的密钥按下表接收者范围
加密封装，日志只记录引用与证明；本地可覆盖 PEM 路径本身不能充当 certified immutable ref。

KMS/HSM 强化单列为[后续扩展计划](../../proposals/key-protection.md)，不是当前实现、部署或验收门禁。
下列 wire 保留 `kms_or_hardware_key` variant 的严格解析边界；能验证该格式不表示已经接入托管
服务，当前没有任何 purpose 必须选择它。Device/Android 已有的本地 Keystore 边界仍按各自 profile 执行。

```text
SecretArtifactRefV2
  schema = 2, cluster_id, proposal_id, secret_id, purpose, owner: SecretArtifactOwnerV1, generation
  public_key?: AuthorityProofKeyV1, immutable_ref
  backend_kind           # sealed_blob | kms_or_hardware_key；exact tagged union
  sealed_blob?: SealedBlobRefV1
  kms_or_hardware_key?     # provider/object_id, exact_version, policy_hash
  possession_proof_hash?, availability_policy_hash, availability_receipts_root

SealingPolicyV1                         # exact tagged union；只接受下文三个 canonical object
  schema = 1, policy_id, generation = 1
  recipient_key_profile
  plaintext_format = "jcs-sealed-secret-plaintext-v1"
  content_aead = "aes-256-gcm", cek_bytes = 32, content_nonce_bytes = 12, tag_bytes = 16
  key_wrap_kind                          # p256_ecdh | rsa_oaep
  p256_ecdh?                             # {curve="p256",shared_secret="x-coordinate-be32",
                                          #  kdf="hkdf-sha256",salt_profile="context-sha256-v1",
                                          #  info_profile="recipient-context-frame-v1",
                                          #  wrap_aead="aes-256-gcm",wrap_nonce_bytes=12}
  rsa_oaep?                              # {modulus_bits=2048,public_exponent=65537,
                                          #  digest="sha256",mgf1_digest="sha1",label="empty"}

SealedBlobRecipientKeyRefV1
  recipient_id, recipient_key_generation, recipient_key_id, recipient_key_profile
  recipient_public_key: AuthorityProofKeyV1

SealedBlobRefV1
  ciphertext_digest                     # 必须等于 sealed_secret_envelope_hash
  sealing_policy: SealingPolicyV1, sealing_policy_hash
  recipient_key_versions[]              # SealedBlobRecipientKeyRefV1，按下文排序

SealedSecretContextV1
  schema = 1, cluster_id, proposal_id, secret_id, purpose, owner: SecretArtifactOwnerV1, generation
  sealing_policy_hash, recipient_set_hash

SealedSecretPlaintextV1
  schema = 1, context: SealedSecretContextV1
  secret_bytes                           # raw secret 的无 padding base64url

SealedSecretRecipientEnvelopeV1          # exact tagged union
  recipient_key: SealedBlobRecipientKeyRefV1
  key_wrap_kind                          # p256_ecdh | rsa_oaep；必须等于 policy
  p256_ecdh?                             # {ephemeral_spki_der,ephemeral_spki_hash,
                                          #  wrap_nonce,wrapped_cek_and_tag}
  rsa_oaep?                              # {wrapped_cek}

SealedSecretEnvelopeV1
  schema = 1, context: SealedSecretContextV1
  content_nonce, ciphertext_and_tag
  recipient_envelopes[]                 # 与 recipient refs 一一对应、同序

SecretPossessionProofBodyV1
  schema = 1, cluster_id, proposal_id, secret_id, generation
  purpose, owner: SecretArtifactOwnerV1, immutable_ref, public_key: AuthorityProofKeyV1

SecretArtifactOwnerV1                    # exact tagged union
  kind                                   # device | recovery_policy
  device?                                # {device_id}
  recovery_policy?                       # {policy_id,policy_generation,key_id}

AuthorityProofKeyV1                    # strict DER SPKI；exact algorithm profile
  algorithm                            # ed25519 | ecdsa-p256-sha256 |
                                       # rsa2048-pkcs1v15-sha256
  public_key_spki_der, key_id           # SPKI 为无 padding base64url

AuthorityProofSignatureV1
  algorithm, key_id                    # 必须等于对应 AuthorityProofKeyV1
  signature                            # 无 padding base64url：Ed25519 raw64 | P-256 low-S raw r||s64 |
                                       # RSA raw256

SecretPossessionProofV1
  body: SecretPossessionProofBodyV1
  proof_signature: AuthorityProofSignatureV1

ArtifactAvailabilityReporterRefV1
  reporter_id, reporter_key: AuthorityProofKeyV1, fault_domain, allowed_purposes[]

ArtifactAvailabilityPolicyV1
  schema = 1, cluster_id, policy_id, generation
  required_receipt_count, required_fault_domain_count, max_receipt_age_seconds
  reporters[]                         # 按 reporter_id 排序去重

ArtifactAvailabilityReceiptBodyV1
  schema = 1, cluster_id, proposal_id, secret_id, generation
  purpose, immutable_ref, artifact_or_version_digest
  reporter_id, recipient_key_ref?: SealedBlobRecipientKeyRefV1, observed_at

ArtifactAvailabilityReceiptV1
  body: ArtifactAvailabilityReceiptBodyV1
  reporter_signature: AuthorityProofSignatureV1

ArtifactAvailabilityReceiptLeafV1
  schema = 1, reporter_id, receipt_hash
```

`backend_kind` 必须与恰好一个同名 variant 对应，另一个必须缺失；`sealed_blob` 与
`kms_or_hardware_key` 是互斥 union。`recipient_key_versions[]` 按 `(recipient_id UTF-8 bytes,
recipient_key_generation,recipient_key_id bytes)` 排序去重且非空，envelope 数组必须逐字段投影同一
refs 且同序。当前引用必须指向不可覆盖 blob；预留 provider version 的扩展约束见独立计划。
`latest`、可变 alias、可覆盖文件路径和仅靠进程内缓存的 handle 均不合法。
软件及非导出私钥都提交 exact `AuthorityProofKeyV1`、精确 key version 和 domain-separated
`SecretPossessionProofV1`，并覆盖 cluster/proposal/secret/purpose/owner/generation、公开 key
和 immutable ref，禁止把另一用途或 proposal 的 PoP 搬来复用；TLS 终止节点先生成 key/CSR，
再提交 SPKI、CSR hash 和本机 availability
receipt。sealed credential 按已提交的 recipient key version 分别封装，日志与 CRDT 只含
ciphertext hash/ref，绝不含 plaintext。

只接受三个逐字段固定的 `SealingPolicyV1`：

| policy_id / recipient_key_profile | key_wrap variant | 用途 |
|---|---|---|
| `sealed-p256-v1` / `p256-keystore-ecdh-v1` | 上式 `p256_ecdh` 全部 literal | Android API 31+ 可用的不可导出、仅 ECDH P-256 wrapping key |
| `sealed-p256-root-only-v1` / `p256-root-only-pkcs8-ecdh-v1` | 同一 `p256_ecdh` 算法与 literal，独立 policy/profile/hash | Linux Device 与软件 executor 的本地 P-256 wrapping key，受保护 PKCS#8 文件；不声称硬件或不可导出 |
| `sealed-rsa2048-v1` / `rsa2048-keystore-decrypt-v1` | 上式 `rsa_oaep` 全部 literal | Android API 26–30 的不可导出、仅解密 fallback |

表中未选 variant 必须缺失；所有共同字段必须等于 schema 中的 literal，不能用 provider 默认值改写。
`sealing_policy_hash=H(frame("loom-sealing-policy-v1",JCS(SealingPolicyV1)))`；profile 到 policy 是上表
一对一映射，未知 profile/policy 或错配 hash 失败关闭。RSA fallback 的 wrapping key 是独立的
Android Keystore RSA-2048 key，生成用途只含 DECRYPT；解封使用 RSA-OAEP SHA-256、MGF1-SHA-1、
空 label。它不把私钥导出到进程，也不允许充当 Device identity/signing key。P-256 profile 只允许
ECDH，且在 Android 上要求 API 31 的 `PURPOSE_AGREE_KEY`；低版本必须选择 record 已授权的 RSA
profile，不能退化为软件 ECDH。Enrollment identity 对包含 wrapping SPKI/profile 的 stable claim
core 作 PoP，wrapping key 本身不取得签名权限。

封装先生成一次 32-byte CSPRNG CEK。`recipient_set_hash=H(frame(
"loom-sealed-secret-recipient-set-v1",JCS(recipient_key_versions)))`；由 artifact 坐标、owner、policy
hash 与该 set hash 构造唯一 `SealedSecretContextV1`，`sealed_secret_context_hash=H(frame(
"loom-sealed-secret-context-v1",JCS(context)))`。content nonce 与 P-256 wrap nonce 都是分别生成的
12-byte CSPRNG 值，禁止在同一 key 下复用。payload plaintext 是严格 JCS
`SealedSecretPlaintextV1`；AES-GCM AAD 是
`frame("loom-sealed-secret-payload-aad-v1",JCS(context))`，wire 的 `ciphertext_and_tag` 是 ciphertext
紧接 16-byte tag 后无 padding base64url。

P-256 recipient 为每个 recipient 生成独立 ephemeral P-256 key；SPKI 必须是 strict DER
`id-ecPublicKey + prime256v1`，并重算
`ephemeral_spki_hash=H(frame("loom-sealed-secret-ephemeral-spki-v1",raw_ephemeral_spki_der))`；ECDH
output 是左补零到 32 bytes 的 affine x-coordinate。非规范 DER、hash 不等或曲线不符都在派生 KEK
前拒绝。
`RecipientWrapContextV1={schema:1,sealed_secret_context_hash,recipient_key,
ephemeral_spki_hash}`；HKDF salt 是
`SHA256(frame("loom-sealed-secret-hkdf-salt-v1",JCS(RecipientWrapContextV1)))`，info 是
`frame("loom-sealed-secret-kek-info-v1",JCS(RecipientWrapContextV1))`，输出 32-byte KEK。
用该 KEK、独立 wrap nonce 和 AAD
`frame("loom-sealed-secret-wrap-aad-v1",JCS(RecipientWrapContextV1))` AES-GCM 加密 CEK；
`wrapped_cek_and_tag` 同样把 16-byte tag 追加在后。RSA recipient 直接以 policy 的 exact OAEP
parameters 加密 32-byte CEK，`wrapped_cek` 必须精确为 256 bytes；其余 variant 字段必须缺失。

`sealed_secret_envelope_hash=H(frame("loom-sealed-secret-envelope-v1",JCS(SealedSecretEnvelopeV1)))`。
`immutable_ref` 取得的 canonical envelope bytes 必须重算为 `ciphertext_digest`，其 context/policy/
recipient set 又必须与 `SecretArtifactRefV2` 逐字段相等；解封后还要验证 plaintext 内嵌 context。
任何 nonce、ephemeral SPKI、recipient、tag 或 ciphertext 变化都形成另一个 envelope/hash，不能在同一
artifact ref 下覆盖。Go/Kotlin/Windows 共享正常与拒绝路径的 JCS、ECDH/HKDF/OAEP/AES-GCM
golden vectors，不能只用各自 provider round-trip 测试代替 wire 互操作。

首版 `purpose` enum 及排序固定为
`invite_token → device_credential → data_plane_credential → tls_private_key → ca_private_key →`
`dns_provider_credential → acme_account_key → acme_order_state → control_peer_identity →`
`recovery_private_key`，未知值拒绝。`owner` 的 tag 必须和唯一 variant 一致；除最后一种 purpose 外
都必须是 `device`，recovery private key 必须是 `recovery_policy`。约束表也是
normative：

| purpose | 当前交付 backend | PoP / public identity | owner 与 recipient |
|---|---|---|---|
| `invite_token` | `sealed_blob` | 二者必须缺失 | owner 为创建 principal 的 control Device；recipient 只能是 invite-delivery renderer key set |
| `device_credential` | `sealed_blob` | 私钥型必须 PoP+SPKI；纯对称凭据二者缺失 | owner 为目标 Device；sealed recipients 必须恰含该 Device 当前 wrapping key versions |
| `data_plane_credential` | `sealed_blob` | 私钥型必须 PoP+public key；对称型二者缺失 | owner 为 endpoint Device；recipients 等于 certified transport profile 的参与 Device 集合 |
| `tls_private_key` | `sealed_blob` | 必须 PoP+DER SPKI | owner/recipient 必须是终止 TLS 的 Device |
| `ca_private_key` | `sealed_blob` | 必须 PoP+DER SPKI | owner 为 certified CA executor；recipients 仅含经认证授权执行或接管该 CA 的 wrapping key versions；普通 control voter 身份不授予解封权 |
| `dns_provider_credential` | `sealed_blob` | 对称/API token 时二者缺失 | owner 为 DNS executor role；recipient scope 不得超出 ManagedZone provider adapter |
| `acme_account_key` | `sealed_blob` | 必须 PoP+public key | owner 为 ACME executor role；recipients 仅含获授权 executor 的 wrapping key versions；不得复用 TLS key |
| `acme_order_state` | `sealed_blob` | 二者必须缺失 | owner 为创建 order 的 ACME executor role；recipients 必须恰为该 certified executor pool 的 wrapping key versions |
| `control_peer_identity` | `sealed_blob` | 必须 PoP+DER SPKI | owner/recipient 必须是该 private directory member 对应 Device |
| `recovery_private_key` | `sealed_blob` | 必须 PoP+DER SPKI | owner 精确绑定 policy generation/key ID；sealed recipients 等于 custody custodian wrapping refs |

`allowed_purposes[]` 只可用此顺序的子序列。backend、PoP、identity、owner 或 recipients 与表及
引用它的 certified profile 任一不符即拒绝。未来启用其他 backend 时须通过显式 profile/版本迁移，
不能由 executor 临时切换。CA 执行者是可经认证变更的角色，不要求固定一台额外常驻签发服务；
接管仍须校验同一密钥版本、当前 fencing 与首次签发结果，不能因换执行者重新生成身份。

PoP signature 覆盖
`frame("loom-secret-possession-proof-signature-v1", JCS(SecretPossessionProofBodyV1))`；
proof key 必须逐字节等于 ref 的 `public_key`，并由它验签。
有 private-key semantics 的 purpose 必须带 PoP，纯随机 bearer/symmetric secret 必须缺失 PoP 与
public key；purpose/profile 表固定这个判断，sender 不能自选。`AuthorityProofKeyV1` 的 SPKI 必须是
strict DER：Ed25519 使用 RFC 8410 OID 且 parameters 缺失；P-256 使用 `id-ecPublicKey + prime256v1`；
RSA 使用 `rsaEncryption` + DER NULL、2048-bit modulus、exponent 65537。`key_id` 固定为
`"sha256:" + lowercase_hex(H(frame("loom-authority-proof-key-id-v1",raw_spki_der)))`。Ed25519 signature
是 raw 64 bytes；P-256 是 SHA-256 ECDSA low-S raw `r||s` 64 bytes；RSA 是
RSASSA-PKCS1-v1_5/SHA-256 raw 256 bytes。algorithm、SPKI、key ID 或长度不匹配、ECDSA DER/high-S、
未知 variant 全部失败关闭。
SPKI 与 signature 的 JSON string 只接受无 padding base64url canonical encoding；标准 base64、padding、
空白或解码后再换一种字符串表示都必须在 JCS/hash 前拒绝。

availability receipt signature
覆盖 `frame("loom-artifact-availability-receipt-signature-v1",`
`JCS(ArtifactAvailabilityReceiptBodyV1))`；receipt envelope 必须逐字段匹配 parent certified policy 的
exact reporter key 并按上述 profile 验签，receipt 的 reporter/purpose、artifact coordinates 与
ref/policy 逐字段相等。

policy reporters 按 ID 排序、ID/key 唯一，allowed purposes 按固定 enum 排序去重；
`1 <= required_receipt_count <= len(reporters)`、`1 <= required_fault_domain_count <=`
`required_receipt_count`，max age 为正 int64 秒。receipt leaves 按 reporter ID 排序去重，receipt 和
fault-domain 门槛都只按不同 reporter 计算；`observed_at` 不得晚于 candidate logical time 加 clock
skew，且 age 不得超过 policy。sealed backend 的 receipt digest 必须等于 ciphertext digest，
recipient version 必须与 envelope/profile 相符；预留 provider backend 的 receipt 约束见独立扩展计划。

voter 在把引用写入 Raft 前验证 artifact schema/hash、用途、owner、recipient/policy、PoP，
以及 secret policy 要求数量和故障域的签名 availability receipt。receipt 证明相同不可变制品已可取；
它不授权在 approval 前向 Device 释放明文。未达 availability policy
不得 commit/进入 `ready`。预生成后 proposal 失败留下的 orphan 没有 authority，必须隔离到
显式 retention/tombstone 后再按 [外部副作用与租约](reconciliation-ui.md#外部副作用与租约) 清理，后续 proposal 不能用可变名字把它重新解释成新 secret。

一旦引用所在 head certified，executor 只能取出并安装该 exact version；失败只重试同一 artifact。
重新生成、换 recipient、换 key version 或“故障切换时再随机一次”都必须产生更高 generation
的新 artifact/proposal/QC。邀请 token 本身也先生成并封装为只供获授权 invite-delivery renderer
读取的 immutable artifact；公开邀请 entry 同时绑定 domain-separated token commitment 和 private
artifact-binding hash，exact ref/recipient policy 只在 control-private binding 中复制。QR 与
`loom://` 携带同一有界 bootstrap descriptor，加入文件可再
内嵌无 token 的完整 proof bundle。服务端只能在邀请 certified 后由授权
invite-delivery renderer 解封，并通过一次性创建响应输出 token；此后明文只存在
用户持有的 descriptor/QR/加入文件/URI，以及自动重试窗口内的 exact claim body；claim 已 commit
后可为 [Bootstrap tunnel capability](bootstrap-capability.md#bootstrap-tunnel-capability) 的管理员授权 resume 保留到事务 `retry_not_after`，但过期 capability 本身不因此
续期。token 明文绝不进入 Raft/CRDT/SSOT、URL/header/cookie 或复制日志。邀请
certified 前不得输出任一可消费载体。ACME nonce/order URL 等临时 provider 值可以在 order intent
certified 后由 executor 取得，但必须立即封装为 purpose=`acme_order_state` 的 exact artifact，并在
任何 DNS/安装/cleanup 副作用前在 [外部副作用与租约](reconciliation-ui.md#外部副作用与租约) 的外部副作用账本中提交 private provider-state object；
不能只留进程内 handle。

每个 ref、policy、PoP 与 receipt 的唯一内容身份固定为：

```text
secret_possession_proof_hash = H(frame(
  "loom-secret-possession-proof-v1", JCS(SecretPossessionProofV1)
))
artifact_availability_policy_hash = H(frame(
  "loom-artifact-availability-policy-v1", JCS(ArtifactAvailabilityPolicyV1)
))
artifact_availability_receipt_hash = H(frame(
  "loom-artifact-availability-receipt-v1", JCS(ArtifactAvailabilityReceiptV1)
))
secret_artifact_ref_hash = H(frame(
  "loom-secret-artifact-ref-v2", JCS(SecretArtifactRefV2)
))
```

`availability_receipts_root` 对 exact
`ArtifactAvailabilityReceiptLeafV1{schema,reporter_id,receipt_hash}` 使用 [内容寻址操作](consensus.md#内容寻址操作) RFC 6962 规则；每个
hash 从同时交付的 receipt 重算。ref 的 policy/proof/root 必须分别等于上述重算结果；缺失、额外、
重复、过期或 fault-domain 不足都在包含 ref 的 proposal commit 前失败关闭。

`secret_artifact_refs[]` 的 exact 排序键固定为 `(purpose 的上述 enum ordinal,
secret_id UTF-8 bytes,generation,proposal_id UTF-8 bytes)`，严格升序且不得重复；其 root 对每个 ref 的
`JCS(SecretArtifactRefV2)` 直接作为 [内容寻址操作](consensus.md#内容寻址操作) RFC 6962 leaf 输入，空数组使用 RFC 6962 空树 root。
这一定义同时用于 Device view 和所有写作 `*_artifact_refs_root` 的字段，不允许各 consumer 另造 leaf
wrapper 或按摘要字符串排序。

所有写作 `credential_artifact_hash(es)` 或 `key_artifact_hash` 的 v2 exact 字段都必须解析到本节
定义的完整 immutable ref 并重算该 hash；invite 的 `token_artifact_binding_hash` 则先解析
control-private InviteTokenArtifactBindingV2，再从中解析同一类完整 token ref。字段名不会创造
第二种 secret-ref 摘要算法；binding 的目标 wire 见 [Invite、catalog 与紧凑二维码](enrollment-invite.md#invitecatalog-与紧凑二维码)。

---
