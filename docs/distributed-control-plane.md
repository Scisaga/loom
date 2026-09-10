# Loom · 分布式控制平面、域名与入口生命周期

> **状态：目标设计。** 迁移输入按一个指定控制节点、单 Ed25519 平台签名、
> `generation` floor 和多静态镜像建模；实际实现是否仍处于该基线只看
> [status/current.md](status/current.md)。本文定义迁移后的协议，不得用它解释当前行为。
>
> **与主设计的关系：** [design.md](design.md) 定义全系统不变量；本文细化其控制平面、
> SSOT 复制、身份、Enrollment、DNS/ACME 和公网入口轮换。发生冲突时，以本文和
> [D100–D130](decisions.md#d100--control-是节点能力控制集合不固定为三台)的新决定为准。

---

## 1. 结论

Loom 不再有一台永久的“中控机器”。一台合格 Device 可以同时承担 `access`、`server` 和
control 能力，但 control 的权威来源不是普通 SSOT 编辑：Raft config ledger 中最新 durable
committed 的 `JointControlSet` 或 `FinalControlSet(epoch)` 是内部选举/提交必须立即遵守的唯一
成员事实；Joint 要求 old/new 双多数，Final 表示稳定态。相应 transition apply/recompute 后
取得所需 joint replication QC，才成为可对客户端发布的 certified authority。
授权 operator 的 private materialized view 中，`control` 职责块只是 certified FinalControlSet
authority 与同 head 绑定的 private ControlPeerDirectory 联合得到的只读 capability projection；公开发布只含 opaque
ControlSet member/key，不含 Device 映射或 peer 拓扑。ControlSet 至少一个，最多可以是全部合格 Device；协议和数据模型不得
写死 3，也不得让节点靠添加本地 `control` 块自我授权。

3 只是最小的高可用部署建议：在崩溃故障模型下，3 个投票成员的多数派为 2，可以容忍
1 个成员离线。它不是节点类型、许可证限制或协议常量。

控制状态采用混合模型：

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

CRDT 负责复制事实、草稿和不可变对象；quorum 负责决定什么已经生效。任一 control Device
都可在内部转发请求，但只有带相应 certified EndpointSet role 且网络可达的入口才对外接收
管理、Enrollment、报告或配置读取；control capability 本身不自动暴露服务。当 `q > 1` 时，单个控制节点不能独立改变成员、权限、配置、邀请、
证书批准、域名绑定或入口端口；`N=1,q=1` 是明确的迁移/最小部署模式，不具备这项抗单节点
失陷性质。

本文中“从多个控制 API 入口任选其一”只是一个集合内选择的简写：
管理客户端只能从已信的 certified `EndpointSet(role=control_api)` 中选入口，
校验精确 URL、hostname/WebPKI 和 SPKI pin 后再用 admin cert 认证。这不包含
control peer RPC 地址、节点的其他 role 入口或 DNS 临时发现的 URL。尚无 Device
身份的 claim 更不读这个管理集合；它只能在本次 `InviteBootstrapDescriptorV2.delivery_context`
直接携带的有界 `EndpointSet(role=enroll)` seed 子集中故障切换，并在发送 token
前逐个完成同样的精确 transport 校验。

---

## 2. 目标与非目标

### 2.1 目标

1. 控制节点数量可以从 1 在线扩展到任意数量，也可以安全缩容。
2. 任一带相应 certified EndpointSet role 的可达入口都能接收请求并转发给当前 leader/服务；
   control Device 没有任何公网 role 时仍可只作为 voter。
3. 网络分区时至多有一个控制状态继续提交，少数派不得自封为新集群。
4. 控制面失去 quorum 不影响已安装的数据面；节点继续使用最后一个已认证 view。
5. 配置来源、传输镜像、DNS 和 TLS 终止点均可替换，但不能扩大签名 authority。
6. 自动为受管入口分配稳定域名、申请和续签证书，并可由另一个控制节点接管执行。
7. Hysteria2、Trojan 等可并行 listener 的公网入口使用同一代次模型无中断轮换；
   WireGuard 只有采用双接口/双 peer 专用状态机后才能宣称同等级别的无中断轮换。
8. Android、Windows 和 Linux 使用同一信任、anti-rollback、端点集合与轮换语义。
9. 从当前单签、单控制节点部署可以分阶段迁移，不重建既有 Device 私钥。

### 2.2 非目标

- 不让控制平面进入用户数据路径。
- 不声称普通多数共识能够容忍 Byzantine 控制节点；首版只承诺 crash/partition safety。
- 不用 DNS、HTTPS 证书、在线节点数或 Web 测量结果决定控制成员资格。
- 不把域名购买、续费扣款或注册商迁移默认做成无人批准的自动操作。
- 不承诺 QUIC/TCP 会话跨端口迁移；“无中断轮换”靠新旧 listener 重叠和旧会话排空。
- 不为控制复制重新引入客户端整路径探测；客户端仍遵守入口单次有界测量约束。

---

## 3. 不变量

| # | 不变量 |
|---:|---|
| 1 | **一个逻辑 SSOT，多份副本。** 副本数量不产生第二套期望态。 |
| 2 | **生效状态必须有唯一 certified head。** CRDT 对象或尚无 QC 的 Raft commit 不能直接授权安全关键动作。 |
| 3 | **quorum 按已提交成员数计算。** 不能按当前在线数自动缩小。 |
| 4 | **成员变化也是被共识保护的状态。** `control` 不能靠本地开关即时获得投票权。 |
| 5 | **签名高于传输信任。** DNS、TLS、反代、镜像和临时 leader 都不是配置 authority。 |
| 6 | **密钥按用途分离。** Device、control peer、配置签名、Enrollment、admin、CA 与公开 TLS 不复用。 |
| 7 | **外部副作用只追随 certified state。** 无 QC 的 Raft commit 不得驱动 DNS/ACME/防火墙；执行失败也不能倒写另一个 SSOT。 |
| 8 | **端点身份稳定，物理地址可轮换。** 客户端选择逻辑 endpoint，不把端口代次当新出口。 |
| 9 | **数据面离线自治。** 无 quorum、所有控制端不可达或新 view 无效时保留 last-known-good。 |
| 10 | **恢复必须显式留下新 epoch。** 丢失 quorum 后不得静默删成员、降门槛或重置 revision。 |

---

## 4. Device 能力与控制角色

目标 SSOT 对 `access/server` 仍使用“角色块存在即拥有能力”；`control` 块只展示
`FinalControlSet` 已授予的 capability projection，不是管理员可直接生效的普通字段：

```yaml
nodes:
  - id: demo-a
    server: { ... }
    control:
      member_id: 00000000000000000000000001
      signing_public_keys:
        config: ed25519:...
        membership: ed25519:...
        enrollment: ed25519:...
```

不存在另一个可写的 `capabilities: [control]`。不过 `control` 不能像普通字段那样先改 SSOT
再自我授权：规范内部成员事实是 Raft 配置日志中的 committed `FinalControlSet`/transition
ledger；reducer 只有在 Final 取得 joint QC、并取得 matching private directory 后，才把它投影为
授权 operator 可见的 private materialized `control` 块。`committed_not_certified` Final 已约束
Raft 自身，却不能更新客户端 authority；public projection 永远只有 opaque set/key 与 directory hash。
用户仍只维护一套逻辑模型，但任何
增删/换 key 都必须走 §9 的 joint state machine，不能用普通 operation、CRDT 合并或手填第二
成员表绕过。

需要区分以下状态：

| 状态 | 含义 | 能否投票 |
|---|---|---:|
| candidate | 管理员已提出加入，但尚未同步 | ❌ |
| learner | 已建立 control mTLS 并复制完整 checkpoint/log | ❌ |
| joint member | 正处于旧、新集合联合提交阶段 | 只按 joint 规则 |
| voter | 当前 `ControlSet(epoch)` 的正式成员 | ✅ |
| retiring | 已从新集合移除，仍完成 joint handoff | 只按 joint 规则 |
| removed | 不再是 control；普通 Device 生命周期另行处理 | ❌ |

candidate/learner/retiring 是控制协议运行态，不作为可与 `control` 块矛盾的长期 SSOT
布尔字段。一次迁移完成后，内部稳定成员状态只由 committed `FinalControlSet` ledger 推导；
private operator view 的 `control` 块只在 certified 结果与 matching directory 上联合投影，不能反向
自我授权，也不得进入 public distribution/per-Device view。

control Device 至少必须具备：耐久磁盘、受保护的独立密钥、受监测的可信时间源、可与其他成员建立
mTLS、支持当前控制 schema/协议，并能保存完整 checkpoint。协议不按 Android、Windows 或
Linux 平台禁止 voter；任何 Device 只有通过相同 eligibility 才可入组。当前部署究竟哪些平台
已有合格实现只见 [status/current.md](status/current.md)，不得写死在目标协议。

静态镜像、DNS/ACME executor 和 control voter 是三种不同职责。镜像不投票；executor
只能应用 certified 期望；voter 不因持有普通 Device 证书或能访问管理 API而自动获得 admin 权限。

---

## 5. ControlSet、quorum 与故障模型

在 crash-fault tolerant（CFT）配置下：

```text
N = |ControlSet(epoch)|
q(N) = floor(N / 2) + 1
可容忍离线数 = N - q(N)
```

| N | q | 可容忍离线 | 说明 |
|---:|---:|---:|---|
| 1 | 1 | 0 | 最小可运行；无控制面 HA |
| 2 | 2 | 0 | 任一成员离线即停写 |
| 3 | 2 | 1 | 最小推荐 HA 部署 |
| 4 | 3 | 1 | 比 3 多一成员但不多容忍一次故障 |
| 5 | 3 | 2 | 更高可用性，提交路径也更长 |

quorum 永远按 committed 成员数 `N` 计算。健康检查、DNS 记录、当前可达成员或操作者
选择都不能改变它，否则一次分区可能让两侧分别按较小的在线集合提交。

架构允许所有合格 Device 都拥有 `control`，但不要求这样部署。跨地域 voter 越多，
控制写入需要跨越的故障域和尾延迟通常越大；常见部署可选择 3 或 5 个稳定 voter，其他
Device 仍可作为镜像、观测副本或 learner。这个建议不进入协议校验。

首版 CFT 假设控制进程可能宕机、丢包或分区，且正确 voter 遵守 Raft 持久化、选举和日志
匹配规则；它不容忍任意作恶或密钥失陷。每个 voter 的独立签名提供来源和审计，不能把 CFT
自动宣传成 Byzantine 容错。若以后需要容忍 `f`
个恶意 voter，必须切换到经过审计的 BFT profile，至少满足 `N >= 3f + 1`、提交证明
至少 `2f + 1`，并实现锁定、轮次和 view-change；仅把签名门槛改大不够。

---

## 6. 信任域与密钥

| 信任域 | 持有者 | 用途 | 明确不能做什么 |
|---|---|---|---|
| recovery root | 离线介质/可选多人门槛 | genesis、失去 quorum 后签新 recovery epoch | 日常发布、在线 API |
| control membership key | 每个 voter | ControlSet 联合迁移 | 签普通配置或 Device 报告 |
| control config key | 每个 voter | 对 committed head/view 投票签名 | 充当公开 TLS 或 admin 身份 |
| control enrollment key | 每个 voter | 对已提交 claim/CSR 作独立 Enrollment approval | 独自签发成员资格或替代 config QC |
| control peer cert | control Device | 控制复制、选举、内部 RPC mTLS | 自动获得人类 admin 权限 |
| admin cert | 人类/自动化管理员 | 向已信 certified `EndpointSet(role=control_api)` 内的入口提交有范围的操作 | 参与 controller quorum |
| Device identity cert | 每台 Device | 报告、配置读取、节点声明 | 管理 SSOT 或成为 voter |
| internal CA | 离线根 + 受约束在线中间 CA | 签 control/admin/Device profile | 配置发布投票 |
| public WebPKI cert | 公开入口所在 Device | HTTPS/Hysteria2/Trojan 传输身份 | 成员资格、配置真实性 |
| application code-signing key | 发布流水线 | APK/MSI/EXE 来源与升级连续性 | 签 SSOT 或 Enrollment |

不同证书 profile 使用不同 EKU、SAN、issuer policy 和私钥。验证器不得再用
`ExtKeyUsageAny` 把角色边界抹平。公开 ACME 证书本身不是配置 authority；但服务端 TLS
SPKI 发生变化时，必须先通过 quorum 把新旧 pin overlap 写入 EndpointSet/邀请 checkpoint，
不能把普通 WebPKI 续签当成静默替换服务身份。客户端同时验证 hostname/WebPKI、签名端点
中的身份 pin 和配置 QC。

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

### 6.1 初始 admin/CA 与轮换

bootstrap ceremony 一次性建立 recovery anchor、初始 admin ACL、证书 profile、第一张有界
admin 证书和 online intermediate 的公开材料；这些摘要全部进入 genesis/迁移对象。第一张
admin 证书由 ceremony 明确授权，不依赖尚未存在的 admin ACL，之后任何 admin/issuer 变更
都走正常 quorum 提交。recovery 私钥、CA 根私钥和各 Device/TLS 私钥不进入 SSOT。

online intermediate 轮换使用 `stage → issue/verify → overlap → revoke old`：先提交新 issuer
公钥/profile 和 CSR approval，再由持租约的 issuer executor 签发；足够 reader 接受新链后
才提交旧 issuer 的撤销与 CRL/registry 水位。admin key replacement 同样先增加新主体、验证
持钥，再撤旧主体，禁止用节点本地运维 cookie 绕过 ACL。

`admin_acl_root` 与 `ca_profile_root` 不是 opaque 本地数据库摘要。首个 v2 profile 固定以下 exact
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
  subject_key_algorithm = "ed25519"
  operation_signature_algorithm = "ed25519"
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
  device_certificate_profile_states[]      # §11.2 DeviceCertificateProfileStateV1，按 profile_id 排序
  ca_profile_root
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
authority_registry_private_object_hash = H(frame(
  "loom-authority-registry-private-object-v1", JCS(AuthorityRegistryPrivateObjectV1)
))
```

`admin_acl_root` 对每个最新 `AdminAuthorizationV1` 重算 `AdminACLLeafV1`，按 authorization ID 排序并
使用 §7.1 RFC 6962 tree；`ca_profile_root` 对两类 profile 重算
`CAProfileRegistryLeafV1`，按 `(profile_kind enum,profile_id)` 排序使用同一 tree。profile 内 DER chain
从 issuing intermediate 到 anchor 排序，`admin_issuer_chain_hash=H(frame("loom-admin-issuer-chain-v1",`
`JCS({schema:1,issuer_chain_der})))`；证书 digest 是
`H(frame("loom-admin-certificate-der-v1",raw_der))`，key ID 从 leaf DER SPKI 重算。所有 refs、leaf、
roots 与 private object 都由 exact bytes 重算，不能从裸 ID 或本机 trust store恢复。
其中 admin leaf 的 `profile_hash` 是 `admin_certificate_profile_hash`；Device leaf 的 `profile_hash`
是 reducer 派生的 `device_certificate_profile_state_hash`，并由 state 内嵌 intent 重算另一层 intent
hash。两个 variant 不得互换摘要 domain。

AdminAuthorization 同 ID generation 从 1 连续递增；首代无 previous，后续必须指向前代 hash。
`revoked` 必须保留前代 cert/profile/permissions/capabilities/scopes bytes且不可回到 active；active cert 必须按 exact
profile 验链/validity/EKU/OID，并要求 leaf SPKI 为 Ed25519。admin key ID 固定为 leaf DER SPKI 的
小写 `sha256:` digest；operation signature 是 raw 64-byte Ed25519 signature。未知 subject/signature
算法、非规范 key ID 或其他签名字节编码全部失败关闭。`scopes` tag 与唯一 variant 一致、数组非空
（cluster exact-empty 除外）。
校验 `ControlOperationV1` 时，从其 base head 的 private registry 解出唯一 active authorization，要求
author/key/cert digest、可信时间、allowed kind 与 payload 的 exact resource scope 同时满足；new head
里的 ACL 不能倒过来授权自己的 mutation。

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
由 leader 按“最合适”选择。`allowed_platforms[]` 按 §11.1 platform enum、
`allowed_responsibilities[]` 按 responsibility enum 排序去重且非空；引用者必须全部落在其 scope。

任一 stage/activate commit 都必须先严格解析 issuer material：`issuer_chain_der[]` 非空、
`issuer_chain_der[0] == issuer_certificate_der`，逐张 strict DER 从 online intermediate 验签到数组最后
一张 self-signed anchor；每张 CA 都必须 `BasicConstraints CA=true`，中间/anchor KeyUsage 含
`keyCertSign`，不得有未知 critical extension。issuer certificate/SPKI 固定为 Ed25519，certificate
signature chain 与 validity 必须有效，且 issuer validity 覆盖整个 issuance window 加
`validity_seconds` 的 checked upper bound；certificate/chain hashes 从 exact bytes 重算。数组最后的
anchor 就是该 profile 冻结的 trust anchor，不读取本机 trust store。
`issuer_key_artifact_hash` 必须解析到 §6.2 purpose=`ca_private_key` 的 exact ref，owner/issuer executor
scope 相符，`public_key` 为 Ed25519 且 SPKI 逐字节等于 issuer certificate，PoP/availability 与
key-unseal fence 均通过；active transition 必须在 candidate time 下重新验证同一 exact
PoP/availability/fence，而不能沿用 staged 时的 mutable provider alias。任何一项不满足都不能形成 staged/active state，避免 registry 认证一份
永远无法签发的 profile。

普通变更的 outer kind 固定为 `upsert_admin_authorization`、`revoke_admin_authorization`、
`upsert_admin_certificate_profile` 或 `upsert_device_certificate_profile`，payload/hash 分别使用上式或
§11.2 `device_certificate_profile_intent_hash`；调用者在 base ACL 中还必须具有
对应 capability、outer kind 及 matching scope。reducer 以 expected previous
state hash 做 CAS，以 candidate Head 的 committed time/recovery epoch/Raft index 派生 profile state，
选择每 ID 最新代并重算两个 root；同一 head 内先按 operation ID 应用全部已授权操作，再计算 root。
bootstrap/emergency 的 `initial_admin_acl_hash` 与
`internal_ca_profile_and_anchor_hash` 精确解释为这两个 root：新 voters 必须在 Genesis durable
install 前私下取得 matching `AuthorityRegistryPrivateObjectV1` 并重算；public bundle仍只携 root。
planned recovery 与 ControlSet Final 按前文继承 registry bytes/roots。缺 preimage 的副本可验证公开
head QC，但不能投票、验证 admin write 或执行 CA。

### 6.2 权威 secret artifact

邀请 token、Device/数据面凭据、TLS/CA/provider key 等 authority-bearing secret 必须在引用
它的 proposal **提交前只生成一次**，并固定成以下二选一的精确后端对象：

```text
SecretArtifactRefV2
  schema = 2, cluster_id, proposal_id, secret_id, purpose, owner: SecretArtifactOwnerV1, generation
  public_key?: AuthorityProofKeyV1, immutable_ref
  backend_kind           # sealed_blob | kms_or_hardware_key；exact tagged union
  sealed_blob?: SealedBlobRefV1
  kms_or_hardware_key?     # provider/object_id, exact_version, policy_hash
  possession_proof_hash?, availability_policy_hash, availability_receipts_root

SealingPolicyV1                         # exact tagged union；首版只接受下文两个 canonical object
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
refs 且同序。引用必须指向不可覆盖 blob 或精确
KMS/HSM/Keystore version；`latest`、可变 alias、可覆盖文件路径和仅靠进程内缓存的 handle 均
不合法。非导出私钥提交 exact `AuthorityProofKeyV1`、精确 key version 和 domain-separated
`SecretPossessionProofV1`，并覆盖 cluster/proposal/secret/purpose/owner/generation、公开 key
和 immutable ref，禁止把另一用途或 proposal 的 PoP 搬来复用；TLS 终止节点先生成 key/CSR，
再提交 SPKI、CSR hash 和本机 availability
receipt。sealed credential 按已提交的 recipient key version 分别封装，日志与 CRDT 只含
ciphertext hash/ref，绝不含 plaintext。

首版只接受两个逐字段固定的 `SealingPolicyV1`：

| policy_id / recipient_key_profile | key_wrap variant | 用途 |
|---|---|---|
| `sealed-p256-v1` / `p256-keystore-sign-ecdh-v1` | 上式 `p256_ecdh` 全部 literal | Android API 31+、Windows、Linux 与 control custodian 可用的不可导出 P-256 key |
| `sealed-rsa2048-v1` / `rsa2048-keystore-sign-decrypt-v1` | 上式 `rsa_oaep` 全部 literal | Android API 26–30 及需要同等 Keystore fallback 的实现 |

表中未选 variant 必须缺失；所有共同字段必须等于 schema 中的 literal，不能用 provider 默认值改写。
`sealing_policy_hash=H(frame("loom-sealing-policy-v1",JCS(SealingPolicyV1)))`；profile 到 policy 是上表
一对一映射，未知 profile/policy 或错配 hash 失败关闭。RSA fallback 的 wrapping key 是独立的
Android Keystore RSA-2048 key，生成用途只含 SIGN 与 DECRYPT；PoP 使用
RSASSA-PKCS1-v1_5/SHA-256，解封使用 RSA-OAEP SHA-256、MGF1-SHA-1、空 label。它不把私钥导出到
进程，也不允许充当 Device identity/signing key。P-256 profile 则只允许 ECDSA PoP + ECDH，且在
Android 上要求 API 31 的 `PURPOSE_AGREE_KEY`；低版本必须选择 record 已授权的 RSA profile，不能
退化为软件 ECDH。

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

| purpose | backend | PoP / public identity | owner 与 recipient |
|---|---|---|---|
| `invite_token` | `sealed_blob` | 二者必须缺失 | owner 为创建 principal 的 control Device；recipient 只能是 invite-delivery renderer key set |
| `device_credential` | `sealed_blob` 或 Device `kms_or_hardware_key` | 非导出私钥必须 PoP+SPKI；纯对称凭据二者缺失 | owner 为目标 Device；sealed recipients 必须恰含该 Device 当前 wrapping key versions |
| `data_plane_credential` | `sealed_blob` 或 owner hardware key | 私钥型必须 PoP+public key；对称型二者缺失 | owner 为 endpoint Device；recipients 等于 certified transport profile 的参与 Device 集合 |
| `tls_private_key` | TLS 终止 Device 的 `kms_or_hardware_key`，仅 profile 明确允许时可 sealed | 必须 PoP+DER SPKI | owner/recipient 必须是终止 TLS 的 Device |
| `ca_private_key` | `kms_or_hardware_key` | 必须 PoP+DER SPKI | owner 为 certified CA executor；不得 seal 给普通 control voter |
| `dns_provider_credential` | `sealed_blob` 或 provider KMS exact version | 对称/API token 时二者缺失 | owner 为 DNS executor role；recipient scope 不得超出 ManagedZone provider adapter |
| `acme_account_key` | `kms_or_hardware_key` | 必须 PoP+public key | owner 为 ACME executor role；不得复用 TLS key |
| `acme_order_state` | `sealed_blob` | 二者必须缺失 | owner 为创建 order 的 ACME executor role；recipients 必须恰为该 certified executor pool 的 wrapping key versions |
| `control_peer_identity` | peer Device `kms_or_hardware_key` | 必须 PoP+DER SPKI | owner/recipient 必须是该 private directory member 对应 Device |
| `recovery_private_key` | `sealed_blob` 或 custodian HSM exact version | 必须 PoP+DER SPKI | owner 精确绑定 policy generation/key ID；sealed recipients 等于 custody custodian wrapping refs |

`allowed_purposes[]` 只可用此顺序的子序列。backend、PoP、identity、owner 或 recipients 与表及
引用它的 certified profile 任一不符即拒绝；表中的“或”只能由 profile 的 exact tagged choice
消歧，不能由 executor 临时选择。

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
skew，且 age 不得超过 policy。sealed backend 的 receipt digest 必须等于 ciphertext digest，KMS/HSM
backend 必须等于 provider 对 exact version 返回的 canonical version digest；recipient version 的
存在/缺失也必须符合 backend/profile。

voter 在把引用写入 Raft 前验证 artifact schema/hash、用途、owner、recipient/policy、PoP，
以及 secret policy 要求数量和故障域的签名 availability receipt。receipt 证明相同不可变字节或
精确 KMS version 已可取；它不授权在 approval 前向 Device 释放明文。未达 availability policy
不得 commit/进入 `ready`。预生成后 proposal 失败留下的 orphan 没有 authority，必须隔离到
显式 retention/tombstone 后再按 §15 清理，后续 proposal 不能用可变名字把它重新解释成新 secret。

一旦引用所在 head certified，executor 只能取出并安装该 exact version；失败只重试同一 artifact。
重新生成、换 recipient、换 KMS version 或“故障切换时再随机一次”都必须产生更高 generation
的新 artifact/proposal/QC。邀请 token 本身也先生成并封装为只供获授权 invite-delivery renderer
读取的 immutable artifact；公开邀请 entry 同时绑定 domain-separated token commitment 和 private
artifact-binding hash，exact ref/recipient policy 只在 control-private binding 中复制。QR 与
`loom://` 携带同一有界 bootstrap descriptor，加入文件可再
内嵌无 token 的完整 proof bundle。服务端只能在邀请 certified 后由授权
invite-delivery renderer 解封，并通过一次性创建响应输出 token；此后明文只存在
用户持有的 descriptor/QR/加入文件/URI 和该事务 `retry_not_after` 前的 exact
claim/retry body，绝不进入 Raft/CRDT/SSOT、URL/header/cookie 或复制日志。邀请
certified 前不得输出任一可消费载体。ACME nonce/order URL 等临时 provider 值可以在 order intent
certified 后由 executor 取得，但必须立即封装为 purpose=`acme_order_state` 的 exact artifact，并在
任何 DNS/安装/cleanup 副作用前提交 §12.4 private provider-state object；不能只留进程内 handle。

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
`ArtifactAvailabilityReceiptLeafV1{schema,reporter_id,receipt_hash}` 使用 §7.1 RFC 6962 规则；每个
hash 从同时交付的 receipt 重算。ref 的 policy/proof/root 必须分别等于上述重算结果；缺失、额外、
重复、过期或 fault-domain 不足都在包含 ref 的 proposal commit 前失败关闭。

所有写作 `credential_artifact_hash(es)` 或 `key_artifact_hash` 的 v2 exact 字段都必须解析到本节
定义的完整 immutable ref 并重算该 hash；invite 的 `token_artifact_binding_hash` 则先解析 §11.1
private binding，再从中解析同一类完整 token ref。字段名不会创造第二种 secret-ref 摘要算法。

---

## 7. 复制模型：CRDT 保存材料，共识决定生效

### 7.1 内容寻址操作

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
  algorithm = "ed25519", admin_key_id
  signature                        # raw 64 bytes，无 padding base64url
```

`author_signature.signature` 覆盖
`frame("loom-control-operation-signature-v1", JCS(ControlOperationBodyV1))`；key ID 必须由 body 所指
admin cert 的 DER SPKI 重算，并在 base head 的 admin ACL scope 内获准执行 exact `kind`。证书/profile、
signature algorithm 和 wire 长度必须逐字段满足 §6.1 固定的 Ed25519 profile；不能从本机 provider
默认值猜算法，也不接受 DER、ECDSA 或可变长度编码。
`object_id = H(frame("loom-control-operation-v1", JCS(ControlOperationV1)))`。每种 `kind` 必须在
版本化 schema 中固定 payload bytes 和 payload hash domain；未知 kind/schema、额外字段、cert digest
不匹配或相同 operation ID 的不同 object ID 全部拒绝。

时间和端口等公开随机选择由调用方产生并进入对象，归约器不读取本机时钟或随机源，继续
满足纯函数约束。秘密随机值同样在 proposal preparation 按 §6.2 预生成，绝不能由 reducer 或
commit 后 executor 临时生成；invite token 明文、Device 数据面凭据和私钥不进入
公开 operation/CRDT/SSOT，只提交 token commitment/binding hash 或公开密钥；需要可接管执行的
exact-version artifact ref 只进入 §6.2 规定的 control-private replicated object，并由公开 hash 承诺。
管理员重试复用 `operation_id`；相同 ID 不同 payload 必须失败关闭。

每个 certified head 的 `operation_root` 使用一个确定的累计操作树，而不是 map 的本地遍历顺序：

```text
ControlOperationLeafV1
  schema = 1, operation_id, object_id
```

只纳入该 head 已按序 apply 的 canonical operation objects；通常是 admin-signed
`ControlOperationV1`，两个非 admin variant 仅为 §11.2 明确定义的 token-authorized
`EnrollmentClaimOperationV1` 与 approval-QC-authorized `EnrollmentCompletionOperationV1`。每个 leaf
的 `object_id` 按其 exact variant/domain 重算，operation ID
从对应 body 取得。leaf 按规范化 `operation_id` UTF-8 bytes 升序，跨 variant 重复 ID 同样拒绝；
`LeafHash=SHA-256(0x00 || JCS(ControlOperationLeafV1))`，内部节点为
`SHA-256(0x01 || left || right)`，奇数叶按 RFC 6962 的最大二次幂递归分树而不复制末叶，空树 root
为 `SHA-256("")`。所有 voter、Device proof 和 Enrollment proof 都必须使用同一 index/tree size；
不能按 object arrival、Raft follower 本地顺序或 JSON map 顺序构造 root。

### 7.2 哪些数据可以直接 CRDT 合并

| 数据 | 合并方式 | 是否直接改变权限/配置 |
|---|---|---:|
| 签名健康、测量、运行回执 | add-only set，按身份/时间/hash 去重 | ❌ |
| 不可变 snapshot、binary、Device view | control 副本内部的内容寻址集合；Device view 不进入公共镜像 | ❌ |
| UI 草稿、评审意见 | MV-register/operation set；冲突显式展示 | ❌ |
| pending proposal | operation DAG | ❌ |
| 审计附件 | add-only set | ❌ |

不得用 last-write-wins 静默解决两份管理员修改。冲突草稿可以都存在，但必须由管理员选择
或生成一个合并提案，最终对精确 hash 取得提交后 quorum attestation/QC。

### 7.3 哪些状态必须串行提交

- ControlSet、信任根、admin 权限和证书 profile；
- Device membership、职责、grants、暂停、撤权和删除；
- 邀请创建、作废、一次性消费和 identity/SPKI 绑定；
- 生效 SSOT、release、rollback、每 Device view 与最低客户端版本；
- 唯一地址、域名、端口、credential generation 和资源租约；
- DNS 生效绑定、证书签发批准、入口 preferred/retired 代次；
- tombstone checkpoint 与垃圾回收水位。

原因不是这些数据无法序列化，而是两个分区各自合法地修改后，事后合并无法撤回已经签发
的证书、消费的 token 或暴露的数据。

### 7.4 Raft committed log 与提交后 certified QC

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
  admin_acl_root, ca_profile_root
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

`ordinary` 的 transition context 精确为 `{schema:1,kind:"ordinary"}`；其他 kind 分别使用 §9.1、§9.3、
§9.4、§10.3 的 context。未知 kind、context 字段不匹配或额外字段全部拒绝。
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
  admin_acl_root, ca_profile_root, render_contract_version, min_reader_version
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
但不得发布为 mutable current、驱动外部副作用或返回“已生效”；客户端继续 LKG。QC 是对
“Raft 已提交且 quorum 已复算”的证明，不是 Raft 投票消息，也不能反向提交日志。

未被 Raft committed 的日志后缀可在更高 term 按 Raft 规则覆盖；不存在永久占用某个 revision
的应用层预签票，因此 leader 切换不会因分散预签而永久停写。已经 committed 的 entry
不得被冲突日志覆盖；同一 lineage/正式 revision 出现冲突 QC 是安全事件。外部 reader 只需
验证 ControlSet/transition、QC 的 term/index/hash/签名集合和 head 链，不需要信任或固定当前
leader。若未来替换 Raft，必须使用新 protocol profile，完整定义 term/round、锁定与解锁、
view change、成员迁移和可机检安全证明；不能只实现 parent/hash 多签。

### 7.5 时间语义

所有会影响归约结果的时间来自日志中的 `committed_logical_time`，并在同一 lineage 内严格
单调；reducer 不读取本机时钟。leader 提议时间，voter 只在其受监测时间源与提议值偏差不
超过最新 certified `max_clock_skew`、且不早于上一 head 时 ack。邀请/提案/证书在**提交时**按该
逻辑时间校验；接收者还要按本地可信墙钟和同一偏差上限再次校验有效期。时间源不可信时，
节点不得批准新邀请、证书或租约，但可以读取旧状态并维持 LKG。

首版 `max_clock_skew_seconds` 是 HeadEntry/QC 必签的 0..300 整数秒；不能用浮点、duration 字符串或
本地默认值。未入网客户端在 proof GET 前使用 descriptor context 中的值但仍硬截断到 300 秒，
下载后必须确认它等于 certified base/record head；不等即拒绝并且不发送 token。

租约同时绑定 Raft term/log index 和有界墙钟期限；executor 必须在 deadline 前预留
`max_clock_skew + request_timeout` 安全裕量，跨过安全截止即停止发新请求。墙钟只帮助停止
旧 executor，不能替代 provider CAS 或本地 generation fencing，具体限制见 §15。

---

## 8. 写入、读取与分区行为

### 8.1 写路径

```text
admin → 已信 certified EndpointSet(role=control_api) 内的任一入口
      → 验精确 URL/hostname/WebPKI/SPKI pin、admin cert、权限、request id、expected head
      → 本地保存并 CRDT 广播 proposal
      → leader/协调者选择 parent，所有 voter 独立校验
      → Raft durable commit
      → apply/recompute，quorum attestation 形成 certified head/QC
      → 返回 certified epoch/revision/hash/QC
      → immutable-artifact renderer、publisher、reconciler 分别收敛
```

接受请求的节点不必是 leader；它可以转发，也可以返回稳定 operation ID 让客户端轮询。
同步成功的 HTTP `200/201` 只能表示已经取得 QC。仅写入本地/CRDT 时显示 `pending`；已经
Raft commit 但尚未收齐 attestation 时显示 `committed_not_certified`，可用 `202 + operation ID`
轮询，但不得声称已生效。无法形成 quorum 返回可重试错误，不能把少数派草稿包装成“稍后会发布”。

所有写 API 携带 `expected {epoch, revision, head_hash}`。陈旧页面得到 conflict，并拿到
当前 head；服务端不能自动把旧表单套到新状态。多份不冲突草稿也必须在一个确定性提案中
提交，不能依赖不同副本的文件锁。

### 8.2 读路径

任何 control 副本都可以返回：

- 本地已验证的最新 certified head 和 QC，以及另行标识的 `committed_not_certified` 诊断状态；
- 该 head 的 materialized SSOT/view；
- CRDT 观测及其来源、新鲜度和覆盖范围；
- 本地 reconcile/applied 进度。

响应必须标明 `committed`、`observed_at` 和本副本是否已追上已知 quorum。读到较旧但仍有
合法 QC 的 certified 状态可以展示为 stale；涉及创建邀请、读取秘密、撤权判定或写前置条件时必须做
线性化读取，落后副本应转发或拒绝，不能凭本地旧状态授权。

### 8.3 分区

- 拥有 quorum 的一侧可以继续 commit/certify；少数派只能读旧 certified state、收集观测和草稿。
- 两侧都不能按“当前在线成员”重新计算门槛。
- Device 继续运行 last-known-good；本地 Direct/Auto/指定出口偏好仍可切换，但不扩权。
- 分区恢复后，CRDT 材料自动合并；只有 QC 链上的状态进入 effective SSOT。
- 同一 `(epoch, revision)` 出现不同 hash/QC 是安全事件，客户端和 publisher 全部 fail closed。

---

## 9. ControlSet 成员变化

### 9.1 加入

ControlSet 不是若干实现自行解释的 Device ID 列表。公开 authority 与 control peer 的私有拨号目录
必须拆开：公开 transition、邀请 proof 与静态镜像只携不暴露 Device/拓扑的 ControlSet，完整 peer
目录只在已认证 control-to-control 通道复制。首版 wire 使用以下 exact 对象；字段缺失、额外字段、
未排序数组、重复 member/key/endpoint 或同一公钥跨用途复用都必须拒绝：

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
InviteProofBundle 或 per-Device view。
每个 `peer_identity_artifact_hash` 必须解析到 §6.2 purpose=`control_peer_identity` 的 exact
`SecretArtifactRefV2`，owner 等于 directory Device、公开 SPKI hash相等且 PoP/availability 满足；
其中 `peer_identity_spki_hash=H(frame("loom-control-peer-identity-spki-v1",raw_spki_der))`，
`peer_certificate_hash=H(frame("loom-control-peer-certificate-der-v1",raw_certificate_der))`。
peer key 固定为 Ed25519；证书必须是 strict DER、自签且验签成功，SPKI 与 artifact 逐字节相等，
`BasicConstraints CA=false`、KeyUsage 仅含 `digitalSignature`、EKU 恰含 client/server authentication，
并在 §7.5 可信时间窗内有效。control-peer TLS 固定 TLS 1.3，双方只接受当前 directory（Joint 时为
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
`{member_id,key_purpose,control_key_pop_hash}` leaves 使用 §7.1 的 RFC 6962 规则计算。PoP 只证明
对应私钥确实存在，不授予成员资格；正常成员变化由
`ControlMembershipApprovalProofV1.new_control_key_possession_proofs` 携带并经其 hash 固定，紧急恢复
与首次 bootstrap 则分别由 §9.3、§10.3 的旧 authority 签名对象承诺该 root。

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

`admin_intent_operation` 必须是 §7.1 exact admin-signed operation：
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
同一 member 在同一侧永远只计一票。Joint config 与 Final head 分别使用 §7.4 的 tagged QC，
不得共用或省略 attestation body。`target_control_epoch` 和 `new_control_epoch` 都必须等于
`old_control_epoch + 1`。Final payload/context 必须精确引用同一 membership proof 以及已提交
Joint 的 entry/proof hash，且其 Raft index/previous-log hash 紧接 Joint；
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
Final payload 的
`raft_index == Joint.raft_index + 1`、`previous_log_entry_hash == joint_entry_hash`；任一不等都
必须拒绝，不能仅因 joint proof 本身有效就把它拼接到另一 lineage、parent 或目标 epoch。

Final membership transition 不授权夹带普通业务、ACL、CA 或 reader-policy 修改。确定性 Final
reducer 从 `parent_certified_head_hash` 的 materialized state 出发，只把 private operator
`control` projection 替换为 new public ControlSet hash、matching directory hash 与新 control epoch，
其余业务对象逐字节保持；随后按同一 render contract 重算 snapshot/effective SSOT hash。因此 Final
payload 的 `operation_root/device_views_root/admin_acl_root/ca_profile_root/render_contract_version/`
`min_reader_version/max_clock_skew_seconds` 必须逐字节继承 parent，`snapshot_hash` 与
`effective_ssot_hash` 必须等于上述唯一 reducer 输出，不能由 sender 自报。`committed_logical_time`
只能按 §7.5 单调前进，`control_revision` 仍由 Final 的 raft index 映射；只有 authority 字段、
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
   `joint_finalization_only(transition_id)`，除与该 transition 精确匹配的 Final 外，不得追加或提交
   普通 head、另一 membership/recovery operation 或外部副作用 intent。期间收到的普通提案只留在
   CRDT/pending 层，等待 Final certified 后基于新 head 重新做 CAS；不得插到 Joint 与 Final 之间。
   重叠 voter 在两边各计一次成员资格，但 QC 必须分别证明两边都达门槛。
6. 在 joint 规则下紧接 Joint 提交并以 old/new 双多数 QC 认证
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

### 9.3 丢失 quorum

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
  key_artifact_ref: SecretArtifactRefV2   # purpose=recovery_private_key；sealed 或 HSM exact version
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
`{key_id,recovery_key_pop_hash}` canonical leaves 使用 §7.1 RFC 6962 树规则计算；缺 key、重复、额外
proof 或字段与 policy 不等都拒绝。若未来采用 DKG/阈值聚合 key，必须新增 policy/ceremony
profile 和黄金向量，不能把它塞进首版独立 Ed25519 多签 schema。

每个 custody artifact 的 policy/key/public key 必须逐字节等于公开 policy；hiding nonce 必须解码为
32 bytes。内嵌 `key_artifact_ref` 的 cluster 必须相等，`proposal_id` 固定为
`H(frame("loom-recovery-custody-proposal-id-v1",JCS({schema:1,cluster_id,policy_id,
policy_generation})))`，`secret_id=key_id`、`purpose=recovery_private_key`，owner 必须是 matching
`recovery_policy` variant。ref 的 `public_key` 必须是 Ed25519 `AuthorityProofKeyV1`；从 strict DER
SPKI 提取的 raw 32-byte key 必须逐字节等于 policy/custody artifact 的 `public_key`。generic
AuthorityProof key ID 按 §6.2 的 SPKI domain 重算，**不要求**等于从 raw key 计算的 recovery policy
`key_id`：generic PoP 用前者，`RecoveryKeyPossessionProofV1` 与 threshold signature 用后者定位同一
raw key，两种命名空间不得直接比较。immutable ref/KMS version 不得为
`latest`、alias 或可覆盖路径；sealed ref 的 recipient refs 必须与 custodian refs 一一对应并满足 §6.2
exact envelope，且每个 custodian/receipt 的 optional recipient key 都必须存在并相等；HSM ref 则
必须缺失 sealed recipient set，并要求所有 custodian/receipt 的 optional recipient key 缺失（HSM
access principal 由 exact provider policy处理，不伪装成 sealed recipient）。`custodians[]` 非空，custodian
ID、receipt key 和 fault domain 均唯一；仅对存在的 recipient key ref 要求彼此唯一，每个 present
recipient public key/profile/key ID
按 §6.2 strict SPKI 与映射重算。receipt public key必须严格解码为 32-byte
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
一次真实 unseal/HSM-sign 测试。

availability root 对按 custodian ID 排序的 `RecoveryKeyCustodyAvailabilityLeafV1`，custody root 对按
key ID 排序的 `RecoveryKeyCustodyLeafV1`，都使用 §7.1 RFC 6962 规则；leaf 中 hash 必须由同行 exact
对象重算。`availability_receipts[]` 是 proposal 固定的门槛子集，不要求所有 custodians 都签，但
每项必须来自列表中唯一 custodian、数量至少达到 receipt 门槛且去重 fault domain 至少达到其门槛；
未知、重复、过期或字段不等的 receipt 均拒绝。每把 public policy key 都必须恰有一份 binding，最终 root 必须等于
`RecoveryPolicyV1.private_key_custody_root`。公开 policy/statement/transition/bundle 只暴露该 root；
`RecoveryPrivateCustodyObjectV1` 的 locator、recipient 与 receipt 只交给 ceremony participant 和将要
接管的 control voters，普通客户端不取得。bootstrap、planned rotation intent commit、emergency
Genesis durable install 前，相关 control voters 都必须先持有并验证同一 private object；PoP 证明
当时有人持钥，不能替代此恢复介质可用性门禁。

每个 recovery epoch 必须由且只由一个 canonical `RecoveryStatementBodyV1` 建立。body 使用
§7.1 的 JCS/UTF-8 规则，必须含 `schema=1` 和 `statement_type`，且不含签名数组、
`recovery_statement_hash` 或其他由自身导出的 hash。epoch 0 的 exact variant 是：

```text
RecoveryBootstrapStatementV1
  schema = 1, statement_type = "bootstrap"
  cluster_id, recovery_epoch = 0
  recovery_policy_hash, initial_recovery_key_pop_root
  initial_control_epoch = 0, initial_control_set_hash, initial_control_peer_directory_hash
  initial_control_key_pop_root
  initial_admin_acl_hash, internal_ca_profile_and_anchor_hash
```

失去 quorum 的恢复使用下述 `RecoveryTransitionBodyV1` 全部字段并取
`statement_type="emergency"`；计划轮换使用 §9.4 的
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
`JCS(RecoveryGenesisPayloadV1)))`，其中 `frame` 是 §7.1 的长度前缀 domain framing；它只覆盖
上列 payload，并且 payload 不含 statement hash、
entry hash、Raft term/index 或 QC，因而不存在 transition ↔ genesis 自引用。首个 wire profile
在每条新 recovery lineage 把 `new_control_epoch` 固定重置为 0；实际 Raft term 由新集合选举
产生，首个 log index 和 control revision 固定为 1、`previous_log_entry_hash=EMPTY_HASH_V1`，均由
完整 Genesis HeadEntry 与 QC 绑定，而不是由旧 recovery signer 预选。
校验 transition 时必须逐字节确认 payload 的 `cluster_id/new_recovery_epoch/`
`new_recovery_policy_hash/new_policy_pop_root/new_control_epoch/new_control_set_hash/`
`new_control_peer_directory_hash/new_control_key_pop_root/initial_admin_acl_hash/`
`internal_ca_profile_and_anchor_hash` 与 transition 同名承诺一致，且
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
或 policy hash 直接视为 recovery fork 并失败关闭。Device Merkle leaf 本身按 D105 不重复放
head 坐标，而是由 envelope 中的 certified head/root 间接绑定上述三元组。
同一个 `previous_recovery_statement_hash` 指向两个 canonical bytes 不同的 transition 也始终是
fork，即使它们选择不同的更高 epoch；客户端不得按更大数字、时间或下载源择一。

### 9.4 recovery policy 的计划轮换

有 quorum 时也应定期轮换 recovery 持有人/介质，但当前 ControlSet 不能单独给自己创造新的
最高 authority。新 policy 先在离线环境产生 canonical
`RecoveryPolicyV1{policy_id,generation,algorithm,key_ids_and_public_keys,threshold,`
`private_key_custody_root,ceremony_profile}` 和每把 key/DKG transcript 的 proof-of-possession；私有 share 走
§9.3 `RecoveryPrivateCustodyObjectV1` 的不可变 sealed/KMS exact version、真实 key-test 与离线
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
`intent_operation` 必须是 §7.1 exact operation：
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
阈值，签名条目使用 §9.3 的 exact `RecoveryThresholdSignatureV1`。按 §9.3 计算
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
payload 的 `operation_root/device_views_root/admin_acl_root/ca_profile_root/render_contract_version/`
`min_reader_version/max_clock_skew_seconds` 必须逐字节继承 last head，`snapshot_hash` 与
`effective_ssot_hash` 必须等于该唯一 reducer 输出；logical time/raft index/revision 按 §7.4～§7.5
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

ControlSet quorum 不可用时不存在“计划轮换”：旧 recovery threshold 仍可用则走 §9.3 的
emergency recovery，并明确缺少 control QC；旧 threshold 已丢失时，普通 control quorum 无权
把另一把 key 宣布为连续的新 root，只能创建新 cluster 并逐 Device 带外 rebootstrap。若旧 key
疑似泄露，轮换无法抹去它已经签出冲突 transition 的可能性；客户端必须 fail closed，并通过
独立带外 witness/人工核验决定新锚，产品不得把“已轮换”误报成历史 compromise 已自动消失。

---

## 10. 发布、签名与客户端 anti-rollback

### 10.1 signed current v2

目标 mutable current 不另造一套扁平但字段不全的 head。首版 exact envelope 为：

```text
SignedCurrentV2
  schema = 2
  head: HeadEntryV2
  quorum_certificate: CertifiedHeadQCV1
  published_at                  # 仅缓存/诊断；不参与 authority 排序
```

客户端必须按 §7.4 重算完整 HeadEntry body 的 entry/head hash，并逐字段验证 tagged attestation、
签名 domain、ControlSet、排序/去重和 stable/joint 门槛；`published_at`、HTTP Date、ETag 或 URL
新鲜度都不能替代 head 中的 logical time、Raft 坐标与 floor。

signed current 不放一个含义不明的全局 `endpoint_set_hash`。不同 Device 可以因 role/grant
得到不同 EndpointSet；每个 D105 leaf 的 `endpoint_set_hash` 承诺该 Device 的精确 bytes，
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
  endpoint_sets[]                      # DeviceEndpointSetBindingV1；按 (role,endpoint_set_id) 排序

DeviceEndpointSetBindingV1
  role                                 # §13 role enum
  endpoint_set: EndpointSetV2, endpoint_set_hash

DeviceActiveViewV1
  identity_spki_hash
  membership: EnrollmentMembershipV1, membership_hash
  responsibilities: EnrollmentResponsibilitiesV1, responsibilities_hash
  grants: EnrollmentDestinationGrantsV1, grants_hash
  direction: EnrollmentDirectionV1, direction_hash
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

DeviceViewEnvelopeV2                   # 只由 authenticated role=device_config 返回
  schema = 2
  payload: DeviceViewPayloadV2
  leaf: DeviceViewLeafV2
  leaf_index, tree_size, audit_path[]
  signed_current: SignedCurrentV2
  secret_artifact_refs[]?              # active view root 的 exact private refs；按 §11.2 排序
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
的 cluster/device/generation/state 必须相等，active/tombstone tag 与唯一 variant 一致。active 的四个
授权对象及 hash 必须从 effective state 重算，Membership 必须已完成 §11.2 completion；endpoint
bundle 的每个 EndpointSet exact bytes/hash/role 必须满足 grants 和职责且数组无缺漏，不能只返回
一个裸 endpoint hash；binding hash 必须等于 §13 `EndpointSetV2.digest`，且 set 内所有 endpoint role
都等于 binding role。Service/route/component 的源依赖索引只是 reducer 的失效重算优化，不进入
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

`transition_proof_hash` 是 head entry 的普通被哈希字段：初始 v2 head 中它等于 §10.3 的
`bootstrap_transition_hash`；恢复时等于不含 Genesis/Activation/head/QC 的 threshold-signed
transition proof hash；ControlSet 变化时同样只引用在该 head 之前已经固定的 Joint proof 与
signature-free Final body，不能引用包含自身 head/QC 的完整交付 bundle。无 transition 的普通
head 延续上一适用值。计算 `head_hash` 时不得忽略该字段；完整 delivery bundle 可以包含该 head
与 QC，但其外层 hash 永远不写回 head。首次 bootstrap 通过先承诺不含它的 payload、再生成
transition、最后生成完整 head 的单向 DAG 避免自引用。

### 10.2 floor 与 recovery lineage

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

### 10.3 v1 → v2 不可逆 latch

为避免 `bootstrap_transition_hash ↔ initial_v2_head_hash` 循环，迁移固定为以下单向对象图：

```text
InitialV2HeadPayloadV1                 # 先生成；不含 transition proof/hash、head hash、QC
  schema = 1, cluster_id, recovery_epoch, recovery_statement_hash, recovery_policy_hash
  control_epoch = 0, control_set_hash, control_peer_directory_hash, control_revision = 1
  snapshot_hash, operation_root, effective_ssot_hash, device_views_root
  admin_acl_root, ca_profile_root, render_contract_version, min_reader_version
  max_clock_skew_seconds

BootstrapTransitionBodyV1ToV2          # signature-free；再 canonicalize
  cluster_id, schema = 1, v1_platform_key_id, v1_platform_key_digest
  v1_device_floor_merkle_root
  recovery_bootstrap_statement: RecoveryBootstrapStatementV1
  recovery_statement_hash
  initial_recovery_key_pop_root
  initial_control_set_hash, initial_control_peer_directory_hash, initial_control_key_pop_root
  initial_admin_acl_hash, internal_ca_profile_and_anchor_hash
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

三个摘要都使用 §7.1 的长度前缀 framing，首版固定为：

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
hash 或 QC。最终 `HeadEntryV2` 按 §7.4 构造：
`head_kind="bootstrap"`，两个 predecessor 均为 `EMPTY_HASH_V1`，Raft index/control revision 为 1，
其余同名 roots/floor 与 initial payload 逐字段一致，包含 `committed_logical_time`，且
`max_clock_skew_seconds` 与 initial payload 相等；transition context
精确等于 `BootstrapHeadContextV1`，且
`transition_proof_hash=bootstrap_transition_hash`。因此构造顺序只有
payload → bootstrap transition body/signature/proof → initial head/QC，不允许把完整 initial head hash
塞回 transition。
Raft term 由初始集合选举产生；首个 v2 log entry/index 和 control revision 在首版固定为 1，
初始 control epoch 按 §9.3 固定为 0。三种 hash/framing 必须提供跨平台黄金向量。

bootstrap 的重复承诺必须逐字段相等：statement 的
`cluster_id/recovery_epoch=0/recovery_policy_hash/initial_recovery_key_pop_root/`
`initial_control_epoch=0/initial_control_set_hash/initial_control_peer_directory_hash/`
`initial_control_key_pop_root/initial_admin_acl_hash/`
`internal_ca_profile_and_anchor_hash` 先导出 body 所带的
`recovery_statement_hash`；body 的 `cluster_id/initial_control_set_hash/`
`initial_control_peer_directory_hash/initial_admin_acl_hash/`
`internal_ca_profile_and_anchor_hash/minimum_reader_version` 必须分别等于 initial payload/head 的
`cluster_id/control_set_hash/control_peer_directory_hash/admin_acl_root/ca_profile_root/min_reader_version`，initial payload 的
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
`SHA-256(0x00 || JCS(BootstrapDeviceFloorLeafV1))`，内部节点、奇数分树和空树规则与 §7.1
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

首次接受完整 v2 head/QC/view proof 时，客户端把 `v2_latched=true`、bootstrap hash 和全部
floor **原子耐久写入**。latch 前只可接受满足 BootstrapTransition 所声明 floor 的受限 v1
配置；latch 后 v1 current、配置、邀请、成员/恢复声明永远不能再成为 authority。迁移期可以
继续用 v1 HTTP 路径搬运 v2 bytes 或发送兼容报告，但传输路径不改变验证规则。客户端状态
丢失只能从可信备份、已钉住 v2 checkpoint/recovery 或带外 rebootstrap 恢复，禁止因“本地
没有 floor”自动退回 v1。

### 10.4 镜像

静态镜像仍然不可信并保留多地址并行拉取。它们只复制公开的 immutable
bootstrap/recovery/ControlSet transition、QC、通用内容寻址制品和 mutable v2 head；不得复制
per-Device view、leaf/proof、私有拓扑或 artifact ref。后者只由 `EndpointSet(role=device_config)`
入口在 Device 身份认证后返回。control 副本内部以内容寻址复制 view 不等于授权公共 publisher
输出它。不同镜像短暂落后是正常；客户端选最高合法连续 head。DNS、镜像顺序和 RTT 只影响
从哪里下载，不能覆盖签名、floor 或 ControlSet。

publisher 不再是某台中控上的 authority。任一 control 副本都可 materialize 相同字节；
只有带 QC 的 head 能更新 mutable current。发布 executor 用租约避免无意义并发，失败后
任何合格副本都可接管。

---

## 11. Enrollment、邀请与报告

### 11.1 邀请 v2

管理员可以连接已信 certified `EndpointSet(role=control_api)` 内的任一入口创建设备；
客户端 claim 则只能使用后续 `InviteBootstrapDescriptorV2` 中的有界
`EndpointSet(role=enroll)` seeds。
复制/提交的记录与一次性交付 envelope 必须
分开；Raft/CRDT/SSOT 永远不含 bearer token 明文：

```text
InviteIssuancePolicyV2
  schema = 2, cluster_id, policy_id, generation
  minimum_ttl_seconds, maximum_ttl_seconds
  maximum_seed_count, maximum_descriptor_bytes

InviteTokenCommitmentInputV2       # canonical preimage；token 是 32-byte CSPRNG 值
  schema = 2, cluster_id, invite_id
  token                            # 无 padding base64url，解码后必须精确为 32 bytes

InviteEnrollSeedV2                # 只允许从 base head 下已认证 enroll listener 逐字段投影
  schema = 2, endpoint_id
  public_endpoint_intent_hash, public_endpoint_intent_generation
  listener_generation, rotation_operation_hash
  https_base_url
  dial_target                     # tagged union：dns_name | ip_literal，恰有一个
  server_name, webpki_profile_ref: WebPKIProfileRefV1
  credential_generation, credential_artifact_hashes[], tls_identity_key_id
  spki_pins[]                     # TlsSpkiPinV1，按 (pin_generation,digest) 排序
  hint_rank                       # 0..seed_count-1 的唯一整数；只表达创建时提示顺序

InviteDeliveryContextV2            # 不含 token、record/head/QC 或自身 hash
  schema = 2, cluster_id, invite_id
  bootstrap_transition_hash
  min_recovery_epoch, recovery_statement_hash, recovery_policy_hash
  control_epoch, control_set_hash
  base_head_hash                   # 创建 intent 的已认证 parent，不是 record_head_hash
  max_clock_skew_seconds           # 0..300；必须等于 base/record head
  seed_enroll_endpoints[]          # InviteEnrollSeedV2；按 endpoint_id UTF-8 bytes 排序

CertifiedInviteRecordV2           # Raft/CRDT 中的 canonical 安全关键记录
  schema = 2, cluster_id, invite_id, record_generation = 1, issued_at, expires_at
  issuance_policy_hash
  record_operation_kind           # create_invite | reissue_invite
  record_operation_id
  device_intent_hash
  token_commitment, token_artifact_binding_hash
  delivery_context: InviteDeliveryContextV2, delivery_context_hash

InviteTokenArtifactBindingV2      # control-private；绝不进入 public proof/QR/mirror
  schema = 2, cluster_id, invite_id, record_operation_id
  token_commitment
  token_artifact_ref: SecretArtifactRefV2
  plaintext_validation_receipts[] # InviteTokenPlaintextValidationReceiptV1，按 renderer_id 排序
  plaintext_validation_receipts_root

InviteTokenPlaintextValidationReceiptBodyV1
  schema = 1, cluster_id, invite_id, record_operation_id
  renderer_id, renderer_identity_key_id, recipient_key: SealedBlobRecipientKeyRefV1
  token_commitment, token_secret_artifact_ref_hash, validated_at

InviteTokenPlaintextValidationReceiptV1
  body: InviteTokenPlaintextValidationReceiptBodyV1
  renderer_signature: AuthorityProofSignatureV1

InviteLifecycleStateV2            # reducer 输出，不由 sender 直接写
  schema = 2, cluster_id, invite_id, lifecycle_generation
  certified_record_hash
  status                          # available | claim_reserved | consumed | revoked
  claim_intent_hash?, retry_not_after?, replaced_by_invite_id?
  last_operation_kind, last_operation_id, last_payload_hash

InviteReissueTransactionV2
  schema = 2, cluster_id, operation_id
  old_invite_id, expected_old_record_hash, expected_old_lifecycle_state_hash
  expected_aborted_enrollment_transaction_state_hash? # 仅 aborted replacement 必需
  new_device_enrollment_intent: DeviceEnrollmentIntentV1
  new_certified_record: CertifiedInviteRecordV2
  reason

InviteRevokeIntentV2
  schema = 2, cluster_id, operation_id, invite_id
  expected_record_hash, expected_lifecycle_state_hash, reason

InviteProofBundleV2               # 无 token；可由任一有界 enroll seed 提供
  schema = 2
  bootstrap_bundle: BootstrapTransitionBundleV1ToV2
  authority_transitions[]         # InviteAuthorityTransitionV2，按 lineage 顺序
  base_head: HeadEntryV2
  base_head_qc: CertifiedHeadQCV1
  device_enrollment_intent: DeviceEnrollmentIntentV1
  certified_record, record_operation       # create_invite 或 reissue_invite exact operation
  record_head: HeadEntryV2
  replication_qc: CertifiedHeadQCV1
  delivery_context
  record_operation_leaf: ControlOperationLeafV1
  record_leaf_index, operation_tree_size, operation_audit_path[]

InviteAuthorityTransitionV2       # exact tagged union
  schema = 2
  kind                            # control_set | emergency_recovery | recovery_policy_rotation
  transition                     # 按 kind 恰为对应的 ControlSetTransitionBundleV1 /
                                 # EmergencyRecoveryBundleV1 / RecoveryPolicyActivationBundleV1

InviteBootstrapDescriptorV2       # QR 与 loom:// 的严格有界 payload
  schema = 2, cluster_id, invite_id, expires_at
  token, token_commitment
  delivery_context, delivery_context_hash
  proof_bundle_hash

InviteOfflinePackageV2            # .loom-invite 可选完整离线载体
  schema = 2
  descriptor: InviteBootstrapDescriptorV2
  proof_bundle: InviteProofBundleV2

DeviceEnrollmentIntentV1
  schema = 1, cluster_id, invite_id, device_id
  platform                          # windows-desktop | android | linux-server
  device_certificate_profile_ref: DeviceCertificateProfileRefV1
  wrapping_key_profiles[]           # p256-keystore-sign-ecdh-v1 |
                                    # rsa2048-keystore-sign-decrypt-v1；按下文 preference 排序
  membership: EnrollmentMembershipV1
  responsibilities: EnrollmentResponsibilitiesV1
  grants: EnrollmentDestinationGrantsV1
  direction: EnrollmentDirectionV1

EnrollmentMembershipV1
  schema = 1, desired_state = "active_on_completion"

EnrollmentResponsibilitiesV1
  schema = 1
  values[]                          # use_loom | forward | internet_egress，按此 enum 顺序

EnrollmentDestinationGrantsV1
  schema = 1
  values[]                          # EnrollmentDestinationGrantV1，按 (kind,target_id) UTF-8 bytes 排序

EnrollmentDestinationGrantV1
  kind                              # service | egress
  target_id

EnrollmentDirectionV1              # exact tagged union
  kind                              # not_applicable | server_direction
  not_applicable?                   # exact empty object
  server_direction?                 # {value: bidirectional | reverse_only | direct_only}
```

两个承诺都采用 §7.1 的 framing/JCS，精确定义为：

```text
token_commitment = H(frame(
  "loom-invite-token-commitment-v2",
  JCS(InviteTokenCommitmentInputV2)
))
invite_issuance_policy_hash = H(frame(
  "loom-invite-issuance-policy-v2", JCS(InviteIssuancePolicyV2)
))
delivery_context_hash = H(frame(
  "loom-invite-delivery-context-v2",
  JCS(InviteDeliveryContextV2)
))
certified_record_hash = H(frame(
  "loom-certified-invite-record-v2",
  JCS(CertifiedInviteRecordV2)
))
invite_token_artifact_binding_hash = H(frame(
  "loom-invite-token-artifact-binding-v2", JCS(InviteTokenArtifactBindingV2)
))
invite_token_plaintext_validation_receipt_hash = H(frame(
  "loom-invite-token-plaintext-validation-receipt-v1",
  JCS(InviteTokenPlaintextValidationReceiptV1)
))
invite_lifecycle_state_hash = H(frame(
  "loom-invite-lifecycle-state-v2", JCS(InviteLifecycleStateV2)
))
invite_reissue_transaction_hash = H(frame(
  "loom-invite-reissue-transaction-v2", JCS(InviteReissueTransactionV2)
))
invite_revoke_intent_hash = H(frame(
  "loom-invite-revoke-intent-v2", JCS(InviteRevokeIntentV2)
))
device_enrollment_intent_hash = H(frame(
  "loom-device-enrollment-intent-v1", JCS(DeviceEnrollmentIntentV1)
))
membership_hash = H(frame(
  "loom-enrollment-membership-v1", JCS(EnrollmentMembershipV1)
))
responsibilities_hash = H(frame(
  "loom-enrollment-responsibilities-v1", JCS(EnrollmentResponsibilitiesV1)
))
grants_hash = H(frame(
  "loom-enrollment-destination-grants-v1", JCS(EnrollmentDestinationGrantsV1)
))
direction_hash = H(frame(
  "loom-enrollment-direction-v1", JCS(EnrollmentDirectionV1)
))
proof_bundle_hash = H(frame(
  "loom-invite-proof-bundle-v2",
  JCS(InviteProofBundleV2)
))
```

`InviteIssuancePolicyV2` 由 admin `ControlOperationV1` 的
`kind="upsert_invite_issuance_policy"`、`payload_schema=2` 与上式 payload hash 提交；operation ID
独立于 policy ID。generation 从 1 连续递增，`60 <= minimum_ttl_seconds <=`
`maximum_ttl_seconds <= 604800`，`1 <= maximum_seed_count <= 3`，
`512 <= maximum_descriptor_bytes <= 1800`。create/reissue record 的 policy hash 必须解析到 base head
中的 exact policy；`issued_at < expires_at`，其差值位于 policy min/max 内，candidate logical time
和创建节点可信墙钟都必须在 issued_at 的 `max_clock_skew_seconds` 容差内且严格早于 expires_at。
已过期或超长期的新 record 不能 commit；旧 expired available record 仍可作为 reissue 的被撤销端。
context 的 seed 数量必须同时满足 `1..policy.maximum_seed_count` 与协议硬上限 3；policy 不是只供
UI 显示，所有 voter 都必须从 base head 解析同一代 policy 后重验。

`CertifiedInviteRecordV2` 是可进入无 token public proof 的最小投影，所以只承诺 private binding
hash，不含 `SecretArtifactRefV2`、backend locator、recipient 或 availability receipt。
`InviteTokenArtifactBindingV2` 的 cluster/invite/record operation/token commitment 必须与 record
逐字段相等，内嵌 ref 必须为 §6.2 purpose=`invite_token` 且重算 availability/policy/hash 成功；所有
stable voters 在 invite head commit 前经 private control channel 持久保存同一 binding bytes/hash。
ref 的 `proposal_id=record_operation_id`、owner 必须是创建 principal 的 control Device，sealed
recipients 必须逐字节等于 ref 的 certified availability policy 中 purpose=`invite_token` 的 renderer
reporters/recipient key refs。每份 plaintext receipt 的 renderer/key/recipient ref 必须解析到
该 policy/ref；`renderer_signature.algorithm/key_id` 必须逐字段等于 policy 中该 renderer 的 exact
`AuthorityProofKeyV1`，并按 §6.2 的算法、长度和 canonical base64url 规则验签。signature 覆盖
`frame("loom-invite-token-plaintext-validation-signature-v1", JCS(body))`；renderer 在签名前必须实际
解封 token、严格得到 32 bytes，并按 record invite ID 重算 commitment 相等。root 对按 renderer ID
排序的 `{schema:1,renderer_id,receipt_hash}` leaves 使用 §7.1 RFC 6962 算法，数量、fault domain 和
age 必须至少满足 ref 的 availability policy。缺 receipt/preimage equality 时 invite 不得 commit，
不能等 QC 后才让 renderer 发现 artifact 与 commitment 不同。
renderer 在 commit 前只可经 control-private、proposal-scoped validation capability 读取/解封并签上式
plaintext receipt；这不是 bearer delivery，结果不得离开 voter proposal sidecar。面向管理员的一次性
创建响应必须等 invite certified 后，才允许具 delivery capability 的 renderer 再读取同一 exact
binding 并输出 token；公开 enroll proof GET、InviteProofBundle、QR、Device view 和 mirror 永远只能
看到 binding hash。缺 private preimage 的副本可验证公开 record/QC，但不能验证或交付 token。

proof bundle 内的 `device_enrollment_intent` 必须重算为 record 的
`device_intent_hash`，其 cluster/invite ID 与 record 相等，device ID 与创建时保留的
唯一 Device 相等。四个子对象都严格解码；数组按 schema 顺序排序去重，未知
platform/responsibility/grant kind/direction 失败关闭。responsibilities 非空，
`internet_egress` 必须同时有 `forward`，只有 `use_loom` 可携非空 grants；
Windows/Android 首版只允许 `use_loom`，Linux 才可组合三种职责。包含
`forward` 时 direction 必须是 `server_direction`，否则必须是
`not_applicable`。`server_direction` 三个值精确沿用主设计 §2.2：`bidirectional` 允许双向建隧道，
`reverse_only` 只允许该 server 主动发起，`direct_only` 只允许对端主动直连；三者均只允许
`platform=linux-server` 且 responsibilities 含 `forward`。每个 grant target 必须在 base head 中解决到同 cluster 的 certified
Service 或 egress Device；显示名、客户端自报或 claim endpoint 不得改写该 intent。
`wrapping_key_profiles[]` 非空、无重复，只能使用 §6.2 两个已知 profile，并按
`p256-keystore-sign-ecdh-v1 → rsa2048-keystore-sign-decrypt-v1` preference 子序列排序。Windows/Linux
首版必须至少支持 P-256；Android intent 若支持仓库现行 API 26 最低版本则必须同时允许 RSA fallback，
API 31+ 客户端选择 P-256，API 26–30 选择 RSA。profile 是客户端按本机 Keystore 能力做的有界选择，
不是 server/leader 根据默认值代选；不在 intent 列表中的选择必须拒绝。
`device_certificate_profile_ref` 必须在同一 base head 的 `ca_profile_root` 解析到唯一 exact
`DeviceCertificateProfileStateV1(status=active)`，并重算其中完整 intent/state 两层 hash；
base/candidate 两种可信时间都在其 issuance window 内，
且 intent 的 platform 与全部 responsibilities 都属于 profile 的有界数组。profile 不唯一不构成
歧义，因为 invite 已选择 exact ref；staged/retired/revoked、过期或后来被更高 generation 取代的 ref
均不得创建新 invite，已有 invite claim 时也必须重新检查并在失效时 reissue。

`base_head_hash` 只指向创建 intent 已认证的 parent，避免
`record → delivery_context → record_head → record` 的哈希环。完整 context 作为 record 的内嵌
canonical bytes 随 operation/head 耐久复制，record 同时承诺其 hash；proof bundle 和 descriptor
只能逐字节复用这份 preimage，不依赖 renderer、本地缓存或从 hash 反查未复制的对象。真正最低可消费 head 就是 proof bundle
携带且包含 `CertifiedInviteRecordV2` 的 `record_head`；客户端必须验证其 QC、记录 inclusion 和从
context checkpoint 到 record head 的连续 transition/head proof，不能相信 renderer 另报的
`min_head_hash`。context 的 seed 是有界集合而非发现机制，其完整对象必须与 record 中 hash 相符。

每个 `InviteEnrollSeedV2` 必须逐字段投影自 `base_head` 已 certified effective state 中一个
`role=enroll, protocol=https` 的 `LogicalEndpoint` 及其当时 `preferred` 或仍可接收新连接的
`advertised` listener：intent hash/generation、listener generation、最后 phase hash、规范化 base
URL/dial target、TLS identity/profile、credential generation 和完整有效 pin 集合都必须相等。
seed 的 `credential_artifact_hashes[]` 也必须逐字节等于 listener/spec 的排序数组并为
PublicEndpointIntent 授权数组的非空子集；这里只公开内容 hash，不把 `SecretArtifactRefV2` 或
backend locator 放进二维码。
`tls_identity_key_id` 固定为该 listener 当前 DER SPKI 的小写 `sha256:` digest，并必须等于同
credential generation 的一个 pin digest。候选 reducer 从 base head state 执行这个确定性 subset
校验；invite QC 不能把任意 URL/pin 自己变成新的公网入口。一个 endpoint ID 在 context 中至多
出现一次，seed 数量为 `1..min(policy.maximum_seed_count,3)`；数组始终按 endpoint ID 排序，`hint_rank` 才保存创建时控制面观测给出
的 0..N-1 无重复提示名次。因此 Web 测量不会改变 canonical 数组顺序或产生另一份 context hash，
客户端也不得把 hint 当 authority 或替代当前底层网络上的有界竞速。

`authority_transitions` 是序列而非集合排序：从 initial head 的 recovery/control `(0,0)` 开始，
`control_set` 只能在同一 recovery epoch 将 control epoch 精确加 1，两个 recovery variant 只能将
recovery epoch 精确加 1 并把 control epoch 重置为 0；每项必须以前一项验证出的 authority
验证自身 old/previous 字段。拒绝未知 tag、epoch 缺口、重复、倒序和多 variant。序列结束后的
authority 必须与 delivery context 的 recovery/statement/policy/control/set 五元组逐字段一致；
`base_head` 必须在该 authority 下有合法 `CertifiedHeadQCV1`，且其 hash 等于 context
`base_head_hash`：普通 head 使用 stable QC，作为 ControlSet transition Final 的 head 使用其
old/new joint head QC；tag 与 head kind 不匹配时拒绝。
创建 invite 使用 expected-head CAS，所以 `record_head.parent_head_hash` 必须直接等于 base head；
不需要把无 authority 变化的全部普通 head 塞入数组。`record_head` 必须是
`head_kind="ordinary"`、context 精确为 `{schema:1,kind:"ordinary"}`，其 recovery/control 五元组
与 base head 及 delivery context 逐字节一致，`control_peer_directory_hash` 与
`transition_proof_hash` 逐字节继承 base head。
它必须由当前稳定 ControlSet 的 `StableHeadReplicationQCV1` 认证；在 Joint 期间由于
§9.1 冻结普通提交，不存在可创建 invite 的 joint ordinary head。bundle 的
`replication_qc` 类型/全部 attestation 字段必须与该 record head 一致，不得把创建
invite 偷换为 control/recovery transition。
context 的 `max_clock_skew_seconds` 必须等于 base head 和 record head 的签名字段；扫码前只可在
0..300 硬上限内用于 pin 时间容差，proof 验证后任一不等即拒绝。
验证 initial head/QC 前必须先验证 `bootstrap_bundle`：从其中的 initial recovery policy、initial
ControlSet 及两类完整 PoP arrays 重算 policy/set hash 与 PoP roots，确认它们与 bootstrap
statement/body/head 逐字段相等，再用该 ControlSet 的 config keys 验初始 QC。每个
emergency/policy transition 同理必须携带并验证 wrapper 中的新 public
policy，emergency 还必须携带新 ControlSet；缺 public key bytes 时不能仅凭 hash 继续。
还必须从 `bootstrap_bundle.initial_head_entry.initial_payload` 重算 bootstrap body 的 payload hash，
并确认 descriptor context 的 `bootstrap_transition_hash` 等于
`bootstrap_bundle.transition_proof` 重算出的 proof hash；两者任一不等即拒绝。

邀请记录 inclusion 使用 §7.1 的累计操作树。`record_operation` 只能是以下两个 exact variant：

- 首次创建：`kind="create_invite"`、`payload_schema=2`，payload 精确为
  `CertifiedInviteRecordV2`，`payload_hash=certified_record_hash`；
- 重新签发：`kind="reissue_invite"`、`payload_schema=2`，payload 精确为
  `InviteReissueTransactionV2`，`payload_hash=invite_reissue_transaction_hash`，且 transaction 内
  `new_certified_record` 必须逐字节等于 bundle 顶层 `certified_record`。

首次创建时 outer/record 的 cluster 相等且
`outer.operation_id == record.record_operation_id`。重新签发时
`outer.cluster_id == transaction.cluster_id == new_record.cluster_id` 且
`outer.operation_id == transaction.operation_id == new_record.record_operation_id`；old/new invite ID
必须不同，new record 的 `record_operation_kind="reissue_invite"`，首次 record 则为
`"create_invite"`。其他 kind、任一三方 equality 不成立或把 transaction hash 冒充 record hash 均拒绝。
outer 的 `base_recovery_epoch/base_recovery_statement_hash/base_recovery_policy_hash` 必须等于
context 的 minimum recovery 三元组，`base_control_epoch/base_control_set_hash` 等于 context
control 坐标，`base_control_revision` 等于实际 base head revision，且
`parent_head_hash == delivery_context.base_head_hash == base_head.head_hash`。再重算完整 operation 的
`object_id` 与 `ControlOperationLeafV1`。客户端验证 leaf、index/tree size 和
`operation_audit_path` 后结果必须精确等于 `record_head.operation_root`；proof bundle 仅携带
record/head/QC 而没有该路径时不可消费。

首次创建把不存在的 invite 归约为 `InviteLifecycleStateV2(lifecycle_generation=1,status=available)`。
重新签发通常只允许 base head 中 old invite 仍为 `available`（因此从未 claim/撤销）且未被另一
transaction 锁定；另一个唯一入口是 old invite 已因 §11.2 matching
`EnrollmentTransactionStateV1(status=aborted)` 成为 `revoked`，且其 `replaced_by_invite_id` 仍缺失。
允许已过期但未领取的 record 重签，旧 token 始终不可恢复。
transaction 必须从该 state/record bytes 重算两个 expected hash，新 invite ID 必须全局未使用，
new record/token commitment/private artifact binding/context 必须全新。其内嵌新 Device intent 的
Device ID、platform、Membership、Responsibilities、grants 与 direction 除 `invite_id` 外必须逐字节
等于 old record 所指 intent。若旧 `device_certificate_profile_ref` 在 reissue parent 仍是 latest active
且处于 issuance window，新 ref 也必须相等；若旧 ref 已 staged/retired/revoked/过期或被高代取代，
reissue admin 必须在 new intent 中显式选择该 parent `ca_profile_root` 中另一个 exact ref；reducer 只
验证它是其自身 profile ID 的 latest generation、active/in-window 且与相同
platform/responsibilities scope-compatible，不在多个 profile ID 间运行“latest/最合适”selector。继续
引用旧失效 ref 必须拒绝。旧、新 intent bytes 均随 transaction 交付并按各自
record hash 重算，所以这个唯一例外不能被用来修改其他授权字段；new record 必须绑定该新 intent hash。一个 certified reducer step 原子完成 old
`available→revoked`，或对 matching aborted old 做一次
`revoked(unreplaced)→revoked(replaced_by_invite_id=new)` metadata CAS（两者都 generation +1），并创建
new `absent→available`；aborted 分支还必须携带并 CAS matching
`expected_aborted_enrollment_transaction_state_hash`，原子把 transaction 的
`replaced_by_invite_id` 设为 new；available 分支必须缺失该字段。不能只创建新码或先暴露新 token。
old token/artifact 从该 head 起永久不能
claim；new token 仅在 reissue head/QC certified 后由一次性响应交付。

显式作废使用 `kind="revoke_invite"`、`payload_schema=2`、payload 为
`InviteRevokeIntentV2` 且 hash 为 `invite_revoke_intent_hash`；outer/payload operation ID 相等，
expected record/state 必须匹配 base head，reducer 只允许 `available→revoked`。claim operation 则在
同一 certified head 把 `available→claim_reserved` 并绑定 `claim_intent_hash` 以及唯一导出的
`retry_not_after = claim_head.committed_logical_time + 3600 seconds`；它只占用 token/Device ID，不激活
Membership、Device view 或 credential。completion head 才把 `claim_reserved→consumed`；abort head
则把它变成 `revoked`。available 必须缺失两个 reservation 字段；reissue 或 abort 产生的 revoked 可
保留它们用于审计，只有一次 reissue metadata CAS 可补 `replaced_by_invite_id`。consumed/revoked 均
不可回退或复活，`claim_reserved` 只能走 §11.2 的 exact complete/abort 边，不能直接 reissue/revoke。

descriptor、context、record 与 `record_operation.body.cluster_id` 必须相等；invite ID 还必须等于
create payload record 或 reissue payload new record 的 invite ID。operation 通过重算 payload hash
绑定 record，leaf 只通过 `operation_id/object_id` 绑定 operation，proof bundle 则通过其所携带这些
对象建立同一 cluster/invite 链。
客户端从 descriptor token 重算的 commitment 必须同时等于 descriptor 与 record 的
`token_commitment`；record 内嵌 context 必须重算为自身 `delivery_context_hash`，且该 hash 同时等于
descriptor；bundle 与 descriptor 的 context 都必须逐字节等于 record 内嵌 context。下载或离线取得的
bundle 重算 hash必须等于 descriptor `proof_bundle_hash`。descriptor 的 `expires_at` 必须逐字节等于
record 的 `expires_at`，并按 §7.5 同时通过 certified logical time 与本地可信墙钟检查。任一不等都
不得发送 token。

`pending` 或 `committed_not_certified` 阶段只返回不含 token/交付载体的 operation status；即使创建端
已经按 §6.2 预生成 token，也必须等邀请 head/QC certified 后才输出可消费载体。二维码与
`loom://enroll/v2#d=<base64url(JCS(descriptor))>` 只携带同一
`InviteBootstrapDescriptorV2`。最终 ASCII URI 必须同时不超过 resolved policy 的
`maximum_descriptor_bytes` 与协议硬上限 1800 bytes。提案方必须在计算
`delivery_context_hash`、record 与 proof-bundle hash **之前**，从 base head 的 certified 集合中
固定 `1..min(policy.maximum_seed_count,3)` 个 seed 和 hint ranks，按最终 exact descriptor bytes
预验 URI 大小。若保留一个 seed 仍超过任一上限，同一提案从一开始就标记为 file-only；预验时对尚未产生的
proof bundle digest 使用同一 wire 格式的固定长度占位值，certified 后再用实际 digest 复核，
但不改 context。file-only 的 certified invite 只输出
`.loom-invite` 的 `InviteOfflinePackageV2`，不生成 QR/URI。QC 形成后 renderer 禁止删减、重排
或替换 seed/pin，因为任何改动都会破坏 record 已承诺的 context hash。

扫码客户端严格解码 32-byte token 并重算 token/context commitment，然后先从 context 中已钉住的
`role=enroll` seed 获取与 `proof_bundle_hash` 相同的 immutable `InviteProofBundleV2`；该 GET 不得在
URL、header、cookie 或 body 中发送 claim token，必须先验证精确 URL、hostname/WebPKI、SPKI pin，
禁止重定向。下载后验证 record inclusion、head/QC 和连续 proof，全部成功才允许 POST claim
token。renderer 不能在 QC 到达后临时替换 token、seed、pin 或 recovery checkpoint，也不能把
descriptor/proof bundle 反写进复制日志。

邀请载体不携带长期私钥、完整 SSOT、数据入口选择或固定出口。seed 的 `hint_rank` 可以由控制面
已有 Web 观测产生，但按 endpoint ID 排列的 canonical 列表和 checkpoint 必须由同一 certified head
绑定；提示名次不是权限，
客户端仍按自己当前网络做有界竞速/故障切换。DNS 只解析这些已签 endpoint，不能发现并
信任列表外的新 controller。由于 token 是 bearer secret，首次 proof GET 与 POST 前还必须同时验证
hostname/WebPKI 和 descriptor context 中该 seed 的 TLS SPKI pin；禁止重定向。证书轮换时，当前与 staged
next pin 可以在短邀请 TTL 内重叠，旧 TLS key 至少保留到相关 invite 失效或被显式作废。

`min_recovery_epoch/recovery_statement_hash/recovery_policy_hash` 是不可拆分的 checkpoint：
客户端低于它时必须先验证完整 recovery transition chain；处在相同 epoch 却任一 hash 不同
时，在发送 token 前按 recovery fork 失败关闭。URL、DNS 新鲜度或更大的普通 control revision
都不能覆盖这个比较。

### 11.2 claim

第三把 enrollment key 不是未使用的备用 key，也不替代 Raft/config QC。claim 的 committed intent 与
提交后 approval 使用以下 exact wire：

```text
EnrollmentApprovalIntentV1           # 作为 claim operation 进入 HeadEntryV2.operation_root
  schema = 1, cluster_id, invite_id, request_id, device_id
  certified_invite_record_hash, token_commitment
  device_enrollment_intent_hash, claim_request_body_hash
  claim_facts: DeviceClaimFactsV1
  csr_hash, identity_spki_hash
  wrapping_key_descriptor_hash
  membership_hash, responsibilities_hash, grants_hash, direction_hash
  device_certificate_issuance_intent: DeviceCertificateIssuanceIntentV1
  device_certificate_issuance_intent_hash
  secret_artifact_refs_root
  initial_device_view_payload: DeviceViewPayloadV2, device_view_hash
  initial_device_view_leaf: DeviceViewLeafV2, device_view_leaf_hash

DeviceCertificateIssuanceIntentV1
  schema = 1, cluster_id, issuance_id, request_id, device_id
  csr_hash, identity_spki_hash
  certificate_profile_ref: DeviceCertificateProfileRefV1
  issuer_certificate_hash, issuer_chain_hash, issuer_key_artifact_hash
  serial_number                    # 20-byte positive integer，无 padding base64url，最高 bit 必须为 0
  not_before, not_after
  subject_alt_names[], eku_oids[], policy_oids[]
  tbs_certificate_der, tbs_certificate_hash

DeviceCertificateProfileRefV1
  profile_id, generation
  device_certificate_profile_intent_hash, device_certificate_profile_state_hash

IssuanceLogCoordinateV1
  recovery_epoch, raft_index

DeviceCertificateProfileIntentV1          # admin-signed、可在 Raft 分配坐标前构造
  schema = 1, cluster_id, profile_id, generation
  expected_previous_profile_state_hash?
  target_status                      # staged | active | retired | revoked
  issuer_id, issuer_generation, issuer_fencing_epoch
  issuance_not_before, issuance_not_after
  revocation_reason?                 # issuer_compromise | administrative；仅 revoked 必需
  profile_kind = "loom-device-x509-v1"
  issuer_certificate_der, issuer_certificate_hash
  issuer_chain_der[], issuer_chain_hash, issuer_key_artifact_hash
  allowed_platforms[], allowed_responsibilities[]
  validity_seconds, allowed_subject_key_algorithm = "p256"
  signature_algorithm = "ed25519", subject_mode = "empty"
  san_uri_prefix, key_usage_bits[]
  basic_constraints_ca = false
  required_eku_oids[], required_policy_oids[]
  extension_order_oids[]

DeviceCertificateProfileStateV1           # reducer 从 intent + 承载 Head 坐标派生
  schema = 1, cluster_id, profile_id, generation
  profile_intent: DeviceCertificateProfileIntentV1
  device_certificate_profile_intent_hash
  status, status_changed_at
  issuance_cutoff?                   # IssuanceLogCoordinateV1；terminal state 必需

IssuedDeviceCertificateV1
  schema = 1, cluster_id, issuance_id
  device_certificate_issuance_intent_hash
  certificate_der, certificate_chain_der[]

IssuedDeviceCertificateLogEntryBodyV1
  schema = 1, cluster_id
  issued_certificate: IssuedDeviceCertificateV1, issued_device_certificate_hash
  issuance_authority_head_hash
  recovery_epoch, recovery_statement_hash, recovery_policy_hash
  control_epoch, control_set_hash, ca_profile_root
  certificate_profile_ref: DeviceCertificateProfileRefV1
  committed_logical_time
  raft_term, raft_index, previous_log_entry_hash

IssuedDeviceCertificateLogEntryV1
  body: IssuedDeviceCertificateLogEntryBodyV1
  entry_hash

DeviceClaimFactsV1
  schema = 1
  platform                           # windows-desktop | android | linux-server
  architecture                       # amd64 | arm64 | armv7
  client_protocol_version, client_build_id

DeviceWrappingKeyDescriptorV1
  schema = 1, cluster_id, invite_id, request_id, device_id
  generation = 1
  profile                            # 从 intent 的 wrapping_key_profiles[] 选择一个 exact enum
  sealing_policy_hash                # §6.2 profile→canonical policy 的唯一映射
  wrapping_spki_der, wrapping_spki_hash, wrapping_key_id

EnrollmentClaimRequestBodyV1
  schema = 1, cluster_id, invite_id, request_id, device_id
  certified_invite_record_hash, token_commitment, device_enrollment_intent_hash
  claim_facts: DeviceClaimFactsV1
  csr_der, csr_hash, identity_spki_der, identity_spki_hash, claimant_key_id
  wrapping_key: DeviceWrappingKeyDescriptorV1, wrapping_key_descriptor_hash

EnrollmentClaimRequestV1
  body: EnrollmentClaimRequestBodyV1
  claimant_signature: ClaimantSignatureV1
  wrapping_key_possession_signature: WrappingKeyPossessionSignatureV1

EnrollmentClaimSubmissionV1             # HTTPS transport-only；不进入 object hash、Raft 或 receipt
  schema = 1
  token                                  # descriptor 同一无 padding base64url 32-byte token
  claim_request: EnrollmentClaimRequestV1

ClaimantSignatureV1
  algorithm = "ecdsa-p256-sha256", claimant_key_id
  signature                         # 无 padding base64url；raw r||s，精确 64 bytes，low-S

WrappingKeyPossessionSignatureV1
  algorithm, wrapping_key_id         # ecdsa-p256-sha256 | rsassa-pkcs1v15-sha256
  signature                          # P-256: raw low-S r||s 64 bytes；RSA: raw 256 bytes

InviteTokenValidationAttestationBodyV1
  schema = 1, attestation_type = "invite_token_validation"
  cluster_id, claim_request_body_hash, claim_intent_hash
  invite_id, request_id, device_id
  certified_invite_record_hash, token_commitment
  record_expires_at, validated_at
  parent_head_hash
  recovery_epoch, recovery_statement_hash, recovery_policy_hash
  control_epoch, control_set_hash

StableInviteTokenValidationProofV1
  schema = 1, proof_type = "stable_invite_token_validation"
  attestation: InviteTokenValidationAttestationBodyV1
  signatures[]                       # ControlEnrollmentSignatureV1
  signer_refs[]

EnrollmentClaimOperationBodyV1       # token-authorized；不是 admin ControlOperationBodyV1
  schema = 1, cluster_id, operation_id
  claim_request_body_hash, claim_preparation_hash
  kind = "claim_invite", payload_schema = 1, payload_hash

EnrollmentClaimOperationV1
  body: EnrollmentClaimOperationBodyV1
  claim_request_body: EnrollmentClaimRequestBodyV1
  intent: EnrollmentApprovalIntentV1

EnrollmentClaimPreparationV1        # request_id keyed、无外部 authority 的 durable first-result record
  schema = 1, cluster_id, request_id, claim_request_body_hash
  certified_invite_record_hash, device_enrollment_intent_hash
  prepared_logical_time
  intent: EnrollmentApprovalIntentV1

EnrollmentClaimPreparationLogEntryBodyV1
  schema = 1, cluster_id
  preparation: EnrollmentClaimPreparationV1, claim_preparation_hash
  preparation_authority_head_hash
  recovery_epoch, recovery_statement_hash, recovery_policy_hash
  control_epoch, control_set_hash
  committed_logical_time
  raft_term, raft_index, previous_log_entry_hash

EnrollmentClaimPreparationLogEntryV1
  body: EnrollmentClaimPreparationLogEntryBodyV1
  entry_hash

EnrollmentSecretArtifactRefLeafV1
  schema = 1, purpose, secret_id, generation, secret_artifact_ref_hash

EnrollmentApprovalAttestationBodyV1  # 仅在 claim head committed/apply 后产生
  schema = 1, attestation_type = "enrollment_approval"
  cluster_id, claim_intent_hash
  recovery_epoch, recovery_statement_hash, recovery_policy_hash
  control_epoch, control_set_hash
  raft_term, raft_index, claim_head_entry_hash, claim_head_hash
  invite_id, request_id, device_id
  device_enrollment_intent_hash, platform
  csr_hash, identity_spki_hash, wrapping_key_descriptor_hash
  device_view_hash, device_view_leaf_hash
  device_certificate_issuance_intent_hash, issued_device_certificate_hash
  issued_device_certificate_log_entry_hash
  issuance_recovery_epoch, issuance_raft_term, issuance_raft_index, issuance_committed_logical_time
  issuance_authority_head_hash
  secret_artifact_refs_root
  approved_at
  retry_not_after

StableEnrollmentApprovalQCV1
  schema = 1, qc_type = "stable_enrollment_approval"
  attestation: EnrollmentApprovalAttestationBodyV1
  signatures[]                     # ControlEnrollmentSignatureV1
  signer_refs[]

EnrollmentTransactionStateV1       # reducer 输出；claim 不直接激活 Device
  schema = 1, cluster_id, request_id, invite_id, device_id
  claim_operation_object_id, claim_request_body_hash, claim_intent_hash
  claim_recovery_epoch, claim_raft_term, claim_raft_index
  reserved_at, retry_not_after
  status                            # reserved | completed | aborted
  completion_operation_id?, completion_attestation_hash?
  abort_intent_hash?, replaced_by_invite_id?

EnrollmentCompletionOperationBodyV1 # approval-QC-authorized；不是 admin operation
  schema = 1, cluster_id, operation_id
  request_id, invite_id, device_id
  expected_enrollment_transaction_state_hash
  claim_intent_hash, enrollment_approval_attestation_hash
  kind = "complete_enrollment", payload_schema = 1
  payload_hash = enrollment_approval_attestation_hash

EnrollmentCompletionOperationV1
  body: EnrollmentCompletionOperationBodyV1

EnrollmentAbortIntentV1             # 由普通 admin ControlOperationV1 承载
  schema = 1, cluster_id, operation_id, request_id, invite_id, device_id
  expected_enrollment_transaction_state_hash
  reason                             # retry_expired | administrator_cancel |
                                     # authority_invalidated | certificate_profile_revoked

EnrollmentApprovalReceiptV2
  schema = 2
  intent: EnrollmentApprovalIntentV1
  claim_operation: EnrollmentClaimOperationV1
  claim_preparation: EnrollmentClaimPreparationV1
  claim_request: EnrollmentClaimRequestV1
  token_validation_proof: StableInviteTokenValidationProofV1
  operation_leaf, leaf_index, operation_tree_size, operation_audit_path[]
  claim_head, claim_head_replication_qc
  enrollment_approval_qc: StableEnrollmentApprovalQCV1
  completion_operation: EnrollmentCompletionOperationV1
  completion_operation_leaf, completion_leaf_index
  completion_operation_tree_size, completion_operation_audit_path[]
  completion_head, completion_head_replication_qc
  enrollment_transaction_state: EnrollmentTransactionStateV1
  secret_artifact_refs[]              # exact SecretArtifactRefV2，按 (purpose,secret_id,generation) 排序
  issued_device_certificate: IssuedDeviceCertificateV1
  issued_device_certificate_entry: IssuedDeviceCertificateLogEntryV1
  issuance_authority_head: HeadEntryV2
  issuance_authority_head_replication_qc: CertifiedHeadQCV1
  device_certificate_profile_state: DeviceCertificateProfileStateV1
  issuance_ca_profile_leaf: CAProfileRegistryLeafV1
  issuance_ca_profile_leaf_index, issuance_ca_profile_tree_size, issuance_ca_profile_audit_path[]
  initial_device_view_envelope
```

`claim_intent_hash = H(frame("loom-enrollment-approval-intent-v1", JCS(intent)))`；其余摘要固定为：

```text
claim_request_body_hash = H(frame(
  "loom-enrollment-claim-request-body-v1", JCS(EnrollmentClaimRequestBodyV1)
))
claim_request_proof_hash = H(frame(
  "loom-enrollment-claim-request-proof-v1", JCS(EnrollmentClaimRequestV1)
))
device_wrapping_key_descriptor_hash = H(frame(
  "loom-device-wrapping-key-descriptor-v1", JCS(DeviceWrappingKeyDescriptorV1)
))
claim_preparation_hash = H(frame(
  "loom-enrollment-claim-preparation-v1", JCS(EnrollmentClaimPreparationV1)
))
claim_preparation_log_entry_hash = H(frame(
  "loom-enrollment-claim-preparation-log-entry-v1",
  JCS(EnrollmentClaimPreparationLogEntryBodyV1)
))
device_certificate_profile_intent_hash = H(frame(
  "loom-device-certificate-profile-intent-v1", JCS(DeviceCertificateProfileIntentV1)
))
device_certificate_profile_state_hash = H(frame(
  "loom-device-certificate-profile-state-v1", JCS(DeviceCertificateProfileStateV1)
))
device_certificate_issuance_intent_hash = H(frame(
  "loom-device-certificate-issuance-intent-v1",
  JCS(DeviceCertificateIssuanceIntentV1)
))
issued_device_certificate_hash = H(frame(
  "loom-issued-device-certificate-v1", JCS(IssuedDeviceCertificateV1)
))
issued_device_certificate_log_entry_hash = H(frame(
  "loom-issued-device-certificate-log-entry-v1",
  JCS(IssuedDeviceCertificateLogEntryBodyV1)
))
tbs_certificate_hash = H(frame(
  "loom-device-tbs-certificate-v1", raw_tbs_certificate_der
))
issuer_chain_hash = H(frame(
  "loom-device-issuer-chain-v1", JCS({schema:1,issuer_chain_der})
))
issuer_certificate_hash = H(frame(
  "loom-device-issuer-certificate-v1", raw_issuer_certificate_der
))
token_validation_attestation_hash = H(frame(
  "loom-invite-token-validation-attestation-v1",
  JCS(InviteTokenValidationAttestationBodyV1)
))
token_validation_proof_hash = H(frame(
  "loom-invite-token-validation-proof-v1", JCS(StableInviteTokenValidationProofV1)
))
enrollment_approval_attestation_hash = H(frame(
  "loom-enrollment-approval-attestation-v1", JCS(EnrollmentApprovalAttestationBodyV1)
))
enrollment_transaction_state_hash = H(frame(
  "loom-enrollment-transaction-state-v1", JCS(EnrollmentTransactionStateV1)
))
enrollment_completion_operation_id = H(frame(
  "loom-enrollment-completion-operation-id-v1",
  JCS({schema:1,cluster_id,request_id,invite_id,device_id})
))
enrollment_completion_operation_object_id = H(frame(
  "loom-enrollment-completion-operation-v1", JCS(EnrollmentCompletionOperationV1)
))
enrollment_abort_intent_hash = H(frame(
  "loom-enrollment-abort-intent-v1", JCS(EnrollmentAbortIntentV1)
))
claim_operation_object_id = H(frame(
  "loom-enrollment-claim-operation-v1", JCS(EnrollmentClaimOperationV1)
))
```

claim request signature 覆盖
`frame("loom-enrollment-claim-request-signature-v1", JCS(EnrollmentClaimRequestBodyV1))`；
signature profile 固定为 SHA-256 + NIST P-256 ECDSA；wire 只接受 32-byte big-endian `r` 后接 32-byte
big-endian `s` 的 64-byte raw 编码，且 `1 <= r < n`、`1 <= s <= n/2`。Android Keystore/Windows
产生的 DER 签名必须在边界严格解析、拒绝非最短/负整数后转换为 low-S raw；wire 不接受 DER、
high-S 或可变长度整数。设备 identity 的唯一 key ID 定义为
`device_identity_key_id="sha256:" + lowercase_hex(H(frame(`
`"loom-device-identity-key-id-v1",raw_identity_spki_der)))`；`claimant_key_id` 必须等于从 CSR
SPKI 重算的该值，并用该 key 验签。完成 enrollment 后，certified Device state 将
`(device_id,identity_spki_hash,device_identity_key_id)` 作为同一 generation 的不可拆分身份绑定；
本文所有 `identity_key_id`、`owner_identity_key_id`、`responder_identity_key_id` 以及
`renderer_identity_key_id` 字段，只要其 authority 是 Device identity，都必须逐字段等于该绑定，
不得改用裸 SPKI SHA-256、`identity_spki_hash` 或 provider 自己的 key handle。由于 ECDSA nonce
允许同一 body 有不同合法签名字节，完整 request 是 detached proof：
operation 只内嵌 exact body 并绑定 `claim_request_body_hash`，receipt/proposal sidecar 携 request
signature；`claim_request_proof_hash` 不进入 operation ID/object ID。重签不会制造同 request ID 的
第二个 operation，修改 body 任一字段则 body hash 不同并按冲突拒绝。
wrapping key 必须是与 CSR identity key 不同的 Android Keystore/Windows CNG/Linux restricted-store
不可导出 key。descriptor 的 cluster/invite/request/device 必须等于 request，generation 首次固定为
1，profile 必须是 Device intent 允许列表中客户端选择的一项，`sealing_policy_hash` 必须等于 §6.2
一对一 canonical policy hash。P-256 profile 的 strict DER SPKI 必须是
`id-ecPublicKey + prime256v1`；RSA profile 必须是 `rsaEncryption`（parameters 为 DER NULL）、2048-bit
modulus、public exponent 65537。两者都重算
`wrapping_spki_hash=H(frame("loom-device-wrapping-spki-v1",raw_spki_der))`、
`wrapping_key_id=H(frame("loom-device-wrapping-key-id-v1",raw_spki_der))`。
`wrapping_key_possession_signature` 覆盖
`frame("loom-device-wrapping-key-possession-signature-v1",JCS(DeviceWrappingKeyDescriptorV1))`。P-256
profile 使用前述 strict low-S raw ECDSA；RSA profile 使用 RSASSA-PKCS1-v1_5/SHA-256，wire signature
必须恰为 256-byte raw RSA result。algorithm、SPKI 类型和 descriptor profile 必须完全匹配；identity
key 对完整 claim body 的签名又把 descriptor 绑定到 claimant。封装/解封严格使用 §6.2 exact policy
和 envelope；任何组件不得把签名 identity key 临时当 wrapping/decryption key。
`POST claims` 的 `Content-Type` 固定为 `application/json`，strict body 只能是上式
`EnrollmentClaimSubmissionV1`；未知/重复字段拒绝。客户端只复制本次 descriptor 的 token；seed 解码
后必须精确为 32 bytes，逐字节等于 private binding 解封出的已验证 token，并以 request 的
cluster/invite ID 重算 commitment 同时等于 request、record 与 descriptor。submission 是 bearer
transport envelope，不进入 request/operation/object hash、日志、
缓存或 receipt；重试必须发送相同 token 与 exact `EnrollmentClaimRequestBodyV1`。两份 detached
proof 可重放原 bytes，也可对同一 body/descriptor 重新产生另一份有效签名；服务端只以 body hash
判断幂等，不比较 ECDSA nonce 导致的 signature bytes。取得/持久化 preparation 后立即丢弃 token
transport bytes。token 不得移入 URL/header/cookie，客户端只向 §13 固定的 same-origin
`POST claims` 发送且拒绝重定向。
`csr_der` 是严格 DER PKCS #10，`identity_spki_der` 是其 subjectPublicKeyInfo 的逐字节 DER 投影；两者
使用无 padding base64url。验证器解析 CSR、拒绝 trailing/非 DER/未知 critical attribute，验证 CSR
self-signature，重算 `csr_hash=H(frame("loom-device-csr-v1",raw_csr_der))` 与
`identity_spki_hash=H(frame("loom-device-identity-spki-v1",raw_spki_der))`，并要求 request/intent/TBS/
receipt 的 bytes/hash 全部一致。只给 opaque hash 而没有这两个 preimage 不可 claim。
token-validation signature 覆盖
`frame("loom-invite-token-validation-attestation-v1",`
`JCS(InviteTokenValidationAttestationBodyV1))`。proof signer/ref 排序、去重，并从 parent head 的唯一
stable ControlSet enrollment keys 重算 `floor(N/2)+1`；Joint 期间不产生此 proof。同一 attestation
可因在线 voter 不同而形成多个等价的合法 proof envelope，因此 proof 是 proposal/receipt 携带的
detached authorization evidence，不进入 `EnrollmentClaimOperationV1`、其 object ID 或 operation
tree leaf。所有 envelope 都必须重算相同 attestation hash；签名子集差异不能制造第二个 claim
operation 或触发“同 operation ID 不同 object ID”。
`record_expires_at` 必须等于 exact record；`parent_head.committed_logical_time <= validated_at <=`
candidate claim head logical time，且 candidate 与 validated_at 的差不超过 parent
`max_clock_skew_seconds`。每个 voter 在签 proof 时、所有 voter 在接受 claim entry 时都必须确认
candidate logical time 与接收节点可信墙钟严格早于 record expiry；预签 proof 不能在过期后提交。

Enrollment approval signature
覆盖 `frame("loom-enrollment-approval-attestation-v1", JCS(attestation))`，approval QC hash 使用
`H(frame("loom-enrollment-approval-qc-v1", JCS(exact_tagged_qc)))`。signature/ref 都按
`(member_id,enrollment_key_id)` 排序、拒绝重复；从 claim head 的唯一 stable ControlSet
重算 `floor(N/2)+1` 多数。首版没有 JointEnrollmentApproval QC；§9.1 在 Joint
commit 后冻结普通 entry，因此 claim ordinary head 不可能产生在 Joint 中。若 claim head
已在成员变更前 certified、但 approval 尚未收齐，仍只使用该历史 claim head
绑定的 stable set/enrollment keys；后续 ControlSet 不能改写 quorum，历史 public keys 必须
保留到 §18 GC waterline 越过该 receipt。旧 quorum 无法收齐时该 claim 不得由新集合
补签；reserved transaction 必须先走下述 certified abort，再用全新 invite/request 重新邀请。
approval coordinator 在收集签名前必须线性化确认 issuance entry 所指的 certified authority head
仍是最新 head；存在任何更晚 head、committed-not-certified head 或 Joint 时，不得为同 request
改绑另一个 approval head，reserved transaction 只能 certified abort。所有 signer 均从 receipt 的该 head/QC、exact
profile leaf 与 inclusion path 重算 profile 仍是自身 ID 的 latest active generation、fence 与 issuance
entry 一致。为消除 coordinator 自选时间，`approved_at` 唯一等于
`issuance_committed_logical_time`，且必须不晚于 `retry_not_after`；它是该 issuance 获准收集 approval
的确定性逻辑时间，不声称最后一份签名的墙钟时刻。这样 retire/revoke 已先进入 head 时无法伪造
更早 approval authority，计划 retire 又能用已绑定的 issuance 坐标区分此前结果。
approval attestation 以 `claim_head_entry_hash`、`claim_head_hash` 和 Raft 坐标绑定业务 head，
不绑定某一种合法 config-QC signer subset；receipt 携带的 `claim_head_replication_qc` 必须是对这些
exact bytes 的任一有效 QC。approval QC 自身也允许不同的合法多数 signer envelope，但所有
attestation 字段、transaction facts、artifact refs 与证书必须相同；这些 envelope hash 不作为
request ID 的幂等 object identity。

intent 内嵌的初始 `DeviceViewPayloadV2/DeviceViewLeafV2` 必须按 §10.1 重算
`device_view_hash/device_view_leaf_hash`，其 cluster/device 与 claim 相等、generation=1、state=active、
`previous_view_hash=EMPTY_HASH_V1`。active view 的 identity SPKI、Membership/Responsibilities/grants/
direction 及各 hash、endpoint bundle、config refs 与 `secret_artifact_refs_root` 必须逐字段来自同一
prepared intent；leaf 的 endpoint hash/min reader version 也必须相等。它们是 future completion 的
确定性 bytes：claim/reservation head 只承诺而不把 leaf 放进 active `device_views_root`；completion
reducer 必须逐字节复用，任何重新 render 出的差异都使 completion 失败。

claim head 的 reducer 只创建 `EnrollmentTransactionStateV1(status=reserved)`：claim 坐标取承载
Head 的真实 recovery epoch/term/index，`reserved_at` 等于其 committed logical time，deadline 用 checked
addition 唯一导出；completion/abort/replacement 字段都必须缺失。它同时把 invite 变为
`claim_reserved` 并占用 Device ID、identity/wrapping SPKI、intent、artifact root 与待发布 view leaf，
但 Membership 仍非 active，view/secret 不可向 Device 交付，孤立 CA certificate 也不构成身份。

approval QC 形成后，任一 control 可提交唯一
`EnrollmentCompletionOperationV1`；operation ID 必须等于上式由 request/invite/device 导出的值，
expected state 必须是 matching reserved hash，attestation hash、claim intent 和三组 ID 必须逐字段
相等。approval QC 是 detached authorization evidence：不同合法 signer subset 不进入 completion
object identity；每个 current voter 都重验历史 claim head/config QC、issuance entry/profile proof 与
approval quorum。candidate 必须仍在同一 recovery statement lineage、两种可信时间均不晚于
`retry_not_after`，且当前 profile 未 revoked；若已 retired，只在 issuance coordinate 不晚于 cutoff 且
`approved_at < status_changed_at` 时继续。满足后 completion 作为 special operation 进入 ordinary
Head 的 operation tree并由当前 stable ControlSet config QC certified，原子完成
`reserved→completed`、invite `claim_reserved→consumed`、Membership 激活、初始 view 发布与 artifact
release。state 的 `completion_operation_id` 必须等于
`EnrollmentCompletionOperationV1.body.operation_id == enrollment_completion_operation_id`，
`completion_attestation_hash` 等于 approval attestation hash，abort/replacement 字段
必须缺失；receipt 必须验证 completion leaf/path/head/QC 并携 matching completed state。到这一步之前
API/UI 都只能显示“加入处理中”，不得返回 joined/ready。

无法完成的 reservation 不允许靠数据库删除。管理员以普通、ACL 有界的
`ControlOperationV1(kind="abort_enrollment",payload_schema=1,payload_hash=enrollment_abort_intent_hash)`
提交 `EnrollmentAbortIntentV1`；outer/payload operation ID 必须相等，expected state 必须仍是 reserved。
`retry_expired` 只在 candidate logical time 与可信 wall clock 都晚于 deadline 时成立；
`certificate_profile_revoked` 必须由 current registry exact state证明；`authority_invalidated` 必须证明
recovery statement 已变化或原 approval authority 已按协议失效；`administrator_cancel` 依赖 matching
admin scope。abort head 原子写 `reserved→aborted` 与 invite `claim_reserved→revoked`，释放未激活的
Device ID/Membership/view，保留 transaction/invite/certificate/artifact tombstone 并把未交付 secret
转入 §15 orphan retention。aborted state 只带 `abort_intent_hash`；之后只有 §11.1 的 exact reissue CAS
可填一次 `replaced_by_invite_id` 并创建全新 token/request，旧 token、identity reservation、certificate
与 artifacts 永不复用。这样 CA/profile变化、旧 enrollment quorum 不足或 retry 超时不会留下 active
但永远拿不到 receipt 的 zombie Device。

`secret_artifact_refs_root` 对每个 receipt 携带的 exact `SecretArtifactRefV2` 重算 §6.2 hash，构造
`EnrollmentSecretArtifactRefLeafV1` 后按 `(purpose enum order,secret_id UTF-8 bytes,generation)`
排序去重，并使用 §7.1 RFC 6962 leaf/node/empty-tree 规则。intent、attestation、approval QC 与
receipt 的 root 必须相等；数组不得缺失/额外，leaf purpose/ID/generation 必须逐字段等于 ref。
每个 ref 的 cluster/proposal/owner、availability policy/receipts/PoP 必须重新验证，且恰好满足
Device intent 与初始 view 所需的 credential profile；receipt 是 Device-authenticated 私有载体，
不得把这些 backend refs 发布到 distribution。这样 reader 能从 receipt bytes 重算 root，而不是
相信 server 提供的一个 opaque 摘要。
对本 enrollment receipt 中的每个 ref，`proposal_id` 必须逐字节等于
`intent.request_id == claim_operation.body.operation_id`；owner 必须是 `kind=device` 且 device ID
等于该 purpose 的 committed
credential profile 所指定主体，不能复用其他 request/proposal 生成的 artifact。现有 CA issuer key
等基础设施 ref 不放进这组 Device 交付数组，而由 certificate profile 的 exact hash 独立引用。
凡该组中需要目标 Device 解封的 sealed ref，其 `recipient_key_versions[]` 必须恰含 request
`DeviceWrappingKeyDescriptorV1` 的 `(device_id,generation,wrapping_key_id,profile)`，内嵌 policy/hash
必须精确等于 descriptor profile 在 §6.2 映射的 canonical policy，且该 profile 必须属于 Device intent
允许列表；缺 wrapping PoP、改用 CSR signing key 或加入另一 recipient
一律拒绝。intent、approval attestation/QC 与 request 必须重算同一
`wrapping_key_descriptor_hash`。

同一 request 的服务端派生输入先由 request-ID keyed first-result reservation 固定：leader 在请求
token-validation signatures 前，把完整 `EnrollmentClaimPreparationV1` 作为**不产生 head、不给予
外部 authority**的 `EnrollmentClaimPreparationLogEntryV1` 线性化提交并耐久复制到当前 stable
quorum。entry 的 term/index/previous hash 按 §7.4 指向真实直接 log 前项，body 中 preparation/hash
重算相等，`entry_hash=claim_preparation_log_entry_hash`。`preparation_authority_head_hash` 必须是该
entry 入列时最新 stable certified head，body 的 recovery/control 坐标逐字段投影自它；存在尚未
certified 的 committed HeadEntry 或 Joint authority 时不得提交 preparation。body
`committed_logical_time == preparation.prepared_logical_time`，不得早于 authority head 或前一
time-bearing log entry，且与每个 voter 可信墙钟的差不超过该 head 的 `max_clock_skew_seconds`。
之后任一 Raft entry（包括 claim head）的
`previous_log_entry_hash` 仍指向它当时的真实直接前项，不得跳过该 coordination entry。first writer
固定 `prepared_logical_time`、intent、view leaf、secret refs 与 certificate TBS；后来 seed/leader 对
相同 request-body hash 只能取回同一 preparation bytes，不同 body hash 直接报 idempotency conflict。
该 entry 不能消费 token、签证、发布 view 或触发 executor。claim operation 绑定 preparation hash，
其内嵌 request body/intent 必须逐字节等于 preparation；每个 voter 还要确认 reservation 已 committed
且 invitation 在实际 claim head parent 仍 available，claim head 的 committed logical time 不得早于
prepared time。claim operation 本身不再携 base-head 坐标；
实际 parent/recovery/control authority 由 detached token proof 和承载它的 claim Head/QC 绑定。因此
普通 head 在 preparation 后前进不会产生同 request ID 的第二个 object，依赖已失效则该 preparation
明确失败并要求客户端生成新 request ID。

certificate issuance intent 在 claim head **提交前**固定全部可变输入。`issuance_id` 必须等于
`H(frame("loom-device-certificate-issuance-id-v1", JCS({schema:1,cluster_id,request_id,device_id})))`；
CSR/SPKI 必须等于 claim，`certificate_profile_ref` 必须逐字段等于 exact
`DeviceEnrollmentIntentV1.device_certificate_profile_ref`，并从 parent `ca_profile_root` 唯一解析到
当前最新 `active` profile state；state 内 intent 的 issuer certificate/chain 分别重算
`issuer_certificate_hash/issuer_chain_hash` 并与 intent 相等；SAN、EKU、policy OID 与 Device
platform/responsibilities/profile 完全相等。数组按 DER/UTF-8
canonical bytes 排序去重。serial 固定取
`H(frame("loom-device-certificate-serial-v1", raw_issuance_id_bytes))` 前 20 bytes、清最高 bit，若结果全
零则把末 byte 置 1；`not_before=preparation.prepared_logical_time`，`not_after` 是与 profile
`validity_seconds` 的 checked addition，全部由 first-result preparation 固定。有效期还必须受 §7.5
clock bounds 限制。intent 内嵌对象与 `tbs_certificate_der` 分别重算同名 hash后必须相等。

`loom-device-x509-v1` 的 TBSCertificate 是 DER v3；signature AlgorithmIdentifier 固定为 RFC 8410
`id-Ed25519` 且 parameters 缺失，issuer Name 逐字节取 exact issuer certificate，subject 是空 Name，
SPKI 逐字节取 CSR。validity 精确到 UTC 秒并按 RFC 5280 的 2049 分界选择 canonical UTCTime/
GeneralizedTime。SAN 是唯一、critical 的 URI `san_uri_prefix + canonical device_id`；BasicConstraints
critical/CA=false、KeyUsage critical 且仅 digitalSignature，EKU 与 certificatePolicies 按 profile 的
DER OID bytes 排序去重，SKI 从 subject SPKI SHA-256、AKI 从 issuer SPKI SHA-256 导出；extension 按
`extension_order_oids[]` 排列，禁止 CSR 请求追加字段、重复 extension、未知 critical extension 或
AlgorithmIdentifier `NULL` 参数。完整 `tbs_certificate_der` 是 commit 后 CA 的规范输入；voter 严格
解析并重验上述投影与 raw hash。Go/Android/Windows/CA builder 必须共享 golden DER/hash vectors。

首个 v2 online Device CA profile 固定用 Ed25519 issuer 和唯一 DER builder：相同 exact TBS bytes 与
issuer key version 必须产生逐字节相同证书。CA 在 claim head/config QC 后先线性化读取最新 stable
certified authority head；若存在 committed-not-certified head/Joint、intent 的 profile ref 已非该
head `ca_profile_root` 中同 ID 最新 state、状态非 active、超出 issuance window，或 exact issuer fence/
key-unseal lease 不匹配，就不得签名。通过后以 `issuance_id` 做
durable first-result CAS：不存在时签 exact intent 并原子保存
`IssuedDeviceCertificateV1`，已存在时只返回同一 bytes；同 issuance ID 的不同 object hash 是安全
故障并停止签发。该 CAS 以 `IssuedDeviceCertificateLogEntryV1` 进入当前 control Raft 的
cluster-wide registry，不是 executor 本地文件：term/index/previous hash 指向真实直接 log 前项，
object/hash 重算相等；entry 的 authority head/recovery/control/CA root/profile ref 必须逐字段等于
上述 certified head。entry `committed_logical_time` 不得早于 authority head、preparation/claim head
或前一 time-bearing log entry，必须落在 profile issuance window 与 leaf certificate 有效期内，并与
每个 voter 可信墙钟满足 authority head 的 skew bound；approval attestation 的同名时间必须相等。
该 entry 实际 apply 时再次执行同样的 latest-active/fence CAS。若 revocation
或 retire head 抢先进入 log，迟到签名只能丢弃。entry hash 使用上式 domain；后继 entry 继续链接该
hash。receipt 携带的 exact entry/object/hash 必须相等，approval voter 只在该 entry committed 后签名。
issued object 的
`certificate_chain_der[]` 必须逐字节等于 profile 的
`issuer_chain_der[]`（顺序为 issuing intermediate 起逐级到但不重复 leaf；是否包含 trust anchor 由
profile bytes 固定），不能附另一条也合法的链。enrollment voters 重验 DER chain、serial/time/SAN/
EKU/OID/CSR-SPKI、issuer hashes，再从 receipt 的 issuance authority head/QC、issuance profile leaf 与
RFC 6962 audit path 重算该 head 的 `ca_profile_root`。approval attestation 必须同时绑定
`issued_device_certificate_hash`、`issued_device_certificate_log_entry_hash`、entry recovery epoch/
term/index、issuance authority head hash 与 `approved_at`；receipt 中这些值及 entry 内 authority
坐标必须逐字段相等，不能替换
一个“同证书、不同 log 坐标”的 wrapper。每个 enrollment voter 签 approval 前还要线性化确认该
profile 仍是最新 active 且 fence 未变；否则不得签 approval，reserved claim 必须经 certified abort
后重新邀请。这样 executor 崩溃/换届不能为
同一 claim 生成另一张“也合法”的证书，CA retire/revoke 后的迟到结果也不能取得 approval。

`DeviceClaimFactsV1` 严格拒绝未知 platform/architecture，protocol version 是非负
int64，build ID 是 1..128-byte 规范 UTF-8；整个 exact facts object 已纳入 claim intent
hash，所以幂等重试不能替换其中任一字段。attestation 的
`retry_not_after` 唯一导出为
`claim_head.committed_logical_time + 3600 seconds`，按 §7.1 checked time arithmetic；其
`platform` 必须等于 intent facts 和下述创建意图。

验证器必须重算 intent/request-body/request-proof/attestation/token-proof/operation 各 hash。
detached request 的 body 必须逐字节等于 operation 内嵌 body；其
cluster/invite/request/device、record/token/device-intent、facts、CSR/SPKI/wrapping descriptor 必须与
intent 逐字段相等；operation body 必须是
`kind="claim_invite"`、`payload_schema=1`、`payload_hash=claim_intent_hash`、
`cluster_id=intent.cluster_id`、`operation_id=intent.request_id`，并绑定所携 request-body/preparation
hash；preparation 内嵌 intent 必须逐字节等于 operation payload。实际 parent 的全部
recovery/control 坐标只从 token-validation attestation 与 claim Head/QC 取得并逐字段相等，不能由
special operation 自报一套 base authority。

每个 token-validation voter 只通过 descriptor seed 接收节点转发的 authenticated control-peer RPC
暂时取得 token preimage，重算 commitment，并确认 parent state 的 invite lifecycle 是未过期
`available`、record/request/intent 完全匹配后才签 attestation；token bytes 不进入 attestation、
operation、Raft log 或持久缓存。proof attestation 的全部 request/intent/invite/parent/authority 字段
必须与 exact objects 相等。接收节点向 Raft proposal 携带至少一份完整 detached proof sidecar；每个
voter 在接受 entry 前验证其 quorum、exact attestation equality 与 expiry，并把至少一份合法 proof
作为该 committed claim 的 availability-critical immutable evidence 保存至 §18 waterline。该
threshold proof只证明 quorum 检查过 bearer preimage，不消费 token；
两个并发 proof 最终仍由 Raft lifecycle CAS 决定唯一 winner。

`claim_head.parent_head_hash` 必须逐字节等于
`token_validation_proof.attestation.parent_head_hash`，并在该 parent 的相同 authority 下作为
`head_kind=ordinary`
提交，并由该 stable ControlSet 的 `StableHeadReplicationQCV1` 认证；Joint/final head 或 joint QC
均不可作 claim head。再以 `claim_operation_object_id` 构造 §7.1
`ControlOperationLeafV1`，验证 index/tree size/audit path 精确落到 claim head 的
`operation_root`。`EnrollmentClaimOperationV1` 是 token-authorized 特例，不含 admin cert、
admin signature 或 ACL 扩权；客户端 CSR key 的 request signature、stable enrollment-key token proof、
Raft config QC 三层缺一不可。attestation 的 lineage、ControlSet、Raft/head/QC 坐标与 intent 中重复的
invite/request/device/CSR/SPKI/view/artifact 承诺必须和该 exact intent、HeadEntryV2 及其 config QC
逐字段相等。enrollment voter 只有完成这些检查才签 approval。在线 CA 只有同时验证 claim head 的
config QC 与其中已承诺的 exact issuance intent 后才可执行 first-result signing；enrollment voters
随后把 issued-certificate hash 纳入 approval QC。再由 approval-QC-authorized completion operation 与
current config QC 原子激活。Device 只有同时验证 claim config QC、issued object、enrollment approval
QC 与 completion head/config QC 才接受身份；任何单节点 enrollment signature、仅有 claim config QC、
仅有 CA certificate 或尚未 completion certified 都不能创建有效身份。

该 parent record 重算的 `certified_record_hash` 必须等于 intent 的
`certified_invite_record_hash`；其
`device_intent_hash` 必须在 parent state 解决到 §11.1 exact
`DeviceEnrollmentIntentV1`，并逐字节等于 intent 的
`device_enrollment_intent_hash`。voter 必须重算该对象及 membership/responsibilities/
grants/direction 四个子 hash，要求它们逐字节等于
`EnrollmentApprovalIntentV1` 的四个字段，并要求 cluster/invite/device ID、
`claim_facts.platform`、token commitment 与该 certified record/creation intent 全部相等。
claim 只为 identity CSR/SPKI、独立 wrapping descriptor/PoP 和不改权的客户端事实填值；不能替换 platform、Membership、
Responsibilities、grants 或 direction。

1. Device 在 Keystore/CNG/root-only store 分别生成不可导出的 P-256 identity/CSR key 与按 intent
   有界协商出的 P-256 或 RSA wrapping/PoP key；Android API 26–30 使用 RSA fallback，API 31+ 优先
   P-256。
2. 它只能从本次 `InviteBootstrapDescriptorV2.delivery_context` 直接携带的有界
   `EndpointSet(role=enroll)` seeds 中选择；先验精确 URL、WebPKI 和
   descriptor-carried SPKI pin，并按 §11.1 先无 token 获取/验证 proof bundle，再向其中任一入口提交同一
   `EnrollmentClaimSubmissionV1{token, exact signed request(CSR,wrapping descriptor/PoP,device facts)}`；
   验证失败前不得发送 token bytes。
3. 接收节点执行线性化读取，经 control-peer mTLS 将 token preimage 仅暂时提供给当前 stable set 的
   enrollment voters，取得上述多数 token-validation proof 后把它作为 detached sidecar 提交专用
   claim operation；token 从
   `available` 到 `claim_reserved` 是 Raft 串行 CAS，claim intent 与 reservation 在同一 head
   commit/apply 并取得 replication QC 后才成为 certified；在此之前不得签证。reservation 不激活
   Device、不发布 view，也不交付 secret。
4. 同 token、exact request body（含 CSR、wrapping descriptor、request ID 与 facts）的重试只在
   approval attestation 的
   `retry_not_after` 内返回同一不可变 transaction facts/artifacts；receipt 可携带任一对相同
   body/descriptor 有效的 claimant/wrapping detached proof，以及任一对相同 attestation 有效的
   token-validation/head/approval QC envelope；签名字节/签名子集不属于业务幂等身份。
   接收节点必须同时确认其最新
   certified head logical time 和可信 wall clock 都不晚于该 deadline；wall clock 不可用时
   fail closed。超时后 token 不再是 recovery credential，不同 facts 或 CSR 永久拒绝。
5. identity/wrapping SPKI、Membership、职责、grants、满足 §6.2 availability/PoP 且只向该 wrapping
   key 封装的 exact-version secret artifact root、exact Device certificate issuance intent 和初始 Device view leaf 在同一
   claim 提交中绑定。
6. 在线 CA 验证 certified claim head/config QC 与最新 active/fenced profile 后，以 issuance ID 执行
   deterministic first-result signing并提交 cluster-wide issuance log；enrollment voters 验证 exact
   certificate/log entry/profile proof 后把它们的 hash/坐标纳入独立 approval QC。
7. 任一 control 用 approval QC 提交 deterministic completion；current config QC certified 后才原子
   `claim_reserved→consumed`、激活 Membership/view 并授权 artifact release。响应附带绑定证书对象/
   SPKI、invite、claim/completion 两个 head/QC、初始 leaf/root、floor 和 intent hash 的 enrollment
   receipt。无法完成者必须 certified abort 后用全新 invite/request 重试。
8. `ready` 只表示 certified completion、view 和必要制品已可取，不表示客户端已安装或在线。

普通 X.509 证书不需要做非标准“多签”。它由受约束的在线 intermediate 签发，但验证端
同时核对 certified registry/enrollment receipt；单个 CA executor 不能靠一张孤立证书
创建有效成员。

邀请 token 由创建端用 CSPRNG 生成；明文只存在于一次性创建响应的授权交付上下文、由用户保存的
QR/加入文件/`loom://` URI，以及 `retry_not_after` 前该 exact 事务的 claim/retry
body。它不进入 URL/header/cookie 或复制日志；客户端持久化 certified receipt/identity
后立即清除。控制日志绑定 domain-separated commitment 与 §6.2
sealed artifact hash/ref，只有获授权 invite-delivery renderer 能在 certified 后解封同一 token。
需要同时交付给 Device 与 server 的数据面秘密，
必须在 approval commit **之前**生成一次，并分别 sealed 给既定接收者，或写入能按不可变
版本取回同一字节的 KMS/HSM；日志只提交 ciphertext hash/immutable secret ref。替任 executor
只能重放同一 artifact，不能按 generation 临时再生一份新秘密。若 artifact 尚未满足 §6.2 的
availability/PoP policy，事务不能 commit 或进入 `ready`；生成前、seal 后、commit 后任一点崩溃的
重试都必须得到同一 artifact 或明确作废后创建更高 generation。

### 11.3 稳态端点

control API、Enrollment、Device config、Device report、静态 distribution 和 data ingress 是
不同 EndpointSet role，wire enum 固定为
`control_api | enroll | device_config | device_report | distribution | data_ingress`；不能从一个
enrollment URL 替换路径或从同 hostname 猜出其他角色。v1 的 `report/data` 等别名只允许迁移
renderer 显式映射，不进入 v2 wire。客户端从已验签
Device view 得到多个 endpoint；失败时按 endpoint ID 切换，拒绝跳到集合外重定向。每个
`control_api/enroll/device_config/device_report/distribution/data_ingress` endpoint 都绑定允许的
hostname、协议和 transport
identity pin set；有合法 WebPKI 证书但 pin 不匹配的服务器仍在发送凭据前被拒绝。

Device 报告仍由 Device 自身签名，不要求每份报告取得 quorum。任一由 control 托管且已在
EndpointSet 中授权的 `device_report` ingress 验证
身份与当前 certified membership 后可接收，再用 CRDT 按
`(device_id, observed_at, attestation_hash)` 去重传播。无法证明自己已追上撤权水位的落后
副本不得向该 Device 返回受保护数据，应返回可重试错误让客户端换端点。

---

## 12. 域名与公开证书管理

### 12.1 管理边界

Loom 自动管理已经委派给它的 DNS zone/subzone，不默认购买、转移或删除注册域名。
注册商续费和账单只做读取、到期告警和显式批准任务。DNS provider 使用可替换 adapter；
Gandi LiveDNS、Dynadot 或支持 RFC 2136 的权威 DNS 都只是实现，不进入客户端协议。

推荐把独立子域委派给 Loom，例如：

```text
api.<node-label>.<managed-zone>       control_api（管理员/API）
enroll.<node-label>.<managed-zone>    enroll（一次性加入）
config.<node-label>.<managed-zone>    device_config（私有 Device view）
report.<node-label>.<managed-zone>    device_report（签名上报）
dist.<node-label>.<managed-zone>      distribution（公开静态制品）
data.<node-label>.<managed-zone>      data_ingress（Hysteria2/Trojan 等）
_acme-challenge.<managed-zone>        独立 DNS-01 validation zone
```

首个 v2 profile 要求六种 role 分离 hostname、CertificateIntent 与认证策略，避免把管理员 API、
bearer-token Enrollment、Device mTLS、公开静态缓存和数据入口放进同一错误的反代/证书边界。
不能仅靠 URL path 区分 role。control peer RPC 另由 head/QC 承诺的 private
ControlPeerDirectory mTLS 地址管理，不进入
上表。稳定 logical endpoint ID 与 Device ID 绑定；hostname label 经规范化和冲突检查后提交，
一经分配不得因节点改名自动变化。

### 12.2 目标模型

```text
ManagedZoneRefV1
  zone_id, generation, managed_zone_hash

DNSProviderProfileRefV1
  profile_id, generation, dns_provider_profile_hash

DNSProviderProfileV1
  schema = 1, cluster_id, profile_id, generation
  adapter_kind, api_base_url, provider_zone_handle
  supports_record_cas, supports_rrset_union, supports_fencing

ACMEDirectoryProfileRefV1
  profile_id, generation, acme_directory_profile_hash

ACMEDirectoryProfileV1
  schema = 1, cluster_id, profile_id, generation
  directory_url, directory_server_name
  directory_webpki_profile_ref: WebPKIProfileRefV1
  allowed_endpoint_origins[]                # canonical HTTPS origins，按 UTF-8 bytes 排序
  redirect_policy = "forbid"
  account_key_algorithm
  allowed_challenge_types[]                 # 首版必须精确为 ["dns-01"]
  maximum_order_lifetime_seconds

CertificateIssuerProfileRefV1
  profile_id, generation, certificate_issuer_profile_hash

CertificateIssuerProfileV1
  schema = 1, cluster_id, profile_id, generation
  issuer_kind                              # public_acme
  acme_directory_profile_ref: ACMEDirectoryProfileRefV1
  allowed_roles[], allowed_dns_suffixes[]
  maximum_validity_seconds, required_eku_oids[], required_policy_oids[]

WebPKIProfileRefV1
  profile_id, generation, webpki_profile_hash

WebPKIProfileV1
  schema = 1, cluster_id, profile_id, generation
  client_trust_mode = "platform_public_webpki"
  consensus_trust_anchor_der[], consensus_trust_anchor_set_hash
  hostname_validation = "rfc6125_dns_id"
  allowed_usages[]                         # acme_directory | endpoint_tls，按此 enum 顺序
  allowed_roles[], minimum_tls_version      # 仅 endpoint_tls 使用，按 EndpointSet role enum
  required_eku_oids[], required_policy_oids[]
  consensus_revocation_mode = "none"
  client_revocation_mode = "platform_default"

AuthoritativeNameServerSetRefV1
  nameserver_set_id, generation, authoritative_nameserver_set_hash

AuthoritativeNameServerV1
  nameserver_id, dns_name

AuthoritativeNameServerSetV1
  schema = 1, cluster_id, nameserver_set_id, generation, zone_id
  nameservers[]                            # 按 nameserver_id UTF-8 bytes 排序去重，非空

ManagedZoneV1
  schema = 1, cluster_id, zone_id, generation
  suffix, provider_profile_ref: DNSProviderProfileRefV1
  authoritative_nameserver_set_ref: AuthoritativeNameServerSetRefV1
  credential_artifact_hash
  allowed_record_types[]                  # A | AAAA | CAA | CNAME | NS | TXT，按此 enum 顺序
  default_ttl_seconds, naming_template, reserved_labels[]
  acme_challenge_zone_ref?                 # ManagedZoneRefV1；必须是已存在的独立 validation zone
  caa_policy_hash?

DomainBindingIntentRefV1
  binding_id, generation, domain_binding_intent_hash

DomainBindingIntentV1
  schema = 1, cluster_id, binding_id, generation
  endpoint_id, owner_device_id, managed_zone_ref: ManagedZoneRefV1
  fqdn, allowed_address_families[]          # ipv4 → ipv6 固定顺序，非空
  address_rotation_policy_hash

AddressClaimRefV1
  claim_id, generation, address_claim_hash

AddressTransportIdentityV1                 # exact tagged projection；必须且只能选择一个 variant
  schema = 1, kind                         # tls | wireguard
  tls?                                     # {protocol,server_name,
                                           #  certificate_identity_projection_hash,spki_digest}
  wireguard?                               # {peer_public_key_id,peer_public_key}

AddressChallengeIntentV1
  schema = 1, cluster_id, challenge_id
  binding_id, binding_generation, endpoint_id, owner_device_id
  address_family, expected_address, challenge_nonce_hash
  expected_transport_identity: AddressTransportIdentityV1
  expected_transport_identity_hash, issued_at, expires_at

AddressChallengeLifecycleStateV1
  schema = 1, cluster_id, challenge_id, challenge_intent_hash
  status                                  # available | consumed | expired
  consumed_by_claim_hash?

AddressClaimBodyV1
  schema = 1, cluster_id, claim_id, generation
  binding_id, binding_generation, endpoint_id, owner_device_id
  previous_claim_ref?                      # 同 family 首次 claim 时缺失，否则 exact AddressClaimRefV1
  address_family, address                  # ipv4 | ipv6；RFC 5952 canonical literal
  challenge_intent_hash, challenge_nonce_hash, observed_at, expires_at
  expected_transport_identity: AddressTransportIdentityV1
  expected_transport_identity_hash
  owner_identity_key_id

AddressClaimV1
  body: AddressClaimBodyV1
  owner_signature: AuthorityProofSignatureV1

DNSAddressRotationPolicyV1
  schema = 1, cluster_id, policy_id, generation
  minimum_stability_seconds, minimum_overlap_seconds
  propagation_safety_seconds, client_dns_cache_grace_seconds
  max_claim_age_seconds, max_stability_sample_gap_seconds, external_vantage_count
  vantages[]                                # DNSAddressVantageRefV1，按 vantage_id 排序

DNSAddressVantageRefV1
  vantage_id, device_id, identity_key_id, fault_domain
  address_families[]                        # ipv4 → ipv6 固定顺序，非空

DNSAddressPhaseOperationV1
  schema = 1, cluster_id, operation_id, rotation_id, phase_seq
  binding_ref: DomainBindingIntentRefV1
  target_claim_ref: AddressClaimRefV1
  replaced_claim_ref?                       # 首次地址缺失，否则同 family 旧代
  parent_phase_operation_hash               # 首步为 EMPTY_OPERATION_HASH_V1
  rotation_policy_hash, evidence_root
  mode                                      # normal | cancel_unpreferred_target
  reason
  transitions[]                             # DNSAddressTransitionV1，按 claim generation 排序

DNSAddressLeaseRenewalV1
  schema = 1, cluster_id, operation_id
  binding_ref: DomainBindingIntentRefV1
  previous_claim_ref: AddressClaimRefV1
  renewed_claim_ref: AddressClaimRefV1
  expected_previous_lifecycle_state_hash, evidence_root, reason

DNSAddressTransitionV1
  claim_id, claim_generation, from_state, to_state # absent | preparing | overlapping | preferred |
                                            # draining | retired

DNSAddressLifecycleStateV1
  schema = 1, cluster_id, binding_id, binding_generation, claim_id, claim_generation
  address_claim_hash, state
  last_transition_operation_hash, last_changed_control_revision
  removal_authoritative_ttl_seconds?, remove_not_before?, retired_tombstone_hash?
  terminal_reason?                           # dns_removed | lease_superseded；仅 retired

DNSAddressEvidenceBodyV1
  schema = 1, cluster_id, evidence_id
  lineage_kind, lineage_id                  # rotation | lease_renewal；恰与承载 operation 匹配
  binding_ref: DomainBindingIntentRefV1
  claim_ref: AddressClaimRefV1
  subject_role                              # target | replaced
  observed_at
  evidence_type                              # ownership_challenge | authoritative_rrset |
                                             # public_rrset | transport_reachability |
                                             # address_stability_window
  detail                                     # exact tagged union：
    ownership_challenge?                     # {transcript:AddressOwnershipChallengeTranscriptV1,
                                             #  succeeded}
    authoritative_rrset?                     # {nameserver_set_ref,nameserver_id,nameserver_dns_name,
                                             #  responder_address,rrtype,values[],ttl_seconds,
                                             #  response_transcript_hash}
    public_rrset?                            # {vantage_id,fault_domain,rrtype,values[],ttl_seconds}
    transport_reachability?                  # {vantage_id,fault_domain,address_family,
                                             #  transcript_hash,succeeded}
    address_stability_window?                # {vantage_id,fault_domain,window_start,window_end,
                                             #  samples[]:DNSAddressStabilitySampleV1}

DNSAddressStabilitySampleV1
  sample_id, observed_at, address

AddressOwnershipChallengeTranscriptV1
  schema = 1, cluster_id, challenge_intent_hash
  binding_id, binding_generation, endpoint_id, owner_device_id
  address_family, address, expected_transport_identity_hash
  nonce                                      # 32-byte CSPRNG，无 padding base64url
  responder_identity_key_id, completed_at

DNSAddressEvidenceV1
  body: DNSAddressEvidenceBodyV1
  reporter_key_id
  reporter_signature: AuthorityProofSignatureV1

DNSAddressEvidenceLeafV1
  schema = 1, evidence_type, evidence_id, evidence_hash

CertificateIdentityProjectionV1
  schema = 1, cluster_id, certificate_intent_id, identity_generation, role
  endpoint_ids[], dns_names[], issuer_profile_ref: CertificateIssuerProfileRefV1
  key_owner_device_id, key_artifact_hash, spki_der, spki_hash

TLSCertificateSigningRequestV1             # public-safe content-addressed exact preimage
  schema = 1, cluster_id, certificate_intent_id, identity_generation, issuance_generation
  identity_projection_hash, key_artifact_hash
  csr_der, csr_der_hash, spki_der, spki_hash

CertificateIntentV1
  schema = 1, cluster_id, certificate_intent_id
  identity_projection: CertificateIdentityProjectionV1
  identity_projection_hash
  certificate_signing_request: TLSCertificateSigningRequestV1
  certificate_signing_request_hash
  renew_before, issuance_generation

PublicEndpointIntentV1
  schema = 1, cluster_id, intent_id, generation, owner_device_id
  role                                  # 与 EndpointSetV2 role enum 完全相同
  exposure                              # public | private；public 必须由显式 proposal/QC 建立
  protocol, address_or_domain_intent_hash, listener_policy_hash
  firewall_mode, mapping_mode           # 各为 required | not_applicable
  credential_artifact_hashes[], certificate_identity_projection_hashes[]?

AddressOrDomainIntentV1                 # exact tagged union，必须且只能选择一个 variant
  schema = 1, cluster_id, address_or_domain_intent_id, generation
  kind                                 # managed_domain | explicit_address | managed_domain_with_address
  managed_domain?                      # DomainBindingIntentRefV1
  explicit_address?                    # AddressClaimRefV1
  managed_domain_with_address?         # {domain_binding:DomainBindingIntentRefV1,
                                        #  address_claim:AddressClaimRefV1}
```

`AddressOrDomainIntentV1` 的 tag 与 variant 必须一致，未选 variant 必须缺失；每个 ref 的 ID、
generation 与 hash 都必须指向 candidate parent state 中唯一 exact 对象并重算成功。
`DomainBindingIntentV1.managed_zone_ref` 同样绑定 zone generation/hash，不能让同一 zone ID 下的
provider scope、credential、TTL 或命名模板漂移。binding 的 FQDN 必须是所属 zone suffix 的
严格子域、canonical lower-case A-label，无通配符/空 label；其 owner/endpoint/cluster 必须与
PublicEndpointIntent 一致。combined variant 的 claim 还必须属于同一 binding generation、owner
和 endpoint，且其 family 属于 binding 的 allowed set。
`credential_artifact_hashes[]` 按 hash bytes 排序、非空且拒绝重复，HTTPS/TLS 类
protocol 的 `certificate_identity_projection_hashes[]` 必须按 hash bytes 排序去重、
数量为 1 或 2，WireGuard 则必须缺失该数组。
每个 credential hash 必须解析到 §6.2 exact `SecretArtifactRefV2`；purpose、owner、generation、
公开 identity 与 endpoint role/protocol 的 credential profile 一致，且 availability/PoP 已满足。

projection 的 endpoint/DNS 数组按 UTF-8 bytes 排序去重且非空，所有 endpoint 必须解析到同一
role；projection 自身的 `role`、cluster、owner、hostname、issuer profile、key artifact/SPKI
必须与 public/logical intent 及 transport identity 逐字节一致。六种公开 role 之间禁止共享
projection、hostname 或 key artifact/SPKI；即便 issuer/profile 相同，也必须分别生成 role-bounded
identity。`spki_der` 是无 padding base64url strict DER，`spki_hash=tls_spki_hash`；key artifact 必须
解析到 §6.2 exact private-key ref，其 `public_key.public_key_spki_der` 逐字节相等。

`TLSCertificateSigningRequestV1` 的 cluster/intent ID/identity generation/projection/key artifact/SPKI
必须逐字段等于 enclosing CertificateIntent 与 projection，issuance generation 也必须相等。
`csr_der` 是无 padding base64url strict DER PKCS #10：拒绝 trailing bytes、非最短 DER、无效
self-signature、SPKI 不等、重复 attribute/extension、未知 critical extension；subject 固定为空，唯一
extensionRequest 中 SAN 必须恰为 projection 排序后的 canonical DNS names，不能请求额外 EKU、role
或 wildcard。CSR signature algorithm 必须由 key profile 唯一映射：Ed25519 OID parameters 缺失；
P-256 为 ecdsa-with-SHA256 且 DER `(r,s)` 必须最短、正数并为 low-S；RSA 为 sha256WithRSAEncryption
且 parameters 为 DER NULL。其他算法/parameters/编码失败关闭。`csr_der_hash=tls_csr_der_hash`，完整 object 重算
`tls_certificate_signing_request_hash`。这些 public-safe bytes 随 intent 进入内容寻址状态，替任 ACME
executor 只能恢复并提交同一 CSR；裸 `csr_hash`、本机文件或重新生成 CSR 都不构成依赖。

摘要固定为：

```text
address_or_domain_intent_hash = H(frame(
  "loom-address-or-domain-intent-v1", JCS(AddressOrDomainIntentV1)
))
dns_provider_profile_hash = H(frame(
  "loom-dns-provider-profile-v1", JCS(DNSProviderProfileV1)
))
acme_directory_profile_hash = H(frame(
  "loom-acme-directory-profile-v1", JCS(ACMEDirectoryProfileV1)
))
certificate_issuer_profile_hash = H(frame(
  "loom-certificate-issuer-profile-v1", JCS(CertificateIssuerProfileV1)
))
webpki_profile_hash = H(frame(
  "loom-webpki-profile-v1", JCS(WebPKIProfileV1)
))
consensus_trust_anchor_set_hash = H(frame(
  "loom-webpki-consensus-trust-anchor-set-v1",
  JCS({schema:1,trust_anchor_der:consensus_trust_anchor_der})
))
authoritative_nameserver_set_hash = H(frame(
  "loom-authoritative-nameserver-set-v1", JCS(AuthoritativeNameServerSetV1)
))
managed_zone_hash = H(frame("loom-managed-zone-v1", JCS(ManagedZoneV1)))
domain_binding_intent_hash = H(frame(
  "loom-domain-binding-intent-v1", JCS(DomainBindingIntentV1)
))
address_challenge_intent_hash = H(frame(
  "loom-address-challenge-intent-v1", JCS(AddressChallengeIntentV1)
))
address_transport_identity_hash = H(frame(
  "loom-address-transport-identity-v1", JCS(AddressTransportIdentityV1)
))
challenge_nonce_hash = H(frame(
  "loom-address-challenge-nonce-v1", raw_32_byte_nonce
))
ownership_challenge_transcript_hash = H(frame(
  "loom-address-ownership-challenge-transcript-v1",
  JCS(AddressOwnershipChallengeTranscriptV1)
))
address_claim_series_id = H(frame(
  "loom-address-claim-series-id-v1",
  JCS({schema:1,cluster_id,binding_id,binding_generation,address_family})
))
address_claim_hash = H(frame("loom-address-claim-v1", JCS(AddressClaimV1)))
dns_address_rotation_policy_hash = H(frame(
  "loom-dns-address-rotation-policy-v1", JCS(DNSAddressRotationPolicyV1)
))
dns_address_phase_operation_hash = H(frame(
  "loom-dns-address-phase-operation-v1", JCS(DNSAddressPhaseOperationV1)
))
dns_address_lease_renewal_hash = H(frame(
  "loom-dns-address-lease-renewal-v1", JCS(DNSAddressLeaseRenewalV1)
))
dns_address_lifecycle_state_hash = H(frame(
  "loom-dns-address-lifecycle-state-v1", JCS(DNSAddressLifecycleStateV1)
))
dns_address_evidence_hash = H(frame(
  "loom-dns-address-evidence-v1", JCS(DNSAddressEvidenceV1)
))
public_endpoint_intent_hash = H(frame(
  "loom-public-endpoint-intent-v1", JCS(PublicEndpointIntentV1)
))
certificate_identity_projection_hash = H(frame(
  "loom-certificate-identity-projection-v1", JCS(CertificateIdentityProjectionV1)
))
tls_csr_der_hash = H(frame("loom-tls-csr-der-v1", raw_csr_der))
tls_spki_hash = H(frame("loom-tls-spki-v1", raw_spki_der))
tls_certificate_signing_request_hash = H(frame(
  "loom-tls-certificate-signing-request-v1", JCS(TLSCertificateSigningRequestV1)
))
certificate_intent_hash = H(frame(
  "loom-certificate-intent-v1", JCS(CertificateIntentV1)
))
```

`AddressClaimV1.owner_signature` 覆盖
`frame("loom-address-claim-signature-v1", JCS(AddressClaimBodyV1))`。owner key 必须从 claim parent
head 的 active Device identity 精确解析，body 的 owner/binding/endpoint、
`address_family == challenge.address_family`、`address == challenge.expected_address`、nonce 与
transport identity 必须和 `challenge_intent_hash` 指向的已 certified
`AddressChallengeIntentV1` 相等；signature 的 algorithm/key ID 必须等于该 exact Device identity
`AuthorityProofKeyV1`，并按 §6.2 的 canonical wire 规则验证；
challenge 必须处于 `available`，candidate logical time 与 owner 可信墙钟都在其
`issued_at..expires_at` 内。`submit_address_claim` 在同一 certified reducer step 原子把它改为
`consumed` 并绑定 `consumed_by_claim_hash`；同 challenge 第二份 claim、expired 后重放或改地址均
拒绝。`claim.expires_at <= challenge.expires_at`，且
`0 < claim.expires_at - claim.observed_at <= policy.max_claim_age_seconds`，全部用 checked time
arithmetic。`AddressChallengeLifecycleStateV1` 只从 issue/claim certified history 推导，`expired` 由首个
晚于 expires_at 的 certified logical time 单调产生，不能复活。
challenge/claim 内嵌的 `AddressTransportIdentityV1` 必须逐字节相等并重算同一 hash。TLS variant
的 protocol/server name/projection/SPKI 必须从 parent certified
`LogicalEndpointIntentV1.transport_identity` 与 matching `PublicEndpointIntentV1` 授权的 projection
逐字段投影；WireGuard variant 同理必须等于 authorized peer-key projection。tag、protocol、key ID/
bytes、projection hash 或 SPKI 任一不等都拒绝，opaque sender 自选 hash 不构成 transport ownership。
ownership evidence 内嵌的 transcript 必须严格解码；nonce 必须解码为 32 bytes，并重算为 challenge/
claim 的 `challenge_nonce_hash`，transcript 的 cluster/binding/endpoint/owner/family/address/transport
identity 必须分别等于 challenge 与 claim，responder key 必须是 owner 当前 identity，completed_at
在 challenge 有效窗内。验证器重算上式 transcript hash；只提交 opaque transcript hash、回显 nonce
hash 或在另一地址完成握手都不成立。

`DNSProviderProfileV1` 与 `AuthoritativeNameServerSetV1` 都是 immutable certified objects：同一 ID
的 generation 从 1 连续递增，ref 的 ID/generation/hash 必须逐字段匹配。provider adapter 的
kind/base URL/zone handle/capability 与 authoritative NS denominator 因而不能由 executor 按本地
“latest”解释。每个 nameserver DNS name 必须是 canonical lower-case A-label FQDN；set 的 cluster/
zone ID 必须与 `ManagedZoneV1` 相等。权威集合发生变化要先提交更高 set generation，再提交引用它的
更高 ManagedZone generation；历史 phase 继续用冻结的旧 set bytes。
`ACMEDirectoryProfileV1`、`CertificateIssuerProfileV1` 与 `WebPKIProfileV1` 同样以 exact
generation/hash ref 解析；URL、trust mode、role/suffix/EKU/OID、TLS/revocation rule 任一改变都创建
更高 generation，历史 order/projection/listener 冻结旧 bytes。role/enum 数组按本文固定 enum 顺序，
DNS suffix 与 OID 数组按 canonical bytes 排序去重。`consensus_trust_anchor_der[]` 是完整 DER CA
certificate bytes，按各自 `H(frame("loom-webpki-anchor-der-v1",raw_der))` 的 hash bytes 排序并拒绝
重复；每张必须严格 DER、`BasicConstraints CA=true` 且可作为 path terminal。验证器重算
`consensus_trust_anchor_set_hash`，control voter 对 ACME 证书、外部握手与安装证据只用这组冻结 anchors
及 exact profile 的时间/EKU/policy/revocation 规则验链，不读取本机 trust store。若公共 CA 的有效
anchor 集合改变，必须先提交更高 WebPKI profile generation，再创建引用新 profile 的 order/projection；
旧历史仍按旧 anchors 验证。public endpoint 的 issuer 必须是 `public_acme`，其 ACME directory ref 与
order 相等。directory profile 的 URL origin 必须在非空 `allowed_endpoint_origins[]` 内，server name
与 URL host 的 canonical DNS name 相等，WebPKI ref 指向 `allowed_usages[]` 含 `acme_directory` 的
exact profile；
GET directory 及其返回的 new-account/new-order/authz/finalize/certificate URL 全部必须是列表内 HTTPS
origin，禁止 redirect、scheme downgrade、userinfo、fragment 与 IP-host 替换。control 共识验链的
revocation mode 首版固定为 `none`，只使用 candidate signed time 检查 exact DER validity；不得由某些
voter临时查询 OCSP/CRL 而另一些不查。客户端对公网 listener 则按平台默认 revocation policy 验链，
两者字段分离，后续若引入 committed OCSP/CRL proof 必须升级 schema。LogicalEndpoint/seed 的
WebPKI ref 必须同时允许 `endpoint_tls` 和同一 role。客户端接收 endpoint 时仍必须同时
通过其当前平台公共 WebPKI 验链、RFC 6125 hostname 和 signed SPKI pin；冻结的 consensus anchors
只是让控制副本得到确定性判定，不会把客户端平台不信任的私有 root 提升成可接受 authority。任何裸
profile ID、“system default”别名或 executor 本地 latest 都不能参与 voter/reader 判断。

`DNSAddressRotationPolicyV1.vantages[]` 非空、按 vantage ID 排序去重，Device/key/fault
domain 均非空且 key 必须等于 candidate parent 中 active Device 当前 identity；
`2 <= external_vantage_count <= len(vantages)`，阈值只按不同 vantage 与 fault domain 同时去重后计算。

`DNSAddressEvidenceV1.reporter_signature` 覆盖
`frame("loom-dns-address-evidence-signature-v1", JCS(DNSAddressEvidenceBodyV1))`。ownership evidence
只能由 binding owner 的 current Device identity 签，其余四类只能由 policy 中逐字段匹配
`vantage_id/device_id/identity_key_id/fault_domain/address_family` 的 vantage key 签；evidence body
不另带可自报的 Device ID，验证器由 key ref 反查唯一 vantage。未知/撤权 key、同 key 冒充不同
vantage 或 family 不在 ref 中一律拒绝。`reporter_key_id` 和 signature 内的 algorithm/key ID 必须
逐字段等于上述解析出的 exact `AuthorityProofKeyV1`，并按 §6.2 的 canonical wire 规则验证。
stability samples 按 `(observed_at,sample_id)` 排序去重，
每项 address 必须等于 target claim；window 满足 `window_start < window_end <= observed_at`，首末
sample 覆盖两端，连续 sample 间隔不得超过 policy `max_stability_sample_gap_seconds`。至少
`external_vantage_count` 个不同 vantage/fault-domain 的完整 window 都覆盖
`minimum_stability_seconds`，才构成“连续稳定”；单个 claim age 或两个无连续性的点不能替代。
phase evidence root 对按 `(evidence_type,evidence_id)` 排序去重的
`DNSAddressEvidenceLeafV1` 使用 §7.1 RFC 6962 算法，leaf 必须从随 operation 交付的 exact 签名
evidence 重算。vantage ID/key/fault-domain 必须解析到 policy 允许的不同 active Device，不能由
reporter 自报；`values[]` 是 canonical IP literals，排序去重，RRtype 与 family 必须相符。

上述对象只能由 §7.1 exact outer operation 承载；kind/payload/schema 映射固定为：

| kind | payload | payload hash |
|---|---|---|
| `upsert_dns_provider_profile` | `DNSProviderProfileV1` | `dns_provider_profile_hash` |
| `upsert_acme_directory_profile` | `ACMEDirectoryProfileV1` | `acme_directory_profile_hash` |
| `upsert_certificate_issuer_profile` | `CertificateIssuerProfileV1` | `certificate_issuer_profile_hash` |
| `upsert_webpki_profile` | `WebPKIProfileV1` | `webpki_profile_hash` |
| `upsert_authoritative_nameserver_set` | `AuthoritativeNameServerSetV1` | `authoritative_nameserver_set_hash` |
| `upsert_managed_zone` | `ManagedZoneV1` | `managed_zone_hash` |
| `upsert_domain_binding_intent` | `DomainBindingIntentV1` | `domain_binding_intent_hash` |
| `issue_address_challenge` | `AddressChallengeIntentV1` | `address_challenge_intent_hash` |
| `submit_address_claim` | `AddressClaimV1` | `address_claim_hash` |
| `upsert_dns_address_rotation_policy` | `DNSAddressRotationPolicyV1` | `dns_address_rotation_policy_hash` |
| `dns_address_phase` | `DNSAddressPhaseOperationV1` | `dns_address_phase_operation_hash` |
| `renew_dns_address_lease` | `DNSAddressLeaseRenewalV1` | `dns_address_lease_renewal_hash` |
| `upsert_address_or_domain_intent` | `AddressOrDomainIntentV1` | `address_or_domain_intent_hash` |
| `upsert_certificate_intent` | `CertificateIntentV1` | `certificate_intent_hash` |

outer `payload_schema=1`，cluster 必须一致。每次 proposal 的 `ControlOperationBodyV1.operation_id`
仍是 §7.1 独立、全局稳定的幂等 ID，绝不等于可跨 generation 复用的 zone/binding/claim/policy/
intent ID；只有 `dns_address_phase` outer operation ID 必须等于其 payload 内本次 phase 的
`operation_id`，`renew_dns_address_lease` 同样必须等于 renewal payload 的 `operation_id`。同一对象 ID
的 generation（证书为 `issuance_generation`）必须从 1 连续递增；
outer 通过 payload hash 绑定 exact object，旧 exact bytes 永久保留供
proof/replay 使用，executor 不能把“latest”解析结果带进 reducer。

每个 `(cluster,binding_id,binding_generation,address_family)` 的 `claim_id` 必须等于上式
`address_claim_series_id`，generation 从 1 连续增加；首代缺 `previous_claim_ref`，后续 ref 必须
指向同 series 的 generation-1 exact hash。phase 的 target/replaced ref 和每个 transition 的
claim ID/generation 必须逐字段相等，数组按 `(claim_id UTF-8 bytes,generation)` 排序；因此两个
series、同为 generation 1 的 claim 也不会混淆。

DNS phase 的 `phase_seq` 从 1 连续递增、parent hash 精确指向同 rotation 前一步；binding、target、
replaced claim refs 与 policy hash 在整个 lineage 不变。`mode=normal` 的首个 phase 只能
`absent→preparing`；随后合法边只有 `preparing→overlapping`、`overlapping→preferred`、旧
`preferred→overlapping`、旧 `overlapping→draining`、`draining→retired`。换址时 target 的
`overlapping→preferred` 与旧 preferred 的 `preferred→overlapping` 必须在同一 operation 原子完成；
首次地址则只提升 target。

每个 `(binding_id,binding_generation,address_family)` 最多一个 active rotation lineage；首个
`absent→preparing` 以 CAS 获取锁。首次地址在 target preferred 时释放；换址在 replaced claim
retired 时释放。锁存在时第二个 rotation、修改 frozen binding/target/replaced/policy 或复活
tombstone 都拒绝。若 target 尚未 preferred 而依赖失效，`mode=cancel_unpreferred_target` 只允许
target 的 `preparing|overlapping→draining`，old listener/claim 必须仍是唯一 preferred；该 certified
edge 才授权 provider 删除 target value，随后沿同一 lineage 用 `draining→retired` 完成 TTL/absence
门槛并释放锁。cancel 不能直接删除、标 terminal 或改变 frozen refs，也不能在 target preferred 后
替代正常 old drain。每个已发布 binding/family 始终恰有一个 preferred。

各边的 predicate 使用 candidate head 的 `committed_logical_time` 和 exact evidence：

| edge | 必需条件 |
|---|---|
| `absent→preparing` | owner challenge、claim 签名/新鲜度、至少 policy 数量且 fault-domain 去重的 transport success；地址已连续稳定 `minimum_stability_seconds` |
| `preparing→overlapping` | 所有权威 NS 与至少 policy 数量公共视角均回答“现有非 retired values ∪ target”，TTL 取观测实际最大值；不得 replace/delete |
| target `overlapping→preferred` | overlap 已持续 `minimum_overlap_seconds`；换址时与旧 preferred 降级原子发生 |
| old `overlapping→draining` 或 cancelled target `preparing|overlapping→draining` | certified phase 才授权 provider 从 RRset 移除 subject value；同时把实际最大权威 TTL 固化为 `removal_authoritative_ttl_seconds` 并以 checked addition 导出 `remove_not_before` |
| `draining→retired` | 所有权威 NS 与 policy 数量公共视角连续确认 subject value 不存在，且已到 `remove_not_before = drain_head_time + actual_ttl + propagation_safety + client_dns_cache_grace`；EndpointSet/offline view 和邀请引用门槛也已满足 |

每份 phase evidence 的 `cluster_id/binding_ref` 必须逐字段等于 phase，且
`lineage_kind="rotation",lineage_id=phase.rotation_id`；其 `claim_ref` 必须
等于 `subject_role=target` 时的 target ref，或 `subject_role=replaced` 时的非空 replaced ref，其他
组合失败关闭。`absent→preparing` 的 ownership/transport/stability 只接受 target；
`preparing→overlapping` 的 authoritative/public RRset 只接受 target；prefer 的时间判断不接受用
另一 lineage evidence 补门槛；正常 old drain/retire 只接受 replaced，cancelled target drain/retire
只接受 target。每个 authoritative evidence 的 `nameserver_set_ref` 必须等于 frozen ManagedZone
所指 set，ID/name 与 set member 相等；要求该 set **每个** member 各有一份 fresh success，不能由
sender 自报“全部”。public evidence 则按 frozen policy 的 vantage/fault-domain denominator 计数。
evidence 的 claim address/family、RRtype、values 与 phase target/replaced exact claim 重算，不得跨
claim generation、binding generation 或 rotation 重放。

`remove_not_before` 的四项用非负 int64 秒 checked addition，overflow 失败关闭。仍 available 且未
过期的 invite，或 consumed 但 candidate logical time/可信墙钟仍未超过 `retry_not_after` 的 invite，
若 context 引用依赖该 address claim 的 seed，则旧 claim 在相应 expiry/retry deadline 前不得 retire，
除非同一 invite context 内另有不依赖它且仍保持可用/证书有效至相应 deadline 的 seed。迟到 provider
请求必须携资源 lease/fencing 与 binding/claim generation CAS；否则只能 supervised，不能覆盖新
RRset。`DNSAddressLifecycleStateV1` 完全由 certified phase/renewal transition history 归约，receipt
本身无权改状态。

同一地址续租不走“新旧值相同”的换址 drain。`renew_dns_address_lease` 只允许该 binding/family
没有 active rotation、previous claim 正是唯一 `preferred` 且 candidate logical time/可信墙钟均未
越过 previous expiry；renewed claim 必须是同 series 的 generation+1，`previous_claim_ref`、
binding/endpoint/owner/family/address/transport identity 全部相等，并通过一份全新 one-time
AddressChallenge、签名、新鲜度和外部稳定/连通 evidence。`expected_previous_lifecycle_state_hash`
必须从 parent state 重算。renewal 的 `evidence_root` 使用同一 leaf/tree 规则，只接受
`lineage_kind="lease_renewal",lineage_id=renewal.operation_id,subject_role="target"` 且 claim ref 等于
renewed claim 的 ownership、transport、stability evidence；数量/fault-domain/window 门槛与 frozen
policy 相同，跨 phase/renewal 证据拒绝。一个 certified reducer step 把 old claim 写为
`retired(terminal_reason=lease_superseded,retired_tombstone_hash=renewal_hash)`，把 new claim 直接写为
`preferred`，二者的 `last_transition_operation_hash=renewal_hash`；它不调用 provider、不删除 RR
value，也不重新计 overlap。若 address 不同则必须走完整 rotation，不能伪装为 renewal。

`explicit_address`、`managed_domain_with_address` 与 seed/listener render 对 claim expiry 使用完全相同
规则：candidate head logical time及验证节点可信墙钟必须在 claim 有效窗内，任何新 EndpointSet/
listener 都不得引用 expired claim。已有引用必须在 expiry 前由上述 renewal/换址替换，否则从新
Device view 与新连接授权中移除并告警；不能让 explicit-address 绕过 managed-domain 的租约检查。

`CertificateIntentV1.identity_projection_hash` 必须从其内嵌 exact projection 重算，
projection 的 cluster/intent ID 必须与外层相等。PublicEndpointIntentV1、
ListenerImmutableSpecV1 和最终 ListenerGeneration 的证书绑定必须逐字节一致：
每个 listener 的单个 `certificate_identity_projection_hash` 必须是 public intent
排序数组的成员，对应 `TlsSpkiPinV1` 必须携相同 projection hash，其 digest
等于该 projection SPKI 的规范 hash，server name 与 LogicalEndpoint TLS transport
identity 一致。LogicalEndpoint 的 pin 集合必须恰好覆盖 public intent 的所有
projection：每个 projection 至少一个当前有效 pin，且不得有数组外 pin。同一
projection 下仅 CSR、renew policy 或
`issuance_generation` 变化会生成新 `certificate_intent_hash`，但不改 projection hash、
PublicEndpointIntent 或 EndpointSet generation；改变 DNS name、issuer profile、owner、key artifact
或 SPKI 必须提高 `identity_generation`、得到新 projection hash，并走新 listener/pin
overlap。

创建/更新 intent 必须由 §7.1 outer operation 以
`kind="upsert_public_endpoint_intent", payload_schema=1,
payload_hash=public_endpoint_intent_hash` 承载，outer 与 payload 的 cluster 必须相等；outer
operation ID 是本次 proposal 的稳定幂等 ID，独立于可跨 generation 复用的 `intent_id`，两者不得
误作 equality。同 `intent_id` 只能递增 generation；不得由 EndpointSet 或 executor 反向
生成 intent。

provider token、ACME account key 和 TLS private key 只存在秘密层。SSOT 保存 secret ref、
公开 key/证书摘要、有效期和 generation，不保存秘密；所有 ref 必须满足 §6.2 的 exact-version
schema 和 availability/PoP 门槛。TLS 私钥优先在实际终止 TLS 的 Device 本地生成；控制平面
批准已绑定 key artifact 的 CSR 和 challenge，不集中生成所有节点私钥。

只有管理员/自动化 principal 显式提交 `PublicEndpointIntentV1(exposure=public)` 才触发公网
命名；拥有 `control` 投票能力本身不隐式暴露 control API，也不要求公网可达。planner 根据
最新 certified `ManagedZone.naming_template` 和稳定 Device/endpoint ID 生成候选 label，避开
保留名并在全局对象图中做唯一性校验；显示名、地域或一次网络测量不得成为域名身份。
`generation` 对同 intent ID 严格递增，`address_or_domain_intent` 必须绑定上面 tagged union 的
精确对象 hash/ref；executor 不得根据本机网卡、DNS 回答或 provider 默认值临时补地址。改变
role、protocol、exposure、地址/域名 variant、provider scope、listener policy 或所绑定的
credential artifact 发生变化都创建更高 generation；同 SPKI 的例行续证可只提高独立
CertificateIntentV1 `issuance_generation`，不强迫 EndpointSet 换代。
所有 safety-critical ref 只能解析 candidate 的 certified parent state；首版不定义 same-head
dependency DAG，因而不能在一个 Head 中同时创建对象并让另一个 operation 引用它。无依赖的兄弟
operation 可以同 head 按 operation ID 排序，存在依赖则必须依次取得 certified heads：ManagedZone/
policy → DomainBinding 与 AddressClaim → AddressOrDomain/CertificateIntent → PublicEndpointIntent →
LogicalEndpointIntent/rotation。任何“先按 operation ID apply，后让早项看见晚项”的实现都失败关闭，
不得由各语言自行拓扑排序。

每个基础 intent 经各自 Raft commit、apply/recompute 和 replication QC 后，只代表相应工作流已获
授权。allocate、prepare、advertise 等每个可见状态转换仍各自形成更高
revision 的 certified entry；对应 executor 只能执行该阶段允许的 DNS、ACME、listener 动作并
回写 receipt，不能拿一次基础授权越过 §12.3～§14 的门槛。域名与证书因此可以自动配置，但
购买/转移 zone、扩大 provider token scope 或产生未预授权费用仍需显式审批。

### 12.3 DNS reconcile

1. ManagedZoneV1、DomainBindingIntentV1、AddressClaimV1 与 DNSAddressRotationPolicyV1 的 exact
   generation/hash，以及逐字段匹配它们的
   `PublicEndpointIntentV1(exposure=public)` 经 Raft commit、apply/recompute 与 replication QC
   成为 certified；缺任一对象或 hash/generation/owner/role 不匹配时不得调用 provider。
2. 持有当前资源租约的 DNS reconciler 读取 certified head 和 provider 实际 RRset。
3. 以稳定 idempotency key 执行 §15 允许的最小 RRset create/upsert；replace/delete 只有具备
   精确 owner/generation CAS/fencing 才自动执行，不修改不归 Loom 所有的记录。
4. 从权威 NS 读取，再从至少两个独立解析视角确认目标值和 TTL；结果作为签名事实进入 CRDT。
5. 只有 DNS 已可见、证书有效且 listener 健康后，它才能进入 certified
   `advertised` 状态。对已有 preferred 的已发布 endpoint，下一 EndpointSet 可同时携带它；
   对首次创建的 endpoint，该 advertised listener 仍只在控制 view，直到达到 §14 门槛后以
   `advertised→preferred` 和首次 EndpointSet 插入原子发布。
6. reconcile 失败只标记 pending/degraded，不回滚 certified desired state，也不发布未经验证的入口。

adapter 必须声明是否支持单 RRset 修改、批量原子更新、条件写和查询。只能“覆盖整区”的 API
不得用于共享 zone；应改用 Loom 独占子区，否则校验直接拒绝。API 限流使用指数退避并尊重
provider 重试提示，绝不把 token 放入 URL 日志。

动态公网地址由 owner Device 签发短寿命 `AddressClaimV1`，绑定 endpoint/binding、地址族、地址、
观测时间和同 family 前代 claim generation。提交前，control 先下发一次性 nonce，目标 Device 必须从
所声明地址/预期 transport 返回以 Device identity 签名的 challenge；至少两个独立视角还要
完成反向连通验证。控制节点再校验身份、地址类型、授权范围和新鲜度。节点不能更新别人的
hostname，也不能借 DDNS 获得 control membership。为减少频繁抖动，地址实际变化且稳定超过
策略窗口才生成新 binding；旧 A/AAAA 在 overlap 内保留。

地址变更严格使用 §12.2 的 `DNSAddressPhaseOperationV1`/reducer，不能在一次 provider replace 中
直接删旧地址：prepare 验证 claim/listener/identity，overlap 只做集合并，原子 prefer 后才 drain
旧 value，最终满足 actual TTL、传播、cache、offline view 与 invite 引用门槛才写 retired tombstone。
provider 无条件删除能力时按 §15 禁止无人值守清理，宁可暂留旧 value/资源并告警。

DNS 是发现层，不是 authority：仅控制 DNS、返回旧 DNS 或给出不匹配的合法 WebPKI 证书，
至多造成不可达；客户端仍拒绝未被 QR checkpoint/Device view 的 transport identity pin 和
signed EndpointSet 同时授权的 controller、端口或配置。若被钉住的服务私钥本身也失陷，
则进入对应 credential revocation/recovery 威胁模型，不能再声称只有 DoS。

### 12.4 ACME

公开证书默认用 ACME DNS-01，便于没有公网 80/TCP 的节点和独立 challenge 子区。完整 zone
API 凭据不复制到所有服务器；使用最小权限 token，优先通过 NS 把 `_acme-challenge` 子区委派
到专用 validation zone。首版 exact profile只实现 derived name 的直接权威 TXT/NS delegation；
CNAME alias 必须等后续 wire profile定义 alias projection，不能静默启用。provider adapter 可以实现
ACME DNS-01 以及 Gandi、Dynadot 等 DNS API，但实现时必须使用本节冻结的 profile/capability，不能把
供应商 URL、账号或本机默认值写进通用示例。

order URL/nonce 可以由 ACME provider 在执行期产生，但任何 DNS/安装/cleanup 副作用之前都要
转换成以下 public checkpoint + control-private exact binding；不能只留 executor 本地状态，也不能把
provider handle/backend locator 放进 public mirror：

```text
ACMEOrderRefV1
  order_id, generation, acme_order_intent_hash

ACMEOrderIntentV1
  schema = 1, cluster_id, order_id, generation
  certificate_intent_hash, identity_projection_hash, certificate_signing_request_hash
  requested_dns_name                       # 首版每个 order 恰一个 canonical DNS name
  acme_directory_profile_ref: ACMEDirectoryProfileRefV1
  acme_account_artifact_hash
  challenge_zone_ref: ManagedZoneRefV1
  dns_rotation_policy_hash, port_evidence_policy_hash
  requested_at, expires_at

ACMEProviderOrderCheckpointV1              # public-safe certified object
  schema = 1, cluster_id, order_ref: ACMEOrderRefV1
  expected_checkpoint = "absent"
  state_binding_hash, created_at

ACMEProviderOrderStatePayloadV1            # sealed artifact 解密后的 strict plaintext
  schema = 1, cluster_id, order_ref: ACMEOrderRefV1
  acme_directory_profile_ref: ACMEDirectoryProfileRefV1
  order_url, finalize_url, authorization_urls[]

ACMEProviderOrderStateBindingV1            # control-private content-addressed object
  schema = 1, cluster_id, order_ref: ACMEOrderRefV1
  hiding_nonce                             # 32-byte CSPRNG，无 padding base64url
  acme_account_artifact_hash
  order_state_plaintext_hash
  order_state_artifact_ref: SecretArtifactRefV2

ACMEDNSChallengeRefV1
  challenge_id, generation, acme_dns_challenge_intent_hash

ACMEDNSChallengeIntentV1
  schema = 1, cluster_id, challenge_id, generation
  order_ref: ACMEOrderRefV1
  provider_order_checkpoint_hash
  fqdn, txt_value
  introduced_at, expires_at

ACMEIssuedCertificateV1
  schema = 1, cluster_id, order_ref: ACMEOrderRefV1
  challenge_ref: ACMEDNSChallengeRefV1
  expected_issued_certificate = "absent"
  certificate_der, certificate_chain_der[]

ACMEChallengePhaseOperationV1
  schema = 1, cluster_id, operation_id, order_ref, challenge_ref
  phase_seq, parent_phase_operation_hash
  from_state, to_state                     # absent | preparing | presented | validated |
                                           # installed | cleanup_pending | retired | abandoned
  mode                                     # normal | abort
  issued_certificate_hash?, evidence_root
  removal_authoritative_ttl_seconds?, remove_not_before?, reason
                                             # normal edge 用对应进度枚举；abort 只允许
                                             # executor_failure | administrator_cancel | expired

ACMEChallengeEvidenceBodyV1
  schema = 1, cluster_id, evidence_id
  order_ref: ACMEOrderRefV1
  challenge_ref: ACMEDNSChallengeRefV1
  observed_at
  evidence_type                            # authoritative_txt | public_txt | owner_install |
                                           # external_tls_handshake | cleanup_absence | failure |
                                           # admin_cancel
  detail                                   # exact tagged union；恰有一个同名 variant：
    authoritative_txt?                     # {vantage_id,fault_domain,nameserver_set_ref,nameserver_id,
                                           #  nameserver_dns_name,responder_address,fqdn,
                                           #  values[],ttl_seconds,response_transcript_hash}
    public_txt?                            # {vantage_id,fault_domain,fqdn,values[],
                                           #  ttl_seconds,response_transcript_hash}
    owner_install?                         # {owner_device_id,identity_key_id,endpoint_id,
                                           #  identity_projection_hash,issued_certificate_hash,
                                           #  rendered_config_hash,installed}
    external_tls_handshake?                # {vantage_id,fault_domain,endpoint_id,dial_target,
                                           #  server_name,webpki_profile_ref,spki_digest,
                                           #  issued_certificate_hash,transcript_hash,succeeded}
    cleanup_absence?                       # {source_kind,authoritative?,public?}；source_kind
                                           #  authoritative: {vantage_id,fault_domain,nameserver_set_ref,nameserver_id,
                                           #    nameserver_dns_name,responder_address,fqdn,
                                           #    values[],ttl_seconds,response_transcript_hash}
                                           #  public: {vantage_id,fault_domain,fqdn,values[],
                                           #    ttl_seconds,response_transcript_hash}
    failure?                               # {source_kind,source_id,fault_domain?,
                                           #  admin_authorization_hash?,admin_scope_hashes[]?,
                                           #  failure_class,diagnostic_hash}；source_kind 只能为
                                           #  owner_device | policy_vantage | automation_admin；
                                           #  failure_class 只能为 provider_order_failed |
                                           #  dns_publish_failed | dns_validation_failed |
                                           #  certificate_finalize_failed | certificate_parse_failed |
                                           #  owner_install_failed | external_tls_failed | expired
    admin_cancel?                          # {admin_authorization_hash,admin_cert_digest,
                                           #  admin_scope_hashes[],reason="administrator_cancel"}

ACMEChallengeEvidenceV1
  body: ACMEChallengeEvidenceBodyV1
  reporter_key_id
  reporter_signature: AuthorityProofSignatureV1

ACMEChallengeEvidenceLeafV1
  schema = 1, evidence_type, evidence_id, evidence_hash

ACMEChallengeLifecycleStateV1              # certified reducer 输出
  schema = 1, cluster_id, order_ref, challenge_ref, state
  issued_certificate_hash?
  removal_authoritative_ttl_seconds?, remove_not_before?
  last_phase_operation_hash, terminal_tombstone_hash?
```

摘要与 operation mapping 固定为：

```text
acme_order_intent_hash = H(frame("loom-acme-order-intent-v1", JCS(ACMEOrderIntentV1)))
acme_provider_order_state_plaintext_hash = H(frame(
  "loom-acme-provider-order-state-plaintext-v1", JCS(ACMEProviderOrderStatePayloadV1)
))
acme_provider_order_state_binding_hash = H(frame(
  "loom-acme-provider-order-state-binding-v1", JCS(ACMEProviderOrderStateBindingV1)
))
acme_provider_order_checkpoint_hash = H(frame(
  "loom-acme-provider-order-checkpoint-v1", JCS(ACMEProviderOrderCheckpointV1)
))
acme_dns_challenge_intent_hash = H(frame(
  "loom-acme-dns-challenge-intent-v1", JCS(ACMEDNSChallengeIntentV1)
))
acme_issued_certificate_hash = H(frame(
  "loom-acme-issued-certificate-v1", JCS(ACMEIssuedCertificateV1)
))
acme_challenge_evidence_hash = H(frame(
  "loom-acme-challenge-evidence-v1", JCS(ACMEChallengeEvidenceV1)
))
acme_challenge_phase_hash = H(frame(
  "loom-acme-challenge-phase-v1", JCS(ACMEChallengePhaseOperationV1)
))
acme_challenge_lifecycle_state_hash = H(frame(
  "loom-acme-challenge-lifecycle-state-v1", JCS(ACMEChallengeLifecycleStateV1)
))
```

admin/automation `ControlOperationV1` 的 kind/payload 固定为：

| kind | payload/hash |
|---|---|
| `upsert_acme_order_intent` | `ACMEOrderIntentV1` / `acme_order_intent_hash` |
| `record_acme_provider_order_checkpoint` | `ACMEProviderOrderCheckpointV1` / `acme_provider_order_checkpoint_hash` |
| `upsert_acme_dns_challenge_intent` | `ACMEDNSChallengeIntentV1` / `acme_dns_challenge_intent_hash` |
| `record_acme_issued_certificate` | `ACMEIssuedCertificateV1` / `acme_issued_certificate_hash` |
| `acme_challenge_phase` | `ACMEChallengePhaseOperationV1` / `acme_challenge_phase_hash` |

payload schema 都为 1；outer operation ID 独立于可跨 generation 的 order/challenge ID，只有 phase
outer ID 等于 phase payload operation ID。automation cert 的 ACL/scope 必须限定 exact zone、
certificate projection 与这些 kind。provider checkpoint proposal 还必须私下携 matching
`ACMEProviderOrderStateBindingV1`；全部 stable voters 在 checkpoint commit 前持久保存相同 binding
hash/preimage，公开 operation/tree 只含 checkpoint。

order/challenge generation 从 1 连续递增且 refs 重算 exact hash。首个 v2 ACME profile 明确限制为
**一张证书、一个 DNS SAN、一个 order、一个 challenge**：`requested_dns_name` 必须逐字节等于
role-bounded projection 唯一的 `dns_names[0]`；projection 若有多个名字必须拆成多个 identity/order，
不能只验证其中一个。challenge `fqdn` 固定为 canonical lower-case A-label
`"_acme-challenge." + requested_dns_name`，必须属于 exact `challenge_zone_ref`；CNAME alias 是后续
独立 profile，首版不得由 executor临时改名。TXT 是 ACME 返回的规范 UTF-8 exact value。

order 的 `requested_at < expires_at`，差值不超过 directory profile
`maximum_order_lifetime_seconds`；commit 时 candidate logical time/可信墙钟都必须在 skew 内且早于
expiry。challenge 必须满足 `order.requested_at <= introduced_at < expires_at <= order.expires_at`，所有
`absent→preparing→presented→validated→installed` 边也必须在两种时间均未过期时发生；abort/
cleanup 可在过期后继续。directory/account/issuer/zone/policy refs 必须从 exact parent state 解析，
requested name、CSR/SPKI、role、suffix/EKU/OID 都在其 scope 内。

provider checkpoint/binding 的 cluster/order ref 与 order intent 必须相等；binding hiding nonce 解码
为 32 bytes，account artifact 等于 order，state artifact purpose 必须是 `acme_order_state` 并满足
§6.2 availability。解封的 `ACMEProviderOrderStatePayloadV1` 必须重算 plaintext hash，directory ref
相等，URL 都是 canonical HTTPS 且 origin 属于 directory profile 的 exact allowlist，authorization
URLs 按 UTF-8 bytes 排序去重且非空；每次请求继续使用 frozen WebPKI profile/server name 且禁止
redirect。替任 executor
只从该 private binding恢复同一 order/finalize/authz URLs；不能凭 public hash新建另一个 order。

checkpoint registry 的唯一键是 exact `(cluster_id,order_id,generation,acme_order_intent_hash)`。
reducer 先按该键执行 durable first-result CAS：不存在时只接受
`expected_checkpoint="absent"`，并要求 matching private binding 在同一提交前已由全部 stable voters
持久保存；已存在且 checkpoint hash 相同是幂等重放并返回原 bytes，不同 hash/state binding 或第二个
outer operation ID 一律冲突失败。provider `newOrder` 与 Raft commit 之间崩溃可能留下无 authority
orphan order，只能按 §15 retention 清理；任何 DNS、finalize、install 或 cleanup 副作用都只能引用首个
certified checkpoint，不能挑另一个外部 order。

issued certificate object 的 order/challenge refs 必须 exact；leaf CSR public key、唯一 SAN、issuer
profile、有效期和 SPKI 逐字段满足 CertificateIntent/projection/order，链用 exact WebPKI/issuer
profile 验证，不能相信 executor 的 `validated` boolean。证书/链均为 DER 后无 padding base64url，
chain 从 issuing intermediate 到 trust anchor 前一张排序且不得重复或夹无关证书。
issued-certificate registry 的唯一键是 exact `(order_ref,challenge_ref)`，同样先执行
`expected_issued_certificate="absent"` first-result CAS：同一 object hash 重放返回原 bytes，任何不同
leaf/chain/hash 或 outer operation ID 冲突均失败关闭。只有该 first certified object 可满足 validated/
installed phase；ACME provider 后续返回的另一张同样有效证书只能作为 orphan 留存，不能由 executor
临时选中。

evidence `detail` 的 tag 必须与唯一出现的 variant 相等，其余 variant 必须缺失；`values[]` 按 UTF-8
bytes 排序去重，IP/hostname/dial target 用各自 canonical wire。每个 body 的 cluster/order ref/
challenge ref 必须逐字段等于 phase，`observed_at` 在 policy max age/skew 内。signature 覆盖
`frame("loom-acme-challenge-evidence-signature-v1", JCS(ACMEChallengeEvidenceBodyV1))`：
`reporter_key_id` 和 signature 内的 algorithm/key ID 必须逐字段等于按下述分支解析出的 exact
Device/admin `AuthorityProofKeyV1`，并按 §6.2 的长度、low-S 与 canonical base64url 规则验证；
`owner_install` 只能由 projection owner current identity 签且 `installed=true`；authoritative/public/
external/cleanup 只能由 order 所指 DNS/port policy 中 exact vantage key 签，detail 的 vantage/fault
domain 必须等于 key ref。failure 的 `source_kind=owner_device` 只允许 projection owner key 且
`source_id=owner_device_id`；`policy_vantage` 只允许 frozen policy 中 exact vantage key，source/fault
domain 必须等于 ref；`automation_admin` 必须带 active exact `AdminAuthorizationV1` hash，reporter key、
cert validity、`allowed_operation_kinds` 与按 hash bytes 排序去重的 `admin_scope_hashes[]` 必须共同覆盖
本 order 的 endpoint、certificate projection 与 challenge zone。其他 source kind、failure class 或
条件字段组合严格拒绝。`admin_cancel` 也只能由满足同一 exact ACL/scope 的 active admin key 签，
`admin_cert_digest`、authorization hash、reporter key 和 scopes 必须逐字段对应；它不能由 owner、
vantage 或 executor 自报替代。`installed/succeeded=false` 只能作为 failure，不能满足 success predicate。

authoritative detail 的 nameserver-set ref 必须等于 challenge zone 的 frozen set，ID/name 等于 exact
member；presented 与 cleanup absence 都要求 set 中**每个** member 的 fresh evidence，不能信 sender
自报 denominator。public/TLS evidence 达到 frozen policy 的不同 vantage 与 fault-domain 门槛。
`evidence_root` 对按 `(evidence_type,evidence_id)` 排序去重的
`ACMEChallengeEvidenceLeafV1` 使用 §7.1 RFC 6962 规则；leaf hash从随 operation 交付的完整签名对象
重算。跨 order/challenge generation、edge、过期或错误 reporter 的 evidence 全部拒绝。

phase seq 从 1 连续递增，parent hash、order/challenge refs 全程冻结。normal reducer 只允许：
`absent→preparing`（empty evidence root；certified 后才把 TXT 纳入 desired union）→ `presented`
（所有权威 NS 与 policy 数量公共视角看到完整 active TXT union）→ `validated`（引用已 certified 的
exact certificate object）→ `installed`（owner install + policy 数量 external TLS success）→
`cleanup_pending`（固化全部权威回答的实际最大 TTL，certified 后才授权删除本 value）→ `retired`
（权威/公共 absence、实际 TTL + propagation safety 已满足，写 terminal tombstone）。

失败/取消不使用无出边的 `failed` state。`mode=abort` 只允许 `absent→abandoned`（TXT 从未获发布
authority）或 `preparing|presented|validated|installed→cleanup_pending`（保留当前旧证书并走同一安全
删除流程）；它不能直接删 TXT 或宣称 retired。`reason=executor_failure` 必须引用至少一份上述枚举
failure 且不得包含 `admin_cancel`；`reason=administrator_cancel` 必须引用恰一份 matching
`admin_cancel`，并拒绝 failure；`reason=expired` 只在 candidate 两种可信时间均晚于 challenge
`expires_at` 时成立，evidence root 必须为空。除 expired 外 abort root 不得为空，且不得混合两种
授权途径；与本次 edge 无关的 evidence 也必须拒绝。`abandoned/retired` 均为 terminal，
`terminal_tombstone_hash` 等于使其进入终态的 phase hash。

同一 FQDN 的 provider desired RRset 精确是 lifecycle state 为
`preparing|presented|validated|installed` 的 certified challenge TXT value 并集；`absent`、
`cleanup_pending`、`retired`、`abandoned` 均不在集合。cleanup 只以
zone/order/challenge/generation/value CAS 删除本值，不得 replace 整组。进入 cleanup_pending 时用
checked addition 导出 `remove_not_before`；retired 前再次证明本值缺失且其他 active values全部仍在。
无 provider CAS/fencing 时 destructive cleanup 只能 supervised。备份/GC 在证书与审计 retention
越过前不得删除 order、private state binding、challenge、certificate、evidence、phase 或 tombstone
preimage。

流程为：target 按 §6.2 生成 exact-version key/CSR/PoP → CertificateIntentV1 与逐字段匹配的
`PublicEndpointIntentV1(exposure=public)` 被 Raft commit、apply/recompute 并取得 replication QC →
order intent certified → ACME executor 创建一次 provider order、封装 private state并让 public
checkpoint certified → challenge intent 与 `absent→preparing` phase certified → executor 展示 TXT →
确认权威传播 → 完成签发 → target 原子安装完整链 → 平滑 reload → 外部握手验证 → CRDT 回报。
并行 order 的 TXT 以 `(fqdn,order_id,value)` 分别归属，期望 RRset 是全部 active order value
的并集；cleanup 只能按 owner/order/value 和 generation 条件删除本 order 的 value，禁止
replace/清空其他 order 的 challenge；provider 无条件删除时按 §15 留存并转人工。

续签窗口、失败阈值和证书到期是签名运行事实；renew 不修改 ControlSet。若沿用同一 SPKI，
可在现有 pin 下换证；若换 key，必须先提交包含 old+new 两个
`certificate_identity_projection_hashes` 的新 PublicEndpointIntent，再让包含两者 SPKI pin
的 EndpointSet certified 并让 reader 获得 overlap，然后安装/切换新 listener。只有当没有
published listener、available 未过期 invite、仍在 retry window 的 `claim_reserved|consumed` invite 或
offline-compatible view 仍引用 old projection，且缓存/离线
窗口均满足后，才能用新 PublicEndpointIntent 将数组收缩为 new 并移除 old pin。旧证书在新
证书验证成功前保留，私钥和证书文件不得经静态分发树公开。

---

## 13. EndpointSet 与公网端口模型

单个 `public_endpoint + inbound_port` 无法表达轮换。目标模型把用户看到的逻辑入口和物理
listener 分开：

```text
EndpointSetV2
  schema = 2, cluster_id, endpoint_set_id
  generation
  source: EndpointSetSourceV1
  endpoints[]                  # 按 LogicalEndpoint.id UTF-8 bytes 排序、拒绝重复
  digest

EndpointSetSourceV1            # exact tagged union，恰有一个 variant
  kind                         # genesis | operation
  genesis?                     # {recovery_epoch}
  operation?                   # {parent_head_hash,operation_id,control_revision}

LogicalEndpointIntentV1
  schema = 1, cluster_id, endpoint_id, generation
  role, owner_device_id, protocol
  public_endpoint_intent_hash, public_endpoint_intent_generation
  address_or_domain_intent_hash
  transport_identity           # 与下列 LogicalEndpoint 使用同一 exact tagged union

LogicalEndpoint
  id                         # 稳定；如 data_ingress/demo-a
  logical_endpoint_intent_hash, logical_endpoint_intent_generation
  role                       # control_api | enroll | device_config | device_report
                             # | distribution | data_ingress
  owner_device_id
  protocol                   # https | hysteria2 | wireguard | trojan | ...
  public_endpoint_intent_hash, public_endpoint_intent_generation
  address_or_domain_intent_hash
  transport_identity         # tagged union，必须与 protocol 匹配：
    tls?                     # HTTPS/Hysteria2/Trojan：server_name + WebPKI profile
      server_name, webpki_profile_ref: WebPKIProfileRefV1
      spki_pins[]            # TlsSpkiPinV1；按 (pin_generation,digest) 排序
    wireguard?               # WireGuard：peer key ID + 精确 public key/digest
      peer_public_key_id, peer_public_key
  listeners[]

ListenerGeneration
  generation
  dial_target                # tagged union：dns_name | ip_literal，恰有一个
  public_port
  local_port?                # NAT/port-map 不同号时显式
  address_families[]         # 非空子集；固定 ipv4 → ipv6 枚举顺序
  https_base_url?            # protocol=https 时必需，否则必须缺失
  credential_generation, credential_artifact_hashes[]
  certificate_identity_projection_hash? # 不随同 SPKI 例行续签变化
  introduction: ListenerIntroductionV1
  retire_not_before?
  published_state            # advertised | preferred | draining
  rotation_operation_hash

TlsSpkiPinV1
  digest                     # "sha256:" + 64 位小写 hex，覆盖 DER SubjectPublicKeyInfo
  pin_generation
  credential_generation
  certificate_identity_projection_hash
  not_before, not_after      # RFC 3339 UTC/Z；not_before < not_after

ListenerIntroductionV1        # exact tagged union，恰有一个 variant
  kind                         # genesis | operation
  genesis?                     # {recovery_epoch}
  operation?                   # {parent_head_hash,operation_id}

PortRotationPolicyV1
  schema = 1, cluster_id, policy_id
  pool_ref: PortPoolRefV1
  trigger                          # tagged union：manual | periodic | degraded
    manual?                        # exact empty object
    periodic?                      # schedule_anchor, interval_seconds, window_start_minute_utc,
                                   # window_end_minute_utc, jitter_max_seconds
    degraded?                      # cooldown_seconds
  minimum_lifetime_seconds, minimum_overlap_seconds
  max_offline_compatibility_seconds, quiet_period_seconds
  evidence_policy_hash
  provisioning_principal_scope_hash, automatic_principal_scope_hash?, emergency_scope_hash

PortRotationAuthorizationScopeV1
  schema = 1, cluster_id, scope_id, generation
  scope_kind                              # owner | provisioning | automatic | emergency
  principals[]                           # PortRotationPrincipalRefV1，按 canonical ref bytes 排序
  endpoint_ids[], owner_device_ids[], pool_ids[]
  roles[], protocols[], trigger_kinds[], transition_edges[]

PortRotationPrincipalRefV1               # exact tagged union，恰有一个 variant
  kind                                    # device_identity | admin_certificate
  device_identity?                       # {device_id,identity_key_id}
  admin_certificate?                     # {admin_cert_digest,admin_key_id}

PortRotationEvidencePolicyV1
  schema = 1, cluster_id, policy_id
  max_evidence_age_seconds
  vantages[]                              # RotationVantageRefV1，按 vantage_id 排序
  external_vantage_count_per_address_family # >= 2
  transport_vantage_count                 # >= 2，与 external 门槛分开
  prefer_min_attempts_per_window, prefer_max_attempts_per_window
  prefer_min_success_basis_points
  prefer_max_loss_basis_points, prefer_max_rtt_milliseconds
  reader_ack_min_basis_points              # 0..10000
  degraded_failure_vantage_count, degraded_failure_window_seconds
  drain_no_new_handshakes_seconds, drain_zero_active_sessions_seconds

RotationVantageRefV1
  vantage_id, device_id, identity_key_id, fault_domain
  address_families[]                       # 固定 ipv4 → ipv6 顺序，非空

PortPoolRefV1
  pool_id, generation, port_pool_hash

PortPoolV1
  schema = 1, cluster_id, pool_id, generation
  protocol, transport_profile, network_namespace
  owner_scope_hash
  public_port_ranges[], local_port_ranges[] # PortRangeV1，按 (start,end) 排序
  reserved_ports[]                          # 升序去重
  reuse_quarantine_seconds

PortRangeV1
  start, end                                # 闭区间；1 <= start <= end <= 65535
```

所有 `*_seconds`、UTC minute 和 port/generation 都是非负 64 位整数；interval/minimum lifetime/
overlap/quiet period 必须大于 0，UTC minute 在 0..1439，jitter 小于 interval。trigger union 恰有一个
variant，非 periodic 时不得出现 window/jitter；window 跨午夜用 start > end 明确表示。
Evidence policy 的所有时间/次数阈值是非负整数，vantage count 至少 2，basis points 在
0..10000，RTT 使用整数毫秒，`prefer_min_attempts_per_window >= 1` 且不大于
max。`vantages[]` 的 vantage/device/key/fault-domain 非空且各自按 schema 唯一；每个 key ID
必须逐字节等于候选 parent certified Device identity 中的当前 key，被撤权/暂停
Device 不得作为 vantage。因此 policy 承诺的是 exact authority refs，不是实现本地的
观测者名单。两个 policy hash 固定为：

```text
port_rotation_policy_hash = H(frame(
  "loom-port-rotation-policy-v1", JCS(PortRotationPolicyV1)
))
port_rotation_evidence_policy_hash = H(frame(
  "loom-port-rotation-evidence-policy-v1", JCS(PortRotationEvidencePolicyV1)
))
port_rotation_authorization_scope_hash = H(frame(
  "loom-port-rotation-authorization-scope-v1", JCS(PortRotationAuthorizationScopeV1)
))
port_pool_hash = H(frame("loom-port-pool-v1", JCS(PortPoolV1)))
logical_endpoint_intent_hash = H(frame(
  "loom-logical-endpoint-intent-v1", JCS(LogicalEndpointIntentV1)
))
listener_resource_intent_hash = H(frame(
  "loom-listener-resource-intent-v1", JCS(ListenerResourceIntentV1)
))
```

所有 `rotation_policy_hash/evidence_policy_hash` 必须由携带的 exact policy bytes 重算并匹配；
`pool_ref`、scope hash 指向的对象也必须存在于 phase parent certified
state，不能由 scheduler 本地补
默认单位、门槛或窗口。PortPool 的 ranges 必须非空、已排序、区间内/区间间不
重叠，每个 port 及 reserved port 都在 1..65535；public/local pool、protocol、transport
profile、network namespace 和 owner scope 必须与 endpoint/target Device 精确匹配。
`local_port` 缺失时它精确等于 public port；存在时必须分别落在 local/public ranges，
  且两者都不在 reserved/current/transition/blocked 集合；默认也排除全部 quarantine。唯一例外是
  phase_seq=1 的 `absent→allocated` 携带 exact `PortQuarantineReuseClaimV1`：old tombstone 必须属于
  matching pool/namespace/protocol/ports，完整旧 lifecycle bytes 必须重算为
  `old_listener_lifecycle_state_hash`，其状态仍为 quarantined、尚无
  `reused_by_phase_operation_hash`，candidate time 已达到 `reuse_not_before`，且旧 client floor/
  compatibility 门槛由 certified history 重新满足。claim 的 `reuse_evidence_ids[]` 必须恰好指向当前
  phase root 中与 old lifecycle/namespace/protocol/ports 全部相等的 fresh `port_reuse_readback`
  evidence：`socket` 必须一份；旧 spec 的 firewall/mapping requirement 为 required 时各必须一份，
  存在 provider binding 时还必须一份 `provider_lease`，not-applicable 项不得伪造。每份都要求
  `absent=true` 和非空 transcript hash；缺项、额外项、重复 check kind 或 ref/hash 不等均拒绝。
  该同一 certified phase 原子
  分配新 listener，并把 old tombstone 的 `reused_by_phase_operation_hash` 写为新 phase hash；竞争
  reuse 只有一个 CAS 成功，历史 tombstone不删除。首版 blocked
  tombstone 永久保留在排除集合，无解封 operation；需要重用时必须先升级协议并定义新
  exact reducer edge，不能由当前 allocator 自行解除。
  `pool_ref` 三字段必须等于
所携 pool 并重算 hash；端口随机值在 proposal 前固定，voter 只校验授权与唯一性。

scope 的所有数组均非空、按对应 enum/UTF-8 canonical bytes 排序并拒绝重复，
`transition_edges[]` 只能使用本节定义的 `from_state->to_state`；没有 wildcard、前缀或本地
ACL 别名。principal ref 必须在 parent head 解决到当前未撤权的 exact Device identity
或 admin certificate/key，且现有 admin ACL 仍须允许 outer operation kind；scope 只能进一步
收紧 ACL，不能扩权。`scope_kind=owner` 的 principals 必须全是
`device_identity`；`provisioning|automatic|emergency` 的 principals 必须全是
`admin_certificate`，因为 exact `ControlOperationV1` 只由 admin cert/key 签名。任何其他
kind/signer 组合在 decode/validation 时拒绝。`PortPoolV1.owner_scope_hash` 必须解决到
`scope_kind=owner` 且覆盖 pool ID、endpoint、owner Device、role 和 protocol；owner receipt
的 Device principal 必须在其 `principals[]` 中。policy 的
`provisioning_principal_scope_hash` 必须解决到 `scope_kind=provisioning`，只允许
`initial_provision` 和初次建立 listener 所需的正常边。
`automatic_principal_scope_hash` 存在时必须解决到 `scope_kind=automatic`，且自动
proposal 的 admin-certificate principal、trigger、pool、endpoint 和每条 transition 都在其精确
集合中；缺失即禁用自动调度。`emergency_scope_hash` 必须解决到
`scope_kind=emergency`，`admin_override.scope_hash` 必须与它逐字节相等，报告者
admin cert/key、endpoint、pool 和被跳过的 transition 必须全部在 scope 中。scope 内
`cluster_id` 必须与 policy/pool/phase 相等；三种用途的 scope kind 不得互换。

`LogicalEndpointIntentV1` 由通用 operation 以
`kind="upsert_logical_endpoint_intent",payload_schema=1,payload_hash=logical_endpoint_intent_hash`
提交，同 endpoint ID 的 generation 严格递增。其 public intent/address hash、owner、role、
protocol 与 transport identity 必须与同 candidate 中已认证对象相等。客户端
`LogicalEndpoint` 除 listeners/source 外的所有字节都必须从该 exact intent 投影，
intent hash/generation 也必须相等；轮换 phase 不得自行补造 role、owner 或 identity。

每个 listener 的实际拨号目标必须由同一个 `address_or_domain_intent_hash` 唯一决定，不能由
executor、DNS 回答或本机网卡替换：

- `managed_domain`：`dial_target.dns_name` 必须逐字节等于 resolved binding 的 `fqdn`，
  `address_families[]` 必须逐字节等于其 `allowed_address_families[]`；
- `explicit_address`：`dial_target.ip_literal` 必须等于 resolved claim 的 canonical `address`，
  `address_families[]` 必须恰含该 claim 的一个 family；
- `managed_domain_with_address`：仍以 binding `fqdn` 为 dial target，family 数组等于 binding allowed
  set，且所携 claim 必须是该 binding 当前 `preferred|overlapping`、未过期的同 family value。

因此改变 FQDN、显式地址或允许 family 必须创建更高 AddressOrDomain/PublicEndpoint/Listener
generation；纯 DNS claim 轮换可保持 hostname listener 不变，但只能经 §12.2 reducer 改 RRset。
`ListenerGeneration`、`ListenerImmutableSpecV1` 与 `InviteEnrollSeedV2` 的
`credential_artifact_hashes[]` 必须逐字节相同、按 hash bytes 排序去重且非空，是
PublicEndpointIntent 排序 credential 数组的子集；每个 hash 一一解析到完整
`SecretArtifactRefV2`，purpose/owner/public identity 与 role、protocol、transport profile 一致。
TLS listener 的 certificate projection role 必须等于 endpoint role，projection key artifact hash
必须是该 listener credential 数组的成员，其 ref generation 等于 `credential_generation`；pin 的
projection/digest/credential generation 也逐字段一致。任何 ref/hash/bytes 缺失都不能 render。

同一 LogicalEndpoint 的 listener `generation` 必须唯一并升序，恰有一个 `preferred`，其余只能是
`advertised` 或 `draining`；`address_families` 拒绝未知值与重复。TLS endpoint 的 pin 集合非空，
`pin_generation`、`(credential_generation,digest)` 均唯一；每个可拨 listener 的
`credential_generation` 至少对应一个在发布该 Device view 的当前 certified head
`committed_logical_time` 有效的 pin。客户端用该 head（扫码前用 descriptor 中同值且硬封顶）的
`max_clock_skew_seconds` 和本地可信墙钟判断：
仅当 `not_before <= local_now + max_clock_skew` 且
`local_now - max_clock_skew <= not_after` 才可接受；墙钟不可用或全部 pin 过期时，Enrollment
token 和管理请求 fail closed，已有数据面仅按 LKG/离线策略处理。

HTTPS listener 的 `https_base_url` 必须是规范化的
`https://<server_name>:<public_port>/<prefix>/`：host 小写 IDNA ASCII、显式十进制 port、path 以
`/` 开始和结束，禁止 userinfo、query、fragment、点段和 percent-encoded path separator；host 必须
逐字节等于 TLS `server_name`。即使 `dial_target` 是 IP，连接也拨该 IP、但 SNI/HTTP Host 和 URL
仍使用 server_name。首版 `role_route_profile="loom-https-role-v2"` 固定从 base URL 解析以下相对
路径，服务端不得用重定向改 role：

| role | 方法与相对路径 |
|---|---|
| `control_api` | 管理 operation 按版本化 API schema 使用 `operations`；Create Device 为 `POST devices` |
| `enroll` | 无 token proof 下载为 `GET invites/{invite_id}/proof/{proof_bundle_hash_hex}`；claim 为 `POST claims` |
| `device_config` | `GET devices/{device_id}/view` |
| `device_report` | `POST devices/{device_id}/reports` |
| `distribution` | `GET objects/{sha256_hex}` 与 `GET current` |

相对路径变量只能使用 schema 规定的 canonical URL-safe ASCII，`*_hash_hex` 是去掉 `sha256:` 前缀的
64 位小写 hex；RFC 3986 resolve 后的 URL 必须仍位于同一 origin 和 base path 下。`data_ingress`
不填写 `https_base_url`，其握手由对应 transport profile 定义。

首个 v2 profile 的 role×protocol 组合固定如下，未知或交叉组合在解析时失败：

| role | 允许 protocol | 必需 transport identity |
|---|---|---|
| `control_api` / `enroll` / `device_config` / `device_report` / `distribution` | `https` | 精确 hostname + WebPKI + generation/overlap-bounded TLS SPKI pins |
| `data_ingress` | `hysteria2` / `trojan` | 精确 server name + WebPKI + generation/overlap-bounded TLS SPKI pins |
| `data_ingress`（专用后续 profile） | `wireguard` | 精确 peer public key；不得填写或验证为 TLS SPKI |

WireGuard 组合只有在 §14 的双 interface/peer/key/address/route profile 完成后才能进入自动轮换；
在此之前 EndpointSet 最多把它作为显式 disruptive maintenance 坐标。TLS union 与 WireGuard
union 必须且只能出现一个，`dns_name` 与 `ip_literal` 也必须且只能出现一个。即使使用 IP dial
target，TLS transport 仍须按 EndpointSet 中的 server name 验 hostname/WebPKI 和 SPKI；不能
把 IP literal 当成跳过证书身份的开关。

control voter 之间的 Raft/mTLS wire 地址只存在 private
`ControlPeerDirectoryV1.members[].peer_endpoints[]`；目录先以 opaque `member_id` 与公开 ControlSet
一一对应，再在私有字段中映射 owner Device ID。只有有权读取目录的管理 UI 才能显示
`control.peer_rpc_endpoints`，不得把它序列化进公开 ControlSet、transition、邀请或 mirror。面向
客户端的公开 API 地址只存在 `EndpointSet(role=control_api)` 并按 `owner_device_id` 关联；不能把
一份 endpoint 列表同时当成员资格、peer 拨号目录与公网发现来源。

每个公开 LogicalEndpoint 必须逐字段匹配同一 certified `PublicEndpointIntentV1` 的 hash、
generation、owner、role、protocol 和 address/domain ref；`exposure=private`、intent 尚未
certified 或实际入口超出 intent scope 时不得进入客户端 EndpointSet。EndpointSet digest 经
D105 Device leaf 绑定，单个 executor 不能靠实际创建成功把新地址或角色追加进返回值。

`EndpointSetSourceV1` 的 `operation` variant 以
`parent_head_hash + operation_id + control_revision` 唯一指向使这份 EndpointSet **内容最后一次
变化**的已提交 operation 及其坐标；`operation_id` 是提案前固定、且不从 EndpointSet bytes
导出的 operation body ID：普通管理变化取 `ControlOperationBodyV1.operation_id`，首次 claim
生成 Device 专属 EndpointSet 时允许取同一 head 的
`EnrollmentClaimOperationBodyV1.operation_id`。两种 variant 都必须在该 head 的 operation tree 中
存在且全局重复 ID 规则仍适用。不得把生成后才存在的当前 head hash、outer
operation object hash 或由 EndpointSet digest 导出的 hash 写回 EndpointSet，否则会形成
`EndpointSet → Device root → head/operation → EndpointSet` 循环。revision 单独不得作为跨
recovery lineage 的标识。listener 的 `ListenerIntroductionV1.operation` 仍只允许 exact admin
allocate operation：它携带提案的 parent head 与预先固定 operation ID，不携带 phase/object hash；
claim operation 不能借此创建公网 listener。

初始 v2 bootstrap 或 emergency Genesis 在没有前驱 operation 的同一 head 中生成新对象时，只能
使用 `genesis{recovery_epoch}` variant；该对象还必须是相应 lineage 首个 head 所承诺 state 的一
部分，其他 head 禁止伪用 genesis variant。这个不含自身 head/statement hash 的数值坐标避免
自引用；cluster ID、endpoint/listener ID、generation 与 recovery epoch 共同区分对象。Genesis
中首次就作为 `preferred` 发布的 listener 必须使用
`rotation_operation_hash=EMPTY_OPERATION_HASH_V1`；任何 operation 后引入或变更过状态的 listener
均禁止该 sentinel，必须指向实际 phase payload hash。端点 bytes
未变时必须复用相同 generation、source provenance 和 digest；不能因无关 SSOT/审计提交重写它，
否则会迫使相同 Device generation 出现不同 leaf。只有 canonical EndpointSet 内容变化才递增
generation、把 source 更新为本次 operation 坐标，并推动所有引用它的 Device view 增加各自
generation。
EndpointSet 本体因此不重复放 recovery/control/head 坐标；这些坐标由 DeviceViewEnvelope 的
certified head/floor 绑定。recovery 或 ControlSet 变化但端点授权内容不变时，可以在新 head
中继续承诺完全相同的 EndpointSet bytes，而不会伪造一次 Device generation 变化。
Device leaf 的 `endpoint_set_hash` 必须精确等于：

```text
digest = H(frame("loom-endpoint-set-v2", JCS(EndpointSetV2 excluding digest)))
```

计算前还必须确认 endpoint/listener/pin/address-family 数组满足上述排序、唯一性与枚举顺序；
验证器拒绝 digest 自包含、未知 EndpointSet schema 或相同
`endpoint_set_id/generation` 的不同 digest。

每一轮端口变化由一个 `rotation_id` 串起，而不是让 reducer 根据 receipt 猜当前阶段：

```text
PortRotationPhaseOperationV1
  schema = 1, cluster_id, operation_id, rotation_id, phase_seq
  endpoint_id, logical_endpoint_intent_hash, target_generation, replaced_generation?
  parent_phase_operation_hash       # 首步使用 EMPTY_OPERATION_HASH_V1
  listener_spec_hash
  listener_transitions[]            # PortRotationListenerTransitionV1，按 generation 排序
  trigger_proof: PortRotationTriggerProofV1
  quarantine_reuse_claim?           # PortQuarantineReuseClaimV1；仅首个 absent→allocated 可出现
  rotation_policy_hash, evidence_root
  reason

PortRotationListenerTransitionV1
  generation, from_state, to_state
  disposition?                      # PortDispositionReasonV1；只在进入 retired/abandoned 时必需

PortQuarantineReuseClaimV1
  pool_ref: PortPoolRefV1
  old_endpoint_id, old_listener_generation, old_listener_lifecycle_state_hash
  network_namespace, protocol, public_port, local_port
  reuse_evidence_ids[]              # 按 evidence ID UTF-8 bytes 排序去重，非空

PortRotationCancellationV1
  schema = 1, cluster_id, operation_id, rotation_id, endpoint_id
  expected_last_phase_operation_hash, target_generation, listener_spec_hash
  mode = "cancel_unpreferred_target"
  reason                            # dependency_superseded | admin_cancel
  changed_dependency_hash, replacement_dependency_hash?
  target_transition: PortRotationListenerTransitionV1
  evidence_root

EndpointEmergencyWithdrawalV1      # 独立于是否存在 active rotation
  schema = 1, cluster_id, operation_id, endpoint_id
  expected_logical_endpoint_intent_hash, expected_public_endpoint_intent_hash
  expected_listener_states_root
  reason                            # credential_revoked | certificate_revoked |
                                    # public_endpoint_revoked | administrative_block
  revoked_dependency_hash?, emergency_scope_hash
  listener_transitions[]            # PortRotationListenerTransitionV1，按 generation 排序
  evidence_root

EndpointWithdrawalListenerLeafV1
  schema = 1, listener_generation, listener_spec_hash
  state, last_phase_operation_hash

EndpointWithdrawalEvidenceBodyV1
  schema = 1, cluster_id, evidence_id, withdrawal_operation_id, endpoint_id
  observed_at, admin_authorization_hash, admin_cert_digest, admin_key_id
  emergency_scope_hash, reason
  revoked_dependency_hash?

EndpointWithdrawalEvidenceV1
  body: EndpointWithdrawalEvidenceBodyV1
  reporter_signature: AuthorityProofSignatureV1

EndpointWithdrawalEvidenceLeafV1
  schema = 1, evidence_id, evidence_hash

PortRotationTriggerProofV1          # 整个 rotation lineage 逐字节不变
  schema = 1
  kind                              # initial_provision | manual | periodic | degraded
  detail                            # exact tagged union：
    initial_provision?              # exact empty object
    manual?                         # exact empty object
    periodic?                       # {period_number,chosen_jitter_seconds,scheduled_not_before}
    degraded?                       # {failure_evidence_root}

ListenerImmutableSpecV1
  endpoint_id, generation, dial_target, public_port, local_port?
  address_families[], https_base_url?
  credential_generation, credential_artifact_hashes[], certificate_identity_projection_hash?
  render_contract_id, rendered_config_hash
  firewall_requirement: ListenerResourceRequirementV1
  mapping_requirement: ListenerResourceRequirementV1
  introduction: ListenerIntroductionV1
  retire_not_before?

ListenerResourceRequirementV1            # exact tagged union
  mode                                    # required | not_applicable
  required?                               # ListenerResourceIntentRefV1
  not_applicable?                         # exact empty object

ListenerResourceIntentRefV1
  resource_kind, resource_intent_id, generation, resource_intent_hash

ListenerResourceIntentV1
  schema = 1, cluster_id, resource_intent_id, generation
  resource_kind                           # firewall | mapping
  endpoint_id, listener_generation, owner_device_id
  network_namespace, protocol, public_port, local_port
  executor_profile_id, provider_binding_hash?

ListenerRuntimeRenderInputV1
  schema = 1, cluster_id
  logical_endpoint_intent: LogicalEndpointIntentV1
  public_endpoint_intent: PublicEndpointIntentV1
  address_or_domain_intent: AddressOrDomainIntentV1
  domain_binding_intent?: DomainBindingIntentV1
  address_claim?: AddressClaimV1
  credential_artifact_refs[]: SecretArtifactRefV2
  certificate_identity_projection?: CertificateIdentityProjectionV1
  listener_spec_without_rendered_config_hash
  resource_intents[]                     # exact ListenerResourceIntentV1，firewall → mapping 排序

ListenerLifecycleStateV1             # reducer 在 certified control state 中保留
  schema = 1, cluster_id, endpoint_id, listener_generation
  logical_endpoint_intent_hash, listener_spec_hash
  state                              # allocated | preparing | advertised | preferred |
                                     # draining | retired | abandoned
  port_disposition                   # in_use | quarantined | blocked
  reuse_not_before?                  # 只在 quarantined 时必需
  disposition_reason?                # PortDispositionReasonV1；只在非 in_use 时必需
  reused_by_phase_operation_hash?    # 仅已被一次性复用的 quarantined tombstone 必需
  last_phase_operation_hash
  last_changed_control_revision

PortDispositionReasonV1
  code                               # normal_rotation | cancelled_before_publish | setup_failed |
                                     # port_conflict | security_revocation |
                                     # administrative_block | abuse_detected
  evidence_ids[]?                    # 按 evidence ID UTF-8 bytes 排序去重

PortRotationEvidenceBodyV1
  schema = 1, cluster_id, evidence_id, rotation_id
  endpoint_id, target_generation, observed_at
  evidence_type                    # listener_ready | external_reachability | reader_ack |
                                   # transport_window | connection_window | failure | admin_override |
                                   # port_reuse_readback
  detail                           # exact tagged union；恰与 evidence_type 对应：
    listener_ready?                # {listener_spec_hash,config_hash,listener_bound,
                                   #  credential_loaded,firewall:ListenerResourceReadyStatusV1,
                                   #  mapping:ListenerResourceReadyStatusV1}
    external_reachability?         # {vantage_id,fault_domain,address_family,
                                   #  handshake_transcript_hash,succeeded}
    reader_ack?                    # {device_id,device_generation,endpoint_set_digest,
                                   #  listener_generation}
    transport_window?              # {source_id,fault_domain,window_start,window_end,samples[]}
    connection_window?             # {listener_generation,window_start,window_end,
                                   #  new_handshakes,active_sessions}
    failure?                       # {source_id,fault_domain,listener_generation,
                                   #  failure_class,diagnostic_hash}；failure_class 只能为
                                   # bind_failed | credential_failed | firewall_failed |
                                   # mapping_failed | dns_unreachable | handshake_failed |
                                   # loss_threshold | timeout | port_conflict |
                                   # administrative_block | abuse_detected
    admin_override?                # {admin_cert_digest,scope_hash,reason}
    port_reuse_readback?           # {old_endpoint_id,old_listener_generation,
                                   #  old_listener_lifecycle_state_hash,network_namespace,
                                   #  protocol,public_port,local_port,check_kind,
                                   #  resource_intent_hash?,provider_binding_hash?,
                                   #  absent,readback_transcript_hash}；check_kind 只能为
                                   #  socket | firewall | mapping | provider_lease

PortRotationEvidenceV1
  body: PortRotationEvidenceBodyV1
  reporter_key_id
  reporter_signature: AuthorityProofSignatureV1

PortRotationEvidenceLeafV1
  schema = 1, evidence_type, evidence_id, evidence_hash

TransportAttemptSampleV1
  sample_id, outcome               # success | failure
  rtt_milliseconds?                # success 时必需；failure 时必须缺失

ListenerResourceReadyStatusV1      # exact tagged union
  mode                             # ready | not_applicable
  ready?                           # {resource_intent_hash}
  not_applicable?                  # exact empty object
```

`EMPTY_OPERATION_HASH_V1 = "sha256:" + 64 个 ASCII '0'`。对
`parent_phase_operation_hash`，它只在一个 rotation lineage 的 `phase_seq=1` 表示没有前一
phase；对 `ListenerGeneration.rotation_operation_hash`，它只在 §13 已定义的 Genesis
preferred listener 上合法。它与 §7.4 的空 head predecessor 取相同字节值，但字段用途和
允许位置分开校验，不能把普通缺失 hash 静默归一化为它。
`listener_spec_hash = H(frame("loom-listener-immutable-spec-v1", JCS(ListenerImmutableSpecV1)))`，
`listener_lifecycle_state_hash = H(frame("loom-listener-lifecycle-state-v1",`
`JCS(ListenerLifecycleStateV1)))`，
`phase_operation_hash = H(frame("loom-port-rotation-phase-operation-v1",`
`JCS(PortRotationPhaseOperationV1)))`，
`port_rotation_cancellation_hash = H(frame("loom-port-rotation-cancellation-v1",`
`JCS(PortRotationCancellationV1)))`，
`endpoint_emergency_withdrawal_hash = H(frame("loom-endpoint-emergency-withdrawal-v1",`
`JCS(EndpointEmergencyWithdrawalV1)))`，
`endpoint_withdrawal_evidence_hash = H(frame("loom-endpoint-withdrawal-evidence-v1",`
`JCS(EndpointWithdrawalEvidenceV1)))`。同一 `rotation_id` 的 `phase_seq` 从 1 连续递增，parent 必须等于
前一 certified phase operation hash；`target_generation`、`replaced_generation` 和 immutable
spec hash 全程不变。
listener 的 spec 字段一经 allocate 全部不可变，后续只能改变 state 与
`rotation_operation_hash`；要改端口、地址、URL、credential、证书 identity 或 retire 下限必须分配
新的 listener generation。

allocate 时解析到的 logical/public/address/certificate/credential/policy/pool/resource exact hashes
在 rotation lineage 内冻结；旧 bytes 保留供每一 phase 重算，绝不把同 ID 的 latest generation
悄悄代入。任何普通 upsert/revoke 若会改变活动 rotation 引用的依赖，CAS 必须拒绝，直到该 lineage
terminal；唯一例外是同一 certified head 携带下述 cancellation。cancellation 由 §7.1 outer operation
以 `kind="cancel_port_rotation"`、`payload_schema=1`、上式 payload hash 承载，outer/payload operation
ID 与 cluster 必须相等，并精确匹配 parent state 的 active rotation、last phase、target/spec。

`cancel_unpreferred_target` 只允许 target 仍为 `allocated|preparing|advertised` 且另一个旧 listener
仍是唯一 preferred。`target_transition.generation` 必须等于 target，from state 等于 parent，to state
固定为 `abandoned`，disposition 固定为
`PortDispositionReasonV1{code:"cancelled_before_publish"}` 且不得带 evidence IDs；`evidence_root` 必须是规范
empty root。reducer 原子把 port disposition 写为 `quarantined`，并唯一导出
`reuse_not_before = max(cancellation_head.committed_logical_time + PortPoolV1.reuse_quarantine_seconds,`
`ListenerImmutableSpecV1.retire_not_before if present)`，
`last_phase_operation_hash=port_rotation_cancellation_hash`，保留完整 tombstone，然后才
允许 dependency 的更高 generation 生效。若 target 已被任一 available invite 或处于 retry window
的 consumed invite context 固定，还必须按 §14 的 same-context seed survivability 找到替代 seed；
系统中另有 preferred 但不在该 immutable context 并不够。target 已 preferred 后，正常
supersede/admin cancel 必须
等原 rotation 完成再开新 rotation，不能把旧依赖换进半条 lineage。
`withdraw_endpoint` 只用于 credential/certificate/public-intent 的 certified security revocation，
不再塞进要求 active rotation 的 cancellation schema。它使用独立 §7.1 outer operation：
`kind="withdraw_endpoint"`、`payload_schema=1`、payload 为
`EndpointEmergencyWithdrawalV1`/上式 hash，outer/payload cluster 与 operation ID 必须相等。
`expected_listener_states_root` 对从 parent certified state 枚举出的全部非终态 listener 构造
`EndpointWithdrawalListenerLeafV1`，按 listener generation 排序并使用 §7.1 RFC 6962 tree；空树
也使用规范 empty root。logical/public intent、revoked dependency 与 emergency scope/admin ACL
必须 exact 匹配；漏列、额外或任一 listener 状态/last phase 不等均 CAS 失败。

withdrawal 必须携恰一份 `EndpointWithdrawalEvidenceV1`，其 leaf 构成 `evidence_root`。evidence 的
signature 覆盖 `frame("loom-endpoint-withdrawal-evidence-signature-v1",`
`JCS(EndpointWithdrawalEvidenceBodyV1))`；body 的 operation/endpoint/reason/dependency/scope 必须与
payload 逐字段相等，reporter key、admin cert digest 与 authorization hash 必须解析到 parent head 中
同一 active `AdminAuthorizationV1`，其有效期、operation kind 与 emergency scope 覆盖本 endpoint、
owner、pool 和所有跳过的 transition；signature 的 algorithm/key ID 必须等于该 admin 的 exact
`AuthorityProofKeyV1`，并按 §6.2 canonical wire 规则验证。前三种 revocation reason 必须携对应已 certified revocation
对象的 `revoked_dependency_hash`，`administrative_block` 则必须缺失该字段。evidence 的
`observed_at` 同时受 candidate logical time 与 §7.5 可信墙钟/skew 约束；相同 ID 不同 bytes、额外
evidence 或 scope 不匹配均拒绝。
`EndpointWithdrawalEvidenceLeafV1.evidence_hash` 必须等于重算的
`endpoint_withdrawal_evidence_hash`；`evidence_root` 对仅此一个 leaf 使用 §7.1 RFC 6962 leaf/tree
规则，不能拿 port-rotation evidence 的相同字符串 ID 或另一种 leaf schema 代替。

`listener_transitions[]` 必须严格枚举 expected root 中每个且仅一个非终态 listener。withdraw reducer
无论 endpoint 当前是否有 active rotation，都在同一 candidate 中从所有 Device EndpointSet 移除该
logical endpoint：`allocated|preparing|advertised` 只能转到 `abandoned`，`preferred|draining` 只能
转到 `retired`，每项 from state/spec generation 必须等于 parent。前三种 revocation reason 的每项
disposition 固定为 `security_revocation`，administrative block 固定为 `administrative_block`；所有项
`evidence_ids[]` 都恰好引用上述唯一 evidence。reducer 写入 blocked tombstone并关闭相关 active
lineage/lock。executor 随后停止新会话并按 revocation
profile 终止或排空旧会话。此路径明确允许中断且 UI 必须显示 emergency withdrawal，不能宣称
无中断；旧 credential 不得因为没有轮换、或轮换尚未结束而继续获得 authority。
`replacement_dependency_hash` 只在 cancel 的同一 head 已提交 replacement 时出现，否则必须缺失。

`ListenerResourceRequirementV1` 的 tag 与 variant 必须一致。其 mode 必须逐字节等于
resolved `PublicEndpointIntentV1` 中对应的 firewall/mapping mode；`not_applicable`
不得带 ref。`required` ref 的 kind/ID/generation/hash 必须与 parent certified state
的 exact `ListenerResourceIntentV1` 逐字节相等并重算 hash，其
cluster/resource kind/endpoint/listener generation/owner/network namespace/protocol/ports 必须与
listener spec、PortPool 和 logical intent 相等。resource intent 由 §7.1 outer operation 以
`kind="upsert_listener_resource_intent",payload_schema=1,payload_hash=listener_resource_intent_hash`
先行提交；provider binding 存在时也必须是 parent state 的 exact-version hash。

`render_contract_id` 必须等于 candidate head 承诺且 voter 支持的确定性 listener
render contract。`rendered_config_hash` 按
`H(frame("loom-listener-rendered-config-v1", render(render_contract_id,`
`ListenerRuntimeRenderInputV1)))` 重算。render input 必须内嵌从 parent state 解决的
exact logical/public/address-or-domain intent objects、按 union 需要的 exact binding/claim、
与 spec hashes 一一对应并按 hash bytes 排序的完整 `credential_artifact_refs[]`、TLS 时唯一
certificate projection、除
`rendered_config_hash` 外的完整 listener spec，以及每个 required requirement 指向的 exact
resource intent；每个可选字段必须恰好按 variant/protocol 出现，它们的
hash/cluster/owner/protocol/identity/credential refs 必须按上述链式校验逐字节一致。
每个 credential ref 重算 hash 后的数组必须逐字节等于 spec 数组且属于 public intent 授权，不能
只把 hash 字符串传给 renderer。`resource_intents[]` 只携
required 对象，按 firewall→mapping 排序，不得额外或缺失。`render` 只输出规范化
runtime bytes 和 exact-version secret/artifact ref，不读取秘密明文、本机环境或时钟。
因而 voter 能在执行前重算同一期望值，owner 回执不能用另一份本地配置的
hash 替代它。

每个 phase payload 必须由 §7.1 的一个 exact outer `ControlOperationV1` 承载：outer body 的
`kind="port_rotation_phase"`、`payload_schema=1`、`payload_hash=phase_operation_hash`，且 outer/payload
的 `cluster_id` 与 `operation_id` 分别相等。Head 的操作树纳入 outer `object_id`；EndpointSet
listener 的 `rotation_operation_hash` 始终指上述 **phase payload hash**，不指 outer object ID。
每个 phase 的 `logical_endpoint_intent_hash` 必须在 outer parent head 的 certified state 中解决到
唯一 exact `LogicalEndpointIntentV1`，其 cluster/endpoint/owner/protocol 必须与 listener spec、
PublicEndpointIntentV1 和 PortPool 授权一致；同一 rotation 全程不得更换该 hash。
其 `public_endpoint_intent_hash` 必须解决到同一 parent state 的 exact
`PublicEndpointIntentV1`，且 phase `rotation_policy_hash` 必须逐字节等于该 public
intent 的 `listener_policy_hash`；解决出的 `PortRotationPolicyV1.evidence_policy_hash`
又必须逐字节等于 phase 交付并重算的 exact
`PortRotationEvidencePolicyV1` hash。三层的 cluster/policy ID、pool ref、owner、role 与
protocol 必须一致；不得从同一 candidate 挑选另一份更宽松的 policy 或 evidence
policy。
首个 `absent→allocated` payload 中，`ListenerIntroductionV1.operation.parent_head_hash/operation_id`
必须分别等于 outer body 的 `parent_head_hash/operation_id`；它不能引用同一个 payload 的 phase
hash，因此 `phase hash → listener spec → introduction → phase hash` 的环不存在。EndpointSet source
的 operation ID 则等于最后实际改变其 published bytes 的 outer operation ID。

`from_state` 不从 EndpointSet 或 receipt 猜测：reducer 必须对已排序的每个
`listener_transitions[]` 先按 `(endpoint_id,transition.generation)` 在 phase parent effective
state 独立查找 `ListenerLifecycleStateV1`，再一次性校验整个转换后向量。无对象时
只有 target generation 的首步可以使用 `from_state=absent`；有对象时 from 必须等于其
state，且已存 generation 沿用其 stored spec/intent，不得被 target spec 覆盖。
`listener_spec_hash` 只创建/约束 `target_generation`；原子 prefer phase 中的旧 generation
必须按自己已存 spec 从 `preferred→advertised`。每个 certified phase 对数组中每个
generation 都以当前 phase hash/revision 更新对应 lifecycle，整个向量不满足“已发布
endpoint 恰一 preferred”时原子拒绝。`retired/abandoned` 作为不可删除
tombstone 继续参与端口冲突/重用检查。Genesis listener 同样物化该状态，
`last_phase_operation_hash=EMPTY_OPERATION_HASH_V1`、`last_changed_control_revision=1`。因此首次
prefer 可从 intent + immutable spec + lifecycle state 确定性构造完整 LogicalEndpoint，而不是在
提交时临时补字段。

`phase_seq=1` 还必须固定替换关系：初次 provisioning 的 `replaced_generation`
必须缺失；其他 rotation 必须把 parent 已发布 LogicalEndpoint 中唯一
`preferred` generation 写入 `replaced_generation`，且 `target_generation` 大于该 endpoint
所有 lifecycle/tombstone generation。从第 1 阶段到结束，prefer phase 中的
`preferred→advertised`、后续 `advertised→draining→retired` 只能作用于该
`replaced_generation`，不得挑选其他 advertised/draining listener。同 endpoint 存在未结束
rotation 时拒绝第二个 `phase_seq=1`；初次 lineage 在 target 进入 preferred 或 abandoned
时结束，替换 lineage 只在 target abandoned，或 target preferred 且 frozen
`replaced_generation` 进入 retired/blocked tombstone 时结束。该锁定关系由 certified history
纯函数推导，不依赖 scheduler 本地任务列表。
唯一反向边是旧代尚处于 `advertised`、还未进入 draining 时的紧急回切：一个携
exact emergency-scope admin override 的同 lineage phase 必须原子提交 target
`preferred→advertised` 与 frozen replaced `advertised→preferred`，不得涉及第三代。
下一直接 phase 必须以匹配 target generation 的 failure 将 target
`advertised→abandoned`，按 `setup_failed` quarantine，然后 lineage 结束。两个 phase
之间禁止任何其他 edge 或新 rotation；旧代已进入 draining 后首版没有反向
edge，不得由 scheduler 猜测回滚。

disposition 也由 reducer 唯一导出：进入或留在
`allocated|preparing|advertised|preferred|draining` 时必须是 `in_use`，且
`reuse_not_before/disposition_reason` 均缺失。进入 `retired|abandoned` 的 transition 必须
携 disposition，其 code 与导出结果固定为：

| disposition code | 允许的终态 | lifecycle `port_disposition` | evidence 约束 |
|---|---|---|---|
| `normal_rotation` | `retired` | `quarantined` | `evidence_ids` 必须缺失，且 retire 的普通 predicate 全部成立 |
| `cancelled_before_publish` | `abandoned` | `quarantined` | 仅 `cancel_unpreferred_target` 可用，`evidence_ids` 必须缺失且 cancellation root 为空 |
| `setup_failed` | `abandoned` | `quarantined` | 恰一个 ID，指向当前 root 中相同 generation 且 class 为 `bind_failed|credential_failed|firewall_failed|mapping_failed|dns_unreachable|handshake_failed|loss_threshold|timeout` 的 failure |
| `port_conflict` | `abandoned` | `blocked` | 恰一个 ID，指向当前 root 中 `failure_class=port_conflict` 的 owner evidence |
| `security_revocation` | `retired` 或 `abandoned` | `blocked` | 仅 emergency withdrawal 前三种 reason 可用；恰一个 ID，指向 matching withdrawal evidence，dependency hash 必须相等 |
| `administrative_block` | `retired` 或 `abandoned` | `blocked` | phase edge 时恰一个 exact emergency-scope admin override；withdrawal 时恰一个 matching withdrawal evidence；owner/vantage failure 不能永久封禁 |
| `abuse_detected` | `retired` 或 `abandoned` | `blocked` | 一个 scope 匹配的 admin override ID，或至少 `degraded_failure_vantage_count` 个 vantage/fault-domain 去重且 class=abuse_detected 的 ID |

`quarantined` 的
`reuse_not_before = max(candidate_committed_logical_time + PortPoolV1.reuse_quarantine_seconds,`
`ListenerImmutableSpecV1.retire_not_before if present)`；上述 retire predicate 已另外要求
offline/reader/quiet 下限在退出前成立。`blocked` 必须缺失 `reuse_not_before`，且
首版没有离开 blocked 的 reducer edge；它永久保留，不由 admin 现有 operation 或
allocator 随时间清除。当前
承载 operation 的 evidence root 中找不到 reason 指定的全部 exact evidence ID/hash，或
code/state/evidence class 组合不在
表中时，reducer 拒绝 candidate。tombstone 保留 spec 中的 public/local port、namespace、
disposition、`reuse_not_before` 与 last phase hash，因而 PortPool 的
current/transition/quarantine/blocked 集合是
certified history 的纯函数。
`reused_by_phase_operation_hash` 初始必须缺失，只能由上述 exact reuse allocation 的 reducer 写入
一次；其值必须等于实际消费该 quarantine 的 phase hash。已写入者永久不可再次作为 reuse claim，
blocked/非 quarantined state 带此字段也拒绝。这样隔离到期不会靠墙钟自动删除，但显式 certified
proposal 有唯一可竞争的复用 edge。

`trigger_proof` 在同一 rotation 所有 phase 逐字节相同。只当该 endpoint 在 parent
certified state 中从未有过任何 lifecycle/tombstone 且 target generation 为 1 时，首步
`absent→allocated` 必须使用 `kind=initial_provision`；它不与 policy 的 rotation trigger
variant 比较，但 outer author 必须被 `provisioning_principal_scope_hash` 的 exact principal/
endpoint/owner/pool/edge 授权。该 lineage 免旧 preferred listener minimum-lifetime 条件，且
首步 evidence root 必须为空；一旦 endpoint 存在或曾存在任何 lifecycle state，
`initial_provision` 必须拒绝。其他 rotation 的 `trigger_proof.kind` 必须等于
`PortRotationPolicyV1.trigger` 的唯一 variant。manual 的 detail 为空；它不引入第四种
PortRotationAuthorizationScope，outer admin cert 必须由 parent head 的 exact admin ACL 直接
允许 `kind=port_rotation_phase`，且仍受 resolved public intent/policy/pool 和本节正常 edge
predicate 约束。periodic 的 `period_number` 是非负整数，
`0 <= chosen_jitter_seconds <= jitter_max_seconds`，且
`scheduled_not_before == schedule_anchor + period_number*interval_seconds + chosen_jitter_seconds`；
candidate 的 committed logical time 不得早于该值，其 UTC minute 必须落在半开
`[window_start,window_end)`（start > end 时跨午夜）。对同
`(endpoint_id,policy_id)`，period 必须是上一已 certified periodic rotation 加一；若从未执行，
取同时不早于当前 preferred listener 的 minimum-lifetime 下限的最小 period。该分支
只能在已有 preferred listener 时进入，初次建立不得伪造 periodic anchor。chosen
jitter 由提案方在提交前一次生成并固化，voter 不重抽，但严格验范围、公式、窗口与
未重放 period。

degraded 的 `failure_evidence_root` 必须等于首个 phase 的 `evidence_root`，并且在
`degraded_failure_window_seconds` 内包含至少 `degraded_failure_vantage_count >= 2` 个
policy-authorized、vantage ID 与 fault domain 均去重的相关 failure。candidate logical time 还必须
不早于上一自动 rotation certified head 的 logical time + cooldown。manual/periodic 的首步
evidence root 必须为空；degraded 后续 phase 携带各阶段自己的 evidence root，但仍需从
content-addressed store 取回并验证 trigger proof 指定的 failure tree。这些规则使“未提前轮换”
和“确有多来源退化”都是 candidate bytes + certified history 的纯函数判定。

Evidence object 的签名覆盖
`frame("loom-port-rotation-evidence-signature-v1", JCS(PortRotationEvidenceBodyV1))`；完整 hash 为
`evidence_hash = H(frame("loom-port-rotation-evidence-v1", JCS(PortRotationEvidenceV1)))`。ready、
connection 只能由 owner Device identity key 报告；external/transport 只能由当前 certified
evidence policy 的 exact vantage identity key 报告；reader ack 只能由该 Device identity key 报告；
failure 可由 owner 或 exact vantage 报告，但 degraded 自动触发只计算 vantage；override
只能由 candidate parent head ACL 允许 emergency scope 的 admin key 报告。所有 detail 布尔值、
枚举、计数、时间和重复 common 字段必须精确校验，不能把无法解码的 opaque diagnostic 当成功。
每份 evidence 的 `reporter_key_id` 必须逐字节等于上述规则解决出的当前
Device/admin identity key，signature 内的 algorithm/key ID 也必须逐字段等于同一 exact
`AuthorityProofKeyV1`，并按 §6.2 的长度、low-S 与 canonical base64url 规则验证；不能只验证“来自某个已知 key”。external 的
`vantage_id/fault_domain`、transport 的 `source_id/fault_domain` 必须分别等于
报告 key 在 evidence policy 中唯一 `RotationVantageRefV1` 的
`vantage_id/fault_domain`。vantage 报告的 failure 使用同样绑定；owner 报告的 failure
必须令 `source_id=owner_device_id`，`fault_domain` 等于 parent Device registry 中该
owner 的 certified fault domain。只有 vantage 报告的
`dns_unreachable|handshake_failed|loss_threshold|timeout` 可进入 degraded 多来源计数；
本地 bind/credential/firewall/mapping、port conflict 以及 administrative/abuse 证据不计入
该自动门槛。
`port_reuse_readback` 的 common body 仍绑定新 rotation/endpoint/target generation，detail 则绑定被
消费的旧 tombstone。`check_kind=socket` 只能由 old listener owner 的 active Device identity 签；
`firewall|mapping|provider_lease` 由其 exact resource intent/provider binding 指定的执行主体签，首版
该主体必须是 parent ACL 与 provisioning scope 同时允许的 active admin certificate。reporter key、
resource/provider hash 与 check kind 必须逐字段解析，不能由 allocator 自报。readback 只证明提交前
资源已释放，不授权先行 bind、开防火墙或创建映射；所有新副作用仍要等 reuse allocation head/QC
certified 后执行。
对每个 evidence，body 的 cluster/rotation/endpoint/target generation 必须等于 phase，
`observed_at <= candidate.committed_logical_time + max_clock_skew_seconds` 且
`candidate.committed_logical_time - observed_at <= max_evidence_age_seconds`。所有 window 必须满足
`window_start < window_end <= observed_at`；整数计数在 0..2^63-1，basis points 用整数算术，
越界/未来/过期对象拒绝。

detail 的首版约束固定如下：`listener_ready` 的 `listener_spec_hash` 与
`config_hash` 必须分别逐字节等于 phase spec hash 和该 spec 重算出的
`rendered_config_hash`，listener/credential 两个 boolean 必须为 true。firewall/mapping status
的 tag 必须与 spec requirement 一致：`ready` 必须回显同一 exact
`resource_intent_hash`，`not_applicable` 只能对应不带 ref 的 `not_applicable`
requirement；`external_reachability` 必须是 success、address
family 属于 spec 且 vantage ID/key/fault domain/family 逐字节匹配 policy ref。
`transport_window.samples[]` 按 sample ID 排序去重，数量在 policy min..max；success 样本
的 RTT 是 0..600000 整数毫秒，failure 样本不得带 RTT。每个 window 独立重算
`success_bp=floor(10000*successes/attempts)`、`loss_bp=10000-success_bp` 和 success RTT
升序后 nearest-rank `P95 = values[ceil(0.95*n)-1]`；无 success 直接失败，不把多个已
汇总 P95 再汇总。`reader_ack` 的 Device/view/digest/listener 必须等于 phase parent
中该 Device 已认证 view，且 `listener_generation=target_generation`。ready 的 spec、
external/transport 的 common body target 也只验证 `target_generation`。
`connection_window.detail.listener_generation` 只能等于 frozen `replaced_generation`，且只在
本 phase 要求该旧代的 `advertised→draining` 或 `draining→retired` predicate 时接受。
failure 用于 target 的 `*→abandoned` 时，其 detail generation 必须等于 target；用于
`replaced_generation` 的 disposition reason 时必须等于 replaced，并且该 generation
必须实际出现在本 phase transition 的相应 edge。其他 listener generation 或未被本 phase
predicate/reason 引用的 evidence 都作为 phase-unrelated 拒绝，不只是忽略。

`evidence_root` 对按 `(evidence_type,evidence_id)` UTF-8 bytes 排序且去重的
`PortRotationEvidenceLeafV1` 使用 §7.1 RFC 6962 规则；leaf 的 `evidence_hash` 必须从同时交付的 exact
evidence object 重算，并要求 leaf `evidence_type/evidence_id` 逐字节等于 object body
同名字段。空集合 root 固定为 §7.1 的 `SHA-256("")`。所有 voter 都针对 candidate 的
`committed_logical_time`、所携带 `PortRotationEvidencePolicyV1` 与 parent certified state 验证同一
组 predicate：

| phase transition | 必需的确定性 evidence/predicate |
|---|---|
| 首次 `absent→allocated` | 必须使用 `initial_provision`，evidence 为空，校验 provisioning scope、端口池与 spec，免除不存在的旧 listener lifetime |
| 已发布 endpoint 的 `absent→allocated` | manual/periodic 的首步 evidence 必须为空；degraded 首步必须等于 trigger proof 的 failure root；端口池、scope 与已有 listener minimum lifetime 由 certified state/policy 校验 |
| `allocated→preparing` | initial/manual/periodic lineage 的 phase evidence 为空；degraded 可为空，但仍必须按 trigger proof 的 content-addressed root 重验首步 failure tree；from-state/spec/scope 必须匹配 |
| `preparing→advertised` | 一份全部 ready/status 为 `true/ready/not_applicable` 的 owner receipt；每个 address family 至少达到 policy 数量、且 fault domain 去重的成功 external reachability；全部未超过 max age |
| `advertised→preferred` | 至少 `transport_vantage_count` 个不同 vantage 且 fault-domain 去重的 window **各自**通过 attempts/success/loss/P95 门槛；已发布 endpoint 还要求 eligible reader 的有效 ack basis points 达标，首次发布因此前没有 EndpointSet 可 ack 而只免 reader 条件，不免 transport/reachability |
| 旧 `preferred→advertised` 与新 `advertised→preferred` | 必须在同一 phase；证据按新 listener 的 prefer 条件计算，reducer 验证交换前后各恰有一个 preferred |
| `advertised→draining` | 已达到 `minimum_overlap` 与 reader ack 门槛；旧代在最近 `drain_no_new_handshakes_seconds` 窗口的新握手为 0 |
| `draining→retired` | 已达到 offline compatibility 与 `retire_not_before` 下限；连续 connection windows 覆盖 quiet/zero-active 两个 policy 时长，期间 new handshakes 与 active sessions 均为 0；所有仍可消费 invite 均满足下述 seed survivability |
| `allocated|preparing|advertised→abandoned` | 至少一份有效 failure；若会使已发布 endpoint 失去唯一 preferred，则拒绝 |
| emergency edge | 一份 scope 匹配的 admin override；UI/operation reason 必须显式列出被跳过的普通 predicate，仍不得绕过 commit/QC 或制造多个 preferred |

eligible reader denominator 精确是 phase parent `device_views_root` 中 state=active、且其已认证
DeviceView EndpointSet 包含该 endpoint ID 的不同 Device ID 数；ack 分子是其中通过上述
view/digest/time/signature 校验的不同 Device ID 数，比率为
`floor(10000*acked/eligible)`。非首次发布且分母为 0 时普通路径失败，只能经
emergency override；address families、owner 与时间窗口也都从 candidate parent 的
certified state 推导，sender 不得在 evidence 中自报更小分母。相同 evidence ID 不同 bytes、同一 reporter
重复计数、过期窗口、相互重叠样本被重复计数或 phase 不相关 evidence 都拒绝。这样
`evidence_root` 是可跨 Go/Kotlin/Windows 重算的输入，而不是让各 voter 自行解释的健康摘要。
需要连续时间的 connection windows 按 `(window_start,window_end,evidence_id)` 排序，必须无
重叠、无缺口，末段 `end >= candidate_time-max_clock_skew_seconds`，且首段
`start <= last_end-required_duration`；所以连续序列自身的实际覆盖长度至少是
`required_duration`，不会因 clock skew 大于 duration 而缩短。drain 的 required duration 取
`drain_no_new_handshakes_seconds`；retire 对 new-handshake 取 `quiet_period_seconds`、对
active-session 取 `drain_zero_active_sessions_seconds`，并在各自整个覆盖区间强制相应计数为 0。

seed survivability 的 denominator 不是 reader ack：它精确枚举 candidate parent 中 status=`available`
且 candidate logical time/可信墙钟均未超过 `expires_at`，以及 status=`claim_reserved|consumed` 且两种时间均未超过
`retry_not_after` 的 invite lifecycle，并从每个
record 的 `delivery_context_hash` 解析 exact context。若任一 context 引用待 retire 的
`(endpoint_id,listener_generation)`，candidate post-state 中必须存在同一 context 的另一个 seed：
其 listener 仍为 `advertised|preferred|draining`、不在本 operation 退役，PublicEndpoint/address
依赖仍有效，且 hostname/WebPKI/SPKI pin 与 certificate projection 的授权至少覆盖到 invite
对应 `expires_at` 或 `retry_not_after` 再加 `max_clock_skew_seconds`。找不到替代 seed（包括
seed_count=1）就拒绝 retire，直到 available invite 被显式 revoke/过期，或 reserved/consumed invite 的
retry window 结束。该判断完全基于 certified invite/context/lifecycle objects；Device ack、
renderer 当前排名或“通常没人再扫码”不能缩小集合。

`listener_transitions` 的 generation 必须严格升序且拒绝重复；每个 from state 必须等于 parent
certified state。phase operation 本身不携带可由实现猜测的提交时间：其生效时间唯一取承载该
operation 的 `HeadEntryPayloadV2.committed_logical_time`，所有 minimum lifetime/overlap/quiet-period
判断都用该签名时间与下表指定的历史 certified phase/head 计算：

| threshold | 唯一时间起点 |
|---|---|
| replacement `minimum_lifetime_seconds` | 当前旧 listener 最近一次进入 `preferred` 的 phase head；Genesis preferred 用 Genesis head |
| `minimum_overlap_seconds` | 新 listener 的 `preparing→advertised` phase head；首次建立不用该值伪造旧代 overlap |
| `max_offline_compatibility_seconds` | 原 preferred 在原子 prefer phase 中首次变为 `advertised` 的 phase head |
| scheduler degraded `cooldown_seconds` | 上一个 automatic rotation 的 `phase_seq=1` head |
| `reuse_quarantine_seconds` | 该 listener 进入 `retired|abandoned` 的 phase head，即 disposition 公式中的 candidate time |
| quiet/zero-active windows | 本 phase candidate time 为右边界，并按上述连续覆盖公式验证原始 windows |

起点 phase hash 必须沿 `parent_phase_operation_hash` 与 certified head predecessor 链唯一解决；
目标 state 曾反复进入同一 enum 时取上表指定事件的最近一次。提案方不携可覆盖
anchor 的时间字段，voter 也不得在 advertise/prefer/drain 中自选更晚的起点。

合法正常边为 `absent→allocated→preparing→advertised→preferred`、切换时旧 listener 的
`preferred→advertised`、随后 `advertised→draining→retired`；prepare/advertise 失败可在旧 preferred
仍存在时走 `allocated|preparing|advertised→abandoned`。一次 prefer operation 必须在同一个有序
`listener_transitions` 数组中把新代 `advertised→preferred` 和旧代 `preferred→advertised` 原子
提交，任何**已经发布** endpoint 的中间状态都不得产生零个或多个 preferred。首次创建 logical
endpoint 时没有旧 preferred：其 `allocated/preparing/advertised` 状态只存在控制 view，不得进入
任何客户端 EndpointSet；首个 prefer operation 原子执行 `advertised→preferred` 并在同一 candidate
中首次插入完整 LogicalEndpoint。于是客户端从未看见“已发布但零 preferred”的一代，也不需要
伪造一个旧 listener。`allocated/preparing/abandoned/retired` 只在
控制/历史 view；EndpointSet 中每个 listener 的 `rotation_operation_hash` 必须等于最后改变它的
certified phase hash，并从该 operation 重算 published state。未知边、跳步、parent 缺口或 immutable
spec 改写全部拒绝。

`allocated / preparing / advertised / preferred / draining / retired / abandoned` 是 certified 轮换 operation 经 reducer
产生的规范枚举；不是由 executor 随手写的多组布尔字段。`preparing` 只在控制/运维 view，
对已经发布的 endpoint，`advertised/preferred/draining` 连同 operation hash 进入客户端
EndpointSet，`retired` 留在历史 tombstone。每个已发布、可用 logical endpoint 必须恰有一个
`preferred` listener，其余只能是
`advertised` 或 `draining`；校验器拒绝零个/多个 preferred。overlap 时新旧两代同时发布，
但仍只有一代是 preferred。因封锁/滥用而退出的端口进入 `blocked` 且默认永久禁用；
正常轮换退出的端口进入有期限 `quarantined`。后者只有在隔离期、旧 client floor/兼容窗口、
socket/NAT/provider 冲突检查均满足，并经显式新提案后才可复用，不能由分配器静默回收。

public port 与 local listen port 必须分开建模，才能表达 NAT、云端口映射和四层负载均衡。
端口池按 protocol/transport/network namespace 约束；分配器检查当前 listener、过渡 listener、
退役历史、系统保留端口、其他 SSOT 资源和外部映射冲突。随机选择由提案方用 CSPRNG 生成并
固化进 operation；校验/渲染仍为纯函数。

轮换不是每次 render 随机换端口。scheduler 只根据 certified policy 和 certified logical tick 生成
候选 operation：周期轮换在 `schedule_window` 内加 CSPRNG jitter，避免所有节点同时变化；
`degraded` 触发需要满足有界、多来源失败证据，凭单次 ICMP 或某个客户端报告不能自动关端口。
自动化 principal 只能在 policy 授予的 port pool/cadence scope 内签 proposal，实际生效仍需
提交后 ControlSet QC。超范围、提前轮换和紧急关闭必须走人工高权限操作。

所有经 certified `PublicEndpointIntentV1(exposure=public)` 授权的公网 listener（包括客户端
data ingress 和 server↔server 公网直拨入口）在境内、境外 server 上都使用同一套模型。v1
`public_data_ingress` 只能在迁移 renderer 中生成待审 intent，既不能自行开放端口，也不能代替
EndpointSet 授权客户端候选。地域不会改变轮换协议，只影响 DNS provider、映射方式、探测视角和 rollout
policy。首版自动无中断轮换范围
限定为能真正并行监听的 Hysteria2/Trojan endpoint。服务器间稳定拓扑的 WireGuard 继续使用
独立 tunnel generation；只有 renderer 支持双 interface、双 peer、独立 key/address/route mark
并通过专门验收后，才可把它纳入相同的“无中断”产品承诺，不能只修改单接口 `ListenPort`。

---

## 14. 无中断端口轮换

本节首版规范的“计划内无中断”产品承诺只覆盖能够同时运行 generation-scoped listener 的
Hysteria2/Trojan。EndpointSet 可以描述 WireGuard endpoint，但在 §13 的双 interface/peer、
独立 key/address/fwmark/route 和跨平台泄漏测试全部实现前，scheduler 不得对 WireGuard 自动
运行本状态机，UI/API 必须标记为 `disruptive_maintenance`，不得显示“无中断”。

### 14.1 正常状态机

| 阶段 | certified 状态与动作 | 前进门槛 |
|---|---|---|
| 1. allocate | 为同一 logical endpoint 分配新 generation/port；旧端口仍 preferred | 唯一性校验、Raft commit 和 replication QC |
| 2. prepare | 目标节点新增 listener、证书/凭据、防火墙和 NAT 映射；不下发给客户端 | 本机自检 + 外部至少两个视角连通证据 |
| 3. advertise | 已发布 endpoint 的 EndpointSet 同时包含新旧 listener，旧 preferred；首次创建时新 listener 仍只在控制 view | 支持轮换的 server/client 已能读取该 view；首次创建则完成 listener/证书/外部连通验证 |
| 4. prefer | 新连接优先新 listener，失败可回退旧 listener；旧会话不搬迁；首次创建在本步原子插入首个 preferred | 新端口成功率/延迟达策略门槛，关键节点已 ack；首次创建无旧代可回退，发布前必须满足独立可用性门槛 |
| 5. drain | 新 view 将旧代标为 draining，已升级客户端不再首选；旧 listener 仍接受旧 view 客户端并维持既有会话 | 最小 overlap、reader 覆盖达标，且旧代在 `drain_no_new_handshakes_seconds` 连续窗口无新握手 |
| 6. retire | certified tombstone 后关闭旧 listener、撤防火墙/映射并记入 retired history | offline compatibility 与 `retire_not_before` 已到，quiet/zero-active 连续窗口达标；QC + §15 fencing（否则 supervised），关闭后外部复核 |

每一行的 desired transition 都必须先成为 certified entry，executor 才能执行该行列出的外部
动作；健康检查、客户端 ack 或 CRDT receipt 只是下一状态的证据，不能自行推进状态。尤其
`committed_not_certified` 的 allocate/prepare 不得开 listener、防火墙、NAT 或发布地址。

每一步都是新的更高 control revision；失败停在当前安全阶段并可重试。不能把
“新端口已监听”直接等同于“客户端已经切换”，也不能因为多数 Device 已 ack 就谎称所有长期
离线 Device 都能继续连接。系统必须声明 `max_offline_compatibility`；超过该期限才上线的旧
客户端需要先通过仍可用的 `device_config` endpoint 更新；`distribution` 只能搬运公开 QC、
transition 或通用静态制品，`control_api` 不能充当 Device 配置通道。若已无受信
`device_config` 路径，则必须明确重新 bootstrap。

正常轮换不得强制迁移已建立 QUIC/TCP 会话。drain 期间仍可能有长期离线客户端按旧 view
向旧端口发起新连接，所以 quiet period 必须分别观察“最后新握手”和“活动会话”；不能只看
当前连接数或已升级客户端 ack。实现必须使用 generation-scoped 并行 listener、
可排空 socket activation 或经实测能保留旧会话的等价机制；若运行时 reload 会杀死旧会话，
它不能被标为无中断实现。只有旧 listener 的活动会话归零或达到管理员明确批准的最长排空
期限后才关闭。

### 14.2 客户端行为

- Android/Windows/Linux 把 logical endpoint ID 映射到多代 listener，不把端口变化显示成
  新出口或新路径。
- Windows/Android 原生客户端为每个底层网络代维护 probe registry；Direct 不冻结候选也不
  花预算。该网络代第一次进入 Auto/指定出口时原子冻结当时的候选集快照，仅对其中去重
  后按地址与源接口去重的授权入口各做至多一次有界入口测量并并行；配置/EndpointSet 刷新、模式或出口切换、
  隧道重连都不得清空本代 probe registry 或再次测量。
- 同一网络代后来收到的新 advertised/preferred listener，Windows/Android 不主动 probe/预热；
  只有真实业务需要新建连接时才按 certified preference 拨号、失败回退并被动记录结果。它在
  下一底层网络代才进入新的首次候选集快照；始终不新增整条业务路径探测或周期轮询。
- Linux access Agent 继续遵守既有 `tuning/window` 候选测量契约；端口轮换只把授权 listener
  纳入原有预算和调度，不得另起 rotation probe loop、重复预热或新增整条业务路径扫描。
- prefer 阶段的新连接先尝试新代，失败立即使用仍 advertised 的旧代并上报原因；现有连接
  保持旧代直至自然结束。
- 客户端耐久保存 EndpointSet digest/generation，但不能在服务端已 certified retire 后凭
  本地缓存无限使用旧端口。
- 更新 EndpointSet 失败时继续旧 active tunnel；若旧端口已被紧急关闭且新端口不可达，
  代理模式 fail closed，不能静默 Direct。
- Android 建立 control/data socket 时继续 `VpnService.protect()` 防回环；域名解析 bootstrap
  与最终出口 DNS 语义保持分离。

### 14.3 server 行为

- 新旧 listener 复用同一逻辑授权与路由策略，但使用可区分的 generation tag 和运行指标。
- credential rotation 与 port rotation 是正交代次；可以在一个显式联合 rollout 中协调，
  不能因端口变化意外让旧凭据永久有效。
- 防火墙、云安全组和 NAT 映射先开后关，且只有对应 listener 实际 ready 才上报成功。
- 每代分别报告 handshake、会话数、最后新连接、丢包/错误和配置 revision；聚合视图不得掩盖
  新端口完全无人使用。

### 14.4 紧急轮换

端口被封锁时，管理员可提交 `emergency` 操作跳过最小 overlap/ack 门槛，但 UI 必须列出会
被中断的 Device/会话和理由，并要求更高权限。凭据泄露必须启动独立的 credential revoke /
rotate 状态机；换端口只能作为并行降低暴露的措施，绝不能被显示成泄露已修复。两条路径仍
需 Raft commit 和提交后 control QC；如果同时失去 quorum，只能维持旧数据面或走 recovery epoch，不能让某
节点单独发布新端口/凭据。

---

## 15. 外部副作用与租约

DNS、ACME、静态发布、云防火墙和 NAT provider API 不是事务数据库，通常也不提供 Loom
可用的 fencing CAS。因此系统不宣称 exactly-once；采用“certified intent + 单活租约执行 +
幂等 reconcile + 读回验证”的 at-least-once 模型。任何调用都必须等其完整 intent 和所引用的
§6.2 secret artifact 所在 head certified；`committed_not_certified`、本地草稿、lease 或已存在
provider credential 都不能提前执行。动作按**迟到重放的最坏结果**而不是 API 名称分类：

| 类别 | 例子 | 必须保护 |
|---|---|---|
| immutable/additive | 上传 hash 对象、增加 generation listener、增加本 order 的 TXT/value | generation/hash namespace、稳定幂等 key；不得覆盖其他 owner/代次 |
| monotonic pointer/upsert | `current`、preferred generation、不含删除的 DNS/metadata upsert | 优先 provider CAS；无 CAS 时只限旧写无法取得密码学 authority、能读回并自动收敛的目标，且标记 degraded |
| destructive/irreversible | 删除 RR/TXT、撤 NAT/防火墙、关闭 listener、删除 secret/key、释放唯一资源 | 新鲜 certified tombstone、精确 owner/generation、单调 fencing 和条件删除；无 CAS/fencing 禁止无人值守执行 |

```text
ResourceLeaseV2
  schema = 2, cluster_id, resource_id
  holder_control_id
  recovery_epoch + control_epoch + raft_term
  acquired_index + desired_hash + fencing_token
  expires_at
```

租约和 fencing token 由 Raft commit + replication QC 签发；租约只协调执行者，不授予或扩展
desired state。executor 每次调用前后都复核最新
certified intent、epoch/term/index/desired hash，将
`{cluster_id,resource_id,action,generation,desired_hash}` 作为 idempotency/fencing context；
失去租约立即停止新动作，已经在网络中的迟到请求仍必须由 provider CAS/generation fencing
限制。
provider 支持条件写或原子 batch 时必须使用。静态发布先写不可变对象，最后才条件更新带
revision 的 pointer；迟到 pointer 只能造成可检测的可用性回退，客户端 floor/QC 必须拒绝其
成为旧 authority。受管节点上的 listener/firewall 由本地 Agent 对 certified generation 做
CAS/fencing。`replace` 若会隐式移除任何集合元素，按 destructive 而不是 upsert 处理。外部
provider 若不支持条件删除，就保留多余资源并告警；不得自动发送可能撤掉新 generation 的
delete/close。管理员只有在重新读回精确对象、查看影响预览并二次确认后，才能执行有审计记录
的 supervised cleanup。过期 executor 的迟到 upsert 由当前租约
executor 读回、标记 degraded 并重新收敛；UI 必须展示这一限制。

外部调用和读回产生的签名 receipt/CRDT observation 只证明“发生了什么”，不能反向改变
desired state；要据此 advertise、prefer、retire 或清理仍须新 certified entry。executor 使用
secret 时只能重放 intent 引用的 exact version，不能把 provider 自动生成的另一把 key、默认
alias 或本地临时文件写回成既成事实。

executor 资格可以只是 ControlSet 的子集，因为并非每个 voter 都应持 DNS/云 API token。
这不会形成第二个 authority：executor 不能产生新 desired state。若只有一个 executor，
只是该副作用暂时没有 HA，控制状态本身仍是分布式的；需要副作用 HA 时至少配置两个不同
故障域的 eligible executor，并使用独立、最小权限 credential。

---

## 16. UI 与 API

任一 control Device 都可托管相同逻辑控制中心；管理客户端只展示已信 certified
`EndpointSet(role=control_api)` 内的独立候选，不把 round-robin DNS 回答当成员表或新入口。
人类在验证精确 transport identity 后通过 admin cert 登录，节点本地
control peer cert 或普通运维口令不能自动获得写权限。

所有写页面显示：

- 本地连接的 controller 和当前 leader/协调者（仅诊断）；
- `control_epoch`、`N`、`q`、已响应 voter 和 fault domain；
- `recovery_epoch/statement_hash/policy_hash`，计划 policy 轮换的旧 threshold 与 current QC 状态；
- base head、proposal hash、`pending → committed_not_certified → certified → published/reconciled → device applied`；
- 无 quorum 时的只读状态，不显示虚假的“已保存”；
- 成员变化前后的 quorum/故障容忍差异；
- PublicEndpointIntentV1 exposure/generation/address-or-domain ref，以及 DNS/证书/EndpointSet/端口
  各代、secret availability/PoP 和阻塞证据。

读页面可以展示本副本持有的最终一致观测，但必须标出 source、observed_at、certified head
和覆盖范围。Events 不再“只记在一台中控”：安全操作在 committed log 中；普通状态变化是
内容寻址事件 CRDT，按 event hash 去重，在任意 control 副本读取。落后副本必须显示 stale，
不能用本地缺失断言“没有问题”。

管理 API 使用稳定资源 ID 和幂等 request ID。外部自动化只能向已信 certified
`EndpointSet(role=control_api)` 内的入口提交，验证精确 transport identity 后，权限
由 admin cert scope 决定；control membership、recovery、CA policy 和 emergency retire
需要独立高权限 scope，不能与日常 Service 编辑共用。

---

## 17. 故障语义

| 故障 | 必须行为 |
|---|---|
| 一个 control Device 离线但仍有 quorum | 自动换协调者，继续提交；管理客户端可切已信 `EndpointSet(role=control_api)` 内另一入口，Device pull 独立切 `role=device_config` 入口 |
| 可达 control 少于 quorum | 只读/收草稿与观测；禁止安全关键写；数据面继续 LKG |
| entry 已 commit 但 QC 未形成 | 标记 `committed_not_certified`；不出 QR、不发布、不执行外部副作用 |
| 两个镜像代次不同 | 选择最高合法连续 QC；修复落后镜像 |
| 同坐标不同 hash | 全部 fail closed，记录高优先级 fork 事件 |
| controller DNS 被劫持 | TLS/ControlSet 验证失败；尝试其他 signed endpoint |
| DNS provider 不可用 | 已发布 endpoint 继续工作；新绑定/续签 pending 并告警 |
| ACME 续签失败 | 保留当前证书，按退避重试；在到期阈值前升级告警 |
| secret artifact/PoP/availability 不完整 | 不 commit/ready；只重试同一 version 或显式作废后升 generation |
| 新端口不可达 | 不进入 preferred；旧端口保持服务 |
| prefer 后新端口退化 | 旧代尚 advertised 时允许客户端被动回退并冻结 drain；需恢复旧 preferred 时只能执行 §13 exact 两步 emergency 回切→abandon，lineage 结束后才能开始新轮换；旧代已 draining 时首版不猜测回滚 |
| Device 长期离线错过 retire | 先更新 EndpointSet；超过兼容窗口时明确要求 rebootstrap |
| WireGuard 未实现双 interface profile | 仅允许显式 disruptive maintenance，不进入自动无中断 scheduler |
| 丢失 control quorum | 修复旧成员或用 recovery root 产生显式新 epoch |
| recovery transition 已签但新 genesis 无 q(new) QC | 不激活 lineage、不出邀请/副作用；客户端继续 LKG |
| 旧 recovery threshold 丢失 | 即使 control quorum 正常也只能新集群/带外重新锚定，不自授新根 |

---

## 18. 备份、恢复与垃圾回收

备份至少包含：最新 certified checkpoint/QC、其后的 committed log（显式区分未 certified
entry）、从 checkpoint 起的操作/QC 链、ControlSet
transition proof、Device identity registry、CA database/CRL、release 与 EndpointSet 历史、
DNS/ACME intents、SecretArtifact exact refs/digests/availability receipts、所需 sealed ciphertext
备份和 KMS/HSM exact-version 清单。每个 control Device 保存可验证
副本；另有离线加密备份。恢复不能把 revision/epoch 重置为较小值。

CRDT tombstone、已消费 invite、已撤权证书、retired port 和旧 ControlSet 不能因副本晚归
而复活。垃圾回收只有在 checkpoint/tombstone certified，确认所有保留副本已越过水位且满足审计/
离线兼容期限后执行。不可变 snapshot 和合法 rollback 所需内容按 release retention policy
保留，不以“当前没引用”直接删除；实际 delete 还必须满足 §15 的 generation fencing，无条件
删除 API 不得无人值守运行。

---

## 19. 从当前实现迁移

迁移按兼容顺序进行，任何一步都不能把目标态写成已经部署：

### M0 · 固化协议和测试

- 固定 JCS/domain framing、Raft durable log/ReplicationAttestation QC、joint transition、Device view
  Merkle proof、RecoveryPolicy/Transition、含 policy hash 的 floor 与跨 Go/Kotlin/Windows 黄金
  测试向量；
- 建立 bootstrap ceremony，提交初始 ControlSet、admin ACL、CA profile/online intermediate、
  recovery anchor 和精确 v1 anchor root；当前平台公钥只签一次 BootstrapTransition，另由
  部署专属 migration-anchor digest 独立钉住；
- 离线保管 recovery root，不能把当前在线 key 永久升级成灾难恢复权威；
- 保持现有 v1 current、Enrollment 和报告可运行。

### M1 · 单成员 ControlSet

- 把迁移输入中的指定控制节点表示为首条 recovery lineage 的
  `ControlSet(epoch=0, N=1, q=1)`；
- 运行完整单成员 Raft durable log；从同一 committed 语义状态分别物化严格 v1 payload + 单签，
  以及独立 versioned v2 head/envelope + QC，绝不让两代共享 wire bytes；明确 N=1 不具备抗单节点失陷能力；
- 发布 `current.v2.json` 或经兼容性证明的独立 v2 envelope，避免旧 reader 误解析。

### M2 · 先升级 reader

- Android、Windows、Linux 验证 BootstrapTransition、Device view inclusion proof、recovery
  statement/policy/ControlSet/QC 链并保存完整 floor；
- 支持带 transport pin 的多 seed endpoint、joint transition、EndpointSet 和旧/新 listener overlap；
- 首次接受 v2 后原子写入 `v2_latched`；latch 后即使 v1 服务仍存在也永不接受 v1 authority。

### M3 · 增加 learner，再扩到多 voter

- 新 control Device 先同步和验证全量状态；
- 用 joint transition 从 1 直接扩到目标集合，常见为 3；
- 证明任一成员离线时仍可写、少数分区不能写。

### M4 · 分布式 Enrollment、事件和发布

- token 消费、registry、admin ACL 和 release head 进入强一致提交；
- 报告/观测和不可变对象进入 CRDT anti-entropy；
- 随机数据凭据在 commit 前形成满足 availability/PoP 的不可变 sealed artifact 或 exact
  KMS/Keystore version；已信 certified `EndpointSet(role=control_api)` 内的任一入口可接收
  管理请求，executor 接管只能重放同一 artifact。

### M5 · 托管域名、ACME 与 EndpointSet

- 先接 sandbox/测试 zone，完成 provider capability 与秘密隔离；
- 先引入带 generation/address-or-domain union 的 PublicEndpointIntentV1，再为
  `control_api/enroll/device_config/device_report/distribution/data_ingress` 建立明确 role；
- 为 api/enroll/config/report/dist/data 六种 role 分配独立合成域名与证书策略，验证续签和 DNS 故障；
- 把旧单 `public_endpoint/inbound_port` 映射为 generation 0 singleton；先发布 transport pin
  overlap，再做任何 TLS key 切换。

### M6 · 双端口轮换

- Linux server 先支持 Hysteria2/Trojan 并行 listener 和会话排空；WireGuard 不在这一承诺内，
  除非另行完成双 interface/peer 状态机；
- Android/Windows/Linux reader 支持 advertise/prefer/drain/retire；
- 真机/跨网络验证后才允许自动 retire。

### M7 · 收口

- 设置最低客户端版本，停止生成 v1 单签 current 和旧邀请；
- 撤销旧在线 signing key，保留离线 recovery 能力；
- 验证所有已迁移客户端均已 latch v2；丢失本地状态必须走可信 v2 checkpoint/rebootstrap，
  不保留自动 v1 fallback；
- 删除单机 SSOT 文件锁/本地 authority 作为协议真值的路径，但可保留本地 cache。

---

## 20. 验收矩阵

### 20.1 共识与成员

- N=1/2/3/4/5 的门槛计算与离线容忍；门槛绝不按在线数变化。
- pre-QC leader 崩溃、不同候选在不同 term 留下未提交后缀后，按 Raft 覆盖规则仍能提交；
  committed entry 永不被覆盖，冲突 QC/fork 全链失败关闭。
- 1→3、3→5、5→3、3→1 的 `JointControlSet → FinalControlSet` 各步骤故障注入；旧、新 quorum 任一
  不足都不激活，两个并发成员变更只有一个能进入 committed joint state。
- learner 未追平、key proof 失败、版本不兼容、fault domain policy 失败均不能入组。
- 丢失 quorum 不能普通删成员；recovery proof 产生新 epoch并压过仍活动旧 quorum 的后续
  revision；相同 recovery epoch 不同 statement/policy hash，或同 previous statement 分叉到
  不同新 epoch/transition，均永久拒绝。
- RecoveryTransition 只有旧 threshold 签名、只有一个新 control 安装 genesis、`q(new)` 未
  durable commit，或新集合 replication QC 缺失时，客户端/QR/publisher 都继续 LKG；完整
  transition + q(new) genesis QC 才激活。
- 计划 recovery policy 轮换必须同时验证旧 threshold 与当前 ControlSet QC、使用 `epoch+1`，
  且与并行 joint/recovery transition 互斥；丢失旧 threshold 时 control quorum 不能自授新根。

### 20.2 CRDT 与 SSOT

- 任意顺序、重复、断连重放操作对象得到相同对象集和 committed materialization。
- 冲突草稿同时可见，不使用 LWW；未获 QC 的对象可以做无副作用 candidate render，但不改变
  effective/published render、权限或外部副作用。
- 撤权/tombstone/消费 token 在旧副本恢复后不复活。
- 相同 committed input 在所有 control Device 产生逐字节一致 SSOT、view 和摘要。

### 20.3 Enrollment 与客户端

- 同 token 只能从同一 `InviteBootstrapDescriptorV2.delivery_context` 内有界
  `EndpointSet(role=enroll)` 的不同 seed 并发 claim，只有一个 SPKI 成功；
  精确重试在 attested `retry_not_after` 内得到同一 receipt，一小时后或改任一
  token/request body（含 CSR、wrapping descriptor、request ID、facts）字段都被拒绝；对同一 body
  重新产生的合法 ECDSA proof bytes 则保持同一幂等事务。
- claim config QC 只产生 `claim_reserved`/reserved transaction，不得发布 active Membership、view 或
  secret；CA issuance + approval QC + completion head/config QC 全部完成后才原子激活。approval 失败、
  CA profile 撤销、旧 quorum 不足和超时都必须经 certified abort 留 tombstone，再以全新 invite/request
  reissue；不得留下 active zombie Device 或复用旧 certificate/artifact。
- Android API 31+ P-256 ECDH 与 API 26–30 RSA-OAEP fallback 都使用不可导出 Keystore key，并共享
  descriptor PoP、SealingPolicy/Envelope 与拒绝路径 golden vectors；软件导出 ECDH、profile/hash
  错配、OAEP 参数漂移、nonce/tag/recipient/SPKI 被改均失败。
- proof bundle 中的 exact DeviceEnrollmentIntent 只要与 record hash、platform、
  Membership/Responsibilities/grants/direction 四个 projection hash 任一不匹配就拒绝；
  claim 不能把 Android/Windows 提升为 forward/egress，也不能追加 grant。
- EnrollmentDirection 的跨平台黄金向量必须覆盖 Linux forward 的
  `bidirectional/reverse_only/direct_only` 与非-forward `not_applicable`，并拒绝 Android/Windows
  server direction、未知 enum、tag/variant 不一致。
- 未消费 invite 的 create→reissue 原子状态转换必须证明旧 token 在新 head 立即失效、新 token
  只在 QC 后交付；并发 reissue/revoke/claim 只能有一个 CAS 成功，consumed/revoked 不得复活。
- invite 在 `pending/committed_not_certified` 时不能取得 token/可消费载体；只有 certified invite
  才能在创建响应中一次性交付；claim reservation certified 后才可签证，只有 completion certified
  才能消费完成并返回 joined/ready。
- Raft log、CRDT、materialized SSOT、列表 API、operation status 与普通日志都不得出现 invite
  明文 token；certified record 只保存 commitment 和 private token-artifact binding hash，exact ref
  仅存在匹配的 control-private binding，且 commit 前已有 plaintext-validation receipts。交付
  descriptor 的 token/commitment/context 与 proof bundle 的 record/head/QC 任一不匹配均拒绝，且不能重取。
- 单 seed 故障、DNS 故障、重定向到集合外、旧 ControlSet、QC 不足均按契约处理；
  hostname/WebPKI 或 descriptor-carried SPKI pin 不匹配时，在发送 token bytes 前失败。
- DNS 指向持有效 WebPKI 证书但 SPKI/transport identity 未被钉住的服务时也在发送 token/数据
  凭据前失败；新旧 pin overlap 后才能换 TLS key。
- 篡改 Device view payload/leaf/index/sibling path/root/QC、EndpointSet bundle、config artifact 或
  secret-ref root 任一字段均被拒绝；Enrollment 初始 view 必须证明属于 receipt 绑定的 completion
  quorum head，而不是较早 claim head。
- 客户端拒绝 recovery/control epoch 回退、同代异 hash、未知 signer、重复 signer和错误用途 key。
- 邀请 descriptor/proof bundle、head、EndpointSet 或 durable floor 缺少/篡改 `recovery_policy_hash` 时失败；跨多次 policy
  轮换只能沿 threshold-signed transition chain 前进。
- 两份冲突 BootstrapTransition、v2 latch 后重放 v1 current/invite/recovery、清空非关键 cache
  后诱导 v1 fallback 均失败关闭。
- invite、证书和 lease 在允许/超出最大时钟偏差两侧均有测试；时间源不可信时不签新时效对象。
- secret generator 在生成前、seal 后、commit 后崩溃，接替 executor 只能交付同一 artifact。
- mutable KMS alias/`latest`、错误 ciphertext digest/recipient key version、缺 availability receipt
  或 PoP 都不能 commit；executor 重试生成另一 secret/version 必须被检测并拒绝。
- 同 hostname/pin 上把 `enroll` URL 改路径当 `device_config/device_report`，或把
  `data_ingress` 当 `control_api` 均因 EndpointSet role 不符被拒绝。
- 同一业务 FQDN 在两个最终出口返回不同 A/AAAA 时，Android/Windows TUN 与 Linux `socks5h`
  都必须实际连接各自最终出口解析到的地址；Auto/指定出口不得使用接入侧解析结果，Direct
  仍本地解析。EndpointSet transport hostname 则只走受保护 underlay resolver/cache，不进入
  FakeIP/业务远端解析，启动不会形成 VPN 回环。
- 所有已授权 `EndpointSet(role=device_config)` 入口离线时 Device 保持 LKG；
  少数派响应不能让客户端接受新配置。

### 20.4 DNS 与证书

- provider API 超时、限流、重复请求、部分成功和 executor 换届后最终收敛同一 RRset。
- 没有 certified `PublicEndpointIntentV1(exposure=public)` 时，即使 Device 有公网 IP、control/server
  role、域名和 provider credential，也不能创建 DNS、证书、listener、防火墙或 NAT。
- PublicEndpointIntentV1 generation 回退、未知 role、缺失/歧义
  `address_or_domain_intent_hash`，以及
  executor 临时发现并追加的地址均被拒绝。
- 共享 zone 的越权 record 修改被拒绝；provider token、长期私钥和数据面秘密明文不进入日志、
  SSOT、邀请载体或镜像；一次性 invite token 作为唯一例外，只允许出现在创建端一次性交付上下文、
  用户保存的 QR/加入文件/`loom://` URI 和恢复窗口内的 exact claim/retry body。
- A/AAAA prepare/overlap/drain/retire、权威/公共解析传播检查、实际 TTL + cache grace 门槛和
  DNSSEC/CAA policy（启用时）可验证；迟到旧 provider 请求不能提前删除新 generation。
- AddressChallenge 必须 one-time consume；AddressClaim 必须通过声明地址上的签名 challenge、
  policy-bounded 多视角连通与无缺口稳定窗口，重放 nonce/过期 claim/伪造 vantage 均失败。
- 两个并行 ACME DNS-01 order 的 TXT value 能并存，cleanup 只删本 order；续签失败保留旧证书；
  完整链在 Android/Windows/Linux 验证。
- TLS key 轮换必须通过 PublicEndpointIntent 的排序 old+new projection hashes、每 listener/pin
  的单 projection 绑定和 EndpointSet exact pin union；仍有 listener/invite/offline view 引用 old
  时收缩授权必须失败。
- api/enroll/config/report/dist/data 的 hostname、CertificateIntent 与认证策略不能串用；若
  certificate profile 使用自定义 policy OID/EKU 约束也必须匹配 role。公开 TLS 证书不能签配置。
- 自动命名只使用稳定 ID/模板并拒绝碰撞；显示名变化不改 hostname，购买/扩权不被静默批准。

### 20.5 端口轮换

- 所有经 certified PublicEndpointIntentV1 授权的公网 Hysteria2/Trojan listener（包括客户端入口和 server↔server 直拨），
  无论地域均能走完整六阶段；
  WireGuard 若进入范围，必须另测双 interface/peer/key/address/route 的 overlap 与回滚。
- 未实现上述 WireGuard 专用 profile 时，scheduler 拒绝自动轮换，UI/API 只能显示
  `disruptive_maintenance`；单 interface 修改 `ListenPort` 绝不能通过无中断验收。
- 新 listener 未外部验证时不 advertise；新端口失败时旧端口不关闭。
- overlap 中新连接优先新代、失败回退旧代；旧 QUIC/TCP 会话持续到自然结束。
- 客户端/reader 覆盖、离线兼容窗口、最后旧端口新握手 quiet period 和活动会话排空任一
  不足时不自动 retire。
- 仍 available 的单-seed invite 引用旧 listener 时不得 retire；多 seed 也必须逐 invite 证明另一
  seed 的 listener/地址/证书授权覆盖到 expiry，不能用 reader ack 代替。
- drain 期间长期离线客户端仍在旧 listener 发起新 handshake 会重置 quiet period；retire certified
  前再次核对最后握手、活动会话和 reader/offline 窗口。
- 防火墙/NAT 先开后关，外部读回；blocked port 不复用，quarantined port 未经显式提案不复用。
- 首次 generation 1 只接受 `initial_provision`；已有 lifecycle/tombstone 后重放它、
  将 phase 替换为未被 PublicEndpointIntent 绑定的更宽松 rotation/evidence policy、
  或用错 owner/provisioning/automatic/emergency scope 均被拒绝。
- owner ready 回执的 render hash、firewall/mapping exact resource intent 不匹配时不得
  advertise；vantage key 伪造另一 `source_id/fault_domain` 不得参与多来源门槛。
- 重放历史 phase 时，lifetime/overlap/offline/cooldown/quiet/quarantine 均从规范指定的
  certified phase/head 时间重算；原子 prefer 同时更新新旧两个 lifecycle，tombstone
  disposition 与 `reuse_not_before` 在所有 voter 得到同一 effective-state root。
- 活动 rotation 的任一 frozen dependency 被普通 upsert 改动时 CAS 失败；prefer 前原子 cancel、
  prefer 后等待终态、安全撤权走 emergency withdraw 的三条路径分别做并发/崩溃注入。
- Android/Windows 的 Direct 不探测；每底层网络代首次进入 Auto/指定出口时，才对当时冻结
  候选快照中按地址与源接口去重的入口各测一次；同代 EndpointSet
  新增 listener、模式/出口切换和重连不 re-probe，仅从真实拨号取得被动样本。
- Linux access Agent 只在既有 `tuning/window` 预算内纳入轮换 listener；测试证明没有第二套
  rotation probe loop、重复预热或新增整路径扫描。

### 20.6 运维与 UI

- 管理工作站经已信 certified `EndpointSet(role=control_api)` 内任一 UI 入口
  连接后看到相同 certified head；落后副本明确显示 stale。
- 写操作展示 pending/committed_not_certified/certified/reconciled，不把本地保存或无 QC 的
  Raft commit 冒充发布成功。
- 3 个 voter 下关闭当前 leader，管理 API 自动经新协调者提交；数据面全程不断。
- 少数分区只能收草稿/观测，所有安全关键写入口一致拒绝。
- 迟到 executor 对旧 generation 的 pointer/delete/close 注入：有 CAS/fencing 时拒绝；没有时
  禁止无人值守破坏性动作，旧 pointer 也不能绕过客户端 floor。
- 对 `committed_not_certified` 的 DNS/ACME/listener/secret/QR 注入执行请求全部拒绝；receipt
  只能更新观测，不能自行推进 advertise/prefer/retire。
- 域名、证书、端口和 controller 页面均显示 generation、证据、阻塞原因和下一步。

---

## 21. 实现约束摘要

1. wire protocol 不出现 `primary_controller` 或固定控制节点数。
2. Raft 内部 membership/提交规则由最新 committed `JointControlSet` 或 `FinalControlSet` 决定：
   Joint 阶段立即要求 old/new 双多数，Final 阶段使用新稳定集合。公开 materialization 只发布
   opaque ControlSet、matching private-directory hash 与 joint-QC-certified Final authority；完整
   `ControlPeerDirectoryV1` 仅进入经 control-peer 身份认证的 private operator projection。普通 SSOT
   编辑不能自授 voter，quorum、成员数和在线状态均由 ledger/运行态推导。
3. 权威对象使用固定 JCS canonical encoding、长度前缀 domain separation、内容 hash 和独立
   签名用途；所有平台通过同一黄金向量。
4. 所有安全关键写先 validate、Raft commit、apply/recompute 并取得 replication QC；只有
   certified intent 才能发布/reconcile，失败不静默降级。
5. 客户端永远验证 ControlSet/QC/floor；endpoint 选择不能改变 authority。
6. provider adapter、Raft 实现库和静态镜像可替换，逻辑协议不绑定 Gandi、Dynadot 或某一台
   Linux 主机；替换 Raft 协议语义必须升 protocol profile 并重新证明安全。
7. 当前单控制实现作为迁移源保留明确标签，直至 M7 完成；文档和 UI 不得提前显示为
   “分布式已启用”。
