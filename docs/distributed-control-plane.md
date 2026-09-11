# Loom · 分布式控制平面、域名与入口生命周期

> **状态：目标设计。** 迁移输入按一个指定控制节点、单 Ed25519 平台签名、
> `generation` floor 和多静态镜像建模；实际实现是否仍处于该基线只看
> [status/current.md](status/current.md)。本文定义迁移后的协议，不得用它解释当前行为。
>
> **与主设计的关系：** [design.md](design.md) 定义全系统不变量；本文细化其控制平面、
> SSOT 复制、身份、Enrollment、DNS/ACME 和公网入口轮换。发生冲突时，以本文和
> [D100–D131](decisions.md#d100--control-是节点能力控制集合不固定为三台)的新决定为准；D131 对公网入口、
> Enrollment、Device-wide direction 和 bootstrap transport 的结论在与 D100–D130 冲突时优先。

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

CRDT 负责复制事实、草稿和不可变对象；quorum 负责决定什么已经生效。control Device
只能通过 Loom overlay 上的私有地址承载管理、Enrollment、报告、配置读取和 peer RPC；
这些服务不得写入公网 DNS、公开 EndpointSet 或 Nginx route。公网 forward server 只承载静态
distribution/fake website 和被签名目录授权的数据/临时 bootstrap listener；它可以不是
ControlSet 成员，也不能因此转发应用层 claim。当 `q > 1` 时，单个控制节点不能独立改变成员、权限、配置、邀请、
证书批准、域名绑定或入口端口；`N=1,q=1` 是明确的迁移/最小部署模式，不具备这项抗单节点
失陷性质。

管理客户端只能在已验证的私有 ControlServiceDirectory 中选择 overlay IP，校验 internal CA、
IP SAN/固定 SPKI 和 admin mTLS 后提交。尚无 Device 身份的客户端先从二维码列出的 2–3 个
公网 distribution mirror 下载并验证不可变 bootstrap catalog，再实测 catalog 中的 HY2
bootstrap ingress；正式版在 UDP 全阻断时使用独立 Trojan/TLS TCP fallback。外层临时隧道
只允许到私有 Enrollment `/32` 或 `/128` 和精确 TCP 端口，token 与 CSR 只在内层 TLS 中发送。
公开 Nginx 永远不接收、终止或代理 Enrollment。

---

## 2. 目标与非目标

### 2.1 目标

1. 控制节点数量可以从 1 在线扩展到任意数量，也可以安全缩容。
2. 任一已入网且合格的 Device 都可晋升为 control；ControlSet 为 1..N，管理与 peer RPC 只在
   Loom overlay 内可达，control Device 不需要任何公网入口。
3. 网络分区时至多有一个控制状态继续提交，少数派不得自封为新集群。
4. 控制面失去 quorum 不影响已安装的数据面；节点继续使用最后一个已认证 view。
5. 配置来源、传输镜像、DNS 和 TLS 终止点均可替换，但不能扩大签名 authority。
6. 每个 active forward server 都有稳定 FQDN 与 public access profile；自动申请和续签证书，
   并显式支持直连 443、替代 TCP 端口和 NAT 映射三种部署。
7. Hysteria2、Trojan/TLS 等可并行 listener 的公网入口使用同一代次模型无中断轮换；
   WireGuard 只有采用双接口/双 peer 专用状态机后才能宣称同等级别的无中断轮换。
8. Android、Windows 和 Linux 使用同一信任、anti-rollback、端点集合与轮换语义。
9. 从当前单签、单控制节点部署可以分阶段迁移，不重建既有 Device 私钥。

### 2.2 非目标

- 不让控制平面进入用户数据路径，也不把控制服务暴露到公网。
- 不声称普通多数共识能够容忍 Byzantine 控制节点；首版只承诺 crash/partition safety。
- 不用 DNS、HTTPS 证书、在线节点数或 Web 测量结果决定控制成员资格或客户端实际入口。
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
| 11 | **公开面与控制面隔离。** Nginx 只给 fake website 和不可变 distribution；Enrollment/control/config/report 只走 Loom 私网。 |
| 12 | **首次入网双层认证。** 外层 capability 只开受限隧道，内层 TLS 才承载 token、CSR 与 Keystore PoP。 |

---

## 4. Device 能力与控制角色

control 候选必须先按 §11 完成 Enrollment、持有有效 Device identity，并已能通过永久 Loom
overlay 到达现有 ControlSet；不能在公网 bootstrap 阶段直接成为 voter。目标 SSOT 对
`access/server` 仍使用“角色块存在即拥有能力”；`control` 块只展示
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

### 6.1 初始 admin/CA 与轮换

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
§11.3 的 `bootstrap_issuer_registry_root` 对每个 authorization ID 的最新代
`BootstrapIssuerAuthorizationLeafV1` 按 ID 排序使用同一 tree；active/revoked 代均必须进 root，
不得通过删除 leaf 隐藏撤销。
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
由 leader 按“最合适”选择。`allowed_platforms[]` 按 §11.2 platform enum、
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
上文 `device_certificate_profile_intent_hash`；调用者在 base ACL 中还必须具有
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
用户持有的 descriptor/QR/加入文件/URI，以及自动重试窗口内的 exact claim body；claim 已 commit
后可为 §11.3 的管理员授权 resume 保留到事务 `retry_not_after`，但过期 capability 本身不因此
续期。token 明文绝不进入 Raft/CRDT/SSOT、URL/header/cookie 或复制日志。邀请
certified 前不得输出任一可消费载体。ACME nonce/order URL 等临时 provider 值可以在 order intent
certified 后由 executor 取得，但必须立即封装为 purpose=`acme_order_state` 的 exact artifact，并在
任何 DNS/安装/cleanup 副作用前在 §15 的外部副作用账本中提交 private provider-state object；
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
`ArtifactAvailabilityReceiptLeafV1{schema,reporter_id,receipt_hash}` 使用 §7.1 RFC 6962 规则；每个
hash 从同时交付的 receipt 重算。ref 的 policy/proof/root 必须分别等于上述重算结果；缺失、额外、
重复、过期或 fault-domain 不足都在包含 ref 的 proposal commit 前失败关闭。

所有写作 `credential_artifact_hash(es)` 或 `key_artifact_hash` 的 v2 exact 字段都必须解析到本节
定义的完整 immutable ref 并重算该 hash；invite 的 `token_artifact_binding_hash` 则先解析
control-private InviteTokenArtifactBindingV2，再从中解析同一类完整 token ref。字段名不会创造
第二种 secret-ref 摘要算法；binding 的目标 wire 见 §11.2。

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
`ControlOperationV1`，三个非 admin variant 仅为 §11.4 明确定义的 admission-QC-authorized
`EnrollmentClaimOperationV2`、CA-authorized `EnrollmentProvisionalIssuanceOperationV1` 与
approval-QC-authorized `EnrollmentCompletionOperationV2`。每个 leaf
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

### 7.5 时间语义

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
旧 executor，不能替代 provider CAS 或本地 generation fencing，具体限制见 §15。

---

## 8. 写入、读取与分区行为

### 8.1 写路径

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
payload 的 `operation_root/device_views_root/admin_acl_root/ca_profile_root/bootstrap_issuer_registry_root/`
`render_contract_version/`
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
  initial_bootstrap_issuer_registry_root
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
`JCS(RecoveryGenesisPayloadV1)))`，其中 `frame` 是 §7.1 的长度前缀 domain framing；它只覆盖
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
payload 的 `operation_root/device_views_root/admin_acl_root/ca_profile_root/bootstrap_issuer_registry_root/`
`render_contract_version/`
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
  secret_artifact_refs[]?              # active view root 的 exact private refs；按 §6.2 排序
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
授权对象及 hash 必须从 effective state 重算，Membership 必须已完成 §11.4 completion；endpoint
bundle 的每个 DataIngressEndpointSet exact bytes/hash 必须满足 grants 和职责且数组无缺漏，不能只返回
一个裸 endpoint hash；binding hash 必须等于 §13 对该 set 的规范摘要。distribution/bootstrap set
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

以下对象都使用 §7.1 的 canonical encoding、domain separator 和内容哈希。数组按文中键排序，
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

### 11.3 Bootstrap tunnel capability

bootstrap capability 是“允许建立受限临时 tunnel”的凭据，不是 Device identity，也不是
Enrollment token。二者必须独立；任何把 token 直接用作 HY2/Trojan 密码的实现都不合规。

~~~text
BootstrapTunnelCapabilityBodyV1
  schema = 1, cluster_id, invite_id
  committed_invite_record_hash
  invite_issuance_policy_hash
  bootstrap_issuer_authorization_hash
  bootstrap_issuer_registry_root
  enrollment_service_ref_hash
  mode                                # initial_claim | resume_committed_claim
  resume_binding?                     # 仅 resume_committed_claim 必需
  issued_at, not_before, expires_at
  allowed_ingress_set_hash
  allowed_service_id
  allowed_destination_ip
  allowed_destination_prefix_length  # 仅允许 IPv4 /32 或 IPv6 /128
  allowed_destination_port
  allowed_inside_transport = tcp
  maximum_connection_attempts
  maximum_concurrent_sessions = 1
  maximum_session_seconds
  maximum_total_bytes
  issuer_epoch, issuer_key_id

BootstrapCapabilityResumeBindingV1
  request_id
  claim_operation_hash
  admission_qc_hash
  claim_core_hash, csr_hash
  identity_key_hash, wrapping_key_hash
  enrollment_transaction_state_hash

BootstrapTunnelCapabilityV1
  body
  capability_id                       # 由 body 派生；body 内不回填 ID
  signature                          # BootstrapIssuer purpose key

BootstrapIssuerAuthorizationActiveV1
  issuer_epoch, issuer_key_id
  issuer_public_key
  invite_issuance_policy_hash
  valid_from, valid_until
  maximum_capability_ttl_seconds
  maximum_connection_attempts
  maximum_concurrent_sessions
  maximum_session_seconds
  maximum_total_bytes
  permitted_ingress_set_hashes[]
  permitted_service_ids[]
  permitted_modes[]                   # initial_claim | resume_committed_claim

BootstrapIssuerAuthorizationRevocationV1
  revoked_authorization_hash
  effective_at, reason

BootstrapIssuerAuthorizationV1
  schema = 1, cluster_id, authorization_id, generation
  status                              # active | revoked
  previous_authorization_hash?        # generation>1 必需；同 ID 上一代
  active?: BootstrapIssuerAuthorizationActiveV1
  revocation?: BootstrapIssuerAuthorizationRevocationV1
  parent_head_hash

BootstrapIssuerAuthorizationLeafV1
  schema = 1, authorization_id, generation
  authorization_hash

BootstrapIssuerAuthorizationProofV1
  schema = 1, cluster_id
  authorization: BootstrapIssuerAuthorizationV1
  authorization_hash
  leaf: BootstrapIssuerAuthorizationLeafV1
  leaf_index, registry_tree_size, registry_audit_path[]
  registry_root

EnrollmentResumeDescriptorV1          # 带外一次性交付；不进 public mirror
  schema = 1, cluster_id, invite_id, request_id, expires_at
  resume_tunnel_capability: BootstrapTunnelCapabilityV1
  claim_core_hash, claim_operation_hash, admission_qc_hash
  enrollment_transaction_state_hash
  bootstrap_catalog_hash
  proof_bundle_hash
  enrollment_service_ref: PrivateEnrollmentServiceRefV1
  distribution_mirrors[]: DistributionMirrorRefV1
~~~

capability signature 覆盖
`frame("loom-bootstrap-tunnel-capability-signature-v1", JCS(BootstrapTunnelCapabilityBodyV1))`；
`capability_body_hash` 与 authorization hash 分别使用独立同名 v1 domain；
`capability_id = H(frame("loom-bootstrap-tunnel-capability-id-v1",`
`JCS(BootstrapTunnelCapabilityBodyV1)))`。ID 只存在 envelope，必须重算后逐字节相等；
不得将 ID 回填 body 再求 hash。authorization leaf 使用 §7.1 RFC 6962 规则，按
`(authorization_id, generation)` 排序并拒绝重复；`bootstrap_issuer_registry_root` 必须由
proof 的 leaf/index/tree size/path 重算。`authorization_hash` 使用
`loom-bootstrap-issuer-authorization-v1`，leaf 使用
`loom-bootstrap-issuer-authorization-leaf-v1`，resume descriptor 使用
`loom-enrollment-resume-descriptor-v1` domain。descriptor 中 capability
的 `allowed_ingress_set_hash` 必须等于所下载 catalog 的 `bootstrap_ingress_set_hash`，且必须出现在
active authorization 的 `permitted_ingress_set_hashes[]`；其 `enrollment_service_ref_hash` 必须从
descriptor 的 exact `PrivateEnrollmentServiceRefV1` 重算，service ID、目的 IP/前缀/端口也必须
逐字段相等并在 authorization 的 service scope 内。
只比较 service ID 而忽略实际 route tuple 不合法。
resume descriptor 的 claim/core/admission/transaction hashes 还必须逐字段等于 capability 的
`resume_binding`；任一重复字段不等都失败关闭。

authorization 是按 ID 的不可变链：generation 从 1 连续增加，首代缺
`previous_authorization_hash`，后续代必须精确指向前代。`active` 必须只携 active body，
`revoked` 必须只携 revocation body，并且其 `revoked_authorization_hash` 必须是该链上最近的
active hash；revoked 后不得回到 active。每个 certified `HeadEntryPayloadV2` 都携
`bootstrap_issuer_registry_root`，config attestation/QC 重复绑定该 root。Invite 记录的 root/proof
证明 capability 签发时的 exact active authorization；公网 ingress 在每次建连时还必须从本机
最新 certified head 重算当前 registry root，沿 same-ID previous-hash 链确认该 active hash 未被
revocation 代取代。无法取得当前 certified root、root 回退、链断裂或已撤销都拒绝；
不能因 capability 仍在时间有效期就继续放行。

Invite 必须先 commit 并取得 QC；随后才允许由 certified BootstrapIssuer 从该记录派生 capability。
BootstrapIssuer 使用独立用途 key，其 authorization 由 ControlSet QC 约束。入口验证：

1. 从 certified Invite record 取得 exact policy hash 和 issuer-registry root，重算 authorization
   leaf/audit path，再核对 capability 中的 authorization hash/root/key/epoch；authorization 必须仍在有效期且未撤销；
2. capability 的 invite/record/policy/service-ref hash、期限和 ingress set 与已验材料一致，且
   ingress-set/service 均在 exact authorization scope 内；
3. capability 的 TTL、流量、session、次数、并发和 ACL 同时不超过 exact authorization
   与 InviteIssuancePolicy；descriptor 字节数、mirror 数/故障域和 transport 也必须满足该 policy；
   initial capability 的 expires_at
   还不得晚于 Invite expires_at，且不得带 resume binding；resume 模式必须逐字段绑定已 committed
   的 claim/transaction，并不得授权新的 claim；
4. 当前 endpoint 属于 allowed ingress set；
5. 目的地址、端口和 transport 精确等于 capability，不接受客户端任意指定；
6. capability 不在本入口的并发、次数、流量或速率封禁状态。

initial/resume capability 默认有效期均为 15 分钟；policy 中两个 TTL 字段都必须在 5–30 分钟内，
签发值还不得超过各自字段，协议硬上限均为 30 分钟。`maximum_reservation_retry_seconds` 默认
1800 秒、必须为正且硬上限 86400 秒。新目标态不存在
1 小时自动恢复窗口；旧 1 小时只属于 v1 compatibility，不能进入 v2 policy。已建立 session
默认最多 180 秒、硬上限 300 秒，总流量默认 8 MiB，同一入口最多 3 次连接尝试且同一时刻最多
1 个 session。来源 IP 只能作为滥用信号，不能作为身份；移动网络切换后仍可在期限和次数内重试。

客户端自动重试只允许在当前 Invite 与 capability 都有效时进行。若 claim 已经 committed，事务为
reserved、issued_provisional 或 completed，但客户端因响应丢失而等到 capability 过期，不能自动刷新，
也不能创建新 request。
管理员可在线性化读取 transaction 后，显式为同一 invite_id + request_id + claim/CSR/identity/
wrapping-key hashes 重签一个短期 resume capability。它只恢复到同一个幂等事务：不延长原 Invite、
不把 lifecycle 改回 available、不重置 reservation，也不再次消费 token；ControlSet 返回原有结果
或继续原事务。任一绑定不同都必须拒绝并要求创建全新 Invite。

这里“不延长 Invite”指 Invite 的 `available` 消费窗口仍在原 `expires_at` 截止；已 certified
reservation 是独立事务状态，其 policy-bound `retry_not_after` 可以晚于 Invite expiry。超过 Invite
expiry 后只能恢复该 exact committed transaction，绝不能以原 token 创建另一 claim、改变 core 或
把 Invite 从 reserved/consumed 改回 available。

重签结果只能是 `EnrollmentResumeDescriptorV1`。管理员必须经 private `control_api`、
admin mTLS 和相应 ACL 请求；ControlSet 线性化核对 transaction 为 `reserved`、`issued_provisional`
或 `completed`、
original claim core 与全部 resume binding 后，才能在一次性响应中返回 descriptor。它不含 token，
不进 public mirror/latest API，也不能被未入网客户自动刷新；管理员只可用新 QR 或
`.loom-resume` 文件带外交给原设备。客户端必须验证 descriptor/capability/hash，重用原
claim core 及 identity/wrapping keys，并对新 server nonce 重签 detached PoP。`expires_at` 不得超过
capability、issuer authorization、policy、catalog、service ref 和 transaction `retry_not_after` 中最早的截止点。

各公网 ingress 对次数/流量的记账可以是保守的本地或最终一致状态，因此它不是全局一次性安全
边界。真正的一次性授权由 private Enrollment 对 token 做 Raft CAS。入口发现异常重放时可提前
拒绝；不能因 ingress 间尚未同步就把 Invite 标记 consumed。

临时 tunnel 的网络策略必须在 ingress 转发器和 private Enrollment 前防火墙两侧执行：

- 只允许 capability 中一个 Enrollment /32 或 /128、一个 TCP 端口；
- 禁止其他 overlay CIDR、control_api、Raft、SSH、DNS、ICMP、隧道内 UDP 和 Internet egress；
- 禁止横向连接、端口扫描和 server-originated reverse connection；
- session 结束或 capability 过期后立即撤销临时路由/状态；
- 日志只记录 capability_id、endpoint_id、计数和结果，不记录 token、CSR 或内层明文。

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
issuance body/envelope/operation、issuance registry leaf、approval attestation/QC、completion operation
和 transaction state 分别使用
`loom-enrollment-claim-core-v2`、`loom-enrollment-pop-challenge-v1`、
`loom-enrollment-admission-{attestation,qc}-v1`、`loom-enrollment-claim-operation-v2`、
`loom-enrollment-provisional-issuance-{body,envelope,operation}-v1`、
`loom-enrollment-issuance-registry-leaf-v1`、`loom-enrollment-approval-{attestation,qc}-v2`、
`loom-enrollment-completion-operation-v2` 和 `loom-enrollment-transaction-state-v2` domain 计算内容哈希。
issuance registry 对每个 claim operation 的唯一 first-result leaf 按 claim-operation hash bytes 排序，
使用 §7.1 RFC 6962 tree；provisional operation 必须携与 previous root 比较后唯一可能的
resulting root，相同 claim 的另一 issuance hash 是 CAS 冲突。

`proof_signature` 精确覆盖
`frame("loom-enrollment-pop-signature-v2", JCS(EnrollmentPoPBodyV2))`，由 claim core 中的 Device
identity private key 签名。服务端在已认证 inner TLS 中为每次尝试生成新
`server_nonce`；challenge 必须未过期、service ID 等于当前 private Enrollment、core hash 相等，
且未在该 service 的有界 replay cache 中使用。`EnrollmentPoPBodyV2.challenge_hash` 必须从
exact challenge 重算。CSR subject/key、声明 public key 和 PoP key 必须逐字段一致。
token 只在已建立且验证过的内层 TLS 中发送；public ingress 只能看到外层 capability，
不能看到 intent opening、token、CSR、Device ID 或签发结果。

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

### 11.5 稳态配置与报告

Enrollment 完成后，客户端关闭 bootstrap listener、删除 descriptor/token/capability 的持久副本，
并通过正式 Loom channel 使用 Device mTLS：

- device_config 返回与 Device 授权相符的 Merkle-proofed private view；
- device_report 接收 Device 签名的健康、版本和观测；
- distribution 仍可从公开 mirror 拉取通用、无秘密、可验签制品；
- control_api 只接受 admin cert；Device identity 不能提升为 admin；
- Raft/peer RPC 只接受 control peer profile。

这些应用服务不得挂到公网 Nginx。是否由一个 control 进程复用内部 socket 不影响协议角色；
证书 EKU、ACL、端口和 handler 必须分别校验。报告失败不停止已安装数据面，配置不可达时继续
使用 LKG；任何过期 bootstrap capability 都不能充当稳态恢复通道。

---

## 12. 域名、公开服务与证书管理

### 12.1 统一的 forward server 公网基线

本章所称 forward server，是 active Device 的 responsibilities 包含 forward；internet_egress
蕴含 forward。use_loom 是可叠加职责，不影响该判定。每个 active forward server 必须有：

1. 一个稳定 FQDN，解析到其公网地址或 NAT 前端；
2. 公网 Nginx HTTPS：TCP 443 可用时使用 443，否则使用 public profile 中的替代 TCP 端口；
3. DNS-01 证书管理和节点本地 TLS private key；
4. Hysteria2 UDP listener/可轮换端口池；
5. WireGuard UDP listener，用于永久 L3/data 或 overlay link；
6. 正式版的独立 Trojan/TLS TCP bootstrap fallback。

FQDN 不携带端口。客户端拨号端口只能来自签名 EndpointSet/catalog，不能根据“有域名”推断为
443。域名必须在 listener advertise 前已解析到正确公网前端并通过外部 transport probe。

公开 Nginx 的允许面只有：

~~~text
GET/HEAD /                              → 静态 fake website
GET/HEAD /distribution/sha256/<digest>  → 精确 immutable object
~~~

可选静态索引也必须自身内容寻址并由 descriptor/hash 引用。禁止动态 latest 选择、上传、cookie、
按 token 变体、目录遍历、claim/control/config/report handler 和这些服务的 reverse proxy。
响应应设置 immutable cache policy、固定 Content-Type、长度与 digest；客户端仍以内容 hash 和
Loom signature/QC 为 authority。

### 12.2 PublicAccessProfile 与三类部署

公开期望与 provider/NAT 私有细节分离：

~~~text
ServerPublicAccessProfileV1
  schema = 1, cluster_id, server_id, generation
  fqdn
  dns_zone_ref
  address_family_policy
  https_public_port                 # 443 或显式替代端口
  deployment_kind                   # direct_standard | direct_alternate | nat_mapped
  public_frontend_addresses[]
  certificate_profile_ref
  forward_listener_resources_hash

ForwardServerListenerResourcesV1    # control-private aggregate；不是旧 ListenerResourceIntentV1
  schema = 1, cluster_id, server_id, generation
  nginx_local_tcp_port
  hy2_local_udp_port_pool[]
  wireguard_local_udp_ports[]
  trojan_local_tcp_port_pool[]
  mappings[]                        # 仅 nat_mapped

PortMappingIntentV1
  schema = 1, mapping_id
  transport                         # tcp | udp
  public_address, public_port_start, public_port_end
  local_address, local_port_start, local_port_end
  mapping_generation

ServerPublicAccessStateV1            # reducer/reconciler projection；不由 intent sender 填写
  schema = 1, cluster_id, server_id, generation
  public_access_profile_hash
  status                             # preparing | active | draining | disabled
  last_verified_observation_hash?
  last_changed_head_hash
~~~

profile、private resources、mapping 和派生 state 分别使用独立
`loom-server-public-access-profile-v1`、`loom-forward-server-listener-resources-v1`、
`loom-port-mapping-intent-v1`、`loom-server-public-access-state-v1` domain 计算 hash。公网 profile
不得嵌入本地运行时 status；只有 certified intent 加验证 observation 后才能派生 active state。

三种合法部署：

| kind | DNS | Nginx | 数据 listener |
|---|---|---|---|
| direct_standard | FQDN → 公网服务器地址 | public TCP 443 → local Nginx | HY2/WG 独立 UDP tuple；Trojan 独立 TCP tuple或 L4 SNI |
| direct_alternate | FQDN → 公网服务器地址 | public 替代 TCP 端口 → local Nginx | 各 transport 显式端口 |
| nat_mapped | FQDN → NAT 公网前端 | public TCP 端口映射到 local Nginx | public UDP/TCP 池按 transport 映射到 local listener |

示例只能使用文档地址和符号端口：

~~~text
demo-edge.example → 192.0.2.40
HTTPS: <public-https-alt>/tcp → <nginx-local>/tcp
HY2 pool: <public-udp-a..b>/udp → <local-udp-a..b>/udp
WG: <public-wg>/udp → <local-wg>/udp
~~~

direct 部署不得伪造 NAT mapping；nat_mapped 部署必须声明公网/本地 tuple 和映射代次。外部与
本地范围长度必须相等，协议必须一致，且验证器要拒绝重叠、反向范围、端口越界和同一 UDP
tuple 同时分配给 HY2/WG。Nginx TCP 与 HY2 UDP 可以使用同一个数值端口，因为 L4 协议不同；
Nginx 与 Trojan 同为 TCP，若共用 tuple 必须有显式 L4 SNI dispatcher，不得由 HTTP location
分流。

active forward profile 要求 Nginx local port、至少一个 HY2 UDP 资源和至少一个 WG UDP 资源；
正式发布 profile 还要求至少一个 Trojan/TLS TCP fallback。preparing 阶段可暂缺尚未部署的资源，
但 UI 必须列出缺口且 validator 不允许把它标 active。internet_egress responsibility 缺 forward
responsibility、FQDN 或上述资源时同样失败关闭。

不能使用 80/443 的服务器仍然必须有 FQDN，并通过 DNS-01 签证书；替代端口不是备案或供应商
政策的绕过机制。executor 在激活前必须确认该公开方式在适用法律、供应商条款和本地网络中可用，
否则保持 preparing。位于光猫/NAT 后的 server 除 DNS 指向外，还必须由 operator/provider 完成
相应 TCP 与 UDP 映射。

### 12.3 DNS 与证书 reconcile

DNS/证书 provider adapter 接收的只是 certified desired state。推荐 DNS API 使用最小权限：

- 仅能修改受管 zone 下指定 record 前缀和 ACME TXT；
- 不能转移域名、修改注册联系人或扣款续费；
- 凭据作为 secret artifact 只封装给当前 executor；
- 所有写入带 provider CAS/version，并以 operation ID 幂等；
- authoritative DNS 与至少两个外部 resolver 一致后才进入 listener verify。

FQDN 分配必须先形成 certified `server_id → fqdn → public frontend` binding，再由 executor 写 DNS。
label、冲突重试结果和 generation 都由 proposal preparation 注入；reducer/renderer 不查询 DNS、
不读时钟也不随机选名字。同一 active server 的 FQDN 跨 listener/端口轮换保持稳定；换域名必须先
让新旧 binding、证书和 EndpointSet 重叠，再按 reader floor 回收旧名。域名购买、续费支付、跨
注册商转移继续要求显式 operator 批准，不因配置了 DNS API 自动授权。

证书统一使用 DNS-01，不依赖公网 80。每个 forward server 在本地生成 private key/CSR；private
key 不进入 SSOT、CRDT、distribution 或 control backup。ACME account 可由受约束 executor 管理，
证书 artifact 只封装给目标 server。续签过程：

~~~text
cert prepare
  → DNS-01 challenge
  → issue
  → local install without advertise
  → external hostname/SNI/SPKI verification
  → EndpointSet old+new pin overlap
  → prefer new
  → drain old
  → remove old pin/key after floor
~~~

公开 WebPKI 只证明 transport identity，不能替代 catalog/head/QC。若 cert 自动续签但 SPKI 未被
当前 certified endpoint generation 接受，listener 不得 advertise。紧急证书撤销也必须先发布
可达替代入口，除非继续运行旧入口的风险高于失联风险。

### 12.4 私有 control 服务没有公网域名依赖

control_api、private Enrollment、device_config/report 按 private `ControlServiceDirectoryV1` 中的
overlay IP 拨号；ControlSet membership 与 Raft/replication peer RPC 只按 private
`ControlPeerDirectoryV1` 拨号。两者都使用 internal CA 的用途隔离证书，并且：

- 不要求公网 FQDN、公开 WebPKI 或 NAT mapping；
- 不写入 PublicAccessProfile、公开 EndpointSet 或 Nginx；
- 不允许通过公网 IP 直连后关闭证书验证；
- 可使用证书 IP SAN，或 directory 绑定的 service ID + SPKI pin；
- 只有已入网 admin/Device/control，或持有效受限 bootstrap tunnel 的未入网客户端可达。

一台物理 Device 同时具有 forward 与 control 职责时，公网和私网 listener 必须绑定不同地址或
受防火墙严格隔离；公网 compromise 不得直接获得 control socket。

---

## 13. EndpointSet、catalog 与公网端口模型

### 13.1 按用途拆分，不再使用公开 role=enroll/control

一个通用 EndpointSet 里混装 distribution、Enrollment 和 control 会让 transport trust 扩权。
独立的链路授权先使用以下逐边契约；EndpointSet 只投影客户端可拨入口，不能替 LinkIntent 创造
server-to-server 边：

~~~text
LinkIntentV1
  schema = 1, cluster_id, link_id
  from_device_id
  to                              # tagged union: device_id | service_id
  purpose                         # control_overlay | data_forward | bootstrap
  allowed_transports[]            # wireguard | hysteria2 | trojan_tls；稳定排序
  initiator                       # from | to；由可达性验证后经共识固化
  listener_resource_refs[]
  credential_refs[]
  route_scope
  generation, parent_head_hash
~~~

LinkIntent 的发起方向不授予访问权限；一个 transport 可用也不允许将该边用于另一 purpose。目标
wire 不含 Device-wide direction。既有“境外端主动向境内端建立 WG”只是一条 data_forward
LinkIntent 的 initiator/transport 选择；同一逻辑数据边可在两端可达性、认证和 profile 均满足时
改为 HY2，不代表全网切换。HY2 未实现并验收 L3-over-HY2 前不能替换 control overlay 的 WG，
默认也不把 WG 套在 HY2 内。目标 EndpointSet/Directory 明确分为：

~~~text
ListenerGenerationV2               # public；同一 logical endpoint 的一个可拨物理代次
  schema = 2, listener_generation
  published_state                   # advertised | preferred | draining
  dial_target_fqdn                  # 必须等于该 forward server 的 certified 稳定 FQDN
  public_port, address_families[]
  transport_identity_refs[]         # WebPKI/pin、HY2/Trojan credential 或 WG peer ref
  credential_generation
  certificate_intent_hash?          # TLS transports 必需，WG 禁止
  public_profile_generation, introduced_revision
  valid_from, valid_until
  retire_not_before?                # 可选的旧代最早物理退役时间；guard 仍是最终门槛
  rotation_operation_hash

ListenerGenerationTombstoneV1      # public terminal fact；不再可拨
  schema = 1, listener_generation
  terminal_state                    # retired | revoked | abandoned
  terminal_at, reason
  rotation_operation_hash
  last_listener_generation_hash

DistributionEndpointV1
  endpoint_id, logical_server_id
  transport = https
  distribution_path_prefix = "/distribution/sha256/"
  listener_generations[]: ListenerGenerationV2
  listener_tombstones[]: ListenerGenerationTombstoneV1

DistributionEndpointSetV1          # public，可进 QR
  schema = 1, cluster_id, endpoint_set_id, generation
  valid_from, valid_until
  endpoints[]: DistributionEndpointV1
  parent_head_hash, config_qc

BootstrapIngressEndpointV1
  endpoint_id, logical_server_id
  transport                         # hysteria2 | trojan_tls
  hint_rank                         # 仅无实测时排序；不扩大 capability
  listener_generations[]: ListenerGenerationV2
  listener_tombstones[]: ListenerGenerationTombstoneV1

BootstrapIngressEndpointSetV1      # public catalog；不含 token/capability
  schema = 1, cluster_id, endpoint_set_id, generation
  valid_from, valid_until
  endpoints[]: BootstrapIngressEndpointV1
  parent_head_hash, config_qc

DataIngressEndpointV2
  endpoint_id, logical_server_id
  transport                         # hysteria2 | wireguard | trojan_tls
  listener_generations[]: ListenerGenerationV2
  listener_tombstones[]: ListenerGenerationTombstoneV1
  path_capabilities[]

DataIngressEndpointSetV2           # Device view；正式数据入口
  schema = 2, cluster_id, endpoint_set_id, generation
  valid_from, valid_until
  endpoints[]: DataIngressEndpointV2
  grants_root, parent_head_hash, config_qc

ControlServiceDirectoryV1          # private；只走认证的 Loom channel
  schema = 1, cluster_id, generation
  services[]: PrivateControlServiceV1
  control_set_hash, previous_directory_hash?
  parent_head_hash, config_qc

PrivateControlServiceV1
  service_id
  role                              # control_api | enroll | device_config |
                                    # device_report
  overlay_ip, port
  certificate_profile_ref, spki_pins[]
  authorized_subject_profiles[]
~~~

ControlServiceDirectoryV1 是 admin/Device/Enrollment 使用的私有 service directory；它与只供 voter
建立 Raft/复制连接的 ControlPeerDirectoryV1 是两个对象，均不得公开。两者可引用同一 control
Device，但不能复用证书 profile、ACL 或把 peer endpoint 下发给普通 Device。

各对象唯一摘要使用以下 domain：

~~~text
link_intent_hash                 = H(frame("loom-link-intent-v1", JCS(LinkIntentV1)))
listener_generation_hash        = H(frame("loom-listener-generation-v2",
  JCS(ListenerGenerationV2)))
listener_generation_tombstone_hash = H(frame("loom-listener-generation-tombstone-v1",
  JCS(ListenerGenerationTombstoneV1)))
distribution_endpoint_set_hash   = H(frame("loom-distribution-endpoint-set-v1",
  JCS(DistributionEndpointSetV1)))
bootstrap_ingress_set_hash       = H(frame("loom-bootstrap-ingress-endpoint-set-v1",
  JCS(BootstrapIngressEndpointSetV1)))
data_ingress_endpoint_set_hash   = H(frame("loom-data-ingress-endpoint-set-v2",
  JCS(DataIngressEndpointSetV2)))
control_service_directory_hash   = H(frame("loom-control-service-directory-v1",
  JCS(ControlServiceDirectoryV1)))
~~~

公开材料不再出现 role=enroll 或 role=control_api 的 HTTPS seed。Bootstrap ingress 只提供受限
transport，真正 enroll 是 ControlServiceDirectory 中的 private service。ControlServiceDirectory
完整 preimage 不进入公开 mirror；Invite descriptor 只携完成该次 claim 所需的一个有界
PrivateEnrollmentServiceRef。

每个 set 的 `endpoint_id` 标识稳定逻辑入口，嵌套的 `listener_generation` 标识物理 listener 代次。
同一 endpoint 内 generation 严格递增且唯一；同一代只能出现一次。`preparing` 只存在于 private
rotation state，绝不发布；可拨数组只接受 advertised/preferred/draining，retired/revoked/abandoned 只接受
tombstone。每个含可拨代的 logical endpoint 必须恰有一个 preferred 代；tombstone 必须引用该代最后发布 bytes 的
hash，低于客户端已见 generation floor 的可拨代不得复活。端口变化不能生成新的 logical_server_id，
也不能让客户端把同一 server 当成新的最终出口。
三类公网 Endpoint 的每个 listener 都必须使用其 forward server 已认证的稳定 FQDN；公开 wire
拒绝 IP literal。overlay IP 只出现在私有 service/peer directory 与本次邀请的有界 Enrollment ref。

### 13.2 公网与本地资源的分离

客户端可见 Endpoint 只包含它实际拨号的公网 tuple、transport identity、generation 与状态；
local bind port、NAT 内部地址、provider mapping ID 和防火墙 handle 只存在于 private
ForwardServerListenerResourcesV1。renderer/reconciler 必须证明以下链条后才 advertise：

~~~text
certified Endpoint public tuple
  ↔ active PublicAccessProfile
  ↔ verified DNS
  ↔ installed local listener
  ↔ direct reachability 或 exact transport-matching NAT mapping
  ↔ external probe success
~~~

端点状态：

| 状态 | 新拨号 | 已有会话 | 目录可见性 |
|---|---:|---:|---|
| preparing | 否 | 不适用 | private diagnostics only |
| advertised | 可作为候选 | 保留 | 新旧并存 |
| preferred | 优先 | 保留 | 正常 |
| draining | 不再选 | 保留至 deadline | 保留给旧 session |
| retired | 否 | 强制结束后清理 | 从新 set 移除 |
| revoked | 否 | 立即终止 | 保留审计 tombstone |

PublicAccessProfile 和 endpoint generation 必须一起被 certified head 引用；单独修改 DNS、NAT 或
本机配置不能使端点生效。

### 13.3 transport 与端口约束

| transport | L4 | 公开证书 | 是否首版 bootstrap | 典型用途 |
|---|---|---|---:|---|
| Hysteria2 | UDP/QUIC | WebPKI + pin | 是，首选 | bootstrap、数据链路 |
| Trojan/TLS | TCP/TLS | WebPKI + pin | 正式版 fallback | UDP 全阻断时 bootstrap、可选数据 |
| WireGuard | UDP | WG peer key | 否 | Enrollment 后永久 L3/control/data link |
| Nginx HTTPS | TCP/TLS | WebPKI + pin | 只下载 | fake website、immutable distribution |

HY2 与 WG 都是 UDP，不能绑定同一个 address/port tuple；它们即使数值端口不同，也必须有各自
listener ownership。Trojan 与 Nginx 都是 TCP，必须使用不同 tuple 或显式 L4 SNI dispatcher。
外部 NAT mapping 必须保留 transport，TCP 映射不能满足 UDP endpoint，反之亦然。

Hysteria2/Trojan 不要求固定在 443。所有客户端授权的数据入口都由当前签名 EndpointSet 明确
给出 public port；客户端禁止扫描端口、从 DNS 猜端口或读取 provider 私有 mapping。

### 13.4 客户端选择与测量边界

未入网客户端：

1. mirror hint 只决定 catalog 下载尝试顺序；
2. 验证 catalog 后，对当前底层网络代中的授权 bootstrap endpoint 做一次有界、并行真实
   transport probe；
3. HY2 有可用候选时选择最佳 HY2；检测到 UDP 全阻断或 HY2 全失败时才尝试已发布 TCP fallback；
4. 不探测未签地址、不做 Service × 路径扫描、不因 UI profile 切换重复测量；
5. 主动 probe 只完成真实 outer transport/SNI 身份验证，不发送 bearer；选中入口后才出示
   capability 建 tunnel，内层 TLS 完成后才发送 token。

已入网 Windows/Android/Linux 继续遵守客户端统一 registry：同一底层网络代冻结授权入口快照，
按地址/源接口去重且每入口最多主动探测一次；Direct 不花探测预算；Auto/指定出口复用观测。
bootstrap registry 与稳态 data registry 生命周期分开，完成 Enrollment 后必须删除前者。

服务器 Web 观测、控制面历史 RTT 和目录 priority 只能作为没有实测时的 hint。任何 UI 或 API
不得把它们标为客户端端到端延迟、丢包或已验证可用性。

---

## 14. Listener 与端口无中断轮换

### 14.1 通用重叠状态机

HY2 和 Trojan/TLS 使用相同逻辑状态机：

~~~text
prepare
  → install new listener/credential without advertise
  → local self-check
  → verify from required external fault domains
  → advertise old + new
  → wait client-reader propagation floor
  → prefer new
  → stop accepting new sessions on old
  → drain old sessions until deadline
  → retire old listener, credential and mapping
~~~

每一步都写 operation ID、expected certified head、listener generation、deadline 和可重入完成证据。
reconciler 重启后从外部事实恢复，而不是重做随机选择。端口选择由提交操作注入；纯 renderer
不读时钟、不查询空闲端口、不产生随机数。

exact rotation wire 固定为：

~~~text
ListenerRotationFrozenDependenciesV1
  schema = 1, cluster_id
  endpoint_kind                     # distribution | bootstrap | data
  endpoint_set_id, endpoint_id, logical_server_id, transport
  source_listener_generation?, source_listener_generation_hash?
  target_listener_generation
  logical_public_endpoint_intent_hash
  public_access_profile_hash
  dns_address_binding_hash
  certificate_identity_projection_hash
  credential_artifact_refs_root
  render_contract_hash, evidence_policy_hash
  port_pool_hash, firewall_policy_hash
  forward_listener_resource_generation_hash
  port_mapping_intent_hash?         # 仅 nat_mapped
  link_intent_hashes[]              # 按 hash bytes 排序

ListenerRotationIntentV1
  schema = 1, cluster_id, rotation_id, operation_id
  base_head_hash, expected_endpoint_set_hash
  frozen_dependencies: ListenerRotationFrozenDependenciesV1
  frozen_dependencies_hash
  advertise_not_before, prefer_not_before, drain_not_before, drain_not_after
  retire_not_before                 # 必须 >= drain_not_after，且仍受 retirement guard 约束
  minimum_reader_floor

ListenerRetirementDependencyLeafV1  # control-private；按 (kind, object_hash) 排序
  schema = 1
  kind                              # endpoint_set | catalog | available_invite | initial_capability |
                                    # resume_descriptor | reserved_transaction | device_view |
                                    # certificate_pin_overlap | offline_lkg
  object_hash, reference_not_after

ListenerRetirementGuardV1
  schema = 1, cluster_id, rotation_id
  rotation_intent_hash, source_listener_generation_hash
  reference_cutoff_head_hash         # 此 head 后禁止创建新的旧代引用
  dependency_leaf_count, dependency_root
  maximum_reference_not_after
  minimum_reader_floor
  offline_grace_not_before, quiet_not_before, backup_retain_until

ListenerRotationStateV1             # reducer projection；不是 executor 自报权威
  schema = 1, cluster_id, rotation_id
  rotation_intent_hash, frozen_dependencies_hash
  phase                              # allocated | preparing | advertised | preferred |
                                     # draining | retired | abandoned | revoked
  source_listener_generation?, target_listener_generation
  retirement_guard_hash?             # draining/retired 必需
  last_transition_head_hash
  evidence_refs_root
~~~

以上四类对象分别使用 `loom-listener-rotation-frozen-dependencies-v1`、
`loom-listener-rotation-intent-v1`、`loom-listener-retirement-dependency-leaf-v1`、
`loom-listener-retirement-guard-v1` 和 `loom-listener-rotation-state-v1` domain 计算 hash。
intent 的 dependency object 必须逐字节重算到 `frozen_dependencies_hash`；从 allocated 到任一 terminal
phase，普通 reconcile/管理操作不得替换 logical/public intent、profile、地址绑定、证书身份投影、
credential、render/evidence policy、port pool、防火墙、listener resource generation、mapping 或
LinkIntent。确需变化时只能先安全 `abandoned` 再建新 rotation；安全事件可走
显式 `revoked`，但必须报告中断而非改写原 intent。

进入 draining 的 certified transition 同时建立 reference cutoff 和
`ListenerRetirementGuardV1`：ControlSet 必须枚举所有仍可能使客户端拨旧代的 immutable catalog、
available Invite、initial/resume capability、reserved transaction 的 `retry_not_after`、Device view、
certificate-pin overlap 与离线 LKG，形成 exact private dependency leaves/root，
并从 exact `reference_not_after` 求最大值。cutoff head 之后任何新对象引用 source generation 或包含
它的旧 EndpointSet hash 都拒绝 commit。只有当前 head 不低于 `minimum_reader_floor`，全部 dependency
期限、`drain_not_after`、`retire_not_before`、offline grace、quiet period 和 backup retention 均已过去，
且相应 signed observation 已
进入 operation 后，reducer 才接受 retired；executor 不得凭本地“没有连接”提前删除 frozen
listener、credential 或 mapping。retired 只禁止拨号并解锁后续清理，审计 tombstone 仍需保留。

“无中断”表示已建立在旧 listener 的 session 可活到 drain deadline，新连接逐步选择新 listener；
不承诺单个 QUIC/TCP session 跨端口迁移。紧急撤销可以跳过 drain，但 UI/API 必须明确显示会断开
旧会话。

### 14.2 NAT 预映射池

nat_mapped server 若预先建立一段一一对应的 public/local UDP 映射，HY2 可以在该池中选择下一
个未占用端口并完成上述重叠，无需每次修改光猫/网关。必须满足：

- certified private intent 记录池边界、transport 和 mapping generation；
- 激活前从外部验证具体 public tuple，不能只相信网关配置；
- HY2 active/draining 端口与 WG 固定/轮换端口不重叠；
- 池耗尽、映射消失或 public/local offset 不一致时停止轮换并报警；
- 客户端只看到当前 advertised/preferred public endpoints，不看到整段私有资源池。

direct server 没有 PortMappingIntent，但仍要做 listener 与外部 reachability 验证。替代 HTTPS
TCP 映射和 Trojan TCP 池按相同原则处理，不能从 UDP 池推导。

### 14.3 客户端行为

客户端接收同一 endpoint_id 的新旧 generation 后：

1. 保持现有会话，不为观察到新 generation 立即重连；
2. 新拨号优先 preferred generation；
3. preferred 失败可在其仍 advertised 且未过期时回退旧 generation；
4. 已见 floor 不接受更低 generation；
5. retired 后不再新拨号；revoked 立即断开；
6. 不把端口代次变化计为最终出口变化。

离线客户端继续使用最后一个仍在有效/宽限期的 LKG endpoint。若离线跨过旧端口 retire deadline，
恢复时必须先取得合法新 set；不能扫描旧端口周边。

### 14.4 WireGuard 独立状态机

WG 不自动继承 HY2 的 listener overlap 结论。若需要无中断 WG 轮换，必须实现双 interface/双 peer、
独立地址/route ownership、old/new peer overlap、握手验证与 drain。只更新同一 interface 的 listen
port 会影响现有 peer，不能宣称无中断。

WG control overlay 的 key/peer 轮换属于 private `ControlPeerDirectoryV1` 与 ControlSet 变更，不进入
public bootstrap port rotation。数据 WG endpoint 可进入 DataIngressEndpointSet，但仍使用专用
generation/state machine。

---

## 15. 外部副作用与租约

DNS、ACME、NAT/provider、listener、防火墙和 publisher 都是 certified desired state 的幂等
reconciler，不是 authority。每类资源按 resource_id + generation 获取短租约；租约绑定 Raft
term/index、certified head 和有界 deadline。

执行规则：

1. 只有持当前租约且已验证 head/QC 的 executor 能创建/修改外部资源；
2. provider 支持 CAS 时必须使用；不支持时用 deterministic ownership tag 和 generation fencing；
3. 超过时钟安全截止立即停止发新请求；
4. 接管者先 read-after-write 观察，再继续未完成步骤；
5. 外部失败写 observation/status，不反向生成另一份 SSOT；
6. 删除动作必须晚于 reader propagation floor、drain deadline 和 backup retention；
7. public Nginx 配置检查必须证明不存在动态 Enrollment/control/config/report route。

执行顺序必须尊重依赖：

~~~text
DNS/映射准备
  → 证书签发
  → local listener install
  → firewall least privilege
  → external verify
  → EndpointSet advertise
  → client floor
  → prefer/drain/retire
  → 回收旧证书、listener、mapping
~~~

ControlSet 失去 quorum 时，不创建新端点、不轮换证书、不删除旧 listener；已有数据面和未过期
LKG 继续运行。证书临近到期但无 quorum 是显式告警，不能让单 executor 绕过 QC 续写 authority。

---

## 16. UI 与 API

UI 是模型的投影，必须把以下状态分开：

- **ControlSet**：成员数、quorum、leader、certified head、replication freshness；只显示 private
  overlay 服务，不出现“公网中控地址”；
- **Server public access**：FQDN、direct/alternate/NAT、DNS/cert 状态、Nginx distribution、
  HY2/WG/Trojan listener 与 mapping generation；
- **Distribution**：镜像可达性、artifact hash、复制进度；不得显示 claim 请求或 token；
- **Enrollment**：Invite committed/QC、capability 期限、bootstrap ingress、private service、
  reserve/consumed 状态；不把 Nginx mirror 标为 Enrollment server；
- **Device**：正式身份、配置 view、报告新鲜度和 LKG；
- **Rotation**：prepare/verified/advertised/preferred/draining/retired 的每代证据。

管理 API 仅在 private control_api 上接受 admin mTLS。写操作必须携 expected head 与 request ID，
成功响应只返回已取得 QC 的结果。公开 Nginx 没有管理 API。UI 中“测试 mirror”只测试静态下载；
“测试 bootstrap”必须测试真实 HY2/Trojan transport；“测试 Enrollment”在不发送 token 的前提下
完成外层 tunnel 和内层 server TLS，不能用普通 HTTPS GET 冒充。

管理端创建预览可从 private intent 显示 expiry、目标 Device intent、mirror 数与 transport 支持；
未入网客户端在 inner-TLS preflight 前只能显示 expiry、mirror/transport 和 opaque commitment，
验过 opening 后才显示 exact intent 并要求确认。不得把 bearer token、capability 原文写进日志、
DOM telemetry、截图诊断或分析事件。诊断导出默认脱敏 public host、
端口、capability ID 和 Device identity。

---

## 17. 故障语义

| 故障 | 必须行为 |
|---|---|
| 所有 distribution mirror 不可达 | 若有已验证离线包则继续，否则在发送任何秘密前失败；不从 DNS 猜新镜像 |
| mirror 返回错误 hash/签名 | 丢弃并标记 mirror 不可信；不尝试解析其 endpoint |
| HY2 全失败但 UDP 未确定阻断 | 有界重试其他已签 HY2；不扫描端口 |
| UDP 完全阻断 | 正式版转 Trojan/TLS TCP fallback；未部署 fallback 时明确报告不支持 |
| capability 过期/超限，claim 未 commit | 入口拒绝并要求新 Invite；客户端不能自动刷新或拿 token 直接拨号 |
| capability/Invite 已过期，reservation 已 certified | `retry_not_after` 前管理员可按 exact transaction binding 重签短期 resume capability；不复活 Invite、不重置事务、不重消费 token |
| bootstrap ingress 被攻陷 | 外层只能转发精确 Enrollment tuple；内层 TLS 阻止其读取/篡改 claim |
| private Enrollment 无 quorum | 不消费 token；返回可重试状态，已 reserve 由 Raft 状态决定 |
| claim 响应丢失 | 保持 exact claim core/key，对新 server challenge 重签 detached PoP；在期限内返回同一 artifact |
| 同 token 不同 key/request | CAS 拒绝并产生安全事件 |
| control_api 公网可达 | 严重配置错误；防火墙/reconciler fail closed |
| Nginx 出现动态 claim/control route | 严重配置错误；不激活该 generation |
| DNS 正确但端口不可达 | endpoint 保持 preparing，不 advertise |
| NAT UDP 映射丢失 | 保留其他 generation；不把 TCP 健康视为 UDP 健康 |
| cert 续签完成但 pin 未提交 | 新 listener 不 advertise，旧 listener继续服务 |
| control quorum 丢失 | 停止新写和外部 destructive reconcile；数据面使用 LKG |
| Device config/report 不可达 | 已安装 tunnel 不停止；缓存报告并按有界策略重试 |
| 同 epoch/revision 出现冲突 QC | 全部 reader/publisher fail closed并报警 |

所有错误必须指明是 distribution、bootstrap transport、inner TLS、claim transaction、control quorum
还是 steady-state API；禁止统一显示“网络错误”导致操作者把 Nginx、HY2 和 Enrollment 混为一谈。

---

## 18. 备份、恢复与垃圾回收

备份必须覆盖：

- Raft log/snapshot、certified heads、QC 和 ControlSet transition；
- CRDT immutable objects 与 content-addressed distribution inventory；
- private ControlServiceDirectory、Invite record/lifecycle 和 enrollment transaction；
- encrypted secret artifacts、issuer authorization、recovery policy；
- DNS/cert/listener/mapping desired generation 与外部 observation；
- 每个 Device 的 view root/result artifact，但不包含 Device private key；
- retention tombstone 和已消费 token commitment。

不备份节点本地 private TLS/WG/Device key；恢复后由原节点证明持钥或走显式 replacement。公开
distribution mirror 可由 signed immutable inventory 重建，不是 authority。

垃圾回收只能追随 certified reachability graph。Invite token plaintext、descriptor 和 capability
应在 consumed/revoked/expired 后尽快擦除；commitment/tombstone 保留到审计期限。旧 endpoint、
证书和 mapping 只有在 reader floor、drain、离线宽限和 backup retention 全部满足后才删除。
Emergency recovery 必须产生新 recovery epoch，不得通过恢复旧数据库回退 floor。

---

## 19. 从当前实现迁移

迁移按 M0–M7 进行。每个阶段都可单独验收；目标字段不能提前塞入严格 v1 wire schema。

### M0 · 协议、不变量与 golden

- 固化本文逐边 LinkIntent、三类公网 EndpointSet/两类私有 directory、listener generation、
  PublicAccessProfile、Invite hiding/opening、capability/claim/admission/issuance wire；
- 更新 decisions/design/client lifecycle 和客户端契约；
- canonical bytes/hash/signature/QC、unknown-field、排序、过期和 anti-rollback golden；
- 加入 repo safety 与“公开 Nginx 无动态 handler”静态检查。

**完成条件：** Go/Android/Windows/Linux 对同一向量产生相同 hash、签名验证和失败结果。

### M1 · 单成员私有 ControlSet

- 把现有指定 control 迁移为 N=1、q=1 的 ControlSet；
- control_api、Raft、Enrollment、config/report 只绑定 overlay IP/internal cert；
- admin/control/Device/Enrollment EKU 与 listener 分离；
- 保留 v1 compatibility transport，但目标 API 不再新增公网依赖。

**完成条件：** 公网扫描无法访问 control 服务；overlay admin 可提交并取得 QC。

### M2 · Reader、静态 distribution 与 bootstrap tunnel

- 先升级 server 和全部客户端 reader，识别拆分后的 endpoint sets；
- 每个 active forward server 建立 FQDN/PublicAccessProfile/Nginx static distribution；
- 实现 HY2 capability validator、双层 tunnel ACL 和 private Enrollment TLS；
- Android/Windows/Linux 实现紧凑 QR/文件、catalog 验签、真实 HY2 probe、Keystore/PoP；
- 正式发布前补独立 Trojan/TLS TCP fallback。

**完成条件：** Nginx 收不到 token；UDP 可用时走 HY2，UDP 全阻断时走 TCP fallback；临时 tunnel
不能访问除 Enrollment tuple 外的任何地址。

### M3 · 多 voter 与动态成员

- learner catch-up、joint consensus、FinalControlSet、private peer directory；
- 从 N=1 在线扩到 N=3/5 或其他 1..N 集合，再安全缩容；
- control 候选必须先是 enrolled Device；
- 验证分区、leader 切换、key possession 和 directory hiding。

**完成条件：** 单副本不能越过 quorum 改安全关键状态，数据面在 control 故障时保持 LKG。

### M4 · 分布式 Enrollment、Device API 与发布

- Invite commit/QC、BootstrapIssuer authorization registry/root、token CAS、stable claim core、
  admission QC、provisional issuance、approval/completion 与 exact-bound resume；
- private device_config/report 与 per-Device proof；
- immutable publisher/镜像接管、CRDT anti-entropy、certified current lineage；
- secret artifact wrapping 与审批收敛。

**完成条件：** 任一健康 control 可接续同一 claim/request；不同 key 重放失败；镜像失陷不能伪造
Device view 或配置 authority。

### M5 · 域名、DNS-01、证书与三类公网部署

- DNS provider adapter、最小权限 credential、domain allocation policy；
- direct_standard、direct_alternate、nat_mapped reconcile；
- 节点本地 CSR/private key、ACME DNS-01、SPKI overlap；
- Nginx fake/static distribution 配置模板和外部 reachability verification。

**完成条件：** 每个 active forward server 有已验证 FQDN/profile；不能用 443 或位于 NAT 后的
server 通过签名 public port/mapping 正确发布，同时 control 服务保持私有。

### M6 · HY2/Trojan 重叠轮换与 WG 独立轮换

- listener port pool、frozen rotation intent、prepare/verify/advertise/prefer/drain/retire guard；
- NAT 预映射范围与资源冲突校验；
- 客户端同 logical endpoint generation overlap；
- WG 双 interface/peer 状态机单独实现和验收。

**完成条件：** 新连接迁移到新 listener，旧会话在 deadline 内保持；HY2/WG UDP tuple 不冲突；
重启 reconciler 不会重复分配或提前删除。

### M7 · 收口与废弃旧路径

- 删除公开 enroll/control/config/report seed、handler、Nginx route 和 UI 文案；
- v2 latch 后拒绝 v1 authority、旧 QR、旧 public role 和 v1 的 1 小时自动恢复窗口；
- 完成 server/Linux/Windows/Android 全矩阵、升级/回滚/撤权/灾难恢复；
- 发布运维手册、source/licence、签名制品与实测记录。

**完成条件：** 仓库、部署和网络扫描均无旧公开控制路径；四平台使用同一目标 wire 与失败语义。

---

## 20. 验收矩阵

### 20.1 共识与成员

1. N=1、3、5 的 quorum 计算正确，不按在线成员缩小；
2. candidate 必须已有 Device identity 和 overlay reachability；
3. learner 未 catch-up 不投票；
4. joint old/new 双多数与 Final QC 正确；
5. leader 在 commit 后、QC 前崩溃可恢复相同 certified result；
6. minority partition 不能创建 Invite、消费 token、改 ACL 或轮换 listener；
7. control peer cert 不能调用 admin API，admin cert 不能参与 Raft；
8. public FQDN/Nginx compromise 不能到达 control socket。

### 20.2 CRDT、SSOT 与 secret

1. operation/object 顺序不同收敛到相同 root；
2. 相同 key 的竞争写确定性处理；
3. CRDT 草稿和 committed_not_certified 不驱动外部副作用；
4. secret artifact 只有目标 Device 能解封；
5. bootstrap issuer 不能签正式 Device cert/config head；
6. backup restore 不回退 recovery/config/listener floor；
7. renderer 输出确定性，无时钟、随机、网络查询。
8. 新 Invite/Device view 出现节点级 direction 字段必须按 unknown field 拒绝；链路只读 certified LinkIntent。

### 20.3 QR、distribution 与 catalog

1. QR 只含 2–3 mirror refs、hash、token/capability 和有界 private service ref；
2. QR 大小上限、未知字段、重复 mirror、单故障域镜像按 policy 拒绝；
3. .loom-invite 与 QR descriptor canonical hash 相同；
4. Nginx 只接受 GET/HEAD fake/static hash path；
5. POST claim、动态 token URL、cookie 和任何 redirect 全部拒绝；
6. mirror 返回错误 digest/QC/floor/expired catalog 时客户端不发送 capability；
7. mirror hints 只影响下载顺序，不决定真实 tunnel；
8. 无 mirror 但有完整合法 offline package 可以继续；
9. 静态 catalog 不含 token、capability、private ControlServiceDirectory 或 per-Device view；
10. public proof 只能披露 hiding commitment，不含 Device intent/opening；客户端只在已验证 inner TLS
    的 private preflight 取得 opening，commitment/opening/intent 任一不匹配即不发送 token。

### 20.4 Bootstrap transport 与 capability

1. HY2 是首选；首版 reader 对 WG bootstrap 明确报不支持；
2. 客户端对当前网络代的每个授权 ingress 最多一次有界主动 probe；
3. UDP 全阻断后选择独立 Trojan/TLS fallback；
4. HTTP 200 或 Nginx RTT 不能标记 HY2/Trojan 可用；
5. capability 必须引用 committed Invite，并 exact 绑定 policy、service ref、issuer authorization、
   当前 registry root/audit path；capability ID 必须仅由 body 重算且无自引用；
6. issuer authorization 的 previous/status/revocation 链异常，或 ingress/service 不在其 scope，均拒绝；
7. 过期、未来签发、超 initial/resume TTL/流量/session/次数、错误 ingress set 全拒绝；
8. tunnel 只能访问一个 Enrollment /32或/128 + TCP port；
9. control_api、Raft、SSH、DNS、ICMP、UDP 和 Internet egress 均不可达；
10. ingress 无法读取内层 opening/token/CSR/Device identity；
11. 同 capability 并发 session 和异常重放受限，但不代替全局 token CAS；
12. 网络切换后在有效期限/次数内可跨 ingress 重试；
13. initial capability 不晚于 Invite 过期，客户端不能自动刷新过期 capability；
14. committed claim 可由管理员签发 exact-bound `EnrollmentResumeDescriptorV1`；completed 返回原
    result，reserved/issued_provisional 继续原事务，且 token consumption 计数不增加；
15. resume 中 request/CSR/identity/wrapping/transaction 任一 hash 改变都拒绝；descriptor 只能经
    private admin-authenticated control_api 一次性交付，v2 拒绝旧 1 小时窗口。

### 20.5 Enrollment transaction

1. internal TLS 验 CA、IP SAN/SPKI；错误 cert fail closed；
2. token 只在内层 TLS 发送，日志/URL/telemetry 无 token；
3. CSR key、声明 key 与 Keystore PoP key 完全一致；
4. stable claim core 绑定 invite、request、record、intent opening、CSR 和 keys；每次 detached PoP
   另绑定 fresh server nonce/challenge 与 token commitment；
5. 同 claim core 可对新 server nonce 重签且仍返回相同 certificate/view artifact；
6. 同 token 不同 request/key/body 只有一个 CAS 成功；
7. 少数签名不能形成 admission QC；claim operation 的 `retry_not_after` 不等于 certified
   policy/Invite/admission 推导值时 reducer 拒绝；
8. leader 在 reservation、provisional issuance、approval、completion 各点崩溃均可恢复且不提前释放；
9. Invite expiry 后的新 admission/reservation 被拒绝；expiry 前已 certified reservation 可在
   `retry_not_after` 前用 exact resume 继续，但原 token 不能创建新 core；
10. capability 过期不能调用稳态 API；
11. Android private key 不可导出，卸载/清除数据后的身份恢复符合 policy；
12. Enrollment 成功后临时 tunnel、token/capability 被擦除。

### 20.6 DNS、证书与公开 profile

1. 每个 active forward server 都有 FQDN；纯 control/use_loom Device 不被错误要求公网域名；
2. direct_standard 解析/443 正常；
3. direct_alternate 的明确 public HTTPS port 正常，客户端不默认 443；
4. nat_mapped 的 TCP/UDP public-local tuple 和 transport 正确；
5. DNS-01 不依赖 80；
6. provider credential 不能修改 zone 外记录或域名注册；
7. private key 节点本地生成，不进入 snapshot/distribution；
8. cert 续签先 old/new pin overlap；
9. DNS 正确但实际端口不可达时不 advertise；
10. Nginx 和 Trojan TCP tuple 冲突必须由独立端口或 L4 SNI 解决；
11. HY2/WG UDP tuple 冲突被 validator 拒绝；
12. direct server 不伪造 NAT mapping，NAT server 缺 mapping 不发布；
13. 三类 public Endpoint listener 只接受已认证的 `dial_target_fqdn`，IP literal 失败关闭。

### 20.7 轮换

1. prepare 未通过 local/external verify 不 advertise；
2. advertise 阶段新旧 generation 同时可拨；
3. prefer 后新连接使用新 listener，旧会话保持；
4. 新 view 不再选择 draining 代，但旧 view 的有界回退与既有会话可持续到 guard deadline；
5. deadline 后 retire，客户端不扫描邻近端口；
6. executor 重启/接管保持相同 operation/port；
7. NAT 预映射池在范围内轮换无需每次网关变更；
8. 池耗尽、映射消失、range offset 错误明确失败；
9. 紧急 revoke 明确中断而非伪称无中断；
10. WG 未实现双 interface/peer 前不能通过“无中断”验收；
11. 同 endpoint ID 的 old/new listener generation 可同时发布，但每代 state 唯一且可拨 endpoint 恰有一个
    preferred，retired/revoked/abandoned 只能以 tombstone 出现；
12. frozen dependency 任一 hash 在 rotation 中途改变都需 abandon/restart；retire 前仍有效的 catalog、
    Invite、capability、resume、Device view/LKG 引用，或 reader/drain/offline/backup guard 未满足均拒绝。

### 20.8 客户端与移动可靠性

1. Android、Windows、Linux 验同一 descriptor/catalog/QC vectors；
2. Android VPN permission、前台服务、protect、防回环和 Keystore 正常；
3. Wi-Fi/蜂窝切换创建新 network generation，旧代观测不污染新代；
4. Direct 不主动探测；Auto/指定出口复用同代 registry；
5. 锁屏、省电、进程回收、重启后恢复正式 LKG，不恢复 bootstrap token；
6. 固定出口只更换入口/listener generation，不偷偷更换最终出口；
7. DNS 在最终出口解析的既有数据面要求继续验收；
8. UDP 丢包、MTU、QUIC、TCP fallback 分别有真实流量验收；
9. 撤权后拒绝新 view/报告并按 policy 停止数据通道；
10. 覆盖升级保持 Device key、anti-rollback floor 和签名连续性。

### 20.9 运维、UI 与负面暴露

1. UI 分开显示 mirror、bootstrap ingress、private Enrollment/control 和 data endpoint；
2. read-only observation 不使用 Apply/切换文案；
3. public scan 只能发现 fake/static distribution 与已发布 data/bootstrap transport；
4. public HTTP path fuzz 无 claim/control/config/report handler；
5. private API 要求正确 admin/Device/control cert profile；
6. 日志和诊断包无 token、capability body、private key、真实拓扑；
7. 无 quorum 时 UI 明确只读/LKG，reconciler 不删旧资源；
8. safety checker 拒绝真实地址、域名、主机名、端口、指纹和指标进入仓库；
9. 历史文档不用于推断当前部署，目标设计不被声称已实现；
10. server、Linux、Windows、Android 的 issue 都引用同一 milestone 与验收编号。

---

## 21. 实现约束摘要

实现者必须同时遵守：

1. ControlSet 是已入网 Device 的 1..N 动态集合；control 服务只在 overlay IP + internal cert 上。
2. CRDT 复制材料，Raft commit + apply + QC 才产生唯一 effective head。
3. 每个 active forward server 有 FQDN/PublicAccessProfile、Nginx、证书管理、HY2 和 WG；
   正式 bootstrap 另有独立 Trojan/TLS TCP fallback。
4. Nginx 只给 fake website 与 immutable content-addressed distribution，绝不处理
   Enrollment/control/config/report。
5. QR 保持紧凑：token/capability、catalog/proof hash、2–3 mirror 和有界 private Enrollment ref；
   完整无秘密 catalog 静态下载。
6. bootstrap capability 只开短期、限地址/端口/流量/次数的 tunnel；token 只在内层 TLS 使用。
7. 首次身份是 server-authenticated TLS + token + Keystore PoP；正式 Device cert 完成后销毁
   bootstrap 状态。
8. HY2 是首选 bootstrap，Trojan/TLS 是 UDP 全阻断 fallback；WG 是入网后的永久 L3/control
   overlay，三者不混成一个隐式 tunnel。
9. 公网 EndpointSet 按 distribution/bootstrap/data 拆分；私有 ControlServiceDirectory 与
   ControlPeerDirectory 再按调用方分离，公网/local/NAT 资源分层。
10. HY2/Trojan 用 overlap generation 轮换；WG 必须有独立双 peer/interface 设计才可称无中断。
11. DNS、WebPKI、镜像和 executor 只提供可达性/副作用，不扩大 quorum、签名或 Device 权限。
12. 任何尚未实现的 transport、证书 profile、轮换步骤或私有 API 必须显式失败，不得静默降级。
