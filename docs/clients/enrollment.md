# 客户端规范 · 加入网络与设备身份

[客户端规范入口](README.md) · [文档地图](../README.md) · [源码能力](../development/implementation.md)

**规范状态：已批准的客户端契约。** 本文负责 加入网络与设备身份；标为 v1 的内容仅适用于迁移输入，
v2 认证、对象与事务以[控制面规范](../protocols/control-plane/README.md)的对应条款定义。
平台运行情况由验收回执确认，正文不记录部署进度。

## 加入网络与设备身份

### 加入码与交付方式

创建端先用 CSPRNG 生成 token 并封装为 exact-version secret artifact；已入网管理员经
Loom overlay 访问已信 `ControlServiceDirectoryV1` 中 `role=control_api` 的私有服务，
验证 overlay IP/内部证书并用 admin cert 认证后，提交只公开
`DeviceEnrollmentIntentCommitmentV1`、token commitment 和 private-binding hash 的 Create Device/invite
proposal；完整 `DeviceEnrollmentIntentOpeningV1`、exact-version ref 与明文一致性回执只
保存在 control-private replicated binding。提案经 Raft durable
commit、apply/recompute 并获得 replication QC 成为 certified 后，renderer 才可解封同一 token
并一次性输出邀请。平台、Responsibilities 与 Destination grants 在
`DeviceEnrollmentIntentOpeningV1` 内的 exact intent 中固定；目标态不携 Device-wide direction，完成加入后的每条
control/data 边由独立 certified `LinkIntent` 固定 initiator、transport 与 route scope。上述
intent 由 certified invite record 的 hiding commitment 承诺。客户端仍按自身
构建目标报告平台，控制平面要求它与 certified invite
精确一致；客户端不能在 claim 时选择或扩张职责。加入码不携带运行时路由模式或手选出口
参数；加入完成后再由客户端选择 Direct / Auto / 指定出口。QR/URI 中的有界
`InviteBootstrapDescriptorV2` 是尽量小且可扫的载体，其 exact 字段是：

- `schema/cluster_id/invite_id/expires_at`、`minimum_recovery_epoch` 和
  `trusted_checkpoint_hash`；
- 短 TTL、单次使用的 `token` 及 `token_commitment`；
- `bootstrap_catalog_hash` 和 `proof_bundle_hash`；
- 2～3 个跨节点/故障域的精确 HTTPS `DistributionMirrorRefV1`，投影自
  `DistributionEndpointSetV1`；
- 一个有界 `PrivateEnrollmentServiceRefV1`，只指向本次 claim 所需的 overlay
  IP/TCP port 和内部 TLS 身份，不公开完整 `ControlServiceDirectoryV1`；
- 与 invite 绑定的 `BootstrapTunnelCapabilityV1`：只授权到上述私有
  Enrollment tuple 的临时路由，不授权通用 overlay 或 Internet egress。

纯 `use_loom` 创建成功后页面呈现二维码图片和同一 descriptor 的可复制
`loom://enroll/v2#d=…` 内部协议 URI；最终 URI 不超过 1800 ASCII bytes，超限时不得生成不可扫
二维码。备用 `.loom-invite` 可以内嵌 descriptor、catalog 和 public proof bundle，
但不能内嵌只应经私有 preflight 交付的 intent opening。包含 `forward` 的 Linux Device 不提供二维码或
加入文件，只把该 URI 作为本地 shell 或管理员 SSH 登录目标机后执行同一 bootstrap 的
一次性标准输入；控制平面不保存 SSH 凭据。Windows
Portable 还可在 control 页面复制二维码图片后直接按 `Ctrl+V` 或点击“粘贴二维码”；图片只在
内存中解析，不写临时文件。这些 access-only 载体
共享 TTL 与单次消费状态；原始 token 只在创建结果中出现，列表不能再次取回。URI 的
fragment 由客户端本地解析，token 只在私有 Enrollment 的内层 TLS claim body 发送，不进入公网 HTTPS query。
它们不包含长期凭据、完整 SSOT 或设备私钥。设备绑定不得依赖浏览器指纹，必须基于客户
端本地生成且不可导出的非对称密钥。

客户端只能从 descriptor 直接携带的 mirrors 下载与两个 hash 分别一致的
immutable catalog 和 public proof bundle，请求不得携带 token/header/cookie，且拒绝重定向。
Nginx 不知道这次下载对应的 token 或 claim，也不处理 claim。客户端验证
bootstrap/recovery/ControlSet transition、record/head/QC、
`DeviceEnrollmentIntentCommitmentV1` 和 `BootstrapIngressEndpointSetV1` 后，从当前网络
对实际 HY2 入口（正式版再包括独立 Trojan/TLS TCP fallback）各测至多一次并选择可达入口。

只在选定入口时才出示 bootstrap capability。入口验签、限制并发/时间/流量，并将隧道
路由限制为 descriptor 认证的 `PrivateEnrollmentServiceRefV1` overlay IP 和 TLS port。
客户端与入口都从已验完整 `BootstrapTunnelCapabilityV1` 派生
`HashObject("loom-bootstrap-transport-credential-v1", capability)`；HY2 使用该值，Trojan 使用其
标准 SHA-224 key。不得用 enrollment token 或仅用 public `capability_id` 代替，也不得把派生值写入
日志、诊断或持久配置。入口在认证成功后、解析目标前即耐久消耗一次 attempt，随后仍须拒绝 DNS、
UDP 及任何非 exact Enrollment IP:port 的请求。
客户端再验证内层 server-auth TLS，先使用不含 token/CSR/key 的
`EnrollmentIntentPreflightRequestV1` 取得 `EnrollmentIntentPreflightResponseV1` 中的 exact
`DeviceEnrollmentIntentOpeningV1`，重算 hiding commitment 并验证平台、职责和 grants。
只有 preflight 通过后才生成稳定 `EnrollmentClaimCoreV2`、取得
`EnrollmentPoPChallengeV1`，并由 identity/CSR key 签名含 server nonce 的
`EnrollmentPoPBodyV2`；然后在 `EnrollmentClaimSubmissionV2` 中发送 token、core、challenge
和 detached signature。公网入口不得终止该内层 TLS。静态镜像的提示顺序可来自 Web 观测，但不能代替客户端对
实际 tunnel transport 的当前网络测量。加入后端点变化必须由已信 ControlSet 的新 view/QC 连续引入。

capability 是 certified Invite 的受限派生物，由 ControlSet 授权的专用 issuer 签名。
默认 TTL 15 分钟（可配 5～30 分钟、硬上限 30 分钟），单 session 最长 180 秒、总流量
默认 8 MiB、最多 3 次顺序建连，且每入口同一 `cap_id` 只允许一个并发 session。
入口与 ControlSet 防火墙双重禁止其他 overlay CIDR、Internet egress、DNS、ICMP、隧道内
UDP、control API、Raft、SSH、配置和报告。这些限额只用于防滥用；一次消费边界仍是
ControlSet 对 enrollment token 的 Raft CAS。

公网 distribution 和 Trojan/TLS bootstrap 入口的 TLS 验收必须在受支持的
Android 真机系统信任库上执行，不能只用服务器侧 OpenSSL/curl 判定。公网服务端必须
发送可构建到目标系统已有根证书的完整兼容链；客户端不得跳过主机名、证书或系统时间校验。
内层 Enrollment 不使用公网 WebPKI 主机名：客户端必须按已验 catalog 中的内部 CA/IP SAN
或固定 SPKI 验证私有 overlay IP，绝不允许 `InsecureSkipVerify`。

### 加入流程

```text
已入网管理员经 overlay 访问 ControlServiceDirectoryV1 中 role=control_api 的私有服务，验服务器证书/IP + admin cert
    ↓ validate → Raft commit → apply/recompute → attest/QC
    ↓ certified 后返回紧凑 QR：token/commitment + trust checkpoint + catalog/proof hash
      + 2～3 个静态 mirrors + PrivateEnrollmentServiceRefV1 + 短期 capability
客户端导入 access-only QR/文件，或在 Linux 本地/SSH 会话执行 shell bootstrap
    ↓
从 mirror 无 token 下载 immutable catalog/public proof，分别验 catalog/proof hash、
authority/QC、DeviceEnrollmentIntentCommitmentV1 及 BootstrapIngressEndpointSetV1
    ↓
从当前 underlay 对实际 HY2 入口各测至多一次；正式版在 UDP 阻断时选独立 Trojan/TLS TCP
    ↓
出示短期 capability，建立只可达 PrivateEnrollmentServiceRefV1 私有 IP/port 的临时隧道
    ↓
验证内层 Enrollment 服务器证书/IP，做无 token intent preflight，
取得 DeviceEnrollmentIntentOpeningV1 并重算 hiding commitment
    ↓
设备按 exact intent 在安全存储中生成 identity/CSR signing key 和只用于封装的独立 wrapping key
    ↓
构造稳定 EnrollmentClaimCoreV2，取得 EnrollmentPoPChallengeV1；identity key 对含 server nonce 的 EnrollmentPoPBodyV2 签名
    ↓
在内层 TLS 中提交 EnrollmentClaimSubmissionV2：token + stable core + challenge + detached PoP
    ↓
当前 stable ControlSet 的 enrollment voters 各自在私有 peer RPC 验 token/core/opening/challenge/PoP，
对同一无秘密 admission body 形成 StableEnrollmentAdmissionQCV1；单 ingress 不能批准
    ↓
Raft durable commit 原子预留 token/Device ID，并承诺 Membership 计划、职责/grants、sealed
secret-artifact root 与 future Device view；尚不激活或交付
    ↓
apply/recompute 规范 reservation/head 字节，quorum 对相同结果 attest 并形成 claim config QC
    ↓
CA 验 claim QC 与最新 active/fenced profile后确定性签证，并把 first-result 写入 Raft issuance registry
    ↓
enrollment voters 验证 issued certificate、issuance entry/profile proof 后形成 approval QC
    ↓
approval-QC-authorized completion 进入第二个 ordinary head，current config QC 后原子消费 invite、
激活 Membership/Device view 并授权 artifact release
    ↓
返回绑定 claim/completion leaf/root/head/config+approval QC 的 ready receipt、节点证书、CA/checkpoint、只为 wrapping key 封装的本机秘密与分发坐标
    ↓
客户端验 bootstrap/recovery/transition/QC/inclusion proof/floor，原子安装正式 cert/view/creds 并 latch v2
    ↓
删除 token、capability、临时 profile/隧道；再由同一客户端宿主建立正式 WG control/L3 overlay
    ↓
客户端上报首份可信状态后，才可由运行态观测判定 online
```

PoP 必须由 identity/CSR key 签名，绑定 stable `claim_core_hash`、network/invite/request ID、
CSR/identity/wrapping-key hash 和服务端 nonce；wrapping key 不签 PoP，只用于封装与解封本机凭据。
Android 用 Keystore，Windows Installed 用 CNG/DPAPI 保护的机器密钥，Windows Portable 用
当前用户 DPAPI，Linux 用 root-only 身份密钥。任何平台都不得把可导出客户端私钥放入 QR。
首次 Enrollment 的客户端认证是“服务器认证 TLS + token + PoP”；正式 Device certificate
必须签给同一本机密钥，不为了形式上的首包 mTLS 再引入可复制的临时客户端私钥。

Device 详情页的 Runtime evidence 只展示经过现有信任链验证的运行问题原文；未签名或
身份校验失败的客户端自述不能作为该问题详情。

加入网络不是单独的“注册客户端”流程，也不是日常连接动作。二维码导入只绑定 certified
invite 已经创建的 Device，不创建第二条记录。重连、网络切换、更新配置、更新程序和重新
启动都继续使用现有设备身份，不得再次要求二维码。v2 首次携 token 的内层请求前，客户端验证 bootstrap
transition/checkpoint；v1 Windows 兼容流程比较二维码部署公钥指纹与发行包内嵌公钥。加入码
一旦成功绑定，v2 控制平面只允许同一 token 与字节完全相同的
`EnrollmentClaimCoreV2`（包括 request/record/intent 绑定、base floors、平台、
CSR/identity、wrapping descriptor 和 client nonce）
在 invite 与 bootstrap capability 仍有效时幂等重试。新鲜 server nonce 会产生新的 detached
PoP 签名，但不得改变 stable core 或 `claim_core_hash`。
Windows Portable v1 兼容契约仍是指定 control 的一小时恢复窗口，并将这组 pending 数据用
操作用户 DPAPI 保护，在加入提交后清除 token。
v2 claim 已 commit 但 capability 过期时，管理员必须先经私有
`ControlServiceDirectoryV1` 中 `role=control_api` 的服务线性化确认 transaction 仍为
reserved/completed，再一次性生成 `EnrollmentResumeDescriptorV1`。它不含 token，携带
exact resume capability、`claim_core_hash`/transaction binding、catalog/proof/service/mirror refs，
只能由管理员带外交付为 QR 或 `.loom-resume`；不经公网 mirror 动态生成，
客户端也不能自动刷新。客户端导入后先用本机 pending core/identity 核对 exact binding，
再以 identity key 对新 server nonce 重签 PoP。ControlSet 幂等返回既有事务结果，
不重置、不再消费 token；不得通过延长原 capability 绕过该绑定。
Installed 经受限 Service broker 使用 machine-scope/受保护 ProgramData。其他 CSR 身份重复消费、未知/不受支持的平台、设备 ID
已被另一身份绑定、SSOT revision 冲突或签名验证失败都不得留下部分加入状态。
加入码在成功绑定前过期时，详情页可重新生成加入码；创建端先封存新 token/artifact，再以
同一个 proposal 撤销旧 record 并创建新 record，事务 certified 后旧码才失效并一次性交付新码。
纯 `use_loom` Device 可显示二维码，包含 `forward` 的 Linux Device 只提供 shell/SSH 辅助交付。若已加入的纯
`use_loom` Device 丢失或删除了本机身份，管理员可在详情页确认后执行 Rejoin Device：
旧接入从 SSOT 移除，旧身份归档，新 ID 和新二维码沿用原名称、平台、职责与 grants。旧数据面凭据
随服务器应用签名配置撤销。该流程不复用已消费 token、不把新密钥绑定到旧 ID，也不
把本机删除解释为已完成远程停机。仍在 provisioning 的未完成身份及服务器职责的恢复
不走这一窄入口，须先处理其原事务。详见
[二维码重发与本机身份丢失](../architecture/device-lifecycle.md#二维码重发与本机身份丢失)。

不需要替换时，详情页的 **Remove Device** 提交一个安全关键事务；只有该事务
Raft durable commit、apply/recompute 并取得 replication QC 成为 certified 后，才移除
纯 `use_loom` Device 的 SSOT membership 和专属数据面凭据，并把 enrollment identity
标为 revoked。它不要求
客户端在线或先消费 decommission，也不会声称已经清除客户端本机文件；旧连接在转发服务器
收敛到下一份 signed snapshot 后失效。包含 `forward` / `internet_egress` 的 Device 不走
该窄入口，因为删除前必须处理隧道、出口策略与依赖凭据。

### 稳态认证

首次加入使用客户端本地 P-256 key/CSR 签发 Device 证书，供可信报告和私有读取使用；
私钥不离机。加入后，private `ControlServiceDirectoryV1` 中的 `device_config` 和
`device_report` 服务只由
正式 Loom overlay 的私有 IP 可达，并用 Device mTLS 与分用途内部服务器证书认证；
不从任何公网 distribution 或 bootstrap URL 推导。目标 pull 同时验证该私有传输身份、
提交后 ControlSet QC、Device Merkle proof、内容 hash、四组 durable floor（含 recovery
policy hash）与 v2 latch，任何一层都不能替代另一层。v1 兼容协议依赖 HTTPS、
单平台签名和 generation floor；严格 schema
决定了 v2 使用并行资源迁移，不能原位添加字段后声称兼容。

### 吊销

吊销设备需要同时产生两类结果：

1. 控制面拒绝该设备继续 pull 或上传；
2. 下一份服务器配置移除该设备凭据，阻止旧配置继续使用数据平面。

只做第一项不能阻止设备凭最后一份离线配置继续连服务器。吊销提案先经
确定性 candidate view 生成/校验后进入 Raft durable commit，apply/recompute 必须复得同一 view，
再由 replication QC 证明为 certified；此后才发布并由服务器应用这份已复算、已认证 view。
`committed_not_certified` 不得触发撤权副作用。传播完成前任一
control UI 都显示“已认证、数据面撤权
尚未全部应用”，不能提前显示完成；落后副本不得凭旧 membership 向已撤权 Device 返回
受保护数据。

---
