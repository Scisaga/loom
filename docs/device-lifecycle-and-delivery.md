# Device 生命周期、Enrollment 与交付架构

> **状态：** 已确认的目标模型，分阶段迁移；不是当前生产能力说明。  
> **范围：** Device 统一、Enrollment、授权边界、版本化对象图、设备配置交付。  
> **当前事实：** 以 [当前状态](status/current.md) 为准；平台客户端细节见
> [客户端接入设计](client-access.md)，局域网转发仍是独立的
> [Local Network 专题](local-network.md)。动态 ControlSet、CRDT/QC、域名/证书和入口轮换
> 见[分布式控制平面设计](distributed-control-plane.md)。
>
> 本文的 **Enrollment** 只指内部的一次性身份 claim 协议。产品界面统一使用
> **Create Device / 加入网络**：管理员只能经 Loom overlay 向已信任的 certified
> `ControlServiceDirectoryV1` 中 `role=control_api` 的私有服务提交，先校验 overlay IP/证书，再用 admin cert
> 认证；只有经 Raft commit、
> apply/recompute 和 quorum attestation 成为 certified 后才创建可交付的
> Device；纯接入客户端可导入二维码，Linux
> 也可通过本地或 SSH 会话执行 shell bootstrap。消费加入输入不会再创建或“注册”第二个 Device。
> claim 不使用公网 Nginx 或 `control_api`；尚无 Device 身份的客户端先验证
> 静态 bootstrap catalog，再以短期 capability 经受限 bootstrap tunnel 访问私有
> `PrivateEnrollmentServiceRefV1` 所指的 Enrollment 服务；它是私有
> `ControlServiceDirectoryV1` 中 `role=enroll` 条目的本次有界投影，不是公网 EndpointSet。

### E1 历史基线（仅用于解释迁移起点）

E1 迁移基线包括统一 `/devices` 读模型、四分授权、一次性加入、公开通用包、逐 URL 发布
证据、fail-closed 首次 pull 和 access-only Device 回收。这些是 v2 要兼容的协议起点，不是
本文维护的运行状态。现网数量、版本、验收结果和部署细节只写入
[当前状态](status/current.md)；提交记录由 Git 保留，不在架构文档复制容易过期的摘要。

既有 Device 的 identity registry 迁移不重新 Enrollment，也不根据名称、hostname 或 IP
猜身份：导入命令要求 Device 已存在于当前期望态，证书链通过 Loom CA，CN 与唯一 SAN 都
精确等于 `<device_id>.node.internal`，且公钥为 ECDSA P-256。UI 中
`Verified existing certificate` 只描述身份来源，不表示软件版本或运行状态。

## 1. 收敛结论

产品模型只保留一种受管实体：**Device**。服务器、桌面和手机的差别是平台事实与
承担的职责，不再是 `Node` / `Client` 两套生命周期。

所有新 Device 使用同一条 **Enrollment** 内部协议：创建端先用 CSPRNG 生成一次性 token，
把它封装为 exact-version secret artifact；管理员经 Loom overlay 从已信任的 certified
`ControlServiceDirectoryV1` 中 `role=control_api` 的私有服务、校验入口并使用 admin cert
认证，再提交只公开 `DeviceEnrollmentIntentCommitmentV1`、token commitment
与 private artifact-binding hash 的 proposal；完整 `DeviceEnrollmentIntentOpeningV1` 与 exact ref
只在 matching control-private binding 中。该 proposal 经 Raft commit、apply/recompute 和 quorum attestation 成为
certified 后，获授权 renderer 才可解封同一 token 并一次性输出加入码。客户端安装并启动通用包后导入加入输入，
再自行生成身份，验证无秘密 bootstrap catalog，通过受限临时隧道 claim 这个
既有 Device。纯 `use_loom` Device 可用二维码、内部兼容 `loom://enroll` URI 或加入文件；
包含 `forward` 的 Linux Device 只通过本地/SSH 会话执行 shell bootstrap，并从标准输入
消费同一 URI。服务器安装命令只获取通用包，本身不携带加入码。

权限不再用“网络权限”或笼统的 Access 表达，而拆成四个问题：

1. **Identity**：这是谁，持有什么设备密钥；
2. **Membership**：它是否属于当前 Loom；
3. **Responsibilities**：它承担哪些普通数据面职责，例如在本机使用 Loom、转发或作为公网出口；
4. **Destination grants**：它获准通过 Loom 访问哪些 Service、出口或后续 Local Network。

`control` 是 Device 的正交 capability，但不是普通、可由邀请或常规 SSOT operation 写入的
Responsibility。Raft 内部成员与 quorum 立即服从配置日志中最新 durable committed 的
JointControlSet/`FinalControlSet`；Final 即使尚无 post-commit QC 也已约束内部协议。只有它
apply/recompute 并取得 old/new replication QC 后，才产生对外可发布的 certified authority；映射到
具体 Device 的只读 `control` 投影还必须使用同一 head 绑定、hash 匹配的 private
`ControlPeerDirectory`。公开 ControlSet 不暴露 Device/peer URL/fault-domain 映射。
`committed_not_certified` membership 不能授权客户端或外部副作用。

信任与配置先按最高级 **Recovery epoch/statement/policy hash** 区分不可逆 lineage，再采用三个相互约束
的轴：**Control epoch** 标识成员/控制 key 集合；epoch 内全局 **Control revision** 记录一次不可变期望对象图；独立
**Device generation** 只在该 Device 的有效配置变化时递增。加入一个 Device 不应
使所有既有 Device 的 generation 一起变化；v1→v2 另有一次性不可逆 protocol latch。

## 2. 已确认决策及迁移归属

| 决策 | v1 迁移基线 | v2 目标工作 |
|---|---|---|
| 统一 Device | 建立统一 ID、库存读模型与 `/devices` 添加入口；删除 `/nodes/add` 产品入口 | 删除剩余旧 `/clients` 命名与兼容存储 |
| 统一 Enrollment | 指定 v1 compatibility control 先创建既有 Device 与一次性 invite，单 registry/endpoint 完成 claim；Linux 可在本地或 SSH 会话运行同一 bootstrap，不另建 SSH 加入协议 | Create Device 只由 `ControlServiceDirectoryV1` 中 `role=control_api` 的 overlay-only 服务在 admin cert 认证后接收；公网 Nginx 只发静态 distribution；claim 经 capability 受限隧道到达 QR 中 `PrivateEnrollmentServiceRefV1` 指向的私有 `role=enroll` 服务；Raft commit、apply/recompute 和 quorum attestation 分别形成 certified invite/claim |
| 四分授权模型 | API、Review 和 UI 分开显示 Identity / Membership / Responsibilities / Destination grants | `control` authority 由 FinalControlSet、Device 投影由 matching private peer directory 联合导出；复杂授权治理另议，不引入 ABAC 或动态组 |
| “Access”文案 | 改为“在此设备上使用 Loom”，明确只表示本机流量可交给 Loom | 无 |
| 直接固定加入意图 | v1 创建时选择平台、职责、grants 和 Linux forward direction；不引入 Device 类型或 Profile 层 | v2 Invite 只固定平台、职责和 grants，不携 Device-wide direction；每条链路的 initiator/transport/route scope 由 Enrollment 后的 certified LinkIntent 固定，职责变更另走显式配置变更 |
| 公开通用包 | GitHub 或实际部署配置中的国内/公网镜像只放通用包、签名和校验材料 | 具体镜像供应商、域名和同步运维按部署决定 |
| 公网分发、bootstrap 与 Device mTLS | v1 只区分公开包地址和设备配置地址，不把传输信任冒充配置 authority | v2 拆分 public distribution/bootstrap/data 与 private control/enrollment/config/report；稳态 Device 通道均用 overlay IP + 分用途 mTLS |
| 最小 per-device signed view | 固定渲染契约和禁止暴露项，不把现有 bundle 冒充最小视图 | ControlSet QC、per-device view、pull/cache 与旧快照迁移 |
| 版本坐标 | 保持 raw SSOT revision、snapshot ID 与全局 signed release generation 的既有含义，禁止改名冒充目标字段 | 引入独立 Recovery lineage、Control epoch/revision、per-Device generation、四组 durable floor 与不可逆 v2 latch |
| 域名与 listener | 公开地址继续来自部署配置 | 托管 zone/ACME；Hysteria2/Trojan 用多 generation listener 做计划内无中断轮换，WireGuard 未完成双 interface/peer profile 前只允许 disruptive maintenance |
| 依赖增量发布 | 正确性允许先对全部 Device 重算 | publisher 只发布 view digest 真正变化的 Device，并做千台压测 |
| 不引入 route broker | 本次即作为 API/UI 负向约束 | 只有出现实测规模或隐私瓶颈才重新评估 |

这里的“v2 目标工作”不是推翻已确认方向。per-device view、多层版本坐标和增量发布必须作为
一个有迁移与回滚的协议改造实施，不能夹进 Create Device / 加入网络页面或 URL 筛选中零散上线。

## 3. 单一 Device 模型

统一产品实体不等于把所有数据塞进一张表。身份、期望态和运行证据仍按安全边界分开，
通过稳定 `device_id` 组成一个 Device：

```text
Device
├── Identity              稳定 ID、公钥/证书、创建与吊销状态
├── Membership            是否进入某个 certified Control head
├── Responsibilities      use_loom / forward / internet_egress / ...
├── Destination grants    获准使用的 Service、出口、后续 Local Network
├── Control projection?   certified FinalControlSet authority + matching private peer directory 的只读投影
├── Desired view          recovery/control 坐标 + device_generation + leaf/proof + QC
├── Public EndpointSets   DistributionEndpointSetV1 / BootstrapIngressEndpointSetV1 / DataIngressEndpointSetV2
├── Private services      ControlServiceDirectoryV1 中按 role 授权的条目
└── Runtime evidence      applied / online / stale；带时间，不写回期望态
```

v1 的 `clientregistry.Client` 与 `model.Node` 是两张表按相同 ID 拼出的迁移形状。迁移期
可以保留底层适配器，但 API、UI 和新代码只能暴露 Device。SSOT 中尚无 registry identity
的机器显示为 `Identity not indexed`；既有节点只能用受信 CA 证书的精确 Device SAN 导入，
不能根据名称、hostname 或 IP 猜身份。`identity_source` 只区分二维码加入与受信的
既有证书，不承担软件版本、在线状态或职责语义。

拓扑仍然存在，但拓扑中的点是承担转发/出口职责的 Device 投影，不再是另一类实体。

## 4. 统一 Enrollment

### 4.1 一条协议，多种载体

```text
创建端一次性生成 token、封装 control-private exact-version artifact binding
  → 已入网管理员经 overlay 访问 ControlServiceDirectoryV1 中 role=control_api 的私有服务，验服务器证书/IP + admin cert 提交 Create Device intent commitment
  → validate 后写入 Raft durable log，apply 后取得 quorum attestation QC
  → certified 后 renderer 才解封同一 token；access-only 一次性显示有界 descriptor QR，Linux 可用本地或 SSH 会话执行同一 bootstrap
  → QR / loom:// URI 携带 token/commitment、trust checkpoint、catalog/proof hash、2～3 个静态 distribution mirrors、PrivateEnrollmentServiceRefV1 和短期 capability；.loom-invite 可内嵌 catalog/public proof
客户端安装并启动通用包
  → 导入上述加入输入
  → 本机检测平台与架构，并与邀请固定的平台比较
  → 从 descriptor 的 mirrors 无 token 下载 immutable catalog/public proof，分别验 bootstrap_catalog_hash、proof_bundle_hash、record/QC/authority、intent hiding commitment 和 BootstrapIngressEndpointSetV1
  → 从当前 underlay 对实际 HY2 入口各测至多一次；正式版对 UDP 全阻断使用独立 Trojan/TLS TCP fallback
  → 只在选定入口时出示 capability，建立只能达 PrivateEnrollmentServiceRefV1 IP/port 的短期隧道
  → 验证内层 server-auth TLS，先做不含 token/CSR/key 的 EnrollmentIntentPreflightRequestV1/ResponseV1，取得 exact DeviceEnrollmentIntentOpeningV1 并重算 hiding commitment
  → 按 exact intent 生成 identity/CSR signing key 和仅用于封装的独立 wrapping key（Android API 31+ P-256 ECDH，API 26–30 RSA-OAEP fallback）
  → 构造稳定 EnrollmentClaimCoreV2，取得 EnrollmentPoPChallengeV1，identity key 对含 server nonce 的 EnrollmentPoPBodyV2 签名
  → 在内层 TLS 提交 EnrollmentClaimSubmissionV2：token + stable core + challenge + detached PoP
  → 当前 stable ControlSet 的 enrollment voters 各自经私有 peer RPC 验 token/core/opening/challenge/PoP，形成 StableEnrollmentAdmissionQCV1；单 ingress 不能批准
  → Raft 以线性化 CAS 提交 token/Device ID reservation，并承诺 Identity、Membership 计划、
    Responsibilities、grants、sealed secret-ref root 与 future view leaf；exact refs 只随私有 receipt
  → apply/recompute 后取得 config replication QC，claim reservation 才成为 certified；尚不激活 Membership/view/secret
  → 在线 CA 验 claim QC 与最新 active/fenced exact profile，确定性签证并提交 Raft issuance registry
  → enrollment voters 验证证书、issuance entry 与 profile inclusion 后形成 Enrollment approval QC
  → approval-QC-authorized completion 进入第二个 ordinary head，current config QC 后原子消费 invite、激活 Membership/view 并授权 artifact release
  → 发布带 claim/completion QC/head 及 Merkle inclusion proof 的 Device view、EndpointSet 与只为该 wrapping key 封装的 artifacts
  → 客户端验证 checkpoint/QC/proof/floor，原子安装正式 cert/view/creds 并 latch v2
  → 清除 token/capability/临时 profile 与隧道，以正式身份由同一平台客户端宿主建立持久 WG control/L3 overlay，再首次 pull 和签名上报
```

这是目标 v2 流程。公开 proof 只含 `DeviceEnrollmentIntentCommitmentV1` 及其认证路径，
不含 exact intent/opening；完整 opening 只经上述 tunnel preflight 交付。公网 Nginx 只提供 fake website 和 immutable distribution，永远不见
token/CSR/PoP，也不反向代理 Enrollment。WG 只是正式入网后的持久 control/L3 overlay，不是首版
bootstrap transport。Android 的该持久 overlay 由同一 libbox/`VpnService` 宿主承载，不启动
第二套系统 VPN 或独立 Tailscale/Headscale 客户端。v1 的严格 invite/claim schema、单 registry 和单 endpoint 保持原样，
只能通过并行的 v2 资源与 reader 迁移，不能向 v1 JSON 就地添加字段。QR 中的 mirrors 和
capability 只是 bootstrap 能力，不是长期权威；加入后只接受已信 transition/QC 连续引入且 transport identity
pin 匹配的新 endpoint。

- 管理员创建时选择平台；客户端仍报告本机平台，服务端要求它与邀请精确一致。
- v1 邀请契约中 Windows 和 Android 只允许 `use_loom`；Linux 可组合 `use_loom`、`forward` 和
  `internet_egress`。`internet_egress` 必须包含 `forward`，只有 `use_loom` 才能携带
  Destination grants。Android 属于统一 Device 模型，可创建固定 Android 平台的邀请；
  客户端仍须完成 Keystore 身份绑定、签名 pull 和候选激活才算加入完成。
- Raft-committed claim 只建立 Identity/Device reservation；证书 issuance、Enrollment approval QC
  和 completion head/config QC 全部完成后，才激活并向 Device 交付 Membership、Responsibilities、
  grants 与 view。reserved、active 与 online 是三个不同状态。
- 一次性码的 TTL 限制首次绑定。只有经已验 `BootstrapIngressEndpointSetV1`
  建立、ACL 只可达本次 `PrivateEnrollmentServiceRefV1` 的 claim 才可接收，并必须以全局 token digest 做
  线性化 CAS；预留后只允许同一 token 与字节完全相同的 `EnrollmentClaimCoreV2`
  在 invite/capability 有效期内重放。server nonce 可更新，identity key 对应的 detached signature bytes
  可随之变化，但 stable core/hash 不变。v1 Windows
  Portable 契约独立保留指定 control 的一小时恢复窗口，未完成期间用当前用户 DPAPI
  保存 pending token，并在 joined 完成标记提交后清除。
- 加入码不能创建 identity-only Device；v2 intent 在创建时固定平台、
  Responsibilities 和 Destination grants，提交前必须展示；它不携 Device-wide direction。
  每条 control/data 边的 initiator/transport/route scope 只能在 Enrollment 后由 certified LinkIntent 授权。
- 重连、升级、网络切换和重启使用既有身份，不重新 Enrollment。
- 服务器不依赖 control 节点 SSH push 作为安装或加入模型。`get.docker.com` 式脚本只负责获取
  通用包，随后仍导入同一加入码；管理员可以先 SSH 到目标机执行同一脚本，但控制平面不保存
  SSH 凭据，也不存在第二套 SSH Enrollment。

`BootstrapTunnelCapabilityV1` 是已 certified Invite 的受限派生物，由 ControlSet 授权的
专用 bootstrap issuer 签名，不能自行扩大 Invite 边界。默认 TTL 15 分钟，可配 5～30 分钟且
硬上限 30 分钟；单隧道会话上限 180 秒、总流量默认 8 MiB、最多 3 次顺序建连尝试，
每入口同一 `cap_id` 最多一个并发 session。这些是防滥用界限，真正的一次消费
仍由 ControlSet 对 enrollment token 执行 Raft CAS；全网强一次拨号不得破坏弱网重试。
若 claim 已 commit 但 capability 过期，管理员必须经私有 `role=control_api` 服务线性化
确认 transaction 仍为 reserved/completed，再一次性生成不含 token 的
`EnrollmentResumeDescriptorV1`。它携带 exact resume capability、`claim_core_hash`/transaction
binding 与 catalog/proof/service/mirror refs，只以带外 QR 或 `.loom-resume` 交付，不发布到
公网 mirror，也不允许客户端自动刷新。客户端必须以本机 pending core/identity
核对 exact binding，并对新 server nonce 重签 PoP；ControlSet 幂等返回既有结果，
不重置、不重消费 token，也不延长旧 capability。

隧道 ACL 只允许 catalog 认证的 Enrollment `/32` 或 `/128` 和 TLS TCP port，禁止其他
overlay CIDR、Internet egress、DNS、ICMP、隧道内 UDP、control API、Raft、SSH、配置和报告。
入口转发器与 ControlSet 防火墙双重执行。内层 server-auth TLS 绑定私有 IP 的内部 CA/IP SAN
或固定 SPKI；token 与 PoP 只在内层发送。PoP 由 identity/CSR key 签名，覆盖 stable
`claim_core_hash`、network/invite/request ID、CSR/identity/wrapping-key hash 和 server nonce；
wrapping key 只用于凭据包装。相同 token + stable core 的跨入口重试幂等；换 key/core 的重放拒绝。

### 4.1.1 二维码重发与本机身份丢失

未领取的身份预留可在 Device 详情页**重新签发**加入码。名称、ID、平台、职责和 grants
保持原值；目标 v2 没有需要保持的 Device-wide direction。创建端先预生成并封存新 token/artifact，再用一个原子 proposal 同时撤销
旧 record 并创建绑定新 commitment/private-binding hash 的 public record，完整 ref 仍只在
control-private binding；取得 QC 后才一次性交付新载体。
旧 invite 的明文不能从列表重新取回。纯 `use_loom` Device 只在新 invite 的一次性创建结果中
显示二维码；结果页内点击二维码可复制同一份一次性加入 URI，不触发图片下载，加入文件仍有
单独下载按钮。离开结果页后如未保存，只能重新签发，不能 reveal 旧 token。
包含 `forward` 的 Linux Device 仍只展示 shell/SSH 辅助交付，不展示 QR。

Windows 的“删除本机 Device”会清除本机身份和配置，不通知控制平面，也不自动撤销网络
中的凭据。管理员确认本机身份已删除后，可对 Enrollment 生成的纯 `use_loom` Device
使用“Rejoin Device”。控制平面提交移除旧成员及其专属凭据、将旧身份归档，并分配新 ID 与
新二维码；只有该替换取得对应 reader 协议要求的认证（v1 单签或 v2 replication QC）后才交付。
名称、平台和原职责/授权保持不变。旧证书属于旧 ID，不能
用于领取新身份。归档记录保留 `replaced_by`，新记录保留 `replaces`。

如果不需要替换设备，同一详情页提供单步 **Remove Device**。它不等待客户端回执：控制平面
提交纯 `use_loom` Device、设备专属凭据和 enrollment identity 的撤销；只有变更取得对应
reader 协议要求的认证后，发布视图才将其标为 revoked，服务器应用下一份认证配置后不再
接受旧数据面凭据。该操作不会远程删除客户端
本机文件，也不会把未收到停机通知误报成“已停机”。未领取 Device 仍使用更窄的
**Delete Device**，只删除从未消费的 identity reservation 和加入码。

转发服务器应用新的签名配置后，旧数据面访问凭据才失效。该流程不证明旧客户端执行过
signed decommission，也不代替服务器/隧道节点的退休迁移或通用证书吊销机制。
仅有“本机删除”时，控制平面保留现有记录且不能猜测在线；完成控制平面替换后，旧身份从当前
列表移入 Archived devices。SSOT 撤销后若 registry 落盘失败，不返回二维码，重试可
继续完成归档与新身份分配；不会恢复旧接入。

设备列表直接提供 **Pause / Resume**，只对当前职责恰好为 `use_loom`、已加入且未下线的
Device 开放；包含 `forward`、`internet_egress`，或存在 FinalControlSet `control` 投影的
Device 不能使用此快捷操作。
未登录时，设备列表不显示添加或管理的登录提示按钮；登录后，暂停/恢复使用图标按钮，
与 `active` / `paused` 状态同行显示，并提供操作提示及无障碍名称。
`nodes[].paused` 是独立的可恢复 SSOT 状态；它不吊销 identity、不改 Destination grants
和秘密，也不停掉客户端或配置拉取。服务器应用签名配置后停止接受该设备的全部数据面
凭据（包括轮换期间的上一代），恢复后沿用原身份和授权，无需重新扫码。
这是暂停 Loom 转发访问，不是系统断网：本机直连不受影响，旧客户端仍可保持启动和上报。
不向旧客户端下发“全部入口阻断”来伪装停机，避免宿主健康检查将其当成故障回滚。
列表中的 `paused` 表示期望态，不能当成所有服务器已经生效的运行回执。

Archived devices 中已为 `revoked` 且不在当前 SSOT 的身份可从详情页永久删除。该操作只清理
归档 identity 与旧邀请记录，不重复撤销、轮换或影响 replacement Device；仍在 SSOT 的记录
和非 revoked 身份由服务端拒绝删除。

概览和拓扑页的当前设备、连线及选路投影以当前 SSOT 成员为准。移除 Device 后，即使
旧快照或 gossip 仍保留该设备的运行观测，也不再把它或引用它的路径显示为当前网络；
概览中的当前异常同样排除已移除设备；暂停设备保留在 Devices，退出当前网络投影。
历史事件、流量时间桶与节点诊断证据仍按原有
保留规则保存，不因 identity 归档或永久删除而被改写。

Archived devices 只读取 identity、SSOT 与当前运行态，不加载无关的 Linux 安装包信息。
控制端对同一组未变化的原子发布文件复用已经完成完整验签的发行包结果；任一 archive、
checksum、signature 或平台公钥文件被替换后都会重新执行完整验证。

### 4.2 邀请级加入意图的边界

不增加 `standard-device`、`server-device` 或命名 Profile。每张新邀请直接保存以下事实：

- `platform`：可创建 `windows-desktop`、`android` 或 `linux-server`；
- `responsibilities`：`use_loom` / `forward` / `internet_egress` 的合法组合；
- `destination_grants`：仅在选择 `use_loom` 时非空。

上述是目标 v2 `DeviceEnrollmentIntent` 的全部 Device 级授权输入；它不包含
`direction`。含 `forward` 不会自动生成全局连接方向，每条实际边必须在 Enrollment 后由
certified LinkIntent 独立固定两端、initiator、transport 和 route scope。

邀请不能携带或授予 `control`。既有 Device 只有先作为 learner 完成同步，再经
`JointControlSet → FinalControlSet` 提交、apply 并取得 old/new replication QC，才获得只读
`control` 投影。

客户端 claim 只提交身份/包装公钥、CSR、已验 base authority 与本机平台，
不能选择或扩张职责和 grants。目标 v2 将 invite
拆成 record、descriptor 与 proof 三层：token 必须在 proposal 前生成并封装，Raft/CRDT 中的 canonical
`CertifiedInviteRecordV2` 只记录 `DeviceEnrollmentIntentCommitmentV1`、token commitment、
control-private artifact-binding hash 和 delivery-context hash；完整 `DeviceEnrollmentIntentOpeningV1`、
exact-version ref 与 token 明文一致性回执只在 matching private binding 中。certified 后的一次性
`InviteBootstrapDescriptorV2` exact 携带 schema/cluster/invite/expiry、token/commitment、
`bootstrap_catalog_hash`、`proof_bundle_hash`、minimum recovery/trusted checkpoint、2～3 个精确
`DistributionMirrorRefV1`、有界 `PrivateEnrollmentServiceRefV1` 和短期
`BootstrapTunnelCapabilityV1`。客户端只向 mirror 无 token 获取并分别验证 catalog/public proof；
public proof 只含 hiding commitment 及 record/head/QC/authority 证明，不含 intent/opening。
客户端验证 `BootstrapIngressEndpointSetV1`、测实际 transport、建立受限隧道并验内层 TLS 后，
才可用 token-free preflight 取得 opening 并重算 commitment，然后提交 claim；`.loom-invite`
可内嵌 descriptor/catalog/public proof，不能内嵌 private intent opening。
这样响应时 head 变化不会改写已提交
record，也不会让完整历史挤爆二维码。token 明文只存在于初始 descriptor，并只进入
当前 invite/capability 有效期内的 `EnrollmentClaimSubmissionV2`；
其 stable `EnrollmentClaimCoreV2` 包含 request/record/intent 绑定、base floors、platform、
CSR/identity、wrapping descriptor 和 client nonce。
`EnrollmentPoPChallengeV1`/server nonce 与 detached PoP 不进入 stable core/hash，因此 exact core 重试可对新
nonce 重签。已 commit 事务只能通过管理员带外交付且 exact-bound 的
`EnrollmentResumeDescriptorV1` 恢复。token 不进入 URL/header/cookie 或复制日志，验证并持久化
certified receipt/identity 后客户端必须清除。v1 registry 的直接字段仍是迁移事实，不向其严格 schema
就地增加 v2 字段。旧 schema 1 邀请全部失效：迁移只保留已经
加入的 identity 及其具体职责，丢弃旧邀请和未完成的 pending/provisioning 记录；管理员必须
按新模型重新创建未加入 Device。这是一次单向迁移，不兼容旧邀请。

为保证 v1 reader 仍能读取并回滚既有 SSOT 存档，模型暂时保留 `enrollment_profiles` 的废弃
decoder-only 字段；它不参与校验、UI、邀请创建或 claim，不能让旧加入码重新生效。

连接方向也不是角色。在 v1 兼容模型中，`reverse_only` 表示该 Linux Device 主动建立并维持
反向 WireGuard 隧道，适用于无公网入站或受限网络；`bidirectional` / `direct_only` 沿用现有方向矩阵。
目标 v2 将发起方向和允许 transport 放到每条 LinkIntent：WG 是稳定 L3/control overlay 的首个实现，
HY2 可承担符合发起/可达条件的数据转发 hop，不把全节点永久定性为某种 tunnel。
旧 v1 部署可把境外节点设为 `reverse_only`，但这只是迁移输入；位置不决定方向，境外节点也不被底层模型禁止
承担 `use_loom`、`forward` 或 `internet_egress`。

## 5. 通用包与设备配置分开

### 5.1 公开通用包

每个公网 Nginx 只允许提供 fake website 和内容寻址的静态 distribution：版本化客户端包/
安装脚本、manifest、checksum、签名、公开验证材料、bootstrap catalog bundle 和不含秘密的
兼容性元数据。Nginx 不接收、终止或代理 Enrollment。加入 token、Device identity、证书、秘密、设备配置、
全局拓扑和运行证据不得进入 GitHub 或公开镜像。

包地址来自实际部署配置，代码不硬编码域名、IP、节点或供应商。Create Device / 加入网络
页面为 access-only 生成二维码/加入文件，为 Linux 生成本地或 SSH 辅助的 bootstrap；二者
内部都消费一次性 URI。安装命令只下载公开通用包，加入 secret 不成为公开包 URL 的一部分。

### 5.2 v1 首次配置分发契约（迁移基线）

v1 的 `readyBootstrap()` / Enrollment 分发适配器只有满足以下规则，才可作为 v2 迁移输入；
实际部署是否满足只见[当前状态](status/current.md)：

1. Enrollment 候选只来自部署配置的 `defaults.distribution_urls`，顺序表达运维偏好；
2. publisher 对每个候选复用现有 `VerifyServed()`，记录 URL、snapshot、SSOT、验证时间、
   成功或失败；验证循环检查全部候选，不在首个失败处停止；
3. 选择函数只保留合法 HTTP/HTTPS、无凭据/query/fragment、非 loopback/link-local/私网
   字面 IP，且已精确提供本次 signed current、manifest 和所需正文的地址；
4. 不根据 `public_endpoint`、节点 `Healthy`、Hysteria2 探测或 RTT 推导下载 URL；
5. 结果按部署配置顺序稳定去重，客户端继续用现有多镜像 pull 在本地完成可达性选择；
6. 没有合格地址时保持 `provisioning` 并给出明确原因，不返回假的 `ready`。

某个镜像失败时，publisher 仍按现有语义显示降级并继续收敛；另一个地址已对同一
SSOT/snapshot 精确验证时，Enrollment 可以使用它，但不能因此把 publisher 标成绿色。
统一 Device 详情只读显示返回地址数、最近验证时间和阻塞原因，不提供手选下载节点。

兼容测试必须覆盖：更换部署地址无需改代码、私网/重复/非法 URL 排除、snapshot 不一致
排除、首选不可达时客户端使用备用地址、无候选 fail closed，以及日志不泄露加入码和密钥。

### 5.3 目标设备配置通道

E1 使用公开的全局 signed distribution 作为过渡。目标态由私有
`ControlServiceDirectoryV1` 中 `role=device_config` 的服务返回本 Device 的最小
signed view；`control_api`、`enroll`、`device_config` 和 `device_report` 都是该私有目录的分用途
role，只经 Loom overlay IP 可达。稳态 Device 使用独立客户端证书 mTLS，内部服务器证书按用途隔离。
`DistributionEndpointSetV1`、`BootstrapIngressEndpointSetV1` 和 `DataIngressEndpointSetV2` 才是公网对象，
三者也不能互相推导。ControlSet replication QC 证明内容已由 Raft 提交并被当前
quorum 复算；传输身份、Device 身份与内容 authority 不能互相替代。v1 URL 和 current
envelope 在兼容期只作为显式 legacy reader 输入。

## 6. 版本化对象图

### 6.1 对象关系

```text
EnrollmentTransaction (短期、单次)
        │ 固定 platform / responsibilities / grants；不含 Device-wide direction
        │ claim
        ▼
DeviceIdentity (稳定)
        │
        ├── MembershipVersion
        ├── ResponsibilitySetVersion
        └── DestinationGrantVersion refs

上述不可变对象的根 ──> candidate ControlRevision
        │ 每个 voter validate/reduce/candidate render
        ▼
ControlSet(epoch) ── Raft durable commit ──> apply/recompute
                                              ├── device_views_root
CandidateDeviceView(RaftCommit, DeviceID)     │
        └── DeviceView bytes + leaf + dependency refs + EndpointSet
                └── 内容变化时 DeviceGeneration + 1
                                              │ voter replication attest
                                              ▼
                                     CertifiedHead + quorum QC
                                              └── publish Device view + inclusion proof
```

RuntimeEvidence 独立进入观察投影，不参与 Control revision，也不因一次上报触发发布。

### 6.2 Recovery lineage、三个版本轴与 protocol latch

**Recovery epoch / statement / policy hash**

- 是高于 Control epoch 的恢复 lineage；无论计划轮换还是灾难恢复，都只能由客户端已钉住的
  旧 recovery policy 达到 threshold 后签署连续 transition 来提高；计划轮换还必须取得当前
  ControlSet 的 intent/activation QC；
- 更高合法 recovery lineage 压过旧 ControlSet 后续产生的任意普通 revision；
- 与 statement hash、policy hash 一起耐久保存，同 epoch 任一 hash 不同都失败关闭。

**Control epoch（作用域为 recovery lineage）**

- 标识一条经过证明的 ControlSet 成员与 membership key 历史；
- 同一 recovery lineage 内只有 `JointControlSet → FinalControlSet` 能递增。两种 recovery 路径都把
  新 lineage 的 control epoch 重置为 0，但承诺不同：emergency `RecoveryGenesis` 明确绑定完整新
  ControlSet、matching private peer-directory hash 与 key PoP；有 quorum 的 planned
  `RecoveryActivation` 保持当前已信 ControlSet/directory hash，由同一稳定集合 QC 认证，不生成
  新成员集合或 PoP；
- 客户端持久化 checkpoint；同一 recovery lineage 内不能从网络响应重新信任更小或无连续
  joint proof 的 epoch，跨 recovery lineage 则先验证 recovery transition，再采用新 lineage
  明确绑定的初始 control epoch。

**Control revision**

- 由当前 recovery/control lineage 内已提交的 Raft log position 确定；只有 apply/recompute 后
  取得 replication QC 的 certified head 才能作为客户端和外部 executor 的生效期望对象图；
- 用于审计、并发提交、影响分析和复现；
- 是规范化对象图的 revision，不等于当前 raw YAML bytes 的编辑摘要；
- 不能替代 Device generation；客户端同时保存 revision/head 与 generation/leaf/view floor。

**Device generation**

- 对每个 Device 独立、单调递增；
- 只有 materialized DeviceView 的语义内容变化时才递增；
- canonical leaf 绑定 `device_id`、generation、state、payload/previous/EndpointSet hash 和最低
  reader version；来源 Control revision 只通过 head QC 与 inclusion proof 绑定，不进入 leaf；
- leaf 本身不含当前 head/revision；通过 RFC 6962 inclusion proof 绑定到 certified
  `device_views_root`，避免无关提交迫使所有 Device 改 generation；
- 客户端持久化自己的 generation/leaf/view floor，并与 recovery/epoch/revision floor 分开比较。

v1 迁移客户端只有在 BootstrapTransition 同时匹配旧本机 floor proof、初始 ControlSet/
admin ACL/CA/recovery 材料和独立 migration anchor 时才能接受首个 v2 head。接受前原子写入
`protocol_latch=v2`；之后 v1 current、QR 或 view 永不再成为 authority，状态丢失必须重新
受信 bootstrap，不能以清 cache 的方式降级。

v1 的 raw SSOT revision、snapshot ID 和全局 signed release generation 是三个兼容坐标，
迁移期间都不能改名冒充上述目标字段。

### 6.3 最小 per-device signed view

目标 View 只允许包含本 Device 执行职责和 grants 所必需的内容：

- 本设备身份绑定、组件约束与本地入口；
- 获授权的 Service/Policy 结果和出口集合；
- 实际候选路径需要的最小 peer endpoint 与凭据引用；
- envelope 中的 recovery/Control checkpoint、Control revision、Device generation、head QC、
  leaf + inclusion proof、transition proof 和按用途拆分且带 transport pin 的 EndpointSet。

禁止包含无关 Device 清单、完整拓扑、其他设备凭据/配置、未授权 Service、加入凭据或
全网运行观测。Device 可以看到它实际需要连接或被授权选择的节点，不能枚举全网。

## 7. 依赖驱动发布

渲染器应是纯函数，并同时返回 View 和依赖集合：

```text
RenderDeviceView(effective_state, device_id)
    -> bytes, digest, dependency_refs
```

同一函数在提交前 candidate 校验和 Raft apply 后复算时必须产生逐字节相同结果；这些结果进入
`device_views_root`。只有 root 所属 head 取得 replication QC 后，publisher 才能交付 view/proof。

Control revision 变化后，以 View digest 是否变化作为最终影响判据：

- 新增普通 Device：只产生新 Device 的 generation；
- 修改某个 Service grant：只更新引用它的 Device；
- 修改共享出口或凭据：更新依赖该对象的 Device；
- 仅修改显示名且不进入运行 View：不增加 Device generation。

第一版可以对全部 Device 重新计算 digest；1000 台规模下这比先建复杂调度系统更可靠。
head QC 认证整棵 root；publisher 只需发布 digest 真正变化的 Device view。依赖索引是性能
优化，不能成为正确性来源。

## 8. 分阶段迁移

### E1：v1 统一入口与安全交付基线

v2 迁移以前必须具备以下基线；本节不记录完成状态：

1. **统一 Device 读模型：** 以稳定 `device_id` 合并 Client registry、SSOT Node 和可信
   runtime evidence；新增 `/devices` 列表/详情，缺失 identity 明确标为 not indexed，
   既有节点只按受信证书迁移；
2. **统一授权语义：** API、Review 和 UI 使用 Identity / Membership /
   Responsibilities / Destination grants；“Access”改为“在此设备上使用 Loom”；
3. **统一加入网络：** Create Device 先建立唯一设备记录并生成一种一次性加入码；服务器、
   Windows、Android 和 Linux 共用底层 claim，管理员先选平台，客户端报告必须一致；客户端启动后
   导入加入输入，只绑定这个既有 Device；不保留 SSH Add node 入口；
4. **直接固定加入意图（v1 基线）：** 创建时直接选择 Responsibilities、必要的
   Destination grants 与 v1 `forward` direction；不新增 Device 类型或 Profile 管理页，不允许
   identity-only 邀请。该 direction 只供 v2 LinkIntent 迁移器一次性投影，不进入 v2 Invite；
5. **公开通用包：** 生成带签名/校验的通用包和服务器安装脚本，发布到部署配置声明的
   公开源；Device 页面按职责给出 access-only QR/文件，或 Linux shell/SSH 辅助安装方法；
6. **修复首次 pull：** 落地 §5.2 的逐 URL 发布证据与选择函数，替换
   `readyBootstrap()` 在 E1 前直接继承节点地址的行为；
7. **收口旧入口：** 产品/API 不暴露 `/nodes/add` SSH 加入；旧 `/clients` 只能是有期限的
   命名兼容层；拓扑中的 Nodes 只保留 Device 的职责投影；
8. **真实端到端 canary：** 每个平台从创建 Device 和加入码、安装、内部 claim、首次 pull、
   apply 到可信 online 分别验收，不能用另一平台或模拟器替代。

上述基线实际覆盖范围只见[当前状态](status/current.md)。E1 保留兼容存储、v1 SSOT 投影、
签名/pull 和全局 snapshot/release generation，以免同时切换全部故障域；这些分别在 E2/E3
迁移。全局 generation 是明确的迁移债务，UI/API 不得把它标成 Device generation，也不得
宣称已经实现最小私有 view 或增量发布。

### E2：v2 对象与单成员 ControlSet

1. 固定 JCS/domain framing、Raft log/提交后 attestation QC、recovery/Control 坐标、Device
   Merkle proof 与 transition 跨平台向量；
2. 将 v1 指定 control 表示为 `N=1, q=1` 并运行完整 durable log，同时发布 v1 单签与独立 v2
   envelope；明确单成员不具备抗单节点失陷能力；
3. 实现确定性的 per-device view/leaf/RFC 6962 proof、digest 与依赖集合；
4. bootstrap transition 精确绑定 v1 per-Device floor root、初始 admin/CA/ControlSet/recovery，
   v1 platform key 签名之外另由部署专属 migration anchor 钉住；
5. 保持严格 v1 reader 不变，禁止在旧 current/invite/report schema 中混入 v2 字段。

### E3：reader 优先与私有 Device Distribution

1. Android、Windows、Linux 先支持 bootstrap/recovery checkpoint、提交后 QC、Device inclusion
   proof、joint transition、完整 floor 和不可逆 v2 latch；
2. 支持紧凑 QR：token/commitment、trust checkpoint、catalog/proof hash、2～3 个静态 mirrors、
   有界 `PrivateEnrollmentServiceRefV1` 和 bootstrap capability；
3. 只从 Nginx 无 token 下载并分别验证 immutable catalog/public proof，public proof 只含
   hiding commitment；然后对实际 HY2 入口各测至多一次；
4. 实现受限临时隧道、私有 Enrollment 内层 TLS、token-free intent preflight、stable claim core、
   identity-key detached PoP、Raft CAS、带外 resume descriptor 与完成清理；
5. 经过 Device mTLS 访问 `ControlServiceDirectoryV1` 中 `role=device_config` 的私有服务
   以返回最小 Device view，报告走 `role=device_report` 的独立私有服务；
6. 双读验证、故障切换和隐私边界通过后，才停止依赖公开全局 snapshot。

### E4：ControlSet 扩容与分布式写入

1. 新 control 先作为 learner 同步并校验 committed history，再经 certified joint transition 入组；
2. invite token CAS、identity registry、admin ACL、release head 和撤权进入 Raft durable commit
   并取得提交后 attestation QC；
3. 不可变提案、报告和观测用 CRDT anti-entropy 复制；candidate 只用于校验，只有取得提交后
   QC 的 certified head 才能发布为 Device view；
4. 已入网管理端可经 overlay 访问已信 `ControlServiceDirectoryV1` 中
   `role=control_api` 的任一已授权私有服务，
   在精确内部证书/IP 和 admin cert 认证后提交管理请求，少数分区拒绝安全关键写。

### E5：域名、证书与端口轮换

1. 以 provider-neutral adapter 接入托管 DNS zone 和 ACME DNS-01；
2. 每个具有 `forward` 职责的服务器使用稳定 FQDN 和 DNS-01，公网 Nginx 只提供
   fake website/immutable distribution；同机 HY2 UDP 和 WG UDP 使用不同端口，正式版另有独立 Trojan/TLS TCP bootstrap listener；
3. 将现有单公网 endpoint 映射为 generation 0；显式 PublicEndpointIntent 才触发公开域名，
   `control` membership 本身不暴露 API、Enrollment、config 或 report；再实现
   allocate → prepare → advertise → prefer → drain → retire；
4. Linux server 先对 Hysteria2/Trojan 并行监听，三平台接受已签新旧代并反馈 ack；新 listener
   未验证或兼容窗口未满足时不得关闭旧端口。WireGuard 只有完成双 interface/peer 专用流程
   后才能宣称无中断轮换。

### E6：收口兼容路径

设置最低客户端版本，确认 reader 已原子 latch v2，停止生成 v1 current/invite，撤销旧在线
signer，删除单机文件锁作为协议 authority 的路径；本地 cache、静态镜像和离线 recovery
能力继续保留。丢失状态的 Device 只能重新受信 bootstrap，不得自动回退 v1。完整顺序与回滚
点见[分布式控制平面设计 §19](distributed-control-plane.md#19-从当前实现迁移)。

## 9. 后续仍需单独决定

只有以下实现选择尚未确定：

1. 通用包实际使用哪些 GitHub/国内镜像及同步、保留和故障切换方式；
2. 首批 DNS provider/托管 zone、provider credential 的保管方式及自动购买/续费审批边界；
3. 离线 recovery root 的持有人、门槛、演练周期与带外重锚流程；
4. v1/v2 双发的最长兼容窗口，以及哪些最低客户端版本允许 retire 旧入口；
5. 已加入 Device 的职责与 grants 是否需要批量变更 UI；这属于显式配置变更，不改变加入协议。

route broker 当前明确不做；Local Network 按独立专题推进，不在本计划重复讨论。

## 10. 验收总原则

- 任意新设备只有一个 Device ID、一个 Enrollment 生命周期和一份状态解释；
- 加入设备不再隐式获得“全部当前及未来 Service”的权限；
- 公开包中找不到加入码、凭据、设备配置或拓扑；
- 更换部署域名或镜像不需要修改代码；
- 同一 Control revision 可对应不同 Device generation，未受影响设备不更新；
- 客户端只能获得本设备实际需要的配置与节点信息；
- N=1/2/3/5 的 quorum、joint transition、少数分区拒写与离线恢复均有确定测试；
- QR 只携带 token/commitment、trust checkpoint、catalog/proof hash、2～3 个镜像、有界
  `PrivateEnrollmentServiceRefV1` 和短期 capability；公网 Nginx 无 token、不处理 Enrollment，
  catalog/public proof 内容寻址且客户端自行验证，proof 只含 intent hiding commitment；
- 客户端从当前网络对实际 HY2/TCP bootstrap 入口各测至多一次；不用 Nginx RTT
  代替，UDP 阻断时仅使用已签独立 Trojan/TLS fallback；
- capability 的时间、并发、次数、流量和 ACL 限制均有测试；隧道只可达私有 Enrollment
  IP/port，入口无法观察 token/CSR/PoP；
- 无 token preflight 交付的 exact intent opening 必须重算出 public proof 中的 hiding commitment；
  不匹配时不得发 token 或 claim；
- 同 token/stable `EnrollmentClaimCoreV2` 跨入口重试幂等，新 server nonce 只允许 identity key
  重签 detached PoP，Raft CAS 只消费一次；换 key/core 重放拒绝。
  `EnrollmentResumeDescriptorV1` 必须不含 token、精确绑定原已 commit 事务并由私有
  control API 确认后带外交付，不得自动刷新；ready 后清除全部临时凭据和隧道状态；
- 客户端拒绝无连续 transition、QC 不足和 recovery、control、head、Device view 任一 durable floor 回退；
- DNS/ACME reconciliation 可幂等接管，域名解析不构成控制权威；
- Hysteria2/Trojan 计划内端口轮换时新旧 listener 重叠，失败时旧入口保持可用；它不承诺
  QUIC/TCP 会话跨端口迁移，只保证没有新旧同时关闭的窗口，旧会话排空后才 retire。
  WireGuard 在双 interface/peer/key/address/route profile 验收前不得通过该项；
- `ready`、`published`、`applied`、`online` 始终是不同状态；
- 任何迁移阶段都能回退，且不能把目标态文案冒充当前已上线能力。
