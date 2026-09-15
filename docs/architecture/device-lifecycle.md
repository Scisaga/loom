# Device 生命周期、Enrollment 与交付架构

> **状态：** 已确认的目标模型，分阶段迁移；不是当前生产能力说明。  
> **范围：** Device 统一、Enrollment、授权边界、版本化对象图、设备配置交付。  
> **引用关系：** 本文定义产品生命周期与授权投影；wire 字段、认证及事务约束由控制面规范定义。
> 源码接线见[实现对照](../development/implementation.md)，运行结果见[部署证据](../operations/local-deployment.md)。平台客户端细节见
> [客户端接入设计](../clients/README.md)，局域网转发仍是独立的
> [Local Network 专题](../proposals/local-network.md)。动态 ControlSet、CRDT/QC、域名/证书和入口轮换
> 见[分布式控制平面设计](../protocols/control-plane/README.md)。
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

## 版本与规则归属

本文定义 Device 的产品实体、交互及交付投影。v1 的 registry、SSOT 投影和分发形态只作为
迁移输入；v2 的认证对象、claim 事务和恢复由[控制面规范](../protocols/control-plane/README.md)定义。
实现时不得为复现旧阶段而新增公开加入入口、Device 类型或 Profile 管理页。

## 单一 Device 模型

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

## 统一 Enrollment

### 一条协议，多种载体

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
- Linux 创建结果页把“已有管理 SSH/ProxyJump”与“SSH 不可达/未开放/NAT 后”作为同页内联
  分支。前者由操作者自行建立会话；后者使用云控制台、串口/IPMI 或本地终端。两者都在目标机
  运行相同 bootstrap，由节点主动取 immutable distribution 并进入私有 Enrollment；页面不弹出
  SSH 凭据表单，也不从 `direction`、职责或 NAT profile 猜测管理可达性。
- 软件/身份安装与 `forward` 公网就绪分开。Loom 不管理网关映射，只验证操作者已提供的 exact
  public/local TCP/UDP tuple。出站 distribution/bootstrap 不可达时显示对应阶段并保持可重试；
  公网 listener 或映射验证失败时 public access 保持 `preparing`、不 advertise，但不得撤销已经
  正确安装的 identity。交互提示检查主机防火墙、确认既有映射，或重新创建不含 `forward` 的
  Device；不扫描端口、不静默降级职责。

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

### 二维码重发与本机身份丢失

未领取的身份预留可在 Device 详情页通过 **New join code** 重新签发加入码。已领取、正在加入、已归档的设备不显示此按钮；运行时离线或缺少观测不改变这个条件。名称、ID、平台、职责和 grants
保持原值；目标 v2 没有需要保持的 Device-wide direction。创建端先预生成并封存新 token/artifact，再用一个原子 proposal 同时撤销
旧 record 并创建绑定新 commitment/private-binding hash 的 public record，完整 ref 仍只在
control-private binding；取得 QC 后才一次性交付新载体。
旧 invite 的明文不能从列表重新取回。纯 `use_loom` Device 只在新 invite 的一次性创建结果中
显示二维码；结果页内点击二维码可复制同一份一次性加入 URI，不触发图片下载，加入文件仍有
单独下载按钮。离开结果页后如未保存，只能重新签发，不能 reveal 旧 token。
包含 `forward` 的 Linux Device 仍只展示 shell/SSH 辅助交付，不展示 QR。

Windows 的“删除本机 Device”会清除本机身份和配置，不通知控制平面，也不自动撤销网络
中的凭据。管理员确认本机身份已删除后，可对 Enrollment 生成的纯 `use_loom` Device
使用 **Rejoin device**。详情页及提交确认必须说明它用于本机身份丢失，会撤销旧身份、分配新 ID，保留名称、平台、职责与授权；正常重连继续使用保存的身份。服务器、控制设备和从既有证书导入的设备不显示此快捷操作。控制平面提交移除旧成员及其专属凭据、将旧身份归档，并分配新 ID 与
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
没有有效管理员客户端证书时，设备列表不显示添加或管理表单；通过当前 certified Admin ACL
授权的证书访问后，暂停/恢复使用图标按钮，
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

Device inventory 由浏览器加载同源 JSON 快照，随后经 private HTTPS 同源 WebSocket
`/api/control/device-inventory/live` 接收完整列表投影；页面切换不重新加载文档，筛选与展开状态保留。可信 Device report、gossip/本机观测或
identity/SSOT 事务成功后由服务端唤醒连接，浏览器不轮询列表 API。连接中断时页面明确显示
重连状态并按有界退避恢复，不能继续把旧画面标成实时。所有 Linux 节点的 Loom report
进程及 Android Device 的已连接 VPN 服务每五秒发送只含 `node`、`ts`、`signature` 的独立签名心跳；十五秒
没有新心跳后，列表必须从 `Online` 转为 `Stale`。完整 Observation 与节点观测同步保留原有
周期、正文和陈旧规则，心跳不能刷新健康、自检、配置、链路、流量、测量或服务器观测。
十五秒租约以服务端接受新签名包的时刻计算；设备时钟偏差及旧包重放不能延长租约。
页面分别显示 last heartbeat 与 last observation；两种证据不能互相替代。缺少心跳只能证明
“当前在线证据已陈旧”，不能伪造已经观测到的 `Offline`。服务端为心跳过期边界设置定时
唤醒，因此即使断开后不再产生新事件，已打开的列表也会自行更新。
不保留旧 Android/Linux 的滚动兼容：从未提交过新协议心跳的节点显示 heartbeat 尚未上报，且不能因为
完整 Observation 仍新鲜而显示 `Online`。完整报告在任何情况下都不能代替心跳。
Windows 客户端保留原完整报告协议和租约；报告一经服务端接受仍会立即触发上述 WebSocket，
不需要浏览器刷新。

概览和拓扑页的当前设备、连线及选路投影以当前 SSOT 成员为准。移除 Device 后，即使
旧快照或 gossip 仍保留该设备的运行观测，也不再把它或引用它的路径显示为当前网络；
概览中的当前异常同样排除已移除设备；暂停设备保留在 Devices，退出当前网络投影。
历史事件、流量时间桶与节点诊断证据仍按原有
保留规则保存，不因 identity 归档或永久删除而被改写。

Archived devices 只读取 identity、SSOT 与当前运行态，不加载无关的 Linux 安装包信息。
控制端对同一组未变化的原子发布文件复用已经完成完整验签的发行包结果；任一 archive、
checksum、signature 或平台公钥文件被替换后都会重新执行完整验证。

### 邀请级加入意图的边界

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

客户端 claim 不能选择或扩大职责和 grants。Invite 的 record、descriptor、proof、私有
intent opening 与临时凭据按[邀请协议](../protocols/control-plane/enrollment-invite.md)分离；
客户端在私有内层 TLS 的无 token preflight 验证 intent 后才提交 claim。
重复提交、fresh server nonce、detached PoP、管理员 exact-bound resume 和完成后清理遵守
[Enrollment 事务](../protocols/control-plane/enrollment-transaction.md)。

旧 schema 1 邀请全部失效：迁移保留已加入 identity 及具体职责，旧邀请和未完成的
pending/provisioning 记录不继续授权；管理员按新模型重新创建未加入 Device。
这是邀请模型的单向迁移，不能向严格 v1 registry 原位添加 v2 字段。

为保证 v1 reader 仍能读取并回滚既有 SSOT 存档，模型暂时保留 `enrollment_profiles` 的废弃
decoder-only 字段；它不参与校验、UI、邀请创建或 claim，不能让旧加入码重新生效。

连接方向也不是角色。在 v1 兼容模型中，`reverse_only` 表示该 Linux Device 主动建立并维持
反向 WireGuard 隧道，适用于无公网入站或受限网络；`bidirectional` / `direct_only` 沿用现有方向矩阵。
目标 v2 将发起方向和允许 transport 放到每条 LinkIntent：WG 是稳定 L3/control overlay 的首个实现，
HY2 可承担符合发起/可达条件的数据转发 hop，不把全节点永久定性为某种 tunnel。
旧 v1 部署可把境外节点设为 `reverse_only`，但这只是迁移输入；位置不决定方向，境外节点也不被底层模型禁止
承担 `use_loom`、`forward` 或 `internet_egress`。

## 通用包与设备配置分开

### 公开通用包

每个公网 Nginx 只允许提供 fake website 和内容寻址的静态 distribution：版本化客户端包/
安装脚本、manifest、checksum、签名、公开验证材料、bootstrap catalog bundle 和不含秘密的
兼容性元数据。Nginx 不接收、终止或代理 Enrollment。加入 token、Device identity、证书、秘密、设备配置、
全局拓扑和运行证据不得进入 GitHub 或公开镜像。

包地址来自实际部署配置，代码不硬编码域名、IP、节点或供应商。Create Device / 加入网络
页面为 access-only 生成二维码/加入文件，为 Linux 生成本地或 SSH 辅助的 bootstrap；二者
内部都消费一次性 URI。安装命令只下载公开通用包，加入 secret 不成为公开包 URL 的一部分。

### v1 首次配置分发契约（迁移基线）

v1 的 `readyBootstrap()` / Enrollment 分发适配器只有满足以下规则，才可作为 v2 迁移输入；
是否满足须核对相关[部署与验收记录](../operations/local-deployment.md)：

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

### 目标设备配置通道

v1 使用公开的全局 signed distribution 作为迁移输入。目标态由私有
`ControlServiceDirectoryV1` 中 `role=device_config` 的服务返回本 Device 的最小
signed view；`control_api`、`enroll`、`device_config` 和 `device_report` 都是该私有目录的分用途
role，只经 Loom overlay IP 可达。稳态 Device 使用独立客户端证书 mTLS，内部服务器证书按用途隔离。
`DistributionEndpointSetV1`、`BootstrapIngressEndpointSetV1` 和 `DataIngressEndpointSetV2` 才是公网对象，
三者也不能互相推导。ControlSet replication QC 证明内容已由 Raft 提交并被当前
quorum 复算；传输身份、Device 身份与内容 authority 不能互相替代。v1 URL 和 current
envelope 在兼容期只作为显式 legacy reader 输入。

## 版本化对象图

### 对象关系

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

### Recovery lineage、三个版本轴与 protocol latch

界面和持久化必须区分以下坐标：

| 坐标 | 表达什么 |
|---|---|
| Recovery epoch / statement / policy hash | 当前受信恢复 lineage；灾难恢复和计划轮换分别认证 |
| Control epoch | 同一 recovery lineage 内的成员历史 |
| Control revision / head hash | 已提交并取得 QC 的精确控制状态 |
| Device generation / leaf / view hash | 本设备配置语义，独立于无关控制提交递增 |

这些坐标分别比较，不能用一个较大的数字覆盖其他维度的回退或分叉。
精确 floor、Device leaf、transition 和不可逆 v2 latch 由[签名发布协议](../protocols/control-plane/publication.md)定义。
v1 的 raw SSOT revision、snapshot ID 和全局 release generation 不能改名冒充上述坐标。

### 最小 per-device signed view

目标 View 只允许包含本 Device 执行职责和 grants 所必需的内容：

- 本设备身份绑定、组件约束与本地入口；
- 获授权的 Service/Policy 结果和出口集合；
- 实际候选路径需要的最小 peer endpoint 与凭据引用；
- envelope 中的 recovery/Control checkpoint、Control revision、Device generation、head QC、
  leaf + inclusion proof、transition proof 和按用途拆分且带 transport pin 的 EndpointSet。

禁止包含无关 Device 清单、完整拓扑、其他设备凭据/配置、未授权 Service、加入凭据或
全网运行观测。Device 可以看到它实际需要连接或被授权选择的节点，不能枚举全网。

## 依赖驱动发布

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

## 迁移与产品验收

协议接管顺序和完成条件统一见[控制面迁移](../protocols/control-plane/migration.md)，
认证、重试、恢复和轮换按[协议验收矩阵](../protocols/control-plane/acceptance.md)执行。
这里仅补充产品投影，避免维护第二套阶段计划。

### v1 存量输入

- 以稳定 `device_id` 合并 Client registry、SSOT Node 和可信运行证据；既有节点只按受信证书
  迁移，缺失 identity 显式标为 not indexed，不能按名称、主机名或 IP 猜测归属。
- v1 的 compatibility storage、SSOT 投影、签名/pull 和全局 snapshot/release generation
  只作为受验证的迁移输入。全局 generation 不能在 UI/API 中改名为 Device generation。
- [v1 首次配置分发契约](#v1-首次配置分发契约迁移基线)解释存量发布证据及地址选择；
  它不要求为 v2 新建或恢复公开 claim、旧命名入口或单控制节点 authority。

### 统一产品动作

- API、Review 和 UI 分开显示 Identity、Membership、Responsibilities 与 Destination grants；
  “在此设备上使用 Loom”只说明本机流量接管，不隐含全部 Service 权限。
- Create Device 建立唯一设备记录与一次性邀请；客户端导入只绑定该 Device。管理员选定的平台
  必须与客户端报告一致，服务器与客户端使用同一私有 claim 协议。
- 公开包只含通用程序、签名和校验材料。设备页面按职责提供二维码、文件或 Linux shell
  bootstrap；SSH 只帮助操作者运行同一脚本，不构成另一套加入协议。
- 删除 `/nodes/add` SSH 加入入口与被替换的 `/clients` 命名、兼容存储和调用路径；
  拓扑中的节点只是 Device 职责的投影，不能产生第二份设备身份。
- 每个在用平台从创建 Device、安装、claim、首次配置、激活到可信 online 取得相关正常流程
  证据。`ready`、`published`、`applied`、`online` 分别显示；平台实机范围按当前任务及平台规程执行。

## 后续仍需单独决定

只有以下实现选择尚未确定：

1. 通用包实际使用哪些 GitHub/国内镜像及同步、保留和故障切换方式；
2. 首批 DNS provider/托管 zone、provider credential 的保管方式及自动购买/续费审批边界；
3. 离线 recovery root 的持有人、门槛、演练周期与带外重锚流程；
4. v1/v2 双发的最长兼容窗口，以及哪些最低客户端版本允许 retire 旧入口；
5. 已加入 Device 的职责与 grants 是否需要批量变更 UI；这属于显式配置变更，不改变加入协议。

route broker 当前明确不做；Local Network 按独立专题推进，不在本计划重复讨论。

## 产品完成条件

- 任意新设备只有一个 Device ID、一个 Enrollment 生命周期和一份状态解释。
- 加入设备不隐式获得全部当前及未来 Service 的权限。
- 公开包不含加入码、凭据、设备配置或拓扑；更换部署域名或镜像无需修改代码。
- 同一 Control revision 可对应不同 Device generation，未受影响设备不更新。
- 客户端只取得本机必需的配置与节点信息，版本、配置与实际运行状态分别展示。
- 迁移保留原身份与数据；v2 latch 后不得回退到 v1 authority，故障按认证恢复流程处理。
- 界面不得把已批准目标显示为已上线能力；业务验收必须满足上述协议矩阵及本产品条件。
