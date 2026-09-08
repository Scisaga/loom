# Device 生命周期、Enrollment 与交付架构

> **状态：** 已确认的目标模型，分阶段迁移；不是当前生产能力说明。  
> **范围：** Device 统一、Enrollment、授权边界、版本化对象图、设备配置交付。  
> **当前事实：** 以 [当前状态](status/current.md) 为准；平台客户端细节见
> [客户端接入设计](client-access.md)，局域网转发仍是独立的
> [Local Network 专题](local-network.md)。
>
> 本文的 **Enrollment** 只指内部的一次性身份 claim 协议。产品界面统一使用
> **Create Device / 加入网络**：中控先创建 Device；纯接入客户端可导入二维码，Linux
> 也可通过本地或 SSH 会话执行 shell bootstrap。消费加入输入不会再创建或“注册”第二个 Device。

### 2026-09-01 E1 实施状态（已完成）

本轮已经完成并通过仓库测试的部分：统一 `/devices` 读模型与详情、规范
`/api/control/devices`、删除旧 `/nodes/add` SSH 入口、收口旧 `/clients` 别名、四分授权展示、加入码固定
平台、职责和 Destination grants、公开通用 Linux 包/校验附件/
安装脚本，以及首次 pull 对每个配置 URL 记录精确发布证据并 fail closed。公开地址只读
部署配置，代码不含部署域名。

统一读模型与公开分发边界最初以提交 `01a16dd172fd` 发布；服务器职责 Enrollment 的
后续实现已于同日以提交 `37f86a3977d2` 发布。E1 的最终回收与 access-only 修复以提交
`0c29455218c3` 发布。六台现有 Device 已运行同一 Device 版本，并由 signed release
持续收敛；两个配置镜像对同一 SSOT/snapshot 的逐 URL 验证均成功。
公开 HTTPS 前门的安装脚本、checksum、
detached signature、平台公钥和 allowlist 的 404/拒绝写边界均已实测；Linux 包 SHA256
为 `7a89edb59023c3eeb8bc685a26d56849c31c470548319ea33bdf82969473dab8`。部署域名和路径
属于本次部署配置，不是产品默认值。

E1 的服务器职责现在也走同一 Enrollment：管理员创建时直接固定 Linux 平台、职责和连接方向；Linux Device
从严格的 `/etc/loom/device.yaml` 读取公网 endpoint、UDP inbound 与 direction，在本机
创建/复用 WireGuard 私钥且只提交公钥。中控以同一个事务生成 server/access 角色、方向
矩阵隧道、固定出口策略与全量自动池增量，先生成和预置秘密，最后才提交 SSOT。自动池
扩大导致原探测预算无法满足 `min_samples` 时，规划器只增加维持既有窗口所需的最小预算。
配置应用后的公网入站仍复用已有签名拓扑观测，不另造一次“拨入验证”。服务器缺少
wireguard-tools 时，在 invitation claim 前使用已有受限包管理器流程安装并复检。

access-only Device 已具备完整回收：先通过 signed SSOT 明确 decommission，目标机停止并
禁用 Agent、Report、sing-box 与 pull timer、落下 marker 后，才允许从期望态移除并 revoke
identity；全网收敛后可按 Device ID 精确清 master/node secrets，并永久清理 revoked registry
记录。未使用加入码仍使用更窄的 `discard-pending`，只允许删除没有公钥、没有 consumed
join code、从未进入 claim 的 identity reservation。

真实 Docker systemd canary `d-89e16d6daa` 已完成公开 HTTPS 下载与 checksum、一次性加入码
claim、P-256 identity、SSOT 提交、generation 66/67 signed pull、首次 apply、3 个自动选择器
运行和 `/status` 可信 200/verified。canary 随后消费 generation 69 的 signed decommission，
验证 marker、`applied` 移除及四类 unit inactive/disabled，再从 SSOT、九项 master secret、
六份 node secret layer、registry 与容器中完整清除；registry 最终恢复为 6 个正式 Device、
0 个加入码。过程中实际发现并修复了三条既有边界：OpenSSL `EC PARAMETERS + EC PRIVATE KEY`
CA 文件、无隧道 Device 不应执行 `wg show`、无 WG unit 的下线发现不能把 systemd 的
“无匹配”当成查询失败。旧 SSH Add node 入口及对应实现现已删除。

六台既有 Device 的统一 identity registry 迁移不重新 Enrollment，也不根据名称、hostname
或 IP 猜身份：导入命令要求 Device 当前存在于 SSOT，证书链通过 Loom CA，CN 与唯一 SAN
都精确等于 `<device_id>.node.internal`，且公钥为 ECDSA P-256。迁移后 UI 将其来源显示为
`Verified existing certificate`；这描述身份来源，不是软件版本或“未升级”状态。

## 1. 收敛结论

产品模型只保留一种受管实体：**Device**。服务器、桌面和手机的差别是平台事实与
承担的职责，不再是 `Node` / `Client` 两套生命周期。

所有新 Device 使用同一条 **Enrollment** 内部协议：管理员先在中控创建 Device 和
一次性加入码，客户端安装并启动通用包后导入加入输入，再自行生成身份并 claim 这个
既有 Device。纯 `use_loom` Device 可用二维码、内部兼容 `loom://enroll` URI 或加入文件；
包含 `forward` 的 Linux Device 只通过本地/SSH 会话执行 shell bootstrap，并从标准输入
消费同一 URI。服务器安装命令只获取通用包，本身不携带加入码。

权限不再用“网络权限”或笼统的 Access 表达，而拆成四个问题：

1. **Identity**：这是谁，持有什么设备密钥；
2. **Membership**：它是否属于当前 Loom；
3. **Responsibilities**：它为 Loom 承担什么，例如在本机使用 Loom、转发、作为公网出口或中控；
4. **Destination grants**：它获准通过 Loom 访问哪些 Service、出口或后续 Local Network。

版本采用两个轴：全局 **Control revision** 记录一次不可变期望对象图；独立
**Device generation** 只在该 Device 的有效配置变化时递增。加入一个 Device 不应
使所有既有 Device 的 generation 一起变化。

## 2. 已确认决策及实施归属

| 决策 | 本次 Device / Enrollment 修改 | 后续工作 |
|---|---|---|
| 统一 Device | 建立统一 ID、库存读模型与 `/devices` 添加入口；删除 `/nodes/add` 产品入口 | 删除剩余旧 `/clients` 命名与兼容存储 |
| 统一 Enrollment | 中控 Create Device 和加入码 → 客户端启动并消费加入输入 → 本机密钥 → claim 既有 Device；Linux 可本地或经 SSH 会话运行同一 bootstrap | 无第二套 SSH 加入协议 |
| 四分授权模型 | API、Review 和 UI 分开显示 Identity / Membership / Responsibilities / Destination grants | 复杂授权治理另议，不引入 ABAC 或动态组 |
| “Access”文案 | 改为“在此设备上使用 Loom”，明确只表示本机流量可交给 Loom | 无 |
| 直接固定加入意图 | 创建时直接选择平台、职责、grants 和必要的连接方向；不引入 Device 类型或 Profile 层 | 已加入 Device 的职责变更另走显式配置变更，不复用加入码 |
| 公开通用包 | GitHub 或实际部署配置中的国内/公网镜像只放通用包、签名和校验材料 | 具体镜像供应商、域名和同步运维按部署决定 |
| HTTPS 前门与 Device mTLS | 本次只区分公开包地址和设备配置地址，不宣称尚不存在的 mTLS | 与证书轮换、吊销一起实施独立的私有 Device Distribution |
| 最小 per-device signed view | 本次固定渲染契约和禁止暴露项，不把现有 bundle 冒充最小视图 | 改造签名、pull、缓存与旧快照迁移 |
| Control revision / Device generation | 本次固定语义和对象关系，不复用现有同名但语义不同的版本号 | 随 per-device view 一起切换协议和 anti-rollback floor |
| 依赖增量发布 | 渲染契约必须返回依赖集合；当前仍可全量计算 | 后续 publisher 只发布 view digest 真正变化的 Device，并做千台压测 |
| 不引入 route broker | 本次即作为 API/UI 负向约束 | 只有出现实测规模或隐私瓶颈才重新评估 |

这里的“后续工作”不是推翻已确认方向。per-device view、双版本轴和增量发布必须作为
一个有迁移与回滚的协议改造实施，不能夹进 Create Device / 加入网络页面或 URL 筛选中零散上线。

## 3. 单一 Device 模型

统一产品实体不等于把所有数据塞进一张表。身份、期望态和运行证据仍按安全边界分开，
通过稳定 `device_id` 组成一个 Device：

```text
Device
├── Identity              稳定 ID、公钥/证书、创建与吊销状态
├── Membership            是否进入某个 Control revision
├── Responsibilities      use_loom / forward / internet_egress / control / ...
├── Destination grants    获准使用的 Service、出口、后续 Local Network
├── Desired view          control_revision + device_generation + digest
└── Runtime evidence      applied / online / stale；带时间，不写回期望态
```

当前 `clientregistry.Client` 与 `model.Node` 是两张表按相同 ID 拼出的过渡状态。迁移期
可以保留底层适配器，但 API、UI 和新代码只能暴露 Device。SSOT 中尚无 registry identity
的机器显示为 `Identity not indexed`；既有节点只能用受信 CA 证书的精确 Device SAN 导入，
不能根据名称、hostname 或 IP 猜身份。`identity_source` 只区分二维码加入与受信的
既有证书，不承担软件版本、在线状态或职责语义。

拓扑仍然存在，但拓扑中的点是承担转发/出口职责的 Device 投影，不再是另一类实体。

## 4. 统一 Enrollment

### 4.1 一条协议，多种载体

```text
管理员在中控创建 Device 和加入码
  → access-only 可显示 QR；Linux 可用本地或 SSH 会话执行同一 bootstrap
  → 内部兼容 loom://enroll URI / .loom-invite 携带同一加入码
客户端安装并启动通用包
  → 导入上述加入输入
  → 本机检测平台与架构，并与邀请固定的平台比较
  → 本机生成不可导出的设备密钥和 CSR
  → 内部 claim 加入码并绑定这个既有 Device
  → 建立 Identity
  → 原子提交邀请已经固定的 Membership / Responsibilities / grants / direction
  → 发布该 Device 的有效期望态
  → 返回可信 bootstrap，首次 pull、验签、安装、上报
```

- 管理员创建时选择平台；客户端仍报告本机平台，服务端要求它与邀请精确一致。
- 当前 Windows 只允许 `use_loom`；Linux 可组合 `use_loom`、`forward` 和
  `internet_egress`。`internet_egress` 必须包含 `forward`，只有 `use_loom` 才能携带
  Destination grants。Android 属于统一 Device 模型，但当前交付尚未实现，因此不能创建邀请。
- claim 建立 Identity；只有 Enrollment 事务成功提交展开后的 Membership、
  Responsibilities 与 grants，Device 才获得对应期望态。两者都不等于已经 online。
- 一次性码的 TTL 限制首次绑定。绑定后只允许同一 token、CSR、request ID、平台和
  Device facts 在一小时恢复窗口内重放；当前 Windows Portable 预览仅在未完成期间用
  当前用户 DPAPI 保存 pending token，并在 joined 完成标记提交后清除。
- 加入码不能创建 identity-only Device；平台、Responsibilities、Destination grants 和
  `forward` 所需的 direction 在创建时直接固定，提交前必须展示。
- 重连、升级、网络切换和重启使用既有身份，不重新 Enrollment。
- 服务器不依赖中控 SSH push 作为安装或加入模型。`get.docker.com` 式脚本只负责获取
  通用包，随后仍导入同一加入码；管理员可以先 SSH 到目标机执行同一脚本，但中控不保存
  SSH 凭据，也不存在第二套 SSH Enrollment。

### 4.1.1 二维码重发与本机身份丢失

未领取的身份预留可在 Device 详情页重新生成加入码。名称、ID、平台、职责、grants 和
direction 保持原值；每次重发都会让旧加入码失效。纯 `use_loom` Device 可重新显示二维码；
点击二维码复制同一份一次性加入 URI，不触发图片下载；加入文件仍有单独下载按钮。
包含 `forward` 的 Linux Device 仍只展示 shell/SSH 辅助交付，不展示 QR。

Windows 的“删除本机 Device”会清除本机身份和配置，不通知中控，也不自动撤销网络
中的凭据。管理员确认本机身份已删除后，可对 Enrollment 生成的纯 `use_loom` Device
使用“Rejoin Device”。中控移除旧成员及其专属凭据、将旧身份归档，并分配新 ID 与
新二维码；名称、平台和原职责/授权保持不变。旧证书属于旧 ID，不能
用于领取新身份。归档记录保留 `replaced_by`，新记录保留 `replaces`。

如果不需要替换设备，同一详情页提供单步 **Remove Device**。它不等待客户端回执：中控
立即从 SSOT 移除纯 `use_loom` Device 及其设备专属凭据，并把 enrollment identity 标为
revoked；服务器应用下一份签名配置后不再接受旧数据面凭据。该操作不会远程删除客户端
本机文件，也不会把未收到停机通知误报成“已停机”。未领取 Device 仍使用更窄的
**Delete Device**，只删除从未消费的 identity reservation 和加入码。

转发服务器应用新的签名配置后，旧数据面访问凭据才失效。该流程不证明旧客户端执行过
signed decommission，也不代替服务器/隧道节点的退休迁移或通用证书吊销机制。
仅有“本机删除”时，中控保留现有记录且不能猜测在线；完成中控替换后，旧身份从当前
列表移入 Archived devices。SSOT 撤销后若 registry 落盘失败，不返回二维码，重试可
继续完成归档与新身份分配；不会恢复旧接入。

设备列表直接提供 **Pause / Resume**，只对当前职责恰好为 `use_loom`、已加入且未下线的
Device 开放，包含 `forward`、`internet_egress` 或 `control` 的设备不能使用此快捷操作。
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

- `platform`：当前可创建 `windows-desktop` 或 `linux-server`；
- `responsibilities`：`use_loom` / `forward` / `internet_egress` 的合法组合；
- `destination_grants`：仅在选择 `use_loom` 时非空；
- `direction`：仅在选择 `forward` 时必填。

客户端 claim 只提交身份与实际服务器声明，不能选择或扩张这些授权。registry 直接字段就是
事务事实，不再额外增加无密钥 digest 或签名层。旧 schema 1 邀请全部失效：迁移只保留已经
加入的 identity 及其具体职责，丢弃旧邀请和未完成的 pending/provisioning 记录；管理员必须
按新模型重新创建未加入 Device。这是一次单向迁移，不兼容旧邀请。

为保证中控仍能读取并回滚既有 SSOT 存档，模型暂时保留 `enrollment_profiles` 的废弃
decoder-only 字段；它不参与校验、UI、邀请创建或 claim，不能让旧加入码重新生效。

连接方向也不是角色。`reverse_only` 表示该 Linux Device 主动建立并维持反向 WireGuard
隧道，适用于无公网入站或受限网络；`bidirectional` / `direct_only` 沿用现有方向矩阵。
当前部署可把境外节点设为 `reverse_only`，但位置不决定方向，境外节点也不被底层模型禁止
承担 `use_loom`、`forward` 或 `internet_egress`。

## 5. 通用包与设备配置分开

### 5.1 公开通用包

公开渠道只允许发布版本化客户端包/安装脚本、manifest、checksum、签名、公开验证
材料和不含秘密的兼容性元数据。加入 token、Device identity、证书、秘密、设备配置、
全局拓扑和运行证据不得进入 GitHub 或公开镜像。

包地址来自实际部署配置，代码不硬编码域名、IP、节点或供应商。Create Device / 加入网络
页面为 access-only 生成二维码/加入文件，为 Linux 生成本地或 SSH 辅助的 bootstrap；二者
内部都消费一次性 URI。安装命令只下载公开通用包，加入 secret 不成为公开包 URL 的一部分。

### 5.2 E1 首次配置分发

E1 之前，`readyBootstrap()` 直接返回 `SSOT.DistributionURLsFor(node)`，可能把加入前
可达的公网地址与接入后才能访问的 WireGuard 私网地址混在一起。E1 已按以下规则修复：

1. Enrollment 候选只来自当前部署的 `defaults.distribution_urls`，顺序表达运维偏好；
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

E1 已覆盖：更换部署地址无需改代码、私网/重复/非法 URL 排除、snapshot 不一致排除、
首选不可达时客户端使用备用地址、无候选 fail closed，以及日志不泄露加入码和密钥。

### 5.3 目标设备配置通道

E1 仍使用公开的全局 signed distribution 作为过渡。目标态由经过认证的
`device_config` endpoint 返回本 Device 的最小 signed view；独立 HTTPS 前门和 Device
mTLS 在 E3 一起实施。签名证明内容，TLS/mTLS 负责传输与访问控制，不能互相替代。

## 6. 版本化对象图

### 6.1 对象关系

```text
EnrollmentTransaction (短期、单次)
        │ 固定 platform / responsibilities / grants / direction
        │ claim
        ▼
DeviceIdentity (稳定)
        │
        ├── MembershipVersion
        ├── ResponsibilitySetVersion
        └── DestinationGrantVersion refs

上述不可变对象的根 ──> ControlRevision

Materialize(ControlRevision, DeviceID)
        └── DeviceView bytes + digest + dependency refs
                └── 内容变化时 DeviceGeneration + 1
```

RuntimeEvidence 独立进入观察投影，不参与 Control revision，也不因一次上报触发发布。

### 6.2 两个版本轴

**Control revision**

- 标识一次已接受的全局期望对象图；
- 用于审计、并发提交、影响分析和复现；
- 是规范化对象图的 revision，不等于当前 raw YAML bytes 的编辑摘要；
- 不直接作为设备 anti-rollback 序号。

**Device generation**

- 对每个 Device 独立、单调递增；
- 只有 materialized DeviceView 的语义内容变化时才递增；
- 与 `device_id`、view digest、来源 Control revision 一起签名；
- 客户端只持久化自己的 generation floor。

当前代码中的 raw SSOT revision、snapshot ID 和全局 signed release generation 是三个
现行坐标，迁移期间都不能改名冒充上述目标字段。

### 6.3 最小 per-device signed view

目标 View 只允许包含本 Device 执行职责和 grants 所必需的内容：

- 本设备身份绑定、组件约束与本地入口；
- 获授权的 Service/Policy 结果和出口集合；
- 实际候选路径需要的最小 peer endpoint 与凭据引用；
- Device generation、Control revision、digest 和签名元数据。

禁止包含无关 Device 清单、完整拓扑、其他设备凭据/配置、未授权 Service、加入凭据或
全网运行观测。Device 可以看到它实际需要连接或被授权选择的节点，不能枚举全网。

## 7. 依赖驱动发布

渲染器应是纯函数，并同时返回 View 和依赖集合：

```text
RenderDeviceView(control_revision, device_id)
    -> bytes, digest, dependency_refs
```

Control revision 变化后，以 View digest 是否变化作为最终影响判据：

- 新增普通 Device：只产生新 Device 的 generation；
- 修改某个 Service grant：只更新引用它的 Device；
- 修改共享出口或凭据：更新依赖该对象的 Device；
- 仅修改显示名且不进入运行 View：不增加 Device generation。

第一版可以对全部 Device 重新计算 digest；1000 台规模下这比先建复杂调度系统更可靠。
确认结果后只签名和发布变化的 Device。依赖索引是性能优化，不能成为正确性来源。

## 8. 分阶段迁移

### E1（已完成）：统一入口与安全交付边界

实际按以下顺序完成，未并行切换签名协议：

1. **统一 Device 读模型：** 以稳定 `device_id` 合并 Client registry、SSOT Node 和可信
   runtime evidence；新增 `/devices` 列表/详情，缺失 identity 明确标为 not indexed，
   既有节点只按受信证书迁移；
2. **统一授权语义：** API、Review 和 UI 使用 Identity / Membership /
   Responsibilities / Destination grants；“Access”改为“在此设备上使用 Loom”；
3. **统一加入网络：** Create Device 先建立唯一设备记录并生成一种一次性加入码；服务器、
   Windows 和 Linux 共用底层 claim，管理员先选平台，客户端报告必须一致；客户端启动后
   导入加入输入，只绑定这个既有 Device；Android 等待客户端交付；删除 SSH Add node 入口；
4. **直接固定加入意图：** 创建时直接选择 Responsibilities、必要的 Destination grants 与
   `forward` direction；不新增 Device 类型或 Profile 管理页，不允许 identity-only 邀请；
5. **公开通用包：** 生成带签名/校验的通用包和服务器安装脚本，发布到部署配置声明的
   公开源；Device 页面按职责给出 access-only QR/文件，或 Linux shell/SSH 辅助安装方法；
6. **修复首次 pull：** 落地 §5.2 的逐 URL 发布证据与选择函数，替换
   `readyBootstrap()` 在 E1 前直接继承节点地址的行为；
7. **收口旧入口：** `/nodes/add` 及其 SSH 实现已删除；旧 `/clients` 仍只作命名别名，
   后续删除该别名和兼容存储；拓扑中的 Nodes 只保留 Device 的职责投影；
8. **真实 Linux canary：** 从创建 Device 和加入码、安装、内部 claim、首次 pull、apply
   到可信 online 全链验收，再发布 E1；Windows/Android 宿主在该基线之后分别开发。

上述 1–8 已完成并上线。E1 仍保留兼容存储与全局 snapshot 协议；它们分别在 E2/E3
迁移，不能因为入口已统一就误称 per-device generation 或私有 Device view 已经实现。

E1 保持当前签名/pull 协议，并通过兼容投影写入现有 SSOT，避免同时切换全部故障域。

E1 仍会触发现有全局 snapshot/release generation，这是明确的迁移债务。UI 和 API
不得把它标成 Device generation，也不得宣称已经实现最小私有 view 或增量发布。

### E2：已确定方向的协议迁移

1. 引入规范化版本对象图和 Control revision；
2. 实现确定性的 per-device view、digest 与独立 Device generation；
3. 双写/双读验证后，将客户端从全局 snapshot 迁到 per-device signed view；
4. 根据 view digest 只发布真正变化的 Device；
5. 完成旧 generation floor、回滚、吊销和公开快照撤除的迁移测试。

### E3：私有 Device Distribution

1. 部署配置声明独立 HTTPS `device_config` endpoint；
2. 启用 Device mTLS、证书轮换与吊销；
3. 公开渠道最终只保留通用包；
4. 从境内外真实网络验收可达性、故障切换与隐私边界。

## 9. 后续仍需单独决定

只有以下实现选择尚未确定：

1. 通用包实际使用哪些 GitHub/国内镜像及同步、保留和故障切换方式；
2. Device mTLS 前门的部署位置、证书生命周期和高可用方式；
3. 已加入 Device 的职责与 grants 是否需要批量变更 UI；这属于显式配置变更，不改变加入协议。

route broker 当前明确不做；Local Network 按独立专题推进，不在本计划重复讨论。

## 10. 验收总原则

- 任意新设备只有一个 Device ID、一个 Enrollment 生命周期和一份状态解释；
- 加入设备不再隐式获得“全部当前及未来 Service”的权限；
- 公开包中找不到加入码、凭据、设备配置或拓扑；
- 更换部署域名或镜像不需要修改代码；
- 同一 Control revision 可对应不同 Device generation，未受影响设备不更新；
- 客户端只能获得本设备实际需要的配置与节点信息；
- `ready`、`published`、`applied`、`online` 始终是不同状态；
- 任何迁移阶段都能回退，且不能把目标态文案冒充当前已上线能力。
