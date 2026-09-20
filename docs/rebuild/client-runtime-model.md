# 客户端运行时最小模型

本文定义重建后的 Android / Linux / Windows 客户端运行时模型。它是实现、持久化、wire、
运行时和 UI 的共同契约；读者不需要阅读代码才能判断一个行为是否符合设计。

这里的“同构”不是要求各层拥有相同结构体，而是要求同一个事实只有一个来源，
各层使用稳定标识保持其身份和语义。安全脱敏与纯派生允许字段变少，但不得在另一层
制造第二份可独立修改的事实。

本文只使用八个核心概念。它们是职责边界，**不要求一个概念对应一个类型、表或服务**；
能够用值、纯函数或现有安全存储表达时，不新增实体。

## 八个概念

| 概念 | 唯一职责 | 不是 |
|---|---|---|
| `DeviceIdentity` | 标识设备、保存已加入网络的信任绑定与不可回退 floor，并对私有请求签名 | 路由状态、网络测量或服务端拓扑副本 |
| `CertifiedLKG` | 最近一次验证通过、可离线继续使用的认证设备视图 | 当前网络是否可用的声明 |
| `RouteCandidate` | 描述从本机到目标的一条允许路径及其最终出口 | 节点类型、健康状态或平台进程 |
| `RuntimeCandidate` | 将一条 `RouteCandidate` 化为宿主可执行且可稳定识别的运行描述 | 第二份拓扑、独立配置源或健康注册表 |
| `Observation` | 记录特定底层网络代中实际 transport / business outcome 及有限提示 | 授权、期望状态或为了填满评分而生成的样本 |
| `Preference` | 表达 Direct、Auto 或指定最终出口的用户意图 | 对当前可用性的断言 |
| `Selection` | 记录宿主 selector 回读确认的当前实际选择 | 仅由决策函数算出的期望值 |
| `HostAdapter` | 连接纯核心与 Android / Linux / Windows 的安全存储、VPN、transport 和 selector | 平台各自实现的一套选路规则 |

八者的关系只有一条主线：

```text
DeviceIdentity 绑定 CertifiedLKG
        │
        └─→ 纯函数派生 RouteCandidate
                    │
                    └─→ 纯函数生成 RuntimeCandidate
                                  │
Preference + Observation ────────┴─→ 纯函数提出候选
                                              │
                                      HostAdapter 应用并回读
                                              │
                                          Selection
```

`CertifiedLKG` 决定“允许做什么”，`Observation` 说明“此刻实际发生了什么”，
`Preference` 说明“用户想要什么”。三者不得互相代替。

## 路径语义

### Direct 不等于一跳直达

- **Direct** 的服务器链为空：本机不经过任何受管服务器，直接访问目标地址。
- **一跳直达** 的服务器链包含一台服务器：客户端通过该服务器公开的数据入口接入，
  这台服务器同时位于路径末端，因此是这条路径的最终出口。
- **中继路径** 至少包含两台服务器：客户端先接入境内服务器，再经既有 WireGuard
  链路到最终出口。

因此，以下是三条不同的 `RouteCandidate`：

```text
Direct:                    device → target
一跳直达 demo-sv:          device → demo-sv → target
同出口中继 demo-sv:        device → demo-cn → demo-sv → target
```

后两条拥有相同的最终出口，但拥有不同的入口和服务器链。它们必须同时保留为候选，
使“一跳直达失败后仍从同一最终出口经境内中继访问”成为普通选路结果，而不是专用分支。

`public_data_ingress` 只表示控制面**授权并提供了**客户端直连该服务器的数据入口，
所以它允许产生一跳直达候选；它绝不表示该入口在当前网络可达。入口可能今天可用、
随后因 UDP 受限而不可用、几天后再次恢复，整个过程都不需要修改认证拓扑。

`reverse_only` 只约束服务器间 WireGuard 的发起方向，也不能据此删除服务器的
公开数据入口候选。授权、隧道方向和实时可达性是三个不同事实。

### 候选身份

`RouteCandidate` 的稳定身份由规范化后的服务器链、最终出口和服务范围确定；
`RuntimeCandidate` 保留这个身份，并补充实际 transport、入口和宿主执行所需引用。
相同路径在 Android、Linux 与 Windows 上必须对应相同的路径身份，即使三个平台生成的底层
配置文本不同。

候选顺序不构成身份。所有派生结果必须确定性排序，不能依赖 map 遍历、时钟或随机数。

客户端 `DeviceView` 还携带一份规范 `RuntimeProfile` 值。它不是新的领域实体，
而是把该 view 已授权的候选投影成宿主可执行配置所需的私有材料：`kind` 固定为 `sing_box`，`config`
是规范 JSON。每条 `RouteCandidate.ID` 必须逐一对应 config 中同名 outbound，`RouteCandidate.Scope`
必须对应包含该 outbound 的 selector；config 不得增加 view 未授权的 selector 成员。服务器把
`RuntimeProfile` 与 route authorization 一起认证，客户端只从完整 LKG 解出它，不另取公开配置、
不拼接旧 bundle，也不把 hydrate 后副本持久成第二权威。

`RuntimeCandidate` 因而是纯投影：

```text
RuntimeCandidate = project(RouteCandidate, DeviceView.RuntimeProfile)
```

Android、Linux 与 Windows 可以把同一候选落成不同宿主进程参数，但候选 ID、scope、服务器链和最终出口保持
不变。若 profile 缺失、不是规范 JSON、候选映射不全或多出未授权成员，整个新 LKG 失败关闭；旧的
已运行 LKG 保持可用。

Windows 的 `RuntimeProfile` 不另设 wire 类型。服务端只接受 `platform=windows` 且带完整
`sing_box` profile 的 Enrollment 或设备更新；外层未知/缺失/多余字段、非规范 JSON、重复键、缺少候选、
多出未授权 selector 成员或候选 scope 映射不全均失败关闭，不能先接收再由 Windows 补默认值。Windows
HostAdapter 可以按交付形态投影本机 capture 配置，但不得增加、删除或重排被认证 selector 的候选语义。

## Observation 与可用性

每条 `Observation` 至少绑定：候选身份、底层网络代、观测范围、结果、可比较的实际指标
和有效期。
时间由调用方传入；纯核心不自行读取时钟。

对当前网络代，一个候选只有三种运行状态：

| 状态 | 含义 |
|---|---|
| `available` | 对该候选执行的真实 transport 建连或正常业务已经成功；成功范围必须如实保留 |
| `unavailable` | 对该候选执行的真实 transport 建连或正常业务已经失败，且结果仍有效 |
| `unknown` | 没有结果、结果属于其他网络代、已经过期、无效，或结果范围不足以证明可用 |

一次入口 transport 成功只能证明对应入口成功，不能伪装成未实际执行的端到端业务成功；
一次完整业务成功则可以证明当时整条候选可用。客户端可以复用认证的服务器段观测，
但不得为了把所有候选变绿而逐条扫描完整业务路径。

ICMP 结果只能作为地址 RTT 提示：

- ICMP 成功不能把候选改成 `available`；
- ICMP 失败不能把候选改成 `unavailable`；
- ICMP RTT 不能冒充 HY2、WireGuard 或业务端到端延迟。

同一底层网络代内，授权入口按稳定候选身份去重，并行且各至多发起一次必要的真实
transport 检查。这个约束由现有 `Observation` 的键和进行中状态自然表达，不新增
scheduler、probe budget 或一次性 registry。入口之后复用已有的有效服务器观测。

“至多一次”约束一个尚未过期的观测窗口，而不是允许进程永远重发启动时结果。当前实际选择的观测
到期后，adapter 可以做一次新的最小真实业务检查并产生下一条有限期 Observation；有效期内不得为刷新
计分重复采样。底层网络代或 selector 回读变化时立即失效相应旧结果并执行同一最小检查。

底层网络代变化后，上一代观测不再决定当前状态，候选先回到 `unknown`。启动和切网
都不得等待观测齐全；缺失观测保持未知，也不得通过补样本制造健康状态。

## Preference 与 Selection

`Preference` 只裁剪和排序授权候选：

| 模式 | 候选范围 |
|---|---|
| `Direct` | 仅服务器链为空的候选；不创建代理入口探测 |
| `Auto` | 所有由当前 `CertifiedLKG` 授权的候选 |
| 指定最终出口 | 所有最终出口相同的候选，包括一跳直达和境内中继 |

在范围内，已知可用候选优先于未知候选，已知不可用候选不参与新选择；多个可用候选按
`Preference` 指定的目标和同范围、仍有效的实际指标排序。不同观测范围的数字不能直接
比较，缺失指标不能补零。没有可用候选时，允许确定性地尝试未知候选，而不是等待测量。
没有更优的可比较证据时保持当前实际选择，避免无理由切换；排序是一次纯计算，不需要
挑战者状态、采样收敛或额外状态机。ICMP RTT 最多只能为同类入口提供次级提示，不能覆盖
真实 transport / business outcome。

指定 `demo-sv` 最终出口时，如果一跳直达候选被真实 transport 结果判定不可用，而
`demo-cn → demo-sv` 仍可尝试或已经可用，选择后者。最终出口没有改变，改变的只是路径。
如果以后真实结果再次证明一跳直达可用，它会正常重新进入候选集，无需修改 SSOT。

纯核心的输出只是“应尝试的候选”。`HostAdapter` 应用它之后必须读取宿主 selector；
只有回读确认成功，才能产生新的 `Selection`。应用失败时，UI 和报告继续显示回读到的
旧选择或“无实际选择”，不得把意图显示成运行事实。

## 跨层同构

下表完整规定八个概念在 domain、wire、persistent、runtime 和 UI 中的对应关系。
“派生”表示该层不得另存一份可写副本；“无”表示该概念不需要出现在该层。

| 概念 | Domain（语义） | Wire（跨进程） | Persistent（重启后） | Runtime（当前进程） | UI（用户可见） |
|---|---|---|---|---|---|
| `DeviceIdentity` | 设备标识、信任绑定、公钥、签名职责和 floor | 只发送标识、公钥及签名证明；不发送私钥 | 私钥、信任绑定进入平台安全存储，标识与 floor 原子保存 | 提供验签边界与签名能力，不参与排序 | 加入状态与公开标识摘要；永不显示秘密 |
| `CertifiedLKG` | 最近一次验证成功的认证设备视图 | 规范字节、签名、版本与 floor | 原封不动原子保存，旧值仅在新值验证并落盘后替换 | 解析为只读输入 | 显示版本、认证状态和是否陈旧，不宣称网络可用 |
| `RouteCandidate` | 允许路径、服务器链、最终出口和服务范围 | 不单独传输；由认证设备视图中的授权事实派生 | 不持久化 | 每次从 LKG 纯函数重建 | 显示 Direct / 服务器链 / 最终出口 |
| `RuntimeCandidate` | 路径的可执行投影及稳定身份 | 不单独传输；所需入口材料来自私有认证配置 | 不持久化独立副本 | 供 adapter 实例化 transport / outbound | 通常只显示协议和入口类别，不暴露秘密参数 |
| `Observation` | 某网络代、某候选、某范围的实际结果 | 可通过私有认证报告上传或读取；保留来源与范围 | 不作为配置权威；可留诊断历史，但恢复时不得直接当作当前结果 | 当前网络代的有限集合 | 显示 available / unavailable / unknown、范围与陈旧状态 |
| `Preference` | Direct、Auto 或指定最终出口 | 如需跨设备同步，只能走私有认证配置；没有同步需求时无 wire | 只保存一份本机用户设置 | 作为纯选择函数输入 | 唯一可编辑的选路意图 |
| `Selection` | selector 回读确认的实际候选 | 可通过私有认证状态报告上送 | 不作为下次启动的权威；事件可供诊断 | 当前实际候选及回读时间 | 与 Preference 分栏显示，明确“当前实际路径” |
| `HostAdapter` | 平台能力边界 | 无独立 wire 对象 | 只使用平台既有安全存储与服务配置 | 执行 load、apply、readback 和真实 outcome 采集 | 提供能力/错误，不提供第二套选路开关 |

同构必须满足以下检查：

1. 同一候选在 wire 派生、持久恢复、运行时和 UI 中使用同一个稳定身份。
2. UI 上的授权、可用性、用户偏好和实际选择分别来自 LKG、Observation、Preference
   和 Selection，不能用一个字段代替另一个。
3. wire 或持久层没有 `RouteCandidate` / `RuntimeCandidate` 的第二份可编辑清单；
   重启后从同一 LKG 得到相同结果。
4. 平台脱敏可以删去私钥和 transport 秘密，但不能改变路径、最终出口、状态或版本语义。
5. Android、Linux 与 Windows 对相同输入得到逐项相同的候选身份和选择结果；平台差异只发生在
   `HostAdapter` 执行阶段。

## 持久与派生边界

必须持久化的只有：

- `DeviceIdentity` 的安全材料和不可回退 floor；
- `CertifiedLKG` 的原始认证字节；
- 用户明确设置的 `Preference`。

`RuntimeProfile` 随完整 `CertifiedLKG` 一同保存，不建立独立 current、bundle 或配置数据库；表中
`RuntimeCandidate`“不持久化”是指不把投影后的候选再保存一份，而不是丢弃 LKG 内受认证的执行材料。

其余均从当前输入或宿主回读获得：

- `RouteCandidate` 与 `RuntimeCandidate` 每次启动重新派生；
- 当前 `Observation` 由实际网络结果产生，历史记录不能在新网络代恢复成健康事实；
- `Selection` 每次由 selector 回读恢复，而不是相信上次写入的期望值；
- `HostAdapter` 是代码边界，不拥有另一套业务状态。

这条边界禁止“为了恢复方便”再增加候选数据库、健康缓存权威、切换 journal、阶段表或
影子 selector。诊断事件可以记录，但事件不能反向成为当前状态。

## 状态转换与恢复

### 首次加入

1. 平台生成或导入 `DeviceIdentity`，并取得该身份已认证的网络信任绑定。
2. 使用该信任绑定验证收到的认证设备视图、设备绑定、版本和 floor，成功后原子保存为
   `CertifiedLKG`。
3. 纯核心派生两类候选；`HostAdapter` 安装必要运行配置。
4. 按 `Preference` 立即选择一个被授权且未被证明不可用的候选，应用并回读。
5. 并行采集必要的真实 transport outcome；结果到达后再以同一纯函数重算。

第 4 步不等待第 5 步，所以首次启动不会被测量阻塞。

### 进程重启与离线

1. 从安全存储加载身份与信任绑定，重新验证持久化的 LKG。
2. 确定性地重建候选。
3. 先读取宿主 selector；仍被授权且未被当前结果证明不可用时保持它。
4. 没有可保持的实际选择时立即选择一个合法候选，不等待控制面或观测。

控制面不可达时继续使用认证 LKG。认证失败、floor 回退或没有任何合法候选必须明确报错，
不能退回 v1 网络路径。

### 新认证配置

新 LKG 只有在签名、设备绑定和 floor 全部通过后才能替换旧值。替换后重新派生候选：

- 被撤销的候选立即停止承接新连接；
- 仍存在且身份相同的候选复用当前网络代内有效的同范围观测；
- 新候选为 `unknown`，可以在没有可用候选时被立即尝试；
- selector 回读确认后才更新 `Selection`。

### 撤权边界

控制面撤销设备时，从认证 `Projection` 删除该设备的授权；此后新的私有 device tunnel、配置读取和报告
必须在握手处拒绝，Web 也不再投影其授权候选。撤权不会改写已经交付到离线设备的历史 LKG 字节：设备在
尚未取得更新认证状态时仍可按该 LKG 的既有数据面能力继续运行，这一能力边界必须由被引用 transport 的
密钥或服务端授权寿命进一步限制，不能谎报为“客户端已经获知撤权”。一旦客户端取得不含旧候选的新 LKG，
旧候选立即停止承接新连接；不得以 v1 fallback 或缓存 DeviceView 重新扩权。

### 切网、故障与恢复

- 切换底层网络代：旧观测不参与决策，启动不等待新探测。
- 当前候选真实失败：记为 `unavailable`，从同一 Preference 范围选择可用或未知候选。
- 一跳直达失败：若指定同一最终出口，中继候选仍正常参与选择。
- 后续真实成功：候选恢复为 `available`，不修改授权或拓扑。
- 所有候选均已知不可用：明确显示不可用，不无限轮询、不填充假样本。

## 纯核心与平台边界

Android、Linux 与 Windows 必须复用同一个无 I/O 纯核心。纯核心只做：

1. 验证后输入的规范化；
2. 候选确定性派生和身份计算；
3. 观测有效性与三态归约；
4. Preference 裁剪、排序和下一候选计算。

时钟、当前网络代、平台能力和 selector 回读都由调用方作为值传入。纯核心不访问文件、
网络、VPN 服务、系统代理或全局单例。

Android、Linux 与 Windows 各自只实现 `HostAdapter`：安全存储、配置安装、真实 transport / business
结果采集、selector apply 和 readback。适配器不得自行排名、增加 fallback 分支或重解释
`public_data_ingress`。

Linux 的具体映射不增加领域概念：`/var/lib/loom-device/state.json` 是 `DeviceIdentity + CertifiedLKG`
的 owner-only 原子文件，并把已部署 schema 1 一次性前向迁移为带 `v2_latch` 的 schema 2，保留原身份、
认证 floor 与完整 LKG；`/var/lib/loom-device/runtime.json` 只保存一份 `Preference` 和当前底层网络代的有限
`Observation`；`/run/loom-client/config.json` 与 `status.json` 分别是可删除重建的
`RuntimeCandidate` 配置和 selector 回读投影。唯一正式 unit `loom-client.service` 运行
`loom client run`，由它启动精确签名包中的 sing-box、应用共享纯核心给出的候选、逐项回读 selector，
再以一次真实 TCP/TLS 与 UDP/DNS 业务结果形成 Observation。第一次失败只触发一次由相同纯函数得出的
必要 fallback；同一网络代已有有效结果时重启不重复采样。

`loom client route direct|auto|exit <ID>` 是 Linux 唯一偏好写入口；写入后重载同一 service。
`loom client status` 只读取 `/run` 中的实际 Selection，不把偏好冒充为运行事实。service 启动时可以尝试
私有配置同步；控制面离线或报告暂不可达时继续使用已验证 LKG，不能改走公开配置或旧 pull。

设备把签名报告交给任一可达控制成员即算上传成功。接收成员先按当前 certified DeviceView 验证设备身份和
`view_digest`，再通过已有的控制成员私有认证通道定期把每台设备最新的一份报告合并到其他成员；时间相同或
更旧的重放不覆盖新结果。报告不是 Raft/QC 权威，成员暂时不可达只会令该成员展示缺少观测；连通恢复后从
其他成员重新合并即可。设备授权或 DeviceView 改变后，旧 `view_digest` 的报告即使签名正确也不得继续投影。

Linux 客户端制品同时为 amd64/arm64 生成、签名和逐文件验证。amd64 在原生宿主做业务验收；arm64
只交叉构建和静态检查。installer 先把精确制品放入内容标识 release 目录，并在切换 `current` 前对现有
LKG 执行 sing-box preflight；切换后若 service/selector 回读未成功，恢复先前 `current` 和 unit。升级失败
不覆盖旧的可运行制品。

installer 在停止任何既有 unit 前还必须检查现有 sing-box 入站的所有权。发现 Hysteria2、Trojan 或无法
证明属于本地客户端接管的入站时，客户端安装失败关闭；它不能把“新客户端自身可运行”解释为同机服务器
职责已被替代。服务器运行时只有在同一认证投影明确提供替代入站、报告和回读，并完成真实业务验收后才能
被退休。

### Windows profile 与 HostAdapter

Windows 的一个 profile 恰好绑定一组 `DeviceIdentity + CertifiedLKG + Preference`。这只是八概念在
本机的聚合保存，不是第九个领域实体。profile 索引只保存不透明本机 ID、显示名称和当前浏览行；它不保存
设备公钥、floor、候选、当前连接、健康或 selector 值，删除后不能据此重建网络状态。当前连接必须从正式
runtime 和 selector 回读；显示名称、列表顺序和被选中行不能改变 Device、授权或实际 Selection。

每个 profile 使用一个严格 schema 的 DPAPI envelope 原子保存 Ed25519 私钥及公钥绑定、稳定 claim request
ID、BootstrapCapability 约束、不可回退 floor、`v2_latch=true`、完整原始 `DeviceViewEnvelope` LKG 和唯一
Preference。Installed 使用 machine-scope DPAPI，并由 MSI 建立 SYSTEM/Administrators DACL；Portable TUN 与
Portable Mixed 使用 current-user DPAPI。磁盘上不得出现明文私钥、拆出的运行配置、hydrate 后候选或第二份
LKG。写入使用同目录临时文件、落盘、原子替换和替换后独立回读；任一步失败都保留旧 envelope。新 LKG 只有
在 wire 规范、Ed25519 设备绑定、QC/证明、RuntimeProfile、floor 和宿主 preflight 全部通过后，才能与提升后
floor 一起替换旧值；不能拼接新旧字段。

首次导入时先生成 Ed25519 身份并把 `v2_latch=true`、floor 0、capability 绑定和默认 Auto Preference 原子
保护，再经受限 bootstrap tunnel claim/resume。同一事务恢复复用同一 identity/request ID；不同邀请不得接管。
完成后保存完整 LKG 并推进 floor。进程、SCM 服务或系统重启从同一 envelope 验证恢复；DPAPI 解密失败、schema
未知、latch 缺失、floor 回退、LKG 无效或 Preference 非规范时整个 profile 失败关闭，不回退 P-256、公开配置、
旧 bundle 或 v1 路径。未完成事务不是可连接 profile，UI 只能显示可继续恢复的加入状态。

Windows HostAdapter 从 LKG 每次纯派生 `RouteCandidate` 与 `RuntimeCandidate`，启动签名包中的正式 sing-box，
应用纯核心提出的候选后读取 Clash selector 的真实值。只有逐 scope 回读均映射到当前 LKG 的同名候选时才形成
Selection；apply 成功但回读缺失、不一致或指向未授权 outbound 时不更新 Selection。TCP connect/TLS 成功、
TCP 业务失败、UDP/DNS 成功或失败分别产生保留 action/scope 的真实 Observation；本机 listener、自检、ICMP、
授权声明和 UI 颜色都不能产生 `available`。

Installed、Portable TUN 与 Portable Mixed 只是 HostAdapter/交付差异：Installed 由 SCM 服务持有 machine DPAPI
和 TUN，Portable TUN 由提权前台进程持有 user DPAPI 和 TUN，Portable Mixed 只提供同一 runtime 的 mixed
入口且不改路由。三者消费同一个 profile envelope、候选派生、选择函数、selector 回读和报告 wire；不得各自
复制选路规则、候选 store 或健康状态机。源码、构建与制品判断只在 Linux 工作树；同机受限 VM 只做 x64 原生
执行，不能抵扣 ARM64、真实睡眠、物理网络切换和显示硬件终验。

旧 Windows P-256/证书状态不属于新 decoder 的兼容输入。若只读审计发现真实旧身份，必须由正式 Rejoin/rekey
把同一稳定 Device 语义前向绑定到新的 Ed25519 公钥，并保持或提高服务端 floor 与 v2 latch；成功前保留旧字节，
成功后删除旧运行 fallback。若审计确认没有对象，只保存脱敏计数证据，不增加空 importer、长期双读或 P-256
fallback。

## 最小必要测试集

测试验证模型边界，不枚举平台、服务器、协议和故障的笛卡尔积。

1. **认证与恢复**：有效 LKG 可离线恢复；错误签名和 floor 回退被拒绝；失败不覆盖旧 LKG。
2. **确定性派生**：相同 LKG 在 Android/Linux/Windows 纯核心得到相同候选身份和顺序，重启结果不变。
3. **Direct 语义**：Direct 的服务器链为空，不产生代理入口检查；一跳直达包含最终出口，二者不混淆。
4. **同出口双路径**：同一最终出口同时产生一跳直达和境内 WG 中继；关闭
   `public_data_ingress` 只删除前者，开启它不会自动得到 `available`。
5. **三态观测**：真实成功、真实失败、缺失/过期/跨网络代分别得到 available、unavailable、unknown；
   ICMP 成败只改变 RTT 提示，不改变三态。
6. **非阻塞与 fallback**：启动在观测未完成时即可应用合法候选；一跳直达真实失败后选择
   同一最终出口的中继；后续成功可恢复，无需配置变化。
7. **运行事实**：adapter apply 成功但 readback 不匹配时不更新 Selection；UI 显示回读实际值，
   不把 Preference 显示为当前路径。
8. **平台契约**：Android/Linux/Windows adapter 各用一个成功 outcome、一个失败 outcome、一次 apply/readback
   验证接口；真实验收各选一条可工作的正常路径和一条同出口 fallback 即可。
9. **运行投影**：一份规范 RuntimeProfile 与 routes 逐项映射；缺候选、多余 selector 成员、非规范
   JSON 或 libbox preflight 失败均不得替换旧可运行 LKG。
10. **Windows DPAPI 与 profile 隔离**：machine/user scope 不能互换；每个 profile 的 Ed25519 身份、floor、
    latch、完整 LKG 与 Preference 往返相等，原子替换失败保留旧值；索引损坏不能制造或覆盖网络权威。
11. **Windows 严格 wire 与恢复**：`platform=windows` 缺 RuntimeProfile，或含未知/缺失/多余字段、重复键、
    非规范 JSON、错误候选映射时服务端拒绝；重启从同一 DPAPI LKG 派生相同候选，Selection 仍只来自 readback。
12. **Windows 最小原生闭环**：Installed x64 用一个 profile 完成 UI invite → claim/resume → DPAPI → runtime →
    selector readback → TCP 与 UDP/DNS → 一个 unavailable 候选 → 同出口 fallback → 签名 report/readback；再按同一
    adapter 契约抽样 Portable TUN/Mixed 的 capture、清理和持久差异，不建立 Edition × 模式 × 协议矩阵。
13. **旧身份等价类**：审计若发现 P-256/证书身份，只测一条正式 Rejoin/rekey 与失败保留；若没有对象，只验证
    脱敏零计数和新 decoder 拒绝旧格式，不为不存在的数据制造迁移状态机。

扩展测试只能在这十三项通过后进行，并且发现新场景时优先把它表达为新的候选或观测数据，
而不是新增路由分支。

## 明确禁止

- 不恢复旧 scheduler、probe budget、`min_samples`、预热、挑战者比较或一次性 registry。
- 不按 Service × 候选路径做完整业务扫描，不要求所有出口和所有 transport 都实测一遍。
- 不为未知状态补样本，不用 ICMP 或单段 RTT 伪造端到端健康与 P50/P95。
- 不把 `public_data_ingress`、认证配置或服务端声明解释为当前可用。
- 不因一跳直达存在而删除同出口中继，也不因 `reverse_only` 删除合法公开入口。
- 不把 Android/Linux/Windows 平台差异写进纯选择规则；Windows Edition 差异只进入 HostAdapter。
- 不持久化派生候选或期望选择来绕过重建与 selector readback。
- 不新增与上述八个概念重复的 manager、store、ledger、gate、phase、receipt 或后台循环。
- 不让 profile 索引、显示名称、UI 选中行、SCM 状态或本机 listener 成为第二网络权威。
- 不读取 P-256/证书旧状态作为运行 fallback；不存在迁移对象时不保留空兼容 decoder。
