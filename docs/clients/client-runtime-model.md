# 客户端运行时最小模型

本文定义现行 Android / Linux / Windows 客户端运行时模型。它是实现、持久化、wire、
运行时和 UI 的共同契约；读者不需要阅读代码才能判断一个行为是否符合设计。

这里的“同构”不是要求各层拥有相同结构体，而是要求同一个事实只有一个来源，
各层使用稳定标识保持其身份和语义。安全脱敏与纯派生允许字段变少，但不得在另一层
制造第二份可独立修改的事实。

本文只使用八个核心概念。它们是职责边界，**不要求一个概念对应一个类型、表或服务**；
能够用值、纯函数或现有安全存储表达时，不新增实体。

## 八个概念

| 概念 | 唯一职责 | 不是 |
|---|---|---|
| `DeviceIdentity` | 标识设备、保存已认证的 `ControlConfig` 成员链信任绑定、已见事实前沿与不可回退 floor，并对私有请求签名 | 路由状态、网络测量或拓扑副本 |
| `CertifiedLKG` | 最近一次验证通过、由有效 control 签名且可离线继续使用的完整设备视图 | 全网最新状态或当前网络是否可用的声明 |
| `RouteCandidate` | 描述某一 Service 范围内从本机到目标的一条允许路径及其最终出口 | 节点类型、健康状态或平台进程 |
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

`Service` 定义目标地址或名称范围，`NetworkPolicy` 定义允许的路径，设备的
`DeviceAuthorization.DestinationGrants` 决定它能使用哪些 Policy。客户端只消费签名 DeviceView
下发的交集，不从入口存在、DNS 解析或探测结果创造新授权。互联网 Service 的终点是指定或可选的
最终出网节点；`local_network` Service 的终点是固定的 `forward` 网关，不称为互联网出口。

### Direct 不等于一跳直达

- **Direct** 的受管节点链为空：本机不经过任何受管节点，直接访问目标地址。
- **一跳直达** 的受管节点链包含一台具有 `internet_egress` 职责的节点：客户端经获授权的
  WG、hy2 等共享数据入口到该节点，再从它访问互联网目标。
- **中继路径** 至少包含入口转发节点和最终出网节点：客户端接入首跳，再沿认证
  `NetworkLink` 到最终出口。每条中继边引用确定的 `LinkID`，不由节点对猜测传输。

因此，以下是三条不同的 `RouteCandidate`：

```text
Direct:                    device → target
一跳直达 demo-sv:          device → demo-sv → target
同出口中继 demo-sv:        device → demo-cn → demo-sv → target
```

后两条拥有相同的最终出口，但拥有不同的入口和受管节点链。它们必须同时保留为候选，
使“一跳直达失败后仍从同一最终出口经境内中继访问”成为普通选路结果，而不是专用分支。

`public_data_ingress` 是可供客户端使用的一种已认证首跳声明；已有 WG、hy2 等共享
`TransportResource` 也可成为首跳。首跳由 Service、Policy、设备授权与资源共同投影，
不要求为每个设备新建接口或 `NetworkLink`。入口声明绝不表示该入口在当前网络可达。入口可能今天可用、
随后因 UDP 受限而不可用、几天后再次恢复，整个过程都不需要修改认证拓扑。

`NetworkLink` 的连接发起端必须满足端点的 `direction` / `reverse_only` 约束；这些约束不删除节点的
公开数据入口候选。授权、链路方向和实时可达性是三个不同事实。

`NetworkPolicy.allow_direct` 表示该 policy 的所有获授权 access 都可产生 `final_exit=direct` 的普通 Direct
候选。它不能表达“只有某个 hybrid access 在本机充当该 policy 的固定出口”。后一语义由规范排序的
`local_egress_devices` 表达：成员必须同时是该 policy 的获准最终出口、具备 `access` 与 `internet_egress`
能力；只有授权设备 ID 命中时才生成受管节点链为空、`final_exit=direct` 且候选 ID 绑定该设备的本地出口
候选。其他设备仍把该节点当作一跳或中继出口。普通 Direct 与设备限定 Direct 的授权来源不同，不能在
导入时把设备级许可提升成全 policy 的 `allow_direct`。

`NetworkIntent` 中的 `NetworkLink` 是有稳定 `LinkID` 的认证节点邻接，引用同一 `NetworkIntent`
内有稳定 ID 的 `TransportResource`。资源明确表示 WireGuard、Hysteria2（hy2）或对现有私有 TLS tunnel
的引用，保存固定承载节点、interface/listener 身份、拨号坐标和公开认证参数；逐设备参与资格从身份与授权投影，
不改写共享资源的规范参与者列表。私钥与本机 secret 仍只在节点受保护的本机输入中。
多条链路和多个候选可以引用同一资源，运行时按资源 ID 复用实际 interface、listener 或连接，
不按候选复制资源。只有源节点具备 `forward`、目标具备该路径所需的 `forward` 或
`internet_egress` 职责且链路允许数据中继时，它才是 `RouteCandidate` 的中继边；
control 通信和设备私有服务可以复用同一资源，不要求专门创建 `NetworkLink`，也不会因此产生业务权限。同一节点对可以有
WG 与 hy2 等多条 `NetworkLink`，各有独立 `LinkID`、建连方向和精确链路探测目标。链路、资源、方向及
设备授权决定 `RouteCandidate`；只有调用方提供的平台能力还支持所引用的传输，才投影可执行的
`RuntimeCandidate`。认证 `DeviceView` 对每个可见 `LinkID` 携带派生的 `link_spec_digest`，其值是该链路
与所引用 `TransportResource` 的规范内容摘要；客户端重算并核对。它不改变 LinkID，也不是另一份权威。
同一 LinkID 的两端、用途、发起端与资源引用不可修改；这些身份关系变化必须使用新 LinkID。
不支持时不得改用另一传输或补造链路。

Linux hybrid 节点同时承担当前 `access` 和 `forward` 职责，且它与最终出口之间存在可用方向的认证
`NetworkLink` 时，可以直接使用该链路，不要求自己或出口另有公网数据入口。该候选的规范受管节点链以本机
hybrid 节点开头，运行时跳过“拨回本机 inbound”，按 `LinkID` 引用的资源连接下一台受管节点：WG
必须使用对应 interface 和精确内核路由，hy2 或私有 TLS tunnel 则使用各自认证的拨号与 TLS 身份，
不能借用 WG 接口或路由。数据面投影也不得为这个本机起点生成回环 user/ACL。Web 拓扑展示时省略链首
重复的本机节点，但 candidate ID 与签名报告仍保留完整规范链及链路 ID。

### 候选身份

`RouteCandidate` 的稳定身份由 Service 范围、首跳资源 ID、规范化后的受管节点链、每条中继边按顺序排列的
`LinkID` 及终点确定；互联网终点标明最终出口，`local_network` 终点标明固定网关。Direct 的首跳资源和链路序列均为空，一跳直达只有首跳资源、没有中继 LinkID。
`RuntimeCandidate` 保留这个身份，并补充由对应
`TransportResource` 投影的实际传输、入口和宿主执行引用。相同节点链若分别使用 WG 与 hy2，必须产生
不同的候选 ID；一个传输的失败或成功不能改变另一传输的观测状态。同一获授权路径在 Android、Linux 与
Windows 上使用相同身份，即使平台生成的底层配置文本不同；平台能力不足只使其不可执行。

候选顺序不构成身份。所有派生结果必须确定性排序，不能依赖 map 遍历、时钟或随机数。

客户端 `DeviceView` 还携带一份规范 `RuntimeProfile` 值。它不是新的领域实体，
而是把该 view 已授权的候选投影成宿主可执行配置所需的私有材料：`kind` 固定为 `sing_box`，`config`
是规范 JSON。每条 `RouteCandidate.ID` 必须逐一对应 config 中同名 outbound，`RouteCandidate.Scope`
必须对应包含该 outbound 的 selector；config 不得增加 view 未授权的 selector 成员。control 把
`RuntimeProfile` 与 route authorization 一起认证，客户端只从完整 LKG 解出它，不另取公开配置、
不拼接旧 bundle，也不把 hydrate 后副本持久成第二权威。

`RuntimeCandidate` 因而是纯投影：

```text
RuntimeCandidate = project(RouteCandidate, DeviceView.RuntimeProfile, PlatformCapabilities)
```

Android、Linux 与 Windows 可以把同一候选落成不同宿主进程参数，但候选 ID、scope、节点链、首跳资源 ID、链路 ID 和最终
出口保持不变。能力不支持时该候选保持获授权但不可执行，不能被选中或伪报 unavailable。若 profile 缺失、
不是规范 JSON、候选映射不全或多出未授权成员，整个新 LKG 失败关闭；旧的
已运行 LKG 保持可用。

Windows 的 `RuntimeProfile` 不另设 wire 类型。服务端只接受 `platform=windows` 且带完整
`sing_box` profile 的 Enrollment 或设备更新；外层未知/缺失/多余字段、非规范 JSON、重复键、缺少候选、
多出未授权 selector 成员或候选 scope 映射不全均失败关闭，不能先接收再由 Windows 补默认值。Windows
HostAdapter 可以按交付形态投影本机 capture 配置，但不得增加、删除或重排被认证 selector 的候选语义。

## Observation 与可用性

每条 `Observation` 至少绑定：Service 范围、候选身份、底层网络代、实际探测目标或业务动作、
观测范围、结果、可比较的实际指标
和有效期。中继段的观测还绑定 `LinkID` 与 `link_spec_digest`；后者由该 `NetworkLink` 和所引用
`TransportResource` 的规范内容计算，不是独立可写状态。候选观测记录其路径各链路的有序摘要，
使共享资源的拨号坐标、认证键或链路精确探测目标变化可精确使受影响的观测失效。
时间由调用方传入；纯核心不自行读取时钟。

对当前网络代，一个候选只有三种运行状态：

| 状态 | 含义 |
|---|---|
| `available` | 对该候选执行的真实 transport 建连或正常业务已经成功；成功范围必须如实保留 |
| `unavailable` | 对该候选执行的真实 transport 建连或正常业务已经失败，且结果仍有效 |
| `unknown` | 没有结果、结果属于其他网络代、已经过期、无效，或结果范围不足以证明可用 |

一次入口 transport 成功只能证明对应入口成功，不能伪装成未实际执行的端到端业务成功；
一次完整业务成功则可以证明当时整条候选可用。客户端可以复用认证的中继段观测，
但不得为了把所有候选变绿而逐条扫描完整业务路径。
因此 transport/link 与 Service business 是两种显式观测范围：前者可为 `available`，同一候选的
Service business 仍为 `unknown`，直到对该 Service 匹配的真实目标或正常业务动作成功。
Auto 可以用已知首跳连通性优先尝试候选，但不能据此向 UI 或报告宣称该 Service 已健康。

完整业务探测的 DNS 地址和 HTTPS 目标都来自同一份认证 `DeviceView`。DNS 是 `NetworkIntent` 的全局值
与节点逐项覆盖；HTTPS 目标来自 `NetworkIntent` 中一份规范排序、去重、仅含 HTTPS URL 的全局业务探测
目标池，不要求每个 access 节点手工填写。服务端先从该设备 `DestinationGrants` 找到获授 policy，再只把
主机名被这些 policy 的 Service matcher 覆盖的 HTTPS URL **按 Service 分别**投影为 `BusinessProbeTargets`，
不建立第二个权威 `ProbeGroup`。同一 policy 下两个 Service 的实际业务结果也不得互相借用。无匹配目标时，
主动业务探测范围保持 `unknown`，不把 transport 成功冒充业务成功，也不把缺少目标视为加入失败；
真实正常业务仍可形成其实际范围的 Observation。客户端用认证 DNS 解析获授权 HTTPS 目标，执行真实
TCP/TLS 与 HTTP 探测，并对认证 DNS
执行 UDP/DNS 查询；不得改用主机 resolver、硬编码公网域名或为使探测通过而扩宽数据面 ACL。出网节点仍只允许
认证 DNS 的 53 端口和既有 Service matcher；目标池及投影均不新增授权。中继 `NetworkLink` 的精确
`LinkProbeTargets` 是另一类输入，按 `LinkID` 和资源传输检查，不从全局 HTTPS 目标池推导。这样，业务成功
仅证明该设备实际获授权的业务链。

`BootstrapCapability` 只授权首次 claim/resume，不因设备已完成加入而继续授权配置或报告。加入后
设备凭本机身份和签名，经有效 control 的设备认证私有入口领取当前签名 View，并上报运行事实；
配置、报告和 control 同步可使用已有共享 `TransportResource`，**不要求专门的 `NetworkLink`**。
某个数据入口或中继链路失效只影响引用它的候选；设备仍可经独立认证管理入口
领取修复 View，缺失业务探测保持 `unknown`。私有入口可达本身不证明业务 `available`。
共享承载上的各项服务仍分别校验 Device tunnel 的 TLS/SPKI 与设备身份；载体握手不能替代私有服务认证。
链路资源或 `EndpointGeneration` 的拨号主机名只用 View 中认证的 DNS 解析，解析结果只作本次拨号地址，
不能改写认证的 server name、SPKI 或稳定节点身份。
DNS overlay 只接受精确 `.loom` A/AAAA 映射，`control.loom` 由已认证 control 的私有 Web 入口投影。
解析结果不能扩大 Service/Policy ACL；在同一网络代内 DNS 映射改变，依赖该名称的旧连接与业务观测
失效并重新解析。Loom 名称的解析不能反过来依赖尚未建立的自身 tunnel，亦不得把 `.loom` 规则
安装为开发宿主初始 namespace 的全局 DNS 接管。
尚未取得 View 的首次 bootstrap 维持 `EndpointGeneration` 原有拨号边界，不从业务运行时反推 bootstrap 权威。
Linux HostAdapter 只在隔离 capture namespace 内将这些 underlay endpoint 的解析结果以逐主机 `/32` 或
`/128` 投影为 TUN 的本机 `route_exclude_address`，使私有控制、引导、
报告和 tunnel 连接不依赖某条业务 policy；认证 RuntimeProfile 不得自行提供或扩大该字段。DNS 变化时重新
解析、重建本机投影，旧结果不是权威也不能扩成网段。这个排除只防止 endpoint 递归进入 TUN，不是宿主 LAN、
管理面或默认路由的安全边界。

ICMP 结果只能作为地址 RTT 提示：

- ICMP 成功不能把候选改成 `available`；
- ICMP 失败不能把候选改成 `unavailable`；
- ICMP RTT 不能冒充 HY2、WireGuard 或业务端到端延迟。

同一底层网络代内，当前业务所需的授权首跳按稳定资源 ID 去重，并行且各至多发起一次必要的真实
transport 检查。中继段的链路观测还必须绑定 `LinkID`、`link_spec_digest`、资源传输、观测范围和网络代；同一节点对的
WG 与 hy2 分别产生真实结果，不能共享握手、RTT 或可用状态。未实测的链路仍为 `unknown`，不为填满
传输组合而扫描每条完整路径。这个约束由现有 `Observation` 的键和进行中状态自然表达，不新增
scheduler、probe budget 或一次性 registry。入口之后复用已有的有效中继观测。

“至多一次”约束一个尚未过期的观测窗口，而不是允许进程永远重发启动时结果。当前实际选择的观测
到期后，adapter 可以做一次新的最小真实业务检查并产生下一条有限期 Observation；有效期内不得为刷新
计分重复采样。底层网络代或 selector 回读变化时立即失效相应旧结果并执行同一最小检查。

底层网络代变化后，上一代观测不再决定当前状态，候选先回到 `unknown`。启动和切网
都不得等待观测齐全；缺失观测保持未知，也不得通过补样本制造健康状态。

## 局域网 Service 范围

具备 `forward` 职责的网关可认证报告自己的本地 IPv4 前缀；报告本身不产生共享权限。
control 签发的 `local_network` Service 值给出稳定映射 ID、网关节点、本地前缀、等长的虚拟前缀和
绑定的 `NetworkPolicy`。access 的 `DestinationGrant` 获授该 Policy 后，签名 DeviceView 才向它
下发虚拟前缀及到**固定网关**的获授权候选。access 不得提交任意 CIDR 或从网关报告自行生成路由。

`local_network:<mapping_id>` 是独立的 Service scope。客户端只对该虚拟前缀建立精确业务捕获与
路由，在到固定网关的一跳或中继路径中自动选择，不把网关误作互联网最终出口。开发宿主上
这些路由、策略规则和 DNS 投影只能在专用 capture namespace 内应用，不进入初始 namespace。
互联网业务的 Direct、Auto、指定最终出口 Preference 维持原有语义；局域网 scope 的候选不受
这三种互联网偏好裁剪，只在到固定网关的授权路径内自动选择，也不成为互联网 Auto 的捷径。
网关按同一授权检查，完成目标地址按主机位对应的转换，并在 LAN 主机没有
回程路由时做必要的源地址转换。只有 overlay 端能主动发起连接；LAN 主机可回复，不能凭映射主动
建立到 access 的会话，不修改 LAN 路由器。

一个网段若没有适用的共享 HTTPS 目标，主动完整业务可用性是 `unknown`，不能从 WG/hy2 握手或
任一 LAN 主机的结果推断整个网段可用。真实业务访问可生成**该目标**范围的 Observation。
映射撤销、策略撤权或网关身份失效时，客户端移除相应精确路由、DNS 投影和候选；已见撤权 floor
不得被较旧 DeviceView 重新降低。自动分配的虚拟前缀是 control 签名事实，不由客户端重算或猜测。

## Preference 与 Selection

`Preference` 只裁剪和排序已获授权且平台可执行的候选：

| 模式 | 候选范围 |
|---|---|
| `Direct` | 仅受管节点链为空的候选；不创建代理入口探测 |
| `Auto` | 当前互联网 Service 范围内所有由 `CertifiedLKG` 授权且平台可执行的候选 |
| 指定最终出口 | 所有最终出口相同的候选，包括一跳直达和境内中继 |

在范围内，已知可用候选优先于未知候选，已知不可用候选不参与新选择；多个可用候选按
`Preference` 指定的目标和同范围、仍有效的实际指标排序。不同观测范围的数字不能直接
比较，缺失指标不能补零。没有可用候选时，允许确定性地尝试未知候选，而不是等待测量。
没有更优的可比较证据时保持当前实际选择，避免无理由切换；排序是一次纯计算，不需要
挑战者状态、采样收敛或额外状态机。ICMP RTT 最多只能为同类入口提供次级提示，不能覆盖
真实 transport / business outcome。

指定 `demo-sv` 最终出口时，如果一跳直达候选被真实 transport 结果判定不可用，而
`demo-cn → demo-sv` 仍可尝试或已经可用，选择后者。最终出口没有改变，改变的只是路径。
如果以后真实结果再次证明一跳直达可用，它会正常重新进入候选集，无需修改签名权威事实。

纯核心的输出只是“应尝试的候选”。`HostAdapter` 应用它之后必须读取宿主 selector；
只有回读确认成功，才能产生新的 `Selection`。应用失败时，UI 和报告继续显示回读到的
旧选择或“无实际选择”，不得把意图显示成运行事实。

## 跨层同构

下表完整规定八个概念在 domain、wire、persistent、runtime 和 UI 中的对应关系。
“派生”表示该层不得另存一份可写副本；“无”表示该概念不需要出现在该层。

| 概念 | Domain（语义） | Wire（跨进程） | Persistent（重启后） | Runtime（当前进程） | UI（用户可见） |
|---|---|---|---|---|---|
| `DeviceIdentity` | 设备标识、已认证成员链、签名能力与不可回退已见事实 floor | 只发送标识、公钥及签名证明；不发送私钥 | 私钥进入平台安全存储；信任绑定、前沿、floor 与新 LKG 同一原子提交 | 提供验签边界与签名能力，不参与排序 | 加入状态与公开标识摘要；永不显示秘密 |
| `CertifiedLKG` | 最近一次验证成功的签名设备视图 | 完整规范 View、签发 control 签名、连续成员证明、签发者事实前沿与设备绑定 | 完整 envelope 原子保存，与信任绑定及 floor 同步替换 | 解析为只读输入；不能证明全网没有未见撤权 | 显示来源、已见前沿和是否陈旧，不宣称网络可用 |
| `RouteCandidate` | 允许路径、首跳资源、受管节点链、按序 `LinkID`、最终出口和 Service 范围 | 不单独传输；由认证设备视图中的授权链路与资源派生 | 不持久化 | 每次从 LKG 纯函数重建 | 显示 Direct / 节点链 / 链路传输 / 最终出口 |
| `RuntimeCandidate` | 路径的可执行投影及稳定身份 | 不单独传输；所需入口和资源材料来自私有认证配置 | 不持久化独立副本 | 按调用方平台能力投影，供 adapter 按资源 ID 复用 transport / outbound | 通常只显示协议和入口类别，不暴露秘密参数 |
| `Observation` | 某网络代、某 Service、某候选、实际目标及链路规范摘要的真实结果 | 私有认证报告保留来源、目标、范围和 `link_spec_digest` | 不作为配置权威；可留诊断历史，但恢复时不得直接当作当前结果 | 当前网络代的有限集合，摘要不匹配即失效 | 显示 available / unavailable / unknown、实测范围与陈旧状态 |
| `Preference` | Direct、Auto 或指定最终出口 | 如需跨设备同步，只能走私有认证配置；没有同步需求时无 wire | 只保存一份本机用户设置 | 作为纯选择函数输入 | 唯一可编辑的选路意图 |
| `Selection` | selector 回读确认的实际候选 | 可通过私有认证状态报告上送 | 不作为下次启动的权威；事件可供诊断 | 当前实际候选及回读时间 | 与 Preference 分栏显示，明确“当前实际路径” |
| `HostAdapter` | 平台能力边界 | 无独立 wire 对象 | 只使用平台既有安全存储与服务配置 | 在平台隔离边界内执行 load、apply、readback 和真实 outcome 采集 | 提供能力/错误，不提供第二套选路开关 |

同构必须满足以下检查：

1. 同一候选在 wire 派生、持久恢复、运行时和 UI 中使用同一个稳定身份。
2. UI 上的授权、可用性、用户偏好和实际选择分别来自 LKG、Observation、Preference
   和 Selection，不能用一个字段代替另一个。
3. wire 或持久层没有 `RouteCandidate` / `RuntimeCandidate` 的第二份可编辑清单；
   重启后从同一 LKG 得到相同结果。
4. 平台脱敏可以删去私钥和 transport 秘密，但不能改变路径、最终出口、状态或版本语义。
5. Android、Linux 与 Windows 对相同 LKG 得到逐项相同的 `RouteCandidate` 身份；再给相同平台能力值
   和观测输入时得到相同可执行集合与选择结果。能力值不同只裁剪不可执行集合，不改变授权候选 ID，
   也不让 `HostAdapter` 发明另一套选路规则。

## 持久与派生边界

必须持久化的网络权威与用户偏好只有：

- `DeviceIdentity` 的安全材料和不可回退 floor；
- `CertifiedLKG` 的原始认证字节；
- 用户明确设置的 `Preference`。

`RuntimeProfile` 随完整 `CertifiedLKG` 一同保存，不建立独立 current、bundle 或配置数据库；表中
`RuntimeCandidate`“不持久化”是指不把投影后的候选再保存一份，而不是丢弃 LKG 内受认证的执行材料。

平台可以持久保存当前网络代的有限 `Observation` 诊断缓存；它不是认证网络权威，过期、换网或验证失败后
必须回到 unknown，缓存可删除重建。Android/Windows 的本机 profile 目录保存用户命名、稳定本机 ID 与
恢复意图，必须按各自模型规范持久往返并在失败时保留；它们不是网络授权或实际连接的权威，但不能当缓存删除。
当前运行事实仍从当前输入或宿主回读获得：

- `RouteCandidate` 与 `RuntimeCandidate` 每次启动重新派生；
- 当前 `Observation` 由实际网络结果产生，历史记录不能在新网络代恢复成健康事实；
- `Selection` 每次由 selector 回读恢复，而不是相信上次写入的期望值；
- `HostAdapter` 是代码边界，不拥有另一套业务状态。

不增加候选数据库、健康缓存权威、切换 journal、阶段表或
影子 selector。诊断事件可以记录，但事件不能反向成为当前状态。

## 状态转换与恢复

### 首次加入

1. 平台本机生成 `DeviceIdentity`，从可信交付的 Invite 固定网络锚、签发者和当前可验证的
   `ControlConfig` 成员链；首次 claim 只找签发者。扫码 Invite 只能授予 `access`。
2. 验证收到的完整 DeviceView、签发 control 的成员资格与签名、连续多数签名的成员变更证明、
   签发者事实前沿及设备绑定。任何已见撤权事实不得在新 View 中消失；通过后与信任绑定、floor
   原子保存为 `CertifiedLKG`。签名 View 不能证明没有尚未传播的撤权。
3. 纯核心从认证的 Service、Policy、首跳资源、节点链和有序 `LinkID` 派生授权候选，再按平台
   实际能力投影可执行候选；`HostAdapter` 按资源 ID 复用并安装必要运行配置。首份 View 没有
   `NetworkLink` 时仍可经设备认证私有入口领配置，并按授权使用共享首跳。
4. 有可执行业务候选时，按 `Preference` 立即选择一个被授权且未被证明不可用的候选，应用并回读；
   没有时业务保持 `unknown`，仍可经现行私有入口领取修复 View 和报告。
5. 并行采集必要的真实 transport outcome；结果到达后再以同一纯函数重算。

第 4 步不等待第 5 步，所以首次启动不会被测量阻塞。

### 进程重启与离线

1. 从安全存储加载身份与信任绑定，重新验证持久化的 LKG。
2. 确定性地重建候选。
3. 先读取宿主 selector；仍被授权且未被当前结果证明不可用时保持它。
4. 没有可保持的实际选择时立即选择一个合法候选，不等待控制面或观测。

控制面不可达时继续使用认证 LKG。认证失败、floor 回退或没有任何合法业务候选必须明确报错，
不能退回旧网络路径；业务候选缺失不阻止已认证设备经现行私有入口领取修复 View 和报告 `unknown`。

### 新认证配置

新 LKG 只有在签名、设备绑定、成员链证明、签发者事实前沿和 floor 全部通过后才能替换旧值。
成员变化时，envelope 必须从设备已固定的成员表起提供连续的后继表，每步引用前一表摘要，
由旧表计算出的多数签署同一提案，并携带旧签发者事实截止前沿。客户端逐步核对网络锚、
成员 ID 与验证键、签名集合、事实截止及最终签发者资格；不接受仅由新表自签的跳跃。
没有成员变化时证明序列为空，但仍必须验证签发 control 当前有效且没有越过其截止前沿。
新 View 的已见前沿对本机保存的签发者序列单调，不能遗漏已经看到的撤权或冲突事实；
冲突未解决的对象不能从某一 control 的局部视图被误判为有效。只有完整 View、成员证明与
非回退 floor 均通过，才将信任绑定、前沿、LKG 和 floor 原子保存。漏项、乱序、旧格式事实、
任意新根、验签或落盘失败均保留旧 LKG 与旧 floor。
替换后重新派生候选：

- 被撤销的候选立即停止承接新连接；
- 仍存在且身份相同的候选仅在当前网络代、观测范围及其相关认证执行/探测输入均未变化时复用观测；
  其中每条引用链路的 `link_spec_digest` 必须相同。相同 `LinkID` 或资源 ID 的规范内容变更，只使该链路
  及包含它的候选观测回到 `unknown`，其他输入未变的候选不受影响；入口、RuntimeProfile、DNS、Service
  matcher 或 HTTPS 探测目标变化也须使依赖它们的旧观测失效；重启后无法证明相关输入仍相同的缓存保守置
  `unknown`；
- 新候选为 `unknown`，可以在没有可用候选时被立即尝试；
- 即使候选 ID 未变，只要资源规范内容已变，就须应用新资源并回读 selector 与实际链路，之后才更新
  `Selection`；旧配置的 readback 不能确认新 LKG 已运行。

Linux daemon 在运行期间按已见事实前沿和 View 摘要获取差量或条件更新，不向每台设备广播全网
事实集，也不在检测步骤保存新 envelope。
变化发生时由同一进程监督器结束当前 sing-box 子进程并启动一个新的运行代：先对新 View 做完整
preflight，按 `TransportResource` 类型事务应用实际需要的 WG interface/精确路由或 hy2、私有 TLS tunnel
配置，启动 sing-box，再读取实际 listener、selector、链路资源和配置摘要；这些读回全部成功后才保存新
LKG。若新代任一步失败，配置文件、CA 及本 generation 拥有的链路资源事务恢复为旧值，监督器
立即从尚未提升的旧 LKG 重启旧运行代，下一次固定间隔才重试。这个“运行代”只是进程内调用边界，
不持久化、不形成阶段表或第二份 authority。

### 撤权边界

控制面撤销设备时，签名撤权事实使 `Projection` 不再给该设备授权；已知撤权的 control 此后对新的
私有 device tunnel、配置读取和报告
必须在握手处拒绝，Web 也不再投影其授权候选。撤权不会改写已经交付到离线设备的历史 LKG 字节：设备在
尚未取得更新认证状态时仍可按该 LKG 的既有数据面能力继续运行，这一能力边界必须由被引用 transport 的
密钥或服务端授权寿命进一步限制，不能谎报为“客户端已经获知撤权”。分区期间尚未收到撤权的
control 与客户端可能暂时继续按旧 View 运作；这个窗口不能被单签视图伪称为全网即时撤权。
一旦客户端取得不含旧候选的新 LKG，
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

时钟、当前网络代、平台支持的资源传输能力和 selector 回读都由调用方作为值传入。纯核心不访问文件、
网络、VPN 服务、系统代理或全局单例。

Android、Linux 与 Windows 各自只实现 `HostAdapter`：安全存储、配置安装、真实 transport / business
结果采集、selector apply 和 readback。适配器不得自行排名、增加 fallback 分支或重解释
`public_data_ingress`。

### Linux capture 边界与宿主不变量

`RuntimeCandidate` 只回答“已经进入 Loom runtime 的业务流量走哪个候选”，它不授权 HostAdapter 捕获宿主的
任意流量。capture 边界是平台执行前提，不是第九个领域权威，也不进入 DeviceView、LKG、Preference 或报告：

TUN 不被删除为产品能力，但它只能作为 overlay 存在于明确的 capture 边界；物理接口或既有 WireGuard 始终承担
underlay，获准的 hy2/TLS 资源也须沿受保护 underlay 拨号。物理接口显示 `UP`、能收到入站包或 main 表存在默认路由
都不证明安全，必须验证连接的实际返回路径。

同一台机器承担 `control`、`forward` 和 `internet_egress` 是合法的 N=1 部署，不要求 TUN：
数据面入站接收获授权连接，用户态 outbound 直接使用宿主 underlay 出网；“最终出口”仍只是候选路径位置。只有本机 workload 也需要作为
`access` 客户端时才需要 capture。此时平台运行时必须把转发与出网运行时留在宿主受限监听边界，把 access workload 与
TUN 放进专用 namespace；二者仍消费同一 DeviceView，不新增节点类型、候选权威或第二份状态。

- 开发宿主的初始 network namespace 禁止 access/hybrid `auto_route` TUN。未完成隔离时 runtime 与 installer
  都失败关闭；纯转发/出网运行时没有 TUN，不受这一条件影响。
- 默认开发入口是显式 Mixed/SOCKS/HTTP proxy。需要 TUN 时，获授权 workload、sing-box、TUN、table、policy
  rules 和 DNS 全部进入同一个专用 network namespace；宿主只保留一条有明确所有权的窄 underlay 边界。
- 宿主 SSH、LAN、默认网关、现有 WireGuard、DNS、HTTP proxy、控制/Enrollment/报告/tunnel endpoint 和 Loom
  自身 underlay 始终保持原路径。业务 report、selector readback、endpoint 排除或单次探测成功不能替代这些回读。
- namespace、veth 和必要 firewall 对象绑定一个运行 generation。正常停止、child/parent 崩溃、SIGKILL、启动
  中途失败和重启恢复都通过外部 cleanup 精确删除本 generation 的对象；不得按共享 table 或 rule 范围 flush。
- cleanup 及宿主不变量回读成功前 service 不得宣称 running，也不得自动重启。未知对象或所有权冲突使启动失败。

专用终端若产品需求明确为整机 VPN，可以在该专用设备的初始 namespace 使用 TUN，但这不是开发/控制/混合节点
的默认交付：它必须显式启用，并在 capture 前建立和回读管理网、SSH、LAN、WireGuard、DNS、默认网关与 tunnel
endpoint bypass；没有独立管理通道和失败回滚时同样禁止激活。当前模型尚无这项显式交付输入，因此现有门禁仍
拒绝全部 initial-namespace access TUN，不能用“未来可能支持整机 VPN”绕过。

删除 capture 边界会重新允许应用接管宿主网络控制平面，直接破坏管理可达性，因此它不能被吸收到 endpoint
排除、selector、Observation 或安装 readiness 中。事故背景见
[宿主网络接管事故记录](../incidents/2026-09-21-host-network-takeover.md)。

Linux 的具体映射不增加领域概念：`/var/lib/loom-device/state.json` 是带 `v2_latch` 的现行 schema 2
`DeviceIdentity + CertifiedLKG` owner-only 原子文件，保留稳定身份、认证 floor 与完整 LKG；
`/var/lib/loom-device/runtime.json` 只保存一份 `Preference` 和当前底层网络代的有限
`Observation`；`/run/loom-client/config.json` 与 `status.json` 分别是可删除重建的
`RuntimeCandidate` 配置和 selector 回读投影。唯一正式 unit `loom-client.service` 运行
`loom client run`；access/hybrid 进程必须先进入专用 network namespace，再启动精确签名包中的 sing-box、
应用共享纯核心给出的候选、逐项回读 selector，
再以一次真实 TCP/TLS 与 UDP/DNS 业务结果形成 Observation。第一次失败只触发一次由相同纯函数得出的
必要 fallback；同一网络代已有有效结果时重启不重复采样。

当前专用 namespace 生命周期尚未实现，因此 Linux access/hybrid preflight 和 runtime 在与 PID 1 相同的
network namespace 中明确拒绝启动，正式 unit 保持 disabled。这个安全暂停不是完成态；只有隔离创建、清理、
宿主不变量回读和崩溃恢复全部接入 installer 后，才能重新启用 service。

`loom client route direct|auto|exit <ID>` 是 Linux 唯一偏好写入口；写入后重载同一 service。
`loom client status` 只读取 `/run` 中的实际 Selection，不把偏好冒充为运行事实。service 启动时可以尝试
私有配置同步；控制面离线或报告暂不可达时继续使用已验证 LKG，不能改走公开配置或旧 pull。

设备把签名报告交给任一可达且已同步该设备授权事实的 control 即算上传成功。接收成员按当前
签名 DeviceView 验证设备身份和 `view_digest`，再通过控制成员私有认证通道按设备报告序列交换
必要差量；较旧的报告不能覆盖新结果。报告不参与治理权威，成员暂时不可达只会令该成员展示缺少观测；连通恢复后从
其他成员重新合并即可。签名报告将当前 `view_digest`、链路 Observation 的 `link_spec_digest` 和候选
Observation 所经链路的有序摘要一同纳入签名字节；接收方按当前 View 重算，不匹配时只投影 `unknown`，
不得沿用旧 `available`。客户端只在相关执行/探测输入经新旧 LKG 比对相同后，才可把旧观测留在新 View 的报告中；
无法证明相同时保守上报 `unknown`。
设备授权或 DeviceView 改变后，旧 `view_digest` 的报告即使签名正确也不得继续投影。

Linux 客户端制品同时为 amd64/arm64 生成、签名和逐文件验证。amd64 在原生宿主做业务验收；arm64
只交叉构建和静态检查。installer 先把精确制品放入内容标识 release 目录，并在切换 `current` 前对现有
LKG 执行 sing-box preflight；切换后若 service/selector 回读未成功，只有先前 release/unit 已证明不会在
初始 netns 接管宿主流量时才可恢复运行，否则只恢复文件指针并保持 service disabled/failed。升级失败
不覆盖旧制品，也不得重新启用危险旧 unit。当前 installer 的失败路径尚需落实这一限制，见
[实施状态](../progress.md)。

installer 在停止任何既有 unit 前还必须检查现有 sing-box 入站的所有权。发现 Hysteria2、Trojan 或无法
证明属于本地客户端接管的入站时，客户端安装失败关闭；它不能把“新客户端自身可运行”解释为同机转发或出网
职责已被替代。相应数据面运行时只有在同一认证投影明确提供替代入站、报告和回读，并完成真实业务验收后才能
被退休。

### Windows profile 与 HostAdapter

Windows 的一个 profile 恰好绑定一组 `DeviceIdentity + CertifiedLKG + Preference`。这只是八概念在
本机的聚合保存，不是第九个网络领域实体。profile 索引只保存不透明本机 ID、显示名称、列表顺序、当前浏览行
和上次明确请求连接的 profile ID；最后一项只是重启时尝试恢复连接的本机用户意图，不是持久的 active 或
Selection。索引不保存设备公钥、floor、候选、当前连接、健康或 selector 值，删除后不能据此重建网络状态。
当前连接必须从正式 runtime 和 selector 回读；名称、顺序、浏览行和恢复请求都不能改变 Device、授权或
实际 Selection。

每个 profile 使用一个严格 schema 的 DPAPI envelope 原子保存 Ed25519 私钥及公钥绑定、稳定 claim request
ID、BootstrapCapability 约束、已验证 `ControlConfig` 成员链、已见事实前沿、不可回退 floor、`v2_latch=true`、
完整原始 `DeviceViewEnvelope` LKG 和唯一 Preference。Installed 使用 machine-scope DPAPI，并由 MSI 建立
SYSTEM/Administrators DACL；Portable TUN 与 Portable Mixed 使用 current-user DPAPI。磁盘上不得出现明文私钥、
拆出的运行配置、hydrate 后候选或第二份 LKG。写入使用同目录临时文件、落盘、原子替换和替换后独立回读；
任一步失败都保留旧 envelope。新 LKG 只有在 wire 规范、Ed25519 设备绑定、由当前信任绑定验证的
连续多数签名成员链、签发 control 的签名与事实前沿、RuntimeProfile、floor 和宿主
preflight 全部通过后，才能与提升后的已验证成员链信任绑定、事实前沿及 floor 一起替换旧值；不能拼接新旧字段。

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

Windows profile decoder 只接受现行 DPAPI envelope、Ed25519 身份及认证 LKG；P-256/证书旧状态不是
运行时输入，也不得以旧 bundle 或旧网络路径补足缺失字段。

## 最小必要测试集

测试验证模型边界，不枚举平台、受管节点、协议和故障的笛卡尔积。

1. **认证与恢复**：有效签名 LKG 可离线恢复；从已固定的 C0 成员表逐项验证后继表对前表的
   摘要引用、旧成员多数签名、旧签发者截止前沿，以及最终 View 签发者资格和设备绑定。
   缺少中间证明、任意新根、错误签名、已见撤权遗漏和 floor 回退均拒绝；失败不覆盖旧
   信任绑定、前沿、floor 或 LKG。没有显式 `NetworkLink` 时仍可从设备认证私有入口领取配置，
   已有共享首跳可按授权使用。
2. **确定性派生**：相同 LKG 在 Android/Linux/Windows 纯核心得到相同授权候选身份和顺序；相同平台
   能力值生成相同可执行集合，重启结果不变；能力不足时不改变授权候选 ID。
3. **Direct 语义**：Direct 的受管节点链为空，不产生代理入口检查；一跳直达包含最终出口，二者不混淆。
4. **同出口多路径**：同一最终出口同时产生一跳直达和中继；不同 WG/hy2 首跳资源及同节点对的
   WG/hy2 中继 `LinkID` 分别形成候选 ID，资源可按 ID 复用；关闭
   `public_data_ingress` 只删除引用该入口的一跳候选，其他共享资源首跳仍保留；开启它不会自动得到
   `available`；hybrid access 在出口无
   公网入口时仍可通过自己已认证且平台支持的 link 形成候选，不生成本机回环 inbound 凭据。
5. **三态观测**：真实成功、真实失败、缺失/过期/跨网络代分别得到 available、unavailable、unknown；
   同一节点对的 WG 与 hy2 及共享同一资源的不同链路都只按各自 `LinkID` 的真实结果改变状态，未实测者
   保持 unknown；同 ID 链路或资源更新规范内容后，旧 `link_spec_digest` 的链路/候选观测及签名报告失效，
   不影响未引用该资源的候选；ICMP 成败只改变 RTT 提示，不改变三态。
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
13. **共享业务探测**：一份规范 HTTPS 目标池只投影 `DestinationGrants` 所获 Service matcher 覆盖的目标；
    同一 Policy 的两个 Service 分别探测、分别选路，一个成功不使另一个变绿。空投影只使相应业务
    范围保持 unknown，不扩大 ACL、不阻断加入；中继链路的精确目标按 `LinkID` 独立验证。
14. **Linux capture 隔离**：初始 network namespace 的 access/hybrid preflight 与 runtime 均失败关闭；专用
    namespace 中只捕获显式 workload；同机 control + forward + internet_egress 在没有 TUN 时保持业务可用；正常
    停止、child/parent crash、SIGKILL、启动中途失败和重启后，宿主 rule、main route、LAN、WireGuard、DNS、
    代理与 SSH 回读均保持基线，未知所有权对象不会被删除。
15. **DNS 与局域网**：`.loom` 仅精确 A/AAAA、`control.loom` 保留，解析不扩大 ACL；
    获授 mapping Policy 的 access 才得到虚拟前缀及固定网关候选，撤权后精确路由和 DNS 投影消失。
    映射范围没有适用 HTTPS 目标时保持 unknown，真实业务结果只证明所访问目标；互联网 Preference 不受影响。

扩展测试只能在上述最小集合通过后进行，并且发现新场景时优先把它表达为新的候选或观测数据，
而不是新增路由分支。

## 明确禁止

- 不恢复旧 scheduler、probe budget、`min_samples`、预热、挑战者比较或一次性 registry。
- 不按 Service × 候选路径做完整业务扫描，不要求所有出口和所有 transport 都实测一遍。
- 不为未知状态补样本，不用 ICMP 或单段 RTT 伪造端到端健康与 P50/P95。
- 不把 `public_data_ingress`、认证配置或服务端声明解释为当前可用。
- 不因一跳直达存在而删除同出口中继，也不因 `reverse_only` 删除合法公开入口。
- 不把同一节点对的多条 `NetworkLink` 合并为一个候选，也不借另一种传输的观测补绿本链路。
- 不因 `LinkID`、资源 ID 或候选 ID 相同就沿用旧观测；`link_spec_digest` 不匹配时相关选择与报告重算。
- 不从节点字段、硬编码域名或公网探测结果构造业务目标；共享 HTTPS 目标池只按既有授权投影，
  缺少获授权目标保持业务 unknown。
- 不把 Android/Linux/Windows 平台差异写进纯选择规则；Windows Edition 差异只进入 HostAdapter。
- 不持久化派生候选或期望选择来绕过重建与 selector readback。
- 不新增与上述八个概念重复的 manager、store、ledger、gate、phase、receipt 或后台循环。
- 不让 profile 索引、显示名称、UI 选中行、SCM 状态或本机 listener 成为第二网络权威。
- 不读取旧配置 overlay、旧 bundle、P-256/证书状态或旧网络路径作为运行 fallback。
- 不用旧 capability 或任意新信任根读取设备配置；无链路时的现行 device-authenticated 私有入口
  不能把业务或链路状态补成 available。
- 不在开发宿主初始 network namespace 运行 access TUN，不用 endpoint 排除、`auto_detect_interface`、临时主机
  路由或业务成功掩盖缺失的 capture 隔离与 rollback。
