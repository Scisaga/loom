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
| `CertifiedLKG` | 最近一次通过认证并原子保存、由有效 control 签名的完整设备视图；决定离线可使用的授权范围 | 宿主应用成功、全网最新状态或当前网络是否可用的声明 |
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

`Service` 定义目标地址或名称范围；每条 `NetworkPolicy` 固定属于一个 Service，定义 allow/deny
和允许的路径。设备的 `DeviceAuthorization.PolicyIDs` 只选择策略，客户端经策略的固定 ServiceID
解析目标。同一设备同一 Service 最多一条 Policy，不叠加或按顺序挑选规则；不同设备可以选择不同
Policy。未选择、deny、已删除或冲突的策略均不产生该服务的候选、ACL、数据面凭据或探测授权。
Loom 管理的请求命中上述目标时须拒绝，不能因没有候选就回退 Direct、换用较宽服务或绕过捕获。
客户端只消费签名 DeviceView 下发的交集，不从入口存在、DNS 解析或探测结果创造新授权。
互联网 Service 的终点是指定或可选的最终出网节点；`local_network` Service 的终点是固定的
`forward` 网关，不称为互联网出口。策略创建后不能改属其他 Service。

### Direct 不等于一跳直达

- **普通 Direct** 的 `final_exit=direct` 且受管节点链为空：本机不以任何受管出口身份，直接访问目标地址。
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

后两条拥有相同的最终出口，但拥有不同的入口和受管节点链。在策略同时允许这两种入口时，须同时保留为候选，
使“一跳直达失败后仍从同一最终出口经境内中继访问”成为普通选路结果，而不是专用分支。

`public_data_ingress` 是可供客户端使用的一种已认证首跳声明；已有 WG、hy2 等共享
`TransportResource` 也可成为首跳。首跳由 Service、Policy、设备授权与资源共同投影，
不要求为每个设备新建接口或 `NetworkLink`。入口声明绝不表示该入口在当前网络可达。入口可能今天可用、
随后因 UDP 受限而不可用、几天后再次恢复，整个过程都不需要修改认证拓扑。

Policy 的业务入口、中间转发及互联网出口分别使用规范范围 `any / only / none`。
any 表示所有符合资格的当前及未来节点；only 只允许非空的明确 ID 集合；none 不允许此位置的节点。
范围模式缺失或仅有空数组不是 any，须在认证输入处拒绝。only 的节点失效后保留限制并移除相关候选，
不自动变为 any。第一台受管节点须满足入口范围、有效资源及职责；中间节点须满足转发范围和显式
LinkID 方向；最终节点须满足出口或固定 LAN 网关约束。一跳互联网候选的节点同时满足入口与出口范围。
中间范围 none 仍可允许一跳，入口 none 则不产生经网络接入受管节点的路径。

普通 Direct 独立由 `allow_direct` 控制，不经过受管首跳或出口。Direct 允许加出口 only 表示两种
路径都允许；要求只经指定出口时必须关闭 Direct。没有设备限定本地出网许可时，纯 Direct 可用入口 none 表达，不能把旧空入口
集合重解释为不限。LAN Policy 只含 allow/deny、入口及转发范围，没有互联网 Direct/出口字段，
入口选择只能改变到固定网关的路径。这些检查均从所选 PolicyIDs 解析，不新增本机授权策略。

`NetworkLink` 的连接发起端必须满足端点的 `direction` / `reverse_only` 约束；这些约束不删除节点的
公开数据入口候选。授权、链路方向和实时可达性是三个不同事实。

`NetworkPolicy.allow_direct` 表示选择该 Policy 的 access 才可为其固定的互联网 Service 产生 `final_exit=direct` 的普通 Direct
候选。它不能表达“只有某个 hybrid access 在本机充当该 policy 的固定出口”。后一语义由规范排序的
`local_egress_devices` 表达：成员必须是该 policy 的获准最终出口、具备 `access` 与 `internet_egress`
能力；只有授权设备 ID 命中时才生成受管节点链为空、`final_exit` 为该设备稳定 NodeID 的本地出口
候选。空链表示本机执行、不经网络隧道，不能抹去逻辑最终出口身份。候选 ID 同样绑定该 NodeID；
其他设备仍把该节点当作一跳或中继出口。普通 Direct 与设备限定本地出网的授权来源不同，不能在
导入时把设备级许可提升成全 policy 的 `allow_direct`。Auto 可选择该本地候选，指定本机 NodeID
作为最终出口时也保留它；Direct 模式只选择 `final_exit=direct` 的普通 Direct，不选择设备限定本地出网。
本地出网没有业务首跳，不套用入口范围，也不要求回拨本机或提供入站资源。

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

候选生成枚举获准路径；验证已有候选时只沿其明确的节点链和 LinkID 逐跳核对入口、中间节点、
出口、跳数、资源与方向，再从相同规范输入重算完整身份和规格摘要。不能为每条候选重新枚举
整张图。两种计算必须得到相同路径；同 ID 的旧规格、被禁位置或跳过邻接均拒绝。这个调整不改变
domain、wire、持久值、运行配置或 UI 的映射，也不增加缓存权威或操作步骤。

Linux hybrid 节点同时承担当前 `access` 和 `forward` 职责，且它与最终出口之间存在可用方向的认证
`NetworkLink` 时，可以直接使用该链路，不要求自己或出口另有公网数据入口。该候选的规范受管节点链以本机
hybrid 节点开头，运行时跳过“拨回本机 inbound”，按 `LinkID` 引用的资源连接下一台受管节点。
当前 WG 业务中继使用用户态原生会话及精确来源投影，不依赖宿主管理接口路由，也不在 WG
内建立 Hy2 或私有 TLS 代理会话。数据面投影不得为这个本机起点生成回环 user/ACL。Web 拓扑展示时省略链首
重复的本机节点，但 candidate ID 与签名报告仍保留完整规范链及链路 ID。

### 候选身份

普通 WG 首跳必须独立认证和承载业务，不能通过 WG 内的 Hy2 会话复用权限。
现行[执行投影](../core/current-contract.md#分段传输的替代执行模型)使用原生 WG 接收与逐段业务转发，
实际部署见[传输实现纠偏](../progress.md#传输实现纠偏)。Service/Policy、候选身份、真实观测和撤权要求
继续成立；不能把“资源类型标为 WG、实际业务仍依赖 Hy2”当成独立 WG 接入完成。

Windows 的 WG underlay UDP socket 保留请求的地址族。省略 IPv6 监听主机时，在底层适配器内
显式使用 IPv6 通配地址，避免向 IPv6-only socket 施加 IPv4 网卡绑定选项；端口、网卡及允许
流量范围不变。此归一化仅是运行时映射，不改签名配置或持久身份，也不增加路由、配置键或候选。

`RouteCandidate` 的稳定身份由 Service 范围、首跳资源 ID、规范化后的受管节点链、每条中继边按顺序排列的
`LinkID` 及终点确定；互联网终点标明最终出口，`local_network` 终点标明固定网关。普通 Direct 和
设备限定本地出网的首跳资源、节点链与链路序列均为空，但前者终点为 `direct`、后者为本机 NodeID，
因此身份不同；不能仅凭空链重建为 Direct。一跳直达只有首跳资源、没有中继 LinkID。
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

完整业务探测的 DNS 地址和 HTTPS 目标都来自同一份认证 `DeviceView`。DNS 地址来自设备授权中的
规范解析器集合，首次加入可由 Invite 配置；HTTPS 目标来自 `NetworkIntent` 中一份规范排序、去重、仅含 HTTPS URL 的全局业务探测
目标池，不要求每个 access 节点手工填写。服务端先解析该设备的 `PolicyIDs`，过滤出有效 allow 策略及其固定 Service，再只把
主机名被这些 Service matcher 覆盖且授权允许的 HTTPS URL **按 Service 分别**投影为 `BusinessProbeTargets`，
不建立第二个权威 `ProbeGroup`。不同设备/Service/Policy 范围的实际业务结果不得互相借用。无匹配目标时，
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
尚未取得 View 的首次 bootstrap 先验证完整 Invite，并使用其中已签名的解析器查询其固定签发者入口；
同事务恢复复用原身份、request ID 和 Invite。具名入口缺解析器时拒绝，字面地址不查询 DNS；不从业务运行时
反推 bootstrap 权威。取得 View 后改用当前 View 的解析器；两条连接共用保留平台 socket 保护的 underlay 适配。
Android HostAdapter 在本机执行投影启用 libbox 的平台接口控制，使其 TCP/UDP underlay socket 实际调用
`VpnService.protect`，否则隧道自身会重新进入 VPN。私有配置/报告使用的认证 Endpoint IP 还须以精确
`/32` 或 `/128` 从 capture 中排除；这是从同一 View 单向派生的本机路由输入，不授予 Service 权限。
Android 私有配置/报告的 Go socket 与 DNS 查询同样使用活跃 VpnService 的 protect 回调；该回调在 capture
之前安装，在确认关闭后撤销，失败则拒绝连接。具名 Endpoint 只经 View 的规范解析器查询，逐次拨号使用
所得 IP，原 TLS 名称及 SPKI 保持；不把可能变化的域名答案当成永久 TUN 排除。纯渲染不查询 DNS，
字面 Endpoint 仍产生上述精确排除。未配置解析器的具名入口与资源明确失败，不借系统 resolver 或 hosts。
解析器来自 Invite 的初始设备配置或随后普通 device.put；业务权限变化不应无意移除未编辑的 DNS 配置。
Linux 内核 WG 的域名同样只由 adapter 使用这些认证解析器查询，纯资源投影不查询网络。发起端在安装前
将结果转为精确 IP:port，内核 `wg` 不接收域名，回读必须匹配该精确地址和认证公钥。同一次解析按名称复用，
答案规范排序；仍在答案中的本代地址优先保留，否则取排序第一项，不将解析顺序解释为可达性排序。
正常刷新重新解析；答案变更确需换地址时，先按本代所有权停止和清理，再从同一已接受 View 重建。
已有认证配置不变时，临时解析失败保留本代地址和身份，不制造健康结果；首次执行或接受新配置后解析失败
不能借旧解析器或宿主 resolver 运行。重启重新解析，不持久化 DNS 答案或倒写签名资源、LKG、授权及端点身份。
正式入口仍是普通 resource.put 与设备 sync/run；UI 回读既有 runtime/业务观测，不增加 DNS 完成状态。
最小验证覆盖字面地址无 DNS、认证解析/拒绝 fallback、多个答案与同名复用、地址变更和真实 WG 中继业务。
这项 Android 平台 socket 控制不证明 Linux 初始 namespace 的 auto_route 安全，不能用于绕过宿主门禁。
Linux HostAdapter 只在隔离 capture namespace 内将这些 underlay endpoint 的解析结果以逐主机 `/32` 或
`/128` 投影为 TUN 的本机 `route_exclude_address`，使私有控制、引导、
报告和 tunnel 连接不依赖某条业务 policy；认证 RuntimeProfile 不得自行提供或扩大该字段。DNS 变化时重新
解析、重建本机投影，旧结果不是权威也不能扩成网段。这个排除只防止 endpoint 递归进入 TUN，不是宿主 LAN、
管理面或默认路由的安全边界。

### TUN 域名目标的传递

正常入口是应用先经 TUN 查询服务名称，再连接返回地址。仅把 DNS 反查或 TLS/HTTP 名称写入本地
匹配元数据不足以完成这条链：Hy2 仍会发送原 IP，接收端的域名 ACL 必须拒绝。HostAdapter 因而只对
进入 `tun-in`、命中当前 Service 域名 matcher 的 A/AAAA 查询使用数据面的本机合成地址映射；
包含拒绝规则中的名称，以免较宽 IP 服务绕过域名拒绝。其他 DNS 查询、Mixed 请求、私有 control 和
数据面自身的 underlay 解析仍使用认证解析器，不进入该映射。

映射只恢复请求的 FQDN 与端口，随后完整执行原有歧义拒绝、Service/Policy 和 selector；最终出口
解析该 FQDN。字面 IP 保持 IP，不能因 SNI 或此前同 IP 的 DNS 答案变成域名请求。接收端继续只按
Hy2 实际目标授权，不启用接收端 sniff 或扩大 IP ACL。明确指向映射池内部的真实目标前缀须拒绝执行；
较宽的默认 IP 范围不把本机映射池声明为真实目标。合成地址仅存在于已授权的 capture 边界，
两族答案都须被捕获。没有认证解析器时不补系统 DNS 或公共默认值。

domain、wire、持久和 UI 均沿用现有 Service、签名 View 与报告；不修改已认证 RuntimeProfile 字节。
本机 DNS 配置和地址映射是单向运行投影，不是新增权威。映射缓存不得保存授权或决定 selector，
停止、撤权和重启均须重新执行当前 LKG 的规则；缓存不能让已撤权名称恢复。重启须保留仍被应用缓存
的地址对应的原名称，不能重新分配给另一名称。丢失映射的连接拒绝，应用须重新查询；缓存可删除重建，
但删除前须停止该 capture 的 workload 并清除其 DNS 缓存，不能运行中自动清空或以缓存恢复代替授权验收。
新增操作成本限于受保护的本机映射缓存，无新的配置键或管理入口。
Windows 同一交付形态的配置共用受保护的本机映射缓存，切换配置仍重新检查各自授权，不共用身份或 LKG；
Android 的单 VPN 使用应用私有缓存，Linux 缓存与隔离 capture 的运行目录绑定。缓存损坏保持原字节并拒绝启动。
地址与名称必须在 DNS 回答前耐久保存；分配位置落后时跳过已有地址，地址池耗尽时拒绝，不能通过循环复用
改变仍被应用缓存的目标。未修复这些恢复语义的数据面制品不得执行该域名 capture。

最小验证为实际 TUN DNS → Hy2 FQDN → HTTPS、IP 前缀请求保留 IP、任意 IP 携带允许名称的 SNI
仍被接收端拒绝、underlay 查询不返回合成地址，以及正常/异常重启与撤权后旧地址不改变目标或复权。

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

Linux adapter 新产生的业务失败观测保留 30 秒，成功观测仍保留 10 分钟。目标是让暂时失败的
Service 在正常刷新中自动恢复：实际 SSH 加入验收中，首次失败后同一授权路径已能完成 HTTPS，
旧实现却因失败和成功共用 10 分钟窗口而持续拒绝业务。最小变化只调整新失败观测的 `valid_until`，
不增加调度器、配置项或权威实体；代价是没有可用候选时，必要候选最短每 30 秒可重测一次，
已有可用选择时仍不扫描其他路径。这不是所有平台的最大观测寿命或多目标归约算法。
domain/wire/持久状态继续使用原 Observation，runtime 按其原始截止时间选路，UI 和报告原样投影；
重启或升级不得缩短已保存观测的有效期，也不清空失败结果。最小验证覆盖有效失败不重试、
到期后的真实恢复探测、成功结果复用、升级保留旧截止时间，以及实际 selector 拒绝与恢复 HTTPS。

底层网络代变化后，上一代观测不再决定当前状态，候选先回到 `unknown`。启动和切网
都不得等待观测齐全；缺失观测保持未知，也不得通过补样本制造健康状态。

### 公开 Hy2 首跳的认证样本

目标是分别回读首跳认证与完整 Service 请求。现有 Service 探测只能说明完整请求结果，Link 样本
只覆盖节点邻接；两者都不能给出普通 access 到公开资源的认证结果。最小变化是复用既有
Observation 的 resource 层及已授权首跳凭据，按[现行契约](../core/current-contract.md)执行和验证，
不增加资源、用户、权限、配置键或健康权威。额外运行成本是当前选择所需的每个公开首跳每个有效
窗口至多一次真实认证，多个 Service 共用首跳只采一次，已有选择先应用再采样。

领域值和签名报告均为原 Observation；control 按当前 View 验证后使用原签名历史持久化。
客户端的首跳执行参数是从当前认证 View 单向生成的临时值，不能编辑或倒写；Linux 在原本机
runtime.json 中以可选 resource_observations 保存诊断缓存，旧文件缺席字段的规范字节不变。
同一文件锁保留并发 CLI Preference，升级、重启和无关 View 变化保留仍能证明执行输入相同的
样本及原截止时间；身份/网络或执行输入变化精确失效。status 和设备页面显示原资源 ID、动作、
目标、结果、时间及完整认证耗时；它们不参与权威往返或宣称整个 Service 健康。

正常链为正式加入/刷新、应用并回读当前选择、必要首跳真实认证、原私有签名报告、daemon
持久化、Web/CLI 回读及重启恢复。反例是同一资源的认证成功但 Service 目标拒绝：资源样本
可以成功，该 Service 仍失败或未知；不能用资源成功抹去业务失败。
最小验证覆盖共享资源去重与独立资源并行、Direct/本机/Link 起点无公开采样、真实认证及错误
TLS/凭据拒绝、取消不造样本、原窗口复用和到期恢复、同 ID 参数/授权变更失效、严格签名报告
拒绝与正式入口重启回读。普通 WG 首跳、三端接线、首跳参与选路及多目标归并的完成情况分别
以实施状态为准，不从这项模型修订推定已经实现。

Windows 的同一正式连接入口在 selector 应用并回读后调用共用首跳认证函数；本轮新增的只是原
Observation 的平台采集和报告接线，不增加授权、凭据或选择算法。三个交付形态使用同一实现。
原运行状态投影增加可选的资源样本，原私有报告按 resource、service 的规范顺序发送；资源样本
变化参与原报告刷新判断，原生页面仍从 Service 观测解释业务状态，管理设备页面回读原资源样本。

Windows UI 读取可删除的 `runtime/status.json` 时允许删除共享，写入在同目录同步临时文件后
原子替换名字；已打开的读者读完原快照，下一读者取得新快照。这样 GUI 轮询不阻断实际运行和
报告更新。停止删除状态文件，正在读取的句柄关闭后完成删除；缓存存在不能恢复连接。
身份、profile 与认证 floor 继续使用既有持久化规则。本修订不新增文件或操作者输入；最小验证
覆盖持有旧读句柄时替换、完整的新旧快照及停止删除，再走原生连接、撤权和重启业务链。

为使同网络代的重启不重采仍有效的样本，Windows 在 profile 的受保护目录内保存可删除的
`runtime/resource-observations.json`。它恰为规范 `schema=3,identity_digest,observations`；后者为
按 ResourceID 唯一排序的原资源样本，保留成功、失败和原时间，最多 8 MiB。identity_digest 为
`SHA256("loom-resource-observation-cache-v3\0" || C({network_id,genesis_digest,device_id,device_public_key,platform}))`，
只从已认证 LKG 生成。该摘要与样本均为可重建的缓存，不是身份、第二份 LKG 或连接状态；不能倒写
DPAPI profile、Preference、selector 或权限。删除缓存只意味着下一次需要时重新执行真实认证。

每次恢复先核对身份摘要，再按当前首跳规范及实际网络代筛选；无关 View 变化保留仍匹配的原样本，
资源、凭据、DNS、身份或网络代变化使对应样本失效。恢复样本与当前进程采样均须满足这些条件；正常停止
保留缓存但删除原运行状态文件，不把缓存存在解释为仍连接。唯一数据面进程锁排除并发采集写入，
原子替换保存缓存。缺失文件可重建；非规范、歧义或损坏缓存拒绝复用并保留原文件，本轮资源采集
保持缺失，不阻断仍获授权的 Service。写入失败保留原文件，真实样本仍可在当前进程使用，但不声称
能跨重启恢复；原日志记录错误。缓存不含凭据，既有 profile 隔离及目录访问权限继续适用。

新增操作成本仅为一份有界诊断缓存；正式验证须覆盖身份与网络代隔离、无关刷新和同代重启保留
原时间、缓存严格拒绝、实际认证失败与恢复、签名报告及设备页面回读。不能用单元测试或交叉构建
抵扣同机 Windows 的实际连接、报告、重启和正常停止；实体终验边界不变。

Android 复用同一公开首跳采样、规范缓存及签名报告模型。原 `VpnService` 的运行回读与
RouteManager 的 selector 回读确定本轮实际选择，原报告循环随后按需采样；DNS 和 QUIC socket
沿既有 `VpnService.protect` underlay 拨号。资源成功不修改 Service 观测、偏好或 selector。
现有连接生命周期锁与路由操作锁覆盖采样输入，原报告序列仍须由受保护身份记录先耐久预留。

同一缓存规范保存于各 profile 的 Keystore 保护槽 `p.<id>.resource-observations`，与 Windows
仅宿主持久位置不同；domain、签名 wire、control 原件及 Web 投影均不增加字段或权威。每轮从
已认证 LKG、实际选择及当前网络代校验、采集，再原子保存缓存，最后进入原私有报告入口。
正常停止保留原样本但不报告运行或当前资源健康；删除 profile 同时删除该缓存。网络代、身份或
资源执行输入改变精确失效，无关 View 更新及同网络代重启保留原样本时间。损坏缓存保留原件、
拒绝采样复用并记录错误，不阻断仍获授权的 Service；写入失败时只在本进程复用已经得到的原样本。
缓存存在、采样成功或报告成功均不能产生 active VPN。

Android 的最小验证为受保护实际 socket 的认证、资源与 Service 结果分别签名回读、当前授权与
网络代筛选、无关刷新和进程重启保留原窗口、实际认证失败与到期恢复，以及撤权和停止后的报告。
共享去重、规范拒绝与 TLS/凭据校验沿用共用测试；还须经同机模拟器的正式加入/VPN 入口、真实
业务及管理浏览器验证。模拟器、交叉构建及签名 APK 不抵扣用户负责的 ARM64 和物理网络终验。

## 局域网 Service 范围

具备 `forward` 职责的网关可认证报告自己的本地 IPv4 前缀；报告本身不产生共享权限。
control 签发的 `local_network` Service 值给出稳定映射 ID、网关节点、本地前缀、等长的虚拟前缀和
固定网关约束。access 的 `PolicyIDs` 选择了属于此 Service 的有效 allow Policy 后，签名 DeviceView 才向它
下发虚拟前缀及到**固定网关**的获授权候选。access 不得提交任意 CIDR 或从网关报告自行生成路由。

`local_network:<mapping_id>` 是独立的 Service scope。客户端只对该虚拟前缀建立精确业务捕获与
路由，在到固定网关的一跳或中继路径中自动选择，不把网关误作互联网最终出口。开发宿主上
这些路由、策略规则和 DNS 投影只能在专用 capture namespace 内应用，不进入初始 namespace。
互联网业务的 Direct、Auto、指定最终出口 Preference 维持原有语义；局域网 scope 的候选不受
这三种互联网偏好裁剪，只在到固定网关的授权路径内自动选择，也不成为互联网 Auto 的捷径。
网关按同一授权检查，完成目标地址按主机位对应的转换，并在 LAN 主机没有
回程路由时做必要的源地址转换。只有 overlay 端能主动发起连接；LAN 主机可回复，不能凭映射主动
建立到 access 的会话，不修改 LAN 路由器。

现有原生传输已在接收节点终止 TCP/UDP。LAN 的最终网关因此在获授权的 direct 拨号器内完成
等长前缀转换：配置 `prefix_mapping:{virtual_prefix,local_prefix}` 只由该 Service 单向生成，
保留主机位与目的端口。接入和中继仍传递原始虚拟目标，只有固定网关可转换；不能同时设置 detour
或单地址/端口 override。物理连接由网关本机发起，LAN 回包自然回到同一 socket，不需安装宿主 NAT
或允许 LAN 主动连接 overlay。UDP 每个会话只允许原始目标及其对应回复，不能借已建立 socket
发送到范围外地址或从另一 LAN 主机注入数据；TCP 半关闭须保留返回方向。
域名解析结果仍须处于虚拟前缀，转换层拒绝未解析名称、IPv6 和范围外地址。该执行配置是可再生投影，
不改变 schema 3，不产生新的传输协议、密钥或权限；所有授权仍由原 Service/Policy 的接收规则承担。

一个网段若没有适用的共享 HTTPS 目标，主动完整业务可用性是 `unknown`，不能从 WG/hy2 握手或
任一 LAN 主机的结果推断整个网段可用。真实业务访问可生成**该目标**范围的 Observation。
映射撤销、策略撤权或网关身份失效时，客户端移除相应精确路由、DNS 投影和候选；已见撤权 floor
不得被较旧 DeviceView 重新降低。自动分配的虚拟前缀是 control 签名事实，不由客户端重算或猜测。

## Preference 与 Selection

`Preference` 只表达 Direct、Auto 或指定最终出口三种意图，不包含延迟、吞吐等额外的用户排序目标或开关。
选择函数先按授权与平台能力过滤候选，再按这三种意图限定范围：

| 模式 | 候选范围 |
|---|---|
| `Direct` | 仅 `final_exit=direct` 且受管节点链为空的普通 Direct 候选；不创建代理入口探测 |
| `Auto` | 当前互联网 Service 范围内所有由 `CertifiedLKG` 授权且平台可执行的候选，包括设备限定本地出网 |
| 指定最终出口 | 所有最终出口为指定 NodeID 的候选，包括一跳直达、中继，以及指定本机时获授权的本地出网 |

在范围内，已知可用候选优先于未知候选，已知不可用候选不参与新选择。比较只能使用同范围、
仍有效的实际指标；不同观测范围的数字不能直接比较，缺失指标不能补零。没有可用候选时，
允许确定性地尝试未知候选，而不是等待测量。当前实际选择仍符合授权、平台能力及偏好范围，
且未被有效结果判定不可用时，没有更优的可比较证据就保持它，避免无理由切换。
排序是一次纯计算，不需要挑战者状态、采样收敛或额外状态机。ICMP RTT 最多只能为同类入口
提供次级提示，不能覆盖真实 transport / business outcome。

必要 fallback 必须能继续尝试其他获授权路径。反例是刷新耗时超过失败观测的有效期：每轮只尝试
两个最小 ID，然后两条失败同时过期，若只按 ID 重选，后面的可用路径永远不会被尝试。
最小修正仅复用同网络代、同候选保留的最新 Observation：过期仍使健康状态变为 unknown，
但在 unknown 内，尚无失败或最新结果成功的路径先于最新结果失败的路径；后者按失败发生时间从旧到新
尝试。此顺序确定后再保持当前选择、以稳定候选 ID 打破平局；有效 available 仍优先，有效 unavailable
仍排除，不为改善排序延长或改写任何观测的有效期。新的成功或失败替换本候选的旧结果，换网后旧代
记录不影响尝试次序。没有新增重试字段、持久对象、调度器或操作者步骤。
domain、wire、持久状态仍为原 Observation；纯选择函数只读取它，runtime 继续至多做一次必要 fallback，
UI/报告仍按原有效期显示健康状态。最小验证覆盖慢刷新下可到达第三条路径、全失败后先重试最早失败、
当前成功路径保留、换网和指定最终出口过滤；该公平性修正不定义多目标归约或新的性能偏好。

某 Service 的所有候选暂时不可用时，该 Service 不产生新的 Selection；其他 Service、服务节点 listener
和认证修复通道继续运行。Linux HostAdapter 在已验证 profile 的每个 selector 中加入既有 `reject` block
作为本机拒绝位置，并以它为启动默认值：它不是 RouteCandidate，不进入授权、Selection 或报告中的候选集合，
也不能转发流量。签名 profile、LKG 和候选成员原字节不变，增加的只是运行时拒绝投影。
每次正常刷新按当前授权、Preference、网络代和观测有效期重算；失败观测过期后成为 unknown，才允许再次
选择并进行实际业务探测。失败不能清空观测以强制重试，也不能等待必须修改权限才能恢复。
反例是单条路径在服务端尚未消费新授权时失败：它暂时拒绝该 Service，不能因此停掉其他服务或将整个
数据面留在永久等待配置修复的状态。selector 应用/回读、进程、认证持久化或网络清理失败仍按原失败关闭规则处理。

上述原则已经确定，但尚不足以构成完整的选择算法。以下问题须在实现排序与归约前明确，
不能由旧实现、测试或原型中的单个例子替代决定：

| 待确认问题 | 已有约束 | 尚缺的决定及受影响行为 |
|---|---|---|
| 同 Service、同候选的多个目标结果如何归约 | 每条结果保留实际目标、动作、网络代与有效期；一个目标成功不证明其他目标成功。 | 同时存在成功、失败或未知目标时，如何形成供选择函数使用的候选结果；例如 `web.example` 成功而 `api.example` 失败，不能仅取最新一条就宣布整个 Service 可用或据此断开 VPN。此决定影响候选是否参与选择和必要 fallback。 |
| 多项可比指标的优先级 | 只有同范围、仍有效且实际测得的值可比较；入口 RTT 不冒充完整 HTTPS 耗时，缺项不补零。 | 多个合法候选都有有效结果时，哪些指标用于排序、适用条件及优先顺序是什么；缺少足以比较的指标时不能宣称某候选“最快”。此决定不新增用户偏好选项。 |

观测时间、最大寿命与时钟偏差的字段边界另见[现行契约的字段级阻塞](../core/current-contract.md#已确定的签名边界与字段级阻塞)。
这些缺项不改变三种 Preference、授权过滤和实际 selector 回读的边界，也不授权各平台各自补一套算法。

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
| `Preference` | Direct、Auto 或指定最终出口 | 私有签名 Report 的可选 preference 只读投影本次采样读取的本机设置，不是设置同步 | 只保存一份本机用户设置；报告历史不成为设置权威 | 作为纯选择函数输入；停止或执行失败仍可上报保存的设置 | 客户端唯一可编辑的选路意图；Web 分别展示已报告设置、原时间和实际选择 |
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
   签发者事实前沿及设备绑定。除经连续多数证书明确封存的验证键按封存序列验收外，已见撤权不得在新 View 中消失；通过后与信任绑定、已见高水位
   原子保存为 `CertifiedLKG`。事实及其因果依赖由签发 control 验证；设备没有全网事实，不能独立重算
   该闭包。签名 View 不能证明没有尚未传播的撤权。
3. 纯核心逐项解析该设备 PolicyIDs，从有效 allow Policy、其固定 Service、首跳资源、节点链和有序 `LinkID` 派生授权候选，再按平台
   实际能力投影可执行候选；`HostAdapter` 按资源 ID 复用并安装必要运行配置。首份 View 没有
   `NetworkLink` 时仍可经设备认证私有入口领配置，并按授权使用共享首跳。
4. 有可执行业务候选时，按 `Preference` 立即选择一个被授权且未被证明不可用的候选，应用并回读；
   没有时业务保持 `unknown`，仍可经现行私有入口领取修复 View 和报告。
5. 并行采集必要的真实 transport outcome；结果到达后再以同一纯函数重算。

第 4 步不等待第 5 步，所以首次启动不会被测量阻塞。
Android 在签名、成员链、设备绑定、floor 和受保护原子写入回读通过后保存该 profile 的
`CertifiedLKG`；`active_profile_id` 只在 libbox 配置校验、VPN 启动及 selector 实际运行回读后产生。
运行应用失败时不把该 profile 画成 active，旧运行路径只有仍获新 View 授权才可继续。
后续 DNS/HTTPS 结果只决定相应 Service 的业务观测，
目标缺席为 `unknown`，真实失败为 `unavailable` 并按同一选择函数尝试必要 fallback；
不能因目标缺席或探测失败删除已认证的 LKG，也不能把 active 画成业务健康。

### 进程重启与离线

1. 从安全存储加载身份与信任绑定，重新验证持久化的 LKG。
2. 确定性地重建候选。
3. 先读取宿主 selector；仍被授权且未被当前结果证明不可用时保持它。
4. 没有可保持的实际选择时立即选择一个合法候选，不等待控制面或观测。

控制面不可达时继续使用认证 LKG。认证失败、未经封存证书授权的事实前沿回退或没有任何合法业务候选必须明确报错，
不能退回旧网络路径；业务候选缺失不阻止已认证设备经现行私有入口领取修复 View 和报告 `unknown`。

### 新认证配置

新 LKG 只有在签名、设备绑定、成员链证明、签发者事实前沿和 floor 全部通过后才能替换旧值。
成员变化时，envelope 必须从设备已固定的成员表起提供连续的后继表，每步引用前一表摘要，
由旧表计算出的多数在同一轮次签署同一提案，并携带失去资格的验证键的封存序列。客户端逐步核对
网络锚、成员 ID 与验证键、签名集合、封存序列及最终签发者资格；不接受仅由新表自签的跳跃。
没有成员变化时证明序列为空，但仍必须验证签发 control 当前有效。
新 View 的事实前沿对未封存键及同键未触发例外的历史单调，不能遗漏仍有效的撤权或冲突事实。只有连续
多数成员证书明确封存某验证键时，才可把**该键**的验收前沿降至证书封存序列；原已认证高水位、
不可回退 latch 继续保存；旧 LKG 在新值验收失败时保留，验收成功后仍只保存一份当前 LKG。其他键、成员链及现网全局认证 floor 不回退。
留任 control 把自身证书验收前已持久接受、可取得原始证据且超过封存点的撤权自动重签为
引用原事实的有效后继事实，并在放宽本机运行授权或交付新 View 前核验其效果；原始证据全失时无法重签，设备仍可凭证书接受新 View，可能恢复未知的旧权限。
设备在替换前对比旧 LKG 与新 View 的可见授权差异，必要时记录非权威诊断事件；高水位超过封存点时 UI 标记可能复权，但不能由 View 或 floor 反推全部遗漏撤权。
留任成员序列跨换届连续；同一有效事实集合的投影不因本机曾见事实而异。
只有完整 View、成员证明与对应验收前沿均通过，才原子保存信任绑定、前沿、LKG 与原已见高水位。
漏项、乱序、旧格式事实、任意新根、验签或落盘失败均保留旧 LKG 与原高水位。
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
事实集。新 View 的签名、规范形状、设备绑定、成员证明与前沿校验通过后，先原子提交唯一新
LKG、信任绑定及 floor，再按新授权收口运行投影。宿主 preflight、组件验证、进程启动和运行回读
属于后续应用，失败不能撤销已经接受的认证状态或恢复旧授权。
同一进程监督器按 `TransportResource` 类型应用需要的 WG interface/精确路由或 hy2、私有 TLS tunnel
配置，启动新的运行代，再读取实际 listener、selector、链路资源和配置摘要；全部成功后才报告新 View 已运行。
新代失败时只回收本 generation 的执行对象。旧配置或资源只能在逐项证明其候选、凭据、ACL、入口及
其他执行输入仍符合新 LKG 时继续或恢复；不能证明时停止相关业务流量，保留设备认证的配置、报告及
修复入口，显示“认证配置已更新，运行未应用”。下一次尝试继续消费同一新 LKG，重启也不恢复旧权限。
例如新 View 撤销服务 A、同时更新资源 B，B 启动失败不得使 A 的旧路径重新接纳连接。
这个“运行代”只是进程内调用边界，不持久化、不形成阶段表或第二份 authority。

#### 私有通道中断时的显式配置交付

管理 UDP 路径失效后，修正资源端点所需的新 View 不能依靠该失效路径送达设备。已有正常
同步验证签名并写入唯一 LKG，现有 control 也能导出同一签名 View；缺口只是 Linux CLI
没有消费该文件的正常同步入口。最小变化是 `loom client sync -view <file>`，由操作者经
既有受保护管理通道交付 `control export-device-view` 的原件，显式指定后执行普通的当前
View 解码、验签、设备/平台绑定和认证前沿检查，再原子保存同一 LKG。省略该选项仍只走
设备认证通道；不会自动寻找文件或读取历史配置，也不调用历史迁移 reader。

领域、签名 wire、persistent、runtime 和 UI 对应关系不变：文件只是现有 DeviceViewEnvelope
的临时交付物，不拥有身份、版本或完成状态。文件须为有界、owner-only 的普通文件，保留
规范原字节；未知字段、非规范编码、错误签名、其他设备或平台、旧前沿均拒绝且不改状态。
同一有效 View 可以重试，报告序列、偏好、身份和不可回退进度保留。已保存后重启失败仍
保留新授权，不能回退旧文件；正式运行和报告必须另行回读。新增操作成本仅为失效路径修复
期间显式导出、私有交付、同步和重启，无第二配置库或常驻传输。反例是将另一节点的有效
签名文件送到本节点：管理员交付本身不能覆盖设备绑定。最小验证覆盖正常前进与重启、
上述拒绝及失败不写状态，生产修复还须通过正常私有同步和报告证明通道恢复。

#### Linux 更新时保留未变的执行输入

目标是普通设备改权后及时收口它的权限，同时让其他设备仍有效的路径结果继续参与选择。此前 Linux
实现按整个 View 摘要清空观测，并在每次运行代退出时删除全部 WG 接口；即使本机 access 路径和 WG
资源未变，也会重新探测并重建握手。修正只细化这两个派生边界，不增加操作者配置、持久权威或选路算法。
共享 Hy2 listener 为撤销旧凭据和存量会话而重启的规则保持，本项不保证该 listener 的合法连接完全不中断。

观测复用的输入是同一进程持有的前一份已认证 LKG、新接受的唯一 LKG、当前底层网络代及原观测缓存。
缓存原绑定必须等于前一 View 摘要；网络锚、设备身份、公钥、平台和网络代必须一致。逐候选比较
稳定 ID、Service scope、完整候选规范摘要、认证 DNS、同一 Service 的唯一真实业务目标，以及该候选
outbound 和递归 detour 的全部规范执行字节，包括凭据。只有这些输入完全相同，才能保留对应的已知
业务动作观测；目标不唯一、动作来源不能证明、候选删除或任一相关输入变化时丢弃该条。新 View 的规范
校验已拒绝目标的跨 Service 歧义，不能绕过它进行复用。遍历及保存继续按稳定候选 ID 排序。
原结果、测量时间和截止时间逐字保留；复用不制造新的成功、不延长有效期，也不清空有效失败来强制重试。
在原缓存文件锁内完成筛选及 View 绑定更新，并保留同期 CLI 写入的 Preference。重启或缺少前一份
已认证输入时，摘要不同的缓存仍保守失效，不能根据候选 ID 猜测旧权限。

WG 的复用只接受本进程成功创建后仍持有的精确所有权句柄。新 View 投影的资源、当前认证 DNS 解析
所得地址、本机公钥与原执行值须一致，再回读接口代、alias、类型、地址、peer 和精确路由。任一
资源变化或撤销时，按原所有权先清理再应用；所有权冲突或清理失败保持 failed/inactive，不自动重试。
新配置预检或应用失败、正常停止及异常退出仍清理本进程拥有的对象；只有确认清理成功才报告 stopped。
崩溃后的外部清理继续只消费原公开所有权记录，不能凭记录、旧 LKG 或相同接口名接管另一进程的接口。

同一 WG 资源可参与多条 Link，不能把第二个对端误判为接口冲突。领域与签名 wire 仍为原资源和
Link；执行时先按本机接口归组，固定资源 ID、本机地址和公钥，每个对端分别保留公钥、精确
AllowedIP、建连方向、拨号端点与 keepalive。相同对端的反向业务 Link 去重；同公钥的异值、
不同对端复用同一地址、本机身份冲突均在修改内核前拒绝。组内任一接收方向需要固定监听时，
接口使用原资源的监听端口，其他发起方向仍各自发起连接；全部为发起方向时保持内核临时端口。
按接口名和对端公钥稳定排序，不因 Link 遍历顺序改变执行结果。

同一接口只创建和清理一次，原所有权记录以同一 kernel token 保存完整对端集合；旧单对端记录
的字段与含义保留。运行回读必须找到全部预期 peer、地址和精确路由，清理只允许预期集合内的
对象，额外 peer、路由或身份变动均失败关闭。一个 peer 撤销后，新执行中不得残留其地址权限；
其他 peer 没有因此获得额外目标权限。该归组不改权威持久值、候选身份或 UI，不增设参与者表。
最小验证覆盖共享接口的两个真实 TCP/UDP 对端、混合建连方向、单对端撤销、重启清理和外来
peer 拒绝；实验全部在独立网络与挂载 namespace 中执行。普通 access 的 WG 接入和服务授权
仍须单独沿正式入口完成，不能以共享接口测试抵扣。

domain、wire 和身份持久层仍使用原 CertifiedLKG 与 Observation 语义，不增加字段或 schema。
唯一当前 LKG 仍先耐久接受，原 `runtime.json` 只保留可删除的观测及唯一 Preference；前一 LKG 和 WG
句柄只在进程内用于比较及清理，不可成为运行 fallback。runtime 必须应用新 ACL 并重新回读 selector，
UI 和报告只投影该回读及保留原时间的观测，不把句柄复用当成业务成功。

最小验证覆盖：无关改权保留原观测时间；同 ID 的规范内容、凭据、DNS 或目标变化使相关观测失效；
缺少旧输入及重启拒绝猜测复用；同期 Preference 不丢失；精确 WG 句柄保留、变更/撤销清理和替换接口
拒绝。最后沿正式改权入口验证未改权设备的既有路径、改权设备的实际拒绝及恢复、正常/异常停止和重启
后的资源与管理连接回读。单元测试或原接口仍存在均不能抵扣这些运行结果。

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
- 匿名 namespace 与进程句柄绑定一个运行 generation，不创建宿主 veth 或 firewall。正常停止、child/parent
  崩溃、SIGKILL、启动中途失败和重启恢复均终止所拥有的应用树并关闭引用；不得按共享 table 或 rule 范围 flush。
- cleanup 及宿主不变量回读成功前 service 不得宣称 running，也不得自动重启。未知对象或所有权冲突使启动失败。

专用终端若产品需求明确为整机 VPN，可以在该专用设备的初始 namespace 使用 TUN，但这不是开发/控制/混合节点
的默认交付：它必须显式启用，并在 capture 前建立和回读管理网、SSH、LAN、WireGuard、DNS、默认网关与 tunnel
endpoint bypass；没有独立管理通道和失败回滚时同样禁止激活。当前模型尚无这项显式交付输入，因此现有门禁仍
拒绝全部 initial-namespace access TUN，不能用“未来可能支持整机 VPN”绕过。

删除 capture 边界会重新允许应用接管宿主网络控制平面，直接破坏管理可达性，因此它不能被吸收到 endpoint
排除、selector、Observation 或安装 readiness 中。事故背景见
[宿主网络接管事故记录](../incidents/2026-09-21-host-network-takeover.md)。

Linux 的具体映射不增加领域概念：`/var/lib/loom-device/state.json` 是保留 `v2_latch` 的 schema 3（见[现行编号](../core/current-contract.md#现行编号)）
`DeviceIdentity + CertifiedLKG` owner-only 原子文件，保留稳定身份、认证 floor 与完整 LKG；
`/var/lib/loom-device/runtime.json` 只保存一份 `Preference` 和当前底层网络代的有限
`Observation`；`/run/loom-client/config.json` 与 `status.json` 分别是可删除重建的
`RuntimeCandidate` 配置和 selector 回读投影。唯一正式 unit `loom-client.service` 运行
`loom client run`；access 数据面子进程必须先进入专用 network namespace，再启动精确签名包中的 sing-box、
应用共享纯核心给出的候选、逐项回读 selector，
再以一次真实 TCP/TLS 与 UDP/DNS 业务结果形成 Observation。第一次失败只触发一次由相同纯函数得出的
必要 fallback；同一网络代已有有效结果时重启不重复采样。

TUN worker 在与 PID 1 或原 underlay 相同的 network namespace 中拒绝启动。监督进程保留原网络，
已验收的 Mixed/service unit 继续按原输入运行。隔离 TUN 的源码与正式 CLI 验证进展不代表生产验收完成；
实际安装、宿主不变量与崩溃恢复结果见[实施状态](../progress.md)。

#### 隔离 TUN 的执行边界

目标是让操作者显式启动的 Linux 应用使用现有 Service/Policy，且同机 control、转发、出网和管理连接保持
原 underlay。当前 Mixed 已满足显式代理应用，但普通 TUN 应用及其安装、停止恢复没有正式入口。最小变化
是由同一 `loom client run -capture tun` 监督独立 access 数据面进程，`loom client exec -- <command>`
是应用进入该边界的唯一产品入口；其他宿主进程不因安装而进入 TUN。新增操作成本是应用须从此入口启动。

认证 DeviceView、LKG、身份、Preference 与报告格式不变。唯一 agent 留在原网络处理私有配置、报告和已有
服务资源；同一认证 View 单向投影 access 与 server 执行配置。server listener/WG 继续在原网络，access
sing-box 与应用在本 generation 的匿名 network namespace。access 只含回环与自身 TUN，underlay socket
从固定的原网络 namespace 引用创建，不创建宿主 veth、地址、route/rule 或 firewall 对象。该引用只定位
本机执行环境，不授予任何候选或业务权限；数据面的 namespace 拨号适配须单独构建和真实验证，不能假定
当前固定的上游版本已有该能力。禁止把新 namespace 字段写入签名 RuntimeProfile 或持久 LKG。

远端资源的拨号名称继续原样进入数据面，由同一 View 的认证解析器经 underlay DNS outbound 解析；
DNS 与传输 socket 都从固定的原网络引用创建。资源不需要在渲染时先变为字面 IP，也不向 access TUN
添加它的地址排除：排除并不提供原网络连接，而这里已经存在明确的 socket 隔离。没有认证解析器仍拒绝，
失败不借系统 DNS；原 CA、TLS 名称、凭据、候选及权限不变，重启从同一认证配置重新解析，不持久化答案。
最小验证是具名 Hy2 资源的隔离 TUN 实际 HTTPS、认证 DNS 查询、原身份重启和宿主网络回读；缺解析器
拒绝与运行投影不改变传输认证参数另有定向回归，不新增操作成本或权威字段。

namespace、进程句柄及本 generation 的运行文件都是执行资源，不能成为第二份权威或完成状态。父进程持有
内核引用，运行回读核对 access namespace 与原网络不同，且实际程序与配置匹配后才开放应用入口。应用
执行者在接收已核验的 namespace 引用后启动受监督的独立进程树；数据面和应用均核对独立 mount namespace，
将挂载传播设为私有并屏蔽宿主系统总线、networkd、解析服务和服务管理器的控制套接字。只有应用私有 mount namespace 设置业务
DNS；不修改宿主 resolver。服务停止、数据面异常或执行者退出都先终止相应应用树，再关闭 namespace 引用；
原应用不跨 generation 自动重启。正常停止、强制退出与启动中途失败均不得留下可继续绕过当前授权的应用。
应用树以独立 PID namespace 的 init 监督，执行者死亡由内核父死亡信号与固定父进程句柄共同覆盖；
service 使用经过核验的 pidfd 终止其精确进程树。握手释放前不执行用户命令，service 拒绝其他 UID
及不属于调用者的 PID namespace init；CLI 还核对服务端正在运行的精确 Loom 制品。应用执行前移除全部 capability，禁止通过 root exec 重新取得网络能力。
DNS 文件只是运行配置旁可重建的本代投影；传递只读文件引用，在应用私有 mount namespace 内核对 inode
后绑定，停止时比较所有权再删除。既不改写宿主 `/etc/resolv.conf`，也不保存新的 DNS 权威。
更新失败保留新 LKG，关闭不再符合授权的 access/server 执行；修复通道仍使用原 underlay。未知残留或清理
失败保持 failed/inactive，不自动反复施加。重启从原身份、LKG 和偏好创建新执行边界，不恢复旧 namespace。

反例：只把 sing-box 移进 namespace、让应用或 server listener 留在错误网络，分别会造成没有捕获应用或
破坏原服务；把 agent 整体移入 TUN 则可能递归捕获修复通道。验收须经正式安装/运行/exec 入口完成真实
DNS 与 HTTPS、授权收窄和恢复，并在正常停止、child/parent 强制退出、启动失败及重启后核对应用树和网络
清理。每次同时比较宿主 namespace、route/rule、resolver 文件及解析服务的逐接口 DNS/域/default-route，
并以新 SSH、LAN、WG、代理与公网连接验证原路径。
源码支持显式 `--capture tun` 生成同一 systemd unit，增加创建 namespace 所需的 `CAP_SYS_ADMIN` 和
`/dev/net/tun` 访问；Mixed 不增加这些权限。systemd 通过 `OpenFile` 预先打开 `/proc/1/ns/net` 并传入只读
文件描述符，供限权进程取得同一个初始 namespace 引用；worker 仍必须逐项比较
初始、underlay 和自身引用，不能因 `/proc` 读取被拒绝就跳过核对，也不为此授予 `CAP_SYS_PTRACE`。TUN 子进程门禁不因 unit 授权而放宽，纯服务节点不创建
access namespace。unit 沿已签模板与实际本机输入精确回读，升级可以显式切换 capture，但不回退发布代。
这些检查通过以前，不宣称对应部署完成。[系统总线事故](../incidents/2026-10-06-isolated-tun-host-dns.md)
说明为何仅比较网络空间或 resolver 文件不足以证明 DNS 隔离。

`loom client route direct|auto|exit <ID>` 是 Linux 唯一偏好写入口；写入后重载同一 service。
`loom client status` 只读取 `/run` 中的实际 Selection，不把偏好冒充为运行事实。service 启动时可以尝试
私有配置同步；控制面离线或报告暂不可达时继续使用已验证 LKG，不能改走公开配置或旧 pull。

设备把签名报告交给任一可达且已同步该设备授权事实的 control 即算上传成功。接收成员按当前
授权验证设备身份和原报告签名，当前结果另按签名 DeviceView 核对 `view_digest`；旧 View 只能保留为诊断。
成员通过控制成员私有认证通道交换[报告必要差量](../core/current-contract.md#control-成员之间的报告差量)，
补齐历史缺口和分叉证据；较旧的报告不能覆盖新结果。报告不参与治理权威，成员暂时不可达只会令该成员展示缺少观测；连通恢复后从
其他成员重新合并即可。签名报告将当前 `view_digest`、链路 Observation 的 `link_spec_digest` 和候选
Observation 所经链路的有序摘要一同纳入签名字节；接收方按当前 View 重算，不匹配时只投影 `unknown`，
不得沿用旧 `available`。客户端只在相关执行/探测输入经新旧 LKG 比对相同后，才可把旧观测留在新 View 的报告中；
无法证明相同时保守上报 `unknown`。
设备授权或 DeviceView 改变后，旧 `view_digest` 的报告即使签名正确也不得继续投影。

Linux 客户端制品同时为 amd64/arm64 生成、签名和逐文件验证。amd64 在原生宿主做业务验收；arm64
只交叉构建和静态检查。installer 先把精确制品放入内容标识 release 目录，并在切换 `current` 前对现有
LKG 执行 sing-box preflight；切换后若 service/selector 回读未成功，只有先前 release/unit 已证明不会在
初始 netns 接管宿主流量，且能消费当前已接受授权、不恢复已撤销权限时才可恢复运行；否则只恢复文件指针并保持 service disabled/failed。升级失败
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
连续多数签名成员链、签发 control 的签名与事实前沿、规范 RuntimeProfile 和 floor 全部通过后，
才能与提升后的已验证成员链信任绑定、事实前沿及 floor 一起替换旧值；不能拼接新旧字段。
宿主 preflight、组件可用性及运行回读不决定认证 LKG 是否接受；应用失败遵循上述新认证配置规则，
保留新 LKG 并收口已撤销授权，不把旧 envelope 恢复为运行权威。

首次导入时先生成 Ed25519 身份并把 `v2_latch=true`、floor 0、capability 绑定和默认 Auto Preference 原子
保护，再经受限 bootstrap tunnel claim/resume。同一事务恢复复用同一 identity/request ID；不同邀请不得接管。
完成后保存完整 LKG 并推进 floor。进程、SCM 服务或系统重启从同一 envelope 验证恢复；DPAPI 解密失败、schema
未知、latch 缺失、未经证书限定的前沿回退、LKG 无效或 Preference 非规范时整个 profile 失败关闭，不回退 P-256、公开配置、
旧 bundle 或 v1 路径。未完成事务不是可连接 profile，UI 只能显示可继续恢复的加入状态。

Windows HostAdapter 从 LKG 每次纯派生 `RouteCandidate` 与 `RuntimeCandidate`，启动签名包中的正式 sing-box，
先由共用适配器校验 View 并保留完整授权 outbounds/route，再添加本机 API 输入；Windows capture 派生只添加一次
认证 DNS、Mixed/TUN 和 sniff 规则。独立 Hy2 首跳的地址、凭据、CA 与 TLS 名称必须原样保留；WG endpoint、精确来源绑定及执行 DNS 由同一认证投影提供，禁止 Hy2 detour；不能用仅接受
Direct 的平台校验器拒绝已经支持的认证候选，也不能重复添加 DNS 绕过该校验。平台结构校验不产生新授权，
未知字段、不安全 TLS、失效或循环 detour 与扩宽的 capture 仍须拒绝。派生值只随受监督子进程存在，停止后删除，
重启从原 LKG 重建；UI 与签名报告继续回读真实 selector，不从配置文件推定连接成功。
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
   摘要引用、旧成员同一轮次多数签名、失格键封存序列，以及最终 View 签发者资格和设备绑定。
   缺少中间证明、任意新根、错误签名及未经证书限定的前沿回退均拒绝；封存低于已见高水位时，
   仅对该封存键允许证书限定的验收例外，原高水位和 latch 保留，旧 LKG 只在验收失败时保留；留任 control 在证书验收前已持久接受的超限撤权有原始
   证据时自动重签，证据缺失时标记可能复权且不伪称全部风险已被发现。失败不覆盖
   旧信任绑定、前沿、高水位或 LKG。没有显式 `NetworkLink` 时仍可从设备认证私有入口领取配置，
   已有共享首跳可按授权使用。
2. **确定性派生**：相同 LKG 在 Android/Linux/Windows 纯核心得到相同授权候选身份和顺序；相同平台
   能力值生成相同可执行集合，重启结果不变；能力不足时不改变授权候选 ID。
3. **Direct 与本地出网语义**：普通 Direct 的终点为 `direct`、链为空；设备限定本地出网终点为本机
   NodeID、链同样为空。两者身份不同，Direct 模式只取前者，Auto 与指定本机出口可取获授权的后者；
   重建不丢失 NodeID，均不产生回拨本机的入口检查；一跳直达包含远端最终出口，不与二者混淆。
4. **同出口多路径**：同一最终出口同时产生一跳直达和中继；不同 WG/hy2 首跳资源及同节点对的
   WG/hy2 中继 `LinkID` 分别形成候选 ID，资源可按 ID 复用；关闭
   `public_data_ingress` 只删除引用该入口的一跳候选，其他共享资源首跳仍保留；开启它不会自动得到
   `available`；hybrid access 在出口无
   公网入口时仍可通过自己已认证且平台支持的 link 形成候选，不生成本机回环 inbound 凭据。
5. **三态观测**：真实成功、真实失败、缺失/过期/跨网络代分别得到 available、unavailable、unknown；
   同一节点对的 WG 与 hy2 及共享同一资源的不同链路都只按各自 `LinkID` 的真实结果改变状态，未实测者
   保持 unknown；同 ID 链路或资源更新规范内容后，旧 `link_spec_digest` 的链路/候选观测及签名报告失效，
   不影响未引用该资源的候选；ICMP 成败只改变 RTT 提示，不改变三态。
6. **非阻塞与 fallback**：启动在观测未完成时即可应用合法候选；Android 在验证并持久保存
   `CertifiedLKG` 后，VPN/selector 回读可使 profile 成为 active，缺少获授权业务目标仍为 `unknown`；
   真实业务失败更新观测并
   选择同一最终出口的必要中继 fallback，后续成功可恢复，无需配置变化或删除认证 LKG。
7. **运行事实**：adapter apply 成功但 readback 不匹配时不更新 Selection；UI 显示回读实际值，
   不把 Preference 显示为当前路径。
8. **平台契约**：Android/Linux/Windows adapter 各用一个成功 outcome、一个失败 outcome、一次 apply/readback
   验证接口；真实验收各选一条可工作的正常路径和一条同出口 fallback 即可。
9. **认证与运行应用分离**：一份规范 RuntimeProfile 与 routes 逐项映射；缺候选、多余 selector 成员或
   非规范 JSON 使新 View 认证失败、保留旧 LKG。认证和原子提交成功后，即使宿主 preflight、组件或
   启动失败也保留新 LKG/floor；仅允许仍符合新授权的旧执行，已撤销服务不得因其他资源失败恢复。
   重启后继续以新 LKG 修复，UI 分别显示认证配置和实际应用结果。
10. **Windows DPAPI 与 profile 隔离**：machine/user scope 不能互换；每个 profile 的 Ed25519 身份、floor、
    latch、完整 LKG 与 Preference 往返相等，原子替换失败保留旧值；索引损坏不能制造或覆盖网络权威。
11. **Windows 严格 wire 与恢复**：`platform=windows` 缺 RuntimeProfile，或含未知/缺失/多余字段、重复键、
    非规范 JSON、错误候选映射时服务端拒绝；重启从同一 DPAPI LKG 派生相同候选，Selection 仍只来自 readback。
12. **Windows 最小原生闭环**：Installed x64 用一个 profile 完成 UI invite → claim/resume → DPAPI → runtime →
    selector readback → TCP 与 UDP/DNS → 一个 unavailable 候选 → 同出口 fallback → 签名 report/readback；再按同一
    adapter 契约抽样 Portable TUN/Mixed 的 capture、清理和持久差异，不建立 Edition × 模式 × 协议矩阵。
13. **共享业务探测**：一份规范 HTTPS 目标池只投影所选有效 allow Policy 对应的 Service matcher 覆盖的目标；
    不同设备/Service/Policy 范围分别探测、分别选路，一个成功不使另一个变绿。空投影只使相应业务
    范围保持 unknown，不扩大 ACL、不阻断加入；中继链路的精确目标按 `LinkID` 独立验证。
14. **Linux capture 隔离**：初始 network namespace 的 TUN worker 失败关闭；监督进程只能创建专用
    namespace 中只捕获显式 workload；同机 control + forward + internet_egress 在没有 TUN 时保持业务可用；正常
    停止、child/parent crash、SIGKILL、启动中途失败和重启后，宿主 rule、main route、LAN、WireGuard、DNS、
    代理与 SSH 回读均保持基线，未知所有权对象不会被删除。
15. **DNS 与局域网**：`.loom` 仅精确 A/AAAA、`control.loom` 保留，解析不扩大 ACL；
    选择了 mapping Service 所属有效 allow Policy 的 access 才得到虚拟前缀及固定网关候选，撤权后精确路由和 DNS 投影消失。
    映射范围没有适用 HTTPS 目标时保持 unknown，真实业务结果只证明所访问目标；互联网 Preference 不受影响。

16. **策略分配与范围**：同服务重复分配拒绝；未分配和 deny 均无业务权限；any 只枚举实际合格资源；
    only 的唯一出口删除后无替代受管出口；none 不等于 any；关闭 Direct 的指定出口规则不能直连绕过；
    LAN 终点不可替换。策略变更仅使依赖其规范摘要的观测失效，重启从认证 LKG 恢复相同范围。

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
