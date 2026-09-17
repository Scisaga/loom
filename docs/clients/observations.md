# 客户端复用现有签名 Observation

> **类型与归属：** 本文是 Windows / Android 入口探测预算、签名观测消费、分段选路与展示的规范正文，
> 同时定义现有服务器 Observation 的私有报告读取契约；平台手册只补宿主接线。Linux Agent 的总体模型见
> [架构总览](../architecture/README.md)，本任务不增加 SSOT 字段、服务器测量协议或推荐路径表。

> **协议代次：** 服务器 Observation 保持原生产者签名与测量时间。客户端通过 certified
> private `ControlServiceDirectoryV1` 取得 overlay-only `device_report` 服务，以 Device mTLS
> 与带持久序号的签名报告认证，回读 exact 绑定回执中的观测。副本间 CRDT 去重不改变授权；
> ControlSet QC 决定当前期望态和可读范围。
> 服务发现、认证和持久信任状态由[分布式控制平面规范](../protocols/control-plane/README.md)定义。
> 源码入口见[实现对照](../development/implementation.md)；生产与真机结论按[部署和证据规程](../operations/local-deployment.md)核对。
>
> v2 授权门禁固定为 certified head 及其 Device view：Raft durable commit 后尚未
> 取得 replication QC 的 `committed_not_certified` 不得改变 report endpoint、可读范围、
> 路由授权或外部副作用；客户端继续 last-known-good。

## 读取与上报职责

| 消费者 | 契约边界 |
|---|---|
| Linux Agent | `internal/agent/observed.go` 的 `pollPeers` 通过 `report.FetchContext` 读取本机及 WG 邻居 `/status` 中的 `observation` 和 `learned`；`ingestObservation` 校验签名绑定、新鲜度及 measurements 后进入现有按来源去重的观测缓存 |
| Windows | 在私有 v2 健康上报周期内读取观测，经跨平台校验器验证后接入入口与服务器分段选路；继续拒绝 Linux 专用 `peers/self_report` 配置 |
| Android | `mobile/loomcore` 拒绝 Linux peer/report 配置并复用同一验签/决策包；宿主在原健康周期读取 200 回执中的观测，按实际 selector 读回重算，不另起探测周期 |

Linux 的 canonical v5 闸门覆盖测量；本机采集例外不能用于客户端读取。
服务器在原周期采集后，将原签名 Observation 随私有 `node-health` 报告提交。
回执 reader 只读已接受的持久报告，不重新采集、刷新原始时间或调用探测器。

## 私有 v2 报告与观测回执

报告地址由已认证的 private service directory 指定，不从 distribution URL 推导。
客户端通过已授权隧道访问私有 `device_report`，验证内部 CA、服务角色和 SPKI，
服务端同时验证 Device mTLS、当前认证身份与 Device view、持久 floor、报告签名及序号。
旧公开报告 handler、同源 URL 推导和本机观测桥接入口已删除。

- 报告必须为严格 canonical JSON，绑定当前 Device 身份、配置 floor 与 payload 摘要。
  持久 store 原子保存后才返回 `200`；同序号仅允许同一报告重试，冲突或过期权限被拒绝。
- 回执绑定原报告 hash、序号和当前授权，客户端验证后才提交报告队列并消费观测；
  `200` 证明报告接受，不代表客户端或返回服务器健康。
- 只返回该客户端**当前认证运行配置候选链中的在役服务器**观测；
  `committed_not_certified` 不能扩张读取集。来源必须仍拥有当前职责与原观测身份，
  排除客户端自己、其他客户端、已移除及范围外来源、过期或验签失败的整份观测，按来源排序。
- 过滤单位是完整的来源 Observation，不裁剪、归一化或重新签署正文。
  保留来源、原始时间、全部签名附件及测量；客户端仍以原观测 CA 验证。
- 没有可用观测时保持空集合；不调用旧 HTTP/Unix 报告入口，不增加采样或等待。

源码入口为 [私有报告服务](../../internal/controlplane/device_report.go)与
[认证观测回读](../../cmd/loom/control_device_observations.go)。

## 哪些信息可复用

| 现有证据 | 可以说明 | 不能推导 |
|---|---|---|
| `Targets` | **来源服务器直连该精确 URL** 的首字节时间、样本/失败数、不可达错误；可复用为该出口对相同目标的已知失败证据 | 客户端直连状态、未列出的 Service、整个域名或其他路径均不可达 |
| `Edges` | 来源节点到配置邻居的 TCP 建连 RTT、样本/失败数 | 客户端到入口的质量、任意业务链端到端性能 |
| `LinkMetrics` 独立签名附件 | 已测 Hy2 单跳的 RTT、p50/p95 与探测响应速率，保留附件自身 `observed_at` | 可用带宽、业务吞吐或未测链路的质量 |
| `Traffic` 独立签名附件 | WG 累计计数；相邻同 epoch 样本可求速率 | 链路剩余容量、某个客户端候选的端到端速率 |
| `SelfCheck`、版本及组件证据 | 来源节点按原健康协议给出的自检、配置和版本事实 | 客户端健康、客户端到它的可达性 |
| `Agent` | **该来源接入节点自己**的选择及相关样本 | 给其他客户端的推荐路线；控制设备自己的选路不得复制成客户端选路 |

实际报告目标来自 `internal/render/report.go` 合并后的声明 `probe_url` 与 Service
具体地址集合，并沿用节点配置的 `probe_targets`（`uplink` 标记）。Service 地址
复用 Agent 的 HTTPS 根路径生成规则，跳过后缀匹配规则；HTTP(S) 空路径和根路径
等价去重，保留既有声明 URL，避免重复采集。服务目标缺失在服务器既有采集周期内
补齐，不增加客户端探测，也不把服务目标自动标成节点出网健康检查。
目标存在但有部分失败时仍保留原样本/失败数；producer 契约仅在窗口全失败时写入
`Reach.Error`。缺失目标、过期或验签失败保持**未知**，不能当作成功或失败。

消费端用 `agent.EquivalentTargetURL` 比较 HTTP(S) 空路径与 `/`，例如
`https://demo.example?x=1` 和 `https://demo.example/?x=1`。其他路径、尾斜线、
百分号转义、查询值/顺序/空查询、端口等保持原状。先验签，再比较；不要改写原对象。

## 客户端消费边界

v2 消费必须先通过[控制面规范](../protocols/control-plane/README.md)定义的 certified head、Device proof、
private service directory、四组 durable floor 与不可逆 latch 校验。报告入口使用认证后的
`device_report` 私有服务，不从 distribution/bootstrap/Enrollment URL 推导，也不退回 v1 authority。

1. 在现有私有 `device_report` 周期内解析 exact 绑定该报告的 200 回执，取得有大小上限的
   Observation 数组；204 表示本轮报告已接受但无观测，不增加独立轮询或探测周期。
   Windows 使用 `windowsv2.DurableReporter`，Android 使用 `V2DeviceReporter`；观测读取失败
   单独记录，不改写已接受的设备健康，也不调用旧公开报告端点。
2. 使用已验证加入身份保存的 CA，复用现有 canonical v5 校验与绑定规则。
   Go 共用入口为 `observation.VerifyObservationAtLeast`（服务端原入口委托它），必须检查
   `MeasurementsVerified`；仅调用 `attest.VerifyFresh` 不会绑定外层 Targets/Edges。
   可选 self-check/traffic/link-metric 需各自验签、绑定来源和时间，不借主签名背书。
   Windows / Android 都以完整 Observation 读取，避免上报最小 DTO 丢掉 measurements；
   `internal/observation` 复用原 verifier 的绑定规则，不实现第二套签名。
3. 按已验证 plan 的候选链和 `observation_stale` 消费证据，以原来源/原时间去重，
   不用 HTTP 接收时间延长有效期；缺失、失效或签名失败不改变授权集合。
   Windows/Android 都必须按该边界消费分段证据。服务器不可达证据作为当轮
   约束及决策原因，
   不按本机探测样本累计；旧 `observation_kind: derived` 记录不进入数值排名。
   不把来源节点的 Agent 选择当成客户端推荐路径。
4. 已验证 plan 只定义授权候选；候选在当前网络中的可用性是独立的动态事实。`public_data_ingress`
   或 certified EndpointSet 不能直接产生“可用”状态。宿主按底层网络上下文隔离实际 transport/业务结果，
   Direct 不启动候选测量或花探测预算；Auto/指定出口不等待测量才启动数据面。真实成功可标记可用，
   明确的当前候选拨号/握手/业务失败可标记不可用，缺失、过期、ICMP 无响应或无法归属候选的结果保持未知。
   同一最终出口的直连与境内入口→WG 中继都由这一模型处理；直连明确不可用时允许选择更长的同出口中继，
   后续真实成功或有界重验可使直连重新参与选择，不永久改写拓扑或授权。

   主动测量必须有界、去重且不阻塞启动，优先复用数据面的真实结果及既有服务器观测；不得为了填满样本、
   通过旧排名器断言或制造健康绿灯而扫描所有业务路径、反复预热或等待 `min_samples`。配置刷新、模式切换、
   重连和网络换代只改变同一模型的候选与观测输入，不另建一套调度状态机。服务器报告未覆盖的目标保持未知。

**运行中的模式切换也不得等待测量。** Android 已有 runtime 从 Direct 首次切到 Auto/指定出口时，
先按已验证配置及已有证据应用并读回 selector，使请求立即按所选模式的授权结果路由；异步结果仅在
runtime、配置与网络上下文仍匹配时按当前最新模式/出口重算选择。结果晚到、用户已切回 Direct、宿主已替换或
OS 网络代已变化时不能恢复旧模式或污染新代。没有有效结果时保持未知和已经应用的合法路径。
初次 VPN 启动与运行中的 Direct→代理均遵守该非阻塞边界。

Direct 是顶层模式覆盖。退出 Direct 时按目标模式与当前签名计划恢复合法选择，不能把显式
Direct 的覆盖结果当作 Auto 决策记忆。Auto 自身选出的合法直连仍可持久复用；清理 Direct
覆盖不清空这类记忆。

ICMP `rtt_ms` 若保留，必须来自实际 echo reply，不能把进程总耗时写入；它只表示地址层 RTT 提示，
不能证明 HY2/Trojan transport 或完整候选可用。无响应、输出无有效 RTT 或无法归属当前网络上下文时保持未知。

共用 Go 决策包按实际失败率、受支持的目标指标与阻尼排序；Windows Agent 与 Android
libbox 宿主必须复用它。Windows TUN 域名识别另在本地派生配置中处理，不改变服务器
观测协议或签名策略。

Windows 客户端适配只能使用 `agent.RunClient`，不得调用服务器完整路径
`agent.Run`。它从已验证
数据面的 detour 找授权候选并记录当前网络上下文。ICMP 可以作为地址层 RTT 提示，但不得作为 transport
成功或失败事实。没有可比较证据时保留合法当前选择；当前直连 transport 明确失败时，即使需要增加一跳，
也可以切到同一最终出口的已授权中继。仅有更低 ping 仍不能证明增加中继后的候选更优。

服务器观测由上报 POST 响应提供，客户端不另建“观测配置”。新鲜且已验签的
服务器结果到达后重算选择，不为填样本另起轮询。
对 latency 目标，比较入口 RTT + 实际承载的服务器邻接/公网 Hy2 RTT + 出口精确目标
首字节时间的分段估算；同一声明使用相同的已覆盖目标子集，未覆盖的目标单独标注未知。
明确不可用的候选先被排除；未知不伪装成可用或不可用。失败率较差的候选不能靠较低延迟胜出。
失败率相同且估算延迟不增加时，减少服务器
跳数立即生效，不受 `switch_threshold` 阻挡；估算相同时选择更少跳数。增加中继或
同跳数替换继续检查配置的改善幅度；但当前候选明确不可用时，同出口可用候选不受“不得增加跳数”限制。
失败率更低时可直接切换。先逐候选检查切换
条件，再在可切换集合内排序，防止一条被门槛挡住的最快多跳候选遮住可简化的路径。
决策原因明确记录减少中继，界面沿用实际 selector 和签名决策原因展示，不增加路径选择
控件。这些判断不等待 min_samples。按签名出站的实际下一跳地址匹配度量：
隧道内下一跳用已有邻接 RTT；公网 Hy2 下一跳用 LinkMetrics，二者不互相替代。
其他目标指标缺少相应证据时明确说明，不能拿延迟冒充吞吐或稳定性。

分段估算不是业务端到端实测。两个客户端的路径页都按实际连线显示证据：本机到
入口或候选使用当前网络上下文中的实际测量，服务器段和精确目标来自原始签名观测；
缺失显示 `—`。
不再用整条路径“健康”或旧 P50/P95 占位概括这些不同来源。每轮健康上报只检查
本机监听与托管网卡，不能把设备健康报告当作候选业务成功。
配置更新仍走验签与 certified 门禁，不改变服务器采集协议。

## 验证范围

必需回归矩阵覆盖：

- 空路径/根路径等价、其他 URL 语义隔离、缺失目标未知以及原始签名内容/时间保留；
- 端到端私有 report POST、持久序号与 exact 回执、范围过滤、撤销拒读，以及过期、无签名或篡改证据缺席；
- v2 private `device_report` service 的 overlay IP、internal CA/EKU、SPKI pin、Device mTLS 与角色隔离，
  `committed_not_certified` 不授权，四组 floor/recovery policy hash 和 latch 回退拒绝；
- Windows/Android 的 Direct 不探测；Auto/指定出口不等待测量启动，结果只能提交给匹配的
  runtime、配置和网络上下文，迟到结果不能恢复旧模式或污染新代；
- 直连候选实际可用、直连明确不可用时选择同出口中继、未知保持未知、未授权或不同固定出口不被选择；
- ICMP 只作为地址层 RTT 提示，不能产生 transport 可用/不可用；动态失败与恢复不改写静态授权；
- 实际 selector 读回、观测拒收/离线缓存与逐连线只读展示，且不把分段估算标为
  端到端实测。

源码及接线缺口见[实现对照](../development/implementation.md)；具体制品和实机验收按[证据规程](../operations/local-deployment.md)核对。

## Windows / Android 拓扑显示

Windows 的“当前选路”契约为一个白色面板，各 Service 用细线分隔；Android 保留
[连接 Tab](../../assets/client/android/connection.svg) 的当前路径卡，在该卡内展开实际链与逐段详情。
其余功能仍位于配置 / 诊断 Tab。Auto 按 Service 展示，FixedExit 只显示一条统一上网路径，
Direct 显示本机直连；视觉分组不合并 selector 决策、candidate 或证据。
两端都把测量标在对应连线上，
不显示整条路径质量占位；业务证据缺失时明确显示未知。本机到入口或候选显示当前网络上下文中的
实际证据及口径；服务器段按实际承载显示对应方向的 RTT。
公网 Hy2 有现成数据时追加该观测的 Δ（P95−P50）与固定响应探测速率；这不是
业务吞吐或容量。WireGuard 原始邻居观测只有 RTT；若客户端收到的已验签
快照不携带历史汇总波动或流量速率，则不补零、不重建历史窗口，也不新增接口或探测。
出口到目标显示服务器已有的精确目标响应耗时，连线只显示毫秒数，测量口径放在详情；多个目标逐个列在详情里，不把其中
一个目标的成功或失败概括成整个设备的健康。缺失或过期显示“—”。详情保留来源、
目标、原测量时间及失败情况；刷新这些显示只读本地缓存，不发起网络测量。
