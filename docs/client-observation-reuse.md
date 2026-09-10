# 客户端复用现有签名 Observation

本文定义服务端 Observation 读取适配，以及 Windows / Android 共用的客户端消费边界。
遵循 design.md §7.3.3、§7.3.4、§16.1.2；不增加 SSOT 字段、测量协议或推荐路径表。

> **协议代次：** v1 兼容契约使用同源 report POST、内存 gossip table 和
> `200/204` 响应。目标 v2 保持 Observation 的生产者签名与原时间不变，但通过 signed
> `EndpointSet(role=device_report)` 发现入口，并将不可变报告按
> `(device_id, observed_at, attestation_hash)` 在 control
> 副本间 CRDT 去重；ControlSet QC 决定授权范围，CRDT 到达本身不能改变期望态。
> 详见[分布式控制平面设计](distributed-control-plane.md)。代码、部署与验收进度只见
> [当前状态](status/current.md)。
>
> v2 授权门禁固定为 certified head 及其 Device view：Raft durable commit 后尚未
> 取得 replication QC 的 `committed_not_certified` 不得改变 report endpoint、可读范围、
> 路由授权或外部副作用；客户端继续 last-known-good。

## 读取与上报职责

| 消费者 | 契约边界 |
|---|---|
| Linux Agent | `internal/agent/observed.go` 的 `pollPeers` 通过 `report.FetchContext` 读取本机及 WG 邻居 `/status` 中的 `observation` 和 `learned`；`ingestObservation` 校验签名绑定、新鲜度及 measurements 后进入现有按来源去重的观测缓存 |
| Windows | 在原有 NAT 签名上报周期内请求观测，经跨平台校验器验证后接入入口与服务器分段选路；继续拒绝 Linux 专用 `peers/self_report` 配置 |
| Android | `mobile/loomcore` 拒绝 Linux peer/report 配置并复用同一验签/决策包；宿主在原健康周期兼容 204 或读取 200 观测，按实际 selector 读回重算，不另起探测周期 |

Linux 的 canonical v5 闸门覆盖测量；旧兼容阶段的本机例外不能用于客户端读取。
v1 公网报告入口将客户端报告写入与 WG gossip、`/status`、控制面展示相同的
内存表。读取适配只从该表取快照，不重新采集、刷新原始时间或调用探测器。

## v1 兼容契约：报告 POST 的可选响应

沿用已验证加入入口的同源报告地址，保持原报告 JSON 和签名不变：

```http
POST /loom-client/report?observations=1
Content-Type: application/json

<现有客户端签名 Observation JSON>
```

公网反代对应控制端 `/api/client/report?observations=1`；继续使用现有 HTTPS
出站通路，无需开放公网 `/status`、增加 WG 隧道或新增 endpoint 配置。
查询参数是传输层读取开关，不属于已签名 Observation 正文。

- 无 `observations=1`：成功仍为空正文 `204`，现有客户端兼容。
- 显式请求：成功为 `200 application/json`，正文是 `report.Observation` 对象数组，
  无可用观测时为 `[]`；`Cache-Control: no-store`。
- 请求继续执行原有 v5 measurements、自检及可选附件验签、registry 当前 enrollment
  身份/SPKI 绑定、在役 Windows/Android SSOT membership 检查；撤销身份不能读取。
  不增加 Bearer token 或 mTLS。认证仍来自签名报告，保留既有时间窗口内重放边界。
- 只返回该客户端**v1 已验证 SSOT 候选链中的在役服务器**观测；候选范围复用
  `ExpectedRoutesForAccess`，不是另一份配置。目标 v2 用 certified Device view 的授权
  候选取代该范围，`committed_not_certified` 不能扩张读取集。排除客户端自己、其他客户端、
  已移除及范围外来源、过期或未通过 v5 测量验签的整份观测，按来源排序。
- 过滤单位是完整的来源 Observation，不是内部单个目标。返回对象仍可能包含该
  来源对其他目标的测量及它自己的 Agent 状态；不裁剪、归一化或重新签署正文。
  保留 `node`、`ts`、`attest`、`attest_extended` 及所有原有附件。
- HTTP 方法、请求体 1 MiB 上限及原有 400/403/413/415/503 边界不变。
  200 表示报告已接受并返回快照，不代表客户端或返回节点健康。

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

v2 客户端在使用报告入口或其观测改变选路前，必须先验证 certified head、
Device inclusion proof 及 `EndpointSet(role=device_report)`，并原子执行四组 durable floor：
`recovery_epoch/recovery_statement_hash/recovery_policy_hash`、
`control_epoch/control_set_hash`、`control_revision/head_hash` 和
`device_generation/device_leaf_hash/device_view_hash`。首次 v2 安装还必须原子写入
`bootstrap_transition_hash` 与不可逆 `protocol_latch=v2`；latch 后 v1 同源 URL 不再是 authority。
`device_report` 的每个 HTTPS endpoint 都按 signed EndpointSet 核对精确 URL、hostname/WebPKI
和带 generation/overlap 边界的 TLS SPKI pin，拒绝重定向。

1. 在现有报告周期内显式选择读取模式，并解析有大小上限的完整 Observation 数组；
   不增加独立轮询/探测周期。Windows 使用 `clientreport.SendWithObservations`，
   保留 `Send` 的原 204 契约；200 已接受报告但观测正文无效时单独报告读取错误，
   不篡改设备健康。Android `HealthReporter` 使用相同的 `observations=1`，兼容
   200 JSON 与旧服务端 204；正文读取错误同样不篡改已接受的设备健康。
   旧服务器若返回 204，表示上报成功但本轮没有观测数据，不能当成失败证据。
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
4. 每个底层网络代维护独立 probe registry；Direct 不冻结候选、不启动 route session、也不花
   探测预算。该网络代第一次进入 Auto 或指定出口时原子冻结当时的候选快照，客户端只对其中
   按地址与源接口去重后的授权入口各做至多一次轻量并行探测；同代后来出现的新入口不加入主动探测集合，入口之后
   复用服务器观测；不再验证整条业务路径，也不以后台补样、健康验证或旧排名器的
   `min_samples` 要求恢复这些探测。配置刷新、模式/出口切换和同一网络代内重连
   复用该结果，不重测。不等待入口或服务器观测才启动数据面。服务器报告未覆盖的
   目标保持未知；客户端不为填空扩大探测面。服务器按上述明确的目标集合采集。

共用 Go 决策包按实际失败率、受支持的目标指标与阻尼排序；Windows Agent 与 Android
libbox 宿主必须复用它。Windows TUN 域名识别另在本地派生配置中处理，不改变服务器
观测协议或签名策略。

Windows 客户端适配只能使用 `agent.RunClient`，不得调用服务器完整路径
`agent.Run`。它从已验证
数据面的 detour 找授权入口，在 TUN 启动前记录源网卡；各地址并行发送一次 ICMP，
单次超时上限一秒且不阻塞数据面激活。ICMP 无响应表示入口质量未知，不证明业务失败。
没有后段观测时保留当前配置出口，只在相同出口且不增加跳数的授权候选中比较入口
延迟；入口 ping 更低不能作为增加一段未知中继的依据。

服务器观测由上报 POST 响应提供，客户端不另建“观测配置”。新鲜且已验签的
服务器结果到达后只重算选择，不再次 ping、不访问业务目标、不轮询等待样本。
对 latency 目标，比较入口 RTT + 实际承载的服务器邻接/公网 Hy2 RTT + 出口精确目标
首字节时间的分段估算；同一声明使用相同的已覆盖目标子集，未覆盖的目标单独标注未知。
失败率较差的候选不能靠较低延迟胜出。失败率相同且估算延迟不增加时，减少服务器
跳数立即生效，不受 `switch_threshold` 阻挡；估算相同时选择更少跳数。增加中继或
同跳数替换继续检查配置的改善幅度；失败率更低时可直接切换。先逐候选检查切换
条件，再在可切换集合内排序，防止一条被门槛挡住的最快多跳候选遮住可简化的路径。
决策原因明确记录减少中继，界面沿用实际 selector 和签名决策原因展示，不增加路径选择
控件。这些判断不等待 min_samples。按签名出站的实际下一跳地址匹配度量：
隧道内下一跳用已有邻接 RTT；公网 Hy2 下一跳用 LinkMetrics，二者不互相替代。
其他目标指标缺少相应证据时明确说明，不能拿延迟冒充吞吐或稳定性。

分段估算不是业务端到端实测。两个客户端的路径页都按实际连线显示证据：本机到
入口是当前底层网络代的单次轻量探测，服务器段和精确目标来自原始签名观测；
缺失显示 `—`。
不再用整条路径“健康”或旧 P50/P95 占位概括这些不同来源。每轮健康上报只检查
本机监听与托管网卡，业务可用性保持未测量。入口探测预算以
`(底层网络代, 源接口, 首次代理模式候选快照中的去重入口地址)` 为键：Direct 不创建该快照；同代新引入入口不取得主动探测预算，只能
从真实拨号/回退取得被动证据；激活、配置刷新、模式/出口切换和同一网络代内重连都不重置
已用预算。退出再进入代理模式不重新冻结；只有底层网络代变化后首次进入代理模式才冻结
新的候选快照并开启新一代预算。
配置更新仍走验签与 certified 门禁，不改变服务器采集协议。

## 验证范围

必需回归矩阵覆盖：

- 空路径/根路径等价、其他 URL 语义隔离、缺失目标未知以及原始签名内容/时间保留；
- 端到端 report POST、200/204 兼容、范围过滤、撤销拒读，以及过期、无签名或篡改证据缺席；
- v2 `device_report` EndpointSet 的 WebPKI/SPKI pin、角色隔离与 overlap，
  `committed_not_certified` 不授权，四组 floor/recovery policy hash 和 latch 回退拒绝；
- Windows/Android 的 Direct 不探测；每底层网络代首次进入 Auto/指定出口时，才对当时冻结
  候选快照中的每个去重入口至多一次并行探测，同代
  新入口、配置刷新、模式/出口切换和重连不新增或重置探测，不发业务 DNS/HTTPS，不扫描
  完整路径或阻塞启动；
- 实际 selector 读回、观测拒收/离线缓存与逐连线只读展示，且不把分段估算标为
  端到端实测。

具体代码、测试与真机验收证据只见[当前状态](status/current.md)。

## Windows / Android 拓扑显示

Windows 的“当前选路”契约为一个白色面板，各 Service 用细线分隔；Android
使用单一“当前路径”卡片逐声明排列。两端都把测量标在对应连线上，不显示
整条路径质量占位；业务证据缺失时明确显示未知。本机到入口显示该底层网络代的
单次轻量探测；服务器段按实际承载显示对应方向的 RTT。
公网 Hy2 有现成数据时追加该观测的 Δ（P95−P50）与固定响应探测速率；这不是
业务吞吐或容量。WireGuard 原始邻居观测只有 RTT；若客户端收到的已验签
快照不携带历史汇总波动或流量速率，则不补零、不重建历史窗口，也不新增接口或探测。
出口到目标显示服务器已有的精确目标响应耗时，连线只显示毫秒数，测量口径放在详情；多个目标逐个列在详情里，不把其中
一个目标的成功或失败概括成整个设备的健康。缺失或过期显示“—”。详情保留来源、
目标、原测量时间及失败情况；刷新这些显示只读本地缓存，不发起网络测量。
