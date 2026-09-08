# 客户端复用现有签名 Observation

本文描述已有服务端读取适配、Windows 消费实现，以及 Android 尚未接入的边界。
遵循 design.md §5.5.1、§16.1.2；不增加 SSOT 字段、测量协议、探测目标或推荐路径表。

## 已核实的读取与上报通路

| 消费者 | 仓库当前行为 |
|---|---|
| Linux Agent | `internal/agent/observed.go` 的 `pollPeers` 通过 `report.FetchContext` 读取本机及 WG 邻居 `/status` 中的 `observation` 和 `learned`；`ingestObservation` 校验签名绑定、新鲜度及 measurements 后进入现有按来源去重的观测缓存 |
| Windows | 在原有 NAT 签名上报周期内请求观测，经跨平台校验器验证后接入入口与服务器分段选路；继续拒绝 Linux 专用 `peers/self_report` 配置 |
| Android | `mobile/loomcore/route.go` 拒绝 Linux peer/report 配置；宿主 `HealthReporter.kt` 只发送报告并接受空正文 204。尚未把服务器观测接入本地候选回路 |

Linux 的 canonical v5 闸门覆盖测量；旧兼容阶段的本机例外不能用于客户端读取。
现有公网报告入口将客户端报告写入与 WG gossip、`/status`、中控展示相同的内存表。
本次读取适配只从这张表取快照，不重新采集、刷新原始时间或调用探测器。

## 本次已实现：现有报告 POST 的可选响应

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
- 只返回该客户端**当前 SSOT 候选链中的在役服务器**观测；候选范围复用
  `ExpectedRoutesForAccess`，不是另一份配置。排除客户端自己、其他客户端、
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

实际报告目标来自 `internal/render/report.go` 的声明 `probe_url` 去重集合，以及
节点已经配置的 `probe_targets`（`uplink` 标记）。本次未扩展到所有 Service 地址。
目标存在但有部分失败时仍保留原样本/失败数；当前 producer 仅在窗口全失败时写入
`Reach.Error`。缺失目标、过期或验签失败保持**未知**，不能当作成功或失败。

消费端用 `agent.EquivalentTargetURL` 比较 HTTP(S) 空路径与 `/`，例如
`https://demo.example?x=1` 和 `https://demo.example/?x=1`。其他路径、尾斜线、
百分号转义、查询值/顺序/空查询、端口等保持原状。先验签，再比较；不要改写原对象。

## 客户端消费边界

1. 在现有报告周期内显式选择读取模式，并解析有大小上限的完整 Observation 数组；
   不增加独立轮询/探测周期。Windows 使用 `clientreport.SendWithObservations`，
   保留 `Send` 的原 204 契约；200 已接受报告但观测正文无效时单独报告读取错误，
   不篡改设备健康。Android `HealthReporter` 仍只接受 204，尚需读取分支适配。
   旧服务器若返回 204，表示上报成功但本轮没有观测数据，不能当成失败证据。
2. 使用已验证加入身份保存的 CA，复用现有 canonical v5 校验与绑定规则。
   Go 共用入口为 `observation.VerifyObservationAtLeast`（服务端原入口委托它），必须检查
   `MeasurementsVerified`；仅调用 `attest.VerifyFresh` 不会绑定外层 Targets/Edges。
   可选 self-check/traffic/link-metric 需各自验签、绑定来源和时间，不借主签名背书。
   Windows 以完整 Observation 读取，避免上报最小 DTO 丢掉 measurements；
   `internal/observation` 复用原 verifier 的绑定规则，不实现第二套签名。
3. 按现有 plan 的候选链和 `observation_stale` 消费证据，以原来源/原时间去重，
   不用 HTTP 接收时间延长有效期；缺失、失效或签名失败不改变授权集合。
   Windows 已接入客户端分段选择。服务器不可达证据作为当轮约束及决策原因，
   不按本机探测样本累计；旧 `observation_kind: derived` 记录不进入数值排名。
   不把来源节点的 Agent 选择当成客户端推荐路径。
4. 按用户已明确的分工，客户端首轮只对授权入口去重后各做一次并行探测，入口之后
   复用服务器观测；不再验证整条业务路径，也不以后台补样、健康验证或旧排名器的
   `min_samples` 要求恢复这些探测。不等待观测到齐才启动。服务器报告未覆盖的
   目标保持未知，不扩大任何一端的探测面来填空。

共用 Go Agent 已修复实际失败率的排序和切换守卫；相同失败率仍使用现有目标指标
与阻尼。Android 的独立候选循环尚未接入。Windows TUN 域名识别另在本地派生配置中
处理，不改变服务器观测协议或签名策略。

Windows 已改用 `agent.RunClient`，不再调用完整路径 `agent.Run`。启动时从已验证
数据面的 detour 找授权入口，在 TUN 启动前记录源网卡；各地址并行发送一次 ICMP，
单次超时上限一秒且不阻塞数据面激活。ICMP 无响应表示入口质量未知，不证明业务失败。
没有后段观测时保留当前配置出口，只在相同出口的授权候选中比较入口延迟。

服务器观测由既有上报 POST 响应提供，客户端没有新增“观测配置”。新鲜且已验签的
服务器结果到达后只重算选择，不再次 ping、不访问业务目标、不轮询等待样本。
对 latency 目标，比较入口 RTT + 原方向公网 Hy2 RTT + 出口精确目标首字节时间的
分段估算；要求各段有证据，失败率较差的候选不能靠较低延迟胜出。沿用配置的
切换阈值抑制小幅波动，但不等待 min_samples。WG RTT 不冒充公网 Hy2 RTT，
其他目标指标缺少相应证据时明确说明，不能拿延迟冒充吞吐或稳定性。

分段估算不是业务端到端实测，界面标明入口单次结果和估算来源，旧 P50/P95、样本数
保持空值。每轮健康上报只检查本机监听与托管网卡，业务可用性保持未测量。
激活、重连沿用原生命周期，每代重新测入口；配置更新仍走原验签流程。
签名、服务器采集和授权候选协议均未改变。Android 尚未接入此客户端流程。

## 验证范围

回归测试覆盖空路径/根路径匹配、其他 URL 语义隔离、缺失目标未知、原始内容保留；
也覆盖旧 10% 分档和现任样本不足时的错误切换，横跨 latency/stability/throughput。
用修改前的 Agent 源码运行同一批新测试可复现 URL 匹配失败及较高失败率胜出。
报告适配使用真实测试证书验证端到端 POST、原签名重新验签、默认 204 兼容、
来源范围过滤、撤销身份拒读与过期/无签名/篡改证据缺席。
Windows 回归还覆盖原签名绑定、范围/过期拒收、原时间去重、200/204 兼容，
以及健康超时后仍保留路径证据。实机验收状态见忽略目录中的当前状态记录；
Android 读取与本地选路接入仍未实现。
