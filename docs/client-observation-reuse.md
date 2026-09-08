# 客户端复用现有签名 Observation

本文描述已核实的代码通路、本次服务端读取适配，以及尚未实现的客户端接入。
遵循 design.md §5.5.1、§16.1.2；不增加 SSOT 字段、测量协议、探测目标或推荐路径表。

## 已核实的读取与上报通路

| 消费者 | 仓库当前行为 |
|---|---|
| Linux Agent | `internal/agent/observed.go` 的 `pollPeers` 通过 `report.FetchContext` 读取本机及 WG 邻居 `/status` 中的 `observation` 和 `learned`；`ingestObservation` 校验签名绑定、新鲜度及 measurements 后进入现有按来源去重的观测缓存 |
| Windows | `observed_windows.go` 的观测读取为空实现；`clientruntime/selector.go` 拒绝 `peers/self_report`。已有 NAT 签名上报，尚无服务器观测消费者 |
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

## 客户端仍需配合，尚未实现

1. 在现有报告周期内显式选择读取模式，并解析有大小上限的完整 Observation 数组；
   不增加独立轮询/探测周期。现有 Go `clientreport.Send` 禁止查询参数且丢弃非 204
   正文；Android `HealthReporter` 也只接受 204，二者都需要读取分支适配。
   旧服务器若返回 204，表示上报成功但本轮没有观测数据，不能当成失败证据。
2. 使用已验证加入身份保存的 CA，复用现有 canonical v5 校验与绑定规则。
   Go 服务端参考入口为 `report.VerifyObservationAtLeast`，必须检查
   `MeasurementsVerified`；仅调用 `attest.VerifyFresh` 不会绑定外层 Targets/Edges。
   可选 self-check/traffic/link-metric 需各自验签、绑定来源和时间，不借主签名背书。
   Windows/Android 不能用当前仅含上报最小字段的 DTO 解码后丢掉 measurements。
   若需抽出跨平台读取代码，应复用该 verifier 的规则与契约测试，不实现第二套签名。
3. 按现有 plan 的候选链和 `observation_stale` 消费证据，以原来源/原时间去重，
   不用 HTTP 接收时间延长有效期；缺失、失效或签名失败不改变授权集合。
   接入现有候选剪枝回路，推导失败沿用 `observation_kind: derived`。
4. 客户端仍须测量自己的直连和到入口的路径，并在已有预算、窗口、`min_samples`
   与 `switch_threshold` 内验证实际端到端候选。客户端网络、DNS、TLS、鉴权及
   入口链路条件无法从服务器报告替代得出。已有报告未覆盖的目标仍依赖原有本地
   探测，不通过扩大服务器探测面补齐。本次未合成链路评分或调整探测量。

共用 Go Agent 已修复实际失败率的排序和切换守卫；相同失败率仍使用现有目标指标
与阻尼。Android 有自己的候选循环，本次没有修改它，也没有修改 Windows TUN。

## 验证范围

回归测试覆盖空路径/根路径匹配、其他 URL 语义隔离、缺失目标未知、原始内容保留；
也覆盖旧 10% 分档和现任样本不足时的错误切换，横跨 latency/stability/throughput。
用修改前的 Agent 源码运行同一批新测试可复现 URL 匹配失败及较高失败率胜出。
报告适配使用真实测试证书验证端到端 POST、原签名重新验签、默认 204 兼容、
来源范围过滤、撤销身份拒读与过期/无签名/篡改证据缺席。
这些是仓库测试事实；尚未取得 Windows/Android 真机读取并影响本地选路的验收证据。
