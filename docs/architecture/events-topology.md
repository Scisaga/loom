# 事件、拓扑与回放

[文档地图](../README.md) · [架构入口](README.md) · [控制面规范](../protocols/control-plane/README.md) · [实现对照](../development/implementation.md) · [本机部署信息](../operations/local-deployment.md)

**规范范围：架构与数据平面。** 本文定义对应主题的规则；标明 v1 的契约仅用于该版本，标明目标态的机制不表示已实现。

---

## 告警

隧道断连超阈值、Agent 失联、**等价类契约校验失败**(输出契约或访问契约)、路径或端点质量劣化、**切换熔断触发**、价格数据过期、证书/凭据将过期、部署失败或回滚发生。

**[数据不足与候选集为空](scheduling.md#数据不足与候选集为空) 引入的三类新告警:**

| 告警 | 含义 |
|---|---|
| **候选集为空** | `fail_closed` 已生效,该访问声明正在拒绝新连接 —— **这是最高优先级,需要人介入** |
| **候选长期冷启动** | 某候选样本数迟迟不达标,说明它既没有真实流量、也没被探测覆盖 |
| **度量数据过期** | 排序正在退化 —— 若多数候选同时过期,说明观测通道本身出了问题,而不是候选出了问题 |

> **告警通道不能依赖被管网络** —— 否则网络挂了收不到告警。

## 事件:只记变化,不记状态

告警之前先要有**历史**。上报者每分钟采一次全网,但"每分钟一条 cn-a 正常"
没有任何价值 —— 那只是另一份没人看的日志。

有价值的是**变化**:什么时候坏的、什么时候好的、坏了多久。

转述表只保留最新观测，无法独自回答历史持续时间，因此变化记录与当前状态分开保存。

### 判据:两次观测不同,才产生一条记录

```
09:33:50  access-a  tunnel  wg-edge-a   active → down
09:34:59  access-a  tunnel  wg-edge-a   down   → active
```

一次 69 秒的断连是**两条**记录,不是 70 条"还在断"。

三条设计约束:

**`From` 和 `To` 都要记。** 只记 `To` 的话,"从坏变好"和"一直是好的"在
日志里长得一样。

**第一轮只播种,不产生事件。** 否则每次重启都会看起来像全网同时变化了一次。

**"还在持续"和"持续了 X 之后恢复了"必须分开。** 后者是历史,前者需要人
现在就管 —— 界面上前者置顶且标红。

当前问题从当前状态读取，事件只补充起止时间和变化原因。重启后若值未变化，继续使用
已保存的 `since`；无法确定真正发生时刻时，显示已知持续时长的下界。没有后续恢复事件
不证明故障仍在持续，也不能用过期观测给当前状态定论。

### 内容寻址事件在 control 副本间收敛

事件由观察到变化的 control 副本生成，绑定 source observation hashes、certified head 和
canonical `From/To`，以 event hash 去重并通过 CRDT anti-entropy 复制。多个副本看见同一
变化不会产生 N 条不同事实；分区中的事件在恢复后合并。事件不是配置 SSOT，不需要先取
quorum 才能记录，但删除/tombstone 与压缩水位必须由 quorum checkpoint 保护，旧副本不能
让已清理或撤权历史复活。

v1 只在单控制节点写事件，因此该节点停机期间存在记录缺口；目标 UI 必须展示
source、coverage 和副本 staleness，不能把“本地没看到”当成“没有发生”。

### 这不是告警,而且不能当告警用

事件副本仍在被管系统里面。即使有多个 control Device，[告警](#告警) 那条约束仍然成立：

> **告警通道不能依赖被管网络** —— 否则网络挂了收不到告警。

所以这是两层,不能互相替代:

| 层 | 回答什么 | 能不能依赖被管网络 |
|---|---|---|
| **事件记录** | 什么时候坏的、坏了多久、跟哪次发布有关 | 可以 —— 它是事后查的 |
| **告警通道** | 现在有人该来看看 | **不可以** |

外部告警是独立能力，不能从 Events 页面是否存在推断其已经部署；实现状态只见
[实现对照](../development/implementation.md)。设计告警策略前应先用事件历史估算频率，避免无依据地设置
噪声门槛。

v1 Events 页的兼容契约允许按节点、类型、级别与文本筛选，并用标准 CSV 编码导出相同
筛选结果；它读取单点变化日志，不能补回停机期间未记录的变化，也不会因筛选/导出升级
成告警。目标态切换为 CRDT event store 后，这项限制才退出；实际页面状态只见
[实现对照](../development/implementation.md)。

## 可视化

“拓扑”必须分层，不能把“没有常驻 WireGuard 直边”画成“两个拓扑节点之间
没有路径”:

1. **承载声明层:** SSOT 中的节点、常驻隧道和可动态拨号关系；
2. **候选路径层:** 从 SSOT 枚举的端到端 `RouteCandidate.server_chain`，明确
   回答任意接入节点经哪些拓扑节点到达出口；候选不等于已在线；
3. **观测层:** 握手、RTT、探测结果、更新时间与信息来源；
4. **决策层:** Agent 当前实际选中的完整 `RouteCandidate` 与切换原因。

界面用实线表示已观测健康的常驻隧道，候选路径表列出未被选择的完整 chain，
虚线表示按 SSOT 允许但未连续观测的动态边，高亮线表示当前选中路径；陈旧或缺失
数据必须明确标注，不能补画成绿色。拓扑位置使用稳定的同心双环：纯 `use_loom` Device
在内圈，具有 `forward` Responsibility 的 Device 在外圈；兼具两者时按 `forward` 放外圈，
`control` 不改变位置。每条 LinkIntent 的箭头/标签单独表达发起方、transport 与 purpose，不能
再用节点所在环暗示所有边的建连方向。内外圈不表示控制层级或地理距离。

线上拓扑不是嵌入的静态 SVG。每次渲染都从当前 `View.Nodes` / `View.Links` 生成：
新增节点按 certified Responsibilities 自动进入对应环并重新等角排列，新增 LinkIntent/声明边随数据一同出现。
`assets/` 下的 SVG 只定义信息结构和视觉样例，不参与运行时绘图。Agent 当前路径是
基础拓扑之上的色彩叠加层，不能参与节点排序或改变双环位置；聚焦某条决策也只能
改变强调程度，不能让底图重新布局。

转述测量只有在观测节点的签名绑定了 `Edges/Targets` 且样本数大于零时，才能
改变实时颜色或进入 Agent 剪枝；legacy/unsigned 数据只能保持 unknown。界面与
决策器必须共用这条可信度边界，不能出现“页面不信、selector 却已经照做”。
**静态拓扑图价值有限，带观测与决策的实时候选集视图才是排障入口。**

Device inventory 也必须投影同一可信边界：浏览器通过 JSON 快照完成首屏渲染，已打开的列表经
private HTTPS 同源 WebSocket 接收结构化数据，在原行更新改变的单元格；不用浏览器轮询制造第二条采集路径。所有现行
Linux 节点的 Loom report 进程、Android Device 的已连接 VPN 服务及已注册的 Windows Loom
进程每五秒发送独立的最小签名心跳，线
正文严格只有 `node`、`ts`、`signature`；证书复用既有已登记身份或已验签 Observation，不在
每包重复携带。Linux 心跳经 overlay 邻居转发，Android 与 Windows v1 compatibility 心跳复用
同源 HTTPS report 入口的精确 `presence=1` 分支；Windows 的发送节拍独立于 WireGuard/Hysteria
流量及完整 Observation worker。连续十五秒没有新心跳时，`Online` lease 到期并显示 `Stale`。
租约从接收端接受到新的、签名时间单调推进的心跳时开始，不直接使用设备时钟计算；
旧签名包重放不能刷新该时刻。

心跳不是节点观测：完整 Observation、服务器 gossip、健康/自检、配置、链路、测量、流量和
服务器观测读取继续按各自原有周期与陈旧边界运行；心跳不得刷新 `ObservedAt`、健康结论或
配置状态。列表与 API 分别保留 `Last heartbeat` 和 `Last observation`。因此在线同时要求当前
心跳和仍有效的可信完整观测；只有心跳不能把旧观测变绿，只有旧观测也不能继续显示在线。
没有新心跳不等于收到离线回执，所以不能写成已证实的 `Offline`。服务端须按心跳 lease deadline
主动唤醒 WebSocket，不能等待下一份完整报告才让旧 Online 失效。
不保留旧 Windows/Android/Linux 的滚动兼容租约：从未产生过 `loom-presence-v1` 的节点明确显示 heartbeat
尚未上报并不得显示 `Online`，即使它刚提交过完整 Observation。这样 Observation 永远不会被
改称或暗中充当心跳。
Windows 心跳请求只接受上述三字段和空正文 `204`，不回退到 Observation 或旧响应语义；到达时
关闭 Device inventory 变更代，lease deadline 到达时由服务端主动刷新已打开的 WebSocket。

流量历史只使用柱状表达离散时间桶，不画暗示连续插值的曲线。Overview 的柱高是
fleet node-interface RX+TX delta，Node detail 用并列 RX/TX 柱，Topology 用链路
TX-only 总量比较条；reset 与长 gap 位置保留空槽并标出质量原因。柱高为零只有在
该桶确实存在可信相邻样本且 delta 为零时成立，缺样本不能画成零高度柱。

Topology 的持久边可附带紧凑滚动标签：当前可信 RTT、近五分钟 TX-only delta
换算的实际传输速率，以及近十五分钟 RTT 摘要的 P95−P50。实际速率不是链路容量，
RTT 变化也不是逐包 jitter；窗口和来源必须可见。RTT 摘要在中控 traffic store 中按
节点、邻居和观测时间去重后计算，候选边因没有连续观测而保持空白。

内圈之间的动态 Hysteria2 直达关系不能复用或拆分 Agent 的端到端候选路径数字。
每个可拨无向对选择一个明确方向，通过专用凭据访问对端 loopback 固定响应，生成独立
签名的单跳探测陈述。界面可显示响应延迟、十五分钟变化和固定响应主动探测速率，并须
披露实际探测方向；主动探测速率不是业务 throughput 或容量，尚无样本时保持 unknown。

布局与视觉层次原型见可编辑 SVG：
[Overview](../../assets/loom-control-center-overview-misaka-v1.svg)、
[Nodes](../../assets/loom-control-center-nodes-misaka-v1.svg)、
[Node detail](../../assets/loom-control-center-node-detail-misaka-v1.svg)、
[Topology](../../assets/loom-control-center-topology-misaka-v1.svg)、
[Services](../../assets/loom-control-center-services-misaka-v1.svg)、
[Routing](../../assets/loom-control-center-routes-misaka-v1.svg)、
[Deployments](../../assets/loom-control-center-deployments-misaka-v1.svg)、
[Events](../../assets/loom-control-center-events-misaka-v1.svg) 与
[Settings](../../assets/loom-control-center-settings-misaka-v1.svg)。
新 head 经 Raft commit、apply/recompute 和 quorum attestation 成为 certified 后，Nodes、
Services、常驻边与候选路径都从同一次 effective SSOT 读取派生；各节点实际 applied snapshot、握手和 Agent
选择继续来自可信运行态。已从 SSOT 删除但仍有最新观测的节点可暂留为
`undeclared observed`，用于识别未清理进程或配置漂移，但它不进入声明库存、健康
比例、joining 数或快照一致性结论。
普通节点没有 current SSOT 视图，其声明库存只来自本机已应用 report config 的
expected inventory，可以合法落后一个或多个 pull 周期；页面必须标为 applied
inventory。control 副本只有在验证 certified head/QC 并成功重算相同 roots 后才把期望层标为
current validated SSOT；落后副本显示 stale，运行态仍然只能来自可信观测。
无论独立 WireGuard UDP 入站探测是否启用（状态见[实现对照](../development/implementation.md)），界面都必须
把 candidate 与 verified endpoint 分开表述，不能把“存在 LinkIntent”说成主动探测成功。
原型只定义信息结构与视觉语言；线上颜色、边和状态必须由上述四层真实数据生成，
不能把原型里的示意状态硬编码进页面。

## 回放与回测

> **[调整周期与阻尼](scheduling.md#调整周期与阻尼) 的阻尼参数无法在线调优。** 你不能拿生产流量试"阈值 20% 与 15% 哪个更好" —— 一次实验要跑很多天,而且期间的网络状况不可复现,两组结果不可比。

因此度量数据必须**可回放**:

```
历史度量序列(某时段全部候选的指标时序)
        │  ← 输入
   [调度引擎,离线模式]
        │  ← 换一组参数重跑
   决策序列(何时切到哪个候选)
        │
   评估:切换次数 / 是否振荡 / 累计延迟 / 累计成本
```

这让下列问题变成可回答的:

- 阈值设 15% 而不是 20%,上周会多切几次?
- 调整周期改成 5 分钟,会不会出现振荡?
- 换一个目标函数,累计成本会降多少?
- **上线一个新端点后,它会抢走多少流量?** —— 在真正接入前就能估算

**实现要求:**

| 要求 | 说明 |
|---|---|
| 度量数据带完整时间戳并长期留存 | 回测的输入 |
| 调度引擎可脱离实时环境运行 | 纯函数式:(度量序列, 参数) → 决策序列 |
| 决策与参数一并记录 | 否则无法解释"当时为什么这么选" |

> 这个能力**在启发式阶段就用得上**,不必等求解器。

---
