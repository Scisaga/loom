# Android 3/4：完成三态选路、可信观测复用与实际路径展示

对应 GitHub Issue #3 的当前正文。旧版“候选轮测 + 窗口 + `min_samples` +
端到端 P50/P95”方案已退出 Android 客户端范围，以本文件为准。

> **协议边界：** 本 Issue 交付当前 v1 signed mobile plan 与现有 report 通路，不包含
> 分布式控制迁移。Android 后续必须增加 recovery、ControlSet、head 与 Device view 四组
> durable anti-rollback floor、recovery policy hash 和不可逆 v2 latch，
> QR v2 多 seed、按 role 的 EndpointSet 及 listener overlap；该工作按
> [分布式控制平面设计 M2/M6](../distributed-control-plane.md#19-从当前实现迁移)另立迁移 Issue，
> 不能通过扩展严格 v1 JSON 偷渡。本文勾选完成也不代表四个 Android 阶段或 v2 已完成。

## 目标

在签名移动调度计划授权范围内完成 Direct / Auto / 指定出口，并让 Android 与
Windows 使用同一窄选路决策。客户端只测它独有的信息：当前底层网络到授权入口；
入口以后只复用服务器原有的可信 Observation。路径页展示实际 selector 与逐连线
证据，不把分段值包装成整条业务路径实测。

## 固定语义

- Direct：全部受管业务从本机直连，不执行入口或完整路径测量。
- Auto：按 active signed `Host → Service → Policy` 使用签名候选；每个底层网络代只对
  首次进入 Auto/指定出口时冻结的候选快照中的授权入口按地址和源接口去重，各并行发送
  至多一次 ICMP，最大并发 4；Direct 不冻结快照、不花预算。
  同代配置刷新、模式/出口切换和重连不得重新探测；不得按 Service × 候选扫描，
  不补样、不预热、不等待观测到齐。
- 指定出口：只保留签名 `Chain` 最后一跳等于所选节点的候选；撤权或没有合法候选时
  fail closed。前置链仍按相同证据比较，不能接受任意地址输入。
- 入口以后只使用 canonical v5 且 measurements 已绑定的服务器 Observation，以及
  已分别验签的 self-check / traffic / link-metric 附件。按当前计划限制来源、保留
  原始时间并执行新鲜度检查；缺失、过期、越界或无效证据保持未知。
- latency 先比较精确失败率，再比较“入口 RTT + 实际承载服务器段 + 出口精确目标”
  的分段估算。同一声明只比较所有候选共同已有的目标子集。
- 失败率相同且估算延迟不增加时，减少服务器中继立即生效，不受
  `switch_threshold` 阻挡；增加中继或同跳数替换仍需达到改善阈值。缺后段证据时
  保留当前出口，且入口更快不能成为增加未知中继的理由。
- 实际选择必须先从 libbox Clash API 读回；切换后再次读回，不一致则回滚选择和
  受保护状态。离线仅沿用最后一份仍可验证配置与仍新鲜观测，不刷新原始证据时间。

## 上报和读取

- 使用现有可信健康上报 `POST .../report?observations=1`，不增加独立读取轮询。
- 新服务端成功返回 `200 application/json` Observation 数组；旧服务端 `204` 仍表示
  报告成功但没有新证据。正文格式错误只影响观测读取状态，不能改写健康上报结果。
- Android Keystore 私钥永不导出。共享 Go 核心准备 canonical v5 / self-check 原文，
  Kotlin 调用 Keystore 签名；canonical v5 同时绑定实际 declaration、selector、
  candidate、chain 和决策原因。

## 路径页

- 页面按实际 selector 读回显示声明、候选和签名 chain；三态下均只读，不提供路径
  下拉或 Apply。
- 分别显示本机到入口的单次 ping、服务器 WireGuard 邻居 RTT、公网 data-ingress 实际协议，
  以及出口到每个精确目标的首次响应耗时；只有已有签名 Hy2 LinkMetric 时才显示其单跳
  RTT / Δ / 固定响应探测速率，Trojan 不借用或补造该指标。
- 每段保留来源、原测量时间、样本/失败和错误；不存在对应证据时显示 `—`。
- 不显示“整条业务健康”、端到端 P50/P95、业务吞吐或“已选最优路径”。

## 验收清单

本文件不维护易过期的完成勾选；GitHub Issue 状态与实机/部署事实应以
[`status/current.md`](../status/current.md) 为准。关闭本 Issue 前需有以下证据：

- Windows / Android 共用平台无关决策包，并覆盖失败率、阈值、少中继与未知证据；
- 从验签后的 sing-box detour 推导真实入口和服务器段承载，不解析 tag 猜测；
- 每底层网络代只在首次进入 Auto/指定出口时对当时冻结的候选快照执行一轮去重并行入口测量；Direct 不探测；同代配置刷新、模式/出口切换
  和重连不再测，网络切换后隔离旧代；
- 在原健康周期读取 `200` 观测并兼容 `204`，验证签名、附件、范围、新鲜度和原时间；
- selector 事务读回、回滚、计划作用域缓存与控制面离线沿用；
- Keystore 外部签名绑定实际路径，控制平面能核对 canonical v5 选择事实；
- 当前路径卡片按连线显示证据，缺失保持未知；
- 生产受管配置真实 `200`、入口故障、固定出口、控制面离线及 Wi-Fi/蜂窝重测有真机证据；
- 路径页视觉和连接交互通过人工验收；Doze、进程回收、重启和覆盖升级归 Stage 4。

## 不在本 Issue

- 按应用、IP/CIDR 的本地规则编辑器；规则继续由中控管理。
- 客户端完整业务路径主动探测、候选矩阵轮测、P50/P95 收敛、吞吐测试或后台补样。
- Stage 4 的 Doze、厂商后台限制、开机恢复、撤权和覆盖升级终验。
