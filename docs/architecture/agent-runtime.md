# Agent 执行与客户端宿主

[文档地图](../README.md) · [架构入口](README.md) · [控制面规范](../protocols/control-plane/README.md) · [实现对照](../development/implementation.md) · [本机部署信息](../operations/local-deployment.md)

**规范范围：Linux/server Agent 与明确标注的平台差异。** Windows/Android 的主动测量预算统一见客户端观测复用规范，不能套用服务器候选轮询。

客户端测量规则的唯一正文：[客户端观测复用](../clients/observations.md)。

---

## Agent：调参回路的唯一执行者


Linux/server Agent 跑在承担 **access** 职责的节点上；仅承担 server 转发职责的节点
没有 selector 可切。它为每条声明运行一个循环,
各按自己的 `tuning_period` 走:

```
在授权轮询预算内选择候选探测(探测入口：一个端口，用户名区分候选、探测预算:有界,而不是全探) → 按窗口聚合 → 排序 → 够格才切 selector
```

**它读的不是 SSOT,是渲染出来的 `agent/config.json`。** 节点上不该有全网
拓扑和别人的凭据;Agent 需要的只是"探测哪些候选、打哪个目标、多久一轮、
什么时候允许切",这些都能从 SSOT 纯函数导出。渲染时 Agent 配置与 sing-box
配置必须**同源枚举** —— 两边各写一遍,分叉的表现是 Agent 去切一个不存在的
selector,或者漏掉某条候选从不探测(它永远达不到 `min_samples`,于是永远
选不上,看起来只是"比较慢")。

### 排序:失败率优先,相同失败率再比目标指标

失败与快慢不是同一个量纲,不能相加。一条 50% 失败但很快的候选,如果把失败
折算成"很慢",按延迟排仍可能赢过一条 100% 成功但慢一点的 —— 而用起来一半
的请求是错误。所以排序键是**(实际失败率 failures/samples, 目标指标)**。
不按 10% 分档，否则 0% 与 9% 失败会被误当成一样可靠。

| objective | 相同失败率比什么 |
|---|---|
| `latency` | p50 |
| `stability` | **p95** —— 它关心的是尾部,p50 好看而 p95 很差的链路正是要避开的 |
| `ttft` / `cost` | ❌ Agent 拒绝执行,见下(`throughput` 已可用,[首字节时间与吞吐](measurement.md#首字节时间与吞吐是不同指标)) |

### 三条切换规则,优先级从高到低

1. **当前候选窗口内全部失败,而别的候选能用 → 立刻切,不看阈值也不看样本数。**
   [调整周期与阻尼](scheduling.md#调整周期与阻尼) 的阻尼是为了防止在两个都能用的候选之间反复横跳,不是为了让流量继续
   停在一条已经证明不通的路上。[数据不足与候选集为空](scheduling.md#数据不足与候选集为空) 的冷启动规则说样本不足的候选"不参与排序
   也不被淘汰",管的是**选谁**,不是**要不要离开一具尸体**。
2. 当前选择不在候选集里(配置变了 / sing-box 刚重启)→ 切到最优的。
3. 否则:在样本数达到 `min_samples` 的健康候选里排序。挑战者失败率更低可切；
   相同失败率时，目标指标改善必须超过 `switch_threshold`；失败率更高不得切换，
   即使现任因样本不足没有进入挑战者集合。

> sing-box 重启后 selector 回到渲染的 default。若该候选已经确认不可用，等待
> `min_samples` 会延长业务中断；立即离开失败候选不受健康候选间的切换阻尼限制。

### Windows / Android 客户端：减少无收益中继

Windows/Android 的证据来源、减少中继、逐候选切换判定和未知数据处理统一见
[客户端消费边界](../clients/observations.md#客户端消费边界)。宿主必须使用该客户端
契约，不能把本节 Linux/server Agent 的采样循环作为平台适配。

### 窗口必须装得下 min_samples

主动探测一个 `tuning_period` 才出一个样本,所以窗口里最多装
`window / tuning_period` 个样本。这个数小于 `min_samples` 时,**没有任何候选
能达到参选门槛,排序永远不会启动** —— 配置看着完整,回路却是死的。校验器必须同时校验这些字段之间的算术关系，
不能只检查每个值是否为正数。

同理 `stale_after` 不能小于 `tuning_period`,否则每轮探测的结果下一刻就过期。

### 不能执行的 objective 必须显式拒绝

`ttft` 要 L7 观测点([被动观测优先,但被动能看到什么由观测点决定](measurement.md#被动观测优先但被动能看到什么由观测点决定))、`cost` 要价格源([评分输入分两类](scheduling.md#评分输入分两类))。拿 L4 首字节时间
冒充它们,产出的排序看着完全正常,却在优化另一件事。
(`throughput` 已经能测了,见 [首字节时间与吞吐](measurement.md#首字节时间与吞吐是不同指标)。)渲染期就把这类声明挡在 Agent 配置外并报出原因,
而不是让 Agent 在节点上启动失败 —— 那时人已经不在终端前面了。

## 探测入口：一个端口，用户名区分候选

在服务器既有预算内，探测入口需要独立指定本轮候选：

| 方案 | 结论 |
|---|---|
| 切 selector、测、切回来 | 串行且打断真实流量 |
| 只允许固定目标的 delay 接口 | 不能证明声明目标的可达性；不能作为任意目标探测契约 |
| 一个探测入口,用户名区分候选 | ✅ 采用 |

做法:渲染一个只监听回环的 `mixed` 入站,每条候选一个用户名,路由规则按
`auth_user` 把它打到同名的候选出站。Agent 用不同用户名连同一个端口,就能
把探测流量精确打到指定候选上 —— **不切 selector、不打断真实流量、目标任选。**

这里的用户名是 Agent 内部探测标签，不是用户可选的代理 profile，也不构成
“同域名多账号”能力。v1 不提供后者。

> **目标必须对应声明。** 固定中立站点可能在某候选上可达，而实际业务目标不可达；
> 用前者延迟给后者排序会倒置结果。Agent 的候选入口因此必须允许调用方指定
> 已授权的观测目标，结果只说明该观测范围内的路径质量。

**两个实现上的坑:**

- `mixed` 入站的用户字段是 `username`,**不是 `name`**(那是 hysteria2/trojan
  的)。用错会让 sing-box 启动即 `FATAL: unknown field "name"`。
- 用户名**不能含冒号**。候选 tag 形如 `cand:best-egress:cn-a`,而 SOCKS5
  客户端普遍在第一个冒号处切分 `user:pass` —— curl 就是这样,结果用户名变成
  `cand`。改用 tag 的哈希前缀,可读性由紧邻的路由规则补上。

服务规则始终来自 certified view，Agent 只切换已授权 selector。新增或删除 Service
走配置变更和渲染流程，不能由节点根据观测重写服务归属；见[客户端路由](../clients/routing.md)。

## 环境变量代理的已知坑

- **是约定不是标准。** `curl`/`wget`/`git`/`pip`/`npm`/Go 的 `net/http` 认;**`ping`/`ssh`/`dig`/`nc` 完全不认**;Java 要 `-Dhttp.proxyHost`。
- **`socks5://` vs `socks5h://`** —— 前者本地解析 DNS,后者代理端解析。本地解析会拿到就近 CDN 的 IP,**同时让调度判断失真**。默认用 `socks5h://`。
- **大小写都要设。** 部分程序只读 `http_proxy`,部分只读 `HTTP_PROXY`。
- **`no_proxy` 语义各实现不一致** —— 别用它做精细分流,交给 Loom 的服务匹配。
- **不认代理的程序**:用 `proxychains-ng` 或 `graftcp`。但 proxychains 靠 `LD_PRELOAD`,**对静态链接二进制无效** —— 很多 Go 程序正是如此,只能靠 TUN 兜底。

## Android 的调度承载

Android 没有 Linux Agent([制品与版本管理](deployment.md#制品与版本管理))，但 [决策位置由信息可得性决定](scheduling.md#决策位置由信息可得性决定) 要求接入节点承担四件事：接收已授权候选和规则、
测量只有本机知道的入口段、执行切换阈值、离线沿用最后一份可信状态。**这些能力必须由
Android 客户端自身内嵌**，否则 Android 只能退化成静态选路。

v1 Android 的 matcher、Service 与声明映射全部来自中控签名配置。应用只能显示
哪些规则已经生效、当前走哪条路径以及规则是否陈旧；用户不能新增规则或修改声明
定义，只能切换 Direct / Auto / 指定出口；指定出口列表来自全部在役
`egress_capable` 节点，Current Paths 始终只读。同一 package 内的应用账号不作为本地
路由匹配轴；[Windows 的 Portable 与安装版](../clients/ui.md#windows-的-portable-与安装版) 的多连接配置用于隔离加入身份与网络，不用于识别应用账号。

| 能力 | 承载方式 |
|---|---|
| 接收授权 plan/view | v1 compatibility 验单签 snapshot；v2 验 bootstrap/recovery、ControlSet QC、Device proof、EndpointSet、四组 floor 与 latch，原子落入 LKG |
| 本地测量与切换 | 宿主执行[客户端消费边界](../clients/observations.md#客户端消费边界)；共享决策包作出选择，libbox `selector` 执行并读回 |
| 离线沿用 | 保留最后一份已验证 plan/view、入口证据和仍新鲜的服务器观测；不延长原证据时间 |
| 观测上报 | 通过 permanent overlay 访问私有 `device_report`，使用 Device 身份签名；**指标限于本机实际可得且声明过的范围**([被动观测优先,但被动能看到什么由观测点决定](measurement.md#被动观测优先但被动能看到什么由观测点决定)) |

> **这不等于把 Linux Agent 装进 Android。** 它不运行候选窗口、`min_samples`、整路径探测、
> 配置收敛、二进制自更新或 Linux 漂移纠正；应用更新走平台分发渠道([性能代价与客户端耦合](fingerprints.md#性能代价与客户端耦合))。配置刷新、
> 模式/出口切换和同一网络代重连也不能重新触发入口探测。

---
