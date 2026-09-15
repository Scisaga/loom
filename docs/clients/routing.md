# 日常入口、三模式与 DNS

[文档地图](../README.md) · [架构入口](../architecture/README.md) · [控制面规范](../protocols/control-plane/README.md) · [实现对照](../development/implementation.md) · [本机部署信息](../operations/local-deployment.md)

**规范范围：v1 客户端入口与宿主。** 本文不能授权继续保留已被 v2 接管的旧业务入口；迁移完成条件见控制面迁移规范。

客户端测量规则的唯一正文：[客户端观测复用](observations.md)。

---

## v1 只有一个逻辑日常入口

“一个入口”是**一个产品与规则入口**，不是要求三个操作系统使用同一种系统 API：

```text
控制规则   Auto: matcher → Service → AccessDeclaration → 候选与授权
Linux      127.0.0.1:1080 mixed ─────┐
Windows    TUN + 127.0.0.1:1080 ─────┼→ 同一份签名配置与顶层路由模式
Android    VpnService TUN ────────────┘
Loom UI    只允许 Direct / Auto / 指定出口；Current Paths 只读
```

Service 页面管理的是“哪些请求属于哪个 Service，以及它由哪条访问声明治理”，
不是给每条策略分配一个端口。一个 Service 的多个 host 仍各自进入正确的服务范围；
同一条声明治理的多个 Service 仍然各自独立选路，不能退回“一个候选服务所有目标”。
应用仍照常发起 URL 请求；Auto 模式使用请求的 host 匹配中控规则，不要求用户先在
Loom UI 里选择 URL。客户端不编辑 matcher、Service、Policy 或候选路径。

Linux Server 没有 TUN，所以用只监听回环的 `1080` mixed 承载日常流量，应用使用
`socks5h://127.0.0.1:1080`。Windows 的 TUN 与 `1080` mixed 只是两种接管方式，
必须读取同一份签名配置；Android 只有 TUN。启停、重连和诊断属于生命周期操作，
不改变路由模式。

客户端只有一个顶层路由模式控件：

| 模式 | 语义 |
|---|---|
| **Direct** | 全部接管的业务流量从设备本地直连，不使用 Loom 服务器路径 |
| **Auto** | 完整使用 certified `Host → Service → Policy`；客户端在签名候选内按入口一次测量与可信服务器观测选择实际链 |
| **指定出口** | 全部接管的上网流量固定由所选最终节点出网；候选仍只能来自签名计划，前置链按同一分段证据择优 |

指定出口可包含内圈或外圈的在役 `egress_capable` 节点；Windows 列表只显示当前签名
默认上网声明有完整候选路径到达的末跳。客户端选择节点 ID，不接受任意 IP 输入。
指定出口是顶层全局模式，不是只处理未命中
Service 的“默认出口”。Current Paths 在三种模式下都只读，不能出现路径下拉框或
`Apply`。模式偏好属于客户端本机：它只在最后一份已验证配置允许的范围内切换并
持久化，控制面离线时仍可工作；当前模式可以作为状态观测上报，但不写入 SSOT。

Windows 固定出口依据签名 sing-box 中覆盖受管业务入口的唯一无目标过滤规则，
关联其默认上网 selector 与 Agent 声明；不能解析 tag 或根据 Service 名称猜测。
所有业务上网规则统一指向该 selector，只保留这一声明的测量与决策；候选严格按
`Chain` 最后一跳等于所选出口裁剪，并保留该声明原有的 targets、objective 和
切换抑制参数。Windows / Android 客户端不执行完整路径窗口或 `min_samples` 等待，
只使用当前底层网络代 probe registry 的入口结果与可信服务器观测。不同网站与 Service 的新连接因此共用实际读回的
同一条服务器链，前置路径仍可随测量改善或故障切换。必要的 DNS、探测认证、引导与
私有网络运行规则保持原状；无唯一完整业务规则或无所选末跳的授权候选时拒绝固定模式。
私网规则若依赖独立 selector，则拒绝合并，保留原 Auto 配置与 Agent；不能停止其测量后
静默冻结私网路径。独立 selector 的私网 CIDR 与域名、公网 CIDR 混合规则同样拒绝：
这些目标条件属于 OR，整条保留会绕过统一上网路径，整条改写又会改变私网行为。
返回 Auto 时从签名原始配置恢复 Service 分流和各自的 Agent 决策。此定义取代 Windows
先前逐 Service 独立固定末跳的行为；Fixed 的状态、路径图和签名报告只呈现这一条实际
共享上网路径，不能继续列出已停用 Service 的旧路径或样本。

接入规划器必须对完整候选 SSOT 中的全部在役 `egress_capable` 节点做固定策略对账：
若某节点没有任何 `from_request + pinned:<node-id>` 声明，就生成
`<node-id>-fixed`，因此既覆盖新节点，也能补齐升级前已存在的节点，并兼容历史策略
ID。最终出口钉到该节点，探测与调参边界从已有 `from_request` 声明继承。固定出口只
固定最后一跳，不等于停止优化前面的中继：日常固定出口策略使用 `latency`（p50）
排序，切换抑制由独立的 `switch_threshold` 承担；`stability` 表示按 p95 尾延迟
排序，不能在 UI 中解释成“固定”或“少切换”。策略声明可以随节点事务自动生成，
但接入凭据的值属于秘密层，必须完成显式安全分发后才可在客户端或 Service 表单中
启用；未授权策略只能显示为待激活，不得伪装成可用选项。

三个模式复用同一 TUN/`1080`，不需要模式专用端口。v1
`access.default_declaration` 只是 Auto 模式下未命中 Service 的 catch-all；控制 API 对该字段
的编辑也不能表达 Direct 或“全部接管业务流量固定最终出口”。三态由具备该能力的客户端
依据最后一份签名配置在本机原子切换并持久化，不新增顶层 SSOT 模型或设备写 API；
宿主实现和实机结果只见[实现对照](../development/implementation.md)。

v1 matcher 只使用接管层真实可见且能稳定渲染的事实：Windows 使用 domain/IP，
Android 可再用 package 缩小范围；Linux mixed 使用代理请求可见的 domain/IP。
规则只引用 `service_id`，再由 Service 引用 `declaration_id`，不直接复制出口参数。
匹配按“package + exact domain → package + 最长 domain suffix → package + 最长 CIDR
→ package only → exact domain → 最长 domain suffix → 最长 CIDR → 显式默认”收敛；
不适用 package 的平台跳过前四项。同一优先级若命中不同 Service 必须在中控校验时
拒绝，YAML 顺序不能成为策略。

### Linux 兼容与高级覆盖

旧的“端口 → AccessDeclaration”是 v1 兼容能力，只允许在 Linux 上作为
兼容或高级覆盖：例如旧程序无法表达中控 matcher，或运维需要临时验证一条已经由
中控授权的固定出口声明。覆盖端口必须显式命名、只监听回环、出现在 Advanced/CLI
而不是 Service 页面，并继续受原有凭据、目标范围和 fail-closed 约束。不能让端口
选择扩大候选集或绕过合规约束。

部署确认没有遗留端口调用方后，才可将惯用的 mixed 端口设为唯一入口并停止兼容端口；
固定出口改由 certified `Service → AccessDeclaration` 表达。若存在遗留调用方则不得
复用旧端口，必须先迁移或选择一个没有历史语义的新端口。

同一域名下的不同账号藏在 TLS 内，L4 看不到账号身份。按账号选择固定出口需要
调用方 profile、SDK 或 L7 上下文；v1 不引入这套 profile，也不允许配置两条相同
域名规则靠顺序碰运气。此场景在 v1 显式不支持，待单独设计身份、凭据与服务端
授权边界后再进入模型。

## selector 需要一个能切它的端点

渲染出的每个生效 Service 对应一个 sing-box `selector` 出站，成员是它的全部
RouteCandidate([决策位置由信息可得性决定](../architecture/scheduling.md#决策位置由信息可得性决定))；只有 Linux 兼容覆盖才保留声明级 selector。

**`selector` 是手动开关:它自己不测速、也不切换。** 这是刻意的 —— sing-box
另有 `urltest` 会自动选最快的,但那会成为第二个互不知情的决策者,与 [决策位置由信息可得性决定](../architecture/scheduling.md#决策位置由信息可得性决定)
"选路的决策者必须只有一个"冲突。

所以接入节点的配置里必须带一个本地控制端点:

```json
"experimental": { "clash_api": {
  "external_controller": "127.0.0.1:61800",
  "secret": "<秘密层引用>"
}}
```

Agent 通过它切换当前候选。**没有这个端点,渲染出的候选集永远停在 default
上 —— [调度](../architecture/scheduling.md#调度) 的整套调度做完了也落不了地。**

只监听回环,并且带口令:同机的其他进程不该能改你的选路。

## DNS 必须显式配,而且要给它留一条出路

sing-box 不配 `dns` 块时会退回系统解析器。这有两个坑,都**只影响直连候选**,
因而极难诊断 —— 走代理的域名是交给出口解析的([环境变量代理的已知坑](../architecture/agent-runtime.md#环境变量代理的已知坑) 的 `socks5h`),根本
不经过本机。

**坑一:系统解析器可能是坏的。** access-a 的 systemd-resolved 上游配的是
`8.8.8.8`,在大陆被污染/超时。表现是"直连候选 100% 失败,代理候选一切正常"。
解析器要按机器所在地选:大陆机器用境外 DNS 会被污染,境外机器用国内 DNS
又绕远。

**坑二:`route.final = block` 会把 DNS 查询也拦掉。** 未匹配一律阻断是对的
([数据不足与候选集为空](../architecture/scheduling.md#数据不足与候选集为空) 的 fail_closed),但 sing-box 自己去问解析器的那个连接也走 route 规则:

```
outbound/block[block]: blocked connection to 223.5.5.5:53
dns: lookup failed: operation not permitted
```

所以 DNS 服务器必须显式指定 `detour`,指向一个专用的直连出站。**它不参与
选路,存在的唯一目的是让解析器可达。**

业务 DNS 是跨平台不变量，不能只在 Android 特判：

- **Direct** 由接入设备的 underlay/本地 resolver 解析并从本机直连；
- **Auto / 指定出口** 必须把 FQDN 保留到候选链的最终出口，由该出口自己的受管 resolver
  解析；禁止把接入侧先得到的 A/AAAA 地址沿链转发，否则 CDN/污染结果会绑定错误地域；
- IP literal 不触发 DNS，也不得被反向改写成域名；
- `distribution`、公网 bootstrap/data ingress 的 dial hostname 属于传输建立，不是业务目标。
  它们使用独立 underlay resolver/cache、signed public EndpointSet、transport identity/pin 和
  防回环保护，不进入 FakeIP 或最终出口业务解析；`control_api`、Enrollment、Raft、
  `device_config` 与 `device_report` 使用 overlay IP 和 internal service certificate，不要求公网
  DNS，也不得经公网 Nginx 解析/反代。

Linux mixed 强制使用 `socks5h://` 或语义等价的远端解析。Windows/Android TUN 使用持久化
FakeIP 映射或经测试等价的 domain-recovery 机制：只对来自 TUN 的业务 A/AAAA 查询返回
FakeIP；连接进入 sing-box 后恢复 FQDN，并沿所选链交给最终出口解析。`reverse_mapping` 只能
补充路由元数据，不会替换已经确定的目标 IP，不能单独满足约束。FakeIP 规则必须限定 TUN
inbound 并与 transport bootstrap resolver 使用独立缓存；映射和 IPv4/IPv6 地址池必须随平台
安全保存并全部被 TUN 接管。Android 宿主不能假定 libbox 一定显式列出两族默认路由：只要
某地址族已配置 TUN 地址而对应路由迭代器为空，`VpnService.Builder` 必须补上该地址族的
默认路由。Windows 必须用等价的双栈路由和域名恢复验收，不能把“系统 DNS 已被 hijack”
误当成“最终出口已解析”。

> 这两个坑叠在一起的症状是同一个:直连候选失败、代理候选正常。第一次遇到时
> 很容易归因成"这台机器上不了网" —— 而实际上它直连 baidu 只要 68ms。
> **排查顺序应当是:先绕过 DNS 用 IP 直连一次,再看是不是解析的问题。**
