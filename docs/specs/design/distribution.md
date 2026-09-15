# 配置分发、apply 与发布

[文档地图](../../README.md) · [架构入口](../../design.md) · [控制面规范](../../distributed-control-plane.md) · [实现对照](../../implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**职责：控制面架构映射。** 本文解释全系统关系和标明的 v1 契约；v2 对象、认证、状态机与验收规则统一定义在控制面专题，本文不另设 wire schema。

---

## 14. 控制通道

### 14.1 可达性是图，不是成员资格

任一管理工作站或 control Device 不一定能直连所有节点。bootstrap inventory 可用 BFS
求最短路径并生成 `ProxyJump` 链：`ssh -J demo-a,demo-b target`。

这个图用于 bootstrap，也可用于操作者显式触发的管理面快速发布；它是 controller-local
运维事实，不进入 `ControlSet`，不能根据 SSH/DNS 可达性增删 voter。节点稳态配置与离线后
的补齐仍走 signed pull。

### 14.2 signed pull 与管理面快速发布并存

| 通道 | 用途 | 方向 | 适用 |
|---|---|---|---|
| **SSH + SCP** | bootstrap；操作者触发的代码快速发布 | 平台 → 节点(可经 ProxyJump) | 所有已登记管理 SSH 的节点 |
| **Agent pull** | 持久收敛、离线补齐、签名配置与排序下发 | **节点 → 平台**(主动轮询) | 所有节点；与 WireGuard `direction` 无关 |

Agent pull 解决节点主动取回、NAT 下配置分发、控制平面可离线和漂移自动收敛；状态上报
仍分别走受保护网络内的 `/status` 拉取/gossip，以及下述 NAT HTTPS POST 适配器。
管理 SSH 可达的生产节点则不必为了交互式代码发布等待下一次轮询。

> **NAT Device 上报的 v1 兼容边界:** Windows Device 使用同一个“客户端主动访问
> 平台”的控制方向，但上报不是把 JSON 塞进静态 signed-current GET 响应，也不改变
> `/status`。客户端将本轮自产的既有 `Observation` POST 到 enrollment 同源的精确
> `/loom-client/report` 路径；服务端不接受完整 `Status` 或 `learned`。入口只做传输
> 适配，状态线协议仍是 `loom-attest-v5`、签名 measurements 与
> `loom-selfcheck-v1`。除 CA、证书节点名、签名和新鲜度外，公网入口还要求全部附件
> 使用同一 P-256 SPKI，且精确匹配 registry 中 `ready`、由 enrollment 建立的当前
> 身份；node 必须同时是 SSOT 中未退役的 `windows-desktop` Device。成功陈述进入
> 既有 gossip table。入口地址只能从已经验真的 enrollment URL 做同源精确路径替换
> 获得，不能信任 HTTP Host、重定向或未签名配置。见 D98。

> 管理 SSH 的可达性来自中控本地 inventory，不能从 `direction` 推断。

新 Linux Device 的创建结果页必须把管理 transport 与 Enrollment 分开，采用同页内联步骤而非
弹窗：已有 SSH/ProxyJump 时，操作者自行打开会话后运行 shell bootstrap；SSH 未开放、不可达或
目标位于 NAT 后时，操作者通过云控制台、串口/IPMI 或本地终端运行完全相同的脚本。后一条路径
由目标节点主动取回 immutable distribution、建立 bootstrap tunnel 并访问私有 Enrollment，
不要求中控反向连入，也不允许上传 SSH 私钥/口令。

`forward` Device 的软件/identity 安装与 public access readiness 是两个状态。外部 observer 未能
按 signed transport 验证 exact public/local TCP/UDP tuple 时，Device 可保持已安装，但 listener
generation 只能是 `preparing` 且不得 advertise。界面逐项提示出站 distribution/bootstrap、
本机 listener、防火墙或既有 NAT mapping 的失败层，并允许操作者修复后重验，或废弃该邀请并
创建不含 `forward` 的 Device；不得扫描邻近端口、改网关或静默降级职责。

### 14.2.1 apply:五步,顺序不能换

不论推还是拉,一次安装的语义是同一个:

```
1. 写暂存        不碰线上文件
2. 预检          在暂存上跑 sing-box check —— 失败时线上还是好的
3. 存 previous   只存这次真的要被替换的那些
4. 就位、重启    只重启**其文件真的变了**的服务
5. 验证          active,并经过稳定窗口;任何一步失败就回滚并恢复原运行态
```

每一条都对应踩过的坑:

**第 2 步在第 4 步之前。** 曾经直接覆盖再重启,配置非法导致 sing-box 崩溃
重启循环 —— 而当时只测了新功能,没看服务起没起来。检查必须在旧配置还在的
时候做。

**第 4 步只重启语义真的变了的服务。** 一律全重启的话,只改一行 sing-box
配置也会把三条隧道断一遍；但 unit 文件不能只 `daemon-reload`：`ExecStart`、
Capability 与 sandbox 都只在新进程上生效，旧进程仍是 `active` 会造成假绿。
因此 Loom 管理的常驻 service 只要 unit 文件变化就重启；无关服务不碰，
`loom-pull.service` 自身永不在自己的事务里重启。

**第 5 步要等几秒再看。** 崩溃循环的第一次崩溃通常在启动后一两秒,立刻查
`is-active` 会看到 `active`。`NRestarts` 是累计计数，不能拿“历史上曾重启过”
冒充“本轮正在重启循环”；验证关注本轮稳定窗口内的状态与增量。

**回滚必须只碰动过的东西。** 若预检阶段失败（什么都没装），回滚却无差别重启
既有隧道，就会把一次干净的拒绝变成一次真实的扰动。

#### wg-quick 不能用 systemctl restart

`restart` 的 down 与 up 之间有竞态,失败信息是 `` `wg-xxx' already exists ``。
后果特别隐蔽:**unit 停在 failed,而接口其实还在,隧道看起来是好的。**
必须显式停、确认接口没了、再起:

```sh
systemctl stop wg-quick@X; ip link del X 2>/dev/null; systemctl start wg-quick@X
```

#### 一次 ssh 传完

文件用 base64 内嵌在脚本里,从 stdin 进 `sh`,不落盘也不另开 scp ——
"传了一半断线"只会让脚本没跑起来,不会在机器上留下半套文件。

### 14.2.2 分发面：公开证明与私有 Device view 分离

公开 Nginx distribution 只承载客户端自行验证的 immutable objects；每 Device 的最小 view、
私有服务目录与 sealed artifact refs 从认证配置通道取得。访问控制保护下载范围，QC、
inclusion proof 与 durable floor 分别保护 authority、内容归属和防回退，不能互相替代。

协议正文见[签名发布与 anti-rollback](../control-plane/publication.md)、
[私有 Device 配置与报告](../control-plane/device-services.md)、
[EndpointSet 与用途边界](../control-plane/endpoints.md)。公开镜像、DNS、URL 顺序和较大 revision
均不能独立建立 authority。本节以下保留 v1 pull/apply 的版本内契约。

> **v1 兼容：** 旧协议使用单 Ed25519 `current.json + generation +
> release-floor.json`，以下 pull/apply 自恢复细节描述 v1 契约；被新版替换的业务入口按
> [迁移完成条件](../control-plane/migration.md)删除。严格 reader
> 决定了 v2 必须使用并行 versioned 资源，不能向 v1 JSON 原位塞入未知字段。

**每台机器只拿自己那份秘密。** `loom secrets split` 扫一遍各节点的渲染产物,
按实际引用拆分总表:cn-a 拿 3 项,edge-b 拿 2 项,只有 access-a 有控制端点与
探测入口的口令。

#### 状态一致比"版本号一致"重要

`loom pull` **不因为快照 id 和本机记录一样就跳过**。

id 只说明"配置来自哪一版",不说明机器现在是不是那个样子。靠它早退会让漂移
永远修不了：例如 `loom-pull.timer` 可能是 `active` 但未 `enable`（重启即消失），
而只比版本的 pull 仍会误报“已是最新，无事可做”。

安装脚本本身幂等(逐文件比哈希),跑一遍很便宜,顺带把 **enable、服务状态
这些不在文件里的期望状态**也拉回来。

#### 三类"自己套自己"的坑

`loom pull` 的最后一步是重启服务,而它自己就是一个服务。需要防住三类递归/并发陷阱：

| 坑 | 后果 |
|---|---|
| 重启 `loom-pull.service`(oneshot,ExecStart 就是 pull) | 内层那次把外层的回滚清单清空,外层失败时"回滚"变成空操作,机器停在装了一半的状态 |
| `Persistent=true` + `OnBootSec` 的 timer | `enable --now` 立刻触发一次 —— 而 enable 这个动作往往就发生在安装阶段里 |
| 定时器触发的那次与手工跑的那次重叠 | 同上 |

前两个按类堵掉(oneshot 永不重启、timer 用 `OnActiveSec` 且不 Persistent),
第三个用文件锁兜住整类问题。

#### v1 二进制与配置的安全契约

v1 `loom pull` 的目标契约是按同一快照安装 Loom 二进制，再由新二进制子进程继续安装同一
快照的配置；旧进程不解析新 schema。代码变更不能因编译自动武装全网，必须先
把构建产物写到 `deploy/staging/loom`，再由人执行 `loom release -reason ...`
显式放行。首次分配 signed generation 1 之前，publisher 会从稳定候选重新执行
`selfcheck -q -require signed-current-v1`，并要求该候选进入同一快照；旧 release
或空 release 都会在 authority 分配之前失败关闭。配置变更仍由发布器自动收敛。

### 14.2.3 Publisher/reconciler：提交与外部副作用分开

任一 control Device 都能在 Raft apply 时重算同一棵树；只有收齐提交后 QC 的 certified head
能授权 private mutable current/view 前移。公网镜像只写 content-addressed immutable objects；
镜像写入由取得资源租约的 publisher executor 执行，leader/executor 换届后
根据相同 desired hash 幂等接管：

```text
admin proposal → 每个 voter validate/reduce/candidate render → Raft durable commit
              → apply/recompute → quorum replication attest/QC
              → public immutable objects + private conditional current/view → 从 Device 视角读回
```

代码构建仍不等于升级批准。binary hash、理由和 rollout policy 作为 release proposal
显式提交；纯配置变更可由策略自动生成 proposal，但仍须完成 Raft commit、apply/recompute
与提交后 QC，不能因保存某个副本的文件而自动成为 certified state。

publisher 同时负责首次写入和持续对账。镜像被清空、部分复制或落后时重推；镜像出现
同坐标不同 hash/QC 时失败关闭，不用本地副本静默覆盖证据。外部发布通常不支持跨镜像
事务，因此保证的是“公开不可变正文先行、private current/view 最后、最终收敛”，客户端用 QC 与 floor
承受短暂代次不同。

三条硬规则保持不变：

1. **校验、Raft commit 或提交后 QC 任一步不足都不发布。** 上一合法 current 原地服务。
2. **commit/QC 先耐久，公开不可变正文其次，带 revision 条件写的 private current/view 最后。** 旧对象按保留策略保存。
3. **写成功不等于取得到。** 发布后必须从声明的 Device/网络视角取回并逐层验证。

DNS、ACME、云防火墙使用同一“certified intent + 租约 executor + 幂等 reconcile + 读回”
边界；additive、monotonic pointer 与 destructive 动作分别处理。NAT 映射不由 Loom 写入：
它是操作者预先提供的外部事实，Loom 只对 certified mapping intent、reservation 和外部验证
证据收敛。受管外部 API 不能提供 generation CAS/fencing 时禁止无人值守 delete/close。详见
[分布式控制平面 §15](../control-plane/reconciliation-ui.md#15-外部副作用与租约)。租约只减少重复
副作用，不授予 authority，也不能在过期时触发删除。只有 v1 compatibility 仍向公开静态树
写 mutable signed-current；目标 v2 不把它延续为公网发现机制。

> **v1 兼容：** 单节点 `publisher` 监视本地 SSOT/放行记录并按配置周期
> 收敛；这是迁移源，不是目标协议。其 authority 文件、单机锁和单签名不得被新实现继续
> 当成全局 CAS。
