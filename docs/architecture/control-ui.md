# 控制界面与管理身份

[文档地图](../README.md) · [架构入口](README.md) · [控制面规范](../protocols/control-plane/README.md) · [实现对照](../development/implementation.md) · [本机部署信息](../operations/local-deployment.md)

**职责：控制面架构映射。** 本文解释全系统关系和标明的 v1 契约；v2 对象、认证、状态机与验收规则统一定义在控制面专题，本文不另设 wire schema。

---

## 界面：运行态可分布读取，管理写经私有 control_api 由任一 control Device 接收

上报者顺带提供一个网页。**它不自己采集任何东西** —— 显示的就是 `/status`
返回的那份数据,于是"页面上说的"和"接口返回的"永远是同一件事。

### 界面是运行模型的投影,不是另一套产品模型

架构、SSOT 或运行时决策语义发生变化时，相关页面、文案、交互、原型和回归测试
必须在同一改动中复核并同步。不能只把后台从“客户端指定路径”迁成
`Host → Service → Policy → Agent` 自动选路，却继续在界面上保留路径下拉框和
`Apply`；那会把只读观测伪装成写操作，等于向操作者暴露一套已经不存在的模型。

运行时 Agent 决策一律自动展示并明确标成只读观测。诊断时可以聚焦、过滤或跳转到
证据详情，但这些查看动作不得使用“应用”“切换”“保存”等期望态词汇。客户端唯一
可写的本地路由偏好是 Direct / Auto / 指定出口三模式；它必须放在客户端偏好界面，与
Topology、Service 当前路径和 Agent 候选检查严格分开。指定出口只选择最终节点，
不能借此把 Current Paths 变成手选路径。

因为有转述([按段量,不按整条路线量](reporting.md#按段量不按整条路线量))，普通节点可以展示自己持有的运行态；control 副本还会复制签名
观测与事件 CRDT。任何页面都必须显示数据来源、观察时间、certified head 和覆盖范围，
不能因为本副本缺数据就断言“全网正常”。

### 进入路径与认证

```
普通节点本地诊断       → 隧道地址或 SSH 转发进入只读页面
control 管理 API/UI   → permanent overlay IP + internal service cert + admin mTLS
一次性加入             → public distribution/catalog → capability-limited bootstrap tunnel → private Enrollment
Device 配置/报告       → permanent overlay IP + internal service cert + Device mTLS
```

节点回环诊断入口继续保留，因为控制网络断掉时它仍有价值。目标态只有经 certified
`PublicEndpointIntent` 明确授权的 distribution/bootstrap/data listener 才能对外服务；
`control_api`、Enrollment、Raft、`device_config` 和 `device_report` 只在 overlay 监听，使用用途
隔离的 internal certificate/认证策略，不能在公网 endpoint 上靠 path 分流。公网 Nginx 只提供
fake website 和 immutable distribution，`/status` 不能因此整体公开。
DNS 只是发现，ControlSet/QC 才是 authority。

### 权限按身份和用途分

| 操作 | 装在哪 | 认证/一致性 |
|---|---|---|
| 本机运行态读 | 每个节点 | 现有受保护网络/回环边界；不获得管理能力 |
| 全局 certified/观测读 | 每个 control Device | admin/Device scope；响应标 recovery/control 坐标、head/QC 与 staleness |
| 管理写 | private ControlServiceDirectory 内任一可达 control | overlay IP + internal cert/IP SAN/SPKI + admin mTLS + certified ACL + base head；Raft commit、apply/recompute 后须取得提交后 QC |
| control 投票 | 当前 voter | control key/cert；不等同 admin 身份 |

当 `q > 1` 时，单个 control API listener 被攻破不能独自形成 certified write；`N=1, q=1`
迁移态没有这一属性。接收端验证管理员证书和
scope，将 proposal 复制并交给临时协调者；每个 voter 独立校验精确 state root 后才签名。
admin cert 不投票，control peer cert 不自动获得人类管理权限。

### 写入口只提交 SSOT operation

界面上没有绕过控制提交链的“直接发布”按钮。Service、Device、域名、证书、入口端口和
raw SSOT 编辑最终都产生带 admin signature、request ID、base epoch/revision/head 和 reason
的 operation；只有完成 Raft commit、apply/recompute 与提交后 QC 的 certified operation 才改变 effective SSOT。生成 controller-local SSH 或
executor secret 是本机 bootstrap，不是另一条网络配置通道。

不存在"对某台机器执行某某"这种旁路,而这正是 [逻辑 SSOT 与纯函数渲染](control-rendering.md#逻辑-ssot-与纯函数渲染) 想要的:节点上的所有配置
都是 SSOT 的渲染输出。开一条临时通道,等于在系统里造一个官方认可的漂移来源。

**提交前每个 voter 都要重新校验。** 页面上的“只校验”按钮只提供预览，不是守卫。
接收节点本地保存或 CRDT 复制成功只能显示 `pending`；Raft commit 后但 QC 未齐显示
`committed_not_certified`，取得提交后 QC 才显示 `certified`，之后另行显示
`published / reconciled / device applied / healthy`。无 quorum 时可以保留草稿，但不能
显示“已保存并将自动生效”。

v1 把单节点写入口分成两层；迁移后 UI 保留产品语义，底层改为 proposal/QC：

| 入口 | v1 产品语义 | 有意不做的事 |
|---|---|---|
| **Services** | 结构化新增、修改、删除服务；严格校验 exact host 与 `.suffix`；展示 certified matcher → Service → Policy 关系；保留无关 YAML 内容、顺序和注释 | 不把多个本地端口当成 Service 主模型；不用不完整表单修改 Policy，也不从当前 route 反推期望态 |
| **Settings / SSOT** | 查看、校验并保存完整原文 | 不提供绕过完整校验的“强制保存” |

v1 的 Services 页面只编辑逻辑控制事实。Windows 与 Android 上如何把规则落到 TUN、
Windows 的开发者 mixed 如何复用同一规则，都是渲染结果。客户端只在本机保存
Direct / Auto / 指定出口三态偏好；它不属于中控 Services 或设备期望态页面，也不允许
改 matcher、Service、Policy 或 Current Paths。现有 `default_declaration` 写入口只编辑 Auto
模式下的 catch-all，不能作为三模式 UI 的后端。Linux 的兼容覆盖端口若需要展示，
只能放在节点详情的 Advanced/Compatibility 区，并明确它不是另一套 Service 配置。

所有写入口携带 current head 作 CAS。过期页面不能静默覆盖别的管理员操作；冲突草稿
使用 MV-register 显式展示并生成新的精确候选，不能用字段级 LWW 自动合并。当前 v1 的
本地 `fsync + rename`、inode/symlink/hardlink 检查和进程锁继续保护单机文件 cache，
但不再充当跨 control Device 的系统 CAS。

### control 本机 bootstrap 与 certified membership 分开

每个 control Device 的本机 bootstrap 配置只记录数据目录、peer listener、secret refs、
初始 trust checkpoint 和 executor 资格；这些路径与私钥是本机事实。正式 voter 身份来自
已取得提交后 QC 的 certified `FinalControlSet`，不能由本机把 `control: true` 或 endpoint
写进文件自授予。缺少 admin、
control 或 executor secret 时对应操作 fail closed，不退化为无认证。

### 页面里不能有任何外部资源

不是极简主义:这些机器不一定能出网,通过 ssh 端口转发进来时更不能。
**一个依赖 CDN 的界面在最需要它的时候恰好打不开。** CSP 设成
`default-src 'none'` 把这条约束钉死,回归测试也盯着。

同理,节点 id 和错误信息都来自**别的机器**,一律转义 —— 一台被拿下的机器
不该能往别人的界面里注入脚本。

## 浏览器渲染与实时更新

管理界面使用 Go 二进制内嵌的静态 HTML、CSS 和 JavaScript 模块。浏览器负责所有页面的
渲染与同源导航；服务端只提供结构化数据和业务接口，不再生成页面正文或通过 WebSocket
推送 HTML。生产环境不需要 Node 服务、CDN 或外部字体。CSP 仅允许同源脚本与样式。

私有 HTTPS 仍在转入 Unix socket 前核对管理员 mTLS、certified ACL 与写请求 Origin。
前端隐藏或禁用控件不是授权措施；匿名 JSON 只投影脱敏摘要，SSOT、邀请、管理操作及
制品下载继续要求管理员身份。业务回调当前仍沿用实现对照中标明的 v1 事务；改为 JSON
传输不代表已经迁移到 v2 certified operations。

首次进入从 `/api/control/ui` 取得能力与快照，之后通过现有 WebSocket 交付结构化快照。
运行态复用 report 的 gossip 周期缓存和现有独立 presence 租约，查看界面不追加主动测量。
浏览器只更新改变的设备单元格，保留筛选、行顺序、展开内容和输入焦点；断线明确显示
重连状态，旧证据不因连接恢复而变新。

### 页面分工

- **Overview**：当前网络、运行问题、自动选路与保留的流量时间桶。
- **Devices**：设备身份、职责、presence、Loom 运行态、配置、版本与最近报告。
  职责支持多选的任一/全部匹配，并与平台、运行状态和名称筛选共同保存在 URL。
  名称为主标识；ID 与平台为辅助信息，授权列表按需展开。
- **Topology / Live paths**：当前 View 生成的双环拓扑及只读 Agent 路径。
  节点排序不依赖选中路径；缺少观测不画成实测可用。
- **Services**：结构化期望态编辑；**SSOT**：完整原文与 revision 冲突保护。
- **Releases**：客户端包与部署记录两个页签。设备列表不再承担通用安装面板；
  邀请页只显示适合该平台的制品与安装步骤。
- **Events**：状态变化、未解决问题与 CSV 导出。

### 状态与控件语义

presence 表示设备心跳租约，Loom 运行态来自独立可信报告，二者分别展示。
现有 WireGuard 累计计数器和相邻同 epoch 样本可显示节点接口总量及区间平均速率；
重置、缺失、过期或未签名样本不推导速率。它们不能被称为某个 Android/Windows 客户端
的应用流量。历史时间桶只展示已接受的 counter delta，缺失桶与实测空闲零流量不同。

Windows/Android 当前固定 `use_loom`，不显示不可用职责。只有 `use_loom` 时显示 grants；
只有 `forward` 时显示方向及 `internet_egress`。隐藏控件禁用并从提交中排除，服务端仍做完整
验证。保存中、校验未通过等暂时不可用的动作保留位置并说明原因。

### 浏览器渲染与原型一致

渲染机制迁移不构成视觉重设计。Overview 与 Topology 的布局、间距、颜色、品牌图形以
[Overview 原型](../../assets/loom-control-center-overview-misaka-v1.svg)和
[Topology 原型](../../assets/loom-control-center-topology-misaka-v1.svg)为准，真实观测替代示例数据。
发布页按 Linux、Android、Windows 分页，平台标签和制品卡片使用对应图标；Windows 卡片标题
显示 `installed`、`portable-tun`、`portable-mixed` 变体，架构单独标明。部署记录仍在 Releases 内独立分页。
