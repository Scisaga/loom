# CLAUDE.md

Loom 是一个基于加密隧道的链路与服务调度基础设施。**既有设计的事实来源是
[docs/design.md](docs/design.md)** —— 动手前先读相关章节,尤其是七条不变量和 §20 的依赖拓扑。
用户明确变更需求时，以用户要求为准，并同步修正文档；不得用旧设计否决新要求。

当前实现进度与已知缺口见 **[docs/status/current.md](docs/status/current.md)**;
已定的决定与未决问题见 [docs/decisions.md](docs/decisions.md)。
动态 `ControlSet`、CRDT/QC、托管域名/证书和 listener 轮换的目标协议见
[docs/distributed-control-plane.md](docs/distributed-control-plane.md)。该文档是迁移目标，
不是当前能力；处理现行代码时不得把目标字段直接塞进严格的 v1 wire schema。

`docs/status/` 含真实地址,**不进版本库**。所以**干净 clone 拿不到它,
上面那个链接会是断的** —— 这是有意的取舍,不是漏配:内容不能提交,
但规矩要提交。新机器上接手时,那个目录得从备份或原机器带过来。

仓库中的文档、测试、代码注释和 SVG 原型同样不得出现真实设备 ID、公网或内网
地址、域名、主机名、端口、指纹、快照 ID 与运行指标。示例统一使用 `demo-*`
身份、RFC 5737 地址和 `example` 域名；提交前运行
`python3 scripts/check_repository_safety.py`。现网信息只能保存在上述忽略目录。

写法规矩:

- **`current.md` 是"现在是什么样"的唯一出处。有变化就改它,不要往下追加。**
  它必须短到能整个读完 —— 读不完的当前状态等于没有当前状态。
- **`history/` 是归档,一件事一个文件,写完不再改。** 想知道现在怎么样,
  别从历史往回推。
- **架构、SSOT 或运行时语义变化必须同步复核 UI、交互文案、原型和测试。**
  UI 是真实模型的投影，不得继续暴露已经退出架构的选择器、端口或写操作语义；
  只读观测不能使用 `Apply` / “切换”伪装成期望态修改。
- **运行时拓扑必须从当前 View 动态生成。** 静态 SVG 只是原型；Agent 路径只能
  作为双环底图的色彩叠加层，不得参与节点排序或因聚焦而重排拓扑。
- 上一版把两者混成一份 1361 行的追加文档,后果是每次都要从流水账里现推
  当前状态,推出来还互相矛盾。这个分法就是为了堵住那个。

## 执行边界与客户端选路约束

- 目标 v2 的 role 入口不得混用：管理请求只能经已信 certified
  `EndpointSet(role=control_api)` 入口的精确 transport 校验和 admin cert 认证后
  提交；尚无 Device 身份的 claim 只能使用本次 `InviteBootstrapDescriptorV2` 中有界的
  `EndpointSet(role=enroll)` seeds。control peer RPC、DNS 临时发现或其他 role
  都不能作为替代入口。
- 开工前从当前对话提取“必须实现”和“明确排除”，交给子任务时一并传递。
  用户排除的方案，不得改名为后台验证、异步补样、兜底或可靠性保障后重新加入。
- 旧框架、文档和测试不是必须保留的需求。发生冲突时，删改不符合要求的实现与测试；
  不围绕旧排名器、`min_samples` 或完整性指标扩张任务。“能发现更多问题”不等于
  “完成当前功能必须检查这些问题”。
- 评价方案必须基于本任务的分工、必要收益和实际成本，不能用抽象的可靠性好处
  为重复工作辩护。用户纠正后应落实修改，不继续罗列已排除方案的一般优点。
- 当前 Windows/Android 客户端选路分工：每个底层网络代维护一份不可因 Agent/profile 重启而
  清空的 probe registry。Direct 不冻结候选也不花探测预算；该网络代第一次进入 Auto 或指定
  出口时，原子冻结当时的授权入口快照，按地址/源接口去重后各探测至多一次并行完成，入口
  之后复用现有已验证服务器观测。同代再次切换模式、出口、配置或重连只复用该 registry，
  后来出现的入口只接收真实拨号的被动证据，直到 OS 报告底层网络代变化。客户端不再探测
  整条业务路径，不按 Service × 候选路径扫描，
  不增加样本预热、挑战者比较或 P50/P95 收敛流程，也不等待服务器观测到齐才启动。
  不以本条约束扩改服务器测量或签名协议。
- 缺失、过期或无效观测保持未知；不得为填满评分、健康绿灯或测试断言追加探测，
  不把单次入口延迟、服务器分段数据包装成实测端到端 P50/P95。
- 验证应检查实际探测目标、次数、并发及是否阻塞启动，防止被排除行为回归；
  不为让旧测试通过恢复旧行为。新增等待、轮询或重复采样必须来自明确需求。
- 发现偏离就撤掉偏离部分，保留独立有效修复，并及时本地提交。明确区分已实现、
  待替换和已部署；接入观测接口不等于已完成客户端选路修复。

## 生产代码发布约定

生产代码（包括嵌入二进制的 Web UI 与 favicon）默认走管理面的 **SSH + SCP
并行快速发布**：从待发布的精确 commit 只构建一次制品，先执行 `loom release`
并立即用一次性 `loom publish` 固化对应 signed current，再用 `.ssh_config` 中的节点
别名把同一制品并行复制到所有当前节点。
远端必须先写同目录临时文件、核对 SHA-256，再原子替换
`/usr/local/bin/loom`；随后只重启该节点实际运行的 Loom 常驻服务。控制设备若同时是
构建机，也必须使用同一制品就位；仓库文档不得记录实际设备 ID、地址或主机名。

`reverse_only` 只约束 WireGuard 加密隧道的发起方向，不表示主机不能被管理 SSH
直连，也不得据此改成等待节点 pull。默认只等待 SSH/SCP/激活命令本身返回；除非
操作者明确要求，不额外探测 SSH 可达性，不等待 publisher 或 pull 的轮询，不轮询
6/6 收敛，也不做发布后的全网核验。哪个节点命令失败，就立即报告哪个节点。

`loom release`、签名快照和 signed pull 继续承担持久发布记录、离线节点补齐与自动
纠偏；SSOT、节点秘密和签名配置仍走原有安全边界，快速直发不得绕过这些边界。
不要用 SCP 原地覆盖正在运行的二进制。仅改 favicon 等静态资源时，除非操作者要求，
不启动 headless 浏览器验证。

## 构建与测试

Windows 客户端加入与上报任务先完整阅读
[Windows 上报接入说明](docs/windows-client-reporting.md)，交接使用
[Windows 上报实测提示词](docs/windows-client-reporting-prompt.md)。已有加入身份直接复用，
仅未加入时从正常二维码流程开始；私钥由客户端自动生成并保存，不要求用户提供私钥。
只修改客户端及必要的跨平台客户端包；中控用于既有加入流程和验收，不在本环境修改
服务端源码、部署配置或手工修补 SSOT/registry。声称完成上报实机验收时，必须取得
实际客户端有效报告的 `200`（读取观测）或 `204`（旧契约）及中控证据，不能用
未签名请求的 `403` 代替。该验收不授权新增业务路径探测，也不是每次改动的前置条件。

```bash
go build ./...
go test ./...
go vet ./...
gofmt -l .              # 应无输出
```

golden 文件在 `testdata/matrix/golden/`,由渲染器生成,不要手工编辑:

```bash
go test ./internal/render/ -run TestGolden -update
```

改完 golden 必须人工看 diff —— 它锁定的是渲染输出的字节,无脑 `-update`
等于取消这层保护。

CLI 自测:

```bash
go run ./cmd/loom validate testdata/matrix/ssot.yaml
go run ./cmd/loom render   testdata/matrix/ssot.yaml -o /tmp/out
go run ./cmd/loom diff     testdata/matrix/ssot.yaml -o /tmp/out

# 快照与签名
go run ./cmd/loom keygen   -o /tmp/keys
go run ./cmd/loom snapshot testdata/matrix/ssot.yaml -o /tmp/out -key /tmp/keys/platform-signing.key
go run ./cmd/loom verify   /tmp/out -pubkey /tmp/keys/platform-signing.pub
```

## 目录

| 路径 | 内容 |
|---|---|
| `internal/model/` | SSOT 数据模型、严格 YAML 解码、§2.2 方向真值表、隧道角色解析 |
| `internal/validate/` | 渲染前的一致性校验 |
| `internal/render/` | 纯函数渲染(WireGuard + sing-box)、配置包哈希、行级 diff |
| `internal/snapshot/` | 冻结成不可变版本、Ed25519 签名、漂移检测比对 |
| `internal/measure/` | 度量记录、窗口聚合、分位数 |
| `internal/agent/` | **决策者**:接入节点上的调参回路,探测 → 排序 → 带阻尼切 selector |
| `internal/report/` | **上报者**:每个节点都跑。隧道健康、配置自检、按段测量与转述。不做任何决定 |
| `internal/deploy/` | 安装计划与远端脚本:暂存 → 预检 → 就位 → 验证,失败回滚 |
| `internal/publish/` | v1 compatibility 指定 control：校验 → 渲染 → 单签 → 推到分发点；目标由 certified head 驱动可接管 executor |
| `internal/attest/` | 节点给自己的身份陈述签名,好让转述过来的版本也能核对(D81) |
| `internal/rollout/` | 节点装一份新快照走到哪一步了。**现在只记录,不接管控制流**(D78) |
| `internal/version/` | 版本坐标:commit(Go 的 VCS 戳自动带入)+ 二进制 sha256 |
| `internal/netx/` | 不依赖机器全局设置的 HTTP 客户端(不读 HTTP_PROXY、自带 DNS) |
| `internal/events/` | 状态变化历史。**只记变化,不记状态**；v1 compatibility 记在指定 control，目标以不可变事件 CRDT 复制 |
| `internal/webui/` | v1 compatibility：节点只读、指定 control 写；目标为已信 certified `EndpointSet(role=control_api)` 内的入口经 admin cert 认证后接收，Raft commit/apply 后取得 replication QC，并显示副本新鲜度 |
| `internal/secret/` | 秘密层:占位符解析与替换、两步轮换。**合并发生在节点上**,分发树里只有占位符 |
| `cmd/loom/` | CLI:`validate` / `render` / `diff` / `snapshot` / `verify` / `keygen` / `firewall` / `hydrate` / `probe` / `agent` / `report` / `selfcheck` / `status` / `apply` / `publish` / `publisher` / `pull` / `secrets` / `backup` / `restore` / `pin` / `rollback` / `snapshots` / `rotate-tunnel` / `version` / `release` |
| `testdata/matrix/` | 参考 SSOT(4 国内云机 + 2 境外 VPS)与 golden |

## 模型:三个词就够了

| 词 | 是什么 | Loom 管吗 |
|---|---|---|
| **接入节点** `access` | 你的设备 | ✅ |
| **服务器节点** `server` | 你的机器,国内云机与境外 VPS 一视同仁 | ✅ |
| **目标地址** | 网站 / API / 内网服务 | ❌ **只是一个地址** |

**没有"目标节点"这个东西,也没有"出口节点"这个类型。** 一条路径上最后那台
服务器就是这次的出口 —— 出口是位置,不是类型。详见 design.md §1 与
[docs/decisions.md](docs/decisions.md) 的 D12。

## 四条动手前必须知道的约束

**1. 渲染与打包必须是纯函数(§12)。** 不得引入随机数、当前时间、外部查询;
**遍历 map 前一律排序**,或者干脆用切片。dry-run diff、漂移检测、回滚三个
产物全都建立在这个性质上,签名更是直接针对那串字节。

时间与作者这类外部输入由**调用方注入**(见 `snapshot.Meta`),包内不读时钟。

> 这条最容易在不起眼的地方破:校验器里用 `for k, v := range map[...]` 输出
> 发现,就足以让 CI 间歇性失败。已经踩过一次。

**2. 推导出来的字段不进结构体。** `mesh_eligible`、`Tunnel.initiator`、
`uses_tun` 这类值都由别的字段推导。SSOT 用 `KnownFields(true)` 严格解码,
在 YAML 里写这些键会直接报错。**不要为了方便加回这些字段** ——
可写即可与推导结果矛盾。

**3. 不完整的实现要显式报出,不许静默降级。** 已有三处先例:
未实现的协议进 `render.Result.Skipped` 并由 CLI 打印;设了混淆参数但渲染器
不支持时**硬报错**,因为 §17.2 说参数全零等于标准 WireGuard —— 静默输出
无参数配置会让人以为开了混淆而实际没开;Agent 跑不了的 objective
(`ttft` / `cost`)在**渲染期**就被挡在 Agent 配置外并报出理由；`throughput`
已经支持,但探测响应体太小时会明确报告样本不足,
而不是拿 L4 首字节时间冒充。新增能力时沿用这个规矩。

**4. 字段之间有算术关系时,校验器要钉住关系本身。** 光检查每个字段自己合法
不够 —— `window` 装不下 `min_samples` 个样本时排序永远不会启动,而每个字段
单看都没毛病。写这条规则时,参考矩阵和本地部署样例里**每一条声明**都违反它
(见 D24)。

## 代码约定

- **项目名不向下渗透**(附录 B)。内部一律用通用词:`node` / `server` /
  `address` / `path` / `declaration` / `snapshot` / `agent` / `tunnel` /
  `credential` / `render` / `apply` / `rollback`。不要出现 `LoomNode` 这类命名。
- **不要引入 `target` 作为节点概念。** 它是被 D12 明确删除的东西;
  再引入会把已经理顺的层次重新搅乱。
- **注释和错误消息用中文,并带上 design.md 的条款号。** 校验发现的格式是
  `[§2.2 相容性] relay-sh:...`。排障的人需要知道这条规则的理由在哪。
- **校验返回全部发现,不是第一个错误。** 修一个 24 文件的矩阵时,一次看到
  所有问题比修一次跑一次重要。
- 注释解释**为什么**,不复述代码在做什么。

## 环境

Go 1.27 装在 `/usr/local/go`,已软链到 `/usr/local/bin`。第三方依赖保持最小：
`gopkg.in/yaml.v3` 用于 SSOT，`github.com/skip2/go-qrcode` 只用于中控邀请二维码。
