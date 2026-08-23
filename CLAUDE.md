# CLAUDE.md

Loom 是一个基于加密隧道的链路与服务调度基础设施。**设计的唯一事实来源是
[docs/design.md](docs/design.md)** —— 动手前先读它,尤其是六条不变量和 §20 的依赖拓扑。

当前实现进度与已知缺口见 [docs/status.md](docs/status.md);
已定的决定与未决问题见 [docs/decisions.md](docs/decisions.md)。

## 构建与测试

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
| `internal/publish/` | 中控侧:校验 → 渲染 → 签名 → 推到分发点;发布器守护进程 |
| `internal/netx/` | 不依赖机器全局设置的 HTTP 客户端(不读 HTTP_PROXY、自带 DNS) |
| `internal/events/` | 状态变化历史。**只记变化,不记状态** —— 记在中控一处 |
| `internal/webui/` | 节点上的操作界面:读在每台机器上,写只在中控 |
| `internal/secret/` | 秘密层:占位符解析与替换、两步轮换。**合并发生在节点上**,分发树里只有占位符 |
| `cmd/loom/` | CLI:`validate` / `render` / `diff` / `snapshot` / `verify` / `keygen` / `firewall` / `hydrate` / `probe` / `agent` / `report` / `selfcheck` / `status` / `apply` / `publish` / `publisher` / `pull` / `secrets` / `backup` / `restore` / `addnode` |
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

## 三条动手前必须知道的约束

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
(`ttft` / `throughput` / `cost`)在**渲染期**就被挡在 Agent 配置外并报出理由,
而不是拿 L4 首字节时间冒充。新增能力时沿用这个规矩。

**4. 字段之间有算术关系时,校验器要钉住关系本身。** 光检查每个字段自己合法
不够 —— `window` 装不下 `min_samples` 个样本时排序永远不会启动,而每个字段
单看都没毛病。写这条规则时,参考矩阵和真实部署里**每一条声明**都违反它
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

Go 1.27 装在 `/usr/local/go`,已软链到 `/usr/local/bin`。唯一的第三方依赖是
`gopkg.in/yaml.v3`。
