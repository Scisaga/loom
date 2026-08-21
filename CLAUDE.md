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
go run ./cmd/loom render  testdata/matrix/ssot.yaml -o /tmp/out
go run ./cmd/loom diff    testdata/matrix/ssot.yaml -o /tmp/out
```

## 目录

| 路径 | 内容 |
|---|---|
| `internal/model/` | SSOT 数据模型、严格 YAML 解码、§2.2 方向真值表、隧道角色解析 |
| `internal/validate/` | 渲染前的一致性校验 |
| `internal/render/` | 纯函数渲染、配置包哈希、行级 diff |
| `cmd/loom/` | CLI:`validate` / `render` / `diff` |
| `testdata/matrix/` | §20.1 的 4 中继 × 3 目标 fixture 与 golden |

## 三条动手前必须知道的约束

**1. 渲染必须是纯函数(§12)。** 不得引入随机数、当前时间、外部查询;
遍历 map 前一律排序。dry-run diff、漂移检测、回滚三个产物全都建立在这个
性质上。`TestRenderIsPure` 会拦住违反,但它只能发现你已经写出来的不确定性
—— 别指望它替你想。

**2. 从 `direction` 推导的字段不进结构体。** `mesh_eligible`、
`Tunnel.initiator` 这类值由 §2.2 的真值表推导。SSOT 用 `KnownFields(true)`
严格解码,在 YAML 里写这些键会直接报错。**不要为了方便加回这些字段** ——
可写即可与推导结果矛盾。

**3. 不完整的实现要显式报出,不许静默降级。** 已有两处先例:
未实现的协议进 `render.Result.Skipped` 并由 CLI 打印;设了混淆参数但渲染器
不支持时**硬报错**,因为 §17.2 说参数全零等于标准 WireGuard —— 静默输出
无参数配置会让人以为开了混淆而实际没开。新增能力时沿用这个规矩。

## 代码约定

- **项目名不向下渗透**(附录 B)。内部一律用通用词:`node` / `path` /
  `declaration` / `snapshot` / `agent` / `tunnel` / `credential` /
  `render` / `apply` / `rollback`。不要出现 `LoomNode` 这类命名。
- **注释和错误消息用中文,并带上 design.md 的条款号。** 校验发现的格式是
  `[§2.2 相容性] relay-sh:...`。排障的人需要知道这条规则的理由在哪。
- **校验返回全部发现,不是第一个错误。** 修一个 24 文件的矩阵时,一次看到
  所有问题比修一次跑一次重要。
- 注释解释**为什么**,不复述代码在做什么。

## 环境

Go 1.27 装在 `/usr/local/go`,已软链到 `/usr/local/bin`。唯一的第三方依赖是
`gopkg.in/yaml.v3`。
