<p align="center">
  <img src="assets/loom-logo-v4.svg" width="180" alt="Loom logo">
</p>

<h1 align="center">Loom</h1>

<p align="center">
  把多条加密网络路径编织成一个可测量、可验证、可持续收敛的服务调度平面。
</p>

Loom 是一个基于加密隧道的链路与服务调度基础设施。它从一份声明式 SSOT
生成每个节点的 WireGuard 与 sing-box 配置，持续测量候选路径，并在约束允许
的范围内选择当前更合适的服务地址与服务器链。

它既能处理普通代理上网，也能处理同一服务分布在多个机房、价格与网络质量
持续变化的场景。Loom 关心的不是“哪个节点叫出口”，而是一次请求最终经过的
完整路径。

> [!IMPORTANT]
> Loom 目前是面向自建基础设施的工程项目，不是开箱即用的商业代理产品。
> 配置回滚的完整闭环与 L7 网关仍在演进，部署前请先阅读
> [设计文档](docs/design.md)。

## 核心能力

- **声明式拓扑**：用严格 YAML 描述节点、隧道、服务、访问声明与调度约束。
- **完整校验**：一次返回所有问题，拒绝未知字段、惰性配置和不完整能力。
- **确定性渲染**：同一份输入稳定生成 WireGuard、sing-box、systemd 与 Agent 配置。
- **路径级调度**：以 `(服务器链, 目标地址)` 为排序和归因单位，支持零跳、单跳与多跳候选。
- **持续测量**：按段采集延迟与吞吐，通过转述共享不可直达节点的观测结果。
- **带阻尼切换**：当前路径失效时立即切换，普通优化则受样本量、窗口和阈值约束。
- **签名发布**：快照使用内容哈希标识并由 Ed25519 签名，节点拉取后先验证再安装。
- **秘密分层**：版本库与分发树只含 `${secret:...}` 占位符，明文只在需要它的节点合并。
- **失败回滚**：安装按“暂存 → 预检 → 就位 → 验证”执行，失败时只回滚实际动过的部分。

## 工作方式

```text
                         ┌──────────────┐
                         │   SSOT YAML  │
                         └──────┬───────┘
                                │ validate
                                ▼
                    render → snapshot → sign
                                │
                                ▼
                      不可信静态分发点
                                │ pull
                 ┌──────────────┼──────────────┐
                 ▼              ▼              ▼
              节点 A          节点 B          节点 C
          verify → hydrate → apply → selfcheck
                 │              │              │
                 └──── measure / report ───────┘
                                │
                                ▼
                     Agent 排序并切换 selector
```

控制平面停机不会让数据平面停机：节点继续使用最后一份已经验签并安装成功的
配置，Agent 也能继续依据本地观测调节现有 selector。

## 三个基本概念

| 概念 | 含义 |
|---|---|
| **接入节点** `access` | 流量进入 Loom 的设备，例如工作站、服务器或 Android 设备 |
| **服务器节点** `server` | 参与转发的机器；同一台机器可同时承担接入与服务器角色 |
| **目标地址** | 网站、API 或内网服务；它只是地址，不是 Loom 节点 |

一条路径写作：

```text
接入节点 → [0..n 台服务器] → 目标地址
```

链上最后一台服务器是这次请求的出口。**出口是路径上的位置，不是节点类型。**

## 快速开始

需要 Go 1.27 或更高版本。仓库中的
[参考 SSOT](testdata/matrix/ssot.yaml) 只使用 RFC 保留地址与示例域名，不会连接
任何真实主机。

```bash
# 构建
go build -o out/loom ./cmd/loom

# 校验参考拓扑
./out/loom validate testdata/matrix/ssot.yaml

# 渲染每个节点的配置包
./out/loom render testdata/matrix/ssot.yaml -o out/demo

# 查看 SSOT 变化会造成的配置差异，不写盘
./out/loom diff testdata/matrix/ssot.yaml -o out/demo

# 计算需要放行的端口
./out/loom firewall testdata/matrix/ssot.yaml
```

### 创建并验证签名快照

下面的密钥仅用于本地演示。生产签名私钥是平台信任根，不应进入版本库或分发点。

```bash
./out/loom keygen -o /tmp/loom-demo-keys

./out/loom snapshot testdata/matrix/ssot.yaml \
  -o out/snapshot \
  -key /tmp/loom-demo-keys/platform-signing.key

./out/loom verify out/snapshot \
  -pubkey /tmp/loom-demo-keys/platform-signing.pub
```

## 常用命令

| 阶段 | 命令 | 作用 |
|---|---|---|
| 建模 | `validate`, `firewall`, `addnode` | 校验 SSOT、计算防火墙规则、分配新节点地址与端口 |
| 渲染 | `render`, `diff`, `hydrate` | 生成配置、查看差异、在节点本地填充秘密 |
| 发布 | `snapshot`, `verify`, `publish`, `publisher` | 创建验签快照并发布到静态分发点 |
| 收敛 | `pull`, `apply`, `selfcheck`, `pin` | 拉取或推送配置、安装验证、钉住二进制版本 |
| 调度 | `probe`, `agent` | 探测候选并带阻尼地切换 selector |
| 观测 | `report`, `status` | 上报节点健康、配置漂移与全网快照分布 |
| 凭据 | `secrets`, `backup`, `restore` | 按节点拆分、两步轮换和备份秘密层 |

运行 `./out/loom help` 可以查看完整参数。

## 安全边界

- WireGuard 私钥由节点本地生成；SSOT 只记录公钥与秘密层代次。
- 配置包、manifest 与二进制版本共同进入签名快照。
- 节点只接受通过平台公钥验证的快照，并在本机填充自己的秘密。
- 分发点只保存签名后的静态内容，不需要被信任，也看不到凭据明文。
- 真实部署配置与运维状态只保存在本机；公开仓库只提交合成测试矩阵。

## 代码结构

| 路径 | 职责 |
|---|---|
| `cmd/loom/` | CLI 入口与运维工作流 |
| `internal/model/` | SSOT 模型、严格解码与路径候选生成 |
| `internal/validate/` | 跨字段、跨节点与能力完整性校验 |
| `internal/render/` | WireGuard、sing-box、systemd 与节点配置渲染 |
| `internal/snapshot/` | 内容寻址快照与 Ed25519 签名 |
| `internal/measure/`, `internal/agent/` | 测量聚合、候选排序与调参回路 |
| `internal/report/`, `internal/events/` | 节点观测、转述与状态变化历史 |
| `internal/deploy/`, `internal/publish/` | 安装回滚、静态发布与版本钉住 |
| `internal/secret/` | 秘密占位符、按节点拆分与轮换 |
| `internal/webui/` | 节点只读界面与中控写入口 |
| `testdata/matrix/` | 合成 SSOT 与逐字节 golden 配置 |

## 开发

```bash
go test ./...
go vet ./...
gofmt -l .
```

渲染 golden 由测试维护，不要直接编辑：

```bash
go test ./internal/render/ -run TestGolden -update
```

更新 golden 后必须人工检查 diff。它锁定的是最终配置字节，直接接受所有变化
等于放弃这层保护。

## 深入阅读

- [设计文档](docs/design.md)：模型、不变量、数据平面、控制平面与部署顺序。
- [决策记录](docs/decisions.md)：重要设计选择、被推翻的假设及其证据。
- [参考 SSOT](testdata/matrix/ssot.yaml)：覆盖方向约束、双轴选择、服务契约与多平台接入的合成示例。
