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
> 跨节点 canary/平台确认闭环与 L7 网关仍在演进，部署前请先阅读
> [设计文档](docs/design.md)。

## 核心能力

- **声明式拓扑**：用严格 YAML 描述节点、隧道、服务、访问声明与调度约束。
- **完整校验**：一次返回所有问题，拒绝未知字段、惰性配置和不完整能力。
- **确定性渲染**：同一份输入稳定生成 WireGuard、sing-box、systemd 与 Agent 配置。
- **路径级调度**：以 `(服务器链, 目标地址)` 为排序和归因单位，支持零跳、单跳与多跳候选。
- **持续测量**：按段采集延迟与吞吐，通过转述共享不可直达节点的观测结果。
- **分层近实时拓扑**：分别展示常驻承载、完整候选、签名观测与 Agent 当前实选路径。
- **带阻尼切换**：当前路径失效时立即切换，普通优化则受样本量、窗口和阈值约束。
- **签名发布**：配置自动发布，二进制须显式 `release`；节点拉取后先验签再安装。
  快照内容已防篡改；`current.json` 的反重放与真实 canary 仍在 D88 收口中。
- **秘密分层**：版本库与分发树只含 `${secret:...}` 占位符，明文只在需要它的节点合并。
- **事务回滚**：安装按“暂存 → 预检 → 就位 → 稳定验证”执行，崩溃后也能恢复未提交事务。

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
                静态分发点（内容不可信；新鲜度暂受信）
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

## 控制中心当前边界

控制中心采用无外部资源的服务端渲染界面，仓库当前提供 Overview，并按 Network
（Nodes / Topology）、Traffic（Services / Live paths）、Operations
（Deployments / Events）和 Advanced（SSOT）组织入口。所有节点都能读取
转述后的全网状态；只有持有本机中控配置和运维口令的节点开放写入口。这里描述的
是仓库实现边界，不表示线上节点已经部署到相同 revision。

| 能力 | 当前状态 |
|---|---|
| Service 管理 | 已支持结构化新增、修改和删除；保存前完整校验，并以 SSOT 内容 revision 防止旧页面覆盖新变更。Policy 仍通过完整 SSOT 编辑器修改。 |
| 事件 | 已支持按节点、类型、级别和文本筛选，并可导出同一筛选结果的 CSV；事件是状态变化历史，不代替当前告警。 |
| SSH bootstrap 身份 | 中控只维护一组共享 Ed25519 身份，界面只导出公钥；远端仍需人工授权该公钥，不会为每个节点生成一组控制密钥。 |
| 节点声明（接入前半段） | 已支持输入 SSH 坐标、人工确认 Ed25519 host key、受信预检、从短 hostname 得到 Node ID、复核 direction、在远端生成/复用 WG 身份并以 revision 原子提交完整节点/隧道计划。SSH host 只有是公网 global-unicast IP，或在中控解析出至少一个公网地址的 DNS 名时，才可作为 endpoint candidate；非公网 literal 和没有公网答案的 DNS 失败关闭。当前没有独立的 WireGuard UDP 入站探测，所以 `Automatic` 保守解析为 `reverse_only`。这一步**不会**安装或启动 Loom Agent，也不会分发平台信任、节点秘密和 TLS 身份；完成后节点只是 SSOT 中的 declared / joining，必须经过单独 bootstrap 并产生首份可信报告，才能称为在线。 |
| 远端节点健康 | 每轮从节点本机完整 `Status` 派生最终健康与精简问题列表，并放入独立的 `loom-selfcheck-v1` ECDSA 签名附件转述。中控验证 CA、节点名、签名、新鲜度和外层 node/TS 绑定后才采用：显式 `healthy=true` 且问题为空才显示 healthy，显式失败显示 problem；旧节点或附件缺失保持 unknown。relay 的外层 HTTP 状态和未签名字段不会被当成远端健康。 |
| 转发流量 | 每个节点按约 60 秒的固定内部节奏把 Loom 管理的 WireGuard peer 累计 RX/TX 放入独立的 `loom-traffic-v1` 签名陈述；中控只对同一 node/interface/peer/epoch 的相邻可信样本计算 delta，并保留 30 天。超过 3 分钟的 gap、reset 与回退都不计入字节。Overview 与 Node detail 使用时间桶柱状图；Topology 的链路量只累加各端 TX，避免再把对端 RX 算一次。“有样本的桶”不冒充完整采集覆盖率。稳定抓取接口是版本化的 `/traffic.json`：byte 使用十进制字符串保证 64 位精度，中控额外附带缓存的历史桶，普通节点不在本地保留历史；`/status` 是诊断状态，可能同时含转述附件。该统计只覆盖 Loom WireGuard，不代表 direct、Service/sing-box 或 Hysteria2 流量。可达性 probe 完全由 SSOT 指定；生产使用 `api.ipify.org` 作为大陆直连分类与境外出口可达性信号，不是程序硬编码默认值，也不能随意替换成普通健康页。 |

通过界面保存的 SSOT 由发布器在下一轮（默认最多约 30 秒）自动校验、渲染、签名
和分发；界面没有“发布”按钮。二进制升级仍必须先用 `loom release` 显式放行。
控制页面会立即从刚保存并重新校验的当前 SSOT 派生期望节点、常驻隧道和候选路径，
不再等待中控自己 pull 后才更新；节点是否真正应用仍由 applied snapshot 和可信
观测单独显示。已删除但仍有运行态证据的节点标为 `undeclared observed`，不会继续
计入声明库存或全网快照一致性。
普通节点没有 SSOT 写权限，它的期望库存只来自本机已经应用的 snapshot，允许在
下一次 pull 前暂时落后；只有中控成功读取并校验 current SSOT 后才替换期望层。

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
| 建模 | `validate`, `firewall`, `addnode`, `rotate-tunnel` | 校验 SSOT、计算防火墙规则、分配新节点地址与端口、给隧道换端口 |
| 渲染 | `render`, `diff`, `hydrate` | 生成配置、查看差异、在节点本地填充秘密 |
| 发布 | `snapshot`, `verify`, `release`, `publish`, `publisher` | 显式放行二进制，创建验签快照并发布到静态分发点 |
| 收敛 | `pull`, `apply`, `selfcheck`, `pin`, `rollback`, `snapshots` | 拉取或推送配置、安装验证、钉住二进制、整份退回历史快照、列出还能退到哪 |
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
- 中控网页的 SSOT 写入口共用同目录的进程锁、revision 校验和原子替换，并拒绝
  symlink/hardlink 目标。Git 或外部编辑器不会自动遵守这把锁；直接编辑时仍须保证
  单写者，并在网页保存前重新加载，不能把任意文件编辑器当作可原子 CAS 的数据库。

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
| `internal/enrollkey/`, `internal/enrollssh/`, `internal/enrollplan/` | 共享 bootstrap 身份、SSH 主机信任与节点/隧道接入事务计划 |
| `internal/ssotedit/` | 保留无关 YAML 结构的 Service 定向编辑 |
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
- [客户端接入设计](docs/client-access.md)：Windows、Linux Server、Android 的单入口、设备默认出口、注册、分发与升级边界。
- [决策记录](docs/decisions.md)：重要设计选择、被推翻的假设及其证据。
- [参考 SSOT](testdata/matrix/ssot.yaml)：覆盖方向约束、双轴选择、服务契约与多平台接入的合成示例。
