# 项目工作指引

开始工作前先完整阅读[设计入口](docs/README.md)，再阅读与任务直接相关的核心模型；
涉及本机节点或部署参数时还须阅读
[配置模型](docs/operations/configuration-model.md)。用户在当前对话中的明确要求优先于仓库旧设计、旧实现、旧测试和旧 issue。

## 当前边界

- 现网身份、密钥、数据、认证 floor 和既有不可回退 latch 必须保留，只允许经验证的前向迁移。
- 控制面 Web、Android 和 Windows 的页面、样式、图标与有效交互必须尽量保留；旧 SSOT、registry、report 拼接层和页面专用状态机不因此获得保留资格。
- Windows 源码、构建和虚拟化原生执行都留在当前服务器；需要时使用受限的同机
  [Windows 11 测试虚拟机](docs/operations/windows-test-vm.md)，不维护第二份开发环境。该 VM 不能
  抵扣 ARM64、真实睡眠、物理网络切换和显示硬件的实体机终验。Windows 的原生范围限于现行模型定义的
  加入、运行、报告、安装和既定三种交付形态；新增功能须由当前任务明确授权。DNS provider、
  DNS-01、ACME 自动签发/续期也不属于当前核心范围。
- 不登录或修改路由器/NAT，只消费操作者已经提供的映射。

## 宿主网络安全门禁

涉及 TUN、策略路由、DNS、代理、WireGuard、网络命名空间、systemd 网络服务或防火墙前，必须先阅读
[宿主网络接管事故记录](docs/incidents/2026-09-21-host-network-takeover.md)。以下约束高于旧实现、旧测试和
“先让业务跑通”的临时验证：

- 开发机和控制机的初始 network namespace 不是应用流量实验环境。Linux access/hybrid runtime 不得在其中
  启动 `auto_route` TUN；`auto_detect_interface`、endpoint `/32` 排除和业务报告成功都不能证明宿主网络安全。
- 开发与验收默认使用显式 Mixed/SOCKS/HTTP proxy；必须验证 TUN 时，sing-box、TUN、路由表、策略规则和测试
  workload 必须全部位于专用 network namespace。容器只有在不使用 host network 且能力仅限其 netns 时才算隔离。
- 未经用户在当前任务中明确授权，不修改宿主的 route/rule、TUN、resolved、NetworkManager/networkd、nftables、
  iptables 或网络 service。授权部署也必须先有独立管理通道、变更前快照、精确所有权清单、失败回滚和变更后回读。
- 任何 capture 设计必须正向定义允许进入的数据源；SSH 管理流量、LAN、默认网关、现有 WireGuard、宿主 DNS/代理、
  control/bootstrap/report/tunnel endpoint 和 Loom 自身 underlay 永不因默认路由或补集规则进入 TUN。
- TUN 是 overlay，物理接口或既有 WireGuard 是 underlay。接口 `UP`、收到入站包或 main 表仍有默认路由都不等于
  安全；必须用真实新连接与返回路径证明管理和基础流量没有被 policy routing 改道。
- 不用临时主机路由、放宽 ACL、ping、selector/report 变绿或单次业务成功替代宿主安全验收。验收至少覆盖新建 SSH
  会话、LAN、WireGuard、DNS、HTTP proxy、默认公网路由、正常停止、异常退出和重启恢复。
- 回滚只能 compare-and-delete 本 generation 明确拥有的对象；禁止 flush 共享路由表、rule 范围或防火墙。临时逃生
  rule 最后删除，且删除后必须重复完整验收。
- 网络清理失败时 service 必须保持 failed/inactive，不得 `Restart=always` 反复重施。当前隔离实现未完成前，禁止
  绕过 Linux 初始 netns 的 fail-closed 门禁或重新启用本机 `loom-client.service`。

## 外部写入

本机 GitHub 凭据可能来自 VS Code AskPass/IPC；agent 缺少相关环境时，从同用户、同仓库终端安全继承。
API 使用带精确仓库 path 的 `git credential fill`；不得输出凭据，临时认证文件须为 `0600` 并及时删除。

## 固定工作顺序

每项功能严格按以下五步推进：

1. 从原始需求提取必须结果、明确排除和真实业务入口；
2. 用最少概念设计模型，并先写清领域、wire、持久、运行时和 UI 的对应关系；
3. 枚举覆盖风险等价类的最小必要测试集；
4. 编码、调试，并沿正式入口完成持久化、运行时消费、回读及本任务授权范围内的部署验收；
5. 最小闭环完成后，才可增加有明确新风险依据的扩展测试。

功能由模型表达，不由路由分支、manager、store、receipt、gate、phase 或测试矩阵堆出来。测试不能发明需求，旧测试失败也不能成为恢复被明确删除行为的理由。

## 模型门禁

每个核心模型文档必须使读者无需阅读代码即可知道：

- 有限的领域概念、稳定身份及删除每个概念会破坏的需求；
- 关系、允许的状态转换、不变量和失败/恢复语义；
- domain、wire、persistent、runtime、UI 的逐项映射；
- 哪些映射必须可逆，哪些只是单向投影；
- 一条正常业务链、最小测试和明确禁止恢复的旧实体。

权威领域值 `D`、规范 wire `W` 和持久值 `P` 必须满足：

```text
decode(encode(D)) = D
load(save(D))      = D
```

未知、歧义和非规范输入必须拒绝。运行时和 UI 只能由权威状态单向投影，不能倒写事实。helper、DTO、adapter、缓存和索引不得拥有文档未定义的生命周期或完成判定；缓存必须可删除重建。

如实现需要新增权威实体，先在模型中证明：现有概念无法表达哪项明确需求，以及删除新实体为何会破坏该需求。不能完成该证明就不增加实体。

## 唯一现行契约与版本冻结

当前只维护[一份现行设计契约](docs/core/current-contract.md)。每种权威对象只有一个当前可写的规范
schema；对象各自已有的格式号不构成多套业务模型。在用户明确要求**新协议或新版本**以前，遇到错误、测试失败、
实现与预期不一致或字段不足时，持续修订同一模型、同一协议和同一现行 schema 的实现与测试；不得以 `v3`、
新的 `runtime_contract` 值、第二份 DTO/store、双写、双读或旧协议/旧配置的长期运行 fallback 绕过问题。

修订不得静默重解释现网已经认证的 head、签名 wire 或已部署持久字节。若同版修订无法同时满足这些不可变事实，
先停止相关写入并报告具体冲突、前向迁移和删除旧路径的方案，等待用户明确决定是否启用新协议/版本；不能自行
升级版本号。旧格式材料不进入现行解码、重放或迁移运行路径；原始字节仅作为受保护的切换证据保全，
不得为新请求生成旧格式或形成第二运行权威。
源码提交号、制品版本和 EndpointGeneration 是业务数据或发布坐标，不是遇错时可新增的协议版本。

## 移植与删除

- 旧代码默认不移植；只按[白名单](docs/migration-whitelist.md)提取最小纯组件或真实 transport adapter。
- 不整提交、整目录搬运旧状态机。必要能力若与错误权威逻辑混在一起，只提取必要部分并删除其余内容。
- 新路径接管后，在同一工作项删除相应旧 handler、路由、反代、启动项、客户端旧协议/旧配置 fallback、重复 store 和失效测试。
- 注释、测试名和长期文档不引用 issue 编号作为语义来源；链接核心模型的有意义标题。
- 每次只推进一个核心 issue；实现、接线、部署、验收和旧路径删除不能拆成可分别关闭的 issue。

## `.env` 与私有资料

- `.env` 继续管理本机节点和部署输入，但必须经过配置模型定义的严格白名单解码；当前唯一允许直接保存的 provider secret 是 `GANDI_PAT_TOKEN`。它不是控制面 SSOT、运行状态、历史证据或派生值数据库。
- 不读取、打印、提交或在回答中复述秘密值。尽量保存密钥/证书文件引用而非秘密正文；节点别名由 `.ssh_config` 解析。
- 不为每个阶段、命令或默认目录增加环境变量。能由一个根目录、模型或确定性规则推导的值不重复配置。
- 真实部署回执只进入被忽略的 `deploy/evidence/`；可再生输出进入 `out/` 或 `dist/`。
- 文档、测试、注释和原型只使用 `demo-*`、RFC 5737 地址及 `example` 域名，不写真实设备、地址、域名、端口、指纹或运行指标。

## 完成与 issue 判定

除远端结果须满足前述读回门禁外，组件存在、测试通过、端口可达和 HTTP 拒绝都不等于完成。一个结果只有同时满足以下条件才可关闭：

1. 正式 UI/CLI 入口提交正常业务请求；
2. daemon 的真实调用链完成认证和业务处理；
3. 权威状态与必要副作用持久化，重启后可恢复；
4. Linux/Android 或服务运行时实际消费结果；
5. 用户可通过正常入口回读结果；
6. 本任务授权的生产配置和精确制品已激活并留有受保护证据；
7. 被替代旧路径从源码、配置和实际入口消失。

外部条件确实缺失时，报告精确阻碍、已完成内容和剩余业务结果，保持 issue open；不得用“主体完成”“待收尾”掩盖缺口。

## 架构不变量

- 节点可组合承担 `access`、`forward`、`internet_egress`、`control` 职责；不受管的目标地址不是节点，最终出口是路径位置，不是节点类型。
- N=1 和 N>1 使用同一控制模型；成员数量只是 `ControlConfig` 的数据，不存在 N=1 门禁或专用模式。
- CRDT 差量同步规范签名的不可变普通事实；任一有效 control 可签发普通变更，成员表变化才由旧成员多数签名。没有普通事实的全局排序、Raft 或认证头部。
- 公网 Nginx 只提供 fake website 和明确认证为公开的通用不可变制品。管理、Enrollment、设备配置和报告只走私有认证服务或受限 bootstrap tunnel。
- 授权不等于可达。客户端用真实 transport/业务结果形成 `available / unavailable / unknown`；声明、ICMP 或 UI 颜色不能制造健康事实。
- Direct、Auto 和指定最终出口复用同一候选模型。指定出口时，一跳直达与经境内节点中继到同一出口可同时存在，由当前网络观测选择。
- 渲染与打包是纯函数：不读时钟、不使用随机数、不查询外部状态；遍历无序集合前稳定排序，时间等外部输入由调用方注入。

## 构建与检查

按改动先运行相关测试，提交前运行：

```bash
go build ./...
go test ./...
go vet ./...
git ls-files --cached --others --exclude-standard -z -- '*.go' | xargs -0 gofmt -l
python3 scripts/check_repository_safety.py
git diff --check
```

格式检查必须无输出。Golden 只能由渲染器更新，更新后人工检查 diff；不得用更新 golden 掩盖模型偏差。
